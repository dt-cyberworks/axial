#!/usr/bin/env python3
"""REQ-PIPE-012: how many requests per second the egress proxy carries, and where
the time goes.

Measured against a throwaway nginx container that only exists for this run, with
a synthetic engagement scoped to it (created and removed through the control
plane's own code) - never against a real target. The load is generated from
inside the tool-runner container, i.e. over the same path every scan tool uses
(runner network -> egress proxy -> target).

What it measures, each on its own so the slowest step can be named:

  dns      getaddrinfo latency for a host name, from inside the proxy container
           (the proxy resolves and pins the target's address on every connection)
  scope    the proxy's read-only scope decision (its database queries)
  audit    one audit submission to the control plane (the hash-chained audit write
           the proxy makes for every connection), sequential and concurrent
  proxy    end-to-end CONNECT and plain-HTTP requests through the proxy at several
           client concurrencies (one client ~ one engagement's tool; two ~ two engagements)

Nothing here changes the proxy or the audit path (decision D5): it only measures.
Every request is audited like any other, so a run adds a few hundred synthetic
`network_request` audit rows to the environment it runs against (dev by default).

    python3 scripts/measure_egress_throughput.py [--requests 100] [--concurrency 1,2,8]
                                                  [--dns-host cloud.example.com] [--out result.json]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

TARGET_HOST = "throughput-target.test"
TARGET_NAME = "asm-throughput-target"

# Runs inside the tool-runner container (stdlib only). argv: proxy_host proxy_port target port mode requests concurrency [engagement_id]
LOADGEN = r'''
import json, socket, sys, threading, time
proxy_host, proxy_port, target, port, mode, total, conc = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5], int(sys.argv[6]), int(sys.argv[7])
engagement = sys.argv[8] if len(sys.argv) > 8 else ""
lock = threading.Lock()
state = {"next": 0}
latencies, statuses = [], {}

def read_head(s):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def one():
    started = time.perf_counter()
    status = "error"
    try:
        s = socket.create_connection((proxy_host, proxy_port), timeout=30)
        try:
            header = ("X-ASM-Engagement-Id: %s\r\n" % engagement) if engagement else ""
            if mode == "connect":
                s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%s\r\n" % (target, port, target, port, header)).encode())
                head = read_head(s)
                status = head.split(b" ")[1].decode() if head.startswith(b"HTTP/") else "bad"
                if status == "200":
                    s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % target).encode())
                    while s.recv(65536):
                        pass
            else:
                s.sendall(("GET http://%s:%d/ HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n" % (target, port, target, header)).encode())
                head = read_head(s)
                status = head.split(b" ")[1].decode() if head.startswith(b"HTTP/") else "bad"
                while s.recv(65536):
                    pass
        finally:
            s.close()
    except Exception as exc:
        status = type(exc).__name__
    elapsed = time.perf_counter() - started
    with lock:
        latencies.append(elapsed)
        statuses[status] = statuses.get(status, 0) + 1

def worker():
    while True:
        with lock:
            if state["next"] >= total:
                return
            state["next"] += 1
        one()

begin = time.perf_counter()
threads = [threading.Thread(target=worker) for _ in range(conc)]
[t.start() for t in threads]
[t.join() for t in threads]
wall = time.perf_counter() - begin
latencies.sort()
pick = lambda q: latencies[min(len(latencies) - 1, int(q * len(latencies)))]
print(json.dumps({"requests": total, "concurrency": conc, "wall_s": round(wall, 3), "rps": round(total / wall, 2),
                  "p50_ms": round(pick(0.5) * 1000, 1), "p95_ms": round(pick(0.95) * 1000, 1),
                  "max_ms": round(latencies[-1] * 1000, 1), "statuses": statuses}))
'''

# Runs inside the egress-proxy container. argv: dns_host engagement_id target samples
STAGES = r'''
import json, socket, sys, time, threading
dns_host, engagement, target, samples = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
out = {}

def timed(fn, n):
    values = []
    for _ in range(n):
        t = time.perf_counter()
        try:
            fn()
        except Exception:
            pass
        values.append((time.perf_counter() - t) * 1000)
    values.sort()
    return {"n": n, "p50_ms": round(values[len(values) // 2], 2), "max_ms": round(values[-1], 2), "mean_ms": round(sum(values) / len(values), 2)}

out["dns_target"] = timed(lambda: socket.getaddrinfo(target, 80, type=socket.SOCK_STREAM), samples)
out["dns_" + dns_host] = timed(lambda: socket.getaddrinfo(dns_host, 443, type=socket.SOCK_STREAM), samples)

from app import db
from app.audit_client import submit_audit

def scope_decision():
    db.load_engagement(engagement)
    db.matching_scope_assets(engagement, target, "/", "deny")
    db.matching_scope_assets(engagement, target, "/", "allow")

out["scope_decision_db"] = timed(scope_decision, samples)
out["candidate_engagements_db"] = timed(db.candidate_engagements, samples)

def audit():
    submit_audit(engagement, "ALLOW", "throughput_measurement", {"method": "CONNECT", "host": target, "port": 80})

out["audit_sequential"] = timed(audit, samples)
for conc in (2, 8):
    lat = []
    lock = threading.Lock()
    def run(k):
        for _ in range(k):
            t = time.perf_counter()
            try:
                audit()
            except Exception:
                pass
            with lock:
                lat.append(time.perf_counter() - t)
    per = max(1, samples // conc)
    begin = time.perf_counter()
    ts = [threading.Thread(target=run, args=(per,)) for _ in range(conc)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    wall = time.perf_counter() - begin
    lat.sort()
    out["audit_concurrent_%d" % conc] = {"n": per * conc, "per_s": round(per * conc / wall, 2), "p50_ms": round(lat[len(lat) // 2] * 1000, 2), "max_ms": round(lat[-1] * 1000, 2)}
print(json.dumps(out))
'''


def sh(*cmd: str, stdin: str | None = None, check: bool = True, timeout: int = 600) -> str:
    result = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr.strip()[:800]}")
    return result.stdout


def compose(*args: str, stdin: str | None = None, timeout: int = 600) -> str:
    return sh("docker", "compose", "--profile", "runner", *args, stdin=stdin, timeout=timeout)


def internal_post(base: str, token: str, path: str, body: dict) -> dict:
    request = urllib.request.Request(
        base + path, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-ASM-Internal-Token": token},
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - operator-supplied local URL
        return json.loads(response.read().decode())


def create_engagement(base: str, token: str) -> str:
    body = {"title": "Throughput measurement (synthetic, safe to delete)", "target_host": TARGET_HOST,
            "tcp_port_from": 80, "tcp_port_to": 80, "tool_categories": ["fingerprint"]}
    return internal_post(base, token, "/internal/benchmark/engagements", body)["id"]


def delete_engagement(engagement_id: str) -> None:
    code = (
        "import sys, uuid\n"
        "from app.db.base import SessionLocal\n"
        "from app.api.engagements import _delete_engagement_dependents\n"
        "from app.models.engagement import Engagement\n"
        "db = SessionLocal(); eid = uuid.UUID(sys.argv[1]); eng = db.get(Engagement, eid)\n"
        "if eng is not None:\n"
        "    _delete_engagement_dependents(db, eid); db.delete(eng); db.commit()\n"
    )
    compose("exec", "-T", "control-plane", "python", "-c", code, engagement_id)


def network_of(service: str, suffix: str) -> str:
    prefix = os.environ.get("ASM_NETWORK_PREFIX", "asm")
    return f"{prefix}_{suffix}"


def start_target() -> None:
    sh("docker", "rm", "-f", TARGET_NAME, check=False)
    sh("docker", "run", "-d", "--rm", "--name", TARGET_NAME, "--network", network_of("proxy", "egress"),
       "--network-alias", TARGET_HOST, "nginx:alpine")
    for _ in range(30):
        probe = sh("docker", "exec", TARGET_NAME, "wget", "-q", "-O", "-", "http://127.0.0.1/", check=False)
        if "nginx" in probe.lower():
            return
        time.sleep(1)
    raise SystemExit("the throwaway target did not start")


def run_loadgen(proxy: str, engagement: str | None, mode: str, requests: int, concurrency: int) -> dict:
    host, _, port = proxy.partition(":")
    args = [host, port, TARGET_HOST, "80", mode, str(requests), str(concurrency)] + ([engagement] if engagement else [])
    out = compose("exec", "-T", "tool-runner", "python3", "-c", LOADGEN, *args, timeout=900)
    return json.loads(out.strip().splitlines()[-1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--requests", type=int, default=100, help="requests per configuration")
    parser.add_argument("--concurrency", default="1,2,8", help="comma-separated client concurrencies")
    parser.add_argument("--dns-host", default="cloud.example.com", help="name whose resolution is timed (DNS only, no connection)")
    parser.add_argument("--control-plane", default="http://127.0.0.1:8000")
    parser.add_argument("--proxy", default="egress-proxy:3128", help="proxy address as seen from the tool-runner")
    parser.add_argument("--out", help="also write the result as JSON to this file")
    args = parser.parse_args()
    token = os.environ.get("INTERNAL_API_TOKEN", "change-me-in-dev")
    levels = [int(c) for c in args.concurrency.split(",") if c.strip()]
    if not 1 <= args.requests <= 2000 or not levels or max(levels) > 32:
        raise SystemExit("--requests must be 1..2000 and concurrency at most 32")

    result: dict = {"measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "requests_per_config": args.requests}
    start_target()
    engagement = create_engagement(args.control_plane, token)
    try:
        result["engagement_id"] = engagement
        stages = compose("exec", "-T", "egress-proxy", "python", "-c", STAGES, args.dns_host, engagement, TARGET_HOST,
                         str(max(20, min(args.requests, 100))))
        result["stages"] = json.loads(stages.strip().splitlines()[-1])
        result["proxy"] = []
        for mode in ("connect", "http"):
            for resolve in ("host", "header"):
                for concurrency in levels:
                    row = run_loadgen(args.proxy, engagement if resolve == "header" else None, mode, args.requests, concurrency)
                    result["proxy"].append({"mode": mode, "engagement_resolved_by": resolve, **row})
                    print(f"{mode:8s} resolve={resolve:6s} c={concurrency:<3d} {row['rps']:8.2f} req/s  "
                          f"p50 {row['p50_ms']:7.1f} ms  p95 {row['p95_ms']:7.1f} ms  {row['statuses']}", flush=True)
    finally:
        try:
            delete_engagement(engagement)
        finally:
            sh("docker", "rm", "-f", TARGET_NAME, check=False)

    print(json.dumps(result["stages"], indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
