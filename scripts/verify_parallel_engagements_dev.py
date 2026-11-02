#!/usr/bin/env python3
"""Prove on the dev stack that two engagements may cover the same host and both run (REQ-EGRESS-006..011/014, GitHub #81).

The shape is the incident of int on 2026-10-20: a MONITORING engagement scoped by name and an ASSESSMENT scoped by the IP
address that name resolves to, both active, both testing the same server at the same time. Before the signed run identity
the proxy guessed the engagement from the destination, found two, and refused both (`409 ambiguous_host`): every
`http_request` of the agent was lost and nothing was audited.

What it shows, with the real control plane, gateway, worker, egress proxy and tool-runner:

  1. Both engagements' `http_request` calls (the agent's own tool) are authorized and **return the target's real response**,
     concurrently, through the proxy, with no setting passed in by this script: the compose defaults decide.
  2. Every request is audited under the engagement it belongs to, with its own run, and none is refused or attributed to the
     other engagement.
  3. The activation guard (REQ-CONCUR-003) turns the overlap into a notice that names the other engagement; with the
     identity switched off it would refuse (shown in-process for contrast).
  4. A request with no identity at all is refused, not guessed.

The target is a throwaway container of this script on the dev networks and both engagements are throwaway ones; all are
removed again. Nothing here touches a real system.

    docker compose --profile runner up -d       # the dev stack
    python3 scripts/verify_parallel_engagements_dev.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = "asm_business"
TOY = "partoy"
TITLE = "parallel-engagements smoke"
MARK = "partoy-ok-7c1d"

TOY_SOURCE = r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>partoy</title></head><body>''' + MARK + r'''</body></html>"
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
'''

SEED_SOURCE = r'''
import datetime as dt, json, sys, uuid
from app.db.base import SessionLocal
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
ip = sys.argv[1]
db = SessionLocal()
now = dt.datetime.now(dt.timezone.utc)
owner = User(email=f"smoke-{uuid.uuid4().hex[:6]}@example.test", display_name="smoke", role="operator", status="active",
             must_change_password=False, password_hash=hash_secret("x"))
db.add(owner); db.flush()

def engagement(title, mode, scope_type, scope_value, status="active", run=True):
    kw = dict(target_review_state="confirmed") if mode == "monitoring" else {}
    eng = Engagement(title=title, source="own_domain", status=status, owner_user_id=owner.id, operating_mode=mode,
                     ai_testing_allowed=True, authorized_from=now - dt.timedelta(hours=1),
                     authorized_until=now + dt.timedelta(hours=4), **kw)
    db.add(eng); db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type=scope_type, value=scope_value, active_allowed=True,
                      authorization_verified=True))
    for cat in ("fingerprint", "vuln"):
        db.add(ToolGrant(engagement_id=eng.id, tool_category=cat, mode="active", requires_manual_approval=False))
    out = {"engagement": str(eng.id)}
    if run:
        r = ScanRun(engagement_id=eng.id, phase="agent", state="running", trigger="manual",
                    supervision="unattended" if mode == "monitoring" else "attended")
        db.add(r); db.flush()
        out["run"] = str(r.id)
    return out

monitor = engagement("parallel-engagements smoke monitor", "monitoring", "domain", "partoy")
assessment = engagement("parallel-engagements smoke assessment", "assessment", "ip", ip)
# A draft assessment that names the same host as the monitor, for the activation guard.
candidate = engagement("parallel-engagements smoke candidate", "assessment", "domain", "partoy", status="draft", run=False)
db.commit()
print(json.dumps({"monitor": monitor, "assessment": assessment, "candidate": candidate, "ip": ip}))
'''

WORKER_SOURCE = r'''
import json, sys, threading, uuid
from app import tool_runner_client as trc
from app.control_plane_client import client
seed = json.loads(sys.argv[1])
MARK = sys.argv[2]
cases = {"monitor": ("partoy", "http://partoy:8000"), "assessment": (seed["ip"], f"http://{seed['ip']}:8000")}
out = {name: [] for name in cases}

def work(name):
    host, url = cases[name]
    eng, run = seed[name]["engagement"], seed[name]["run"]
    for _ in range(3):
        payload = {"tool": "http_request", "category": "vuln", "mode": "active", "target": host,
                   "args": {"method": "GET", "path": "/"}, "is_automated": True, "phase": "agent", "scan_run_id": run,
                   "rationale": "verify_parallel_engagements_dev"}
        d = client.authorize(uuid.UUID(eng), payload)
        if not d["allowed"]:
            out[name].append({"authorized": False, "reason": d["reason"]})
            continue
        r = trc.tool_runner.run("http_request", url, {"method": "GET", "path": "/"}, scan_run_id=run, engagement_id=eng)
        body = r.get("stdout") or r.get("response") or ""  # the runner returns the raw response as stdout
        out[name].append({"authorized": True, "success": bool(r.get("success")), "real_response": MARK in body,
                          "status_line": body.splitlines()[0][:40] if body else ""})

threads = [threading.Thread(target=work, args=(n,)) for n in cases]
[t.start() for t in threads]; [t.join(300) for t in threads]
print("RESULT " + json.dumps(out))
'''

AUDIT_SOURCE = r'''
import json, sys, uuid
from collections import Counter
from sqlalchemy import select
from app.db.base import SessionLocal
from app.models.audit import AuditLog
seed = json.loads(sys.argv[1]); db = SessionLocal()
out = {}
for name in ("monitor", "assessment"):
    eid, run = seed[name]["engagement"], seed[name]["run"]
    rows = db.scalars(select(AuditLog).where(AuditLog.engagement_id == uuid.UUID(eid), AuditLog.action == "network_request")).all()
    out[name] = {
        "requests": Counter((r.decision, r.reason) for r in rows),
        "runs": sorted({r.payload.get("scan_run_id") for r in rows}),
        "own_run": run,
    }
out = {k: {"requests": [[*a, n] for a, n in v["requests"].items()], "runs": v["runs"], "own_run": v["own_run"]} for k, v in out.items()}
print(json.dumps(out))
'''

GUARD_SOURCE = r'''
import json, sys, uuid
from types import SimpleNamespace
from unittest import mock
from fastapi import HTTPException
from sqlalchemy import select
from app.api import engagements as api
from app.config import get_settings
from app.db.base import SessionLocal
from app.models.engagement import Engagement, ScopeAsset
seed = json.loads(sys.argv[1]); db = SessionLocal()
cand = db.get(Engagement, uuid.UUID(seed["candidate"]["engagement"]))
assets = list(db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == cand.id)))
out = {"require_token_in_this_container": get_settings().egress_require_token}
conflicts = api._check_no_active_scope_overlap(db, cand, assets)
out["conflicts"] = [e.title for e, _ in conflicts]
out["notice"] = api._overlap_notice(conflicts)
with mock.patch.object(api, "get_settings", return_value=SimpleNamespace(egress_require_token=False)):
    try:
        api._check_no_active_scope_overlap(db, cand, assets)
        out["refused_when_off"] = None
    except HTTPException as exc:
        out["refused_when_off"] = [exc.status_code, str(exc.detail)[:90]]
print(json.dumps(out))
'''

CLEANUP_SOURCE = r'''
from sqlalchemy import select, delete
from app.db.base import SessionLocal
from app.api.engagements import _delete_engagement_dependents
from app.models.engagement import Engagement
from app.models.user import User, UserSession
db = SessionLocal()
for eid in list(db.scalars(select(Engagement.id).where(Engagement.title.like("parallel-engagements smoke%")))):
    _delete_engagement_dependents(db, eid)
    db.execute(delete(Engagement).where(Engagement.id == eid))
smoke = select(User.id).where(User.email.like("smoke-%@example.test")).scalar_subquery()
db.execute(delete(UserSession).where(UserSession.user_id.in_(smoke)))
db.execute(delete(User).where(User.email.like("smoke-%@example.test")))
db.commit()
'''

TOKENLESS_SOURCE = r'''
import urllib.error, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": "http://egress-proxy:3128"}))
try:
    opener.open("http://partoy:8000/", timeout=8)
    print("ALLOWED")
except urllib.error.HTTPError as e:
    print(f"{e.code} {e.read()[:60].decode()}")
'''


def sh(*args: str, stdin: str | None = None, check: bool = True) -> str:
    done = subprocess.run(args, input=stdin, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:4])} failed ({done.returncode}): {(done.stderr or done.stdout).strip()[-600:]}")
    return done.stdout


def last_line(text: str) -> str:
    return text.strip().splitlines()[-1]


def main() -> int:
    up = set(sh("docker", "ps", "--format", "{{.Names}}").split())
    missing = [n for n in ("control-plane", "worker", "egress-proxy", "tool-runner", "raw-egress-gateway") if f"{PROJECT}-{n}-1" not in up]
    if missing:
        print(f"the dev stack is not fully up (missing: {', '.join(missing)}); start it with:\n"
              "  docker compose --profile runner up -d", file=sys.stderr)
        return 2
    cp, worker = f"{PROJECT}-control-plane-1", f"{PROJECT}-worker-1"
    cpx = lambda source, *a: sh("docker", "exec", "-i", cp, "python", "-", *a, stdin=source)  # noqa: E731
    wx = lambda source, *a: sh("docker", "exec", "-i", worker, "python", "-", *a, stdin=source)  # noqa: E731
    sh("docker", "rm", "-f", TOY, check=False)
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="asm-par-") as tmp:
        toy = Path(tmp) / "toy.py"
        toy.write_text(TOY_SOURCE)
        try:
            sh("docker", "run", "-d", "--name", TOY, "--network", "asm_egress", "-v", f"{toy}:/toy.py:ro",
               "--entrypoint", "python", f"{PROJECT}-worker:latest", "/toy.py")
            ip = sh("docker", "inspect", "-f", '{{(index .NetworkSettings.Networks "asm_egress").IPAddress}}', TOY).strip()
            switches = {c: dict(l.split("=", 1) for l in sh("docker", "exec", c, "env").splitlines() if l.startswith(("EGRESS_REQUIRE_TOKEN=", "EGRESS_RUN_TOKENS=")))
                        for c in (cp, f"{PROJECT}-egress-proxy-1", worker)}
            print(f"0. the identity switches in the running containers (compose defaults, nothing passed in): {switches}")
            seed_text = last_line(cpx(SEED_SOURCE, ip))
            seed = json.loads(seed_text)
            print(f"   monitor scoped by NAME 'partoy', assessment scoped by IP {ip}: the same server, both active")

            result = json.loads(last_line(wx(WORKER_SOURCE, seed_text, MARK)).removeprefix("RESULT "))
            print("1. http_request, concurrently, through the proxy:")
            for name, rows in result.items():
                ok = [r for r in rows if r.get("authorized") and r.get("success") and r.get("real_response")]
                print(f"   {name:10} {len(ok)}/{len(rows)} authorized, executed and returned the target's real response ({rows[0].get('status_line', rows[0])})")
                if len(ok) != 3:
                    failures.append(f"{name}: only {len(ok)} of 3 http_request calls returned the real response: {rows}")

            audit = json.loads(last_line(cpx(AUDIT_SOURCE, seed_text)))
            print("2. what the proxy audited, per engagement:")
            for name, a in audit.items():
                print(f"   {name:10} requests {a['requests']}; runs seen {[r[-6:] for r in a['runs']]}, own run {a['own_run'][-6:]}")
                allowed = sum(n for d, _, n in a["requests"] if d == "ALLOW")
                refused = [r for r in a["requests"] if r[0] != "ALLOW"]
                if allowed < 3 or refused or a["runs"] != [a["own_run"]]:
                    failures.append(f"{name}: audit is wrong (allowed {allowed}, refused {refused}, runs {a['runs']})")

            guard = json.loads(last_line(cpx(GUARD_SOURCE, seed_text)))
            print(f"3. activation of a third assessment naming the same host: {guard['conflicts']} -> notice: {guard['notice']}")
            print(f"   with the identity switched off the same call would be refused: {guard['refused_when_off']}")
            if not guard["require_token_in_this_container"] or guard["conflicts"] != ["parallel-engagements smoke monitor"] \
                    or not guard["notice"] or not guard["refused_when_off"] or guard["refused_when_off"][0] != 409:
                failures.append(f"the activation guard did not behave as REQ-EGRESS-011 says: {guard}")

            tokenless = last_line(wx(TOKENLESS_SOURCE))
            print(f"4. a request with no identity at all: {tokenless}")
            if not tokenless.startswith("407"):
                failures.append(f"a request with no identity was not refused: {tokenless}")
        finally:
            sh("docker", "rm", "-f", TOY, check=False)
            cpx(CLEANUP_SOURCE)
    print("OK: two engagements covered one host and both ran" if not failures else "FAILED:\n  - " + "\n  - ".join(failures))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
