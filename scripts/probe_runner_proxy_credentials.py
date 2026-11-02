#!/usr/bin/env python3
"""Step 0 of GitHub #81: which runner tools send proxy credentials, and on which kind of request?

The egress proxy cannot tell which engagement a request belongs to (it guesses from the destination). The plan is a
signed run token that every tool presents as proxy credentials (`http://asm:<token>@egress-proxy:3128`). Whether that
works depends on each tool, so this script finds out instead of assuming: it starts a recording stand-in proxy inside
a throwaway container of the real tool-runner image (no network: loopback only, nothing leaves the container), points
each tool at it with a sentinel password in the proxy URL, sends one plain-HTTP and one HTTPS (CONNECT) request to a
name that does not exist, and records whether `Proxy-Authorization` arrived and carried the sentinel.

Nothing here touches a real target or the running stack. The stand-in proxy answers every request itself.

    python3 scripts/probe_runner_proxy_credentials.py [--image asm_business-tool-runner:latest] [--json]

A second group of cases covers the tools that cannot send credentials at all (testssl, the screenshot browser): they are
pointed at the runner image's loopback forwarder (tool-runner/egress_forwarder.py, REQ-EGRESS-010), which adds them, and
the same recording stand-in proxy shows whether the credentials arrived.

The result is recorded with GitHub #81 (the engagement identity of the egress proxy); run it again when the runner image
changes.
"""

from __future__ import annotations

import argparse
import base64
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SENTINEL = "SENTINEL-RUN-TOKEN-0123456789abcdef"
USER = "asm"
PROXY_PORT = 3129

# The stand-in proxy. Stdlib only, runs under the image's python3. One JSON line per connection.
PROXY_SOURCE = r'''
import asyncio, base64, json, sys

LOG = "/probe/log.jsonl"

async def handle(reader, writer):
    try:
        line = (await asyncio.wait_for(reader.readline(), 5)).decode("latin-1").strip()
        headers = {}
        while True:
            raw = await asyncio.wait_for(reader.readline(), 5)
            if raw in (b"\r\n", b"\n", b""):
                break
            if b":" in raw:
                k, v = raw.decode("latin-1").split(":", 1)
                headers[k.strip().lower()] = v.strip()
        auth = headers.get("proxy-authorization", "")
        user = password = None
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("latin-1")
                # nuclei's raw (unsafe-template) client puts the URL scheme in front; the proxy accepts exactly that
                for scheme in ("http://", "https://"):
                    if decoded.startswith(scheme):
                        decoded = decoded[len(scheme):]
                        break
                user, _, password = decoded.partition(":")
            except Exception:
                pass
        with open(LOG, "a") as fh:
            fh.write(json.dumps({
                "request": line.split(" ")[0], "target": line.split(" ")[1] if " " in line else "",
                "proxy_authorization": bool(auth), "user": user, "password_is_sentinel": password == sys.argv[1],
            }) + "\n")
        if line.startswith("CONNECT"):
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", int(sys.argv[2]))
    async with server:
        await server.serve_forever()

asyncio.run(main())
'''

NUCLEI_UNSAFE_TEMPLATE = """id: probe-raw
info:
  name: probe-raw
  author: probe
  severity: info
http:
  - unsafe: true
    raw:
      - |+
        GET / HTTP/1.1
        Host: {{Hostname}}

"""

NUCLEI_TEMPLATE = """id: probe
info:
  name: probe
  author: probe
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
"""


def cases(proxy: str, hostport: str) -> list[tuple[str, str, str]]:
    """(tool, scheme, shell command). The flags mirror how worker/app/tool_runner_client.py builds each command."""
    out: list[tuple[str, str, str]] = []
    for scheme in ("http", "https"):
        url = f"{scheme}://probe.test/"
        out += [
            ("curl", scheme, f"curl -sS -k -m 8 -x {proxy} {url} -o /dev/null"),
            ("httpx", scheme, f"echo {url} | httpx -silent -timeout 5 -retries 0 -proxy {proxy}"),
            ("nuclei", scheme, f"nuclei -u {url} -t /probe/tpl.yaml -p {proxy} -timeout 5 -retries 0 -silent -disable-update-check -no-interactsh"),
            # nuclei's raw HTTP client (every `unsafe: true` template) is a different code path and encodes the
            # credentials differently: found on int, where it made 238 requests of one scan come back as refused.
            ("nuclei raw", scheme, f"nuclei -u {url} -t /probe/unsafe.yaml -p {proxy} -timeout 5 -retries 0 -silent -disable-update-check -no-interactsh"),
            ("ffuf", scheme, f"ffuf -s -u {scheme}://probe.test/FUZZ -w /probe/words.txt -x {proxy} -timeout 5"),
            ("katana", scheme, f"katana -u {url} -proxy {proxy} -d 1 -timeout 5 -silent -no-color"),
            ("wafw00f", scheme, f"wafw00f {url} -p {proxy}"),
            ("nikto", scheme, f"nikto -h {url} -useproxy {proxy} -maxtime 8 -nointeractive"),
            ("chromium", scheme, f"timeout 25 chromium --headless --no-sandbox --disable-gpu --proxy-server={proxy} --dump-dom {url}"),
        ]
    # testssl only knows host:port and has no place for credentials, and the browser refuses a proxy URL that has some:
    # directly they get nothing (the verdict says why). Through the forwarder they must.
    out.append(("testssl", "https", f"timeout 30 testssl --quiet --protocols --proxy {hostport} --ip 203.0.113.9 probe.test:443"))
    return out


FORWARDER = "via forwarder"


def forwarder_cases() -> list[tuple[str, str, str]]:
    """(tool, scheme, shell command): the same two tools, pointed at the loopback forwarder instead."""
    proxy = "127.0.0.1:$FWD_PORT"
    out = [("testssl", FORWARDER, f"timeout 40 testssl --quiet --protocols --proxy {proxy} --ip 203.0.113.9 probe.test:443")]
    for scheme in ("http", "https"):
        out.append((
            "chromium", f"{FORWARDER} {scheme}",
            f"timeout 25 chromium --headless --no-sandbox --disable-gpu --proxy-server=http://{proxy} --dump-dom {scheme}://probe.test/",
        ))
    return out


def run_case(image: str, workdir: Path, tool: str, scheme: str, command: str) -> dict:
    log = workdir / "log.jsonl"
    log.unlink(missing_ok=True)
    (workdir / "fwd.port").unlink(missing_ok=True)
    forwarder = scheme.startswith(FORWARDER)
    start_forwarder = (
        f"ASM_PROXY_CREDENTIAL={SENTINEL} python3 /probe/egress_forwarder.py --upstream 127.0.0.1:{PROXY_PORT} --user {USER} "
        "--port-file /probe/fwd.port --max-lifetime 120 & F=$!; "
        "for i in $(seq 1 50); do [ -s /probe/fwd.port ] && break; sleep 0.1; done; FWD_PORT=$(cat /probe/fwd.port); "
        if forwarder else ""
    )
    script = (
        f"python3 /probe/proxy.py {SENTINEL} {PROXY_PORT} & P=$!; sleep 1; {start_forwarder}"
        f"( {command} ) >/probe/tool.out 2>&1; echo $? >/probe/tool.rc; sleep 1; kill $P {'$F ' if forwarder else ''}2>/dev/null; true"
    )
    done = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", "-v", f"{workdir}:/probe", image, "-c", script],
        capture_output=True, text=True, timeout=120,
    )
    seen = []
    if log.exists():
        seen = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    want = "CONNECT" if scheme.endswith("https") or tool in ("testssl", "nuclei raw") else None
    relevant = [s for s in seen if (s["request"] == "CONNECT") == (want == "CONNECT")] or seen
    sent = [s for s in relevant if s["proxy_authorization"]]
    rc = (workdir / "tool.rc").read_text().strip() if (workdir / "tool.rc").exists() else "?"
    out = (workdir / "tool.out").read_text(errors="replace") if (workdir / "tool.out").exists() else ""
    if not seen:
        verdict = "no request reached the proxy"
        if "ERR_NO_SUPPORTED_PROXIES" in out:
            verdict = "the browser refuses a proxy URL that carries credentials (ERR_NO_SUPPORTED_PROXIES)"
        elif tool == "testssl" and not forwarder:
            verdict = "no way to give testssl credentials (--proxy takes host:port only)"
    elif any(s["password_is_sentinel"] and s["user"] == USER for s in sent):
        verdict = "credentials sent" + (" (on every request)" if len(sent) == len(relevant) else " (on some requests only)")
        if forwarder:
            verdict += ", added by the forwarder"
    elif sent:
        verdict = "authorization header sent, but not our credentials"
    else:
        verdict = "NO credentials"
    return {
        "tool": tool, "scheme": scheme, "requests": len(seen), "request_kinds": sorted({s["request"] for s in seen}),
        "verdict": verdict, "exit_code": rc, "docker_rc": done.returncode,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", default="asm_business-tool-runner:latest")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--only-forwarder", action="store_true", help="run only the cases that go through the loopback forwarder")
    args = parser.parse_args()
    if shutil.which("docker") is None:
        print("docker is required", file=sys.stderr)
        return 2
    proxy = f"http://{USER}:{SENTINEL}@127.0.0.1:{PROXY_PORT}"
    with tempfile.TemporaryDirectory(prefix="asm-proxy-probe-") as tmp:
        workdir = Path(tmp)
        (workdir / "proxy.py").write_text(PROXY_SOURCE)
        shutil.copy(Path(__file__).resolve().parents[1] / "tool-runner" / "egress_forwarder.py", workdir / "egress_forwarder.py")
        (workdir / "tpl.yaml").write_text(NUCLEI_TEMPLATE)
        (workdir / "unsafe.yaml").write_text(NUCLEI_UNSAFE_TEMPLATE)
        (workdir / "words.txt").write_text("probe\n")
        workdir.chmod(0o777)
        results = [run_case(args.image, workdir, *case) for case in [*([] if args.only_forwarder else cases(proxy, f"127.0.0.1:{PROXY_PORT}")), *forwarder_cases()]]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"{'tool':9} {'scheme':6} {'requests':8} {'kinds':14} verdict (tool exit code)")
        for r in results:
            print(f"{r['tool']:9} {r['scheme']:6} {r['requests']:<8} {','.join(r['request_kinds']) or '-':14} {r['verdict']} ({r['exit_code']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
