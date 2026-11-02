#!/usr/bin/env python3
"""Prove the out-of-band chain end to end on the dev stack (REQ-COVER-004, REQ-OOB-002; GitHub #76).

What it shows: a real nuclei pass of the platform's own interaction-server mode, in the real tool-runner image, through
the real egress proxy (with the run's signed identity) and the real interaction server, confirms blind vulnerabilities
against a stand-in target - and it does so for callback templates that carry no `oast` tag, which the earlier tag-based
selection never ran.

The target is a throwaway container of this script: wherever a request mentions a name under the interaction server's
domain, it calls that name back, as a backend that is vulnerable to blind injection would. It is on the dev networks
only, belongs to a throwaway engagement and is removed again. Nothing here touches a real system.

    docker compose --profile runner --profile oob up -d      # the dev stack, with the interaction server
    python3 scripts/verify_oob_dev.py [--part cves_legacy]

A callback from the internet needs a delegated domain; inside the stack the stand-in calls the interaction server
directly, which is all this check needs.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = "asm_business"
TOY = "oobtoy"
DOMAIN = "oob.invalid"  # the dev default of OOB_DOMAIN

TOY_SOURCE = r'''
import re, sys, threading, urllib.parse, http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
DOMAIN, SERVER = sys.argv[1], (sys.argv[2], int(sys.argv[3]))
NAME = re.compile(r"[a-z0-9][a-z0-9.-]*\." + re.escape(DOMAIN), re.I)

def call_back(name):
    try:
        conn = http.client.HTTPConnection(*SERVER, timeout=5)
        conn.request("GET", "/", headers={"Host": name})
        conn.getresponse().read()
        conn.close()
    except Exception as exc:
        print("callback failed", name, exc, flush=True)

class H(BaseHTTPRequestHandler):
    def _all(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length).decode("latin-1") if length else ""
        text = urllib.parse.unquote(self.requestline + "\n" + str(self.headers) + "\n" + body)
        for name in {m.group(0).lower() for m in NAME.finditer(text)}:
            threading.Thread(target=call_back, args=(name,), daemon=True).start()
        payload = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _all
    def log_message(self, *a): pass

ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
'''

SEED_SOURCE = r'''
import datetime as dt, json, uuid
from app.db.base import SessionLocal
from app.models.engagement import Engagement, ScopeAsset
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
db = SessionLocal()
now = dt.datetime.now(dt.timezone.utc)
owner = User(email=f"smoke-{uuid.uuid4().hex[:6]}@example.test", display_name="smoke", role="operator", status="active",
             must_change_password=False, password_hash=hash_secret("x"))
db.add(owner); db.flush()
eng = Engagement(title="egress-identity smoke oob", source="own_domain", status="active", owner_user_id=owner.id,
                 authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(hours=4))
db.add(eng); db.flush()
db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="oobtoy", active_allowed=True, authorization_verified=True))
run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running", trigger="manual")
db.add(run); db.commit()
print(json.dumps({"engagement": str(eng.id), "run": str(run.id)}))
'''

CLEANUP_SOURCE = r'''
from sqlalchemy import select, delete
from app.db.base import SessionLocal
from app.api.engagements import _delete_engagement_dependents
from app.models.engagement import Engagement
from app.models.user import User, UserSession
db = SessionLocal()
for eid in list(db.scalars(select(Engagement.id).where(Engagement.title.like("egress-identity smoke%")))):
    _delete_engagement_dependents(db, eid)
    db.execute(delete(Engagement).where(Engagement.id == eid))
smoke = select(User.id).where(User.email.like("smoke-%@example.test")).scalar_subquery()
db.execute(delete(UserSession).where(UserSession.user_id.in_(smoke)))
db.execute(delete(User).where(User.email.like("smoke-%@example.test")))
db.commit()
'''

RUN_SOURCE = r'''
import json, sys, time
from app import tool_runner_client as trc
seed, part = json.loads(sys.argv[1]), sys.argv[2]
t0 = time.time()
r = trc.tool_runner.run("nuclei", "http://oobtoy:8000", {"mode": "oob", "part": part}, scan_run_id=seed["run"],
                        engagement_id=seed["engagement"], budget_s=290)
ids = []
for line in (r.get("stdout") or "").splitlines():
    if line.startswith("{"):
        try:
            ids.append(json.loads(line).get("template-id"))
        except ValueError:
            pass
print(json.dumps({"success": r.get("success"), "error_reason": r.get("error_reason"), "exit_code": r.get("exit_code"),
                  "seconds": round(time.time() - t0), "template_ids": sorted(set(i for i in ids if i)),
                  "oob_server": trc.OOB_SERVER_URL}))
'''


def sh(*args: str, stdin: str | None = None, check: bool = True) -> str:
    done = subprocess.run(args, input=stdin, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise SystemExit(f"failed: {' '.join(args)}\n{done.stderr.strip()[:600]}")
    return done.stdout


def running(*names: str) -> list[str]:
    out = sh("docker", "ps", "--format", "{{.Names}}").split()
    return [n for n in names if f"{PROJECT}-{n}-1" not in out]


def untagged(runner_image: str, ids: list[str]) -> list[str]:
    """Of the matched templates, those that carry no `oast` tag (found by looking in the runner image)."""
    script = (
        "for id in " + " ".join(ids) + "; do "
        "f=$(grep -rl \"^id: $id\\$\" /opt/nuclei-templates/http 2>/dev/null | head -1); [ -z \"$f\" ] && continue; "
        "grep -qE '^\\s*tags:.*\\boast\\b' \"$f\" || echo \"$id\"; done"
    )
    return sh("docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", runner_image, "-c", script).split()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--part", default="cves_legacy", help="which interaction-server pass to run")
    parser.add_argument("--expect-untagged", action="store_true",
                        help="also require a confirmed template without the `oast` tag (true of cves_legacy and generic_a "
                             "against this stand-in; not of every pass)")
    args = parser.parse_args()
    missing = running("control-plane", "worker", "egress-proxy", "tool-runner", "interactsh", "oob-relay")
    if missing:
        print(f"the dev stack is not fully up (missing: {', '.join(missing)}); start it with:\n"
              "  docker compose --profile runner --profile oob up -d", file=sys.stderr)
        return 2
    cp, worker = f"{PROJECT}-control-plane-1", f"{PROJECT}-worker-1"
    runner_image = sh("docker", "inspect", f"{PROJECT}-tool-runner-1", "--format", "{{.Config.Image}}").strip()
    sh("docker", "rm", "-f", TOY, check=False)
    ok = False
    with tempfile.TemporaryDirectory(prefix="asm-oob-") as tmp:
        toy = Path(tmp) / "toy.py"
        toy.write_text(TOY_SOURCE)
        try:
            sh("docker", "run", "-d", "--name", TOY, "--network", "asm_egress", "-v", f"{toy}:/toy.py:ro",
               "--entrypoint", "python", f"{PROJECT}-worker:latest", "/toy.py", DOMAIN, "interactsh-edge", "8080")
            sh("docker", "network", "connect", "asm_edge", TOY)
            seed = sh("docker", "exec", "-i", cp, "python", "-", stdin=SEED_SOURCE).strip().splitlines()[-1]
            result = json.loads(sh(
                "docker", "exec", "-e", "EGRESS_RUN_TOKENS=true", "-i", worker, "python", "-", seed, args.part,
                stdin=RUN_SOURCE).strip().splitlines()[-1])
            ids = result["template_ids"]
            extra = untagged(runner_image, ids) if ids else []
            print(f"pass {args.part}: success={result['success']} exit={result['exit_code']} {result['seconds']}s "
                  f"server={result['oob_server']}")
            print(f"  confirmed {len(ids)} callback templates, {len(extra)} of them without the `oast` tag"
                  + (f" ({', '.join(extra[:5])})" if extra else ""))
            ok = bool(result["success"]) and len(ids) > 0 and (len(extra) > 0 or not args.expect_untagged)
            print(("OK: the chain works" + (" and reaches templates the tag-based selection missed" if extra else ""))
                  if ok else "FAILED: no callback was confirmed" + (", or no untagged template was reached" if args.expect_untagged else ""))
        finally:
            sh("docker", "rm", "-f", TOY, check=False)
            sh("docker", "exec", "-i", cp, "python", "-", stdin=CLEANUP_SOURCE, check=False)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
