#!/usr/bin/env python3
"""Prove on the dev stack that a wait for one decision does not stop the run's other actions (REQ-APPROVAL-008, #83).

What it shows, with the real control plane, gateway, worker, egress proxy and tool-runner:

  1. One action of an attended run needs approval (an approval-gated `nuclei` check) and the worker waits for the
     decision. The run is `waiting_approval` with the reason `approval_wait`.
  2. While that decision is open, the run's other checks (httpx, through the runner and the proxy, with the run's signed
     identity) are authorized and execute. Before the fix every one of them was refused `scan_run_not_active`.
  3. The decision is made (the approve endpoint's own state change). The waiting check is then claimed through the gateway
     and executes, and the run is `running` again with the reason removed.
  4. Negative, on the deployed gateway: a run that is `waiting_approval` with no reason, with another reason, or parked is
     still refused `scan_run_not_active`.
  5. The audit trail has no `scan_run_not_active` denial for the run's real checks, and a transition to `waiting_approval`
     and back.

The target is a throwaway container of this script on the dev networks, the engagement is a throwaway one, and both are
removed again. Nothing here touches a real system.

    docker compose --profile runner up -d       # the dev stack
    python3 scripts/verify_approval_wait_dev.py
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT = "asm_business"
TOY = "waitoy"
TITLE = "approval-wait smoke"

TOY_SOURCE = r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>waitoy</title></head><body>ok</body></html>"
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
'''

SEED_SOURCE = r'''
import datetime as dt, json, uuid
from app.db.base import SessionLocal
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
db = SessionLocal()
now = dt.datetime.now(dt.timezone.utc)
owner = User(email=f"smoke-{uuid.uuid4().hex[:6]}@example.test", display_name="smoke", role="operator", status="active",
             must_change_password=False, password_hash=hash_secret("x"))
db.add(owner); db.flush()
eng = Engagement(title="approval-wait smoke", source="own_domain", status="active", owner_user_id=owner.id,
                 operating_mode="assessment", authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(hours=4))
db.add(eng); db.flush()
db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="waitoy", active_allowed=True, authorization_verified=True))
db.add(ToolGrant(engagement_id=eng.id, tool_category="fingerprint", mode="active", requires_manual_approval=False))
db.add(ToolGrant(engagement_id=eng.id, tool_category="vuln", mode="active", requires_manual_approval=True))
run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running", trigger="manual", supervision="attended")
db.add(run); db.commit()
print(json.dumps({"engagement": str(eng.id), "run": str(run.id)}))
'''

STATE_SOURCE = r'''
import json, sys
from sqlalchemy import select
from app.db.base import SessionLocal
from app.models.approval import ApprovalRequest
from app.models.scan_run import ScanRun
import uuid
seed = json.loads(sys.argv[1]); db = SessionLocal()
run = db.get(ScanRun, uuid.UUID(seed["run"]))
appr = db.scalars(select(ApprovalRequest).where(ApprovalRequest.engagement_id == uuid.UUID(seed["engagement"]),
                                                ApprovalRequest.state == "requested")).first()
print(json.dumps({"state": run.state, "reason": run.state_reason, "approval": str(appr.id) if appr else None,
                  "budget_used": run.budget_tool_calls_used}))
'''

APPROVE_SOURCE = r'''
import datetime as dt, sys, uuid
from app.db.base import SessionLocal
from app.models.approval import ApprovalRequest
db = SessionLocal()
a = db.get(ApprovalRequest, uuid.UUID(sys.argv[1]))
a.state, a.approved_by, a.approved_at = "approved", "smoke@example.test", dt.datetime.now(dt.timezone.utc)
db.commit()
print("approved")
'''

SHAPE_SOURCE = r'''
import json, sys, uuid
from app.db.base import SessionLocal
from app.models.scan_run import ScanRun
seed, state, reason, parked = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3] or None, sys.argv[4] == "parked"
db = SessionLocal()
run = db.get(ScanRun, uuid.UUID(seed["run"]))
run.state, run.state_reason = state, reason
run.checkpoint = {"parked": {"approval_id": "x", "since": "2026-01-01T00:00:00+00:00"}} if parked else None
db.commit()
print("set", state, reason, parked)
'''

AUDIT_SOURCE = r'''
import json, sys, uuid
from collections import Counter
from sqlalchemy import select
from app.db.base import SessionLocal
from app.models.audit import AuditLog
seed = json.loads(sys.argv[1]); db = SessionLocal()
rows = db.scalars(select(AuditLog).where(AuditLog.engagement_id == uuid.UUID(seed["engagement"])).order_by(AuditLog.ts)).all()
calls = Counter((r.payload.get("tool"), r.decision, r.reason) for r in rows if r.action == "tool_call" and r.payload.get("scan_run_id") == seed["run"])
transitions = [r.payload.get("state") for r in rows if r.action == "scan_run_transition"]
print(json.dumps({"calls": [[*k, v] for k, v in sorted(calls.items(), key=str)], "transitions": transitions}))
'''

CLEANUP_SOURCE = r'''
from sqlalchemy import select, delete
from app.db.base import SessionLocal
from app.api.engagements import _delete_engagement_dependents
from app.models.engagement import Engagement
from app.models.user import User, UserSession
db = SessionLocal()
for eid in list(db.scalars(select(Engagement.id).where(Engagement.title.like("approval-wait smoke%")))):
    _delete_engagement_dependents(db, eid)
    db.execute(delete(Engagement).where(Engagement.id == eid))
smoke = select(User.id).where(User.email.like("smoke-%@example.test")).scalar_subquery()
db.execute(delete(UserSession).where(UserSession.user_id.in_(smoke)))
db.execute(delete(User).where(User.email.like("smoke-%@example.test")))
db.commit()
'''

# Runs in the worker container: the real pipeline functions, the real runner and proxy.
WORKER_SOURCE = r'''
import json, os, sys, threading, time
from app import tool_runner_client as trc
from app.tasks import fingerprint
seed = json.loads(sys.argv[1]); eng, run = seed["engagement"], seed["run"]
out = {}

def waiting_action():
    t0 = time.time()
    decision = fingerprint._propose(eng, "nuclei", "vuln", "waitoy", {"mode": "takeover"}, run)
    out["waiting_action"] = {"executed": decision is not None, "reason": (decision or {}).get("reason"),
                             "waited_s": round(time.time() - t0)}

thread = threading.Thread(target=waiting_action, daemon=True)
thread.start()
while not os.path.exists("/tmp/aw-go"):
    time.sleep(0.3)
others = []
for _ in range(3):
    decision = fingerprint._propose(eng, "httpx", "fingerprint", "waitoy", {}, run)
    result = trc.tool_runner.run("httpx", "http://waitoy:8000", {}, scan_run_id=run, engagement_id=eng) if decision else None
    others.append({"authorized": decision is not None, "executed": bool(result and result.get("success"))})
print("OTHERS " + json.dumps(others), flush=True)
thread.join(120)
print("RESULT " + json.dumps(out), flush=True)
'''

NEGATIVE_SOURCE = r'''
import json, sys, uuid
from app.control_plane_client import client
seed = json.loads(sys.argv[1])
payload = {"tool": "httpx", "category": "fingerprint", "mode": "active", "target": "waitoy", "args": {}, "is_automated": True,
           "phase": "fingerprint", "scan_run_id": seed["run"], "rationale": "verify_approval_wait_dev"}
d = client.authorize(uuid.UUID(seed["engagement"]), payload)
print(json.dumps({"allowed": d["allowed"], "reason": d["reason"]}))
'''


def sh(*args: str, stdin: str | None = None, check: bool = True) -> str:
    done = subprocess.run(args, input=stdin, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:4])} failed ({done.returncode}): {(done.stderr or done.stdout).strip()[-600:]}")
    return done.stdout


def last_json(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def running(*names: str) -> list[str]:
    up = set(sh("docker", "ps", "--format", "{{.Names}}").split())
    return [n for n in names if f"{PROJECT}-{n}-1" not in up]


def main() -> int:
    argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    missing = running("control-plane", "worker", "egress-proxy", "tool-runner", "raw-egress-gateway")
    if missing:
        print(f"the dev stack is not fully up (missing: {', '.join(missing)}); start it with:\n"
              "  docker compose --profile runner up -d", file=sys.stderr)
        return 2
    cp, worker = f"{PROJECT}-control-plane-1", f"{PROJECT}-worker-1"
    cpx = lambda source, *a: sh("docker", "exec", "-i", cp, "python", "-", *a, stdin=source)  # noqa: E731
    sh("docker", "rm", "-f", TOY, check=False)
    sh("docker", "exec", worker, "rm", "-f", "/tmp/aw-go", check=False)
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="asm-aw-") as tmp:
        toy = Path(tmp) / "toy.py"
        toy.write_text(TOY_SOURCE)
        proc = None
        try:
            sh("docker", "run", "-d", "--name", TOY, "--network", "asm_egress", "-v", f"{toy}:/toy.py:ro",
               "--entrypoint", "python", f"{PROJECT}-worker:latest", "/toy.py")
            seed_text = cpx(SEED_SOURCE).strip().splitlines()[-1]
            seed = json.loads(seed_text)

            # 1. the worker starts the approval-gated check and waits for the decision
            proc = subprocess.Popen(
                ["docker", "exec", "-i", worker, "python", "-", seed_text],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            proc.stdin.write(WORKER_SOURCE)
            proc.stdin.close()
            state = {}
            for _ in range(120):
                state = last_json(cpx(STATE_SOURCE, seed_text))
                if state["state"] == "waiting_approval" and state["approval"]:
                    break
                time.sleep(0.5)
            print(f"1. the run while the decision is open: state={state['state']} reason={state['reason']} "
                  f"approval={'open' if state['approval'] else 'none'}")
            if (state["state"], state["reason"]) != ("waiting_approval", "approval_wait") or not state["approval"]:
                failures.append("the run did not enter the live wait")

            # 2. the other checks run while it waits
            sh("docker", "exec", worker, "touch", "/tmp/aw-go")
            line = ""
            deadline = time.time() + 240
            while time.time() < deadline:
                line = proc.stdout.readline()
                if line.startswith("OTHERS ") or not line:
                    break
            others = json.loads(line[len("OTHERS "):]) if line.startswith("OTHERS ") else []
            mid = last_json(cpx(STATE_SOURCE, seed_text))
            print(f"2. other checks while it waits: {others}; run still {mid['state']}/{mid['reason']}, budget used {mid['budget_used']}")
            if len(others) != 3 or not all(o["authorized"] and o["executed"] for o in others):
                failures.append("a check of the run was refused or did not execute while one decision was open")
            if (mid["state"], mid["reason"]) != ("waiting_approval", "approval_wait"):
                failures.append("the run left the wait before the decision")

            # 4. negative on the deployed gateway (the waiting check is still open; shapes are set and restored)
            print("4. what the deployed gateway answers for a run that waits for something else:")
            for label, st, reason, parked in [("live wait", "waiting_approval", "approval_wait", ""),
                                              ("no reason", "waiting_approval", "", ""),
                                              ("asset review", "waiting_approval", "asset_review_pending", ""),
                                              ("parked", "waiting_approval", "", "parked"),
                                              ("parked + marker", "waiting_approval", "approval_wait", "parked")]:
                cpx(SHAPE_SOURCE, seed_text, st, reason, parked)
                answer = last_json(sh("docker", "exec", "-i", worker, "python", "-", seed_text, stdin=NEGATIVE_SOURCE))
                expected_allowed = label == "live wait"
                print(f"     {label:16} -> allowed={answer['allowed']} reason={answer['reason']}")
                if answer["allowed"] != expected_allowed or (not expected_allowed and answer["reason"] != "scan_run_not_active"):
                    failures.append(f"the gateway answered {answer} for '{label}'")
            cpx(SHAPE_SOURCE, seed_text, "waiting_approval", "approval_wait", "")  # back to the live wait

            # 3. the decision is made; the waiting check is claimed and executes, the run runs again
            cpx(APPROVE_SOURCE, state["approval"])
            out_text = proc.stdout.read()
            proc.wait(timeout=180)
            result = json.loads([ln for ln in out_text.splitlines() if ln.startswith("RESULT ")][-1][len("RESULT "):])
            after = last_json(cpx(STATE_SOURCE, seed_text))
            print(f"3. after the decision: waiting action {result.get('waiting_action')}; run {after['state']}/{after['reason']}")
            if not result.get("waiting_action", {}).get("executed"):
                failures.append("the approved check did not go through the gateway claim")
            if (after["state"], after["reason"]) != ("running", None):
                failures.append("the run is not running again with the reason removed")

            # 5. the audit trail
            audit = last_json(cpx(AUDIT_SOURCE, seed_text))
            refused = sum(c[3] for c in audit["calls"] if c[2] == "scan_run_not_active")
            print(f"5. audit: transitions {audit['transitions']}; calls {audit['calls']}")
            if "waiting_approval" not in audit["transitions"] or audit["transitions"][-1] != "running":
                failures.append("the audit trail lacks the transition to waiting_approval and back")
            # the only refusals allowed are the four deliberate ones of step 4 (no reason, asset review, parked, parked + marker)
            if refused != 4:
                failures.append(f"{refused} scan_run_not_active denials, expected exactly the four deliberate ones of step 4")
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
            sh("docker", "rm", "-f", TOY, check=False)
            sh("docker", "exec", worker, "rm", "-f", "/tmp/aw-go", check=False)
            cpx(CLEANUP_SOURCE)
    print("OK: one open decision did not stop the run's other actions" if not failures else "FAILED:\n  - " + "\n  - ".join(failures))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
