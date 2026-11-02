#!/usr/bin/env python3
"""Prove on the dev stack that "Test deeper" works end to end (REQ-HANDOVER-001..008, GitHub #84).

With the real control plane, worker, gateway, egress proxy and tool-runner, and a stand-in target of this script:

  1. A MONITOR (active, scoped by name, one healthy run with a service and an open finding that carries a secret in its
     evidence, a deny rule) is the starting point.
  2. The owner starts a deeper test through the real HTTP API: the preview, then the handover. A draft assessment appears,
     linked to the monitor, with the hosts that were picked, the monitor's deny rule, a window the owner gave, and nothing
     attested or allowed for active testing.
  3. The draft is finished as the wizard does it (the row replaced with active testing and attestation, a tool grant) and
     ACTIVATED. The host is the monitor's too, so activation answers with the notice that names the monitor.
  4. Both engagements are active. `http_request` is authorized and returns the target's real response for BOTH, concurrently,
     and each request is audited under its own engagement.
  5. The assessment's agent context carries what the monitor found (the service and the finding) and NOT the secret in the
     evidence; the worker renders it into the agent's prompt.
  6. The monitor is unchanged by all of it (compared field by field, apart from the audit entry of the handover).

The target is a throwaway container of this script on the dev networks; the engagements and users are throwaway ones. All are
removed again. Nothing here touches a real system.

    docker compose --profile runner up -d       # the dev stack, with the new control plane
    python3 scripts/verify_handover_dev.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = "asm_business"
TOY = "hotoy"
TITLE = "handover smoke"
MARK = "hotoy-ok-91ac"
SECRET = "=".join(["SESSION", "do-not-leak-4411"])

TOY_SOURCE = r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>hotoy</title></head><body>''' + MARK + r'''</body></html>"
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
'''

# Runs in the control-plane container: seeds the monitor and mints a session for its owner (no real account is touched).
SEED_SOURCE = r'''
import datetime as dt, json, sys, uuid
from app import auth_service
from app.db.base import SessionLocal
from app.models.asset import DiscoveredAsset, Service
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.finding import Finding
from app.models.monitoring import RunInventorySnapshot
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
secret = sys.argv[1]
db = SessionLocal()
now = dt.datetime.now(dt.timezone.utc)
owner = User(email=f"smoke-{uuid.uuid4().hex[:6]}@example.test", display_name="smoke owner", role="operator", status="active",
             must_change_password=False, password_hash=hash_secret("x"))
db.add(owner); db.flush()
mon = Engagement(title="handover smoke monitor", source="own_domain", status="active", operating_mode="monitoring",
                 owner_user_id=owner.id, emergency_contact="oncall@example.test", ai_testing_allowed=True, scan_profile="light",
                 authorized_from=now - dt.timedelta(days=3), authorized_until=now + dt.timedelta(days=300),
                 state_changing_requests=True, schedule_every_days=7, schedule_set_at=now, new_asset_policy="hold",
                 target_review_state="confirmed", targets_confirmed_at=now, targets_confirmed_by="smoke")
db.add(mon); db.flush()
db.add(ScopeAsset(engagement_id=mon.id, rule="allow", asset_type="domain", value="hotoy", active_allowed=True,
                  authorization_verified=True, authorization_method="operator_attestation"))
db.add(ScopeAsset(engagement_id=mon.id, rule="deny", asset_type="domain", value="admin.hotoy"))
for cat in ("fingerprint", "vuln"):
    db.add(ToolGrant(engagement_id=mon.id, tool_category=cat, mode="active", requires_manual_approval=False))
asset = DiscoveredAsset(engagement_id=mon.id, asset_type="domain", value="hotoy", in_scope=True, discovered_via="ct",
                        first_seen=now - dt.timedelta(days=3), last_seen=now - dt.timedelta(hours=5))
db.add(asset); db.flush()
svc = Service(asset_id=asset.id, port=8000, protocol="tcp", product="toy-httpd", version="1.0")
db.add(svc); db.flush()
db.add(Finding(engagement_id=mon.id, asset_id=asset.id, service_id=svc.id, category="misconfig", title="Toy server banner discloses its version",
               confidence="validated", severity="low", status="open", evidence={"leak": secret}, fingerprint="hotoy|8000|banner"))
run = ScanRun(engagement_id=mon.id, phase="report", state="done", health="ok", trigger="scheduled",
              started_at=now - dt.timedelta(hours=6), finished_at=now - dt.timedelta(hours=5))
db.add(run); db.flush()
db.add(RunInventorySnapshot(scan_run_id=run.id, kind="service", key="hotoy:8000/tcp", engagement_id=mon.id,
                            data={"product": "toy-httpd", "version": "1.0"}))
db.commit()
token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
print(json.dumps({"monitor": str(mon.id), "owner": str(owner.id), "token": token}))
'''

# Runs in the control-plane container, talking to the real HTTP server on localhost.
API_SOURCE = r'''
import datetime as dt, json, sys, urllib.error, urllib.request
seed = json.loads(sys.argv[1])
H = {"Authorization": "Bearer " + seed["token"], "Content-Type": "application/json"}
BASE = "http://localhost:8000"
def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method, headers=H, data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw.decode()[:200]
out = {}
mon = seed["monitor"]
status, preview = call("GET", f"/engagements/{mon}/handover-preview")
out["preview"] = {"status": status, "hosts": [(h["host"], h["services"], h["open_findings"], h["denied_by"]) for h in preview["hosts"]],
                  "deny": [d["value"] for d in preview["deny_rows"]], "overlap": preview["overlap"]}
now = dt.datetime.now(dt.timezone.utc)
body = {"authorized_from": now.isoformat(), "authorized_until": (now + dt.timedelta(days=2)).isoformat(), "hosts": ["hotoy"]}
status, created = call("POST", f"/engagements/{mon}/handover", body)
out["handover"] = {"status": status, "overlap": created.get("overlap") if isinstance(created, dict) else None}
if status != 201:
    print(json.dumps(out)); sys.exit(0)
eid = created["id"]
out["assessment_id"] = eid
_, draft = call("GET", f"/engagements/{eid}")
_, rows = call("GET", f"/engagements/{eid}/scope-assets")
out["draft"] = {"status": draft["status"], "mode": draft["operating_mode"], "scan_profile": draft["scan_profile"],
                "ai": draft["ai_testing_allowed"], "from": draft["handover_from"]["title"],
                "scope": sorted((r["rule"], r["value"], r["active_allowed"], r["authorization_verified"]) for r in rows)}
# Finish the draft the way the wizard does: replace the edited allow row (delete + add) with active testing, attest, grant tools.
for r in rows:
    if r["rule"] == "allow":
        call("DELETE", f"/engagements/{eid}/scope-assets/{r['id']}")
        s, new = call("POST", f"/engagements/{eid}/scope-assets", {"rule": "allow", "asset_type": r["asset_type"], "value": r["value"], "active_allowed": True})
        call("POST", f"/engagements/{eid}/scope-assets/{new['id']}/verify-authorization", {"method": "operator_attestation", "verified_by": "smoke owner"})
for cat in ("fingerprint", "vuln"):
    call("POST", f"/engagements/{eid}/tool-grants", {"tool_category": cat, "mode": "active", "requires_manual_approval": False})
status, activated = call("POST", f"/engagements/{eid}/activate")
out["activate"] = {"status": status, "state": activated.get("status") if isinstance(activated, dict) else activated,
                   "notice": (activated.get("scope_overlap_notice") if isinstance(activated, dict) else None)}
_, handovers = call("GET", f"/engagements/{mon}/handovers")
out["listed"] = [(h["id"] == eid, h["status"]) for h in handovers]
_, mon_now = call("GET", f"/engagements/{mon}")
out["monitor_after"] = {"status": mon_now["status"], "handover_from": mon_now.get("handover_from")}
print(json.dumps(out))
'''

STATE_SOURCE = r'''
import hashlib, json, sys, uuid
from sqlalchemy import func, select
from app.db.base import SessionLocal
from app.models.asset import DiscoveredAsset
from app.models.audit import AuditLog
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.finding import Finding
from app.models.scan_run import ScanRun
db = SessionLocal(); mon = db.get(Engagement, uuid.UUID(sys.argv[1]))
row = {c.name: str(getattr(mon, c.name)) for c in Engagement.__table__.columns}
counts = {m.__name__: db.scalar(select(func.count()).select_from(m).where(m.engagement_id == mon.id)) for m in (ScopeAsset, ToolGrant, ScanRun, Finding, DiscoveredAsset)}
audit = sorted(r.action for r in db.scalars(select(AuditLog).where(AuditLog.engagement_id == mon.id)) if r.action != "handover_created")
print(json.dumps({"hash": hashlib.sha256(json.dumps([row, counts, audit], sort_keys=True).encode()).hexdigest(), "counts": counts}))
'''

RUNS_SOURCE = r'''
import datetime as dt, json, sys, uuid
from app.db.base import SessionLocal
from app.models.scan_run import ScanRun
seed = json.loads(sys.argv[1]); db = SessionLocal(); out = {}
for name, eid in (("monitor", seed["monitor"]), ("assessment", seed["assessment_id"])):
    run = ScanRun(engagement_id=uuid.UUID(eid), phase="agent", state="running", trigger="manual",
                  supervision="unattended" if name == "monitor" else "attended")
    db.add(run); db.flush(); out[name] = {"engagement": eid, "run": str(run.id)}
db.commit(); print(json.dumps(out))
'''

WORKER_SOURCE = r'''
import json, sys, threading, uuid
from app import tool_runner_client as trc
from app.control_plane_client import client
from app.tasks import agent
seed, MARK = json.loads(sys.argv[1]), sys.argv[2]
out = {name: [] for name in ("monitor", "assessment")}
def work(name):
    eng, run = seed[name]["engagement"], seed[name]["run"]
    for _ in range(3):
        payload = {"tool": "http_request", "category": "vuln", "mode": "active", "target": "hotoy", "args": {"method": "GET", "path": "/"},
                   "is_automated": True, "phase": "agent", "scan_run_id": run, "rationale": "verify_handover_dev"}
        d = client.authorize(uuid.UUID(eng), payload)
        if not d["allowed"]:
            out[name].append({"authorized": False, "reason": d["reason"]}); continue
        r = trc.tool_runner.run("http_request", "http://hotoy:8000", {"method": "GET", "path": "/"}, scan_run_id=run, engagement_id=eng)
        out[name].append({"authorized": True, "real_response": MARK in (r.get("stdout") or "")})
ts = [threading.Thread(target=work, args=(n,)) for n in out]; [t.start() for t in ts]; [t.join(300) for t in ts]
ctx = client.get_agent_context(uuid.UUID(seed["assessment"]["engagement"]))
known = ctx.get("known_from_monitor")
prompt = agent._initial_context(seed["assessment"]["engagement"], {"hotoy": "asset-1"})
block = prompt[prompt.index("KNOWN FROM MONITORING"):prompt.index("Now work the surface")] if "KNOWN FROM MONITORING" in prompt else ""
print("RESULT " + json.dumps({"calls": out, "known": known, "block": block, "context_text": json.dumps(ctx)}))
'''

AUDIT_SOURCE = r'''
import json, sys, uuid
from collections import Counter
from sqlalchemy import select
from app.db.base import SessionLocal
from app.models.audit import AuditLog
seed = json.loads(sys.argv[1]); db = SessionLocal(); out = {}
for name in ("monitor", "assessment"):
    rows = db.scalars(select(AuditLog).where(AuditLog.engagement_id == uuid.UUID(seed[name]["engagement"]), AuditLog.action == "network_request")).all()
    out[name] = {"requests": [[*k, n] for k, n in Counter((r.decision, r.reason) for r in rows).items()],
                 "own_run_only": sorted({r.payload.get("scan_run_id") for r in rows}) == [seed[name]["run"]]}
print(json.dumps(out))
'''

CLEANUP_SOURCE = r'''
from sqlalchemy import select, delete
from app.db.base import SessionLocal
from app.api.engagements import _delete_engagement_dependents
from app.models.engagement import Engagement
from app.models.user import User, UserSession
db = SessionLocal()
ids = list(db.scalars(select(Engagement.id).where(Engagement.title.like("handover smoke%") | Engagement.title.like("Test: handover smoke%"))))
for eid in ids:
    _delete_engagement_dependents(db, eid)
    db.execute(delete(Engagement).where(Engagement.id == eid))
smoke = select(User.id).where(User.email.like("smoke-%@example.test")).scalar_subquery()
db.execute(delete(UserSession).where(UserSession.user_id.in_(smoke)))
db.execute(delete(User).where(User.email.like("smoke-%@example.test")))
db.commit()
'''


def sh(*args: str, stdin: str | None = None, check: bool = True) -> str:
    done = subprocess.run(args, input=stdin, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:4])} failed ({done.returncode}): {(done.stderr or done.stdout).strip()[-700:]}")
    return done.stdout


def last(text: str) -> str:
    return text.strip().splitlines()[-1]


def main() -> int:
    up = set(sh("docker", "ps", "--format", "{{.Names}}").split())
    missing = [n for n in ("control-plane", "worker", "egress-proxy", "tool-runner", "raw-egress-gateway") if f"{PROJECT}-{n}-1" not in up]
    if missing:
        print(f"the dev stack is not fully up (missing: {', '.join(missing)}); start it with:\n  docker compose --profile runner up -d", file=sys.stderr)
        return 2
    cp, worker = f"{PROJECT}-control-plane-1", f"{PROJECT}-worker-1"
    cpx = lambda source, *a: sh("docker", "exec", "-i", cp, "python", "-", *a, stdin=source)  # noqa: E731
    wx = lambda source, *a: sh("docker", "exec", "-i", worker, "python", "-", *a, stdin=source)  # noqa: E731
    sh("docker", "rm", "-f", TOY, check=False)
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="asm-ho-") as tmp:
        toy = Path(tmp) / "toy.py"
        toy.write_text(TOY_SOURCE)
        try:
            sh("docker", "run", "-d", "--name", TOY, "--network", "asm_egress", "-v", f"{toy}:/toy.py:ro",
               "--entrypoint", "python", f"{PROJECT}-worker:latest", "/toy.py")
            seed = json.loads(last(cpx(SEED_SOURCE, SECRET)))
            before = json.loads(last(cpx(STATE_SOURCE, seed["monitor"])))
            api = json.loads(last(sh("docker", "exec", "-i", cp, "python", "-", json.dumps(seed), stdin=API_SOURCE)))
            # Compared right here: everything the handover and the activation did, and nothing this script adds afterwards.
            after = json.loads(last(cpx(STATE_SOURCE, seed["monitor"])))

            print(f"1. preview: hosts {api['preview']['hosts']}, deny rows {api['preview']['deny']}, overlap {api['preview']['overlap']}")
            if api["preview"]["status"] != 200 or api["preview"]["hosts"] != [["hotoy", 1, 1, None]] or api["preview"]["deny"] != ["admin.hotoy"]:
                failures.append(f"the preview was not what the monitor knows: {api['preview']}")
            print(f"2. handover: HTTP {api['handover']['status']}")
            if api["handover"]["status"] != 201:
                failures.append(f"the handover was refused: {api['handover']}")
                raise RuntimeError("no draft to continue with")
            d = api["draft"]
            print(f"   draft: {d['status']} {d['mode']}, depth {d['scan_profile']}, agent {d['ai']}, follows '{d['from']}'")
            print(f"   scope as created: {d['scope']}")
            expected = [["allow", "hotoy", False, False], ["deny", "admin.hotoy", False, False]]
            if d["status"] != "draft" or d["mode"] != "assessment" or d["scan_profile"] != "thorough" or not d["ai"] or sorted(d["scope"]) != sorted(expected):
                failures.append(f"the draft is not what REQ-HANDOVER-002/003/004 say: {d}")
            a = api["activate"]
            print(f"3. activation as the wizard finishes it: HTTP {a['status']} -> {a['state']}; notice: {a['notice']}")
            if a["status"] != 200 or a["state"] != "active" or not a["notice"] or "handover smoke monitor" not in a["notice"]:
                failures.append(f"the assessment was not activated with the overlap notice naming the monitor: {a}")
            if api["listed"] != [[True, "active"]] or api["monitor_after"]["status"] != "active":
                failures.append(f"the link or the monitor is wrong afterwards: {api['listed']} {api['monitor_after']}")

            runs = json.loads(last(cpx(RUNS_SOURCE, json.dumps({**seed, "assessment_id": api["assessment_id"]}))))
            seed2 = {**runs}
            result = json.loads(last(wx(WORKER_SOURCE, json.dumps(seed2), MARK)).removeprefix("RESULT "))
            print("4. http_request through the proxy, both engagements active on one host, concurrently:")
            for name, rows in result["calls"].items():
                ok = [r for r in rows if r.get("authorized") and r.get("real_response")]
                print(f"   {name:10} {len(ok)}/{len(rows)} authorized and returned the target's real response")
                if len(ok) != 3:
                    failures.append(f"{name}: {rows}")
            audit = json.loads(last(cpx(AUDIT_SOURCE, json.dumps(seed2))))
            for name, v in audit.items():
                print(f"   audit {name:10} {v['requests']} (own run only: {v['own_run_only']})")
                if not v["own_run_only"] or any(r[0] != "ALLOW" for r in v["requests"]):
                    failures.append(f"{name}: the proxy audit is wrong: {v}")

            known = result["known"]
            print(f"5. the assessment's agent context: {json.dumps(known)[:260]}")
            if not known or [h["host"] for h in known["hosts"]] != ["hotoy"] or known["hosts"][0]["services"][0]["product"] != "toy-httpd" \
                    or known["hosts"][0]["findings"][0]["title"] != "Toy server banner discloses its version":
                failures.append(f"the summary is not what the monitor found: {known}")
            if SECRET in result["context_text"] or SECRET in result["block"]:
                failures.append("THE SECRET FROM THE MONITOR'S EVIDENCE REACHED THE AGENT'S CONTEXT")
            print("   the prompt block the agent reads:\n     " + "\n     ".join(result["block"].strip().splitlines()))
            if "KNOWN FROM MONITORING" not in result["block"] or "does NOT change what is in scope" not in result["block"]:
                failures.append("the worker did not render the summary as context")

            print(f"6. the monitor, compared before the handover and after the handover and the assessment's activation: "
                  f"{'identical' if after['hash'] == before['hash'] else 'CHANGED'} {after['counts']}")
            if after["hash"] != before["hash"]:
                failures.append("the handover changed the monitor")
        except RuntimeError as exc:
            if not failures:
                failures.append(str(exc))
        finally:
            sh("docker", "rm", "-f", TOY, check=False)
            cpx(CLEANUP_SOURCE)
    print("OK: a deeper test started from a monitor, both ran, and the monitor was not touched" if not failures else "FAILED:\n  - " + "\n  - ".join(failures))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
