#!/usr/bin/env python3
"""Prove on the dev stack that test accounts work end to end and keep their secrets (REQ-TESTACCT-001..011, GitHub #89, R4).

With the real control plane, worker, Scope Gateway, egress proxy and tool-runner, and a stand-in login target of this script:

  1. A MONITOR (active, two hosts in scope) gets two test accounts through the real HTTP API, as the console does it: `shop` (a valid
     login) and `stale` (a password the target rejects), both assigned to ONE of the two hosts only. The login consent is read, then
     given once.
  2. The worker registers the accounts and the agent's first message carries the real value and the two host lists (decision D1).
  3. The agent's own code path (`_handle_http_request`) then does what a model would, with the real password written into its calls:
       - logs in on the assigned host (password URL-encoded the way a browser would send it) -> allowed without an approval, the
         target receives EXACTLY the bytes the model wrote, the session is kept and the private area is reached with it;
       - the same password on the other in-scope host, in a query string, in a header, as a third login attempt, and with a
         placeholder after the run ended -> each refused or not sent; the target never sees any of them;
       - the stale account's login is rejected, the target REFLECTS the password in its answer;
       - a finding and an agent step whose text contains the password.
     The run's outcomes are reported: the rejected login reads as a lost login, not as "nothing found".
  4. The audit trail names the consent; the console views carry no secret; the authorization document lists the accounts.
  5. EVERY table of the database (a full dump), every service's log and the queue are searched for the passwords in every form the
     platform recognizes AND for the session ids the target issued (REQ-TESTACCT-014). A positive control proves the search can find them.
  6. Everything is removed again, and the database holds nothing of the run.

The target is a throwaway container of this script on the dev networks; the engagement, users and accounts are throwaway ones.
Nothing here touches a real system.

    docker compose --profile runner up -d       # the dev stack, with the new control plane and worker
    python3 scripts/verify_testaccounts_dev.py
"""

from __future__ import annotations

import base64
import json
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote, quote_plus

PROJECT = "asm_business"
TOY = "latoy"
OTHER = "latoy-other"
TITLE = "testacct smoke monitor"

TOY_SOURCE = r'''
import json, os, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
USERS = {"alice": os.environ["PW_SHOP"], "admin": os.environ["PW_REAL_ADMIN"]}
SESSIONS = {}
class H(BaseHTTPRequestHandler):
    def _log(self, body):
        with open("/log/requests.jsonl", "a") as f:
            f.write(json.dumps({"method": self.command, "path": self.path, "host": self.headers.get("Host"),
                                "headers": dict(self.headers), "body": body}) + "\n")
    def _send(self, status, text, cookie=None):
        data = text.encode()
        self.send_response(status); self.send_header("Content-Type", "text/plain"); self.send_header("Content-Length", str(len(data)))
        if cookie: self.send_header("Set-Cookie", cookie)
        self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self._log("")
        if self.path.split("?")[0] == "/account":
            cookie = self.headers.get("Cookie", "")
            session = next((v.split("=", 1)[1] for v in cookie.split("; ") if v.startswith("session=")), None)
            if session in SESSIONS:
                return self._send(200, "ACCOUNT-AREA-MARKER welcome " + SESSIONS[session])
            return self._send(401, "login required")
        return self._send(200, "latoy index")
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        self._log(raw)
        if self.path != "/login":
            return self._send(404, "no such route")
        form = {k: v[0] for k, v in parse_qs(raw).items()}
        user, password = form.get("username"), form.get("password")
        if USERS.get(user) == password and password is not None:
            token = secrets.token_hex(16); SESSIONS[token] = user
            with open("/log/sessions.txt", "a") as f:
                f.write(token + "\n")
            return self._send(200, json.dumps({"ok": True, "user": user}), cookie="session=" + token + "; HttpOnly; Path=/")
        return self._send(401, "Login failed for " + str(user) + ". The password was: " + str(password))
    def log_message(self, *a): pass
ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
'''

# Runs in the control-plane container: the throwaway owner, the monitor and its run (no real account is touched).
SEED_SOURCE = r'''
import datetime as dt, json, sys, uuid
from app import auth_service
from app.db.base import SessionLocal
from app.models.asset import DiscoveredAsset
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
title, hosts = sys.argv[1], sys.argv[2:]
db = SessionLocal()
now = dt.datetime.now(dt.timezone.utc)
owner = User(email=f"smoke-{uuid.uuid4().hex[:6]}@example.test", display_name="smoke owner", role="operator", status="active",
             must_change_password=False, password_hash=hash_secret("x"))
db.add(owner); db.flush()
mon = Engagement(title=title, source="own_domain", status="active", operating_mode="monitoring", owner_user_id=owner.id,
                 emergency_contact="oncall@example.test", ai_testing_allowed=True, scan_profile="light",
                 authorized_from=now - dt.timedelta(days=3), authorized_until=now + dt.timedelta(days=300),
                 schedule_every_days=7, schedule_set_at=now, new_asset_policy="hold",
                 target_review_state="confirmed", targets_confirmed_at=now, targets_confirmed_by="smoke")
db.add(mon); db.flush()
assets = {}
for host in hosts:
    db.add(ScopeAsset(engagement_id=mon.id, rule="allow", asset_type="domain", value=host, active_allowed=True,
                      authorization_verified=True, authorization_method="operator_attestation"))
    asset = DiscoveredAsset(engagement_id=mon.id, asset_type="domain", value=host, in_scope=True, discovered_via="ct",
                            first_seen=now - dt.timedelta(days=3), last_seen=now - dt.timedelta(hours=5))
    db.add(asset); db.flush(); assets[host] = str(asset.id)
for cat in ("fingerprint", "vuln"):
    db.add(ToolGrant(engagement_id=mon.id, tool_category=cat, mode="active", requires_manual_approval=False))
run = ScanRun(engagement_id=mon.id, phase="agent", state="running", trigger="scheduled", supervision="unattended")
db.add(run); db.commit()
token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
print(json.dumps({"engagement": str(mon.id), "owner": str(owner.id), "token": token, "run": str(run.id), "assets": assets}))
'''

# Runs in the control-plane container, talking to the real HTTP server on localhost: what the console does.
API_SOURCE = r'''
import json, sys, urllib.error, urllib.request
seed = json.loads(sys.argv[1]); pw = json.loads(sys.argv[2]); toy = sys.argv[3]; other = sys.argv[4]
H = {"Authorization": "Bearer " + seed["token"], "Content-Type": "application/json"}
BASE = "http://localhost:8000"
def call(method, path, body=None, raw=False):
    req = urllib.request.Request(BASE + path, method=method, headers=H, data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
            return r.status, (data if raw else (json.loads(data) if data else None))
    except urllib.error.HTTPError as e:
        data = e.read()
        try:
            return e.code, json.loads(data)
        except Exception:
            return e.code, data.decode(errors="replace")[:300]
eid = seed["engagement"]; out = {}
def account(label, role, username, secret, **kw):
    return call("POST", f"/engagements/{eid}/test-accounts",
                {"label": label, "role": role, "kind": "login_form", "username": username, "secret": secret, "login_path": "/login",
                 "hosts": [{"host": toy}], "attested": True, **kw})
# refusals first: nothing may be saved by them
out["refusals"] = {
    "not_attested": account("x1", "user", "alice", "Longenough-1", attested=False)[0:2],
    "too_short": account("x2", "user", "alice", "short")[0:2],
    "bad_label": account("bad label", "user", "alice", "Longenough-1")[0:2],
    "host_outside_scope": account("x3", "user", "alice", "Longenough-1", hosts=[{"host": "outside.example.test"}])[0:2],
}
s1, shop = account("shop", "user", "alice", pw["shop"])
s2, stale = account("stale", "admin", "admin", pw["stale"])
out["created"] = [s1, s2]
_, ov = call("GET", f"/engagements/{eid}/test-accounts")
out["overview"] = {"accounts": [(a["label"], a["state"], a["can_use_on"], [c["host"] for c in a["cannot_use_on"]], a["secret_set"]) for a in ov["accounts"]],
                   "consent_before": {"applicable": ov["consent"]["applicable"], "current": ov["consent"]["current"],
                                      "uncovered": sorted((p["label"], p["host"]) for p in ov["consent"]["uncovered"])}}
out["views_text"] = [json.dumps(ov), json.dumps(shop), json.dumps(stale)]
s3, consent = call("POST", f"/engagements/{eid}/login-consent")
_, ov2 = call("GET", f"/engagements/{eid}/test-accounts")
out["consent"] = {"status": s3, "current": ov2["consent"]["current"], "uncovered": len(ov2["consent"]["uncovered"]), "given_at": ov2["consent"]["given_at"]}
out["views_text"].append(json.dumps(ov2))
print(json.dumps(out))
'''

# Runs in the worker container: the agent's own code path, with the model's calls written the way a model writes them.
WORKER_SOURCE = r'''
import json, sys, uuid
from urllib.parse import quote
from app import test_accounts
from app.control_plane_client import client
from app.tasks import agent, dispatch
seed = json.loads(sys.argv[1]); pw = json.loads(sys.argv[2]); TOY, OTHER = sys.argv[3], sys.argv[4]
eng, run = seed["engagement"], seed["run"]
asset_by_host = seed["assets"]
out = {}
ctx = client.get_agent_context(uuid.UUID(eng))
given = ctx.get("test_accounts") or []
out["given"] = [{**{k: v for k, v in a.items() if k != "secret"}, "secret_is_real": a["secret"] in (pw["shop"], pw["stale"])} for a in given]
test_accounts.register(run, given)
prompt = agent._initial_context(eng, asset_by_host)
out["prompt"] = {"has_block": "TEST ACCOUNTS" in prompt, "real_value_for_model": pw["shop"] in prompt and pw["stale"] in prompt,
                 "names_can": f"Can be used on: {TOY}" in prompt, "names_cannot": OTHER in prompt[prompt.index("TEST ACCOUNTS"):] if "TEST ACCOUNTS" in prompt else False}
context = agent.SimpleContext(scan_run_id=run, unattended=True, single_port=8000, protocol_by_host={TOY: "http", OTHER: "http"})
form = {"Content-Type": "application/x-www-form-urlencoded"}
def http(name, **kw):
    kw.setdefault("rationale", "verify_testaccounts_dev")
    kw.setdefault("risk_level", "low"); kw.setdefault("risk", "log in with the dedicated test account")
    out.setdefault("calls", {})[name] = agent._handle_http_request(eng, kw, asset_by_host, {}, context)
enc = lambda s: quote(s, safe="")
login = lambda user, secret: f"username={user}&password={enc(secret)}"
http("login_ok", target=TOY, method="POST", path="/login", headers=form, body=login("alice", pw["shop"]), identity="shop")
http("private_area", target=TOY, method="GET", path="/account", identity="shop", rationale="read the private area behind the login")
http("other_host", target=OTHER, method="POST", path="/login", headers=form, body=login("alice", pw["shop"]), identity="shop")
http("query_string", target=TOY, method="GET", path="/search?q=" + enc(pw["shop"]), identity="shop")
http("header", target=TOY, method="GET", path="/account", headers={"X-Debug-Token": pw["shop"]}, identity="shop")
http("login_attempt_2", target=TOY, method="POST", path="/login", headers=form, body=login("alice", pw["shop"]), identity="shop")
http("login_attempt_3", target=TOY, method="POST", path="/login", headers=form, body=login("alice", pw["shop"]), identity="shop")
http("stale_login", target=TOY, method="POST", path="/login", headers=form, body=login("admin", pw["stale"]), identity="stale")
out["login_outcomes"] = {f"{k[0]}@{k[1]}": v for k, v in context.login_outcomes.items()}
out["denied_reasons"] = [d["reason"] for d in context.denied]
out["finding"] = agent._handle_report_finding(eng, {
    "target": TOY, "title": "Private area reachable with the shop test account", "severity": "info", "category": "exposure",
    "rationale": f"Logged in as alice with the password {pw['shop']} ({enc(pw['shop'])}) and read ACCOUNT-AREA-MARKER.",
    "evidence_basis": "direct_technical_proof"}, asset_by_host, context)
client.record_agent_step(uuid.UUID(eng), scan_run_id=run, iteration=1,
                         prompt=f"login with {pw['shop']} and {pw['stale']}", response=f"I will POST username=alice&password={enc(pw['shop'])}")
agent._report_test_account_outcomes(run, given, context)
out["coverage"] = {"lost": context.auth_coverage_lost, "note": context.auth_coverage_note}
test_accounts.unregister(run)
obs = dispatch.dispatch(eng, asset_by_host[TOY], "http_request", TOY, None,
                        args={"method": "POST", "path": "/login", "headers": form, "body": "username=alice&password={{testaccount:shop}}"},
                        scan_run_id=run, single_port=8000, confirmed_protocol="http")
out["after_run_ended"] = obs.as_text()
print("RESULT " + json.dumps(out))
'''

AFTER_SOURCE = r'''
import json, sys, uuid
from collections import Counter
from sqlalchemy import select, text
from app.db.base import SessionLocal
from app.models.audit import AuditLog
from app.models.scan_run import ScanRun
from app.models.test_account import TestAccountLoginAttempt
seed = json.loads(sys.argv[1]); eid = uuid.UUID(seed["engagement"])
db = SessionLocal(); out = {}
rows = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eid, AuditLog.action == "tool_call")).all()
out["gateway"] = sorted([d, r, n] for (d, r), n in Counter((x.decision, x.reason) for x in rows).items())
out["login_rows_name_the_consent"] = [bool((r.payload or {}).get("consent_id")) for r in rows if r.reason == "testaccount_login"]
out["attempts"] = db.scalar(text("select count(*) from engagement_test_account_login_attempt a join engagement_test_account t on t.id = a.account_id where t.engagement_id = :e"), {"e": eid})
run = db.get(ScanRun, uuid.UUID(seed["run"]))
out["checkpoint_outcomes"] = sorted((o["label"], o["host"], o["outcome"]) for o in (run.checkpoint or {}).get("test_account_outcomes", []))
print(json.dumps(out))
'''

VIEWS_SOURCE = r'''
import json, sys, urllib.error, urllib.request
seed = json.loads(sys.argv[1]); eid = seed["engagement"]
H = {"Authorization": "Bearer " + seed["token"], "Content-Type": "application/json"}
def get(path):
    with urllib.request.urlopen(urllib.request.Request("http://localhost:8000" + path, headers=H), timeout=60) as r:
        return r.read()
ov = json.loads(get(f"/engagements/{eid}/test-accounts"))
pdf = get(f"/engagements/{eid}/authorization-pdf")
text = ""
try:
    import io, pypdf
    text = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(io.BytesIO(pdf)).pages)
except Exception as exc:
    text = "PDF-TEXT-UNAVAILABLE " + repr(exc)
print(json.dumps({"hosts": [(a["label"], [(h["host"], h["last_outcome"], h["suspended"]) for h in a["hosts"]]) for a in ov["accounts"]],
                  "overview": json.dumps(ov), "pdf_bytes": len(pdf), "pdf_text": text}))
'''

CLEANUP_SOURCE = r'''
from sqlalchemy import select, delete, text
from app.db.base import SessionLocal
from app.api.engagements import _delete_engagement_dependents
from app.models.engagement import Engagement
from app.models.user import User, UserSession
db = SessionLocal()
ids = list(db.scalars(select(Engagement.id).where(Engagement.title.like("testacct smoke%"))))
for eid in ids:
    _delete_engagement_dependents(db, eid)
    db.execute(delete(Engagement).where(Engagement.id == eid))
smoke = select(User.id).where(User.email.like("smoke-%@example.test")).scalar_subquery()
db.execute(delete(UserSession).where(UserSession.user_id.in_(smoke)))
db.execute(delete(User).where(User.email.like("smoke-%@example.test")))
db.commit()
left = {t: db.scalar(text(f"select count(*) from {t}")) for t in ("engagement_test_account", "engagement_test_account_host", "engagement_login_consent", "engagement_test_account_login_attempt")}
print(__import__("json").dumps({"deleted_engagements": len(ids), "test_account_rows_left": left}))
'''


def sh(*args: str, stdin: str | None = None, check: bool = True) -> str:
    done = subprocess.run(args, input=stdin, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:4])} failed ({done.returncode}): {(done.stderr or done.stdout).strip()[-700:]}")
    return done.stdout


def last(text: str) -> str:
    return text.strip().splitlines()[-1]


def forms_of(secret: str, username: str | None) -> list[str]:
    """Every form the platform recognizes a secret in (testaccounts.py), searched here independently of that code."""
    import json as _json
    forms = [secret, quote(secret, safe=""), quote_plus(secret), _json.dumps(secret)[1:-1], base64.b64encode(secret.encode()).decode(),
             base64.urlsafe_b64encode(secret.encode()).decode().rstrip("=")]
    if username:
        raw = f"{username}:{secret}".encode()
        forms += [base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode().rstrip("=")]
    return sorted(set(forms), key=len, reverse=True)


def count_hits(patterns: Path, command: str) -> int:
    done = subprocess.run(["bash", "-c", f"set -o pipefail; {command} | grep -a -c -F -f {patterns}"], capture_output=True, text=True)
    return int(done.stdout.strip() or 0) if done.returncode in (0, 1) else -1


def main() -> int:
    up = set(sh("docker", "ps", "--format", "{{.Names}}").split())
    missing = [n for n in ("control-plane", "worker", "egress-proxy", "tool-runner", "raw-egress-gateway", "postgres") if f"{PROJECT}-{n}-1" not in up]
    if missing:
        print(f"the dev stack is not fully up (missing: {', '.join(missing)}); start it with:\n  docker compose --profile runner up -d", file=sys.stderr)
        return 2
    cp, worker, pg = f"{PROJECT}-control-plane-1", f"{PROJECT}-worker-1", f"{PROJECT}-postgres-1"
    cpx = lambda source, *a: sh("docker", "exec", "-i", cp, "python", "-", *a, stdin=source)  # noqa: E731
    wx = lambda source, *a: sh("docker", "exec", "-i", worker, "python", "-", *a, stdin=source)  # noqa: E731
    pw = {"shop": f"Sh0p pw/{secrets.token_hex(5)}&x+y", "stale": f"St4le+{secrets.token_hex(5)}/z", "real_admin": f"Adm1n-{secrets.token_hex(6)}"}
    sh("docker", "rm", "-f", TOY, check=False)
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="asm-ta-") as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "toy.py").write_text(TOY_SOURCE)
        (tmpdir / "log").mkdir()
        (tmpdir / "log").chmod(0o777)
        patterns = tmpdir / "patterns.txt"
        patterns.write_text("\n".join(forms_of(pw["shop"], "alice") + forms_of(pw["stale"], "admin")) + "\n")
        seed = None
        try:
            sh("docker", "run", "-d", "--name", TOY, "--network", "asm_egress", "--network-alias", OTHER,
               "-e", f"PW_SHOP={pw['shop']}", "-e", f"PW_REAL_ADMIN={pw['real_admin']}",
               "-v", f"{tmpdir / 'toy.py'}:/toy.py:ro", "-v", f"{tmpdir / 'log'}:/log",
               "--entrypoint", "python", f"{PROJECT}-worker:latest", "/toy.py")
            seed = json.loads(last(cpx(SEED_SOURCE, TITLE, TOY, OTHER)))

            # 1. the real API
            api = json.loads(last(sh("docker", "exec", "-i", cp, "python", "-", json.dumps(seed), json.dumps({"shop": pw["shop"], "stale": pw["stale"]}), TOY, OTHER, stdin=API_SOURCE)))
            print("1. console API (as the console calls it):")
            print(f"   refused without saving: {api['refusals']}")
            if any(status not in (400, 422) for status, _ in api["refusals"].values()):
                failures.append(f"a malformed or unattested account was not refused: {api['refusals']}")
            print(f"   created: HTTP {api['created']}; accounts {api['overview']['accounts']}")
            if api["created"] != [201, 201]:
                failures.append(f"the accounts were not created: {api['created']}")
            want = [("shop", "active", [TOY], [OTHER], True), ("stale", "active", [TOY], [OTHER], True)]
            if [tuple(a) for a in api["overview"]["accounts"]] != want:
                failures.append(f"the account views are wrong (can/cannot use): {api['overview']['accounts']}")
            before = api["overview"]["consent_before"]
            print(f"   consent before: {before}")
            if not (before["applicable"] and not before["current"] and before["uncovered"] == [["shop", TOY], ["stale", TOY]]):
                failures.append(f"the monitor did not ask for consent for exactly the two logins: {before}")
            c = api["consent"]
            print(f"   consent given once: HTTP {c['status']}, current {c['current']}, still uncovered {c['uncovered']}")
            if c["status"] != 201 or not c["current"] or c["uncovered"] != 0:
                failures.append(f"the consent did not cover the logins: {c}")

            # 2-3. the worker
            result = json.loads(last(wx(WORKER_SOURCE, json.dumps(seed), json.dumps({"shop": pw["shop"], "stale": pw["stale"]}), TOY, OTHER)).removeprefix("RESULT "))
            print("2. what the worker is given and what the model reads:")
            print(f"   given: {[(g['label'], g['can_use_on'], [c['host'] for c in g['cannot_use_on']]) for g in result['given']]}; real value delivered: "
                  f"{all(g['secret_is_real'] for g in result['given'])}")
            print(f"   first message: {result['prompt']}")
            if not all(g["secret_is_real"] for g in result["given"]) or len(result["given"]) != 2:
                failures.append("the worker was not given the two accounts with their real value")
            if not all(result["prompt"].values()):
                failures.append(f"the agent's first message is missing the accounts, the real value or the two host lists: {result['prompt']}")

            calls = result["calls"]
            mask = lambda t: t.replace(pw["shop"], "<shop>").replace(quote(pw["shop"], safe=""), "<shop|url>").replace(pw["stale"], "<stale>").replace(quote(pw["stale"], safe=""), "<stale|url>")  # noqa: E731
            print("3. the agent's calls (what the model gets back):")
            for name in ("login_ok", "private_area", "other_host", "query_string", "header", "login_attempt_2", "login_attempt_3", "stale_login"):
                print(f"   {name:16} {mask(calls[name]).splitlines()[0][:150]}")
            if "200" not in calls["login_ok"].splitlines()[0] and "200" not in calls["login_ok"][:200]:
                failures.append(f"the login on the assigned host did not reach the target: {mask(calls['login_ok'])[:200]}")
            if "ACCOUNT-AREA-MARKER" not in calls["private_area"]:
                failures.append("the session from the login was not used: the private area was not reached")
            expectations = {"other_host": "credential_host_not_usable", "query_string": "credential_wrong_use", "header": "credential_wrong_use",
                            "login_attempt_3": "login_attempt_limit"}
            for name, reason in expectations.items():
                if reason not in calls[name] or "DENIED" not in calls[name]:
                    failures.append(f"{name} was not denied with {reason}: {mask(calls[name])[:200]}")
            if "200" not in calls["login_attempt_2"][:200]:
                failures.append(f"the second login attempt (allowed) did not reach the target: {mask(calls['login_attempt_2'])[:200]}")
            if "--verbose" in sys.argv:
                for name in ("login_ok", "private_area", "stale_login"):
                    print(f"   --- {name}:\n" + "\n".join("      " + line for line in mask(calls[name]).splitlines()[:25]))
            print(f"   login outcomes: {result['login_outcomes']}; denied by the gateway: {result['denied_reasons']}")
            if result["login_outcomes"] != {f"shop@{TOY}": "session_established", f"stale@{TOY}": "rejected"}:
                failures.append(f"the login outcomes are wrong: {result['login_outcomes']}")
            print(f"   run outcomes reported: lost login = {result['coverage']['lost']} ({result['coverage']['note']})")
            if not result["coverage"]["lost"] or "authenticated_coverage_lost" not in (result["coverage"]["note"] or ""):
                failures.append(f"a rejected login did not read as lost authenticated coverage: {result['coverage']}")
            print(f"   after the run ended, a placeholder is not sent: {mask(result['after_run_ended'])[:120]!r}")
            if "ACCOUNT" in result["after_run_ended"] or "200" in result["after_run_ended"][:60]:
                failures.append("a placeholder was sent (or answered) after the run ended")

            # the target's own log: what actually arrived
            log = [json.loads(line) for line in (tmpdir / "log" / "requests.jsonl").read_text().splitlines()]
            posts = [r for r in log if r["method"] == "POST"]
            print(f"   the target received {len(log)} request(s): " + ", ".join(f"{r['method']} {r['host']}{r['path']}" for r in log))
            expect_bodies = [f"username=alice&password={quote(pw['shop'], safe='')}"] * 2 + [f"username=admin&password={quote(pw['stale'], safe='')}"]
            if [r["body"] for r in posts] != expect_bodies:
                failures.append(f"the target did not receive exactly the login bytes the model wrote (twice shop, once stale): {len(posts)} POST(s)")
            if any(r["host"] not in (TOY, f"{TOY}:8000") for r in log):
                failures.append(f"a request reached a host other than {TOY}: {[r['host'] for r in log]}")
            leaked = [r for r in log if r["method"] == "GET" and any(f in json.dumps(r) for f in forms_of(pw["shop"], "alice") + forms_of(pw["stale"], "admin"))]
            if leaked:
                failures.append(f"a credential reached the target outside its login: {[(r['method'], r['path']) for r in leaked]}")
            area = [r for r in log if r["path"] == "/account"]
            carried = bool(area) and "session=" in {k.lower(): v for k, v in area[0]["headers"].items()}.get("cookie", "")
            if not carried:
                failures.append(f"the private-area request did not carry the session cookie (headers seen: {sorted(area[0]['headers']) if area else None})")
            print(f"   the target saw the real password in {len(posts)} login POST(s) only; the private area request carried the session cookie: {carried}")

            # 4. the audit trail and the views
            after = json.loads(last(cpx(AFTER_SOURCE, json.dumps(seed))))
            print(f"4. gateway decisions: {after['gateway']}")
            print(f"   consent named on the login rows: {after['login_rows_name_the_consent']}; login attempts kept: {after['attempts']}")
            reasons = {(d, r): n for d, r, n in after["gateway"]}
            if reasons.get(("ALLOW", "testaccount_login")) != 3 or after["login_rows_name_the_consent"] != [True, True, True]:
                failures.append(f"the consented logins are not three ALLOW/testaccount_login rows naming the consent: {after}")
            for deny in ("credential_host_not_usable", "credential_wrong_use", "login_attempt_limit"):
                if not any(d == "DENY" and r == deny for (d, r) in reasons):
                    failures.append(f"no audited denial {deny}")
            if after["attempts"] != 3:
                failures.append(f"login attempts kept should be 3 (2 shop + 1 stale): {after['attempts']}")
            if after["checkpoint_outcomes"] != [["shop", TOY, "session_established"], ["stale", TOY, "rejected"]]:
                failures.append(f"the run's outcomes were not recorded: {after['checkpoint_outcomes']}")
            views = json.loads(last(sh("docker", "exec", "-i", cp, "python", "-", json.dumps(seed), stdin=VIEWS_SOURCE)))
            print(f"   console view after the run: {views['hosts']}; authorization document {views['pdf_bytes']} bytes")
            if "shop" not in views["pdf_text"] or "stale" not in views["pdf_text"] or TOY not in views["pdf_text"]:
                failures.append(f"the authorization document does not list the accounts and their hosts: {views['pdf_text'][:200]!r}")
            outcome_by = {label: dict((h, o) for h, o, _ in hosts) for label, hosts in views["hosts"]}
            if outcome_by.get("shop", {}).get(TOY) != "session_established" or outcome_by.get("stale", {}).get(TOY) != "rejected":
                failures.append(f"the console does not show the logins' outcomes: {views['hosts']}")
            texts = api["views_text"] + [views["overview"], views["pdf_text"]]
            if any(f in t for t in texts for f in forms_of(pw["shop"], "alice") + forms_of(pw["stale"], "admin")):
                failures.append("A SECRET IS IN A CONSOLE VIEW OR THE AUTHORIZATION DOCUMENT")

            # 5. the search of everything: the passwords in every form, and every session id the target issued
            sessions = [line.strip() for line in (tmpdir / "log" / "sessions.txt").read_text().splitlines() if line.strip()]
            if not sessions:
                failures.append("the target issued no session, so the session search has nothing to look for")
            patterns.write_text("\n".join(forms_of(pw["shop"], "alice") + forms_of(pw["stale"], "admin") + sessions) + "\n")
            positive = count_hits(patterns, f"cat {tmpdir / 'log' / 'requests.jsonl'}")
            print(f"5. the search finds the passwords and the {len(sessions)} session id(s) where they belong (the target's own log): {positive} line(s)")
            if positive < 4:
                failures.append("the search cannot find the passwords and sessions even where they are (the positive control failed)")
            hits = {
                "database (full dump, every table)": count_hits(patterns, f"docker exec {pg} pg_dump -U asm -d asm"),
                "control-plane log": count_hits(patterns, f"docker logs {cp} 2>&1"),
                "worker log": count_hits(patterns, f"docker logs {worker} 2>&1"),
                "egress-proxy log": count_hits(patterns, f"docker logs {PROJECT}-egress-proxy-1 2>&1"),
                "tool-runner log": count_hits(patterns, f"docker logs {PROJECT}-tool-runner-1 2>&1"),
                "raw-egress-gateway log": count_hits(patterns, f"docker logs {PROJECT}-raw-egress-gateway-1 2>&1"),
                "queue (redis, every key)": count_hits(
                    patterns, f"docker exec {PROJECT}-redis-1 sh -c 'for k in $(redis-cli --scan); do redis-cli --no-raw DUMP \"$k\"; done'"),
            }
            for place, n in hits.items():
                print(f"   {place:36} {'clean' if n == 0 else ('SEARCH FAILED' if n < 0 else f'{n} LINE(S) CONTAIN A PASSWORD')}")
                if n != 0:
                    failures.append(f"{place}: {n}")
        except RuntimeError as exc:
            failures.append(str(exc))
        finally:
            sh("docker", "rm", "-f", TOY, check=False)
            try:
                gone = json.loads(last(cpx(CLEANUP_SOURCE)))
                print(f"6. cleanup: {gone}")
                if any(gone["test_account_rows_left"].values()):
                    failures.append(f"test-account rows are left after deleting the engagement: {gone}")
                if seed is not None:
                    residue = count_hits(patterns, f"docker exec {pg} pg_dump -U asm -d asm")
                    if residue != 0:
                        failures.append(f"after cleanup the database still holds a password ({residue})")
            except RuntimeError as exc:
                failures.append(f"cleanup failed: {exc}")
    print("OK: test accounts logged in under the gateway's rules, every other use was refused, and no secret was kept anywhere" if not failures
          else "FAILED:\n  - " + "\n  - ".join(failures))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
