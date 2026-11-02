"""Retest and open items (REQ-RETEST-001..008, GitHub #75).

What a monitor could not do is kept and listed, a run can be restricted to it, and a request that changes data is sent
only after a person confirmed that exact request. The Scope Gateway is not changed by any of this: the claim of a
confirmed request is tested here against the real gateway.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import auth_service, celery_client, open_items, scan_diff
from app.config import get_settings
from app.db.base import get_db
from app.gateway.audit import append_audit_log  # noqa: F401  (the audit helper the code under test uses)
from app.gateway.authorize import ToolCall
from app.main import app
from app.models.approval import ApprovalRequest
from app.models.asset import DiscoveredAsset
from app.models.audit import AuditLog
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.finding import Finding, FindingObservation
from app.models.monitoring import InboxItem
from app.models.open_request import OpenRequest
from app.models.scan_plan import ScanCheck, ScanSurface
from app.models.scan_run import ScanRun
from app.models.user import User
from app.monitoring import on_run_finished
from app.passwords import hash_secret

HOST = "app.example.test"


@pytest.fixture
def client(engine):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _no_broker(monkeypatch):
    sent: list[dict] = []

    def fake(engagement_id, scan_run_id, **kw):
        sent.append({"engagement_id": engagement_id, "scan_run_id": scan_run_id, **kw})
        return "task-1"

    monkeypatch.setattr(celery_client, "enqueue_scan", fake)
    return sent


def _user(db, role="operator") -> User:
    user = User(
        email=f"u-{uuid.uuid4().hex[:10]}@example.com", display_name="U", role=role, status="active",
        must_change_password=False, password_hash=hash_secret("x"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _auth(db, user: User) -> dict:
    token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    return {"Authorization": f"Bearer {token}"}


def _internal() -> dict:
    return {"x-asm-internal-token": get_settings().internal_api_token}


def _engagement(db, owner: User, *, mode="assessment") -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title=f"E-{mode}", source="own_domain", status="active", operating_mode=mode, ai_testing_allowed=True,
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=30),
        owner_user_id=owner.id, target_review_state="confirmed" if mode == "monitoring" else None,
    )
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="example.test",
                      active_allowed=True, authorization_verified=True))
    for category in ("fingerprint", "vuln"):
        db.add(ToolGrant(engagement_id=eng.id, tool_category=category, mode="active", requires_manual_approval=False))
    db.add(DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=HOST, in_scope=True, discovered_via="ct"))
    db.commit()
    db.refresh(eng)
    return eng


def _run(db, eng, *, minutes_ago=60, state="done", **kw) -> ScanRun:
    started = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes_ago)
    run = ScanRun(engagement_id=eng.id, phase="report", state=state, started_at=started,
                  finished_at=started + dt.timedelta(minutes=5), **kw)
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _post_call(eng, run, *, path="/login", body="username=guest&password=guest", target=HOST, method="POST") -> dict:
    """The call as the gateway judged and stored it: what an approval holds."""
    return ToolCall(
        engagement_id=eng.id, tool="http_request", category="vuln", mode="active", target=target,
        args={"method": method, "path": path, "body": body,
              "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "session=SECRET"}},
        is_automated=True, phase="agent", rationale="the login page shows a demo account",
        risk={"level": "low", "description": "establishes a session"}, scan_run_id=run.id,
    ).as_jsonable()


def _approval(db, eng, run, **kw) -> ApprovalRequest:
    ap = ApprovalRequest(
        engagement_id=eng.id, tool_call=_post_call(eng, run, **kw), state="requested",
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=15),
    )
    db.add(ap)
    db.commit()
    return ap


def _withdraw(client, ap) -> dict:
    r = client.post(f"/internal/approvals/{ap.id}/withdraw", json={"reason": "unattended_run"}, headers=_internal())
    assert r.status_code == 200, r.text
    return r.json()


def _plan(db, eng, run, host, port, checks):
    surface = ScanSurface(scan_run_id=run.id, engagement_id=eng.id, host=host, port=port, service_class="web")
    db.add(surface)
    db.flush()
    for seq, (check_id, tool, state, reason, detail) in enumerate(checks, start=1):
        db.add(ScanCheck(scan_run_id=run.id, engagement_id=eng.id, surface_id=surface.id, seq=seq, check_id=check_id,
                         tool=tool, state=state, reason=reason, outcome_summary={"detail": detail} if detail else {}))
    db.commit()


def _audit(db, eng, action) -> list[AuditLog]:
    db.expire_all()
    return list(db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == action)))


# ------------------------------------------------------------- REQ-RETEST-004: a held-back request is kept whole


def test_a_withdrawn_unattended_approval_is_kept_with_everything_a_person_needs(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring")
    run = _run(db, eng, state="running", supervision="unattended")
    ap = _approval(db, eng, run)

    out = _withdraw(client, ap)
    assert out["withdrawn"] is True and out["open_request_id"]

    row = db.get(OpenRequest, uuid.UUID(out["open_request_id"]))
    assert (row.method, row.path, row.target, row.state, row.state_changing) == ("POST", "/login", HOST, "open", True)
    assert row.call == ap.tool_call and row.rationale == "the login page shows a demo account"
    assert row.risk["level"] == "low" and row.reason == "approval_unavailable_unattended"

    item = db.scalar(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.kind == "suggestion"))
    assert item.summary == f"Held back: POST /login on {HOST}" and item.dedupe_key == f"request:{row.id}"
    assert item.detail["method"] == "POST" and item.detail["path"] == "/login"

    entry = next(e for e in client.get("/inbox", headers=h).json() if e["id"] == str(item.id))
    assert entry["link"] == f"/engagements/{eng.id}/open-items" and entry["can_acknowledge"] is False
    assert client.post(f"/inbox/{item.id}/acknowledge", headers=h).status_code == 409
    assert _audit(db, eng, "open_request_parked")


def test_two_different_posts_on_one_host_are_two_items_and_an_identical_one_replaces_the_older(client, db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    run = _run(db, eng, state="running", supervision="unattended")
    first = _withdraw(client, _approval(db, eng, run, path="/login"))["open_request_id"]
    second = _withdraw(client, _approval(db, eng, run, path="/admin/login"))["open_request_id"]
    assert first != second
    assert db.scalar(select(OpenRequest).where(OpenRequest.id == uuid.UUID(second))).path == "/admin/login"

    again = _withdraw(client, _approval(db, eng, run, path="/login"))["open_request_id"]
    db.expire_all()
    states = {str(r.id): r.state for r in db.scalars(select(OpenRequest).where(OpenRequest.engagement_id == eng.id))}
    assert states[first] == "superseded" and states[again] == "open" and states[second] == "open"
    open_inbox = list(db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.state == "open")))
    assert sorted(i.dedupe_key for i in open_inbox) == sorted([f"request:{second}", f"request:{again}"])


def test_a_failure_while_keeping_the_request_is_not_silent_and_still_leaves_a_suggestion(client, db, monkeypatch):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    run = _run(db, eng, state="running", supervision="unattended")
    ap = _approval(db, eng, run)
    real = open_items.monitoring.open_inbox_item
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("inbox write failed")
        return real(*args, **kwargs)

    monkeypatch.setattr(open_items.monitoring, "open_inbox_item", flaky)
    out = _withdraw(client, ap)
    assert out["withdrawn"] is True and out["open_request_id"] is None  # the worker's withdrawal is not what fails
    assert _audit(db, eng, "open_request_park_failed")
    assert db.scalar(select(OpenRequest).where(OpenRequest.engagement_id == eng.id)) is None  # rolled back whole
    thin = db.scalar(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.kind == "suggestion"))
    assert thin is not None and thin.summary.startswith("Suggested manual test")


def test_a_non_http_tool_that_needs_approval_is_kept_too(client, db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    run = _run(db, eng, state="running", supervision="unattended")
    call = ToolCall(engagement_id=eng.id, tool="nikto", category="vuln", mode="active", target=HOST, args={},
                    scan_run_id=run.id).as_jsonable()
    ap = ApprovalRequest(engagement_id=eng.id, tool_call=call, state="requested",
                         expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=15))
    db.add(ap)
    db.commit()
    row = db.get(OpenRequest, uuid.UUID(_withdraw(client, ap)["open_request_id"]))
    assert row.tool == "nikto" and row.method is None and row.state_changing is False


# ------------------------------------------------------------- REQ-RETEST-003: what is still open


def test_what_is_open_comes_from_the_latest_result_of_each_check(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    old = _run(db, eng, minutes_ago=300)
    _plan(db, eng, old, HOST, 443, [
        ("testssl", "testssl", "failed", "web_over_tls", "nonzero_exit"),
        ("ffuf", "ffuf", "partial", "web", "budget_reached"),
        ("wafw00f", "wafw00f", "complete", "web", None),
        ("katana", "katana", "skipped", "switch_off", None),
        ("nuclei:tech", "nuclei", "skipped", "materialized_ip_missing", None),
        ("screenshot", "screenshot", "skipped", "gateway_denied:no_tool_grant", None),
        ("nuclei:generic:1of3", "nuclei", "complete", "generic_web", None),
        ("nuclei:generic:2of3", "nuclei", "failed", "generic_web", "runner_execution_failed"),
        ("nuclei:generic:3of3", "nuclei", "complete", "generic_web", None),
        ("header_findings", "httpx", "skipped", "web_alias_of:other", None),
    ])
    newer = _run(db, eng, minutes_ago=30, retest_items=[{"host": HOST, "check": "ffuf"}], scope_hosts=[HOST])
    _plan(db, eng, newer, HOST, 443, [
        ("ffuf", "ffuf", "complete", "web", None),  # settles the old partial ffuf
        ("testssl", "testssl", "skipped", "not_in_this_run", None),  # says nothing about testssl
    ])

    body = client.get(f"/engagements/{eng.id}/open-items", headers=h).json()
    by_check = {i["check"]: i for i in body["items"] if i["kind"] == "check"}
    assert set(by_check) == {"testssl", "nuclei:tech", "screenshot", "nuclei:generic"}
    assert by_check["testssl"]["state"] == "failed" and by_check["testssl"]["reason"] == "nonzero_exit"
    assert by_check["nuclei:tech"]["reason"] == "materialized_ip_missing"
    assert by_check["screenshot"]["reason"] == "gateway_denied:no_tool_grant"
    assert by_check["nuclei:generic"]["state"] == "failed"  # the shards are one check; the worst one decides
    assert all(i["needs_confirmation"] is False for i in by_check.values())
    assert body["counts"]["checks"] == 4 and body["counts"]["requests"] == 0


def test_a_check_that_did_not_run_because_the_run_ended_is_open(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    run = _run(db, eng, state="aborted")
    _plan(db, eng, run, HOST, 443, [("nuclei:headless", "nuclei", "planned", "web", None)])
    items = client.get(f"/engagements/{eng.id}/open-items", headers=h).json()["items"]
    assert [(i["check"], i["state"], i["reason"]) for i in items] == [("nuclei:headless", "did_not_run", "run_ended_early")]


def test_a_discovery_run_has_no_plan_and_a_running_run_is_not_judged(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    running = _run(db, eng, state="running")
    _plan(db, eng, running, HOST, 443, [("testssl", "testssl", "failed", "x", None)])
    base = _run(db, eng, trigger="baseline")
    assert base.state == "done"
    assert client.get(f"/engagements/{eng.id}/open-items", headers=h).json()["items"] == []


def test_negative_a_reader_who_does_not_manage_the_engagement_does_not_see_the_body_of_a_held_back_request(client, db):
    owner, reader = _user(db), _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    run = _run(db, eng, state="running", supervision="unattended")
    _withdraw(client, _approval(db, eng, run))
    seen = client.get(f"/engagements/{eng.id}/open-items", headers=_auth(db, reader)).json()
    req = next(i for i in seen["items"] if i["kind"] == "request")["request"]
    assert req["body"] is None and req["body_hidden"] is True and req["headers"] == {}
    assert req["method"] == "POST" and req["path"] == "/login"  # what it is stays visible
    assert "guest" not in str(seen)
    own = next(i for i in client.get(f"/engagements/{eng.id}/open-items", headers=_auth(db, owner)).json()["items"]
               if i["kind"] == "request")["request"]
    assert own["body"] == "username=guest&password=guest" and own["body_hidden"] is False


def test_the_held_back_request_is_listed_with_its_headers_redacted_and_expires(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring")
    run = _run(db, eng, state="running", supervision="unattended")
    rid = _withdraw(client, _approval(db, eng, run))["open_request_id"]

    items = client.get(f"/engagements/{eng.id}/open-items", headers=h).json()["items"]
    req = next(i for i in items if i["kind"] == "request")
    assert req["needs_confirmation"] is True and req["state_changing"] is True and req["expired"] is False
    assert req["request"]["method"] == "POST" and req["request"]["path"] == "/login"
    assert req["request"]["body"] == "username=guest&password=guest"
    assert req["request"]["headers"]["Cookie"] == "[redacted]"
    assert "SECRET" not in str(req)
    assert req["request"]["rationale"] == "the login page shows a demo account"

    row = db.get(OpenRequest, uuid.UUID(rid))
    row.created_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=get_settings().open_item_max_age_days + 1)
    db.commit()
    req = next(i for i in client.get(f"/engagements/{eng.id}/open-items", headers=h).json()["items"] if i["kind"] == "request")
    assert req["expired"] is True


# ------------------------------------------------------------- REQ-RETEST-001: the retest of a finding


def _finding(db, eng, *, evidence, category="misconfig", asset=True):
    asset_row = db.scalar(select(DiscoveredAsset).where(DiscoveredAsset.engagement_id == eng.id))
    f = Finding(engagement_id=eng.id, asset_id=asset_row.id if asset else None, category=category, title="F",
                confidence="validated", status="open", severity="medium", fingerprint=uuid.uuid4().hex, evidence=evidence)
    db.add(f)
    db.commit()
    return f


@pytest.mark.parametrize("evidence, category, expected", [
    ({"tool": "ffuf", "wordlist": "quickhits", "port": 443}, "exposure", [{"check": "ffuf", "port": 443}]),
    ({"tool": "ffuf", "wordlist": "raft-medium-dirs", "port": 8443}, "exposure", [{"check": "ffuf:deep", "port": 8443}]),
    ({"tool": "testssl", "port": 443}, "misconfig", [{"check": "testssl", "port": 443}]),
    ({"tool": "nuclei", "template_id": "x"}, "misconfig", [{"tool": "nuclei", "port": None}]),
    ({"tool": "nmap"}, "cve", [{"check": "correlate", "port": None}]),
    ({"tool": "nvd_correlation"}, "cve", [{"check": "correlate", "port": None}]),
])
def test_the_retest_names_the_check_that_produced_the_finding(client, db, evidence, category, expected):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    f = _finding(db, eng, evidence=evidence, category=category)
    plan = client.get(f"/engagements/{eng.id}/findings/{f.id}/retest-plan", headers=h).json()
    assert plan["fallback"] is None and plan["host"] == HOST
    got = [{k: i[k] for k in expected[0]} for i in plan["items"]]
    assert got == expected and all(i["host"] == HOST for i in plan["items"])


def test_a_finding_no_plan_check_produced_falls_back_to_the_host_and_says_so(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    f = _finding(db, eng, evidence={"tool": "vector_agent"})
    plan = client.get(f"/engagements/{eng.id}/findings/{f.id}/retest-plan", headers=h).json()
    assert plan["items"] == [] and plan["fallback"] == "host" and "all checks for this host" in plan["explanation"]
    other = _engagement(db, owner)
    assert client.get(f"/engagements/{other.id}/findings/{f.id}/retest-plan", headers=h).status_code == 404


def _restricted_run(db, eng, owner, finding, items, *, checks):
    run = _run(db, eng, retest_finding_id=finding.id, retest_items=items, scope_hosts=[HOST], initiated_by=owner.email)
    _plan(db, eng, run, HOST, 443, checks)
    return run


def test_a_retest_resolves_the_finding_only_when_its_check_ran_to_the_end_and_did_not_see_it(db):
    owner = _user(db)
    eng = _engagement(db, owner)
    f = _finding(db, eng, evidence={"tool": "testssl", "port": 443})
    items = [{"host": HOST, "port": 443, "check": "testssl"}]
    done = _restricted_run(db, eng, owner, f, items, checks=[("testssl", "testssl", "complete", "web", None)])
    done.health = "ok"
    db.commit()
    on_run_finished(db, done)
    db.refresh(f)
    assert f.status == "resolved" and "retest" in f.status_note


@pytest.mark.parametrize("state", ["failed", "partial", "skipped"])
def test_negative_a_retest_whose_check_did_not_complete_never_resolves_the_finding(db, state):
    owner = _user(db)
    eng = _engagement(db, owner)
    f = _finding(db, eng, evidence={"tool": "testssl", "port": 443})
    items = [{"host": HOST, "port": 443, "check": "testssl"}]
    run = _restricted_run(db, eng, owner, f, items, checks=[("testssl", "testssl", state, "web", None)])
    on_run_finished(db, run)
    db.refresh(f)
    assert f.status == "open"
    assert [a.reason for a in _audit(db, eng, "finding_retest")] == ["retest_incomplete"]


def test_a_retest_that_still_sees_the_finding_leaves_it_open(db):
    owner = _user(db)
    eng = _engagement(db, owner)
    f = _finding(db, eng, evidence={"tool": "testssl", "port": 443})
    run = _restricted_run(db, eng, owner, f, [{"host": HOST, "port": 443, "check": "testssl"}],
                          checks=[("testssl", "testssl", "complete", "web", None)])
    db.add(FindingObservation(scan_run_id=run.id, engagement_id=eng.id, fingerprint=f.fingerprint, finding_id=f.id))
    db.commit()
    on_run_finished(db, run)
    db.refresh(f)
    assert f.status == "open"


# ------------------------------------------------------------- REQ-RETEST-002: a restricted run


def test_a_run_can_be_restricted_to_a_list_of_checks(client, db, _no_broker):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    body = {"items": [{"host": HOST.upper() + ".", "port": 443, "check": "nuclei:generic:2of5"},
                      {"host": HOST, "tool": "nuclei"}]}
    r = client.post(f"/engagements/{eng.id}/scan", json=body, headers=h)
    assert r.status_code == 202, r.text
    assert r.json()["restricted"] is True and r.json()["requests_confirmed"] == 0
    run = db.get(ScanRun, uuid.UUID(r.json()["scan_run_id"]))
    assert run.retest_items == [{"host": HOST, "port": 443, "check": "nuclei:generic"}, {"host": HOST, "tool": "nuclei"}]
    assert run.scope_hosts == [HOST] and run.supervision == "attended"
    started = _audit(db, eng, "scan_run_started")[0]
    assert started.payload["retest_items"] == run.retest_items and started.payload["send_requests"] == []


@pytest.mark.parametrize("body, status", [
    ({"items": []}, 422),
    ({"items": [{"host": "evil.invalid", "check": "ffuf"}]}, 422),
    ({"items": [{"host": HOST}]}, 422),
    ({"items": [{"host": HOST, "check": "ffuf", "tool": "ffuf"}]}, 422),
    ({"items": [{"host": HOST, "tool": "no-such-tool"}]}, 422),
    ({"items": [{"host": HOST, "port": 70000, "check": "ffuf"}]}, 422),
])
def test_a_restriction_that_makes_no_sense_or_leaves_the_scope_is_refused_and_starts_nothing(client, db, body, status):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    assert client.post(f"/engagements/{eng.id}/scan", json=body, headers=h).status_code == status
    assert db.scalar(select(ScanRun).where(ScanRun.engagement_id == eng.id)) is None


def test_negative_a_restricted_run_is_never_the_baseline_of_a_comparison(db):
    owner = _user(db)
    eng = _engagement(db, owner)
    full = _run(db, eng, minutes_ago=300)
    host_limited = _run(db, eng, minutes_ago=200, scope_hosts=[HOST])
    restricted = _run(db, eng, minutes_ago=100, retest_items=[{"host": HOST, "check": "ffuf"}], scope_hosts=[HOST])
    request_only = _run(db, eng, minutes_ago=50, retest_items=[])
    latest = _run(db, eng, minutes_ago=10)
    assert scan_diff._previous_run(db, latest).id == full.id
    assert host_limited.id != full.id and restricted.id != full.id and request_only.id != full.id


def test_a_restricted_run_of_a_monitor_raises_no_change_event_and_still_gets_its_own_snapshot(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    run = _run(db, eng, retest_items=[{"host": HOST, "check": "ffuf"}], scope_hosts=[HOST], health=None)
    summary = on_run_finished(db, run)
    assert summary["events"] == 0
    assert _audit(db, eng, "run_evaluated") == []  # the full-run evaluation did not happen


# ------------------------------------------------------------- REQ-RETEST-008: attended on a monitor


def test_a_monitor_runs_attended_only_when_the_run_is_restricted_to_what_is_open(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    mon = _engagement(db, owner, mode="monitoring")
    full = client.post(f"/engagements/{mon.id}/scan", json={"supervision": "attended"}, headers=h)
    assert full.status_code == 202 and full.json()["supervision"] == "unattended"  # ignored, as REQ-MODE-002 says
    run = db.get(ScanRun, uuid.UUID(full.json()["scan_run_id"]))
    run.state = "done"
    db.commit()
    items = {"items": [{"host": HOST, "check": "ffuf"}]}
    attended = client.post(f"/engagements/{mon.id}/scan", json={**items, "supervision": "attended"}, headers=h)
    assert attended.status_code == 202 and attended.json()["supervision"] == "attended"
    db.get(ScanRun, uuid.UUID(attended.json()["scan_run_id"])).state = "done"
    db.commit()
    silent = client.post(f"/engagements/{mon.id}/scan", json=items, headers=h)
    assert silent.json()["supervision"] == "unattended"


# ------------------------------------------------------------- REQ-RETEST-006: sending a confirmed request


def _held_back(client, db, eng, **kw) -> str:
    run = _run(db, eng, state="done", supervision="unattended", minutes_ago=120)
    return _withdraw(client, _approval(db, eng, run, **kw))["open_request_id"]


def test_choosing_to_send_a_request_is_the_approval_for_exactly_that_request(client, db, _no_broker):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring")
    rid = _held_back(client, db, eng)
    other = _held_back(client, db, eng, path="/admin/login")

    r = client.post(f"/engagements/{eng.id}/scan", json={"send_requests": [rid], "supervision": "attended"}, headers=h)
    assert r.status_code == 202, r.text
    assert r.json()["requests_confirmed"] == 1 and r.json()["supervision"] == "attended"
    run = db.get(ScanRun, uuid.UUID(r.json()["scan_run_id"]))
    assert run.retest_items == []  # nothing is checked, one confirmed request is sent

    db.expire_all()
    sent, kept = db.get(OpenRequest, uuid.UUID(rid)), db.get(OpenRequest, uuid.UUID(other))
    assert sent.state == "sent" and sent.sent_run_id == run.id and sent.decided_by == owner.email
    assert kept.state == "open" and kept.sent_approval_id is None  # not named, so never sent
    approvals = list(db.scalars(select(ApprovalRequest).where(ApprovalRequest.engagement_id == eng.id,
                                                              ApprovalRequest.state == "approved")))
    assert [a.id for a in approvals] == [sent.sent_approval_id]
    assert approvals[0].approved_by == owner.email and approvals[0].tool_call["scan_run_id"] == str(run.id)
    assert approvals[0].tool_call["args"]["path"] == "/login"
    assert [a.reason for a in _audit(db, eng, "open_request_confirmed")] == ["individual_confirmation"]
    assert any(a.payload.get("via") == "open_request" for a in _audit(db, eng, "approval"))

    claim = client.post("/internal/scan-runs/{}/claim".format(run.id), json={"task_id": "t"}, headers=_internal())
    assert claim.status_code == 200 and claim.json()["send_approval_ids"] == [str(sent.sent_approval_id)]
    assert claim.json()["retest_items"] == []


def test_the_confirmed_call_passes_the_unchanged_gateway_claim_and_only_once(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring")
    rid = _held_back(client, db, eng)
    r = client.post(f"/engagements/{eng.id}/scan", json={"send_requests": [rid], "supervision": "attended"}, headers=h)
    run = db.get(ScanRun, uuid.UUID(r.json()["scan_run_id"]))
    run.state, run.attempt = "running", 1
    db.commit()
    approval_id = db.get(OpenRequest, uuid.UUID(rid)).sent_approval_id

    first = client.post(f"/internal/approvals/{approval_id}/claim", headers=_internal()).json()
    assert first["allowed"] is True and first["tool_call"]["args"]["body"] == "username=guest&password=guest"
    again = client.post(f"/internal/approvals/{approval_id}/claim", headers=_internal()).json()
    assert again["allowed"] is False and again["reason"].startswith("approval_not_claimable")


def test_negative_the_approval_cannot_be_used_for_another_request_and_expires(client, db):
    from app.gateway.authorize import authorize

    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring")
    rid = _held_back(client, db, eng)
    r = client.post(f"/engagements/{eng.id}/scan", json={"send_requests": [rid], "supervision": "attended"}, headers=h)
    run = db.get(ScanRun, uuid.UUID(r.json()["scan_run_id"]))
    run.state, run.attempt = "running", 1
    db.commit()
    approval = db.get(ApprovalRequest, db.get(OpenRequest, uuid.UUID(rid)).sent_approval_id)

    # The same approval, offered for a different request than the one the person confirmed: the gateway refuses.
    other = ToolCall(
        engagement_id=eng.id, tool="http_request", category="vuln", mode="active", target=HOST,
        args={"method": "POST", "path": "/delete-everything", "body": "x=1"}, is_automated=True, phase="agent",
        rationale="r", risk={"level": "low", "description": "d"}, scan_run_id=run.id,
    )
    assert authorize(db, other, approved_request_id=approval.id).reason == "approval_call_mismatch"
    db.refresh(approval)
    assert approval.state == "approved"  # the mismatch used nothing up

    approval.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    db.commit()
    denied = client.post(f"/internal/approvals/{approval.id}/claim", headers=_internal()).json()
    assert denied["allowed"] is False and denied["reason"] == "approval_expired"


@pytest.mark.parametrize("case", ["unknown", "other_engagement", "sent", "rejected", "expired"])
def test_negative_a_request_that_is_not_open_and_unexpired_for_this_engagement_starts_nothing(client, db, case):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring")
    other = _engagement(db, owner, mode="monitoring")
    rid = _held_back(client, db, other if case == "other_engagement" else eng)
    row = db.get(OpenRequest, uuid.UUID(rid))
    if case == "sent":
        row.state = "sent"
    elif case == "rejected":
        row.state = "rejected"
    elif case == "expired":
        row.created_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=get_settings().open_item_max_age_days + 1)
    db.commit()
    asked = str(uuid.uuid4()) if case == "unknown" else rid
    r = client.post(f"/engagements/{eng.id}/scan", json={"send_requests": [asked], "supervision": "attended"}, headers=h)
    assert r.status_code in (404, 409), r.text
    assert db.scalar(select(ScanRun).where(ScanRun.engagement_id == eng.id, ScanRun.state == "running")) is None
    assert list(db.scalars(select(ApprovalRequest).where(ApprovalRequest.state == "approved"))) == []


def test_negative_a_request_that_changes_data_is_never_sent_in_an_unattended_run(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring")
    rid = _held_back(client, db, eng)
    r = client.post(f"/engagements/{eng.id}/scan", json={"send_requests": [rid]}, headers=h)  # no attended supervision
    assert r.status_code == 422 and "attended" in r.text
    db.expire_all()
    assert db.get(OpenRequest, uuid.UUID(rid)).state == "open"
    assert list(db.scalars(select(ApprovalRequest).where(ApprovalRequest.state == "approved"))) == []


def test_negative_only_the_owner_or_an_administrator_can_confirm_or_reject(client, db):
    owner, stranger, admin = _user(db), _user(db), _user(db, role="admin")
    eng = _engagement(db, owner, mode="monitoring")
    rid = _held_back(client, db, eng)
    hs = _auth(db, stranger)
    assert client.get(f"/engagements/{eng.id}/open-items", headers=hs).status_code == 200  # everyone reads
    assert client.post(f"/engagements/{eng.id}/scan", json={"send_requests": [rid], "supervision": "attended"},
                       headers=hs).status_code == 403
    assert client.post(f"/engagements/{eng.id}/open-requests/{rid}/reject", headers=hs).status_code == 403
    db.expire_all()
    assert db.get(OpenRequest, uuid.UUID(rid)).state == "open"
    ok = client.post(f"/engagements/{eng.id}/open-requests/{rid}/reject", headers=_auth(db, admin))
    assert ok.status_code == 200 and ok.json()["state"] == "rejected"


def test_a_rejected_request_is_gone_from_the_list_and_the_inbox_and_audited(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring")
    rid = _held_back(client, db, eng)
    assert client.post(f"/engagements/{eng.id}/open-requests/{rid}/reject", headers=h).json()["state"] == "rejected"
    assert [i for i in client.get(f"/engagements/{eng.id}/open-items", headers=h).json()["items"] if i["kind"] == "request"] == []
    assert [e for e in client.get("/inbox", headers=h).json() if e["kind"] == "suggestion"] == []
    audit = _audit(db, eng, "open_request_rejected")
    assert audit and audit[0].actor == f"user:{owner.email}"
    assert client.post(f"/engagements/{eng.id}/open-requests/{rid}/reject", headers=h).status_code == 409


# ------------------------------------------------------------- REQ-RETEST-007: nothing is lost


def test_a_confirmed_request_that_was_not_sent_is_open_again_with_the_reason(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring")
    rid = _held_back(client, db, eng)
    r = client.post(f"/engagements/{eng.id}/scan", json={"send_requests": [rid], "supervision": "attended"}, headers=h)
    run = db.get(ScanRun, uuid.UUID(r.json()["scan_run_id"]))
    approval = db.get(ApprovalRequest, db.get(OpenRequest, uuid.UUID(rid)).sent_approval_id)
    approval.state, approval.execution_error = "execution_failed", "outside_time_window"  # the claim was denied
    run.state = "done"
    db.commit()

    on_run_finished(db, run)
    db.expire_all()
    row = db.get(OpenRequest, uuid.UUID(rid))
    assert row.state == "open" and row.reason == "not_sent:outside_time_window" and row.decided_by is None
    assert [a.reason for a in _audit(db, eng, "open_request_not_sent")] == ["outside_time_window"]
    item = next(i for i in client.get(f"/engagements/{eng.id}/open-items", headers=h).json()["items"] if i["kind"] == "request")
    assert item["id"] == rid and item["reason"] == "not_sent:outside_time_window"
    assert db.scalar(select(InboxItem).where(InboxItem.dedupe_key == f"request:{rid}", InboxItem.state == "open")) is not None


def test_a_request_that_was_sent_stays_sent(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring")
    rid = _held_back(client, db, eng)
    r = client.post(f"/engagements/{eng.id}/scan", json={"send_requests": [rid], "supervision": "attended"}, headers=h)
    run = db.get(ScanRun, uuid.UUID(r.json()["scan_run_id"]))
    db.get(ApprovalRequest, db.get(OpenRequest, uuid.UUID(rid)).sent_approval_id).state = "consumed"
    run.state = "done"
    db.commit()
    on_run_finished(db, run)
    db.expire_all()
    assert db.get(OpenRequest, uuid.UUID(rid)).state == "sent"
    assert _audit(db, eng, "open_request_not_sent") == []
