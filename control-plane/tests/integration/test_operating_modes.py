"""Operating modes (REQ-MODE-001..008, REQ-MODE-011/012, REQ-MODE-014, REQ-MODE-017,
REQ-MON-002) at the HTTP layer and on the domain functions.

Not covered here, because it lives in the Scope Gateway and was withheld pending an
explicit decision (see the operating-modes requirement records): the gateway-side
deny rules for monitoring/passive/held hosts, and the standing consent."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import auth_service, celery_client, monitoring, scan_diff
from app.db.base import get_db
from app.gateway.authorize import ToolCall, authorize
from app.main import app
from app.models.asset import DiscoveredAsset
from app.models.engagement import Engagement, ScopeAsset, ToolApprovalPolicy, ToolGrant
from app.models.finding import Finding, FindingObservation
from app.models.monitoring import (
    AlertEvent,
    ChangeEvent,
    InboxItem,
    NotificationTarget,
    RunInventorySnapshot,
)
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
from app.webhook_guard import WebhookTargetRefused, sign, validate_webhook_url


# ----------------------------------------------------------------- helpers


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


def _engagement(db, owner: User, *, mode="assessment", status="active", source="own_domain", **kw) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title=f"E-{mode}", source=source, status=status, operating_mode=mode,
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=30),
        owner_user_id=owner.id, **kw,
    )
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="example.test",
                      active_allowed=True, authorization_verified=True))
    db.add(ToolGrant(engagement_id=eng.id, tool_category="fingerprint", mode="active", requires_manual_approval=False))
    db.commit()
    db.refresh(eng)
    return eng


def _run(db, eng, *, minutes_ago=60, state="done", reason=None, health=None, **kw) -> ScanRun:
    started = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes_ago)
    run = ScanRun(
        engagement_id=eng.id, phase="report", state=state, state_reason=reason, started_at=started,
        finished_at=started + dt.timedelta(minutes=5), health=health, **kw,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


# -------------------------------------------------- REQ-MODE-001: the mode


def test_new_engagement_defaults_to_assessment_and_monitoring_can_be_chosen(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    now = dt.datetime.now(dt.timezone.utc)
    window = {"authorized_from": now.isoformat(), "authorized_until": (now + dt.timedelta(days=30)).isoformat()}
    legacy = client.post("/engagements", json={"title": "Plain", **window}, headers=h)
    assert legacy.status_code == 201 and legacy.json()["operating_mode"] == "assessment"
    mon = client.post("/engagements", json={"title": "Mon", "operating_mode": "monitoring", **window}, headers=h)
    assert mon.status_code == 201 and mon.json()["operating_mode"] == "monitoring"
    assert mon.json()["asset_review_enabled"] is False


def test_mode_is_fixed_once_active_and_monitoring_refuses_asset_review(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    active = _engagement(db, owner, status="active")
    r = client.patch(f"/engagements/{active.id}", json={"operating_mode": "monitoring"}, headers=h)
    assert r.status_code == 409

    draft = _engagement(db, owner, status="draft", mode="monitoring")
    r = client.patch(f"/engagements/{draft.id}", json={"asset_review_enabled": True}, headers=h)
    assert r.status_code == 409
    # a draft's mode can still be chosen
    d2 = _engagement(db, owner, status="draft")
    r = client.patch(f"/engagements/{d2.id}", json={"operating_mode": "monitoring"}, headers=h)
    assert r.status_code == 200 and r.json()["operating_mode"] == "monitoring"


def test_monitoring_activation_sets_a_review_date_within_the_window(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, status="draft", mode="monitoring")
    r = client.post(f"/engagements/{eng.id}/activate", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["review_at"] is not None
    assert dt.datetime.fromisoformat(body["review_at"]) <= dt.datetime.fromisoformat(body["authorized_until"])


# --------------------------------------------- REQ-MODE-002: run attribution


def test_a_started_run_records_who_started_it_and_is_audited(client, db, _no_broker):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    r = client.post(f"/engagements/{eng.id}/scan", headers=h)
    assert r.status_code == 202, r.text
    run = db.get(ScanRun, uuid.UUID(r.json()["scan_run_id"]))
    assert run.trigger == "manual" and run.initiated_by == owner.email and run.supervision == "attended"
    assert _no_broker and _no_broker[0]["scan_run_id"] == str(run.id)

    from app.models.audit import AuditLog
    row = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == "scan_run_started")).one()
    assert row.actor == f"user:{owner.email}"
    assert row.payload["trigger"] == "manual" and row.payload["supervision"] == "attended"


def test_supervision_is_chosen_for_assessments_and_fixed_for_monitoring(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    assess = _engagement(db, owner)
    r = client.post(f"/engagements/{assess.id}/scan", json={"supervision": "semi_attended"}, headers=h)
    assert r.status_code == 202 and r.json()["supervision"] == "semi_attended"

    mon = _engagement(db, owner, mode="monitoring")
    r = client.post(f"/engagements/{mon.id}/scan", json={"supervision": "attended"}, headers=h)
    assert r.status_code == 202 and r.json()["supervision"] == "unattended"


def test_a_second_start_is_refused_while_a_run_is_active(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    assert client.post(f"/engagements/{eng.id}/scan", headers=h).status_code == 202
    assert client.post(f"/engagements/{eng.id}/scan", headers=h).status_code == 409


def test_a_non_owner_cannot_start_a_run(client, db):
    owner, other = _user(db), _user(db)
    eng = _engagement(db, owner)
    r = client.post(f"/engagements/{eng.id}/scan", headers=_auth(db, other))
    assert r.status_code == 403


# ------------------------------------ REQ-MODE-017: scoped runs and retests


def test_a_run_can_be_limited_to_in_scope_hosts_and_never_widened(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    db.add(DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value="www.example.test",
                           in_scope=True, discovered_via="ct"))
    db.commit()
    bad = client.post(f"/engagements/{eng.id}/scan", json={"hosts": ["evil.invalid"]}, headers=h)
    assert bad.status_code == 422
    ok = client.post(f"/engagements/{eng.id}/scan", json={"hosts": ["WWW.example.test"]}, headers=h)
    assert ok.status_code == 202
    run = db.get(ScanRun, uuid.UUID(ok.json()["scan_run_id"]))
    assert run.scope_hosts == ["www.example.test"]


def test_a_retest_resolves_a_finding_that_is_no_longer_observed(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    asset = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value="www.example.test",
                            in_scope=True, discovered_via="ct")
    db.add(asset)
    db.flush()
    finding = Finding(engagement_id=eng.id, asset_id=asset.id, category="misconfig", title="Old", confidence="validated",
                      status="open", severity="medium", fingerprint="fp-old")
    db.add(finding)
    db.commit()
    r = client.post(f"/engagements/{eng.id}/scan", json={"retest_finding_id": str(finding.id)}, headers=h)
    assert r.status_code == 202, r.text
    run = db.get(ScanRun, uuid.UUID(r.json()["scan_run_id"]))
    assert run.scope_hosts == ["www.example.test"] and run.retest_finding_id == finding.id
    run.state, run.state_reason = "done", None
    db.commit()
    monitoring.on_run_finished(db, run)
    db.refresh(finding)
    assert finding.status == "resolved"


def test_a_retest_keeps_a_finding_that_is_still_observed(db):
    owner = _user(db)
    eng = _engagement(db, owner)
    finding = Finding(engagement_id=eng.id, category="misconfig", title="Still", confidence="validated",
                      status="open", severity="high", fingerprint="fp-still")
    db.add(finding)
    db.flush()
    run = _run(db, eng, retest_finding_id=finding.id, initiated_by=owner.email)
    db.add(FindingObservation(scan_run_id=run.id, engagement_id=eng.id, fingerprint="fp-still", finding_id=finding.id))
    db.commit()
    monitoring.on_run_finished(db, run)
    db.refresh(finding)
    assert finding.status == "open"


# --------------------------------------------- REQ-MODE-003: lifecycle


def test_pause_stops_the_run_and_the_gateway_denies_everything(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    run = _run(db, eng, state="running", health=None)
    r = client.post(f"/engagements/{eng.id}/pause", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "paused"
    db.expire_all()  # the API committed from another session
    db.refresh(run)
    assert run.state == "aborted" and run.cancel_requested is True

    decision = authorize(db, ToolCall(engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active",
                                      target="www.example.test", phase="fingerprint", scan_run_id=run.id))
    assert decision.allowed is False and decision.reason == "engagement_not_active"


def test_resume_needs_an_open_window_and_close_cannot_be_undone(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    assert client.post(f"/engagements/{eng.id}/pause", headers=h).status_code == 200
    assert client.post(f"/engagements/{eng.id}/resume", headers=h).json()["status"] == "active"
    assert client.post(f"/engagements/{eng.id}/close", headers=h).json()["status"] == "completed"
    assert client.post(f"/engagements/{eng.id}/resume", headers=h).status_code == 409

    expired = _engagement(db, owner, status="paused")
    expired.authorized_until = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    db.commit()
    assert client.post(f"/engagements/{expired.id}/resume", headers=h).status_code == 409


def test_close_is_refused_while_a_run_is_active_and_revoke_is_final(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    _run(db, eng, state="running")
    assert client.post(f"/engagements/{eng.id}/close", headers=h).status_code == 409
    assert client.post(f"/engagements/{eng.id}/revoke", headers=h).json()["status"] == "revoked"
    assert client.post(f"/engagements/{eng.id}/resume", headers=h).status_code == 409
    assert client.post(f"/engagements/{eng.id}/pause", headers=h).status_code == 409


def test_lifecycle_controls_are_for_owner_or_admin_only(client, db):
    owner, other, admin = _user(db), _user(db), _user(db, role="admin")
    eng = _engagement(db, owner)
    for action in ("pause", "close", "revoke"):
        assert client.post(f"/engagements/{eng.id}/{action}", headers=_auth(db, other)).status_code == 403
    db.refresh(eng)
    assert eng.status == "active"
    assert client.post(f"/engagements/{eng.id}/pause", headers=_auth(db, admin)).status_code == 200


# ------------------------------------------ REQ-MODE-004: diff baseline


def test_the_diff_ignores_failed_aborted_and_partial_runs_as_baseline(db):
    owner = _user(db)
    eng = _engagement(db, owner)
    good = _run(db, eng, minutes_ago=400, state="done")
    _run(db, eng, minutes_ago=300, state="failed", reason="pipeline_error:X:fingerprint")
    _run(db, eng, minutes_ago=200, state="done", reason="coverage_partial:nuclei=2")
    _run(db, eng, minutes_ago=100, state="aborted", reason="cancelled_by_operator")
    current = _run(db, eng, minutes_ago=10, state="done")
    diff = scan_diff.compute_diff(db, current)
    assert diff["has_baseline"] is True and diff["previous_run_id"] == str(good.id)


def test_the_diff_has_no_baseline_when_no_earlier_run_was_healthy(db):
    owner = _user(db)
    eng = _engagement(db, owner)
    _run(db, eng, minutes_ago=300, state="failed")
    current = _run(db, eng, minutes_ago=10, state="done", reason="coverage_degraded:nmap=timeout")
    diff = scan_diff.compute_diff(db, current)
    assert diff["has_baseline"] is False and diff["run_coverage_reduced"] is True


# ----------------------------------------- REQ-MODE-006: capabilities


def test_capabilities_view_apply_and_copy_of_defaults(client, db):
    admin = _user(db, role="admin")
    h = _auth(db, admin)
    now = dt.datetime.now(dt.timezone.utc)
    window = {"authorized_from": now.isoformat(), "authorized_until": (now + dt.timedelta(days=30)).isoformat()}

    # A change of the defaults is copied into NEW engagements only.
    r = client.put("/settings/monitoring-defaults", json={"capabilities": {"content_discovery": False}}, headers=h)
    assert r.status_code == 200 and r.json()["capabilities"]["content_discovery"] is False
    first = client.post("/engagements", json={"title": "A", "operating_mode": "monitoring", **window}, headers=h).json()
    caps = {c["id"]: c["enabled"] for c in client.get(f"/engagements/{first['id']}/capabilities", headers=h).json()["capabilities"]}
    assert caps["content_discovery"] is False and caps["web_fingerprint"] is True and caps["agent"] is False

    client.put("/settings/monitoring-defaults", json={"capabilities": {"content_discovery": True}}, headers=h)
    again = {c["id"]: c["enabled"] for c in client.get(f"/engagements/{first['id']}/capabilities", headers=h).json()["capabilities"]}
    assert again["content_discovery"] is False, "a change of the defaults must not change an existing engagement"
    second = client.post("/engagements", json={"title": "B", "operating_mode": "monitoring", **window}, headers=h).json()
    caps2 = {c["id"]: c["enabled"] for c in client.get(f"/engagements/{second['id']}/capabilities", headers=h).json()["capabilities"]}
    assert caps2["content_discovery"] is True


def test_capability_change_is_one_audit_row_and_holds_for_the_gateway(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring", status="draft")
    r = client.put(f"/engagements/{eng.id}/capabilities", json={"capabilities": {"vulnerability_templates": True}}, headers=h)
    assert r.status_code == 200
    off = client.put(f"/engagements/{eng.id}/capabilities", json={"capabilities": {"vulnerability_templates": False}}, headers=h)
    caps = {c["id"]: c["enabled"] for c in off.json()["capabilities"]}
    assert caps["vulnerability_templates"] is False
    row = db.get(ToolApprovalPolicy, {"engagement_id": eng.id, "tool_name": "nuclei"})
    assert row is not None and row.enabled is False
    from app.models.audit import AuditLog
    updates = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == "capabilities_updated")).all()
    assert len(updates) == 2


def test_widening_after_activation_needs_confirmation_and_no_active_run(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring", status="active")
    body = {"capabilities": {"vulnerability_templates": True}}
    r = client.put(f"/engagements/{eng.id}/capabilities", json=body, headers=h)
    assert r.status_code == 409 and "confirmation_required" in r.text
    ok = client.put(f"/engagements/{eng.id}/capabilities", json={**body, "confirm_widening": True}, headers=h)
    assert ok.status_code == 200

    _run(db, eng, state="running")
    blocked = client.put(f"/engagements/{eng.id}/capabilities",
                         json={"capabilities": {"crawling": True}, "confirm_widening": True}, headers=h)
    assert blocked.status_code == 409 and "scan_run_active" in blocked.text
    # narrowing is always possible
    narrow = client.put(f"/engagements/{eng.id}/capabilities", json={"capabilities": {"vulnerability_templates": False}}, headers=h)
    assert narrow.status_code == 200


def test_capabilities_cannot_be_set_on_an_assessment(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    r = client.put(f"/engagements/{eng.id}/capabilities", json={"capabilities": {"agent": True}}, headers=_auth(db, owner))
    assert r.status_code == 409


def test_monitoring_refuses_credential_exploit_grants_and_approval_settings(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring", status="draft")
    for category in ("cred", "exploit"):
        r = client.post(f"/engagements/{eng.id}/tool-grants",
                        json={"tool_category": category, "mode": "active", "requires_manual_approval": False}, headers=h)
        assert r.status_code == 409, category
    r = client.post(f"/engagements/{eng.id}/tool-grants",
                    json={"tool_category": "vuln", "mode": "active", "requires_manual_approval": True}, headers=h)
    assert r.status_code == 409
    r = client.put(f"/engagements/{eng.id}/config", json={"tools": [{"tool": "nuclei", "requires_approval": True}]}, headers=h)
    assert r.status_code == 409


def test_monitoring_defaults_are_admin_only(client, db):
    operator = _user(db)
    r = client.put("/settings/monitoring-defaults", json={"fragility_breaker": False}, headers=_auth(db, operator))
    assert r.status_code == 403


# ------------------------------------------------- REQ-MODE-008: hold


def _held_setup(db, owner):
    eng = _engagement(db, owner, mode="monitoring", new_asset_policy="hold", source="customer")
    run = _run(db, eng, state="running", minutes_ago=1)
    now = dt.datetime.now(dt.timezone.utc)
    apex = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value="example.test", in_scope=True,
                           discovered_via="scope-direct", first_seen=now, last_seen=now)
    sub = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value="new.example.test", in_scope=True,
                          discovered_via="ct", first_seen=now, last_seen=now)
    old = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value="old.example.test", in_scope=True,
                          discovered_via="ct", first_seen=now - dt.timedelta(days=3), last_seen=now)
    db.add_all([apex, sub, old])
    db.commit()
    return eng, run, apex, sub, old


def test_hold_keeps_back_only_new_undeclared_hosts(db):
    owner = _user(db)
    eng, run, apex, sub, old = _held_setup(db, owner)
    result = monitoring.evaluate_hold(db, run, [{"asset_id": str(a.id)} for a in (apex, sub, old)])
    assert result["held"] == [str(sub.id)]
    assert set(result["released"]) == {str(apex.id), str(old.id)}
    db.refresh(sub)
    assert sub.hold_state == "held"
    item = db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.kind == "held_asset")).one()
    assert item.detail["value"] == "new.example.test"
    # asking again does not create a second item and keeps it held
    again = monitoring.evaluate_hold(db, run, [{"asset_id": str(sub.id)}])
    assert again["held"] == [str(sub.id)]
    assert db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.state == "open")).all().__len__() == 1


def test_acknowledging_a_held_host_releases_it_for_the_next_run(client, db):
    owner = _user(db)
    eng, run, apex, sub, old = _held_setup(db, owner)
    monitoring.evaluate_hold(db, run, [{"asset_id": str(sub.id)}])
    item = db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id)).one()
    r = client.post(f"/inbox/{item.id}/acknowledge", headers=_auth(db, owner))
    assert r.status_code == 200 and r.json()["released_asset"] == "new.example.test"
    db.refresh(sub)
    assert sub.hold_state == "released"
    run.state = "done"
    db.commit()
    nxt = _run(db, eng, state="running", minutes_ago=0)
    assert monitoring.evaluate_hold(db, nxt, [{"asset_id": str(sub.id)}])["released"] == [str(sub.id)]


def test_hold_does_nothing_for_auto_policy_and_for_assessments(db):
    owner = _user(db)
    for mode, policy in (("monitoring", "auto"), ("assessment", "hold")):
        eng = _engagement(db, owner, mode=mode, new_asset_policy=policy)
        run = _run(db, eng, state="running", minutes_ago=1)
        now = dt.datetime.now(dt.timezone.utc)
        asset = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=f"n-{mode}.example.test",
                                in_scope=True, discovered_via="ct", first_seen=now, last_seen=now)
        db.add(asset)
        db.commit()
        assert monitoring.evaluate_hold(db, run, [{"asset_id": str(asset.id)}])["held"] == []


def test_only_the_owner_or_an_admin_can_acknowledge(client, db):
    owner, other = _user(db), _user(db)
    eng, run, apex, sub, old = _held_setup(db, owner)
    monitoring.evaluate_hold(db, run, [{"asset_id": str(sub.id)}])
    item = db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id)).one()
    assert client.post(f"/inbox/{item.id}/acknowledge", headers=_auth(db, other)).status_code == 403
    db.refresh(sub)
    assert sub.hold_state == "held"


def test_the_inbox_lists_only_my_engagements_and_admins_see_all(client, db):
    owner, other, admin = _user(db), _user(db), _user(db, role="admin")
    eng = _engagement(db, owner, mode="monitoring")
    monitoring.add_suggestion(db, eng.id, "nuclei", "www.example.test", "worth a look")
    db.commit()
    assert [i["kind"] for i in client.get("/inbox", headers=_auth(db, owner)).json()] == ["suggestion"]
    assert client.get("/inbox", headers=_auth(db, other)).json() == []
    assert len(client.get("/inbox", headers=_auth(db, admin)).json()) == 1
    assert client.get("/inbox/count", headers=_auth(db, owner)).json() == {"count": 1}


def test_a_suggestion_is_raised_once_while_it_is_open(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    assert monitoring.add_suggestion(db, eng.id, "nuclei", "a.example.test", "x") is not None
    assert monitoring.add_suggestion(db, eng.id, "nuclei", "A.example.test", "x") is None
    db.commit()
    assert len(db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id)).all()) == 1


# ------------------------------------------------ REQ-MODE-012/013: feed


def _snapshot(db, run, assets=(), services=()):
    for a in assets:
        db.add(RunInventorySnapshot(scan_run_id=run.id, engagement_id=run.engagement_id, kind="asset", key=a, data={}))
    for key, product, version in services:
        db.add(RunInventorySnapshot(scan_run_id=run.id, engagement_id=run.engagement_id, kind="service", key=key,
                                    data={"product": product, "version": version}))
    db.commit()


def test_health_of_a_run(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    assert monitoring.health_of(_run(db, eng)) == "ok"
    assert monitoring.health_of(_run(db, eng, reason="coverage_partial:nuclei=1")) == "degraded"
    assert monitoring.health_of(_run(db, eng, state="aborted", reason="reaped_stale_heartbeat")) == "failed"
    assert monitoring.health_of(_run(db, eng, state="failed")) == "failed"


def test_the_first_healthy_run_is_the_baseline_and_produces_no_events(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    run = _run(db, eng, minutes_ago=10, health="ok")
    _snapshot(db, run, assets=["a.example.test"], services=[("a.example.test:443/tcp", "nginx", "1.0")])
    assert monitoring.compute_changes(db, run) == []


def test_assets_and_ports_that_appear_change_and_disappear(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    base = _run(db, eng, minutes_ago=200, health="ok")
    _snapshot(db, base, assets=["a.example.test", "gone.example.test"],
              services=[("a.example.test:443/tcp", "nginx", "1.0"), ("a.example.test:22/tcp", "openssh", "8")])
    now = _run(db, eng, minutes_ago=10, health="ok")
    _snapshot(db, now, assets=["a.example.test", "b.example.test"],
              services=[("a.example.test:443/tcp", "nginx", "1.1"), ("a.example.test:8080/tcp", "tomcat", "9")])
    kinds = {(e.kind, e.subject) for e in monitoring.compute_changes(db, now)}
    assert ("asset_new", "b.example.test") in kinds
    assert ("asset_gone", "gone.example.test") in kinds
    assert ("port_opened", "a.example.test:8080/tcp") in kinds
    assert ("port_closed", "a.example.test:22/tcp") in kinds
    assert ("service_changed", "a.example.test:443/tcp") in kinds


def test_a_degraded_run_never_reports_things_gone_or_fixed(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    base = _run(db, eng, minutes_ago=200, health="ok")
    _snapshot(db, base, assets=["a.example.test", "b.example.test"],
              services=[("a.example.test:22/tcp", "openssh", "8")])
    short = _run(db, eng, minutes_ago=10, health="degraded", reason="coverage_partial:nuclei=3")
    _snapshot(db, short, assets=["a.example.test", "c.example.test"])
    kinds = {e.kind for e in monitoring.compute_changes(db, short)}
    assert "asset_new" in kinds
    assert kinds.isdisjoint({"asset_gone", "port_closed", "finding_resolved"})


def test_a_degraded_run_is_not_the_baseline_of_the_next_one(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    good = _run(db, eng, minutes_ago=300, health="ok")
    _snapshot(db, good, assets=["a.example.test", "b.example.test"])
    short = _run(db, eng, minutes_ago=200, health="degraded", reason="coverage_degraded:nmap=timeout")
    _snapshot(db, short, assets=["a.example.test"])
    nxt = _run(db, eng, minutes_ago=10, health="ok")
    _snapshot(db, nxt, assets=["a.example.test", "b.example.test"])
    # b was "gone" only in the degraded run: against the healthy baseline nothing changed.
    assert monitoring.compute_changes(db, nxt) == []


def _finding(db, eng, fp, title="F", severity="high", confidence="validated", category="misconfig"):
    f = Finding(engagement_id=eng.id, category=category, title=title, confidence=confidence, status="open",
                severity=severity, fingerprint=fp)
    db.add(f)
    db.flush()
    return f


def _obs(db, run, finding):
    db.add(FindingObservation(scan_run_id=run.id, engagement_id=run.engagement_id,
                              fingerprint=finding.fingerprint, finding_id=finding.id))


def test_a_finding_is_resolved_only_after_two_clean_runs(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    f = _finding(db, eng, "fp-1", "Exposed panel")
    r1 = _run(db, eng, minutes_ago=400, health="ok"); _obs(db, r1, f)
    r2 = _run(db, eng, minutes_ago=300, health="ok"); _obs(db, r2, f)
    r3 = _run(db, eng, minutes_ago=200, health="ok")   # first run without it
    db.commit()
    assert "finding_resolved" not in {e.kind for e in monitoring.compute_changes(db, r3)}
    r4 = _run(db, eng, minutes_ago=100, health="ok")   # second run without it
    db.commit()
    resolved = [e for e in monitoring.compute_changes(db, r4) if e.kind == "finding_resolved"]
    assert [e.subject for e in resolved] == ["Exposed panel"]


def test_a_new_finding_is_an_event_and_alerts_respect_threshold_and_confidence(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    db.add(NotificationTarget(engagement_id=eng.id, kind="webhook", url="https://hooks.example.org/x",
                              min_severity="high", enabled=True))
    db.commit()
    base = _run(db, eng, minutes_ago=200, health="ok")
    now = _run(db, eng, minutes_ago=10, health="ok")
    crit = _finding(db, eng, "c", "Critical RCE", "critical", "validated")
    med = _finding(db, eng, "m", "Medium thing", "medium", "validated")
    lead = _finding(db, eng, "l", "Agent lead", "high", "inferred", category="logic")
    cve = _finding(db, eng, "v", "CVE-2099-1 in nginx", "high", "inferred", category="cve")
    for f in (crit, med, lead, cve):
        _obs(db, now, f)
    db.commit()
    events = monitoring.compute_changes(db, now)
    assert {e.subject for e in events if e.kind == "finding_new"} == {"Critical RCE", "Medium thing", "Agent lead", "CVE-2099-1 in nginx"}
    for ev in events:
        monitoring._alert_for_event(db, eng, now, ev)
    db.commit()
    alerts = db.scalars(select(AlertEvent).where(AlertEvent.engagement_id == eng.id)).all()
    titles = {a.payload["title"]: a.immediate for a in alerts}
    assert titles == {"New finding: Critical RCE": True, "New finding: CVE-2099-1 in nginx": False}


def test_alert_bodies_carry_no_evidence_or_secrets(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    db.add(NotificationTarget(engagement_id=eng.id, kind="webhook", url="https://hooks.example.org/x",
                              secret_enc="gAAAA-secret", min_severity="info", enabled=True))
    db.commit()
    f = Finding(engagement_id=eng.id, category="exposure", title="Leaked .env", confidence="validated", status="open",
                severity="critical", fingerprint="fp-env", evidence={"response": "DB_PASSWORD=hunter2"})
    db.add(f)
    db.commit()
    run = _run(db, eng, health="ok")
    ev = ChangeEvent(engagement_id=eng.id, scan_run_id=run.id, kind="finding_new", subject=f.title, severity="critical",
                     detail={"finding_id": str(f.id), "confidence": "validated", "category": "exposure"})
    monitoring._alert_for_event(db, eng, run, ev)
    db.commit()
    alert = db.scalars(select(AlertEvent).where(AlertEvent.engagement_id == eng.id)).one()
    blob = str(alert.payload)
    assert "hunter2" not in blob and "DB_PASSWORD" not in blob and "gAAAA" not in blob
    assert set(alert.payload) == {"event", "engagement", "title", "severity", "run_id", "link"}


def test_triaged_findings_do_not_alert_because_they_are_not_new(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    f = _finding(db, eng, "acc", "Accepted thing", "high")
    f.status = "accepted_risk"
    base = _run(db, eng, minutes_ago=200, health="ok"); _obs(db, base, f)
    now = _run(db, eng, minutes_ago=10, health="ok"); _obs(db, now, f)
    db.commit()
    assert [e for e in monitoring.compute_changes(db, now) if e.kind == "finding_new"] == []


def test_run_finished_writes_health_snapshot_and_inbox_items(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    now = dt.datetime.now(dt.timezone.utc)
    db.add(DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value="a.example.test", in_scope=True,
                           discovered_via="ct", first_seen=now, last_seen=now))
    run = _run(db, eng, minutes_ago=5, state="done", reason="coverage_partial:nuclei=2",
               checkpoint={"services": [{"target": "a.example.test", "port": 443, "protocol": "tcp",
                                         "product": "nginx", "version": "1.2"}]})
    db.commit()
    summary = monitoring.on_run_finished(db, run)
    assert summary["health"] == "degraded"
    snaps = {(s.kind, s.key) for s in db.scalars(select(RunInventorySnapshot).where(RunInventorySnapshot.scan_run_id == run.id))}
    assert ("asset", "a.example.test") in snaps and ("service", "a.example.test:443/tcp") in snaps
    kinds = {i.kind for i in db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id))}
    assert "run_degraded" in kinds

    healthy = _run(db, eng, minutes_ago=1, state="done")
    monitoring.on_run_finished(db, healthy)
    open_kinds = {i.kind for i in db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.state == "open"))}
    assert "run_degraded" not in open_kinds


def test_an_assessment_run_gets_a_health_but_no_change_feed(db):
    owner = _user(db)
    eng = _engagement(db, owner)
    run = _run(db, eng, state="done")
    monitoring.on_run_finished(db, run)
    db.refresh(run)
    assert run.health == "ok"
    assert db.scalars(select(RunInventorySnapshot).where(RunInventorySnapshot.scan_run_id == run.id)).all() == []


def test_missed_runs_and_expiring_authorization_are_raised_once(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    now = dt.datetime.now(dt.timezone.utc)
    eng.review_at = now + dt.timedelta(days=5)
    # REQ-MON-001: the interval lives on the engagement (a daily monitor, set four days ago).
    eng.schedule_every_days = 1
    eng.schedule_set_at = now - dt.timedelta(days=4)
    eng.schedule_anchor_at = now - dt.timedelta(days=4)
    _run(db, eng, minutes_ago=60 * 24 * 4, health="ok")
    db.commit()
    first = monitoring.housekeeping(db, now)
    assert first == {"missed_runs": 1, "expiring": 1}
    second = monitoring.housekeeping(db, now)
    assert second == {"missed_runs": 0, "expiring": 0}
    kinds = {i.kind for i in db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id))}
    assert {"missed_run", "authorization_expiring"} <= kinds


# ------------------------------------------- REQ-MON-002: notification targets


def test_webhook_targets_must_be_public_https(db):
    for url in ("http://hooks.example.org/x", "https://localhost/x", "https://127.0.0.1/x", "https://10.0.0.5/x",
                "https://169.254.169.254/latest", "https://user:pw@hooks.example.org/x", "https://svc.internal/x"):
        with pytest.raises(WebhookTargetRefused):
            validate_webhook_url(url, resolve=lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    with pytest.raises(WebhookTargetRefused):
        validate_webhook_url("https://rebind.example.org/x",
                             resolve=lambda *a, **k: [(2, 1, 6, "", ("10.1.2.3", 443))])
    assert validate_webhook_url("https://hooks.example.org/x",
                                resolve=lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])


def test_signature_is_verifiable():
    body = b'{"event":"asset_new"}'
    sig = sign("s3cret", "1700000000", body)
    import hashlib, hmac
    expected = hmac.new(b"s3cret", b"1700000000." + body, hashlib.sha256).hexdigest()
    assert sig == "sha256=" + expected


def test_notification_target_is_stored_without_returning_the_secret(client, db, monkeypatch):
    import app.api.monitoring as api_monitoring

    monkeypatch.setattr(api_monitoring, "validate_webhook_url", lambda url: url)
    monkeypatch.setattr(api_monitoring, "_encrypt_api_key", lambda s: "enc:" + s)
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    h = _auth(db, owner)
    r = client.post(f"/engagements/{eng.id}/notification-targets",
                    json={"url": "https://hooks.example.org/x", "secret": "topsecret", "min_severity": "medium"}, headers=h)
    assert r.status_code == 201
    assert r.json()["has_secret"] is True and "topsecret" not in r.text and "secret_enc" not in r.text
    listed = client.get(f"/engagements/{eng.id}/notification-targets", headers=h)
    assert "topsecret" not in listed.text and "enc:" not in listed.text


def test_private_webhook_target_is_refused_at_save(client, db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    r = client.post(f"/engagements/{eng.id}/notification-targets",
                    json={"url": "https://10.0.0.7/hook"}, headers=_auth(db, owner))
    assert r.status_code == 422


def test_delivery_result_retries_with_backoff_and_then_fails_visibly(client, db, monkeypatch):
    import app.api.internal_monitoring as internal_monitoring
    from app.config import get_settings

    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    target = NotificationTarget(engagement_id=eng.id, kind="webhook", url="https://hooks.example.org/x",
                                min_severity="info", enabled=True)
    db.add(target)
    db.flush()
    alert = AlertEvent(engagement_id=eng.id, target_id=target.id, event_kind="asset_new", immediate=True,
                       payload={"title": "x"}, deliver_after=dt.datetime.now(dt.timezone.utc))
    db.add(alert)
    db.commit()
    token = {"x-asm-internal-token": get_settings().internal_api_token}
    monkeypatch.setattr(internal_monitoring, "validate_webhook_url", lambda url: url)
    due = client.get("/internal/alerts/due", headers=token).json()
    assert [d["id"] for d in due] == [str(alert.id)]
    for attempt in range(internal_monitoring.MAX_ATTEMPTS):
        r = client.post(f"/internal/alerts/{alert.id}/result", json={"delivered": False, "error": "HTTP 500"}, headers=token)
        assert r.status_code == 200
    db.refresh(alert)
    assert alert.state == "failed" and alert.attempts == internal_monitoring.MAX_ATTEMPTS
    # a failed delivery never touches the run or the engagement
    db.refresh(eng)
    assert eng.status == "active"


def test_an_unattended_run_can_withdraw_an_approval_it_will_not_wait_for(client, db):
    from app.config import get_settings
    from app.models.approval import ApprovalRequest

    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    ap = ApprovalRequest(engagement_id=eng.id, tool_call={"tool": "nuclei", "scan_run_id": str(uuid.uuid4())},
                         state="requested", expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=15))
    db.add(ap)
    db.commit()
    token = {"x-asm-internal-token": get_settings().internal_api_token}
    r = client.post(f"/internal/approvals/{ap.id}/withdraw", json={"reason": "unattended_run"}, headers=token)
    assert r.json()["withdrawn"] is True
    db.refresh(ap)
    assert ap.state == "cancelled"
    # an approved one is not touched
    ap2 = ApprovalRequest(engagement_id=eng.id, tool_call={"tool": "x"}, state="approved",
                          expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5))
    db.add(ap2)
    db.commit()
    again = client.post(f"/internal/approvals/{ap2.id}/withdraw", json={}, headers=token)
    assert again.json() == {"id": str(ap2.id), "state": "approved", "withdrawn": False}


# ----------------------------------- REQ-MODE-016: park and resume


def _approval(db, eng, run, *, state="requested", minutes=15):
    from app.models.approval import ApprovalRequest

    ap = ApprovalRequest(
        engagement_id=eng.id, tool_call={"tool": "http_request", "target": "www.example.test", "scan_run_id": str(run.id)},
        state=state, expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes),
    )
    db.add(ap)
    db.commit()
    return ap


def _parked_run(db, eng, owner, *, minutes=15, state="requested"):
    run = _run(db, eng, state="running", minutes_ago=30,
               checkpoint={"params": {"budget_max_iterations": 7, "approval_timeout_seconds": 900}},
               supervision="semi_attended", initiated_by=owner.email)
    run.attempt = 1
    run.owner_task_id = "task-1"
    run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=3)  # nobody polls while parked
    db.commit()
    ap = _approval(db, eng, run, state=state, minutes=minutes)
    return run, ap


def _internal(client):
    from app.config import get_settings

    return {"x-asm-internal-token": get_settings().internal_api_token}


def test_parking_stores_how_to_continue_frees_the_task_and_tells_the_tester(client, db, _no_broker):
    owner = _user(db)
    eng = _engagement(db, owner)
    run = _run(db, eng, state="running", minutes_ago=5, supervision="semi_attended", initiated_by=owner.email)
    run.attempt = 1
    db.commit()
    ap = _approval(db, eng, run)
    body = {"approval_id": str(ap.id), "attempt": 1,
            "resume_state": {"messages": [{"role": "assistant"}], "iterations": 3, "park": {"approval_id": str(ap.id)}}}
    r = client.post(f"/internal/scan-runs/{run.id}/park", json=body, headers=_internal(client))
    assert r.status_code == 200 and r.json()["state"] == "waiting_approval"
    db.expire_all()
    db.refresh(run)
    assert run.state == "waiting_approval" and run.owner_task_id is None
    assert run.checkpoint["parked"]["approval_id"] == str(ap.id) and run.checkpoint["agent_resume"]["iterations"] == 3
    item = db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id)).one()
    assert item.kind == "run_needs_you" and item.detail["approval_id"] == str(ap.id)


def test_a_superseded_attempt_or_a_stopped_run_cannot_be_parked(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    run = _run(db, eng, state="running", minutes_ago=5)
    run.attempt = 2
    db.commit()
    ap = _approval(db, eng, run)
    body = {"approval_id": str(ap.id), "resume_state": {}, "attempt": 1}
    assert client.post(f"/internal/scan-runs/{run.id}/park", json=body, headers=_internal(client)).status_code == 409
    run.state, run.cancel_requested = "aborted", True
    db.commit()
    body["attempt"] = 2
    assert client.post(f"/internal/scan-runs/{run.id}/park", json=body, headers=_internal(client)).status_code == 409


def test_a_parked_run_is_not_reaped_as_stale(db):
    from app.scan_lifecycle import park_run, reap_all_stale_runs

    owner = _user(db)
    eng = _engagement(db, owner)
    run, ap = _parked_run(db, eng, owner)
    park_run(db, run, approval_id=str(ap.id), resume_state={"iterations": 1})
    run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=5)
    db.commit()
    assert reap_all_stale_runs(db) == 0
    db.refresh(run)
    assert run.state == "waiting_approval"


def test_an_unparked_stale_run_is_still_reaped(db):
    from app.scan_lifecycle import reap_all_stale_runs

    owner = _user(db)
    eng = _engagement(db, owner)
    run = _run(db, eng, state="running", minutes_ago=600)
    run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=5)
    db.commit()
    assert reap_all_stale_runs(db) == 1


def test_a_parked_run_resumes_when_its_approval_is_approved(client, db, _no_broker):
    from app.scan_lifecycle import park_run

    owner = _user(db)
    eng = _engagement(db, owner)
    run, ap = _parked_run(db, eng, owner)
    park_run(db, run, approval_id=str(ap.id), resume_state={"iterations": 2})
    db.commit()

    r = client.post(f"/approvals/{ap.id}/approve", json={}, headers=_auth(db, owner))
    assert r.status_code == 200
    db.expire_all()
    db.refresh(run)
    assert run.state == "running" and "parked" not in (run.checkpoint or {})
    assert run.checkpoint["agent_resume"]["iterations"] == 2, "what the worker needs is kept for it"
    assert [c["scan_run_id"] for c in _no_broker] == [str(run.id)]
    assert _no_broker[0]["approval_timeout_seconds"] == 900


def test_a_rejection_resumes_it_too_and_never_runs_the_call(client, db, _no_broker):
    from app.scan_lifecycle import park_run

    owner = _user(db)
    eng = _engagement(db, owner)
    run, ap = _parked_run(db, eng, owner)
    park_run(db, run, approval_id=str(ap.id), resume_state={})
    db.commit()
    assert client.post(f"/approvals/{ap.id}/reject", json={}, headers=_auth(db, owner)).status_code == 200
    db.expire_all()
    db.refresh(ap)
    assert ap.state == "rejected"
    assert len(_no_broker) == 1


def test_an_expired_approval_resumes_the_run_with_not_approved(db, _no_broker):
    from app.scan_lifecycle import park_run, resume_decided_parked_runs

    owner = _user(db)
    eng = _engagement(db, owner)
    run, ap = _parked_run(db, eng, owner, minutes=-1)
    park_run(db, run, approval_id=str(ap.id), resume_state={})
    db.commit()
    assert resume_decided_parked_runs(db) == 1
    db.refresh(ap)
    assert ap.state == "expired"
    assert len(_no_broker) == 1


def test_an_open_approval_leaves_the_run_parked(db, _no_broker):
    from app.scan_lifecycle import park_run, resume_decided_parked_runs

    owner = _user(db)
    eng = _engagement(db, owner)
    run, ap = _parked_run(db, eng, owner, minutes=30)
    park_run(db, run, approval_id=str(ap.id), resume_state={})
    db.commit()
    assert resume_decided_parked_runs(db) == 0
    db.refresh(run)
    assert run.state == "waiting_approval" and _no_broker == []


def test_a_cancelled_parked_run_is_never_resumed_and_its_approval_cannot_be_decided(client, db, _no_broker):
    from app.scan_lifecycle import park_run, resume_decided_parked_runs

    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    run, ap = _parked_run(db, eng, owner)
    park_run(db, run, approval_id=str(ap.id), resume_state={})
    db.commit()
    assert client.post(f"/engagements/{eng.id}/scan-runs/{run.id}/cancel", headers=h).status_code == 200
    db.expire_all()
    db.refresh(ap)
    assert ap.state == "cancelled"
    assert client.post(f"/approvals/{ap.id}/approve", json={}, headers=h).status_code == 409
    assert resume_decided_parked_runs(db) == 0 and _no_broker == []


def test_pausing_closes_the_parked_approval_and_nothing_resumes(client, db, _no_broker):
    from app.scan_lifecycle import park_run, resume_decided_parked_runs

    owner = _user(db)
    eng = _engagement(db, owner)
    run, ap = _parked_run(db, eng, owner)
    park_run(db, run, approval_id=str(ap.id), resume_state={})
    db.commit()
    assert client.post(f"/engagements/{eng.id}/pause", headers=_auth(db, owner)).status_code == 200
    db.expire_all()
    db.refresh(ap)
    db.refresh(run)
    assert ap.state == "cancelled" and run.state == "aborted"
    assert resume_decided_parked_runs(db) == 0 and _no_broker == []


def test_an_approved_call_is_denied_at_claim_when_the_window_ended_while_parked(client, db):
    from app.scan_lifecycle import park_run

    owner = _user(db)
    eng = _engagement(db, owner)
    run, ap = _parked_run(db, eng, owner)
    ap.tool_call = {
        "engagement_id": str(eng.id), "tool": "httpx", "category": "fingerprint", "mode": "active",
        "target": "www.example.test", "args": {}, "is_automated": True, "phase": "fingerprint",
        "scan_run_id": str(run.id), "path": None, "rationale": None, "risk": None, "target_is_range": False,
    }
    ap.state = "approved"
    park_run(db, run, approval_id=str(ap.id), resume_state={})
    eng.authorized_until = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    db.commit()
    r = client.post(f"/internal/approvals/{ap.id}/claim", headers=_internal(client))
    assert r.status_code == 200
    assert r.json()["allowed"] is False and r.json()["reason"] == "outside_time_window"


def test_a_resume_is_idempotent(db, _no_broker):
    from app.scan_lifecycle import park_run, resume_parked_run

    owner = _user(db)
    eng = _engagement(db, owner)
    run, ap = _parked_run(db, eng, owner, state="approved")
    park_run(db, run, approval_id=str(ap.id), resume_state={})
    db.commit()
    assert resume_parked_run(db, run) is True
    db.commit()
    assert resume_parked_run(db, run) is False
    assert len(_no_broker) == 1


def test_resuming_resolves_the_run_needs_you_item(client, db, _no_broker):
    from app.scan_lifecycle import park_run

    owner = _user(db)
    eng = _engagement(db, owner)
    run, ap = _parked_run(db, eng, owner)
    park_run(db, run, approval_id=str(ap.id), resume_state={})
    db.commit()
    monitoring.notify_run_needs_you(db, eng, run, ap, "http_request on www.example.test")
    assert len(db.scalars(select(InboxItem).where(InboxItem.state == "open")).all()) == 1
    client.post(f"/approvals/{ap.id}/approve", json={}, headers=_auth(db, owner))
    db.expire_all()
    assert db.scalars(select(InboxItem).where(InboxItem.state == "open")).all() == []


# ------------------------------------- REQ-MODE-001 / REQ-MODE-015: the document


def test_a_monitoring_engagement_cannot_be_created_with_an_asset_review(client, db):
    owner = _user(db)
    now = dt.datetime.now(dt.timezone.utc)
    r = client.post("/engagements", json={
        "title": "Mon", "operating_mode": "monitoring", "asset_review_enabled": True,
        "authorized_from": now.isoformat(), "authorized_until": (now + dt.timedelta(days=30)).isoformat(),
    }, headers=_auth(db, owner))
    assert r.status_code == 409


def _pdf_text(raw: bytes) -> str:
    import io

    from pypdf import PdfReader

    return "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(raw)).pages)


def test_the_authorization_document_of_a_monitor_states_what_runs_unattended(client, db, monkeypatch):
    import app.api.monitoring as api_monitoring

    monkeypatch.setattr(api_monitoring, "validate_webhook_url", lambda u: u)
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring", status="draft", new_asset_policy="hold", scan_profile="light")
    client.post(f"/engagements/{eng.id}/notification-targets", json={"url": "https://hooks.example.org/x"}, headers=h)
    text = _pdf_text(client.get(f"/engagements/{eng.id}/authorization-pdf", headers=h).content)
    assert "Unattended monitoring" in text
    assert "without a person watching" in text
    assert "light" in text
    assert "held until acknowledged" in text
    assert "hooks.example.org" in text
    assert "Credential testing and exploitation are not part of monitoring" in text


def test_the_document_of_an_assessment_has_no_unattended_section(client, db):
    owner = _user(db)
    eng = _engagement(db, owner, status="draft")
    text = _pdf_text(client.get(f"/engagements/{eng.id}/authorization-pdf", headers=_auth(db, owner)).content)
    assert "Unattended monitoring" not in text


def test_a_change_after_signing_changes_the_checksum(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner, mode="monitoring", status="draft")
    first = _pdf_text(client.get(f"/engagements/{eng.id}/authorization-pdf", headers=h).content)
    # the fixture's fingerprint grant makes this one capability active; switching it off changes what runs
    client.put(f"/engagements/{eng.id}/capabilities", json={"capabilities": {"web_fingerprint": False}}, headers=h)
    second = _pdf_text(client.get(f"/engagements/{eng.id}/authorization-pdf", headers=h).content)
    grab = lambda t: next(line for line in t.splitlines() if "Configuration checksum" in line)  # noqa: E731
    assert grab(first) != grab(second)


def test_the_readiness_message_says_what_to_do_for_the_status(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    for status, phrase in (("paused", "Resume it"), ("completed", "cannot scan again"), ("revoked", "revoked"), ("draft", "Activate it")):
        eng = _engagement(db, owner, status=status)
        body = client.get(f"/engagements/{eng.id}/scan-readiness", headers=h).json()
        assert phrase in body["blockers"][0]["message"], (status, body)
