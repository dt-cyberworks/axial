"""REQ-BASE-001..005: a monitor is activated into a passive discovery, the owner chooses the targets,
the deny list records the choice, and only then the first scan runs.

The negative tests are the point: nothing but the discovery may run before the owner has confirmed,
a decision narrows freely but widening is confirmed, a request is all-or-nothing, and a discovery run is
never a change-detection baseline."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import auth_service, celery_client, monitoring, scan_diff, scheduling
from app.db.base import get_db
from app.gateway.audit import verify_audit_chain
from app.main import app
from app.models.asset import DiscoveredAsset
from app.models.audit import AuditLog
from app.models.dns_record import DnsRecord
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.monitoring import InboxItem, RunInventorySnapshot
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret

NOW = dt.datetime.now(dt.timezone.utc)
ROOT_IP = "203.0.113.10"
OTHER_IP = "198.51.100.77"


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


def _monitor(db, owner: User, *, status="draft", mode="monitoring", source="own_domain", **kw) -> Engagement:
    eng = Engagement(
        title=f"M-{mode}", source=source, status=status, operating_mode=mode,
        authorized_from=NOW - dt.timedelta(hours=1), authorized_until=NOW + dt.timedelta(days=30),
        owner_user_id=owner.id, **kw,
    )
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="example.test",
                      active_allowed=True, authorization_verified=True))
    db.add(ToolGrant(engagement_id=eng.id, tool_category="fingerprint", mode="active", requires_manual_approval=False))
    db.add(ToolGrant(engagement_id=eng.id, tool_category="recon", mode="passive", requires_manual_approval=False))
    db.commit()
    db.refresh(eng)
    return eng


def _host(db, eng, name, ips, *, via="passive-osint", resolved=True) -> DiscoveredAsset:
    asset = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=name, in_scope=True, discovered_via=via)
    db.add(asset)
    db.flush()
    db.add(DnsRecord(engagement_id=eng.id, asset_id=asset.id, fqdn=name, cname_chain=[], terminal_ips=ips,
                     dns_status="resolved" if resolved else "nxdomain", hosting_provider="TestHost" if ips else None))
    db.commit()
    db.refresh(asset)
    return asset


def _discovered(db, eng):
    """root + two hosts on the root's address + one elsewhere + one that does not resolve."""
    return {
        "root": _host(db, eng, "example.test", [ROOT_IP], via="scope"),
        "www": _host(db, eng, "www.example.test", [ROOT_IP]),
        "mail": _host(db, eng, "mail.example.test", [ROOT_IP]),
        "dangling": _host(db, eng, "old.example.test", [OTHER_IP]),
        "gone": _host(db, eng, "gone.example.test", [], resolved=False),
    }


def _activate(client, db, owner, eng):
    return client.post(f"/engagements/{eng.id}/activate", headers=_auth(db, owner))


def _runs(db, eng):
    db.expire_all()
    return db.scalars(select(ScanRun).where(ScanRun.engagement_id == eng.id).order_by(ScanRun.started_at)).all()


def _finish(db, run, state="done", reason=None):
    db.expire_all()
    run = db.get(ScanRun, run.id)
    run.state, run.state_reason, run.finished_at = state, reason, NOW
    db.commit()
    monitoring.on_run_finished(db, run)
    db.expire_all()


def _awaiting(client, db, owner):
    """A monitor with its discovery finished, the five hosts found, ready for the selection."""
    eng = _monitor(db, owner)
    hosts = _discovered(db, eng)
    assert _activate(client, db, owner, eng).status_code == 200
    run = _runs(db, eng)[0]
    _finish(db, run)
    db.expire_all()
    assert db.get(Engagement, eng.id).target_review_state == "awaiting_selection"
    return eng, hosts


def _confirm(client, db, owner, eng, selected, **extra):
    body = {"selected_asset_ids": [str(i) for i in selected], **extra}
    return client.post(f"/engagements/{eng.id}/targets/confirm", json=body, headers=_auth(db, owner))


# ------------------------------------------------ REQ-BASE-001: activation


def test_activating_a_monitor_starts_a_passive_discovery_and_nothing_else(client, db):
    owner = _user(db)
    eng = _monitor(db, owner)
    r = _activate(client, db, owner, eng)
    assert r.status_code == 200
    assert r.json()["target_review_state"] == "discovering"
    runs = _runs(db, eng)
    assert len(runs) == 1
    run = runs[0]
    assert run.trigger == "baseline" and run.scan_profile == "passive" and run.supervision == "unattended"
    started = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id,
                                                AuditLog.action == "scan_run_started")).one()
    assert started.payload["trigger"] == "baseline" and started.payload["scan_profile"] == "passive"


def test_an_assessment_is_activated_as_before(client, db):
    owner = _user(db)
    eng = _monitor(db, owner, mode="assessment")
    r = _activate(client, db, owner, eng)
    assert r.status_code == 200 and r.json()["target_review_state"] is None
    assert _runs(db, eng) == []


def test_negative_nothing_but_the_discovery_can_run_before_the_targets_are_confirmed(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _monitor(db, owner)
    assert _activate(client, db, owner, eng).status_code == 200
    _finish(db, _runs(db, eng)[0])  # awaiting_selection

    r = client.post(f"/engagements/{eng.id}/scan", headers=h)
    assert r.status_code == 409
    assert "targets_not_confirmed" in str(r.json())
    assert len(_runs(db, eng)) == 1

    eng.schedule_every_days = 1
    eng.schedule_anchor_at = NOW - dt.timedelta(days=3)
    db.commit()
    result = scheduling.run_due(db, now=NOW, enqueue=lambda *a, **k: "t")
    assert result["started"] == 0 and len(_runs(db, eng)) == 1
    db.expire_all()
    assert db.get(Engagement, eng.id).schedule_skip_reason == "targets_not_confirmed"


def test_the_discovery_is_not_a_change_detection_baseline_and_holds_no_host(client, db):
    owner = _user(db)
    eng = _monitor(db, owner)
    hosts = _discovered(db, eng)
    eng.new_asset_policy = "hold"
    db.commit()
    assert _activate(client, db, owner, eng).status_code == 200
    run = _runs(db, eng)[0]

    verdict = monitoring.evaluate_hold(db, run, [{"asset_id": str(a.id), "value": a.value} for a in hosts.values()])
    assert verdict["held"] == [] and len(verdict["released"]) == len(hosts)
    assert db.scalars(select(InboxItem).where(InboxItem.kind == "held_asset")).all() == []

    _finish(db, run)
    assert db.scalars(select(RunInventorySnapshot).where(RunInventorySnapshot.scan_run_id == run.id)).all() == []
    later = ScanRun(engagement_id=eng.id, phase="report", state="done", health="ok",
                    started_at=NOW + dt.timedelta(minutes=5), finished_at=NOW + dt.timedelta(minutes=9))
    db.add(later)
    db.commit()
    assert scan_diff._previous_run(db, later) is None  # the discovery is not a full picture


def test_a_failed_discovery_can_be_run_again(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _monitor(db, owner)
    assert _activate(client, db, owner, eng).status_code == 200
    _finish(db, _runs(db, eng)[0], state="failed", reason="pipeline_error:x")
    got = client.get(f"/engagements/{eng.id}/targets", headers=h).json()
    assert got["state"] == "discovery_failed"
    open_items = db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.state == "open")).all()
    assert {i.kind for i in open_items} == {"discovery_failed"}

    r = client.post(f"/engagements/{eng.id}/targets/discover", headers=h)
    assert r.status_code == 202 and r.json()["state"] == "discovering"
    assert len(_runs(db, eng)) == 2


def test_a_discovery_stopped_by_a_pause_does_not_leave_the_monitor_stuck(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _monitor(db, owner)
    assert _activate(client, db, owner, eng).status_code == 200
    assert client.post(f"/engagements/{eng.id}/pause", headers=h).status_code == 200  # aborts the run directly
    assert client.post(f"/engagements/{eng.id}/resume", headers=h).status_code == 200
    got = client.get(f"/engagements/{eng.id}/targets", headers=h).json()
    assert got["state"] == "discovery_failed"  # healed: the run is over
    assert client.post(f"/engagements/{eng.id}/targets/discover", headers=h).status_code == 202


def test_a_monitor_that_existed_before_is_confirmed_and_not_blocked(client, db):
    owner = _user(db)
    eng = _monitor(db, owner, status="active")
    assert client.post(f"/engagements/{eng.id}/scan", headers=_auth(db, owner)).status_code == 202
    assert _runs(db, eng)[0].trigger == "manual"


# ------------------------------------------- REQ-BASE-002: the list


def test_the_list_flags_each_host_by_where_it_resolves(client, db):
    owner = _user(db)
    eng, hosts = _awaiting(client, db, owner)
    got = client.get(f"/engagements/{eng.id}/targets", headers=_auth(db, owner)).json()
    by_name = {c["value"]: c for c in got["candidates"]}
    assert by_name["example.test"]["is_root"] and by_name["example.test"]["suggested"]
    assert by_name["www.example.test"]["flag"] == "same_address" and by_name["www.example.test"]["suggested"]
    assert by_name["old.example.test"]["flag"] == "other_address" and not by_name["old.example.test"]["suggested"]
    assert by_name["old.example.test"]["addresses"] == [OTHER_IP]
    assert by_name["gone.example.test"]["flag"] == "unresolved" and not by_name["gone.example.test"]["suggested"]
    assert got["state"] == "awaiting_selection" and got["counts"]["candidates"] == 5
    inbox = db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.state == "open")).all()
    assert [i.kind for i in inbox] == ["targets_to_select"]


def test_anyone_signed_in_can_read_the_list_but_not_change_it(client, db):
    owner, other = _user(db), _user(db)
    eng, hosts = _awaiting(client, db, owner)
    h = _auth(db, other)
    assert client.get(f"/engagements/{eng.id}/targets", headers=h).status_code == 200
    r = _confirm(client, db, other, eng, [hosts["root"].id])
    assert r.status_code == 403
    assert client.post(f"/engagements/{eng.id}/targets/discover", headers=h).status_code == 403


# ------------------------------------------- REQ-BASE-003: confirming


def test_confirming_denies_the_rest_and_starts_the_first_scan_on_the_selection(client, db):
    owner = _user(db)
    eng, hosts = _awaiting(client, db, owner)
    keep = [hosts["root"].id, hosts["www"].id, hosts["mail"].id]
    r = _confirm(client, db, owner, eng, keep, new_asset_policy="hold")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "confirmed" and body["excluded"] == 2 and body["monitored"] == 3
    assert body["first_run_id"] is not None and body["new_asset_policy"] == "hold"

    denies = {s.value for s in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id,
                                                                     ScopeAsset.rule == "deny"))}
    assert denies == {"old.example.test", "gone.example.test"}
    db.expire_all()
    assert db.get(DiscoveredAsset, hosts["dangling"].id).in_scope is False
    assert db.get(DiscoveredAsset, hosts["www"].id).in_scope is True

    audit = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id,
                                              AuditLog.action == "target_excluded")).all()
    assert {a.payload["host"] for a in audit} == denies and len({a.payload["bulk_id"] for a in audit}) == 1
    summary = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id,
                                                AuditLog.action == "targets_confirmed")).one()
    assert summary.payload["excluded"] == 2 and summary.payload["first_confirmation"] is True
    assert verify_audit_chain(db, eng.id).ok

    first = [r for r in _runs(db, eng) if r.trigger != "baseline"]
    assert len(first) == 1 and first[0].initiated_by == owner.email and first[0].scan_profile == eng.scan_profile
    items = db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.state == "open")).all()
    assert items == []  # the "choose the targets" item is resolved


def test_confirming_with_the_suggestion_excludes_exactly_the_flagged_hosts(client, db):
    owner = _user(db)
    eng, hosts = _awaiting(client, db, owner)
    suggested = [c["asset_id"] for c in client.get(f"/engagements/{eng.id}/targets",
                                                  headers=_auth(db, owner)).json()["candidates"] if c["suggested"]]
    r = client.post(f"/engagements/{eng.id}/targets/confirm", json={"selected_asset_ids": suggested},
                    headers=_auth(db, owner))
    assert r.status_code == 200 and r.json()["excluded"] == 2


def test_negative_a_root_cannot_be_left_out(client, db):
    owner = _user(db)
    eng, hosts = _awaiting(client, db, owner)
    r = _confirm(client, db, owner, eng, [hosts["www"].id])  # the root is not selected
    assert r.status_code == 422
    db.expire_all()
    assert db.get(Engagement, eng.id).target_review_state == "awaiting_selection"
    assert db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "deny")).all() == []
    assert [r for r in _runs(db, eng) if r.trigger != "baseline"] == []


def test_negative_the_request_is_all_or_nothing(client, db):
    owner = _user(db)
    eng, hosts = _awaiting(client, db, owner)
    r = _confirm(client, db, owner, eng, [hosts["root"].id, uuid.uuid4()])
    assert r.status_code == 404
    db.expire_all()
    assert db.get(Engagement, eng.id).target_review_state == "awaiting_selection"
    assert db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "deny")).all() == []
    other_owner = owner
    other = _monitor(db, other_owner)
    foreign = _host(db, other, "www.example.test", [ROOT_IP])
    r = _confirm(client, db, owner, eng, [hosts["root"].id, foreign.id])
    assert r.status_code == 404


def test_negative_confirming_is_refused_while_the_discovery_runs_or_failed(client, db):
    owner = _user(db)
    eng = _monitor(db, owner)
    host = _host(db, eng, "example.test", [ROOT_IP], via="scope")
    assert _activate(client, db, owner, eng).status_code == 200
    assert _confirm(client, db, owner, eng, [host.id]).status_code == 409  # still discovering
    _finish(db, _runs(db, eng)[0], state="failed", reason="x")
    assert _confirm(client, db, owner, eng, [host.id]).status_code == 409  # failed


def test_negative_a_scheduled_run_does_not_start_until_confirmed_and_then_it_may(client, db):
    owner = _user(db)
    eng, hosts = _awaiting(client, db, owner)
    assert _confirm(client, db, owner, eng, [hosts["root"].id, hosts["www"].id]).status_code == 200
    # the first scan is running: finish it, then the interval governs as usual
    first = [r for r in _runs(db, eng) if r.trigger != "baseline"][0]
    _finish(db, first)
    db.expire_all()
    eng = db.get(Engagement, eng.id)
    eng.schedule_every_days = 1
    eng.schedule_anchor_at = NOW - dt.timedelta(days=2)
    db.commit()
    assert scheduling.run_due(db, now=NOW, enqueue=lambda *a, **k: "t")["started"] == 1


# ------------------------------------------- REQ-BASE-004: later review


def test_a_review_later_refreshes_without_blocking_the_monitor(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng, hosts = _awaiting(client, db, owner)
    assert _confirm(client, db, owner, eng, [hosts["root"].id, hosts["www"].id, hosts["mail"].id]).status_code == 200
    _finish(db, [r for r in _runs(db, eng) if r.trigger != "baseline"][0])

    r = client.post(f"/engagements/{eng.id}/targets/discover", headers=h)
    assert r.status_code == 202 and r.json()["state"] == "confirmed"  # state untouched
    db.expire_all()
    assert db.get(Engagement, eng.id).target_review_state == "confirmed"


def test_negative_including_a_denied_host_again_is_a_confirmed_widening(client, db):
    owner = _user(db)
    eng, hosts = _awaiting(client, db, owner)
    assert _confirm(client, db, owner, eng, [hosts["root"].id, hosts["www"].id]).status_code == 200
    _finish(db, [r for r in _runs(db, eng) if r.trigger != "baseline"][0])

    again = [hosts["root"].id, hosts["www"].id, hosts["dangling"].id]
    r = _confirm(client, db, owner, eng, again)
    assert r.status_code == 409 and "confirmation_required" in str(r.json())
    db.expire_all()
    assert "old.example.test" in {s.value for s in db.scalars(
        select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "deny"))}

    r = _confirm(client, db, owner, eng, again, confirm_widening=True)
    assert r.status_code == 200 and r.json()["included"] == 1
    db.expire_all()
    assert "old.example.test" not in {s.value for s in db.scalars(
        select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "deny"))}
    assert db.scalars(select(AuditLog).where(AuditLog.action == "target_included")).one().payload["host"] == "old.example.test"


def test_negative_widening_is_refused_while_a_run_is_active(client, db):
    owner = _user(db)
    eng, hosts = _awaiting(client, db, owner)
    assert _confirm(client, db, owner, eng, [hosts["root"].id, hosts["www"].id]).status_code == 200
    # the first scan is still running
    r = _confirm(client, db, owner, eng, [hosts["root"].id, hosts["www"].id, hosts["mail"].id], confirm_widening=True)
    assert r.status_code == 409 and "scan_run_active" in str(r.json())


# --------------------- REQ-BASE-005: one policy, no ownership distinction


@pytest.mark.parametrize("source", ["own_domain", "customer"])
def test_a_new_monitor_gets_the_one_default_whatever_the_source(client, db, source):
    admin = _user(db, role="admin")
    h = _auth(db, admin)
    assert client.put("/settings/monitoring-defaults", json={"new_asset_policy": "hold"}, headers=h).status_code == 200
    body = {"title": "N", "operating_mode": "monitoring", "source": source,
            "authorized_from": NOW.isoformat(), "authorized_until": (NOW + dt.timedelta(days=30)).isoformat()}
    r = client.post("/engagements", json=body, headers=h)
    assert r.status_code == 201 and r.json()["new_asset_policy"] == "hold"
    assert client.put("/settings/monitoring-defaults", json={"new_asset_policy": "auto"}, headers=h).status_code == 200
    r = client.post("/engagements", json=body, headers=h)
    assert r.json()["new_asset_policy"] == "auto"


def test_the_default_is_hold_and_the_two_old_keys_are_gone(client, db):
    admin = _user(db, role="admin")
    got = client.get("/settings/monitoring-defaults", headers=_auth(db, admin)).json()
    assert got["new_asset_policy"] == "hold"
    assert "new_asset_policy_customer" not in got and "new_asset_policy_other" not in got
    bad = client.put("/settings/monitoring-defaults", json={"new_asset_policy": "sometimes"}, headers=_auth(db, admin))
    assert bad.status_code == 422


def test_the_owner_chooses_the_policy_on_the_target_screen(client, db):
    owner = _user(db)
    eng, hosts = _awaiting(client, db, owner)
    r = _confirm(client, db, owner, eng, [hosts["root"].id], new_asset_policy="auto")
    assert r.status_code == 200 and r.json()["new_asset_policy"] == "auto"
    db.expire_all()
    assert db.get(Engagement, eng.id).new_asset_policy == "auto"


# ------------------------------------------- REQ-BASE-006: the step is visible and cannot be dismissed


def test_the_inbox_item_opens_the_target_screen_and_cannot_be_dismissed(client, db):
    owner = _user(db)
    eng, hosts = _awaiting(client, db, owner)
    h = _auth(db, owner)
    entries = [e for e in client.get("/inbox", headers=h).json() if e["engagement_id"] == str(eng.id)]
    assert [e["kind"] for e in entries] == ["targets_to_select"]
    assert entries[0]["link"] == f"/engagements/{eng.id}/targets" and entries[0]["can_acknowledge"] is False

    # [Negative] dismissing it would hide a monitor that scans nothing: refused, still open.
    r = client.post(f"/inbox/{entries[0]['id']}/acknowledge", headers=h)
    assert r.status_code == 409
    db.expire_all()
    assert db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.state == "open")).all()

    # Taking the step clears it.
    assert _confirm(client, db, owner, eng, [hosts["root"].id, hosts["www"].id]).status_code == 200
    db.expire_all()
    assert not db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.state == "open")).all()


def test_a_failed_discovery_item_also_opens_the_target_screen(client, db):
    owner = _user(db)
    eng = _monitor(db, owner)
    _discovered(db, eng)
    assert _activate(client, db, owner, eng).status_code == 200
    _finish(db, _runs(db, eng)[0], state="failed", reason="boom")
    h = _auth(db, owner)
    entries = [e for e in client.get("/inbox", headers=h).json() if e["engagement_id"] == str(eng.id)]
    assert [e["kind"] for e in entries] == ["discovery_failed"]
    assert entries[0]["link"].endswith("/targets") and entries[0]["can_acknowledge"] is False
    assert client.post(f"/inbox/{entries[0]['id']}/acknowledge", headers=h).status_code == 409
