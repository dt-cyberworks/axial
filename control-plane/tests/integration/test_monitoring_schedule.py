"""Run a monitoring engagement every N days (REQ-MON-001, REQ-MON-003; console in REQ-MON-004).

R3: the scheduler is the first thing that starts scans without a person. The negative paths are
the point of this file: a due run must not start when the engagement is not active, outside its
window, after its review date, while a run is active, when it is not ready, or beyond the capacity
cap, and each reason must be visible."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app import auth_service, celery_client, monitoring, scheduling
from app.db.base import get_db
from app.main import app
from app.models.audit import AuditLog
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.monitoring import InboxItem
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret

NOW = dt.datetime.now(dt.timezone.utc)


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
    monkeypatch.delenv(scheduling.MAX_CONCURRENT_ENV, raising=False)
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


def _engagement(db, owner: User, *, mode="monitoring", status="active", **kw) -> Engagement:
    eng = Engagement(
        title=f"E-{mode}", source="own_domain", status=status, operating_mode=mode,
        authorized_from=NOW - dt.timedelta(hours=1), authorized_until=NOW + dt.timedelta(days=30),
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


def _due(db, eng: Engagement, every_days: int = 7, overdue_days: int = 1) -> Engagement:
    """The interval is set and the next run was due `overdue_days` ago."""
    eng.schedule_every_days = every_days
    eng.schedule_set_at = NOW - dt.timedelta(days=every_days + overdue_days)
    eng.schedule_anchor_at = NOW - dt.timedelta(days=every_days + overdue_days)
    db.commit()
    db.refresh(eng)
    return eng


def _tick(db, sent=None):
    calls: list[dict] = []

    def enqueue(engagement_id, scan_run_id, **kw):
        calls.append({"engagement_id": engagement_id, "scan_run_id": scan_run_id, **kw})
        return "task-sched"

    result = scheduling.run_due(db, now=NOW, enqueue=enqueue)
    return result, calls


def _runs(db, eng):
    db.expire_all()
    return db.scalars(select(ScanRun).where(ScanRun.engagement_id == eng.id).order_by(ScanRun.started_at)).all()


def _audit(db, eng, action):
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == action)).all()


# ----------------------------------------- REQ-MON-001: setting the interval


def test_owner_sets_and_clears_the_interval_and_it_is_audited(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    r = client.put(f"/engagements/{eng.id}/schedule", json={"every_days": 7}, headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["every_days"] == 7 and body["next_run_at"] is not None
    nxt = dt.datetime.fromisoformat(body["next_run_at"])
    assert abs((nxt - dt.datetime.now(dt.timezone.utc)) - dt.timedelta(days=7)) < dt.timedelta(minutes=2)
    row = _audit(db, eng, "monitoring_schedule_updated")[0]
    assert row.actor == f"user:{owner.email}" and row.payload["from"] is None and row.payload["to"] == 7

    r = client.put(f"/engagements/{eng.id}/schedule", json={"every_days": None}, headers=h)
    assert r.status_code == 200 and r.json()["every_days"] is None and r.json()["next_run_at"] is None
    assert client.get(f"/engagements/{eng.id}/schedule", headers=h).json()["every_days"] is None
    assert len(_audit(db, eng, "monitoring_schedule_updated")) == 2


def test_the_default_is_no_automatic_runs(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    body = client.get(f"/engagements/{eng.id}/schedule", headers=_auth(db, owner)).json()
    assert body["every_days"] is None and body["next_run_at"] is None


@pytest.mark.parametrize("days", [0, -1, 91, 365])
def test_an_interval_outside_one_to_ninety_days_is_refused(client, db, days):
    owner = _user(db)
    eng = _engagement(db, owner)
    r = client.put(f"/engagements/{eng.id}/schedule", json={"every_days": days}, headers=_auth(db, owner))
    assert r.status_code == 422
    db.expire_all()
    assert db.get(Engagement, eng.id).schedule_every_days is None


@pytest.mark.parametrize("days", [1, 90])
def test_the_bounds_are_accepted(client, db, days):
    owner = _user(db)
    eng = _engagement(db, owner)
    r = client.put(f"/engagements/{eng.id}/schedule", json={"every_days": days}, headers=_auth(db, owner))
    assert r.status_code == 200 and r.json()["every_days"] == days


def test_a_non_owner_cannot_set_it_but_an_admin_can(client, db):
    owner, other, admin = _user(db), _user(db), _user(db, role="admin")
    eng = _engagement(db, owner)
    r = client.put(f"/engagements/{eng.id}/schedule", json={"every_days": 3}, headers=_auth(db, other))
    assert r.status_code == 403
    db.expire_all()
    assert db.get(Engagement, eng.id).schedule_every_days is None
    # everyone signed in can read it
    assert client.get(f"/engagements/{eng.id}/schedule", headers=_auth(db, other)).status_code == 200
    assert client.put(f"/engagements/{eng.id}/schedule", json={"every_days": 3}, headers=_auth(db, admin)).status_code == 200


def test_an_assessment_cannot_have_an_interval(client, db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="assessment")
    r = client.put(f"/engagements/{eng.id}/schedule", json={"every_days": 7}, headers=_auth(db, owner))
    assert r.status_code == 409
    # and the database refuses it too, whatever the code does
    eng.schedule_every_days = 7
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


@pytest.mark.parametrize("status", ["completed", "revoked"])
def test_a_finished_engagement_cannot_be_scheduled(client, db, status):
    owner = _user(db)
    eng = _engagement(db, owner, status=status)
    r = client.put(f"/engagements/{eng.id}/schedule", json={"every_days": 7}, headers=_auth(db, owner))
    assert r.status_code == 409


def test_the_database_refuses_an_interval_out_of_range(db):
    owner = _user(db)
    eng = _engagement(db, owner)
    eng.schedule_every_days = 120
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


# --------------------------------------------- the counting rule (REQ-MON-001)


def test_setting_the_interval_never_starts_a_run(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    assert client.put(f"/engagements/{eng.id}/schedule", json={"every_days": 1}, headers=_auth(db, owner)).status_code == 200
    result, calls = _tick(db)
    assert result == {"due": 0, "started": 0, "waiting": 0} and calls == []
    assert _runs(db, eng) == []


def test_a_manual_run_restarts_the_count(client, db):
    owner = _user(db)
    eng = _due(db, _engagement(db, owner), every_days=7, overdue_days=0)
    assert client.post(f"/engagements/{eng.id}/scan", headers=_auth(db, owner)).status_code == 202
    db.expire_all()
    eng = db.get(Engagement, eng.id)
    assert abs(eng.schedule_anchor_at - dt.datetime.now(dt.timezone.utc)) < dt.timedelta(minutes=2)
    assert scheduling.next_run_at(eng) > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=6)


def test_resume_restarts_the_count_so_a_long_pause_does_not_cause_a_run(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _due(db, _engagement(db, owner), every_days=7, overdue_days=30)
    assert client.post(f"/engagements/{eng.id}/pause", headers=h).status_code == 200
    assert client.post(f"/engagements/{eng.id}/resume", headers=h).status_code == 200
    db.expire_all()
    eng = db.get(Engagement, eng.id)
    assert scheduling.next_run_at(eng) > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=6)
    result, calls = _tick(db)
    assert result["started"] == 0 and calls == []


# ------------------------------------------ REQ-MON-003: starting a due run


def test_a_due_run_starts_through_the_normal_start_path(db):
    owner = _user(db)
    eng = _due(db, _engagement(db, owner, scan_profile="light"), every_days=3)
    result, calls = _tick(db)
    assert result == {"due": 1, "started": 1, "waiting": 0}
    assert len(calls) == 1 and calls[0]["engagement_id"] == str(eng.id)
    run = _runs(db, eng)[0]
    assert run.trigger == "scheduled" and run.supervision == "unattended"
    assert run.initiated_by == "schedule:every-3-days" and run.scan_profile == "light"
    started = _audit(db, eng, "scan_run_started")[0]
    assert started.actor == "schedule:every-3-days" and started.payload["trigger"] == "scheduled"
    db.expire_all()
    eng = db.get(Engagement, eng.id)
    assert eng.schedule_skip_reason is None
    assert scheduling.next_run_at(eng) > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)


def test_nothing_starts_before_the_interval_has_passed(db):
    owner = _user(db)
    eng = _engagement(db, owner)
    eng.schedule_every_days = 7
    eng.schedule_anchor_at = NOW - dt.timedelta(days=6, hours=23)
    db.commit()
    result, calls = _tick(db)
    assert result["due"] == 0 and calls == [] and _runs(db, eng) == []


def test_a_second_tick_does_not_start_a_second_run(db):
    owner = _user(db)
    eng = _due(db, _engagement(db, owner))
    assert _tick(db)[0]["started"] == 1
    result, calls = _tick(db)
    assert result["started"] == 0 and calls == []
    assert len(_runs(db, eng)) == 1


def test_a_due_run_waits_while_another_run_is_active_and_is_never_doubled(db):
    owner = _user(db)
    eng = _due(db, _engagement(db, owner))
    active = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running", trigger="manual", started_at=NOW)
    db.add(active)
    db.commit()
    result, calls = _tick(db)
    assert result == {"due": 1, "started": 0, "waiting": 1} and calls == []
    assert len(_runs(db, eng)) == 1
    db.expire_all()
    assert db.get(Engagement, eng.id).schedule_skip_reason == "a_run_is_active"


def test_paused_engagement_does_not_run_and_the_reason_is_audited_once(client, db):
    owner = _user(db)
    eng = _due(db, _engagement(db, owner))
    assert client.post(f"/engagements/{eng.id}/pause", headers=_auth(db, owner)).status_code == 200
    # pausing restarts nothing; make it due again as it would be after the interval
    db.expire_all()
    eng = db.get(Engagement, eng.id)
    eng.schedule_anchor_at = NOW - dt.timedelta(days=8)
    db.commit()
    for _ in range(3):
        result, calls = _tick(db)
        assert result["started"] == 0 and calls == []
    assert _runs(db, eng) == []
    db.expire_all()
    got = db.get(Engagement, eng.id)
    assert got.schedule_skip_reason == "engagement_paused"
    assert len(_audit(db, eng, "scheduled_run_skipped")) == 1  # not one row per tick
    assert "paused" in scheduling.view(got)["skip_message"]


@pytest.mark.parametrize("status", ["draft", "completed", "revoked"])
def test_an_engagement_that_is_not_active_never_runs(db, status):
    owner = _user(db)
    eng = _engagement(db, owner, status=status)
    eng.schedule_every_days = None
    db.commit()
    # a stale interval (e.g. set while active, then closed) must not start anything
    db.execute(Engagement.__table__.update().where(Engagement.id == eng.id).values(
        schedule_every_days=7, schedule_anchor_at=NOW - dt.timedelta(days=9)))
    db.commit()
    result, calls = _tick(db)
    assert result["started"] == 0 and calls == [] and _runs(db, eng) == []
    db.expire_all()
    assert db.get(Engagement, eng.id).schedule_skip_reason == f"engagement_{status}"


def test_outside_the_authorized_window_nothing_runs_and_a_person_is_told_once(db):
    owner = _user(db)
    eng = _due(db, _engagement(db, owner))
    eng.authorized_until = NOW - dt.timedelta(minutes=5)
    eng.authorized_from = NOW - dt.timedelta(days=60)
    db.commit()
    for _ in range(2):
        result, calls = _tick(db)
        assert result["started"] == 0 and calls == []
    db.expire_all()
    assert db.get(Engagement, eng.id).schedule_skip_reason == "outside_authorized_window"
    items = db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.kind == "schedule_blocked")).all()
    assert len(items) == 1 and items[0].state == "open"


def test_after_the_review_date_nothing_runs(db):
    owner = _user(db)
    eng = _due(db, _engagement(db, owner))
    eng.review_at = NOW - dt.timedelta(days=1)
    db.commit()
    result, calls = _tick(db)
    assert result["started"] == 0 and calls == [] and _runs(db, eng) == []
    db.expire_all()
    assert db.get(Engagement, eng.id).schedule_skip_reason == "authorization_review_due"


def test_a_not_ready_engagement_gets_no_run_and_one_inbox_item_until_fixed(db):
    owner = _user(db)
    eng = _due(db, _engagement(db, owner))
    for asset in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id)):
        db.delete(asset)
    db.commit()
    for _ in range(3):
        result, calls = _tick(db)
        assert result["started"] == 0 and calls == []
    assert _runs(db, eng) == []
    db.expire_all()
    got = db.get(Engagement, eng.id)
    assert got.schedule_skip_reason.startswith("not_ready")
    items = db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.kind == "schedule_blocked")).all()
    assert len(items) == 1 and items[0].state == "open"
    assert len(_audit(db, eng, "scheduled_run_skipped")) == 1

    # fixed: the next tick starts the run, clears the reason and closes the item
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="example.test",
                      active_allowed=True, authorization_verified=True))
    db.commit()
    result, calls = _tick(db)
    assert result["started"] == 1 and len(calls) == 1
    db.expire_all()
    assert db.get(Engagement, eng.id).schedule_skip_reason is None
    assert db.scalars(select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.kind == "schedule_blocked")
                      ).one().state == "resolved"


def test_the_capacity_cap_holds_back_the_second_due_engagement(db, monkeypatch):
    owner = _user(db)
    first = _due(db, _engagement(db, owner), overdue_days=3)
    second = _due(db, _engagement(db, owner), overdue_days=1)
    result, calls = _tick(db)
    assert result == {"due": 2, "started": 1, "waiting": 1} and len(calls) == 1
    assert calls[0]["engagement_id"] == str(first.id)  # the longest overdue goes first
    db.expire_all()
    assert db.get(Engagement, second.id).schedule_skip_reason == "waiting_for_capacity"
    assert _runs(db, second) == []

    # the cap is a setting: with room for two, the next tick starts the waiting one
    monkeypatch.setenv(scheduling.MAX_CONCURRENT_ENV, "2")
    result, calls = _tick(db)
    assert result["started"] == 1 and calls[0]["engagement_id"] == str(second.id)


def test_a_failed_run_is_not_retried_by_the_scheduler(db):
    owner = _user(db)
    eng = _due(db, _engagement(db, owner))
    assert _tick(db)[0]["started"] == 1
    run = _runs(db, eng)[0]
    run.state, run.health = "failed", "failed"
    run.finished_at = NOW
    db.commit()
    result, calls = _tick(db)
    assert result["started"] == 0 and calls == []  # next run is one interval after the last start
    assert len(_runs(db, eng)) == 1


def test_the_scheduler_changes_nothing_about_scope_or_the_interval(db):
    owner = _user(db)
    eng = _due(db, _engagement(db, owner), every_days=5)
    before = sorted((a.rule, a.value) for a in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id)))
    grants_before = db.scalars(select(ToolGrant).where(ToolGrant.engagement_id == eng.id)).all()
    _tick(db)
    db.expire_all()
    got = db.get(Engagement, eng.id)
    assert got.schedule_every_days == 5 and got.scan_profile == eng.scan_profile
    assert before == sorted((a.rule, a.value) for a in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id)))
    assert len(grants_before) == len(db.scalars(select(ToolGrant).where(ToolGrant.engagement_id == eng.id)).all())


# ------------------------------------------- REQ-MODE-012: missed run, interval


def test_a_run_is_missed_after_twice_the_interval(db):
    owner = _user(db)
    eng = _engagement(db, owner)
    eng.review_at = NOW + dt.timedelta(days=300)
    eng.schedule_every_days = 7
    eng.schedule_set_at = NOW - dt.timedelta(days=40)
    eng.schedule_anchor_at = NOW - dt.timedelta(days=5)
    db.commit()
    # healthy 10 days ago: inside 2 x 7 days, not missed
    started = NOW - dt.timedelta(days=10)
    run = ScanRun(engagement_id=eng.id, phase="report", state="done", health="ok", started_at=started,
                  finished_at=started + dt.timedelta(minutes=5))
    db.add(run)
    db.commit()
    assert monitoring.housekeeping(db, NOW)["missed_runs"] == 0
    # healthy 15 days ago: outside 14 days, missed - once
    run.finished_at = NOW - dt.timedelta(days=15)
    db.commit()
    assert monitoring.housekeeping(db, NOW)["missed_runs"] == 1
    assert monitoring.housekeeping(db, NOW)["missed_runs"] == 0


def test_without_an_interval_nothing_is_ever_missed(db):
    owner = _user(db)
    eng = _engagement(db, owner)
    eng.review_at = NOW + dt.timedelta(days=300)
    db.commit()
    assert monitoring.housekeeping(db, NOW)["missed_runs"] == 0


# ---------------------------------------- REQ-MODE-015: the signed document


def test_the_interval_is_part_of_the_authorization_configuration(db):
    from app.api.engagements import _authorization_config_payload

    owner = _user(db)
    eng = _engagement(db, owner)
    plain = _authorization_config_payload(eng, [], [], [])
    assert "run_every_days" not in plain  # a document signed before the scheduler keeps its checksum
    eng.schedule_every_days = 7
    with_interval = _authorization_config_payload(eng, [], [], [])
    assert with_interval["run_every_days"] == 7 and with_interval != plain


def test_an_assessment_document_is_unchanged(db):
    from app.api.engagements import _authorization_config_payload

    owner = _user(db)
    eng = _engagement(db, owner, mode="assessment")
    assert "run_every_days" not in _authorization_config_payload(eng, [], [], [])
