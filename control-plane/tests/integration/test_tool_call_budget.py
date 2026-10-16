"""REQ-BUDGET-001/002 at the HTTP layer and on the start path.

The point of the negative tests: nobody but an administrator can change the budget, a request cannot
pick its own, a change never rewrites a run that is already going, and an exhausted budget is a
degraded run, never an ok one."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import auth_service, celery_client, monitoring, scan_diff, scheduling
from app.config import get_settings
from app.db.base import get_db
from app.main import app
from app.models.audit import AuditLog
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
from app.report_builder import budget_denied_calls

NOW = dt.datetime.now(dt.timezone.utc)


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
    monkeypatch.setattr(celery_client, "enqueue_scan", lambda *a, **k: "task-1")


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


def _engagement(db, owner: User, *, mode="assessment", **kw) -> Engagement:
    eng = Engagement(
        title="E", source="own_domain", status="active", operating_mode=mode,
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


def _set_budget(client, db, value) -> int:
    admin = _user(db, role="admin")
    r = client.put("/settings/tool-call-budget", json={"value": value}, headers=_auth(db, admin))
    return r.status_code


def _finish(db, run_id):
    db.expire_all()
    run = db.get(ScanRun, run_id)
    run.state, run.finished_at = "done", NOW
    db.commit()


# ----------------------------------------------- REQ-BUDGET-001: the setting


def test_the_default_is_200_and_an_admin_can_change_it(client, db):
    admin = _user(db, role="admin")
    h = _auth(db, admin)
    got = client.get("/settings/tool-call-budget", headers=h)
    assert got.status_code == 200 and got.json() == {"value": 200, "min": 20, "max": 5000}
    put = client.put("/settings/tool-call-budget", json={"value": 450}, headers=h)
    assert put.status_code == 200 and put.json()["value"] == 450
    assert client.get("/settings/tool-call-budget", headers=h).json()["value"] == 450


@pytest.mark.parametrize("value", [19, 0, -5, 5001, "many", None, 12.5])
def test_a_bad_value_is_refused_and_the_old_one_stays(client, db, value):
    admin = _user(db, role="admin")
    h = _auth(db, admin)
    assert client.put("/settings/tool-call-budget", json={"value": 300}, headers=h).status_code == 200
    r = client.put("/settings/tool-call-budget", json={"value": value}, headers=h)
    assert r.status_code == 422
    assert client.get("/settings/tool-call-budget", headers=h).json()["value"] == 300


def test_an_operator_cannot_read_or_change_it(client, db):
    op = _user(db)
    h = _auth(db, op)
    assert client.get("/settings/tool-call-budget", headers=h).status_code == 403
    assert client.put("/settings/tool-call-budget", json={"value": 4000}, headers=h).status_code == 403
    admin = _user(db, role="admin")
    assert client.get("/settings/tool-call-budget", headers=_auth(db, admin)).json()["value"] == 200


def test_without_credentials_it_is_401(client):
    assert client.get("/settings/tool-call-budget").status_code == 401
    assert client.put("/settings/tool-call-budget", json={"value": 300}).status_code == 401


def test_a_new_run_starts_with_the_global_value_and_records_it(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    assert _set_budget(client, db, 640) == 200
    r = client.post(f"/engagements/{eng.id}/scan", headers=_auth(db, owner))
    assert r.status_code == 202
    db.expire_all()
    run = db.get(ScanRun, uuid.UUID(r.json()["scan_run_id"]))
    assert run.budget_tool_calls_max == 640
    row = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == "scan_run_started")).one()
    assert row.payload["budget_tool_calls_max"] == 640


def test_a_run_keeps_the_budget_it_started_with(client, db):
    owner = _user(db)
    h = _auth(db, owner)
    eng = _engagement(db, owner)
    assert _set_budget(client, db, 300) == 200
    first = client.post(f"/engagements/{eng.id}/scan", headers=h).json()["scan_run_id"]
    assert _set_budget(client, db, 900) == 200
    db.expire_all()
    assert db.get(ScanRun, uuid.UUID(first)).budget_tool_calls_max == 300  # unchanged while running
    _finish(db, uuid.UUID(first))
    second = client.post(f"/engagements/{eng.id}/scan", headers=h).json()["scan_run_id"]
    db.expire_all()
    assert db.get(ScanRun, uuid.UUID(second)).budget_tool_calls_max == 900


def test_a_scheduled_run_gets_the_global_value_too(client, db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    eng.schedule_every_days = 1
    eng.schedule_anchor_at = NOW - dt.timedelta(days=3)
    db.commit()
    assert _set_budget(client, db, 777) == 200
    result = scheduling.run_due(db, now=NOW, enqueue=lambda *a, **k: "t")
    assert result["started"] == 1
    db.expire_all()
    run = db.scalars(select(ScanRun).where(ScanRun.engagement_id == eng.id)).one()
    assert run.trigger == "scheduled" and run.budget_tool_calls_max == 777


def test_a_request_cannot_choose_the_budget(client, db):
    """The legacy internal start endpoint used to take one. It must ignore it now."""
    owner = _user(db)
    eng = _engagement(db, owner)
    assert _set_budget(client, db, 250) == 200
    headers = {"X-ASM-Internal-Token": get_settings().internal_api_token}
    r = client.post(f"/internal/engagements/{eng.id}/scan-runs", json={"budget_tool_calls_max": 99999}, headers=headers)
    assert r.status_code == 201
    assert r.json()["budget_tool_calls_max"] == 250


def test_the_console_start_body_has_no_budget_field(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    r = client.post(f"/engagements/{eng.id}/scan", json={"budget_tool_calls_max": 5000}, headers=_auth(db, owner))
    assert r.status_code == 202
    db.expire_all()
    assert db.get(ScanRun, uuid.UUID(r.json()["scan_run_id"])).budget_tool_calls_max == 200


# ------------------------------------ REQ-BUDGET-002: exhaustion is degraded


def test_health_of_a_run_that_exhausted_its_budget_is_degraded_not_ok(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    run = ScanRun(engagement_id=eng.id, phase="report", state="done", started_at=NOW, finished_at=NOW,
                  state_reason="coverage_degraded:tool_call_budget=exhausted_95_denied")
    assert monitoring.health_of(run) == "degraded"
    clean = ScanRun(engagement_id=eng.id, phase="report", state="done", started_at=NOW, finished_at=NOW)
    assert monitoring.health_of(clean) == "ok"
    # exactly the maximum used, nothing denied: not degraded
    exact = ScanRun(engagement_id=eng.id, phase="report", state="done", started_at=NOW, finished_at=NOW,
                    budget_tool_calls_used=200, budget_tool_calls_max=200)
    assert monitoring.health_of(exact) == "ok"


def test_a_budget_exhausted_run_is_never_the_baseline_of_the_next_comparison(db):
    owner = _user(db)
    eng = _engagement(db, owner, mode="monitoring")
    good = ScanRun(engagement_id=eng.id, phase="report", state="done", health="ok",
                   started_at=NOW - dt.timedelta(days=2), finished_at=NOW - dt.timedelta(days=2))
    cut = ScanRun(engagement_id=eng.id, phase="report", state="done",
                  started_at=NOW - dt.timedelta(days=1), finished_at=NOW - dt.timedelta(days=1),
                  state_reason="coverage_degraded:tool_call_budget=exhausted_12_denied")
    latest = ScanRun(engagement_id=eng.id, phase="report", state="done", started_at=NOW, finished_at=NOW)
    db.add_all([good, cut, latest])
    db.commit()
    baseline = scan_diff._previous_run(db, latest)
    assert baseline is not None and baseline.id == good.id


@pytest.mark.parametrize("reason,expected", [
    ("coverage_degraded:tool_call_budget=exhausted_95_denied", 95),
    ("coverage_degraded:nmap=runner_dispatch_failed,tool_call_budget=exhausted_3_denied", 3),
    ("coverage_partial:ffuf=1; coverage_degraded:tool_call_budget=exhausted_7_denied", 7),
    ("coverage_degraded:nmap=runner_dispatch_failed", 0),
    ("coverage_partial:ffuf=1", 0),
    (None, 0),
    ("", 0),
    ("tool_call_budget=exhausted_9_denied", 0),  # not inside a coverage_degraded list
])
def test_the_denied_calls_are_read_from_the_run_reason(reason, expected):
    assert budget_denied_calls(reason) == expected
