"""TC-RESUME-001/002 (GitHub issue #42): a scan run is claimed by one worker
attempt at a time, fenced by that attempt, and resumed by the reaper when its
worker was lost."""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app import celery_client
from app.api.internal import (
    claim_scan_run_endpoint, heartbeat_scan_run, scan_run_cancel_requested, update_scan_run,
)
from app.config import get_settings
from app.models.audit import AuditLog
from app.models.scan_run import ScanRun
from app.scan_lifecycle import reap_all_stale_runs
from app.schemas.internal import ScanRunClaimIn, ScanRunUpdate

STALE = 10_000


def _run(db, eng_id, *, age: int = 1, state: str = "running", phase: str = "fingerprint") -> ScanRun:
    now = dt.datetime.now(dt.timezone.utc)
    run = ScanRun(engagement_id=eng_id, phase=phase, state=state,
                  started_at=now - dt.timedelta(seconds=age + 10), heartbeat_at=now - dt.timedelta(seconds=age))
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _claim(db, run, task="task-1", **kw):
    return claim_scan_run_endpoint(run.id, ScanRunClaimIn(task_id=task, **kw), db)


@pytest.fixture()
def queued(monkeypatch):
    calls = []
    monkeypatch.setattr(celery_client, "enqueue_scan", lambda *a, **k: calls.append((a, k)) or "new-task")
    return calls


# --- claim ---------------------------------------------------------------------

def test_claim_raises_the_attempt_and_returns_where_to_continue(db, lab_engagement):
    run = _run(db, lab_engagement.id, phase="correlate")
    out = _claim(db, run, budget_max_iterations=7, approval_timeout_seconds=60)
    assert out.attempt == 1 and out.phase == "correlate" and out.state == "running"
    assert out.checkpoint["params"] == {"budget_max_iterations": 7, "approval_timeout_seconds": 60}


def test_claim_keeps_the_original_task_parameters_on_a_later_claim(db, lab_engagement):
    run = _run(db, lab_engagement.id)
    _claim(db, run, task="t1", budget_max_iterations=7)
    run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=STALE)
    db.commit()
    out = _claim(db, run, task="t2", budget_max_iterations=99)
    assert out.attempt == 2 and out.checkpoint["params"]["budget_max_iterations"] == 7


@pytest.mark.parametrize("state", ["done", "failed", "aborted"])
def test_negative_claim_of_a_finished_run_is_refused(db, lab_engagement, state):
    run = _run(db, lab_engagement.id, state=state)
    with pytest.raises(HTTPException) as exc:
        _claim(db, run)
    assert exc.value.status_code == 409 and "terminal" in exc.value.detail


def test_negative_claim_of_an_unknown_run_is_refused(db):
    import uuid
    with pytest.raises(HTTPException) as exc:
        claim_scan_run_endpoint(uuid.uuid4(), ScanRunClaimIn(task_id="t"), db)
    assert exc.value.status_code == 409


def test_negative_claim_by_another_task_while_the_owner_is_alive_is_refused(db, lab_engagement):
    run = _run(db, lab_engagement.id)
    _claim(db, run, task="owner")
    with pytest.raises(HTTPException) as exc:
        _claim(db, run, task="duplicate-delivery")
    assert exc.value.status_code == 409 and "owned_by_live_attempt" in exc.value.detail
    db.refresh(run)
    assert run.attempt == 1 and run.owner_task_id == "owner"


def test_claim_by_the_same_task_again_is_allowed(db, lab_engagement):
    run = _run(db, lab_engagement.id)
    _claim(db, run, task="t")
    assert _claim(db, run, task="t").attempt == 2  # a Celery retry of the same task


def test_claim_of_a_run_whose_owner_went_silent_takes_it_over(db, lab_engagement):
    run = _run(db, lab_engagement.id)
    _claim(db, run, task="lost")
    run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=STALE)
    db.commit()
    assert _claim(db, run, task="new").attempt == 2


# --- fencing -------------------------------------------------------------------

def test_negative_a_replaced_attempt_cannot_write_poll_or_heartbeat(db, lab_engagement):
    run = _run(db, lab_engagement.id)
    _claim(db, run, task="old")
    run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=STALE)
    db.commit()
    _claim(db, run, task="new")  # attempt 2

    with pytest.raises(HTTPException) as exc:
        update_scan_run(run.id, ScanRunUpdate(phase="score", attempt=1), db)
    assert exc.value.status_code == 409 and "superseded" in exc.value.detail
    with pytest.raises(HTTPException) as exc:
        scan_run_cancel_requested(run.id, attempt=1, db=db)
    assert exc.value.status_code == 409
    with pytest.raises(HTTPException) as exc:
        heartbeat_scan_run(run.id, attempt=1, db=db)
    assert exc.value.status_code == 409
    db.refresh(run)
    assert run.phase == "fingerprint"

    update_scan_run(run.id, ScanRunUpdate(phase="correlate", attempt=2), db)
    db.refresh(run)
    assert run.phase == "correlate"


def test_a_write_without_an_attempt_is_still_accepted(db, lab_engagement):
    run = _run(db, lab_engagement.id)
    update_scan_run(run.id, ScanRunUpdate(phase="agent"), db)
    db.refresh(run)
    assert run.phase == "agent"


def test_checkpoint_is_merged_and_written_with_the_phase(db, lab_engagement):
    run = _run(db, lab_engagement.id)
    _claim(db, run, budget_max_iterations=5)
    update_scan_run(run.id, ScanRunUpdate(phase="fingerprint", attempt=1, checkpoint={"discovered": [{"value": "a"}]}), db)
    update_scan_run(run.id, ScanRunUpdate(phase="correlate", attempt=1, checkpoint={"services": [{"t": 1}]}), db)
    db.refresh(run)
    assert run.phase == "correlate"
    assert run.checkpoint["discovered"] == [{"value": "a"}] and run.checkpoint["services"] == [{"t": 1}]
    assert run.checkpoint["params"]["budget_max_iterations"] == 5


def test_a_cancel_poll_from_the_current_attempt_counts_as_life(db, lab_engagement):
    run = _run(db, lab_engagement.id, age=STALE, state="waiting_approval")
    _claim(db, run, task="waiting")  # a claim also refreshes the heartbeat
    run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=STALE)
    db.commit()
    assert scan_run_cancel_requested(run.id, attempt=1, db=db) == {"cancel_requested": False}
    db.refresh(run)
    assert (dt.datetime.now(dt.timezone.utc) - run.heartbeat_at).total_seconds() < 60
    assert reap_all_stale_runs(db) == 0 and run.state == "waiting_approval"


def test_the_checkpoint_is_not_part_of_the_operator_run_output():
    from app.schemas.internal import ScanRunOut
    assert "checkpoint" not in ScanRunOut.model_fields and "owner_task_id" not in ScanRunOut.model_fields


# --- the reaper ------------------------------------------------------------------

def test_reaper_resumes_a_claimed_stale_run_with_its_stored_parameters(db, lab_engagement, queued):
    run = _run(db, lab_engagement.id, phase="agent")
    _claim(db, run, budget_max_iterations=11, approval_timeout_seconds=120)
    run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=STALE)
    db.commit()

    assert reap_all_stale_runs(db) == 0  # nothing aborted
    db.refresh(run)
    assert run.state == "running" and run.phase == "agent" and run.owner_task_id is None
    assert (dt.datetime.now(dt.timezone.utc) - run.heartbeat_at).total_seconds() < 60
    (args, kwargs), = queued
    assert args == (str(lab_engagement.id), str(run.id))
    assert kwargs == {"budget_max_iterations": 11, "approval_timeout_seconds": 120}
    audit = db.scalars(select(AuditLog).where(AuditLog.engagement_id == lab_engagement.id,
                                              AuditLog.action == "scan_run_resumed")).all()
    assert len(audit) == 1

    # The queued task can claim it at once, and the run is not resumed twice.
    assert _claim(db, run, task="new-task").attempt == 2
    assert reap_all_stale_runs(db) == 0 and len(queued) == 1


def test_reaper_stops_resuming_after_the_configured_number_of_resumes(db, lab_engagement, queued, monkeypatch):
    monkeypatch.setattr(get_settings(), "scan_max_resumes", 1)
    run = _run(db, lab_engagement.id)
    for expected_state in ("running", "aborted"):
        _claim(db, run, task=f"t-{run.attempt}")
        run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=STALE)
        db.commit()
        reap_all_stale_runs(db)
        db.refresh(run)
        assert run.state == expected_state
    assert run.state_reason == "reaped_stale_heartbeat" and len(queued) == 1


def test_negative_reaper_does_not_resume_a_cancelled_run(db, lab_engagement, queued):
    run = _run(db, lab_engagement.id)
    _claim(db, run)
    run.cancel_requested = True
    run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=STALE)
    db.commit()
    assert reap_all_stale_runs(db) == 1
    db.refresh(run)
    assert run.state == "aborted" and queued == []


def test_negative_reaper_does_not_resume_a_run_that_was_never_claimed(db, lab_engagement, queued):
    run = _run(db, lab_engagement.id, age=STALE)
    assert reap_all_stale_runs(db) == 1
    db.refresh(run)
    assert run.state == "aborted" and queued == []


def test_negative_reaper_aborts_when_the_resume_cannot_be_queued(db, lab_engagement, monkeypatch):
    def _broker_down(*a, **k):
        raise ConnectionError("redis down")
    monkeypatch.setattr(celery_client, "enqueue_scan", _broker_down)
    run = _run(db, lab_engagement.id)
    _claim(db, run)
    run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=STALE)
    db.commit()
    assert reap_all_stale_runs(db) == 1
    db.refresh(run)
    assert run.state == "aborted" and run.state_reason == "reaped_stale_heartbeat"


def test_a_fresh_claimed_run_is_left_alone(db, lab_engagement, queued):
    run = _run(db, lab_engagement.id)
    _claim(db, run)
    assert reap_all_stale_runs(db) == 0 and queued == []


# --- the HTTP wiring the worker actually uses --------------------------------------

def test_the_worker_protocol_works_over_http(db, engine, lab_engagement):
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.db.base import get_db
    from app.main import app

    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override
    try:
        http = TestClient(app, headers={"X-ASM-Internal-Token": get_settings().internal_api_token})
        run = _run(db, lab_engagement.id)
        r = http.post(f"/internal/scan-runs/{run.id}/claim", json={"task_id": "t1", "budget_max_iterations": 3})
        assert r.status_code == 200 and r.json()["attempt"] == 1
        assert http.post(f"/internal/scan-runs/{run.id}/claim", json={"task_id": "t2"}).status_code == 409
        assert http.get(f"/internal/scan-runs/{run.id}/cancel-requested", params={"attempt": 1}).status_code == 200
        assert http.get(f"/internal/scan-runs/{run.id}/cancel-requested", params={"attempt": 5}).status_code == 409
        ok = http.patch(f"/internal/scan-runs/{run.id}", json={"phase": "correlate", "attempt": 1, "checkpoint": {"services": []}})
        assert ok.status_code == 200 and "checkpoint" not in ok.json()
        stale = http.patch(f"/internal/scan-runs/{run.id}", json={"phase": "score", "attempt": 9})
        assert stale.status_code == 409 and "superseded" in stale.text
        assert http.post(f"/internal/scan-runs/{run.id}/heartbeat", params={"attempt": 9}).status_code == 409
    finally:
        app.dependency_overrides.clear()
