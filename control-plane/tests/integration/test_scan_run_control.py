"""Scan-Run-Steuerung: Preflight-Readiness (REQ-RUN-002), kooperativer Stopp
(REQ-RUN-001) und Agent-Step-Persistenz (REQ-RUN-006)."""

from __future__ import annotations

import datetime as dt
import pathlib
import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from app import scan_readiness
from app.api.engagements import cancel_scan_run
from app.api.internal import update_scan_run
from app.gateway.authorize import ToolCall, authorize
from app.models.approval import ApprovalRequest
from app.models.engagement import ScopeAsset, ToolGrant
from app.models.scan_run import AgentStep, ScanRun
from app.schemas.internal import ScanRunUpdate


# --- REQ-RUN-002: Readiness ------------------------------------------------

def test_lab_engagement_is_scan_ready(db, lab_engagement):
    r = scan_readiness.evaluate(db, lab_engagement.id)
    assert r.ready is True and r.blockers == []


def test_after_time_window_blocks(db, lab_engagement):
    lab_engagement.authorized_until = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    db.commit()
    r = scan_readiness.evaluate(db, lab_engagement.id)
    assert not r.ready
    assert any(b.code == "after_time_window" for b in r.blockers)


def test_inactive_engagement_blocks(db, lab_engagement):
    lab_engagement.status = "paused"
    db.commit()
    r = scan_readiness.evaluate(db, lab_engagement.id)
    assert not r.ready
    assert any(b.code == "engagement_not_active" for b in r.blockers)


def test_no_active_scope_blocks(db, lab_engagement):
    for a in db.query(ScopeAsset).filter(ScopeAsset.engagement_id == lab_engagement.id).all():
        a.active_allowed = False
    db.commit()
    r = scan_readiness.evaluate(db, lab_engagement.id)
    assert not r.ready
    assert any(b.code == "no_active_scope" for b in r.blockers)


def test_no_active_grant_blocks(db, lab_engagement):
    db.query(ToolGrant).filter(ToolGrant.engagement_id == lab_engagement.id,
                               ToolGrant.mode == "active").delete()
    db.commit()
    r = scan_readiness.evaluate(db, lab_engagement.id)
    assert not r.ready
    assert any(b.code == "no_active_tool_grant" for b in r.blockers)


# --- REQ-RUN-001: cooperative cancel --------------------------------------

def test_cancel_flag_defaults_false(db, lab_engagement):
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run); db.commit(); db.refresh(run)
    assert run.cancel_requested is False


def test_waiting_approval_run_can_be_cancelled(db, lab_engagement, test_user):
    run = ScanRun(engagement_id=lab_engagement.id, phase="agent", state="waiting_approval")
    db.add(run); db.commit(); db.refresh(run)

    result = cancel_scan_run(lab_engagement.id, run.id, db, user=test_user)

    db.refresh(run)
    assert result == {
        "scan_run_id": str(run.id), "cancel_requested": True,
        "state": "aborted", "state_reason": "cancelled_by_operator",
    }
    assert run.cancel_requested is True
    assert run.state == "aborted"
    assert run.state_reason == "cancelled_by_operator"
    assert run.finished_at is not None


def test_terminal_run_cannot_be_cancelled(db, lab_engagement, test_user):
    run = ScanRun(engagement_id=lab_engagement.id, phase="report", state="done")
    db.add(run); db.commit(); db.refresh(run)

    with pytest.raises(HTTPException) as exc:
        cancel_scan_run(lab_engagement.id, run.id, db, user=test_user)

    assert exc.value.status_code == 409
    assert run.cancel_requested is False


def test_cancelled_run_is_terminal_and_stale_worker_cannot_resurrect_it(db, lab_engagement, test_user):
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run); db.commit(); db.refresh(run)

    cancel_scan_run(lab_engagement.id, run.id, db, user=test_user)
    stale = update_scan_run(
        run.id, ScanRunUpdate(phase="report", state="done", state_reason="stale_worker"), db
    )

    db.refresh(run)
    assert stale.state == "aborted"
    assert run.phase == "fingerprint"
    assert run.state == "aborted"
    assert run.state_reason == "cancelled_by_operator"


def test_cancel_closes_pending_approvals(db, lab_engagement, test_user):
    run = ScanRun(engagement_id=lab_engagement.id, phase="agent", state="waiting_approval")
    db.add(run); db.flush()
    approval = ApprovalRequest(
        engagement_id=lab_engagement.id,
        tool_call={"tool": "http_request", "scan_run_id": str(run.id)},
        state="requested", expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5),
    )
    unrelated = ApprovalRequest(
        engagement_id=lab_engagement.id,
        tool_call={"tool": "http_request", "scan_run_id": str(uuid.uuid4())},
        state="requested", expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5),
    )
    db.add_all([approval, unrelated]); db.commit()

    cancel_scan_run(lab_engagement.id, run.id, db, user=test_user)

    db.refresh(approval)
    db.refresh(unrelated)
    assert approval.state == "cancelled"
    assert approval.execution_finished_at is not None
    assert approval.execution_error == "scan_cancelled_by_operator"
    assert unrelated.state == "requested"


def test_migration_reconciles_historical_stuck_cancel_idempotently(db, lab_engagement):
    run = ScanRun(
        engagement_id=lab_engagement.id, phase="fingerprint", state="running",
        cancel_requested=True,
    )
    db.add(run); db.flush()
    exact = ApprovalRequest(
        engagement_id=lab_engagement.id,
        tool_call={"tool": "nuclei", "scan_run_id": str(run.id)}, state="executing",
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5),
    )
    unrelated = ApprovalRequest(
        engagement_id=lab_engagement.id,
        tool_call={"tool": "nuclei", "scan_run_id": str(uuid.uuid4())}, state="requested",
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5),
    )
    db.add_all([exact, unrelated]); db.commit()
    migration = pathlib.Path(__file__).resolve().parents[2] / "migrations" / "0009_finalize_cancelled_scan_runs.sql"

    db.execute(text(migration.read_text()))
    db.execute(text(migration.read_text()))  # explicitly idempotent
    db.commit()

    db.refresh(run); db.refresh(exact); db.refresh(unrelated)
    assert run.state == "aborted"
    assert run.state_reason == "cancelled_by_operator"
    assert run.finished_at is not None
    assert exact.state == "cancelled"
    assert exact.execution_error == "scan_cancelled_by_operator"
    assert unrelated.state == "requested"


def test_gateway_denies_exact_cancelled_run(db, lab_engagement, test_user):
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run); db.commit(); db.refresh(run)
    cancel_scan_run(lab_engagement.id, run.id, db, user=test_user)

    decision = authorize(db, ToolCall(
        engagement_id=lab_engagement.id, scan_run_id=run.id,
        tool="httpx", category="fingerprint", mode="active",
        target="metasploitable2", args={}, phase="fingerprint",
    ))

    assert not decision.allowed
    assert decision.reason == "scan_run_cancelled"


def test_fingerprint_call_without_run_id_fails_closed(db, lab_engagement):
    decision = authorize(db, ToolCall(
        engagement_id=lab_engagement.id, tool="httpx", category="fingerprint",
        mode="active", target="metasploitable2", args={}, phase="fingerprint",
    ))
    assert not decision.allowed
    assert decision.reason == "scan_run_required"


# --- REQ-RUN-006: agent steps ---------------------------------------------

def test_agent_step_persists_prompt_and_response(db, lab_engagement):
    run = ScanRun(engagement_id=lab_engagement.id, phase="agent", state="running")
    db.add(run); db.commit()
    step = AgentStep(
        engagement_id=lab_engagement.id, scan_run_id=run.id, iteration=1,
        request_messages=[{"role": "system", "content": "you are..."},
                          {"role": "user", "content": "in-scope: x"}],
        response_text="I will probe /api/users",
        response_tool_calls=[{"name": "http_request", "arguments": "{\"target\":\"x\"}"}],
        stop_reason="tool_calls",
    )
    db.add(step); db.commit(); db.refresh(step)
    assert step.request_messages[0]["role"] == "system"
    assert step.response_tool_calls[0]["name"] == "http_request"
    # kein api_key im gespeicherten Kontext
    assert "api_key" not in str(step.request_messages)
