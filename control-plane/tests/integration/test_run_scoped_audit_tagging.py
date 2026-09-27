"""REQ-FIDELITY-008: agent_event/dns_materialization/approval/approval_execution
audit rows carry a top-level scan_run_id when known, and the run-scoped
Activity stream's time-window fallback is recomputed fresh on every poll
instead of freezing at SSE-connect time."""

from __future__ import annotations

import datetime as dt
import time

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api import stream as stream_module
from app.api.approvals import approve, reject
from app.api.internal import internal_agent_event, internal_complete_approval
from app.gateway import dns_materialization
from app.gateway.dns_materialization import materialize
from app.models.approval import ApprovalRequest
from app.models.audit import AuditLog
from app.models.scan_run import ScanRun
from app.schemas.approval import ApprovalDecision
from app.schemas.internal import AgentEventIn, ApprovalExecutionResult


def _fake_getaddrinfo(mapping: dict[str, list[str]]):
    def _inner(host, *args, **kwargs):
        ips = mapping.get(host)
        if not ips:
            import socket
            raise socket.gaierror("name not found")
        return [(None, None, None, "", (ip, 0)) for ip in ips]
    return _inner


def _last_audit(db, engagement_id, action):
    return db.scalars(
        select(AuditLog)
        .where(AuditLog.engagement_id == engagement_id, AuditLog.action == action)
        .order_by(AuditLog.ts.desc())
    ).first()


def _running_scan_run(db, engagement_id, state: str = "running") -> ScanRun:
    run = ScanRun(engagement_id=engagement_id, phase="agent", state=state)
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _pending_approval(db, engagement_id, scan_run_id) -> ApprovalRequest:
    approval = ApprovalRequest(
        engagement_id=engagement_id,
        tool_call={"tool": "http_request", "target": "metasploitable2", "scan_run_id": str(scan_run_id)},
        state="requested",
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=15),
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)
    return approval


# --- Payload tagging (the real fix) -----------------------------------------

def test_agent_event_is_tagged_with_scan_run_id(db, lab_engagement):
    internal_agent_event(
        lab_engagement.id,
        AgentEventIn(event="started", payload={"scan_run_id": "22222222-2222-2222-2222-222222222222"}),
        db,
    )
    row = _last_audit(db, lab_engagement.id, "agent_event")
    assert row.payload["scan_run_id"] == "22222222-2222-2222-2222-222222222222"


def test_dns_materialization_is_tagged_with_scan_run_id(db, lab_engagement, monkeypatch):
    monkeypatch.setattr(dns_materialization.socket, "getaddrinfo",
                        _fake_getaddrinfo({"metasploitable2": ["10.0.0.5"]}))
    run = _running_scan_run(db, lab_engagement.id)

    materialize(db, lab_engagement.id, scan_run_id=run.id)

    row = _last_audit(db, lab_engagement.id, "dns_materialization")
    assert row.payload["scan_run_id"] == str(run.id)


def test_approve_hoists_scan_run_id_from_tool_call(db, lab_engagement, test_user):
    run = _running_scan_run(db, lab_engagement.id)
    approval = _pending_approval(db, lab_engagement.id, run.id)

    approve(approval.id, ApprovalDecision(), db, user=test_user)

    row = _last_audit(db, lab_engagement.id, "approval")
    assert row.payload["scan_run_id"] == str(run.id)


def test_reject_hoists_scan_run_id_from_tool_call(db, lab_engagement, test_user):
    run = _running_scan_run(db, lab_engagement.id)
    approval = _pending_approval(db, lab_engagement.id, run.id)

    reject(approval.id, ApprovalDecision(), db, user=test_user)

    row = _last_audit(db, lab_engagement.id, "approval")
    assert row.payload["scan_run_id"] == str(run.id)


def test_approval_execution_is_tagged_with_scan_run_id(db, lab_engagement, test_user):
    run = _running_scan_run(db, lab_engagement.id)
    approval = _pending_approval(db, lab_engagement.id, run.id)
    approval.state = "executing"
    db.commit()

    internal_complete_approval(approval.id, ApprovalExecutionResult(success=True, error=None), db)

    row = _last_audit(db, lab_engagement.id, "approval_execution")
    assert row.payload["scan_run_id"] == str(run.id)


# --- Stream scoping: fail-fast validation + fresh-window regression --------

def test_validate_run_rejects_unknown_or_cross_engagement_run(db, lab_engagement, test_user):
    from app.models.engagement import Engagement

    with pytest.raises(HTTPException) as exc:
        stream_module._validate_run(db, lab_engagement.id, "22222222-2222-2222-2222-222222222222")
    assert exc.value.status_code == 404

    now = dt.datetime.now(dt.timezone.utc)
    other = Engagement(
        title="Other", source="lab", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
        owner_user_id=test_user.id,
    )
    db.add(other)
    db.commit()
    other_run = _running_scan_run(db, other.id)
    with pytest.raises(HTTPException) as exc:
        stream_module._validate_run(db, lab_engagement.id, other_run.id)
    assert exc.value.status_code == 404


def test_run_scoped_clause_never_leaks_a_different_runs_tagged_event(db, lab_engagement):
    """Negative test (required for R3): an event tagged for run A must never
    match run B's window, regardless of timestamp proximity."""
    run_a = _running_scan_run(db, lab_engagement.id)
    # GitHub issue #18: only one running/waiting_approval scan_run per
    # engagement is now a real database invariant - run_b is a second,
    # terminal run in the SAME engagement (its own state never affects
    # _run_scoped_clause, which only reads started_at/finished_at), which
    # still proves the point: an explicit tag mismatch beats a structurally
    # similar OTHER run, whether or not that run happens to be active.
    run_b = _running_scan_run(db, lab_engagement.id, state="done")

    internal_agent_event(lab_engagement.id, AgentEventIn(event="started", payload={"scan_run_id": str(run_a.id)}), db)
    row = _last_audit(db, lab_engagement.id, "agent_event")

    clause_b = stream_module._run_scoped_clause(db, lab_engagement.id, run_b.id)
    leaked = db.scalars(select(AuditLog).where(AuditLog.id == row.id, clause_b)).first()
    assert leaked is None

    clause_a = stream_module._run_scoped_clause(db, lab_engagement.id, run_a.id)
    matched = db.scalars(select(AuditLog).where(AuditLog.id == row.id, clause_a)).first()
    assert matched is not None


def test_run_scoped_clause_window_end_advances_with_wall_clock(db, lab_engagement, monkeypatch):
    """REQ-FIDELITY-008 regression: reusing a clause built once at connect
    time (the old bug) misses an untagged event created afterward; a FRESH
    call (what stream.py now makes on every poll) must not."""
    monkeypatch.setattr(dns_materialization.socket, "getaddrinfo",
                        _fake_getaddrinfo({"metasploitable2": ["10.0.0.5"]}))
    run = _running_scan_run(db, lab_engagement.id)
    clause_at_connect_time = stream_module._run_scoped_clause(db, lab_engagement.id, run.id)

    time.sleep(1.1)
    materialize(db, lab_engagement.id, scan_run_id=None)  # untagged - falls back to the time window
    row = _last_audit(db, lab_engagement.id, "dns_materialization")

    missed_by_frozen_clause = db.scalars(select(AuditLog).where(AuditLog.id == row.id, clause_at_connect_time)).first()
    assert missed_by_frozen_clause is None, "sanity check: the row must genuinely postdate the frozen window"

    fresh_clause = stream_module._run_scoped_clause(db, lab_engagement.id, run.id)
    matched = db.scalars(select(AuditLog).where(AuditLog.id == row.id, fresh_clause)).first()
    assert matched is not None
