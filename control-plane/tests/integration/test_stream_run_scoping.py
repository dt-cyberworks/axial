"""TC-FIDELITY-002: the activity stream's run-scoping clause matches exactly
one run's own events - tagged events by exact scan_run_id (never a different
run's, even with overlapping timestamps), untagged events by time window."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select

from app.api.stream import _run_scoped_clause
from app.models.audit import AuditLog
from app.models.scan_run import ScanRun


def _run(db, engagement_id, started_at, finished_at=None):
    # GitHub issue #18: only one running/waiting_approval scan_run per
    # engagement is a real database invariant now (uq_scan_run_one_active_per_
    # engagement) - a run with finished_at set must carry a real terminal
    # state, not "running", or two such rows for one engagement collide.
    state = "done" if finished_at is not None else "running"
    run = ScanRun(engagement_id=engagement_id, phase="fingerprint", state=state,
                  started_at=started_at, finished_at=finished_at)
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _row(db, engagement_id, ts, payload):
    row = AuditLog(engagement_id=engagement_id, actor="worker", action="tool_execution",
                    decision=None, reason=None, payload=payload, prev_hash=None, row_hash="test")
    db.add(row)
    db.flush()
    db.execute(
        AuditLog.__table__.update().where(AuditLog.id == row.id).values(ts=ts)
    )
    db.commit()
    return row


def test_run_scoping_matches_tagged_and_windowed_untagged_only(db, lab_engagement):
    t0 = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
    run_a = _run(db, lab_engagement.id, started_at=t0, finished_at=t0 + dt.timedelta(minutes=10))
    run_b = _run(db, lab_engagement.id, started_at=t0 + dt.timedelta(minutes=5))  # still running

    tagged_a = _row(db, lab_engagement.id, t0 + dt.timedelta(minutes=2), {"scan_run_id": str(run_a.id)})
    tagged_b_inside_a_window = _row(
        db, lab_engagement.id, t0 + dt.timedelta(minutes=6), {"scan_run_id": str(run_b.id)},
    )
    untagged_inside_window = _row(db, lab_engagement.id, t0 + dt.timedelta(minutes=3), {})
    untagged_before_window = _row(db, lab_engagement.id, t0 - dt.timedelta(hours=1), {})

    clause = _run_scoped_clause(db, lab_engagement.id, run_a.id)
    matched_ids = set(db.scalars(
        select(AuditLog.id).where(AuditLog.engagement_id == lab_engagement.id, clause)
    ).all())

    assert tagged_a.id in matched_ids
    assert untagged_inside_window.id in matched_ids
    assert tagged_b_inside_a_window.id not in matched_ids  # different run's tag - no leakage
    assert untagged_before_window.id not in matched_ids    # outside the window


def test_old_finished_run_is_not_starved_by_a_newer_runs_volume(db, lab_engagement):
    """Regression for the reported bug: opening an OLD run's Activity view
    returned nothing once a newer run generated enough events to evict the old
    run's rows from an engagement-wide, row-count-capped query."""
    t0 = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=3)
    old_run = _run(db, lab_engagement.id, started_at=t0, finished_at=t0 + dt.timedelta(minutes=5))
    old_event = _row(db, lab_engagement.id, t0 + dt.timedelta(minutes=1), {"scan_run_id": str(old_run.id)})

    new_run = _run(db, lab_engagement.id, started_at=t0 + dt.timedelta(hours=2))
    for i in range(50):
        _row(db, lab_engagement.id, new_run.started_at + dt.timedelta(seconds=i), {"scan_run_id": str(new_run.id)})

    clause = _run_scoped_clause(db, lab_engagement.id, old_run.id)
    matched_ids = set(db.scalars(
        select(AuditLog.id).where(AuditLog.engagement_id == lab_engagement.id, clause)
    ).all())

    assert matched_ids == {old_event.id}
