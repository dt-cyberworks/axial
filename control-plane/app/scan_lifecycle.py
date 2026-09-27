"""Scan-run liveness / reaping (REQ-RAWLEASE-001).

Ein Lauf, der keinen Fortschritt mehr macht (Worker abgestuerzt oder haengend),
darf neue Scans nicht dauerhaft blockieren. Der Worker frischt scan_run.heartbeat_at
auf, solange er Fortschritt macht; hier werden Laeufe mit veraltetem Heartbeat
geerntet (auf 'aborted' gesetzt), bevor ein neuer Lauf angelegt wird.

Reaping aendert ausschliesslich Lauf-Buchhaltung - es autorisiert nie ein Ziel und
umgeht nie das Scope Gateway. Ein Lauf mit frischem Heartbeat bleibt unangetastet.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.scan_run import ScanRun

_ACTIVE_STATES = ["running", "waiting_approval"]


class ScanRunAlreadyActive(Exception):
    """GitHub issue #18: raised when the one-active-scan_run-per-engagement
    slot is already held, whether by the cheap SELECT fast path or by the
    database's own unique index catching a concurrent insert that slipped
    past it. Callers translate this to the existing 409."""


def start_scan_run(db: Session, engagement_id: uuid.UUID, *, budget_tool_calls_max: int = 200) -> ScanRun:
    """Create THE one allowed active scan_run for this engagement, race-safe.

    GitHub issue #18: starting a scan was a check-then-act with no lock and no
    database invariant, in two separate places (this one and the worker's own
    internal creation call) - concurrent requests could both pass the SELECT
    check and both insert a running row, multiplying real traffic sent at a
    real target and doubling every per-engagement budget/rate limit.

    The SELECT below is only a fast path for the common, uncontended case
    (an immediate, readable 409 without touching the database's error path).
    The actual invariant is `uq_scan_run_one_active_per_engagement`
    (migration 0028) - a concurrent insert that slips past the SELECT still
    hits that index and is translated to ScanRunAlreadyActive here, inside a
    savepoint, so the caller's session is left usable rather than poisoned by
    an unhandled IntegrityError.
    """
    active = db.scalar(
        select(ScanRun.id).where(
            ScanRun.engagement_id == engagement_id,
            ScanRun.state.in_(_ACTIVE_STATES),
        ).limit(1)
    )
    if active is not None:
        raise ScanRunAlreadyActive()

    run = ScanRun(
        engagement_id=engagement_id,
        started_at=datetime.datetime.now(datetime.timezone.utc),
        phase="discovery",
        state="running",
        budget_tool_calls_max=budget_tool_calls_max,
    )
    try:
        with db.begin_nested():
            db.add(run)
            db.flush()
    except IntegrityError as exc:
        raise ScanRunAlreadyActive() from exc
    db.commit()
    db.refresh(run)
    return run


def reap_stale_runs(db: Session, engagement_id: uuid.UUID) -> int:
    """Setzt running/waiting_approval-Laeufe ohne heartbeat_at-Update seit
    > stale_run_seconds auf 'aborted'. Gibt die Anzahl geernteter Laeufe zurueck."""
    return _reap(db, engagement_id=engagement_id)


def reap_all_stale_runs(db: Session) -> int:
    """GitHub issue #29: the engagement-scoped reap_stale_runs above only ever
    ran opportunistically, from inside a request that happened to touch that
    ONE engagement (start_scan, create_scan_run) - an abandoned run on an
    engagement nobody happens to interact with again stayed 'running'
    indefinitely. This is the same reaping logic with no engagement filter,
    meant to be called periodically (Celery beat) independent of any inbound
    request."""
    return _reap(db, engagement_id=None)


def _reap(db: Session, *, engagement_id: uuid.UUID | None) -> int:
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=get_settings().stale_run_seconds
    )
    conditions = [ScanRun.state.in_(_ACTIVE_STATES), ScanRun.heartbeat_at < cutoff]
    if engagement_id is not None:
        conditions.append(ScanRun.engagement_id == engagement_id)
    stale = db.scalars(select(ScanRun).where(*conditions).with_for_update()).all()
    for run in stale:
        run.state = "aborted"
        run.state_reason = "reaped_stale_heartbeat"
        run.finished_at = datetime.datetime.now(datetime.timezone.utc)
    if stale:
        db.commit()
    return len(stale)
