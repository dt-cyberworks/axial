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
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.gateway.audit import append_audit_log
from app.models.engagement import Engagement
from app.models.scan_run import ScanRun

logger = logging.getLogger(__name__)

_ACTIVE_STATES = ["running", "waiting_approval"]


class ScanRunNotClaimable(Exception):
    """GitHub issue #42: a worker asked to run a scan_run it must not run -
    it is finished, unknown, or another live worker attempt owns it."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


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

    engagement = db.get(Engagement, engagement_id)
    run = ScanRun(
        engagement_id=engagement_id,
        started_at=datetime.datetime.now(datetime.timezone.utc),
        phase="discovery",
        state="running",
        budget_tool_calls_max=budget_tool_calls_max,
        # REQ-PIPE-005: recorded on the run; a later change of the engagement
        # setting does not rewrite what this run did.
        scan_profile=engagement.scan_profile if engagement is not None else "standard",
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


def claim_scan_run(
    db: Session, scan_run_id: uuid.UUID, *, task_id: str,
    budget_max_iterations: int | None = None, approval_timeout_seconds: int | None = None,
) -> ScanRun:
    """REQ-RESUME-002: a worker takes ownership of a run. Every claim raises
    `attempt`, and every later worker write carries it, so a worker that was
    replaced (its run resumed elsewhere) can no longer change the run.

    A claim is refused when the run is finished, or when a DIFFERENT task
    holds it and has shown life within the stale window: a duplicate delivery
    of the same message must not run the scan twice in parallel."""
    run = db.scalar(select(ScanRun).where(ScanRun.id == scan_run_id).with_for_update())
    if run is None:
        raise ScanRunNotClaimable("not_found")
    if run.state not in _ACTIVE_STATES:
        raise ScanRunNotClaimable(f"terminal:{run.state}")
    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(seconds=get_settings().stale_run_seconds)
    alive = run.heartbeat_at is not None and run.heartbeat_at >= cutoff
    if run.attempt > 0 and run.owner_task_id and run.owner_task_id != task_id and alive:
        raise ScanRunNotClaimable("owned_by_live_attempt")
    run.attempt += 1
    run.owner_task_id = task_id
    run.heartbeat_at = now
    checkpoint = dict(run.checkpoint or {})
    if "params" not in checkpoint:
        checkpoint["params"] = {
            "budget_max_iterations": budget_max_iterations,
            "approval_timeout_seconds": approval_timeout_seconds,
        }
        run.checkpoint = checkpoint
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
    resumed: list[ScanRun] = []
    reaped = 0
    for run in stale:
        if _try_resume(run):
            resumed.append(run)
            continue
        run.state = "aborted"
        run.state_reason = "reaped_stale_heartbeat"
        run.finished_at = datetime.datetime.now(datetime.timezone.utc)
        reaped += 1
    if stale:
        db.commit()
    for run in resumed:
        append_audit_log(
            db, engagement_id=run.engagement_id, actor="control-plane", action="scan_run_resumed",
            decision=None, reason="worker_lost",
            payload={"scan_run_id": str(run.id), "phase": run.phase, "attempt": run.attempt},
        )
    return reaped


def _try_resume(run: ScanRun) -> bool:
    """REQ-RESUME-003: a claimed run whose worker went silent is handed to a
    new worker task, which continues at the phase after the last one that
    completed, instead of being thrown away. Resuming only re-queues the same
    run: the resumed phases still go through the Scope Gateway like any other.
    Falls back to aborting when there is nothing to resume from, the operator
    asked to stop, the resume budget is spent, or the queue is unreachable."""
    if run.attempt < 1 or run.cancel_requested or run.attempt > get_settings().scan_max_resumes:
        return False
    params = (run.checkpoint or {}).get("params")
    if not isinstance(params, dict):
        return False
    kwargs = {k: v for k, v in params.items() if v is not None}
    try:
        from app.celery_client import enqueue_scan  # imported here: the broker client is only needed on this path
        enqueue_scan(str(run.engagement_id), str(run.id), **kwargs)
    except Exception:  # noqa: BLE001 - any broker failure means: abort as before
        logger.warning("scan_run %s: resume could not be queued - aborting it", run.id, exc_info=True)
        return False
    run.owner_task_id = None
    run.heartbeat_at = datetime.datetime.now(datetime.timezone.utc)
    return True
