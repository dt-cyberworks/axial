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
from app.settings_store import get_global_tool_call_budget

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


def start_scan_run(
    db: Session, engagement_id: uuid.UUID, *, budget_tool_calls_max: int | None = None,
    scan_profile: str | None = None, trigger: str = "manual", initiated_by: str | None = None,
    supervision: str | None = None, scope_hosts: list[str] | None = None,
    retest_finding_id: uuid.UUID | None = None, schedule_id: uuid.UUID | None = None,
) -> ScanRun:
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
    # REQ-BUDGET-001: the tool-call budget is one global setting; this is the one place it is read,
    # so every way of starting a run (Run now, a schedule, a retest, the internal endpoint) gets
    # it. The run keeps the value it started with, whatever the setting becomes later.
    if budget_tool_calls_max is None:
        budget_tool_calls_max = get_global_tool_call_budget(db)
    run = ScanRun(
        engagement_id=engagement_id,
        started_at=datetime.datetime.now(datetime.timezone.utc),
        phase="discovery",
        state="running",
        budget_tool_calls_max=budget_tool_calls_max,
        # REQ-PIPE-005: recorded on the run; a later change of the engagement
        # setting does not rewrite what this run did. REQ-MODE-002/011: a schedule
        # tier or a person may start a run at another depth than the default.
        scan_profile=scan_profile or (engagement.scan_profile if engagement is not None else "standard"),
        # REQ-MODE-002: how the run started and how supervised it is.
        trigger=trigger, initiated_by=initiated_by, supervision=supervision,
        schedule_id=schedule_id, scope_hosts=scope_hosts, retest_finding_id=retest_finding_id,
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
    conditions = [
        ScanRun.state.in_(_ACTIVE_STATES), ScanRun.heartbeat_at < cutoff,
        # REQ-MODE-016: a run parked on a person's decision has no worker and polls
        # nothing; it is not abandoned, it waits (its approval expires on its own).
        ScanRun.checkpoint["parked"].astext.is_(None),
    ]
    if engagement_id is not None:
        conditions.append(ScanRun.engagement_id == engagement_id)
    stale = db.scalars(select(ScanRun).where(*conditions).with_for_update()).all()
    resumed: list[ScanRun] = []
    aborted: list[ScanRun] = []
    reaped = 0
    for run in stale:
        if _try_resume(run):
            resumed.append(run)
            continue
        run.state = "aborted"
        run.state_reason = "reaped_stale_heartbeat"
        run.finished_at = datetime.datetime.now(datetime.timezone.utc)
        aborted.append(run)
        reaped += 1
    if stale:
        db.commit()
    for run in aborted:
        # REQ-MODE-012: an abandoned run of a monitor is a failed run, visible as one.
        from app import monitoring  # local import: monitoring imports models, not this module

        monitoring.on_run_finished(db, run)
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


# ---- semi-attended runs: park on a decision, resume when it is made (REQ-MODE-016) ----


def park_run(db: Session, run: ScanRun, *, approval_id: str, resume_state: dict, attempt: int | None = None) -> None:
    """The worker hands the run back while it waits for a person: the run stays
    `waiting_approval`, what the agent needs to continue is stored in the checkpoint,
    and the worker task ends - no worker slot is held while nobody answers.

    The same run stays open on purpose. The approval is bound to this run's id and
    the gateway re-checks the run when the call is claimed, so approving into a new
    run would mean re-binding an approval, which must not loosen."""
    now = datetime.datetime.now(datetime.timezone.utc)
    checkpoint = dict(run.checkpoint or {})
    checkpoint["parked"] = {"approval_id": approval_id, "since": now.isoformat()}
    checkpoint["agent_resume"] = resume_state
    run.checkpoint = checkpoint
    run.state = "waiting_approval"
    run.owner_task_id = None
    run.heartbeat_at = now


def resume_parked_run(db: Session, run: ScanRun) -> bool:
    """Queue the same run again so a worker continues it. Returns True when it was
    queued. Idempotent: a run that is not parked, or whose approval is still open,
    is left alone. Never resumes a run the operator stopped."""
    parked = (run.checkpoint or {}).get("parked")
    if not isinstance(parked, dict) or run.state != "waiting_approval" or run.cancel_requested:
        return False
    from app.models.approval import ApprovalRequest

    approval = db.get(ApprovalRequest, uuid.UUID(str(parked.get("approval_id"))))
    now = datetime.datetime.now(datetime.timezone.utc)
    if approval is not None and approval.state == "requested":
        if approval.expires_at >= now:
            return False  # still waiting for the person
        approval.state = "expired"
    params = (run.checkpoint or {}).get("params") or {}
    kwargs = {k: v for k, v in params.items() if v is not None}
    try:
        from app.celery_client import enqueue_scan

        enqueue_scan(str(run.engagement_id), str(run.id), **kwargs)
    except Exception:  # noqa: BLE001 - stays parked; the next sweep tries again
        logger.warning("parked scan_run %s: resume could not be queued", run.id, exc_info=True)
        return False
    checkpoint = dict(run.checkpoint or {})
    checkpoint.pop("parked", None)
    run.checkpoint = checkpoint
    run.state = "running"
    run.owner_task_id = None
    run.heartbeat_at = now
    try:
        from app import monitoring  # local import: monitoring imports models, not this module

        monitoring.resolve_inbox_items(db, run.engagement_id, f"run_needs_you:{parked.get('approval_id')}", "system")
    except Exception:  # noqa: BLE001 - the inbox is a courtesy; the run is what matters
        logger.warning("could not resolve the inbox item of parked scan_run %s", run.id, exc_info=True)
    return True


def resume_decided_parked_runs(db: Session) -> int:
    """Sweep: resume every parked run whose approval was decided or has expired. The
    approve/reject endpoints resume at once; this catches expiry and a failed queue."""
    runs = db.scalars(
        select(ScanRun).where(ScanRun.state == "waiting_approval", ScanRun.checkpoint["parked"].astext.is_not(None))
        .with_for_update(skip_locked=True)
    ).all()
    resumed = 0
    for run in runs:
        if resume_parked_run(db, run):
            resumed += 1
            append_audit_log(
                db, engagement_id=run.engagement_id, actor="control-plane", action="scan_run_resumed",
                decision=None, reason="parked_approval_decided",
                payload={"scan_run_id": str(run.id), "phase": run.phase},
            )
    db.commit()
    return resumed
