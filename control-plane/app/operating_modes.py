"""Operating modes and the one start path for scan runs (REQ-MODE-001/002).

An engagement is either `monitoring` (unattended, scheduled, never waits for a
person) or `assessment` (attended or semi-attended testing, the behaviour every
engagement had before modes existed). The mode never widens what the Scope
Gateway allows; it selects defaults, the trigger model, and how a decision that
needs a person is handled.

`begin_scan` is the single place a run is created and queued. The console's
Start run, a scheduled run and a retest all come through it, so readiness, the
one-active-run rule, budgets and the audit row are the same for all of them.
"""

from __future__ import annotations

import dataclasses
import datetime
import uuid

from sqlalchemy.orm import Session

from app import config_resolver, scan_readiness
from app.gateway.audit import append_audit_log
from app.models.engagement import Engagement
from app.models.scan_run import ScanRun
from app.scan_lifecycle import ScanRunAlreadyActive, reap_stale_runs, start_scan_run

MODES = ("monitoring", "assessment")
SUPERVISIONS = ("attended", "semi_attended", "unattended")
TRIGGERS = ("manual", "scheduled")
SCAN_PROFILES = ("passive", "light", "standard", "thorough")
NEW_ASSET_POLICIES = ("auto", "hold")


class ScanNotStartable(Exception):
    """The run was not started; `status` is the HTTP status a caller should use."""

    def __init__(self, status: int, detail):
        super().__init__(str(detail))
        self.status = status
        self.detail = detail


@dataclasses.dataclass
class StartedScan:
    run: ScanRun
    task_id: str


def is_monitoring(eng: Engagement) -> bool:
    return eng.operating_mode == "monitoring"


def resolve_supervision(eng: Engagement, trigger: str, requested: str | None) -> str:
    """REQ-MODE-002: a monitoring run is always unattended; an assessment run is
    attended unless the person starting it says it is semi-attended."""
    if is_monitoring(eng):
        return "unattended"
    if trigger == "scheduled":
        raise ScanNotStartable(409, "only a monitoring engagement can run on a schedule")
    if requested in (None, "attended"):
        return "attended"
    if requested == "semi_attended":
        return "semi_attended"
    raise ScanNotStartable(422, f"supervision must be one of {', '.join(SUPERVISIONS[:2])}")


def begin_scan(
    db: Session,
    engagement_id: uuid.UUID,
    *,
    trigger: str,
    initiated_by: str,
    supervision: str | None = None,
    scan_profile: str | None = None,
    scope_hosts: list[str] | None = None,
    retest_finding_id: uuid.UUID | None = None,
    schedule_id: uuid.UUID | None = None,
    enqueue=None,
) -> StartedScan:
    """Create the run (race-safe) and queue it for the worker.

    Raises ScanNotStartable(409) with the readiness blockers, or because a run
    is already active. Nothing is created in that case."""
    if trigger not in TRIGGERS:
        raise ScanNotStartable(422, f"trigger must be one of {', '.join(TRIGGERS)}")
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise ScanNotStartable(404, "engagement not found")

    reap_stale_runs(db, engagement_id)
    readiness = scan_readiness.evaluate(db, engagement_id)
    if not readiness.ready:
        raise ScanNotStartable(409, {
            "error": "engagement_not_scan_ready",
            "blockers": [{"code": b.code, "message": b.message, "action": b.action} for b in readiness.blockers],
        })

    resolved_supervision = resolve_supervision(eng, trigger, supervision)
    profile = scan_profile or eng.scan_profile or "standard"
    if profile not in SCAN_PROFILES:
        raise ScanNotStartable(422, f"scan depth must be one of {', '.join(SCAN_PROFILES)}")

    max_iterations = config_resolver.effective_agent_max_iterations(db, engagement_id)
    approval_timeout_seconds = config_resolver.effective_approval_timeout_seconds(db, engagement_id)
    try:
        run = start_scan_run(
            db, engagement_id, scan_profile=profile, trigger=trigger,
            initiated_by=initiated_by, supervision=resolved_supervision, scope_hosts=scope_hosts,
            retest_finding_id=retest_finding_id, schedule_id=schedule_id,
        )
    except ScanRunAlreadyActive:
        raise ScanNotStartable(409, "engagement already has an active scan_run") from None

    actor = initiated_by if initiated_by.startswith(("user:", "schedule:")) else f"user:{initiated_by}"
    append_audit_log(
        db, engagement_id=engagement_id, actor=actor, action="scan_run_started", decision="ALLOW",
        reason=f"{trigger}:{resolved_supervision}",
        payload={
            "scan_run_id": str(run.id), "trigger": trigger, "supervision": resolved_supervision,
            "scan_profile": profile, "operating_mode": eng.operating_mode,
            # REQ-BUDGET-001: the global setting as it was when this run started.
            "budget_tool_calls_max": run.budget_tool_calls_max,
            "scope_hosts": scope_hosts, "retest_finding_id": str(retest_finding_id) if retest_finding_id else None,
            "schedule_id": str(schedule_id) if schedule_id else None,
        },
    )
    if eng.schedule_every_days is not None:
        # REQ-MON-001: any run, whoever started it, restarts the count of the interval
        # (done here, not in scheduling.py, which imports this module).
        eng.schedule_anchor_at = run.started_at or utcnow()
        eng.schedule_skip_reason = None
        eng.schedule_skip_since = None
    db.commit()
    if enqueue is None:
        from app.celery_client import enqueue_scan as enqueue  # the broker client is only needed here
    task_id = enqueue(
        str(engagement_id), scan_run_id=str(run.id), budget_max_iterations=max_iterations,
        approval_timeout_seconds=approval_timeout_seconds,
    )
    return StartedScan(run=run, task_id=task_id)


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)
