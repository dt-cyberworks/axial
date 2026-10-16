"""Automatic runs of a monitoring engagement: "run every N days" (REQ-MON-001/003).

One interval per engagement, stored on the engagement. The next run is due `N` days after
`schedule_anchor_at`, the latest of: when the interval was set, when the engagement last became
active, and when a run last started (by anyone). Nothing else is stored, so a manual run, a
resume or an activation simply moves the anchor.

The scheduler is not a second way to start a scan. A due run is created by
`operating_modes.begin_scan`, the one start path, with `trigger="scheduled"`: the same readiness
check, the same one-active-run rule, the same Scope Gateway and budgets as a person pressing
Run now. This module only decides *whether it is time and whether it is allowed*, and records why
not. It never changes scope, grants, capabilities or the interval itself, and it never retries a
failed run by itself.

Every tick may find the same engagement still blocked. The reason is stored on the engagement and
audited only when it changes, so a paused engagement does not write a row per minute.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import monitoring, operating_modes
from app.gateway.audit import append_audit_log
from app.models.engagement import Engagement
from app.models.scan_run import ScanRun

logger = logging.getLogger(__name__)

MIN_DAYS = 1
MAX_DAYS = 90
ACTIVE_RUN_STATES = ("running", "waiting_approval")
BLOCKED_ITEM_KEY = "schedule_blocked"
MAX_CONCURRENT_ENV = "MONITORING_MAX_CONCURRENT_RUNS"

# What a person reads next to the schedule. The code is what is stored and audited.
REASON_TEXT = {
    "a_run_is_active": "A run of this engagement is still going; the next one starts after it.",
    "waiting_for_capacity": "Other scheduled runs are using the installation's capacity; this one waits for its turn.",
    "outside_authorized_window": "The authorized window of this engagement is not open.",
    "authorization_review_due": "The authorization review date has passed; review it to continue.",
}
_NOT_ACTIVE_TEXT = "The engagement is {status}; automatic runs only start while it is active."


class ScheduleError(Exception):
    """The interval cannot be set; `status` is the HTTP status a caller should use."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def max_concurrent_runs() -> int:
    """How many scheduled runs may execute at once on this installation (REQ-MON-003)."""
    try:
        return max(1, int(os.environ.get(MAX_CONCURRENT_ENV, "1")))
    except ValueError:
        return 1


def next_run_at(eng: Engagement) -> dt.datetime | None:
    if not eng.schedule_every_days or eng.schedule_anchor_at is None:
        return None
    return eng.schedule_anchor_at + dt.timedelta(days=int(eng.schedule_every_days))


def reason_text(reason: str | None) -> str | None:
    if not reason:
        return None
    if reason in REASON_TEXT:
        return REASON_TEXT[reason]
    if reason.startswith("engagement_"):
        return _NOT_ACTIVE_TEXT.format(status=reason.removeprefix("engagement_"))
    if reason.startswith("not_ready:"):
        return "The engagement is not ready to scan (" + reason.removeprefix("not_ready:") + "); fix it so the next run can start."
    return reason


def view(eng: Engagement) -> dict:
    """What the console shows: the interval, when the next run is due and why a due run waits."""
    nxt = next_run_at(eng)
    return {
        "every_days": eng.schedule_every_days,
        "next_run_at": nxt.isoformat() if nxt else None,
        "set_at": eng.schedule_set_at.isoformat() if eng.schedule_set_at else None,
        "skip_reason": eng.schedule_skip_reason,
        "skip_message": reason_text(eng.schedule_skip_reason),
        "skip_since": eng.schedule_skip_since.isoformat() if eng.schedule_skip_since else None,
        "min_days": MIN_DAYS,
        "max_days": MAX_DAYS,
    }


# ------------------------------------------------------------------ setting


def set_interval(db: Session, eng: Engagement, every_days: int | None, *, actor: str, now: dt.datetime | None = None) -> None:
    """REQ-MON-001: set, change or clear (None) the interval. Audited. The caller has checked
    that the actor may change the engagement."""
    now = now or _now()
    if eng.operating_mode != "monitoring":
        raise ScheduleError(409, "automatic runs are set on monitoring engagements; this engagement is an assessment")
    if eng.status in ("completed", "revoked"):
        raise ScheduleError(409, f"engagement is {eng.status}")
    if every_days is not None and not (MIN_DAYS <= int(every_days) <= MAX_DAYS):
        raise ScheduleError(422, f"the interval must be between {MIN_DAYS} and {MAX_DAYS} days")

    before = eng.schedule_every_days
    if every_days == before:
        return
    if every_days is None:
        eng.schedule_every_days = None
        eng.schedule_set_at = None
        eng.schedule_anchor_at = None
        eng.schedule_skip_reason = None
        eng.schedule_skip_since = None
        monitoring.resolve_inbox_items(db, eng.id, BLOCKED_ITEM_KEY, by=actor)
    else:
        eng.schedule_every_days = int(every_days)
        eng.schedule_set_at = now
        # Setting an interval never starts a run at once: the count starts now (REQ-MON-001).
        eng.schedule_anchor_at = now
        eng.schedule_skip_reason = None
        eng.schedule_skip_since = None
    append_audit_log(
        db, engagement_id=eng.id, actor=actor, action="monitoring_schedule_updated", decision="ALLOW",
        reason="operator_set", payload={"from": before, "to": eng.schedule_every_days, "engagement_status": eng.status},
    )
    db.commit()


def restart_count(eng: Engagement, now: dt.datetime | None = None) -> None:
    """The count starts again at `now`: a run started, or the engagement became active.
    Does not commit; the caller's transaction does."""
    if eng.schedule_every_days is not None:
        eng.schedule_anchor_at = now or _now()
        eng.schedule_skip_reason = None
        eng.schedule_skip_since = None


# --------------------------------------------------------------------- tick


def _is_due(eng: Engagement, now: dt.datetime) -> bool:
    nxt = next_run_at(eng)
    return nxt is not None and nxt <= now


def _active_run_exists(db: Session, engagement_id: uuid.UUID) -> bool:
    return db.scalar(
        select(ScanRun.id).where(ScanRun.engagement_id == engagement_id, ScanRun.state.in_(ACTIVE_RUN_STATES)).limit(1)
    ) is not None


def _scheduled_runs_active(db: Session) -> int:
    return int(db.scalar(
        select(func.count()).select_from(ScanRun).where(
            ScanRun.trigger == "scheduled", ScanRun.state.in_(ACTIVE_RUN_STATES)
        )
    ) or 0)


def _blocking_reason(db: Session, eng: Engagement, now: dt.datetime) -> str | None:
    """The first rule that forbids a start, cheapest first; None means "go and try"."""
    if eng.status != "active":
        return f"engagement_{eng.status}"
    if not (eng.authorized_from and eng.authorized_until and eng.authorized_from <= now <= eng.authorized_until):
        return "outside_authorized_window"
    if eng.review_at is not None and now > eng.review_at:
        return "authorization_review_due"
    if _active_run_exists(db, eng.id):
        return "a_run_is_active"
    if _scheduled_runs_active(db) >= max_concurrent_runs():
        return "waiting_for_capacity"
    return None


def _record_skip(db: Session, eng: Engagement, reason: str, now: dt.datetime) -> bool:
    """Store why a due run waits. Audited only when the reason changes."""
    if eng.schedule_skip_reason == reason:
        return False
    eng.schedule_skip_reason = reason
    eng.schedule_skip_since = now
    append_audit_log(
        db, engagement_id=eng.id, actor="schedule", action="scheduled_run_skipped", decision="DENY",
        reason=reason, payload={"every_days": eng.schedule_every_days, "due_at": (next_run_at(eng) or now).isoformat()},
    )
    return True


def _raise_blocked(db: Session, eng: Engagement, reason: str) -> None:
    """A reason that needs a person (the schedule is stuck, not just waiting its turn)."""
    text = reason_text(reason) or reason
    created = monitoring.open_inbox_item(
        db, eng.id, "schedule_blocked", BLOCKED_ITEM_KEY,
        f"{eng.title}: the scheduled run did not start. {text}", {"reason": reason},
    )
    if created is not None:
        monitoring.queue_alert(db, eng, "schedule_stopped", f"{eng.title}: scheduled run did not start ({reason})", tab="runs")


# Reasons that wait for a person rather than for time.
_NEEDS_A_PERSON = ("outside_authorized_window", "authorization_review_due")


def run_due(db: Session, now: dt.datetime | None = None, enqueue=None) -> dict:
    """One tick (REQ-MON-003). Safe to call as often as you like and from several places at once."""
    now = now or _now()
    result = {"due": 0, "started": 0, "waiting": 0}
    candidates = db.scalars(
        select(Engagement.id).where(
            Engagement.operating_mode == "monitoring",
            Engagement.schedule_every_days.is_not(None),
            Engagement.schedule_anchor_at.is_not(None),
        ).order_by(Engagement.schedule_anchor_at)
    ).all()
    for engagement_id in candidates:
        # Own lock per engagement: a second tick (or a manual start) that holds it is skipped.
        eng = db.scalar(
            select(Engagement).where(Engagement.id == engagement_id).with_for_update(skip_locked=True)
        )
        if eng is None or not _is_due(eng, now):
            db.rollback()
            continue
        result["due"] += 1
        reason = _blocking_reason(db, eng, now)
        if reason is None:
            try:
                operating_modes.begin_scan(
                    db, eng.id, trigger="scheduled", initiated_by=f"schedule:every-{eng.schedule_every_days}-days",
                    enqueue=enqueue,
                )
            except operating_modes.ScanNotStartable as exc:
                db.rollback()
                eng = db.get(Engagement, engagement_id)
                reason = _reason_from(exc)
            else:
                eng = db.get(Engagement, engagement_id)
                monitoring.resolve_inbox_items(db, eng.id, BLOCKED_ITEM_KEY, by="schedule")
                db.commit()
                result["started"] += 1
                continue
        changed = _record_skip(db, eng, reason, now)
        if changed and (reason in _NEEDS_A_PERSON or reason.startswith("not_ready")):
            _raise_blocked(db, eng, reason)
        db.commit()
        result["waiting"] += 1
    return result


def _reason_from(exc: operating_modes.ScanNotStartable) -> str:
    detail = exc.detail
    if isinstance(detail, dict) and detail.get("error") == "engagement_not_scan_ready":
        codes = ",".join(str(b.get("code")) for b in detail.get("blockers", []))[:180]
        return f"not_ready:{codes}" if codes else "not_ready"
    if isinstance(detail, str) and "active scan_run" in detail:
        return "a_run_is_active"
    return f"not_started:{exc.status}"
