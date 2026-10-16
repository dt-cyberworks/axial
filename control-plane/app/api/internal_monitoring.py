"""Worker-facing endpoints of the monitoring mode (internal token only).

The worker never writes the database; everything it learns about a run's mode,
the hold policy, suggestions, withdrawn approvals and alert delivery goes
through here, where the control plane decides.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import monitoring, scheduling
from app.api.internal import require_internal_token
from app.db.base import get_db
from app.gateway.audit import append_audit_log
from app.models.approval import ApprovalRequest
from app.models.monitoring import AlertEvent, NotificationTarget
from app.models.scan_run import ScanRun
from app.settings_store import SettingsCipherUnavailable, _decrypt_api_key
from app.webhook_guard import WebhookTargetRefused, validate_webhook_url

router = APIRouter(prefix="/internal", tags=["internal"], dependencies=[Depends(require_internal_token)])

MAX_ATTEMPTS = 6
BACKOFF_MINUTES = (1, 5, 15, 60, 240, 720)


class HoldCandidate(BaseModel):
    asset_id: str
    value: str | None = None


class HoldIn(BaseModel):
    candidates: list[HoldCandidate]


@router.post("/scan-runs/{scan_run_id}/hold")
def evaluate_hold(scan_run_id: uuid.UUID, body: HoldIn, db: Session = Depends(get_db)):
    """REQ-MODE-008: which discovered hosts are tested in this run, which are held."""
    run = db.get(ScanRun, scan_run_id)
    if run is None:
        raise HTTPException(404, "scan_run not found")
    return monitoring.evaluate_hold(db, run, [c.model_dump() for c in body.candidates])


class SuggestionIn(BaseModel):
    tool: str
    target: str
    rationale: str = ""


@router.post("/engagements/{engagement_id}/suggestions", status_code=201)
def add_suggestion(engagement_id: uuid.UUID, body: SuggestionIn, db: Session = Depends(get_db)):
    """REQ-MODE-007: a proposal an unattended run could not get a decision for."""
    item = monitoring.add_suggestion(db, engagement_id, body.tool[:60], body.target[:253], body.rationale)
    db.commit()
    return {"created": item is not None}


class WithdrawIn(BaseModel):
    reason: str = "unattended_run"


@router.post("/approvals/{approval_id}/withdraw")
def withdraw_approval(approval_id: uuid.UUID, body: WithdrawIn, db: Session = Depends(get_db)):
    """The worker will not wait for this approval (an unattended run): close it so no
    popup is left for a decision nothing would act on. Only a `requested` approval
    can be withdrawn; an approved one stays claimable."""
    ap = db.scalar(select(ApprovalRequest).where(ApprovalRequest.id == approval_id).with_for_update())
    if ap is None:
        raise HTTPException(404, "approval not found")
    if ap.state != "requested":
        return {"id": str(ap.id), "state": ap.state, "withdrawn": False}
    ap.state = "cancelled"
    ap.execution_finished_at = dt.datetime.now(dt.timezone.utc)
    ap.execution_error = f"withdrawn:{body.reason}"[:500]
    append_audit_log(
        db, engagement_id=ap.engagement_id, actor="worker", action="approval_withdrawn", decision="DENY",
        reason=body.reason, payload={"approval_id": str(ap.id), "scan_run_id": (ap.tool_call or {}).get("scan_run_id")},
    )
    return {"id": str(ap.id), "state": ap.state, "withdrawn": True}


@router.post("/monitoring/housekeeping")
def housekeeping(db: Session = Depends(get_db)):
    """Missed-run and authorization-review checks (REQ-MODE-012)."""
    return monitoring.housekeeping(db)


@router.post("/monitoring/run-due-schedules")
def run_due_schedules(db: Session = Depends(get_db)):
    """One scheduler tick (REQ-MON-003): start the runs that are due and allowed, record why
    the others wait. The worker only calls this; the control plane decides."""
    return scheduling.run_due(db)


# ----------------------------------------------------------------- alerts


@router.get("/alerts/due")
def due_alerts(db: Session = Depends(get_db), limit: int = 50):
    """Alerts whose time has come, with what the sender needs. The signing secret is
    decrypted here and travels only on this token-protected route."""
    now = dt.datetime.now(dt.timezone.utc)
    rows = db.scalars(
        select(AlertEvent).where(
            AlertEvent.state == "pending", AlertEvent.deliver_after <= now,
            (AlertEvent.next_attempt_at.is_(None)) | (AlertEvent.next_attempt_at <= now),
        ).order_by(AlertEvent.deliver_after).limit(min(max(limit, 1), 200))
    ).all()
    out = []
    for row in rows:
        target = db.get(NotificationTarget, row.target_id)
        if target is None or not target.enabled:
            row.state = "failed"
            row.last_error = "target_removed_or_disabled"
            continue
        try:
            secret = _decrypt_api_key(target.secret_enc) if target.secret_enc else None
        except SettingsCipherUnavailable:
            row.attempts += 1
            row.last_error = "secret_unreadable"
            row.next_attempt_at = now + dt.timedelta(minutes=BACKOFF_MINUTES[min(row.attempts, len(BACKOFF_MINUTES)) - 1])
            continue
        try:
            validate_webhook_url(target.url)
        except WebhookTargetRefused as exc:
            row.state = "failed"
            row.last_error = f"target_refused:{exc}"[:300]
            continue
        out.append({
            "id": str(row.id), "event": row.event_kind, "payload": row.payload, "url": target.url, "secret": secret,
            "attempts": row.attempts, "immediate": row.immediate,
        })
    db.commit()
    return out


class AlertResultIn(BaseModel):
    delivered: bool
    error: str | None = None


@router.post("/alerts/{alert_id}/result")
def alert_result(alert_id: uuid.UUID, body: AlertResultIn, db: Session = Depends(get_db)):
    row = db.get(AlertEvent, alert_id)
    if row is None:
        raise HTTPException(404, "alert not found")
    now = dt.datetime.now(dt.timezone.utc)
    row.attempts += 1
    if body.delivered:
        row.state = "delivered"
        row.delivered_at = now
        row.last_error = None
        row.next_attempt_at = None
    else:
        row.last_error = (body.error or "delivery_failed")[:300]
        if row.attempts >= MAX_ATTEMPTS:
            row.state = "failed"
        else:
            row.next_attempt_at = now + dt.timedelta(minutes=BACKOFF_MINUTES[row.attempts - 1])
    db.commit()
    return {"id": str(row.id), "state": row.state, "attempts": row.attempts}
