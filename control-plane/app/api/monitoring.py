"""Monitoring-mode API: capabilities, the change feed, the inbox, notification
targets and the monitoring defaults (REQ-MODE-006, -013, -014, REQ-MON-002).

Engagement-scoped routes live under /engagements/{id}/..., so the router-wide
access rule applies unchanged: every signed-in user reads, only the owner or an
administrator changes.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import capabilities, monitoring, monitoring_settings, scheduling
from app.db.base import get_db
from app.gateway.audit import append_audit_log
from app.models.approval import ApprovalRequest
from app.models.asset_review import AssetReviewRequest
from app.models.engagement import Engagement
from app.models.monitoring import AlertEvent, ChangeEvent, InboxItem, NotificationTarget
from app.models.scan_run import ScanRun
from app.models.user import User
from app.schemas.engagement import (
    CapabilitiesIn,
    CapabilitiesOut,
    NotificationTargetIn,
    NotificationTargetOut,
)
from app.security import NOT_OWNER_DETAIL, can_manage_engagement, require_user
from app.settings_store import SettingsCipherUnavailable, _encrypt_api_key
from app.webhook_guard import WebhookTargetRefused, validate_webhook_url

router = APIRouter(prefix="/engagements", tags=["monitoring"])
inbox_router = APIRouter(prefix="/inbox", tags=["monitoring"])
settings_router = APIRouter(prefix="/settings/monitoring-defaults", tags=["settings"])

_DEPTH_ORDER = {"passive": 0, "light": 1, "standard": 2, "thorough": 3}
_ACTIVE = ("running", "waiting_approval")


def _engagement(db: Session, engagement_id: uuid.UUID) -> Engagement:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(404, "engagement not found")
    return eng


# ----------------------------------------------------------------- capabilities


def _capabilities_out(db: Session, eng: Engagement) -> CapabilitiesOut:
    return CapabilitiesOut(
        operating_mode=eng.operating_mode, scan_profile=eng.scan_profile, new_asset_policy=eng.new_asset_policy,
        fragility_breaker=bool(eng.fragility_breaker), capabilities=capabilities.view(db, eng),
    )


@router.get("/{engagement_id}/capabilities", response_model=CapabilitiesOut)
def get_capabilities(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    return _capabilities_out(db, _engagement(db, engagement_id))


@router.put("/{engagement_id}/capabilities", response_model=CapabilitiesOut)
def put_capabilities(
    engagement_id: uuid.UUID, body: CapabilitiesIn,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """REQ-MODE-006: one transaction, one audit row. A change holds for every run."""
    eng = _engagement(db, engagement_id)
    if eng.operating_mode != "monitoring":
        raise HTTPException(409, "capabilities are set on monitoring engagements; this engagement is an assessment")
    if eng.status in ("completed", "revoked"):
        raise HTTPException(409, f"engagement is {eng.status}")

    changes = dict(body.capabilities)
    widening = capabilities.widens(db, eng, changes)
    if body.scan_profile is not None and _DEPTH_ORDER[body.scan_profile] > _DEPTH_ORDER.get(eng.scan_profile, 2):
        widening = True
    if body.new_asset_policy == "auto" and eng.new_asset_policy == "hold":
        widening = True
    if widening and eng.status != "draft":
        if db.scalar(select(ScanRun.id).where(ScanRun.engagement_id == eng.id, ScanRun.state.in_(_ACTIVE)).limit(1)):
            raise HTTPException(409, "scan_run_active: capabilities cannot be widened while a run is active")
        if not body.confirm_widening:
            raise HTTPException(
                409, "confirmation_required: this widens what the engagement does unattended; confirm to proceed"
            )

    before = {c["id"]: c["enabled"] for c in capabilities.view(db, eng)}
    try:
        applied = capabilities.apply(db, eng, changes)
    except capabilities.CapabilityError as exc:
        db.rollback()
        raise HTTPException(exc.status, exc.detail) from None
    fields: dict = {}
    if body.scan_profile is not None and body.scan_profile != eng.scan_profile:
        fields["scan_profile"] = {"from": eng.scan_profile, "to": body.scan_profile}
        eng.scan_profile = body.scan_profile
    if body.new_asset_policy is not None and body.new_asset_policy != eng.new_asset_policy:
        fields["new_asset_policy"] = {"from": eng.new_asset_policy, "to": body.new_asset_policy}
        eng.new_asset_policy = body.new_asset_policy
    if body.fragility_breaker is not None and body.fragility_breaker != bool(eng.fragility_breaker):
        fields["fragility_breaker"] = {"from": bool(eng.fragility_breaker), "to": body.fragility_breaker}
        eng.fragility_breaker = body.fragility_breaker

    if applied or fields:
        append_audit_log(
            db, engagement_id=eng.id, actor=f"user:{user.email}", action="capabilities_updated", decision="ALLOW",
            reason="widening_confirmed" if widening and eng.status != "draft" else "operator_set",
            payload={"capabilities": applied, "fields": fields, "before": before, "engagement_status": eng.status},
        )
    db.commit()
    db.refresh(eng)
    return _capabilities_out(db, eng)


# ------------------------------------------------------------------ change feed


@router.get("/{engagement_id}/changes")
def list_changes(
    engagement_id: uuid.UUID,
    run_id: uuid.UUID | None = Query(default=None),
    kind: str | None = Query(default=None, max_length=40),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    _engagement(db, engagement_id)
    stmt = select(ChangeEvent).where(ChangeEvent.engagement_id == engagement_id)
    if run_id is not None:
        stmt = stmt.where(ChangeEvent.scan_run_id == run_id)
    if kind:
        stmt = stmt.where(ChangeEvent.kind == kind)
    rows = db.scalars(stmt.order_by(ChangeEvent.created_at.desc(), ChangeEvent.id.desc()).limit(limit).offset(offset)).all()
    return [
        {
            "id": str(r.id), "kind": r.kind, "subject": r.subject, "severity": r.severity, "detail": r.detail,
            "scan_run_id": str(r.scan_run_id) if r.scan_run_id else None, "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/{engagement_id}/health")
def get_health(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """REQ-MODE-012: how healthy the monitor is, at a glance."""
    eng = _engagement(db, engagement_id)
    last_ok = db.scalar(
        select(ScanRun).where(ScanRun.engagement_id == eng.id, ScanRun.health == "ok")
        .order_by(ScanRun.finished_at.desc()).limit(1)
    )
    last = db.scalar(
        select(ScanRun).where(ScanRun.engagement_id == eng.id).order_by(ScanRun.started_at.desc()).limit(1)
    )
    open_items = db.scalars(
        select(InboxItem).where(InboxItem.engagement_id == eng.id, InboxItem.state == "open")
    ).all()
    return {
        "operating_mode": eng.operating_mode,
        "status": eng.status,
        "last_ok_run_at": last_ok.finished_at.isoformat() if last_ok and last_ok.finished_at else None,
        "last_run_health": last.health if last else None,
        "last_run_state": last.state if last else None,
        "review_at": eng.review_at.isoformat() if eng.review_at else None,
        "authorized_until": eng.authorized_until.isoformat() if eng.authorized_until else None,
        "open_inbox_items": len(open_items),
        "schedule": scheduling.view(eng),
    }


# ------------------------------------------------------------- automatic runs


class ScheduleIn(BaseModel):
    # null switches automatic runs off. Out-of-range values are a 422 (REQ-MON-001).
    every_days: int | None = Field(default=None, ge=scheduling.MIN_DAYS, le=scheduling.MAX_DAYS)


@router.get("/{engagement_id}/schedule")
def get_schedule(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """REQ-MON-004: the interval, when the next run is due, and why a due run waits."""
    return scheduling.view(_engagement(db, engagement_id))


@router.put("/{engagement_id}/schedule")
def put_schedule(
    engagement_id: uuid.UUID, body: ScheduleIn,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """REQ-MON-001: set, change or clear the interval. The owner/admin rule is the router-wide
    engagement access check (REQ-IAM-023); one audit row."""
    eng = _engagement(db, engagement_id)
    try:
        scheduling.set_interval(db, eng, body.every_days, actor=f"user:{user.email}")
    except scheduling.ScheduleError as exc:
        raise HTTPException(exc.status, exc.detail) from None
    db.refresh(eng)
    return scheduling.view(eng)


# -------------------------------------------------------- notification targets


def _target_out(t: NotificationTarget) -> NotificationTargetOut:
    return NotificationTargetOut(
        id=t.id, kind=t.kind, url=t.url, min_severity=t.min_severity, enabled=t.enabled,
        has_secret=bool(t.secret_enc), created_at=t.created_at,
    )


@router.get("/{engagement_id}/notification-targets", response_model=list[NotificationTargetOut])
def list_notification_targets(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    _engagement(db, engagement_id)
    rows = db.scalars(
        select(NotificationTarget).where(NotificationTarget.engagement_id == engagement_id)
        .order_by(NotificationTarget.created_at)
    ).all()
    return [_target_out(t) for t in rows]


@router.post("/{engagement_id}/notification-targets", response_model=NotificationTargetOut, status_code=201)
def create_notification_target(
    engagement_id: uuid.UUID, body: NotificationTargetIn,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    eng = _engagement(db, engagement_id)
    try:
        url = validate_webhook_url(body.url)
    except WebhookTargetRefused as exc:
        raise HTTPException(422, str(exc)) from None
    secret_enc = None
    if body.secret:
        try:
            secret_enc = _encrypt_api_key(body.secret)
        except SettingsCipherUnavailable as exc:
            raise HTTPException(503, str(exc)) from None
    target = NotificationTarget(
        engagement_id=eng.id, kind=body.kind, url=url, secret_enc=secret_enc,
        min_severity=body.min_severity, enabled=body.enabled, created_by=user.email,
    )
    db.add(target)
    db.flush()
    append_audit_log(
        db, engagement_id=eng.id, actor=f"user:{user.email}", action="notification_target_added", decision="ALLOW",
        reason="operator_added", payload={"target_id": str(target.id), "kind": target.kind, "has_secret": bool(secret_enc)},
    )
    db.commit()
    db.refresh(target)
    return _target_out(target)


@router.delete("/{engagement_id}/notification-targets/{target_id}", status_code=204)
def delete_notification_target(
    engagement_id: uuid.UUID, target_id: uuid.UUID,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    target = db.get(NotificationTarget, target_id)
    if target is None or target.engagement_id != engagement_id:
        raise HTTPException(404, "notification target not found")
    db.delete(target)
    append_audit_log(
        db, engagement_id=engagement_id, actor=f"user:{user.email}", action="notification_target_removed",
        decision="ALLOW", reason="operator_removed", payload={"target_id": str(target_id)},
    )
    db.commit()


@router.get("/{engagement_id}/alerts")
def list_alerts(engagement_id: uuid.UUID, limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db)):
    """Delivery state of what was sent (or is waiting), so a failure is visible."""
    _engagement(db, engagement_id)
    rows = db.scalars(
        select(AlertEvent).where(AlertEvent.engagement_id == engagement_id)
        .order_by(AlertEvent.created_at.desc()).limit(limit)
    ).all()
    return [
        {
            "id": str(r.id), "event": r.event_kind, "title": (r.payload or {}).get("title"), "state": r.state,
            "attempts": r.attempts, "immediate": r.immediate, "last_error": r.last_error,
            "created_at": r.created_at.isoformat(),
            "delivered_at": r.delivered_at.isoformat() if r.delivered_at else None,
        }
        for r in rows
    ]


# ------------------------------------------------------------------------ inbox


class InboxEntry(BaseModel):
    id: str
    source: str            # inbox | approval | asset_review
    kind: str
    engagement_id: str
    engagement_title: str
    summary: str
    created_at: str
    link: str
    can_acknowledge: bool


def _visible_engagements(db: Session, user: User) -> dict[uuid.UUID, Engagement]:
    stmt = select(Engagement)
    if user.role != "admin":
        stmt = stmt.where(Engagement.owner_user_id == user.id)
    return {e.id: e for e in db.scalars(stmt)}


@inbox_router.get("", response_model=list[InboxEntry])
def list_inbox(user: User = Depends(require_user), db: Session = Depends(get_db)):
    """REQ-MODE-014: everything that needs a person, in one list."""
    engagements = _visible_engagements(db, user)
    if not engagements:
        return []
    ids = list(engagements)
    out: list[InboxEntry] = []
    for item in db.scalars(
        select(InboxItem).where(InboxItem.engagement_id.in_(ids), InboxItem.state == "open")
        .order_by(InboxItem.created_at.desc())
    ):
        eng = engagements[item.engagement_id]
        out.append(InboxEntry(
            id=str(item.id), source="inbox", kind=item.kind, engagement_id=str(eng.id), engagement_title=eng.title,
            summary=item.summary, created_at=item.created_at.isoformat(),
            link=f"/engagements/{eng.id}", can_acknowledge=True,
        ))
    for ap in db.scalars(
        select(ApprovalRequest).where(ApprovalRequest.engagement_id.in_(ids), ApprovalRequest.state == "requested")
        .order_by(ApprovalRequest.expires_at)
    ):
        eng = engagements[ap.engagement_id]
        call = ap.tool_call or {}
        run_id = call.get("scan_run_id")
        out.append(InboxEntry(
            id=str(ap.id), source="approval", kind="approval", engagement_id=str(eng.id), engagement_title=eng.title,
            summary=f"Approval needed: {call.get('tool', 'tool call')} on {call.get('target', '?')}",
            created_at=(ap.expires_at or dt.datetime.now(dt.timezone.utc)).isoformat(),
            link=f"/engagements/{eng.id}/runs/{run_id}" if run_id else f"/engagements/{eng.id}",
            can_acknowledge=False,
        ))
    for rv in db.scalars(
        select(AssetReviewRequest).where(AssetReviewRequest.engagement_id.in_(ids), AssetReviewRequest.state == "pending")
    ):
        eng = engagements[rv.engagement_id]
        out.append(InboxEntry(
            id=str(rv.id), source="asset_review", kind="asset_review", engagement_id=str(eng.id),
            engagement_title=eng.title, summary="Discovered hosts wait for your review",
            created_at=rv.created_at.isoformat() if getattr(rv, "created_at", None) else dt.datetime.now(dt.timezone.utc).isoformat(),
            link=f"/engagements/{eng.id}/runs/{rv.scan_run_id}", can_acknowledge=False,
        ))
    return out


@inbox_router.get("/count")
def inbox_count(user: User = Depends(require_user), db: Session = Depends(get_db)):
    return {"count": len(list_inbox(user=user, db=db))}


@inbox_router.post("/{item_id}/acknowledge")
def acknowledge(item_id: uuid.UUID, user: User = Depends(require_user), db: Session = Depends(get_db)):
    item = db.get(InboxItem, item_id)
    if item is None:
        raise HTTPException(404, "inbox item not found")
    eng = db.get(Engagement, item.engagement_id)
    if eng is None or not can_manage_engagement(user, eng):
        raise HTTPException(403, NOT_OWNER_DETAIL)
    if item.state != "open":
        raise HTTPException(409, "inbox item is already resolved")
    released = None
    if item.kind == "held_asset":
        asset_id = (item.detail or {}).get("asset_id")
        if asset_id and monitoring.release_asset(db, eng.id, uuid.UUID(str(asset_id)), user.email):
            released = (item.detail or {}).get("value")
    item.state = "resolved"
    item.resolved_at = dt.datetime.now(dt.timezone.utc)
    item.resolved_by = user.email
    append_audit_log(
        db, engagement_id=eng.id, actor=f"user:{user.email}", action="inbox_acknowledged", decision="ALLOW",
        reason=item.kind, payload={"item_id": str(item.id), "released_asset": released},
    )
    db.commit()
    return {"id": str(item.id), "state": item.state, "released_asset": released}


@inbox_router.post("/release-held")
def release_all_held(
    engagement_id: uuid.UUID = Query(...), user: User = Depends(require_user), db: Session = Depends(get_db),
):
    eng = _engagement(db, engagement_id)
    if not can_manage_engagement(user, eng):
        raise HTTPException(403, NOT_OWNER_DETAIL)
    items = db.scalars(
        select(InboxItem).where(
            InboxItem.engagement_id == eng.id, InboxItem.kind == "held_asset", InboxItem.state == "open"
        )
    ).all()
    released = []
    for item in items:
        asset_id = (item.detail or {}).get("asset_id")
        if asset_id and monitoring.release_asset(db, eng.id, uuid.UUID(str(asset_id)), user.email):
            released.append((item.detail or {}).get("value"))
        item.state = "resolved"
        item.resolved_at = dt.datetime.now(dt.timezone.utc)
        item.resolved_by = user.email
    if items:
        append_audit_log(
            db, engagement_id=eng.id, actor=f"user:{user.email}", action="inbox_acknowledged", decision="ALLOW",
            reason="release_all_held", payload={"released_assets": released},
        )
    db.commit()
    return {"released": released}


# ------------------------------------------------------- monitoring defaults


class MonitoringDefaultsOut(BaseModel):
    capabilities: dict[str, bool]
    scan_profile: str
    new_asset_policy_customer: str
    new_asset_policy_other: str
    fragility_breaker: bool
    max_concurrent_monitoring_runs: int


class MonitoringDefaultsIn(BaseModel):
    capabilities: dict[str, bool] | None = None
    scan_profile: str | None = None
    new_asset_policy_customer: str | None = None
    new_asset_policy_other: str | None = None
    fragility_breaker: bool | None = None
    max_concurrent_monitoring_runs: int | None = None


def _defaults_out(db: Session) -> MonitoringDefaultsOut:
    return MonitoringDefaultsOut(
        **monitoring_settings.get_monitoring_defaults(db),
        max_concurrent_monitoring_runs=monitoring_settings.get_max_concurrent_monitoring_runs(db),
    )


@settings_router.get("", response_model=MonitoringDefaultsOut)
def read_monitoring_defaults(db: Session = Depends(get_db)):
    """What a NEW monitoring engagement starts with (copied at creation, REQ-MODE-006)."""
    return _defaults_out(db)


@settings_router.put("", response_model=MonitoringDefaultsOut)
def update_monitoring_defaults(body: MonitoringDefaultsIn, db: Session = Depends(get_db)):
    values = body.model_dump(exclude_none=True)
    concurrent = values.pop("max_concurrent_monitoring_runs", None)
    try:
        monitoring_settings.set_monitoring_defaults(db, values)
        if concurrent is not None:
            monitoring_settings.set_max_concurrent_monitoring_runs(db, concurrent)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return _defaults_out(db)
