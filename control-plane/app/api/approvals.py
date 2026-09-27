import datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.gateway.audit import append_audit_log
from app.models.approval import ApprovalRequest
from app.models.engagement import Engagement
from app.models.user import User
from app.schemas.approval import ApprovalDecision, ApprovalOut
from app.security import require_user

router = APIRouter(prefix="/approvals", tags=["approvals"])


def _require_engagement_owner(db: Session, engagement_id: uuid.UUID, user: User) -> None:
    """approvals.py routes key on approval_id, not engagement_id, so the
    router-wide path-param ownership check (enforce_engagement_ownership)
    doesn't see them - enforced explicitly here instead (REQ-IAM-007)."""
    if user.role == "admin":
        return
    eng = db.get(Engagement, engagement_id)
    if eng is None or eng.owner_user_id != user.id:
        raise HTTPException(404, "approval not found")


@router.get("", response_model=list[ApprovalOut])
def list_approvals(
    state: str = Query(default="requested"), user: User = Depends(require_user), db: Session = Depends(get_db),
):
    """Operator-Queue (UI Kap. 3.2): bleibt meist leer, fuellt sich nur bei
    requires_manual_approval=true (cred/exploit) oder Scope-Grenzfaellen.
    REQ-IAM-007: scoped to the caller's own engagements unless admin."""
    stmt = select(ApprovalRequest).where(ApprovalRequest.state == state)
    if user.role != "admin":
        stmt = stmt.join(Engagement, Engagement.id == ApprovalRequest.engagement_id).where(
            Engagement.owner_user_id == user.id
        )
    return db.scalars(stmt).all()


def _get_pending_or_404(db: Session, approval_id: uuid.UUID) -> ApprovalRequest:
    approval = db.get(ApprovalRequest, approval_id)
    if approval is None:
        raise HTTPException(404, "approval not found")
    if approval.state != "requested":
        raise HTTPException(409, f"approval already in state '{approval.state}'")
    if approval.expires_at < datetime.datetime.now(datetime.timezone.utc):
        approval.state = "expired"
        db.commit()
        raise HTTPException(409, "approval expired")
    return approval


@router.post("/{approval_id}/approve", response_model=ApprovalOut)
def approve(
    approval_id: uuid.UUID, body: ApprovalDecision,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """Einmalige, ablaufende Freigabe (Architektur Listing 5): requested -> approved.

    Die eigentliche Ausfuehrung (approved -> consumed) erfolgt durch den
    MCP-Runner im Worker, der genau diesen einen Tool-Call konsumiert.
    """
    approval = _get_pending_or_404(db, approval_id)
    _require_engagement_owner(db, approval.engagement_id, user)
    approval.state = "approved"
    approval.approved_by = user.email
    approval.approved_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(approval)
    append_audit_log(
        db, engagement_id=approval.engagement_id, actor=f"user:{user.email}",
        action="approval", decision="ALLOW", reason="manual_approval",
        # scan_run_id is hoisted to the top level (it already lives nested in
        # tool_call) so the run-activity stream can tag-match this row
        # directly instead of relying on its time-window fallback.
        payload={
            "approval_id": str(approval.id), "tool_call": approval.tool_call,
            "scan_run_id": approval.tool_call.get("scan_run_id"),
        },
    )
    return approval


@router.post("/{approval_id}/reject", response_model=ApprovalOut)
def reject(
    approval_id: uuid.UUID, body: ApprovalDecision,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    approval = _get_pending_or_404(db, approval_id)
    _require_engagement_owner(db, approval.engagement_id, user)
    approval.state = "rejected"
    approval.approved_by = user.email
    approval.approved_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(approval)
    append_audit_log(
        db, engagement_id=approval.engagement_id, actor=f"user:{user.email}",
        action="approval", decision="DENY", reason="manual_rejection",
        payload={
            "approval_id": str(approval.id), "tool_call": approval.tool_call,
            "scan_run_id": approval.tool_call.get("scan_run_id"),
        },
    )
    return approval
