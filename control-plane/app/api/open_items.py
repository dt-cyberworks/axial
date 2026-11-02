"""What is still open, and the retest of a finding (REQ-RETEST-001/003/004).

Reading is open to everyone who can see the engagement; rejecting a held-back request changes something, so the
router-wide owner/admin rule (REQ-IAM-023) answers 403 for anyone else.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import open_items
from app.db.base import get_db
from app.models.engagement import Engagement
from app.models.finding import Finding
from app.models.user import User
from app.security import can_manage_engagement, require_user

router = APIRouter(prefix="/engagements", tags=["open-items"])


def _engagement(db: Session, engagement_id: uuid.UUID) -> Engagement:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(404, "engagement not found")
    return eng


@router.get("/{engagement_id}/open-items")
def get_open_items(engagement_id: uuid.UUID, user: User = Depends(require_user), db: Session = Depends(get_db)):
    """REQ-RETEST-003: the checks that are not settled and the requests a monitor held back. The body and the
    headers of a held-back request are shown only to the owner and administrators."""
    eng = _engagement(db, engagement_id)
    return open_items.list_open(db, eng, reveal=can_manage_engagement(user, eng))


@router.get("/{engagement_id}/findings/{finding_id}/retest-plan")
def get_retest_plan(engagement_id: uuid.UUID, finding_id: uuid.UUID, db: Session = Depends(get_db)):
    """REQ-RETEST-001: what a retest of this finding would run, before anything starts."""
    eng = _engagement(db, engagement_id)
    finding = db.get(Finding, finding_id)
    if finding is None or finding.engagement_id != eng.id:
        raise HTTPException(404, "finding not found for this engagement")
    return open_items.retest_plan_for_finding(db, eng, finding)


@router.post("/{engagement_id}/open-requests/{request_id}/reject")
def reject_open_request(
    engagement_id: uuid.UUID, request_id: uuid.UUID, user: User = Depends(require_user), db: Session = Depends(get_db),
):
    """The person says this held-back request is never to be sent."""
    eng = _engagement(db, engagement_id)
    try:
        row = open_items.reject_request(db, eng, request_id, user.email)
    except open_items.OpenRequestRefused as exc:
        raise HTTPException(exc.status, exc.detail) from None
    db.commit()
    return {"id": str(row.id), "state": row.state}
