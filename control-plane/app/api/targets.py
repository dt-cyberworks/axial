"""The target baseline of a monitoring engagement (REQ-BASE-001..005).

Reading is open to everyone who can see the engagement; starting a discovery and confirming the
targets are changes, so the router-wide owner/admin rule (REQ-IAM-023) answers 403 for anyone else.
"""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import targets
from app.db.base import get_db
from app.models.engagement import Engagement
from app.models.scan_run import ScanRun
from app.models.user import User
from app.security import require_user

router = APIRouter(prefix="/engagements", tags=["targets"])

MAX_SELECTED = 5000


def _engagement(db: Session, engagement_id: uuid.UUID) -> Engagement:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(404, "engagement not found")
    return eng


class CandidateOut(BaseModel):
    asset_id: uuid.UUID
    value: str
    addresses: list[str]
    provider: str | None
    dns_status: str
    discovered_via: str
    first_seen: str | None
    denied: bool
    is_root: bool
    flag: str
    suggested: bool
    held: bool = False


class BaselineRunOut(BaseModel):
    id: uuid.UUID
    state: str
    started_at: str | None
    finished_at: str | None
    state_reason: str | None


class TargetsOut(BaseModel):
    operating_mode: str
    state: str | None
    new_asset_policy: str
    confirmed_at: str | None
    confirmed_by: str | None
    baseline_run: BaselineRunOut | None
    candidates: list[CandidateOut]
    counts: dict[str, int]


class ConfirmIn(BaseModel):
    selected_asset_ids: list[uuid.UUID] = Field(default_factory=list, max_length=MAX_SELECTED)
    new_asset_policy: Literal["auto", "hold"] | None = None
    confirm_widening: bool = False


class ConfirmOut(BaseModel):
    state: str
    monitored: int
    excluded: int
    included: int
    released: int = 0
    new_asset_policy: str
    first_run_id: uuid.UUID | None = None
    first_run_error: object | None = None


class DiscoverOut(BaseModel):
    scan_run_id: uuid.UUID
    state: str | None


def _iso(value) -> str | None:
    return value.isoformat() if value else None


@router.get("/{engagement_id}/targets", response_model=TargetsOut)
def get_targets(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    eng = _engagement(db, engagement_id)
    targets.heal(db, eng)
    run = db.get(ScanRun, eng.target_review_run_id) if eng.target_review_run_id else None
    cand = targets.candidates(db, eng) if eng.operating_mode == "monitoring" else []
    counts = {"candidates": len(cand), "denied": 0, "held": 0, "same_address": 0, "other_address": 0, "unresolved": 0}
    for c in cand:
        counts["denied"] += int(c.denied)
        counts["held"] += int(c.held)
        counts[c.flag] += 1
    return TargetsOut(
        operating_mode=eng.operating_mode, state=eng.target_review_state, new_asset_policy=eng.new_asset_policy,
        confirmed_at=_iso(eng.targets_confirmed_at), confirmed_by=eng.targets_confirmed_by,
        baseline_run=None if run is None else BaselineRunOut(
            id=run.id, state=run.state, started_at=_iso(run.started_at), finished_at=_iso(run.finished_at),
            state_reason=run.state_reason,
        ),
        candidates=[
            CandidateOut(
                asset_id=c.asset_id, value=c.value, addresses=c.ips, provider=c.provider, dns_status=c.dns_status,
                discovered_via=c.discovered_via, first_seen=_iso(c.first_seen), denied=c.denied, is_root=c.is_root,
                flag=c.flag, suggested=c.suggested, held=c.held,
            ) for c in cand
        ],
        counts=counts,
    )


@router.post("/{engagement_id}/targets/discover", response_model=DiscoverOut, status_code=202)
def discover(engagement_id: uuid.UUID, user: User = Depends(require_user), db: Session = Depends(get_db)):
    """A passive discovery: public sources and DNS, nothing sent to the engagement's systems."""
    eng = _engagement(db, engagement_id)
    try:
        run = targets.start_discovery(db, eng, initiated_by=user.email)
    except targets.TargetsError as exc:
        raise HTTPException(exc.status, exc.detail) from None
    db.refresh(eng)
    return DiscoverOut(scan_run_id=run.id, state=eng.target_review_state)


@router.post("/{engagement_id}/targets/confirm", response_model=ConfirmOut)
def confirm(
    engagement_id: uuid.UUID, body: ConfirmIn, user: User = Depends(require_user), db: Session = Depends(get_db),
):
    eng = _engagement(db, engagement_id)
    try:
        result = targets.confirm(
            db, eng, selected_ids=body.selected_asset_ids, policy=body.new_asset_policy,
            actor_email=user.email, confirm_widening=body.confirm_widening,
        )
    except targets.TargetsError as exc:
        db.rollback()
        raise HTTPException(exc.status, exc.detail) from None
    db.refresh(eng)
    return ConfirmOut(
        state=eng.target_review_state or "confirmed", monitored=result.kept, excluded=result.excluded,
        included=result.included, released=result.released, new_asset_policy=result.policy, first_run_id=result.first_run_id,
        first_run_error=result.first_run_error,
    )
