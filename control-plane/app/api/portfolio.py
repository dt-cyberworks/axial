"""REQ-PORTFOLIO-001: findings across every engagement the caller can see.

Every other findings route carries an engagement_id in its path, where the
router-wide enforce_engagement_ownership check applies. This one does not, so
that check never runs here. The ownership rule (REQ-IAM-007: operators see
their own engagements, admins all) is therefore part of every query below -
never a filter over results - so totals and counts cannot leak other users'
data either.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.findings import _finding_out
from app.db.base import get_db
from app.models.asset import DiscoveredAsset
from app.models.engagement import Engagement
from app.models.finding import Finding, FindingObservation
from app.models.user import User
from app.schemas.finding import FINDING_STATUSES, SEVERITIES, FindingPage, PortfolioFindingOut
from app.security import require_user

router = APIRouter(prefix="/findings", tags=["findings"])


def _escape_like(text: str) -> str:
    """`q` is literal text: `%` and `_` must not act as LIKE wildcards."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("", response_model=FindingPage)
def list_all_findings(
    status: str = Query(default="open"),
    severity: str | None = Query(default=None),
    engagement_id: uuid.UUID | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if status not in FINDING_STATUSES:
        raise HTTPException(422, f"unknown status {status!r}")
    if severity is not None and severity not in SEVERITIES:
        raise HTTPException(422, f"unknown severity {severity!r}")

    # Filters shared by the page, the total, and both count groups.
    scope = []
    if user.role != "admin":
        scope.append(Engagement.owner_user_id == user.id)
    if engagement_id is not None:
        scope.append(Finding.engagement_id == engagement_id)
    text = (q or "").strip()
    if text:
        pattern = f"%{_escape_like(text)}%"
        scope.append(or_(Finding.title.ilike(pattern, escape="\\"), DiscoveredAsset.value.ilike(pattern, escape="\\")))
    by_status = Finding.status == status
    by_severity = [Finding.severity == severity] if severity else []

    def visible(stmt):
        return (
            stmt.select_from(Finding)
            .join(Engagement, Engagement.id == Finding.engagement_id)
            .outerjoin(DiscoveredAsset, DiscoveredAsset.id == Finding.asset_id)
            .where(*scope)
        )

    rows = db.scalars(
        visible(select(Finding))
        .where(by_status, *by_severity)
        # severity_level is a Postgres enum declared info..critical, so DESC puts critical first.
        .order_by(Finding.severity.desc().nulls_last(), Finding.risk_score.desc().nulls_last(),
                  Finding.first_seen.desc(), Finding.id)
        .limit(limit)
        .offset(offset)
    ).all()
    total = db.scalar(visible(select(func.count(Finding.id))).where(by_status, *by_severity)) or 0
    counts_by_status = {s: 0 for s in FINDING_STATUSES}
    counts_by_status.update(dict(db.execute(
        visible(select(Finding.status, func.count(Finding.id))).where(*by_severity).group_by(Finding.status)
    ).all()))
    counts_by_severity = {s: 0 for s in SEVERITIES}
    counts_by_severity.update({
        sev: count for sev, count in db.execute(
            visible(select(Finding.severity, func.count(Finding.id))).where(by_status).group_by(Finding.severity)
        ).all() if sev is not None
    })

    ids = [finding.id for finding in rows]
    titles = dict(db.execute(
        select(Engagement.id, Engagement.title).where(Engagement.id.in_({f.engagement_id for f in rows}))
    ).all()) if rows else {}
    last_seen = dict(db.execute(
        select(FindingObservation.finding_id, func.max(FindingObservation.observed_at))
        .where(FindingObservation.finding_id.in_(ids))
        .group_by(FindingObservation.finding_id)
    ).all()) if ids else {}

    items = [
        PortfolioFindingOut(
            **_finding_out(db, finding, last_seen.get(finding.id)).model_dump(),
            engagement_title=titles.get(finding.engagement_id, ""),
        )
        for finding in rows
    ]
    return FindingPage(
        items=items, total=total, limit=limit, offset=offset,
        counts_by_status=counts_by_status, counts_by_severity=counts_by_severity,
    )
