"""Crawled endpoints and web screenshots of one engagement (REQ-COVER-003/006).

Mounted under /engagements in the public router, so ownership of the
engagement in the path is enforced router-wide (enforce_engagement_ownership).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.models.discovery_artifacts import DiscoveredEndpoint, WebScreenshot

router = APIRouter(prefix="/engagements", tags=["discovery"])

_MAX_LIST = 1000


@router.get("/{engagement_id}/endpoints")
def list_endpoints(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    rows = db.scalars(
        select(DiscoveredEndpoint)
        .where(DiscoveredEndpoint.engagement_id == engagement_id)
        .order_by(DiscoveredEndpoint.host, DiscoveredEndpoint.url)
        .limit(_MAX_LIST)
    ).all()
    return [
        {"id": str(r.id), "url": r.url, "host": r.host, "port": r.port, "method": r.method,
         "source": r.source, "param_names": list(r.param_names or []),
         "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None}
        for r in rows
    ]


@router.get("/{engagement_id}/screenshots")
def list_screenshots(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    rows = db.scalars(
        select(WebScreenshot)
        .where(WebScreenshot.engagement_id == engagement_id)
        .order_by(WebScreenshot.host, WebScreenshot.port)
        .limit(_MAX_LIST)
    ).all()
    return [
        {"id": str(r.id), "url": r.url, "host": r.host, "port": r.port, "byte_size": r.byte_size,
         "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in rows
    ]


@router.get("/{engagement_id}/screenshots/{screenshot_id}/image")
def screenshot_image(engagement_id: uuid.UUID, screenshot_id: uuid.UUID, db: Session = Depends(get_db)):
    shot = db.get(WebScreenshot, screenshot_id)
    # The row's own engagement is compared, so an id from another engagement
    # is a 404 here even when the caller owns this one.
    if shot is None or shot.engagement_id != engagement_id or not shot.content:
        raise HTTPException(404, "screenshot not found")
    return Response(
        content=bytes(shot.content),
        media_type="image/png",
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store"},
    )
