"""REQ-AGENT-027: the public, deliberately-unauthenticated OpenWire probe
callback receiver.

This endpoint is fetched by a PROBED TARGET, never by an operator or the
worker - it cannot require any of this platform's own authentication, by
definition. It is intentionally minimal: check the token, mark it triggered,
serve static inert content. Nothing about the calling request (headers,
source IP, body) is read or stored - the caller is by definition untrusted,
and potentially the very host we just proved is compromised.
"""

from __future__ import annotations

import datetime

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.models.openwire_callback import OpenwireCallbackToken

router = APIRouter(tags=["openwire-callback"])

# A syntactically valid, functionally empty Spring bean definition. Serving
# THIS (rather than an error page, or nothing) is what lets
# FileSystemXmlApplicationContext's fetch complete cleanly - but it defines
# no bean, so there is nothing for the target to instantiate or execute even
# if it tried. The mere act of fetching this URL at all is already the
# proof (REQ-AGENT-027) - no second-stage payload is ever served.
_INERT_SPRING_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<beans xmlns="http://www.springframework.org/schema/beans"></beans>\n'
)


def _not_found() -> Response:
    # Indistinguishable from any other 404 - must not leak whether a token
    # was ever valid, is still pending, or belongs to a real engagement.
    return Response(status_code=404, content="Not Found")


@router.get("/callback/openwire/{token}")
def openwire_callback(token: str, db: Session = Depends(get_db)) -> Response:
    row = db.get(OpenwireCallbackToken, token)
    now = datetime.datetime.now(datetime.timezone.utc)
    if row is None:
        return _not_found()
    expires_at = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=datetime.timezone.utc)
    if expires_at < now:
        return _not_found()
    # Single-use: a repeat fetch of an already-triggered token is treated
    # exactly like an unknown one - the first hit is already the proof, and
    # not distinguishing further prevents a token from being usable as a
    # standing, replayable probe of our own infrastructure.
    if row.triggered_at is not None:
        return _not_found()
    row.triggered_at = now
    db.commit()
    return Response(status_code=200, content=_INERT_SPRING_XML, media_type="text/xml")
