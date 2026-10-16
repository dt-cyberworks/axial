"""Worker-facing endpoints of the outbound e-mail service (REQ-MAIL-003). Internal
token only: the relay password and the message bodies travel here and nowhere else."""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import mail_settings, mailer
from app.api.internal import require_internal_token
from app.db.base import get_db
from app.models.mail import MailOutbox
from app.settings_store import SettingsCipherUnavailable, _decrypt_api_key

router = APIRouter(prefix="/internal/mail", tags=["internal"], dependencies=[Depends(require_internal_token)])

BATCH = 10
EXPIRE_AFTER = dt.timedelta(hours=24)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


@router.get("/due")
def due_messages(db: Session = Depends(get_db)):
    """Messages whose time has come, with the relay settings. Empty when mail is not
    available; a message that waited a day without a configured relay fails."""
    cutoff = _now() - EXPIRE_AFTER
    for stale in db.scalars(select(MailOutbox).where(MailOutbox.state == "pending", MailOutbox.created_at < cutoff)):
        stale.state, stale.last_error, stale.body_enc = "failed", "expired_before_delivery", None
    db.commit()
    try:
        relay = mail_settings.relay_credentials(db)
    except SettingsCipherUnavailable:
        return {"relay": None, "messages": [], "error": "secret_unreadable"}
    if relay is None:
        return {"relay": None, "messages": []}
    rows = db.scalars(
        select(MailOutbox).where(MailOutbox.state == "pending", MailOutbox.next_attempt_at <= _now())
        .order_by(MailOutbox.next_attempt_at).limit(BATCH)
    ).all()
    messages = []
    for row in rows:
        try:
            body = _decrypt_api_key(row.body_enc) if row.body_enc else ""
        except SettingsCipherUnavailable:
            continue
        messages.append({"id": str(row.id), "to": row.to_address, "subject": row.subject, "body": body,
                         "attempts": row.attempts})
    return {"relay": relay, "messages": messages}


class ResultIn(BaseModel):
    delivered: bool
    error: str | None = None


@router.post("/{message_id}/result")
def message_result(message_id: uuid.UUID, body: ResultIn, db: Session = Depends(get_db)):
    row = db.get(MailOutbox, message_id)
    if row is None:
        raise HTTPException(404, "message not found")
    if row.state != "pending":
        return {"id": str(row.id), "state": row.state}
    row.attempts += 1
    if body.delivered:
        row.state, row.delivered_at, row.last_error, row.body_enc = "delivered", _now(), None, None
    else:
        row.last_error = (body.error or "delivery_failed")[:300]
        if row.attempts >= mailer.MAX_ATTEMPTS:
            row.state, row.body_enc = "failed", None
        else:
            row.next_attempt_at = _now() + dt.timedelta(seconds=mailer.BACKOFF_SECONDS[row.attempts - 1])
    db.commit()
    return {"id": str(row.id), "state": row.state, "attempts": row.attempts}
