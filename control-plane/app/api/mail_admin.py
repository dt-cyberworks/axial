"""Administrator's mail settings (REQ-MAIL-002/004). Included next to the other
/settings routers, behind the administrator role."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import mail_settings, mailer
from app.db.base import get_db
from app.models.mail import MailOutbox
from app.models.user import User
from app.security import require_user
from app.settings_store import SettingsCipherUnavailable

router = APIRouter(prefix="/settings/mail", tags=["settings"])

TEST_LIMIT_PER_HOUR = 5


class MailConfigOut(BaseModel):
    enabled: bool
    host: str
    port: int
    security: str
    username: str
    password_set: bool
    from_address: str
    from_name: str
    available: bool
    last_test: dict | None = None


class MailConfigIn(BaseModel):
    enabled: bool = False
    host: str = Field(default="", max_length=253)
    port: int = Field(default=587, ge=1, le=65535)
    security: str = "starttls"
    username: str = Field(default="", max_length=200)
    # Write-only. Empty keeps the stored password.
    password: str | None = Field(default=None, max_length=1024)
    from_address: str = Field(default="", max_length=254)
    from_name: str = Field(default="", max_length=100)


def _out(db: Session) -> MailConfigOut:
    cfg = mail_settings.get_mail_config(db)
    last = db.scalar(select(MailOutbox).where(MailOutbox.kind == "test").order_by(MailOutbox.created_at.desc()).limit(1))
    return MailConfigOut(
        **cfg.__dict__, available=mail_settings.is_available(db),
        last_test=None if last is None else {
            "state": last.state, "attempts": last.attempts, "error": last.last_error,
            "at": last.created_at.isoformat(),
        },
    )


@router.get("", response_model=MailConfigOut)
def read_mail_config(db: Session = Depends(get_db)):
    return _out(db)


@router.put("", response_model=MailConfigOut)
def update_mail_config(body: MailConfigIn, db: Session = Depends(get_db)):
    try:
        mail_settings.set_mail_config(
            db, enabled=body.enabled, host=body.host, port=body.port, security=body.security, username=body.username,
            password=body.password, from_address=body.from_address, from_name=body.from_name,
        )
    except mail_settings.MailConfigError as exc:
        raise HTTPException(422, str(exc)) from None
    except SettingsCipherUnavailable as exc:
        raise HTTPException(503, str(exc)) from None
    return _out(db)


@router.post("/test", response_model=MailConfigOut, status_code=202)
def send_test_message(user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Queues one message to the caller's own address, so the relay can be proven
    without typing a recipient."""
    if not mail_settings.is_available(db):
        raise HTTPException(409, "e-mail is not configured or not switched on")
    if mailer.recent_count(db, kind="test", requested_by=user.id) >= TEST_LIMIT_PER_HOUR:
        raise HTTPException(429, "too many test messages; try again later")
    subject, body = mailer.diagnostic_message()
    try:
        mailer.enqueue(db, kind="test", to=user.email, subject=subject, body=body, requested_by=user.id)
    except SettingsCipherUnavailable as exc:
        raise HTTPException(503, str(exc)) from None
    db.commit()
    return _out(db)
