"""Queueing a message (REQ-MAIL-003/005).

The control plane has no route to the internet by design, so it never sends: it
writes a row, and the worker, which already has the network path alerts use,
delivers it. The body is encrypted at rest and removed once delivered, because the
password-reset message carries a secret link.

Templates are fixed plain text. Nothing here ever logs a recipient, a subject or a
body.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import mail_settings
from app.models.mail import MailOutbox
from app.settings_store import _encrypt_api_key

MAX_ATTEMPTS = 6
BACKOFF_SECONDS = (30, 120, 600, 1800, 7200, 14400)


class MailNotAvailable(RuntimeError):
    """Mail is not configured or not switched on."""


def _line(value: str, field: str) -> str:
    if any(ch in value for ch in "\r\n\x00"):
        raise ValueError(f"{field} must be one line")
    return value.strip()


def enqueue(
    db: Session, *, kind: str, to: str, subject: str, body: str, requested_by: uuid.UUID | None = None,
    require_available: bool = True,
) -> MailOutbox:
    """Adds one message to the outbox (committed by the caller)."""
    if require_available and not mail_settings.is_available(db):
        raise MailNotAvailable("e-mail is not configured")
    address = _line(to, "recipient")
    if not mail_settings.valid_address(address):
        raise ValueError("recipient is not a plain e-mail address")
    row = MailOutbox(
        kind=kind, to_address=address, subject=_line(subject, "subject")[:200], body_enc=_encrypt_api_key(body),
        requested_by=requested_by, next_attempt_at=dt.datetime.now(dt.timezone.utc),
    )
    db.add(row)
    db.flush()
    return row


def recent_count(db: Session, *, kind: str, requested_by: uuid.UUID, minutes: int = 60) -> int:
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)
    return db.scalar(
        select(func.count()).select_from(MailOutbox).where(
            MailOutbox.kind == kind, MailOutbox.requested_by == requested_by, MailOutbox.created_at >= since
        )
    ) or 0


def password_reset_message(link: str, minutes: int) -> tuple[str, str]:
    subject = "Reset your Axial password"
    body = (
        "Someone asked to reset the password of your Axial account.\n\n"
        "To choose a new password, open this link and enter a code from your authenticator app:\n\n"
        f"{link}\n\n"
        f"The link works once and expires in {minutes} minutes. If you did not ask for this, ignore this "
        "message: your password stays as it is.\n"
    )
    return subject, body


def diagnostic_message() -> tuple[str, str]:
    return (
        "Axial e-mail test",
        "This is a test message from your Axial installation. If you can read it, outbound e-mail works.\n",
    )
