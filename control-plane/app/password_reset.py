"""Self-service password reset (REQ-IAM-020, GitHub issue #44).

Proof of recovery is two things together: possession of the mailbox (a single-use,
30-minute link) and possession of the second factor (an authenticator code or an
unused backup code, asked for when the new password is set). A reset never touches
MFA, signs nobody in, revokes every session and clears the lockout.

The request answers the same whether or not the address belongs to an account: the
work done does not depend on the answer (a token is generated, hashed and written for
every request; only an eligible request keeps it), and the message is sent later by the
worker, never inside the request.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
import uuid

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app import mail_settings, mailer, mfa, passwords
from app.auth_service import _try_backup_code, revoke_all_sessions
from app.config import get_settings
from app.gateway.account_audit import append_account_audit_log
from app.models.mail import PasswordResetToken
from app.models.user import User

TOKEN_TTL = dt.timedelta(minutes=30)
MAX_REQUESTS_PER_HOUR = 3
MAX_CODE_ATTEMPTS = 5


class ResetError(Exception):
    """A reset could not be completed. `public` is the one message the caller may show;
    which check failed is only in the account audit log."""

    def __init__(self, public: str, status: int = 400):
        super().__init__(public)
        self.public = public
        self.status = status


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def hash_token(raw: str) -> str:
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


def reset_link(raw_token: str) -> str:
    """The token rides in the fragment: a fragment is never sent to a server, so it is
    not in a request path, an access log or a Referer header."""
    base = (get_settings().public_base_url or "").rstrip("/")
    return f"{base}/reset-password#{raw_token}"


def _eligible(user: User | None) -> bool:
    """Only an account that signs in normally can use a reset: active, past its first
    sign-in, with a confirmed authenticator (the reset asks for it)."""
    return (
        user is not None and user.status == "active" and not user.must_change_password
        and user.totp_confirmed_at is not None and user.totp_secret_encrypted is not None
    )


def request_reset(db: Session, email: str, *, ip: str | None, user_agent: str | None) -> None:
    """Never raises about the account. Everything that happens is in the account audit
    log (never the address' existence in the response)."""
    address = (email or "").lower().strip()
    user = db.scalar(select(User).where(User.email == address)) if address else None
    raw = secrets.token_urlsafe(32)
    row = PasswordResetToken(
        user_id=user.id if user is not None else uuid.uuid4(), token_hash=hash_token(raw),
        expires_at=_now() + TOKEN_TTL, request_ip=ip,
    )
    available = mail_settings.is_available(db)
    reason = None
    if not available:
        reason = "mail_not_available"
    elif user is None:
        reason = "unknown_email"
    elif not _eligible(user):
        reason = "account_not_eligible"
    else:
        recent = db.scalar(
            select(PasswordResetToken.id).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.created_at >= _now() - dt.timedelta(hours=1),
            ).offset(MAX_REQUESTS_PER_HOUR - 1).limit(1)
        )
        if recent is not None:
            reason = "throttled"

    if reason is None:
        # Eligible: invalidate what came before, keep this token, queue the message.
        db.execute(
            update(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None),
                PasswordResetToken.invalidated_at.is_(None),
            ).values(invalidated_at=_now())
        )
        db.add(row)
        subject, body = mailer.password_reset_message(reset_link(raw), int(TOKEN_TTL.total_seconds() // 60))
        mailer.enqueue(db, kind="password_reset", to=user.email, subject=subject, body=body, requested_by=user.id)
        db.commit()
        append_account_audit_log(db, actor_user_id=user.id, action="password_reset_request", outcome="success",
                                 ip_address=ip, user_agent=user_agent, payload={"queued": True})
        return

    # Not eligible: do the same writes and take them back, so the work is the same.
    try:
        with db.begin_nested():
            if user is not None:
                db.add(row)
            if available:
                dummy = mailer.enqueue(
                    db, kind="password_reset", to="nobody@example.invalid", subject="x", body=reset_link(raw),
                    require_available=False,
                )
                db.delete(dummy)
            db.flush()
            raise _Rollback()
    except _Rollback:
        pass
    db.rollback()
    append_account_audit_log(db, actor_user_id=user.id if user is not None else None, action="password_reset_request",
                             outcome="failure", ip_address=ip, user_agent=user_agent, payload={"reason": reason})


class _Rollback(Exception):
    pass


def _fail(db: Session, user: User | None, reason: str, public: str, *, ip, user_agent, status: int = 400):
    append_account_audit_log(db, actor_user_id=user.id if user is not None else None,
                             action="password_reset_complete", outcome="failure",
                             ip_address=ip, user_agent=user_agent, payload={"reason": reason})
    raise ResetError(public, status)


def complete_reset(
    db: Session, raw_token: str, new_password: str, code: str, *, ip: str | None, user_agent: str | None,
) -> None:
    """Sets the new password, or raises ResetError. A wrong token and a wrong code are
    told apart only after the token is proven valid."""
    invalid_link = "this reset link is invalid or has expired"
    row = db.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(raw_token)).with_for_update()
    ) if raw_token else None
    if row is None:
        _fail(db, None, "unknown_token", invalid_link, ip=ip, user_agent=user_agent)
    user = db.get(User, row.user_id)
    if row.used_at is not None:
        _fail(db, user, "token_used", invalid_link, ip=ip, user_agent=user_agent)
    if row.invalidated_at is not None:
        _fail(db, user, "token_superseded", invalid_link, ip=ip, user_agent=user_agent)
    if row.expires_at < _now():
        _fail(db, user, "token_expired", invalid_link, ip=ip, user_agent=user_agent)
    if not _eligible(user):
        _fail(db, user, "account_not_eligible", invalid_link, ip=ip, user_agent=user_agent)

    # The second factor. A wrong code counts against this token and ends it after a few.
    verified = False
    raw_secret = mfa.decrypt_secret(user.totp_secret_encrypted)
    step = raw_secret and mfa.verify_code(raw_secret, code, user.totp_last_step)
    if step:
        won = db.execute(
            update(User).where(User.id == user.id, or_(User.totp_last_step.is_(None), User.totp_last_step < step))
            .values(totp_last_step=step)
        )
        db.commit()
        verified = won.rowcount == 1
    elif _try_backup_code(db, user, code):
        verified = True
    if not verified:
        row = db.get(PasswordResetToken, row.id)
        row.attempts += 1
        if row.attempts >= MAX_CODE_ATTEMPTS:
            row.invalidated_at = _now()
        db.commit()
        _fail(db, user, "wrong_code", "that code was not accepted", ip=ip, user_agent=user_agent)

    row = db.get(PasswordResetToken, row.id)
    row.used_at = _now()
    db.execute(
        update(PasswordResetToken).where(
            PasswordResetToken.user_id == user.id, PasswordResetToken.id != row.id,
            PasswordResetToken.used_at.is_(None), PasswordResetToken.invalidated_at.is_(None),
        ).values(invalidated_at=_now())
    )
    user.password_hash = passwords.hash_secret(new_password)
    user.must_change_password = False
    user.failed_password_count = 0
    user.locked_until = None
    db.commit()
    revoked = revoke_all_sessions(db, user.id)
    append_account_audit_log(db, actor_user_id=user.id, action="password_reset_complete", outcome="success",
                             ip_address=ip, user_agent=user_agent, payload={"sessions_revoked": revoked})
