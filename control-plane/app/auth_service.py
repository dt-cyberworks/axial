"""Core login/MFA/session business logic (REQ-IAM-002..006), shared by the
public /auth endpoints and the admin user-management endpoints. Every
outcome (success and failure) is recorded via account_audit_log
(REQ-IAM-009) - never with the raw password/TOTP code/backup code/session
token in the payload.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app import mfa, passwords, sessions
from app.gateway.account_audit import append_account_audit_log
from app.models.user import LoginChallenge, User, UserBackupCode, UserSession

CHALLENGE_TTL = dt.timedelta(minutes=5)
MAX_CHALLENGE_ATTEMPTS = 5
LOCKOUT_THRESHOLD = 5
LOCKOUT_BASE_SECONDS = 30
LOCKOUT_MAX_SECONDS = 900

# GitHub issue #23: a constant-time target for the "unknown email" path - run
# the SAME expensive Argon2 verify against a fixed dummy hash regardless of
# whether the account exists, so response timing cannot be used as a
# username oracle. The raw string this was hashed from is irrelevant and
# never used for anything else; only its shape (a valid Argon2 hash) matters.
_DUMMY_PASSWORD_HASH = passwords.hash_secret("asm-dummy-hash-for-constant-time-unknown-email-path")


class AuthError(Exception):
    """Generic authentication failure - callers must return one uniform
    response regardless of which check inside actually failed (REQ-IAM-003:
    never reveal which factor was wrong, never reveal whether an email
    exists)."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _is_locked(user: User) -> bool:
    return user.locked_until is not None and user.locked_until > _now()


def _register_failed_password(db: Session, user: User) -> None:
    """GitHub issue #23: the old `user.failed_password_count += 1; db.commit()`
    was a plain read-modify-write - two concurrent failures could both read
    the same pre-increment count and both write back count+1, losing an
    increment (a real weakening of brute-force protection under concurrency).

    The increment itself is expressed as a single UPDATE ... SET count =
    count + 1, so Postgres's own row-level write lock (implicit in any
    UPDATE, held only for the statement/transaction, released at commit)
    does the arithmetic atomically - no lost updates, and no held lock
    spanning the subsequent audit-log call (append_account_audit_log takes
    its own advisory lock for hash-chain serialization; holding a
    SELECT...FOR UPDATE row lock across that call was tried first and
    produced real deadlocks under contention - two independent lock
    primitives with an achievable acquisition-order inversion across
    concurrent callers)."""
    db.execute(
        update(User).where(User.id == user.id).values(failed_password_count=User.failed_password_count + 1)
    )
    db.commit()
    db.refresh(user)
    if user.failed_password_count >= LOCKOUT_THRESHOLD:
        backoff = min(
            LOCKOUT_BASE_SECONDS * (2 ** (user.failed_password_count - LOCKOUT_THRESHOLD)),
            LOCKOUT_MAX_SECONDS,
        )
        user.locked_until = _now() + dt.timedelta(seconds=backoff)
        db.commit()


def _reset_failed_password(db: Session, user: User) -> None:
    if user.failed_password_count or user.locked_until:
        user.failed_password_count = 0
        user.locked_until = None
        db.commit()


def authenticate_password(
    db: Session, email: str, password: str, *, ip: str | None, user_agent: str | None,
) -> tuple[User, str]:
    """Returns (user, next_step) where next_step is one of
    'set_password' | 'mfa_enroll' | 'mfa_verify'. Raises AuthError on any
    failure (bad email, bad password, locked account, disabled account).

    GitHub issue #23: the failed-attempt counter's atomicity comes from
    _register_failed_password's own UPDATE ... SET count = count + 1 (see
    its docstring) - deliberately NOT a SELECT ... FOR UPDATE held across
    this whole function, which produced real deadlocks against
    append_account_audit_log's advisory lock under concurrent contention.
    """
    user = db.scalar(select(User).where(User.email == email.lower().strip()))
    if user is None:
        # Constant-time: burn the same Argon2 verify cost an existing user's
        # wrong-password path pays, so response timing cannot distinguish
        # "no such account" from "account exists, wrong password".
        passwords.verify_secret(password, _DUMMY_PASSWORD_HASH)
        append_account_audit_log(db, actor_user_id=None, action="login_password", outcome="failure",
                                 ip_address=ip, user_agent=user_agent, payload={"reason": "unknown_email"})
        raise AuthError("invalid credentials")
    if user.status == "disabled":
        append_account_audit_log(db, actor_user_id=user.id, action="login_password", outcome="failure",
                                 ip_address=ip, user_agent=user_agent, payload={"reason": "account_disabled"})
        raise AuthError("invalid credentials")
    if _is_locked(user):
        append_account_audit_log(db, actor_user_id=user.id, action="login_password", outcome="failure",
                                 ip_address=ip, user_agent=user_agent, payload={"reason": "locked_out"})
        raise AuthError("invalid credentials")
    if not passwords.verify_secret(password, user.password_hash):
        _register_failed_password(db, user)
        append_account_audit_log(db, actor_user_id=user.id, action="login_password", outcome="failure",
                                 ip_address=ip, user_agent=user_agent, payload={"reason": "wrong_password"})
        raise AuthError("invalid credentials")

    _reset_failed_password(db, user)
    append_account_audit_log(db, actor_user_id=user.id, action="login_password", outcome="success",
                             ip_address=ip, user_agent=user_agent, payload={})
    if user.must_change_password:
        return user, "set_password"
    if user.totp_confirmed_at is None:
        return user, "mfa_enroll"
    return user, "mfa_verify"


def create_login_challenge(db: Session, user: User, purpose: str) -> LoginChallenge:
    challenge = LoginChallenge(user_id=user.id, purpose=purpose, expires_at=_now() + CHALLENGE_TTL)
    db.add(challenge)
    db.commit()
    db.refresh(challenge)
    return challenge


def _load_valid_challenge(db: Session, challenge_id: uuid.UUID, purpose: str) -> LoginChallenge:
    challenge = db.get(LoginChallenge, challenge_id)
    if (
        challenge is None or challenge.purpose != purpose or challenge.consumed_at is not None
        or challenge.expires_at < _now() or challenge.attempts >= MAX_CHALLENGE_ATTEMPTS
    ):
        raise AuthError("invalid or expired challenge")
    return challenge


def set_first_password(db: Session, challenge_id: uuid.UUID, new_password: str, *, ip, user_agent) -> User:
    challenge = _load_valid_challenge(db, challenge_id, "set_password")
    user = db.get(User, challenge.user_id)
    if user is None or not user.must_change_password:
        raise AuthError("invalid or expired challenge")
    user.password_hash = passwords.hash_secret(new_password)
    user.must_change_password = False
    db.commit()
    append_account_audit_log(db, actor_user_id=user.id, action="password_set_first", outcome="success",
                             ip_address=ip, user_agent=user_agent, payload={})
    return user


def begin_mfa_enrollment(db: Session, challenge_id: uuid.UUID) -> tuple[User, str, str]:
    """Returns (user, raw_secret, otpauth_uri). The raw secret is encrypted
    and stored immediately but NOT confirmed (totp_confirmed_at stays NULL)
    until confirm_mfa_enrollment succeeds."""
    challenge = _load_valid_challenge(db, challenge_id, "mfa_enroll")
    user = db.get(User, challenge.user_id)
    if user is None or user.totp_confirmed_at is not None:
        raise AuthError("invalid or expired challenge")
    raw_secret = mfa.generate_secret()
    user.totp_secret_encrypted = mfa.encrypt_secret(raw_secret)
    db.commit()
    return user, raw_secret, mfa.provisioning_uri(raw_secret, user.email)


def confirm_mfa_enrollment(
    db: Session, challenge_id: uuid.UUID, code: str, *, ip, user_agent,
) -> tuple[User, str, list[str]]:
    """Returns (user, raw_session_token, backup_codes). backup_codes are
    generated and returned exactly once here."""
    challenge = _load_valid_challenge(db, challenge_id, "mfa_enroll")
    user = db.get(User, challenge.user_id)
    if user is None or user.totp_secret_encrypted is None or user.totp_confirmed_at is not None:
        raise AuthError("invalid or expired challenge")
    raw_secret = mfa.decrypt_secret(user.totp_secret_encrypted)
    step = raw_secret and mfa.verify_code(raw_secret, code, user.totp_last_step)
    if not step:
        challenge.attempts += 1
        db.commit()
        append_account_audit_log(db, actor_user_id=user.id, action="mfa_enroll_confirm", outcome="failure",
                                 ip_address=ip, user_agent=user_agent, payload={})
        raise AuthError("invalid code")

    user.totp_confirmed_at = _now()
    user.totp_last_step = step
    user.status = "active"
    user.last_login_at = _now()
    challenge.consumed_at = _now()

    raw_codes = _regenerate_backup_codes(db, user)
    db.commit()

    append_account_audit_log(db, actor_user_id=user.id, action="mfa_enroll_confirm", outcome="success",
                             ip_address=ip, user_agent=user_agent, payload={})
    raw_token, _ = create_session(db, user, ip=ip, user_agent=user_agent)
    return user, raw_token, raw_codes


def _regenerate_backup_codes(db: Session, user: User) -> list[str]:
    db.query(UserBackupCode).filter(UserBackupCode.user_id == user.id).delete()
    raw_codes = passwords.generate_backup_codes()
    for raw_code in raw_codes:
        db.add(UserBackupCode(user_id=user.id, code_hash=passwords.hash_secret(raw_code)))
    return raw_codes


def start_mfa_reenrollment(db: Session, user: User, current_password: str) -> tuple[str, str]:
    """REQ-IAM-004: an already-logged-in user re-enrolling (e.g. new phone)
    must re-prove their password first. Returns (raw_secret, otpauth_uri);
    the previous secret is overwritten immediately (unconfirmed) but the OLD
    one remains valid for verify_mfa_login until this is confirmed, so the
    user isn't locked out mid-reenrollment... except we do overwrite it here
    for simplicity - see confirm_mfa_reenrollment for the atomic switch."""
    if not passwords.verify_secret(current_password, user.password_hash):
        raise AuthError("invalid password")
    raw_secret = mfa.generate_secret()
    user.totp_secret_encrypted = mfa.encrypt_secret(raw_secret)
    db.commit()
    return raw_secret, mfa.provisioning_uri(raw_secret, user.email)


def confirm_mfa_reenrollment(db: Session, user: User, code: str, *, ip, user_agent) -> tuple[list[str], str]:
    raw_secret = mfa.decrypt_secret(user.totp_secret_encrypted) if user.totp_secret_encrypted else None
    step = raw_secret and mfa.verify_code(raw_secret, code, None)
    if not step:
        append_account_audit_log(db, actor_user_id=user.id, action="mfa_reenroll_confirm", outcome="failure",
                                 ip_address=ip, user_agent=user_agent, payload={})
        raise AuthError("invalid code")
    user.totp_confirmed_at = _now()
    user.totp_last_step = step
    raw_codes = _regenerate_backup_codes(db, user)
    db.commit()
    # GitHub issue #26: same reasoning as change_password - re-enrolling MFA
    # (new device, or recovery after losing the old one) is also a strong
    # "something changed" signal that should evict any other still-valid
    # session, not just rotate the authenticator secret.
    revoked = revoke_all_sessions(db, user.id)
    raw_token, _ = create_session(db, user, ip=ip, user_agent=user_agent)
    append_account_audit_log(db, actor_user_id=user.id, action="mfa_reenroll_confirm", outcome="success",
                             ip_address=ip, user_agent=user_agent, payload={"sessions_revoked": revoked})
    return raw_codes, raw_token


def admin_reset_mfa(db: Session, target_user: User, *, actor_user_id: uuid.UUID, ip, user_agent) -> None:
    target_user.totp_secret_encrypted = None
    target_user.totp_confirmed_at = None
    target_user.totp_last_step = None
    db.query(UserBackupCode).filter(UserBackupCode.user_id == target_user.id).delete()
    db.commit()
    revoke_all_sessions(db, target_user.id)
    append_account_audit_log(db, actor_user_id=actor_user_id, action="mfa_reset", outcome="success",
                             ip_address=ip, user_agent=user_agent, payload={"target_user_id": str(target_user.id)})


def _try_backup_code(db: Session, user: User, code: str) -> bool:
    """GitHub issue #23: a backup code is meant to be single-use. The old
    SELECT-then-mutate-then-commit had no atomic guard between "read as
    unused" and "mark used" - two requests submitting the SAME code in
    parallel could both read it unused (before either commits) and both
    succeed. The UPDATE ... WHERE used_at IS NULL below is the atomic
    primitive: Postgres serializes concurrent UPDATEs to the same row, so the
    second writer's WHERE re-evaluates against the FIRST writer's already-
    committed used_at and matches zero rows - rowcount is the authoritative
    "did *I* win the race" signal, not the earlier SELECT.
    """
    normalized = (code or "").strip().upper()
    codes = db.scalars(
        select(UserBackupCode).where(UserBackupCode.user_id == user.id, UserBackupCode.used_at.is_(None))
    ).all()
    for row in codes:
        if passwords.verify_secret(normalized, row.code_hash):
            result = db.execute(
                update(UserBackupCode)
                .where(UserBackupCode.id == row.id, UserBackupCode.used_at.is_(None))
                .values(used_at=_now())
            )
            db.commit()
            return result.rowcount == 1
    return False


def verify_mfa_login(db: Session, challenge_id: uuid.UUID, code: str, *, ip, user_agent) -> tuple[User, str]:
    """Returns (user, raw_session_token). Accepts a TOTP code or an unused
    backup code."""
    challenge = _load_valid_challenge(db, challenge_id, "mfa_verify")
    user = db.get(User, challenge.user_id)
    if user is None or user.totp_secret_encrypted is None or user.totp_confirmed_at is None:
        raise AuthError("invalid or expired challenge")

    raw_secret = mfa.decrypt_secret(user.totp_secret_encrypted)
    step = raw_secret and mfa.verify_code(raw_secret, code, user.totp_last_step)
    if step:
        # GitHub issue #23: same lost-update shape as backup codes - two
        # concurrent requests presenting the SAME valid TOTP code could both
        # read the pre-consumption totp_last_step (before either commits),
        # both verify successfully, and both mint a session from one code
        # presentation. The conditional UPDATE is the atomic guard: it only
        # actually advances the step (and thus only this request "wins") if
        # totp_last_step is still behind the step being consumed at commit
        # time - a concurrent winner's already-committed advance makes the
        # loser's WHERE match zero rows.
        result = db.execute(
            update(User)
            .where(User.id == user.id, or_(User.totp_last_step.is_(None), User.totp_last_step < step))
            .values(totp_last_step=step)
        )
        db.commit()
        if result.rowcount != 1:
            challenge.attempts += 1
            db.commit()
            append_account_audit_log(db, actor_user_id=user.id, action="login_mfa", outcome="failure",
                                     ip_address=ip, user_agent=user_agent, payload={"reason": "totp_step_already_consumed"})
            raise AuthError("invalid code")
        challenge.consumed_at = _now()
        db.commit()
    elif _try_backup_code(db, user, code):
        challenge.consumed_at = _now()
        db.commit()
    else:
        challenge.attempts += 1
        db.commit()
        append_account_audit_log(db, actor_user_id=user.id, action="login_mfa", outcome="failure",
                                 ip_address=ip, user_agent=user_agent, payload={})
        raise AuthError("invalid code")

    user.last_login_at = _now()
    db.commit()
    append_account_audit_log(db, actor_user_id=user.id, action="login_mfa", outcome="success",
                             ip_address=ip, user_agent=user_agent, payload={})
    raw_token, _ = create_session(db, user, ip=ip, user_agent=user_agent)
    return user, raw_token


def create_session(db: Session, user: User, *, ip: str | None, user_agent: str | None) -> tuple[str, UserSession]:
    raw_token = sessions.generate_token()
    session = UserSession(
        user_id=user.id, token_hash=sessions.hash_token(raw_token), ip_address=ip, user_agent=user_agent,
        expires_at=_now() + sessions.ABSOLUTE_MAX_LIFETIME,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return raw_token, session


def resolve_session(db: Session, raw_token: str) -> User | None:
    if not raw_token:
        return None
    token_hash = sessions.hash_token(raw_token)
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash))
    if session is None or session.revoked_at is not None or session.expires_at < _now():
        return None
    if session.last_seen_at + sessions.IDLE_TIMEOUT < _now():
        return None
    user = db.get(User, session.user_id)
    if user is None or user.status == "disabled":
        return None
    session.last_seen_at = _now()
    db.commit()
    return user


def revoke_session_by_token(db: Session, raw_token: str) -> None:
    token_hash = sessions.hash_token(raw_token)
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash))
    if session is not None and session.revoked_at is None:
        session.revoked_at = _now()
        db.commit()


def revoke_all_sessions(db: Session, user_id: uuid.UUID) -> int:
    active = db.scalars(
        select(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    ).all()
    now = _now()
    for session in active:
        session.revoked_at = now
    db.commit()
    return len(active)


def change_password(db: Session, user: User, current_password: str, new_password: str, *, ip, user_agent) -> str:
    """GitHub issue #26: a password change is the standard response to "I
    think my account was compromised" - so besides updating the hash, every
    existing session (including whichever one made this call) is revoked and
    replaced with exactly one new one. An attacker holding a stolen-but-
    still-valid session is evicted; the caller, who just re-proved the
    current password, stays logged in on a fresh token rather than being
    logged out by their own security action. Returns the new raw session
    token."""
    if not passwords.verify_secret(current_password, user.password_hash):
        raise AuthError("invalid current password")
    user.password_hash = passwords.hash_secret(new_password)
    db.commit()
    revoked = revoke_all_sessions(db, user.id)
    raw_token, _ = create_session(db, user, ip=ip, user_agent=user_agent)
    append_account_audit_log(db, actor_user_id=user.id, action="password_change", outcome="success",
                             ip_address=ip, user_agent=user_agent, payload={"sessions_revoked": revoked})
    return raw_token


def oldest_active_admin(db: Session) -> User | None:
    """The account that takes ownership of engagements nobody created through the
    console (REQ-IAM-021): the benchmark harness's, and the legacy ones the
    migration adopted."""
    return db.scalars(
        select(User).where(User.role == "admin", User.status == "active").order_by(User.created_at, User.id).limit(1)
    ).first()
