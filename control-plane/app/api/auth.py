"""Login/MFA/session endpoints (REQ-IAM-002..006). No public account
creation here - see app/api/admin.py for admin-only user provisioning
(REQ-IAM-008)."""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import auth_service, sessions
from app.config import get_settings
from app.db.base import get_db
from app.models.user import UserSession
from app.security import require_user
from app.models.user import User
from app.schemas.auth import (
    ChangePasswordIn,
    LoginChallengeOut,
    LoginIn,
    MfaConfirmIn,
    MfaEnrollIn,
    MfaEnrollOut,
    MfaReenrollConfirmIn,
    MfaReenrollConfirmOut,
    MfaReenrollStartIn,
    MfaReenrollStartOut,
    MfaVerifyIn,
    SessionInfoOut,
    SessionOut,
    SetFirstPasswordIn,
    UserOut,
)

router = APIRouter(prefix="/auth", tags=["auth"])

SESSION_COOKIE = "session"


def _client_info(request: Request) -> tuple[str | None, str | None]:
    forwarded = request.headers.get("x-forwarded-for")
    ip = (forwarded.split(",")[0].strip() if forwarded else None) or (request.client.host if request.client else None)
    return ip, request.headers.get("user-agent")


def _set_session_cookie(response: Response, raw_token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=SESSION_COOKIE, value=raw_token, httponly=True,
        secure=settings.environment.lower() == "production", samesite="strict", path="/",
        max_age=int(sessions.ABSOLUTE_MAX_LIFETIME.total_seconds()),
    )


@router.post("/login", response_model=LoginChallengeOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip, ua = _client_info(request)
    try:
        user, status = auth_service.authenticate_password(db, body.email, body.password, ip=ip, user_agent=ua)
    except auth_service.AuthError:
        raise HTTPException(401, "invalid credentials")
    challenge = auth_service.create_login_challenge(db, user, status)  # status doubles as the challenge purpose
    return LoginChallengeOut(status=status, challenge_id=challenge.id)


@router.post("/password/set-first", response_model=LoginChallengeOut)
def set_first_password(body: SetFirstPasswordIn, request: Request, db: Session = Depends(get_db)):
    ip, ua = _client_info(request)
    try:
        user = auth_service.set_first_password(db, body.challenge_id, body.new_password, ip=ip, user_agent=ua)
    except auth_service.AuthError:
        raise HTTPException(401, "invalid or expired challenge")
    next_status = "mfa_enroll" if user.totp_confirmed_at is None else "mfa_verify"
    challenge = auth_service.create_login_challenge(db, user, next_status)
    return LoginChallengeOut(status=next_status, challenge_id=challenge.id)


@router.post("/mfa/enroll", response_model=MfaEnrollOut)
def mfa_enroll(body: MfaEnrollIn, db: Session = Depends(get_db)):
    try:
        user, raw_secret, uri = auth_service.begin_mfa_enrollment(db, body.challenge_id)
    except auth_service.AuthError:
        raise HTTPException(401, "invalid or expired challenge")
    return MfaEnrollOut(challenge_id=body.challenge_id, secret=raw_secret, otpauth_uri=uri)


@router.post("/mfa/enroll/confirm", response_model=SessionOut)
def mfa_enroll_confirm(body: MfaConfirmIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip, ua = _client_info(request)
    try:
        user, raw_token, backup_codes = auth_service.confirm_mfa_enrollment(
            db, body.challenge_id, body.code, ip=ip, user_agent=ua,
        )
    except auth_service.AuthError:
        raise HTTPException(401, "invalid code")
    _set_session_cookie(response, raw_token)
    return SessionOut(session_token=raw_token, user=UserOut.model_validate(user), backup_codes=backup_codes)


@router.post("/login/mfa", response_model=SessionOut)
def login_mfa(body: MfaVerifyIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip, ua = _client_info(request)
    try:
        user, raw_token = auth_service.verify_mfa_login(db, body.challenge_id, body.code, ip=ip, user_agent=ua)
    except auth_service.AuthError:
        raise HTTPException(401, "invalid code")
    _set_session_cookie(response, raw_token)
    return SessionOut(session_token=raw_token, user=UserOut.model_validate(user))


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    authorization = request.headers.get("authorization")
    raw_token = None
    if authorization and authorization.lower().startswith("bearer "):
        raw_token = authorization[7:].strip()
    raw_token = raw_token or request.cookies.get(SESSION_COOKIE)
    if raw_token:
        auth_service.revoke_session_by_token(db, raw_token)
    response.delete_cookie(SESSION_COOKIE, path="/")


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(require_user)):
    return UserOut.model_validate(user)


@router.post("/change-password", response_model=SessionOut)
def change_password(
    body: ChangePasswordIn, request: Request, response: Response,
    user: User = Depends(require_user), db: Session = Depends(get_db),
):
    """GitHub issue #26: revokes every other session and rotates this one -
    see auth_service.change_password for why."""
    ip, ua = _client_info(request)
    try:
        raw_token = auth_service.change_password(db, user, body.current_password, body.new_password, ip=ip, user_agent=ua)
    except auth_service.AuthError:
        raise HTTPException(401, "invalid current password")
    _set_session_cookie(response, raw_token)
    return SessionOut(session_token=raw_token, user=UserOut.model_validate(user))


@router.post("/mfa/reenroll/start", response_model=MfaReenrollStartOut)
def mfa_reenroll_start(body: MfaReenrollStartIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    try:
        raw_secret, uri = auth_service.start_mfa_reenrollment(db, user, body.current_password)
    except auth_service.AuthError:
        raise HTTPException(401, "invalid password")
    return MfaReenrollStartOut(secret=raw_secret, otpauth_uri=uri)


@router.post("/mfa/reenroll/confirm", response_model=MfaReenrollConfirmOut)
def mfa_reenroll_confirm(
    body: MfaReenrollConfirmIn, request: Request, response: Response,
    user: User = Depends(require_user), db: Session = Depends(get_db),
):
    """GitHub issue #26: same session-rotation reasoning as change_password -
    see auth_service.confirm_mfa_reenrollment."""
    ip, ua = _client_info(request)
    try:
        backup_codes, raw_token = auth_service.confirm_mfa_reenrollment(db, user, body.code, ip=ip, user_agent=ua)
    except auth_service.AuthError:
        raise HTTPException(401, "invalid code")
    _set_session_cookie(response, raw_token)
    return MfaReenrollConfirmOut(backup_codes=backup_codes, session_token=raw_token)


@router.get("/sessions", response_model=list[SessionInfoOut])
def list_sessions(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    current_hash = None
    authorization = request.headers.get("authorization")
    raw_token = authorization[7:].strip() if authorization and authorization.lower().startswith("bearer ") else request.cookies.get(SESSION_COOKIE)
    if raw_token:
        current_hash = sessions.hash_token(raw_token)
    rows = db.scalars(
        select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .order_by(UserSession.last_seen_at.desc())
    ).all()
    return [
        SessionInfoOut(
            id=row.id, ip_address=row.ip_address, user_agent=row.user_agent,
            created_at=row.created_at.isoformat(), last_seen_at=row.last_seen_at.isoformat(),
            is_current=(row.token_hash == current_hash),
        )
        for row in rows
    ]


@router.delete("/sessions/{session_id}", status_code=204)
def revoke_session(session_id: uuid.UUID, user: User = Depends(require_user), db: Session = Depends(get_db)):
    row = db.get(UserSession, session_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(404, "session not found")
    row.revoked_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
