"""Self-service password reset endpoints (REQ-IAM-020) and the public answer to "is it
offered" (REQ-MAIL-001). Unauthenticated by nature; each step is rate-limited by source
address like the other sign-in steps (REQ-IAM-016)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import mail_settings, password_reset
from app.db.base import get_db
from app.rate_limit import client_ip, enforce_login_rate_limit
from app.settings_store import SettingsCipherUnavailable

router = APIRouter(prefix="/auth", tags=["auth"])


class RecoveryOptionsOut(BaseModel):
    self_service_reset: bool


class ResetRequestIn(BaseModel):
    email: str = Field(max_length=254)


class ResetRequestOut(BaseModel):
    status: str = "accepted"
    detail: str = "If an account with that address can be reset, a message with a link is on its way."


class ResetCompleteIn(BaseModel):
    token: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=12, max_length=1024)
    code: str = Field(min_length=1, max_length=64)


@router.get("/recovery-options", response_model=RecoveryOptionsOut)
def recovery_options(db: Session = Depends(get_db)):
    """REQ-MAIL-001: tells the sign-in page whether to offer "Forgot password?". Nothing
    else about the mail setup is public."""
    return RecoveryOptionsOut(self_service_reset=mail_settings.is_available(db))


@router.post("/password-reset/request", response_model=ResetRequestOut, status_code=202,
             dependencies=[Depends(enforce_login_rate_limit)])
def request_password_reset(body: ResetRequestIn, request: Request, db: Session = Depends(get_db)):
    ip, ua = client_ip(request), request.headers.get("user-agent")
    try:
        password_reset.request_reset(db, body.email, ip=ip, user_agent=ua)
    except SettingsCipherUnavailable:
        # A misconfiguration is not something this endpoint may reveal either; the audit
        # log of the account chain records every request that was refused.
        db.rollback()
    return ResetRequestOut()


@router.post("/password-reset/complete", status_code=204, dependencies=[Depends(enforce_login_rate_limit)])
def complete_password_reset(body: ResetCompleteIn, request: Request, db: Session = Depends(get_db)):
    ip, ua = client_ip(request), request.headers.get("user-agent")
    try:
        password_reset.complete_reset(db, body.token, body.new_password, body.code, ip=ip, user_agent=ua)
    except password_reset.ResetError as exc:
        raise HTTPException(exc.status, exc.public) from None
