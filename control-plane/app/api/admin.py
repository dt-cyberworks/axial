"""Admin-only user management (REQ-IAM-008) and account audit view
(REQ-IAM-009). Mounted with dependencies=[Depends(require_admin)] in
app/api/__init__.py - every route here already requires the admin role."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import auth_service, passwords
from app.db.base import get_db
from app.gateway.account_audit import append_account_audit_log
from app.models.user import AccountAuditLog, User
from app.security import require_user
from app.schemas.auth import (
    AdminCreateUserIn,
    AdminCreateUserOut,
    AdminResetPasswordOut,
    AdminUpdateUserIn,
    UserOut,
)

router = APIRouter(prefix="/admin", tags=["admin"])

_VALID_ROLES = {"admin", "operator"}
_VALID_STATUSES = {"invited", "active", "disabled"}

# GitHub issue #24: REQ-CONCUR-005's "never leave zero active admins" guard
# counted other admins and then mutated the target with no lock between the
# two steps - two concurrent demotions of the last two admins could each see
# the OTHER as proof an admin remains (under READ COMMITTED, neither sees the
# other's uncommitted write), and both succeed. A transaction-scoped advisory
# lock serializes the count-then-mutate sequence: the arbitrary constant is
# just this lock's namespace, released automatically at commit/rollback.
_ADMIN_ROLE_LOCK_KEY = 0x41444D4C4F434B  # "ADMLOCK" as bytes, for a stable/legible key


def _client_info(request: Request) -> tuple[str | None, str | None]:
    forwarded = request.headers.get("x-forwarded-for")
    ip = (forwarded.split(",")[0].strip() if forwarded else None) or (request.client.host if request.client else None)
    return ip, request.headers.get("user-agent")


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.created_at)).all()


@router.post("/users", response_model=AdminCreateUserOut, status_code=201)
def create_user(
    body: AdminCreateUserIn, request: Request, actor: User = Depends(require_user), db: Session = Depends(get_db),
):
    if body.role not in _VALID_ROLES:
        raise HTTPException(422, "invalid role")
    email = body.email.lower().strip()
    if db.scalar(select(User).where(User.email == email)) is not None:
        raise HTTPException(409, "a user with this email already exists")

    temp_password = passwords.generate_temp_password()
    user = User(
        email=email, display_name=body.display_name, role=body.role,
        password_hash=passwords.hash_secret(temp_password),
        status="invited", must_change_password=True, created_by_user_id=actor.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    ip, ua = _client_info(request)
    append_account_audit_log(db, actor_user_id=actor.id, action="user_created", outcome="success",
                             ip_address=ip, user_agent=ua, payload={"target_user_id": str(user.id), "role": user.role})
    return AdminCreateUserOut(user=UserOut.model_validate(user), temporary_password=temp_password)


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID, body: AdminUpdateUserIn, request: Request,
    actor: User = Depends(require_user), db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "user not found")

    # REQ-CONCUR-005: a transition away from "active admin" must never leave
    # zero active admins - that would lock the platform out of user
    # management through the application itself.
    was_active_admin = target.role == "admin" and target.status == "active"
    if was_active_admin:
        final_role = body.role if body.role is not None else target.role
        final_status = body.status if body.status is not None else target.status
        if not (final_role == "admin" and final_status == "active"):
            # GitHub issue #24: serialize the count-then-mutate sequence so a
            # concurrent demotion of a DIFFERENT admin cannot be counted as
            # "another admin remains" before it has actually committed.
            # Transaction-scoped: released automatically at commit/rollback,
            # so a crashed/aborted request can never leave the lock held.
            db.execute(select(func.pg_advisory_xact_lock(_ADMIN_ROLE_LOCK_KEY)))
            other_active_admins = db.scalar(
                select(func.count()).select_from(User).where(
                    User.role == "admin", User.status == "active", User.id != target.id,
                )
            )
            if not other_active_admins:
                raise HTTPException(409, "cannot remove the last active admin account")

    if body.role is not None:
        if body.role not in _VALID_ROLES:
            raise HTTPException(422, "invalid role")
        target.role = body.role
    if body.status is not None:
        if body.status not in _VALID_STATUSES:
            raise HTTPException(422, "invalid status")
        target.status = body.status
        if body.status == "disabled":
            auth_service.revoke_all_sessions(db, target.id)
    db.commit()
    db.refresh(target)

    ip, ua = _client_info(request)
    append_account_audit_log(db, actor_user_id=actor.id, action="user_updated", outcome="success",
                             ip_address=ip, user_agent=ua,
                             payload={"target_user_id": str(target.id), "role": body.role, "status": body.status})
    return target


@router.post("/users/{user_id}/reset-password", response_model=AdminResetPasswordOut)
def reset_password(
    user_id: uuid.UUID, request: Request, actor: User = Depends(require_user), db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "user not found")
    temp_password = passwords.generate_temp_password()
    target.password_hash = passwords.hash_secret(temp_password)
    target.must_change_password = True
    db.commit()
    auth_service.revoke_all_sessions(db, target.id)

    ip, ua = _client_info(request)
    append_account_audit_log(db, actor_user_id=actor.id, action="password_reset_by_admin", outcome="success",
                             ip_address=ip, user_agent=ua, payload={"target_user_id": str(target.id)})
    return AdminResetPasswordOut(temporary_password=temp_password)


@router.post("/users/{user_id}/reset-mfa", status_code=204)
def reset_mfa(
    user_id: uuid.UUID, request: Request, actor: User = Depends(require_user), db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "user not found")
    ip, ua = _client_info(request)
    auth_service.admin_reset_mfa(db, target, actor_user_id=actor.id, ip=ip, user_agent=ua)


@router.get("/audit", response_model=list[dict])
def list_account_audit(limit: int = 200, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 1000))
    rows = db.scalars(select(AccountAuditLog).order_by(AccountAuditLog.ts.desc()).limit(limit)).all()
    return [
        {
            "id": str(r.id), "ts": r.ts.isoformat(), "actor_user_id": str(r.actor_user_id) if r.actor_user_id else None,
            "action": r.action, "outcome": r.outcome, "ip_address": r.ip_address, "payload": r.payload,
        }
        for r in rows
    ]
