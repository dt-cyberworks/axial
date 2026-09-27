"""Individual accounts, MFA state, sessions, and the account-security audit
trail (REQ-IAM-002..011). Separate from Customer (the client being scanned
for) - a User is an internal console operator/admin."""

import datetime
import uuid

from sqlalchemy import ForeignKey, LargeBinary, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class User(Base):
    __tablename__ = "app_user"

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, server_default="operator")
    status: Mapped[str] = mapped_column(String, nullable=False, server_default="invited")
    must_change_password: Mapped[bool] = mapped_column(server_default="true")
    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_confirmed_at: Mapped[datetime.datetime | None]
    totp_last_step: Mapped[int | None]
    failed_password_count: Mapped[int] = mapped_column(server_default="0")
    locked_until: Mapped[datetime.datetime | None]
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("app_user.id"))
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    last_login_at: Mapped[datetime.datetime | None]


class UserBackupCode(Base):
    __tablename__ = "user_backup_code"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("app_user.id"), nullable=False)
    code_hash: Mapped[str] = mapped_column(String, nullable=False)
    used_at: Mapped[datetime.datetime | None]
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class LoginChallenge(Base):
    """Bridges password verification and MFA verification (REQ-IAM-003) - a
    session is never issued from a password alone."""

    __tablename__ = "login_challenge"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("app_user.id"), nullable=False)
    purpose: Mapped[str] = mapped_column(String, nullable=False)  # set_password | mfa_enroll | mfa_verify
    attempts: Mapped[int] = mapped_column(server_default="0")
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime.datetime] = mapped_column(nullable=False)
    consumed_at: Mapped[datetime.datetime | None]


class UserSession(Base):
    """Server-side, revocable session (REQ-IAM-005) - only token_hash is
    stored, mirroring password/backup-code hashing; the raw token is only
    ever sent to the client, once, at creation."""

    __tablename__ = "user_session"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("app_user.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    ip_address: Mapped[str | None] = mapped_column(String)
    user_agent: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    last_seen_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime.datetime] = mapped_column(nullable=False)
    revoked_at: Mapped[datetime.datetime | None]


class AccountAuditLog(Base):
    """Globally hash-chained (REQ-IAM-009) - deliberately separate from
    AuditLog (app/models/audit.py), which is chained PER ENGAGEMENT and
    carries per-engagement legal-evidence semantics account/security events
    (no engagement) don't fit."""

    __tablename__ = "account_audit_log"

    id: Mapped[uuid.UUID] = uuid_pk()
    ts: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("app_user.id"))
    action: Mapped[str] = mapped_column(String, nullable=False)
    outcome: Mapped[str] = mapped_column(String, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String)
    user_agent: Mapped[str | None] = mapped_column(String)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    prev_hash: Mapped[str | None] = mapped_column(String)
    row_hash: Mapped[str] = mapped_column(String, nullable=False)
