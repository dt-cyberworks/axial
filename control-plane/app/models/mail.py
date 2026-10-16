"""Outbound e-mail queue and password-reset tokens (REQ-MAIL-003, REQ-IAM-020)."""

import datetime
import uuid

from sqlalchemy import ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class MailOutbox(Base):
    """One queued message. The body is encrypted at rest and removed once the message
    is delivered or has failed for good."""

    __tablename__ = "mail_outbox"

    id: Mapped[uuid.UUID] = uuid_pk()
    kind: Mapped[str] = mapped_column(String, nullable=False)
    to_address: Mapped[str] = mapped_column(String, nullable=False)
    subject: Mapped[str] = mapped_column(String, nullable=False)
    body_enc: Mapped[str | None] = mapped_column(String)
    state: Mapped[str] = mapped_column(String, nullable=False, server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    next_attempt_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    last_error: Mapped[str | None] = mapped_column(String)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True))
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    delivered_at: Mapped[datetime.datetime | None]


class PasswordResetToken(Base):
    __tablename__ = "password_reset_token"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("app_user.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime.datetime] = mapped_column(nullable=False)
    used_at: Mapped[datetime.datetime | None]
    invalidated_at: Mapped[datetime.datetime | None]
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    request_ip: Mapped[str | None] = mapped_column(String)
