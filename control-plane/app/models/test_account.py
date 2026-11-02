"""Test accounts (REQ-TESTACCT-001..009, GitHub #89). Migration 0047."""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class TestAccount(Base):
    __tablename__ = "engagement_test_account"
    __test__ = False  # not a pytest class

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False)
    label: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    login_path: Mapped[str | None] = mapped_column(String)
    header_name: Mapped[str | None] = mapped_column(String)
    username: Mapped[str | None] = mapped_column(String)
    secret_enc: Mapped[str | None] = mapped_column(String)
    secret_set_at: Mapped[datetime.datetime | None]
    state: Mapped[str] = mapped_column(String, nullable=False, server_default="active")
    suspended_reason: Mapped[str | None] = mapped_column(String)
    attested_by: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("app_user.id"))
    attested_at: Mapped[datetime.datetime | None]
    attestation_version: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class TestAccountHost(Base):
    __tablename__ = "engagement_test_account_host"
    __test__ = False

    id: Mapped[uuid.UUID] = uuid_pk()
    account_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement_test_account.id", ondelete="CASCADE"), nullable=False)
    host: Mapped[str] = mapped_column(String, nullable=False)
    login_path: Mapped[str | None] = mapped_column(String)
    assigned_by: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("app_user.id"), nullable=False)
    assigned_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    attestation_version: Mapped[str] = mapped_column(String, nullable=False)
    failed_runs: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    suspended_at: Mapped[datetime.datetime | None]
    suspended_reason: Mapped[str | None] = mapped_column(String)
    last_outcome: Mapped[str | None] = mapped_column(String)
    last_outcome_at: Mapped[datetime.datetime | None]


class LoginConsent(Base):
    __tablename__ = "engagement_login_consent"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False)
    given_by: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("app_user.id"), nullable=False)
    given_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    wording_version: Mapped[str] = mapped_column(String, nullable=False)
    pairs: Mapped[list] = mapped_column(JSONB, nullable=False)
    revoked_at: Mapped[datetime.datetime | None]
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("app_user.id"))


class TestAccountLoginAttempt(Base):
    __tablename__ = "engagement_test_account_login_attempt"
    __test__ = False

    id: Mapped[uuid.UUID] = uuid_pk()
    account_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement_test_account.id", ondelete="CASCADE"), nullable=False)
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True))
    host: Mapped[str] = mapped_column(String, nullable=False)
    at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
