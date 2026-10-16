"""Monitoring-mode records (REQ-MODE-006..014, REQ-MON-001/002): the consent, the
schedule, what a run saw, what changed, what needs a person, and where alerts go."""

import datetime
import uuid

from sqlalchemy import ARRAY, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class EngagementConsent(Base):
    """Append-only. The latest row of a kind decides; it is valid when its action is
    `given` and its wording version is the one the code currently ships."""

    __tablename__ = "engagement_consent"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    wording_version: Mapped[int] = mapped_column(Integer, nullable=False)
    wording_sha256: Mapped[str] = mapped_column(String, nullable=False)
    given_by: Mapped[str] = mapped_column(String, nullable=False)
    given_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class EngagementSchedule(Base):
    __tablename__ = "engagement_schedule"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    tier: Mapped[str] = mapped_column(String, nullable=False)
    cadence: Mapped[str] = mapped_column(String, nullable=False)
    time_of_day: Mapped[str] = mapped_column(String, nullable=False, server_default="02:00")
    timezone: Mapped[str] = mapped_column(String, nullable=False, server_default="UTC")
    weekday: Mapped[int | None] = mapped_column(Integer)
    window_start: Mapped[str | None] = mapped_column(String)
    window_end: Mapped[str | None] = mapped_column(String)
    window_days: Mapped[list[int] | None] = mapped_column(ARRAY(Integer))
    jitter_minutes: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    enabled: Mapped[bool] = mapped_column(server_default="true")
    disabled_reason: Mapped[str | None] = mapped_column(String)
    next_run_at: Mapped[datetime.datetime | None]
    last_run_at: Mapped[datetime.datetime | None]
    last_skip_reason: Mapped[str | None] = mapped_column(String)
    skip_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_by: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class RunInventorySnapshot(Base):
    __tablename__ = "run_inventory_snapshot"

    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_run.id", ondelete="CASCADE"), primary_key=True
    )
    kind: Mapped[str] = mapped_column(String, primary_key=True)
    key: Mapped[str] = mapped_column(String, primary_key=True)
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")


class ChangeEvent(Base):
    __tablename__ = "change_event"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_run.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String, nullable=False)
    subject: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str | None] = mapped_column(String)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class InboxItem(Base):
    __tablename__ = "inbox_item"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String, nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[str] = mapped_column(String, nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    state: Mapped[str] = mapped_column(String, nullable=False, server_default="open")
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    resolved_at: Mapped[datetime.datetime | None]
    resolved_by: Mapped[str | None] = mapped_column(String)


class NotificationTarget(Base):
    __tablename__ = "notification_target"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[str] = mapped_column(String, nullable=False)
    secret_enc: Mapped[str | None] = mapped_column(String)
    min_severity: Mapped[str] = mapped_column(String, nullable=False, server_default="high")
    enabled: Mapped[bool] = mapped_column(server_default="true")
    created_by: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class AlertEvent(Base):
    __tablename__ = "alert_event"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("notification_target.id", ondelete="CASCADE"), nullable=False
    )
    event_kind: Mapped[str] = mapped_column(String, nullable=False)
    immediate: Mapped[bool] = mapped_column(server_default="false")
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    state: Mapped[str] = mapped_column(String, nullable=False, server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    deliver_after: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    next_attempt_at: Mapped[datetime.datetime | None]
    last_error: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    delivered_at: Mapped[datetime.datetime | None]
