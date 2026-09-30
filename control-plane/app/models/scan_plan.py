import datetime
import uuid

from sqlalchemy import ForeignKey, Integer, Numeric, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk

SERVICE_CLASSES = ("web", "web_alias", "tls_service", "service", "unknown")
CHECK_STATES = ("planned", "running", "complete", "partial", "failed", "skipped")
SCAN_PROFILES = ("standard", "thorough")


class ScanSurface(Base):
    """One open port of an approved asset in one scan run (REQ-PIPE-001): its
    service class and its technology profile (REQ-PIPE-002)."""

    __tablename__ = "scan_surface"
    __table_args__ = (UniqueConstraint("scan_run_id", "host", "port", name="uq_scan_surface"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_run.id", ondelete="CASCADE"), nullable=False
    )
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("discovered_asset.id", ondelete="SET NULL")
    )
    host: Mapped[str] = mapped_column(String, nullable=False)
    ip: Mapped[str | None] = mapped_column(String)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    scheme: Mapped[str | None] = mapped_column(String)
    service_class: Mapped[str] = mapped_column(String(16), nullable=False)
    alias_of: Mapped[str | None] = mapped_column(String)
    profile: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    fingerprint: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class ScanCheck(Base):
    """One planned or deliberately skipped check against a surface
    (REQ-PIPE-003/006/008). The row is the check-level checkpoint."""

    __tablename__ = "scan_check"
    __table_args__ = (UniqueConstraint("scan_run_id", "surface_id", "check_id", name="uq_scan_check"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_run.id", ondelete="CASCADE"), nullable=False
    )
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    surface_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_surface.id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    check_id: Mapped[str] = mapped_column(String, nullable=False)
    tool: Mapped[str] = mapped_column(String, nullable=False)
    args: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    depends_on: Mapped[str | None] = mapped_column(String)
    state: Mapped[str] = mapped_column(String(16), nullable=False, server_default="planned")
    reason: Mapped[str] = mapped_column(String, nullable=False)
    budget_s: Mapped[int | None] = mapped_column(Integer)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    started_at: Mapped[datetime.datetime | None]
    finished_at: Mapped[datetime.datetime | None]
    duration_s: Mapped[float | None] = mapped_column(Numeric(10, 2))
    findings: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    outcome_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
