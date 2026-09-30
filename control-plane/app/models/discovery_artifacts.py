import datetime
import uuid

from sqlalchemy import ForeignKey, Integer, LargeBinary, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class DiscoveredEndpoint(Base):
    """Von Crawler/URL-Historie gefundener Endpunkt (REQ-COVER-003).

    Nur Kontext fuer Web-Suite und Agent: ein Endpunkt erzeugt nie neuen Scope.
    """

    __tablename__ = "discovered_endpoint"
    __table_args__ = (UniqueConstraint("engagement_id", "method", "url", name="uq_discovered_endpoint"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_run.id", ondelete="SET NULL")
    )
    url: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str] = mapped_column(String, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    method: Mapped[str] = mapped_column(String, nullable=False, server_default="GET")
    source: Mapped[str] = mapped_column(String, nullable=False)
    param_names: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    first_seen_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class WebScreenshot(Base):
    """Screenshot eines Live-Webdienstes (REQ-COVER-006), PNG in Postgres
    (wie Report: kleine, engagement-gebundene Blobs, keine neue Abhaengigkeit)."""

    __tablename__ = "web_screenshot"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_run.id", ondelete="SET NULL")
    )
    url: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str] = mapped_column(String, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    sha256: Mapped[str | None] = mapped_column(String(64))
    content: Mapped[bytes | None] = mapped_column(LargeBinary)
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
