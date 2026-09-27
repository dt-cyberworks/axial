import datetime
import uuid

from sqlalchemy import ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk
from app.models.engagement import AssetType


class DiscoveredAsset(Base):
    """Entdeckte (nicht zwingend freigegebene) Assets (Kap. 2.4)."""

    __tablename__ = "discovered_asset"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("discovered_asset.id"))
    asset_type: Mapped[str] = mapped_column(AssetType, nullable=False)
    value: Mapped[str] = mapped_column(String, nullable=False)
    in_scope: Mapped[bool] = mapped_column(nullable=False)
    discovered_via: Mapped[str] = mapped_column(String, nullable=False)
    first_seen: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    last_seen: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    # Set by the deterministic fingerprint phase's httpx probe (live or dead),
    # regardless of outcome - lets the agent phase know a host was ALREADY
    # checked and found to have no live HTTP service, instead of re-probing it
    # from scratch every run (found live: the agent re-ran httpx against the
    # same confirmed-dead subdomains in every one of 3 consecutive scan runs).
    http_checked_at: Mapped[datetime.datetime | None]
    http_live: Mapped[bool | None]


class Service(Base):
    __tablename__ = "service"

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("discovered_asset.id"), nullable=False)
    port: Mapped[int | None]
    protocol: Mapped[str | None] = mapped_column(String)
    transport: Mapped[str | None] = mapped_column(String)
    product: Mapped[str | None] = mapped_column(String)
    version: Mapped[str | None] = mapped_column(String)
    tls_info: Mapped[dict | None] = mapped_column(JSONB)
    http_headers: Mapped[dict | None] = mapped_column(JSONB)
    tech_stack: Mapped[dict | None] = mapped_column(JSONB)
