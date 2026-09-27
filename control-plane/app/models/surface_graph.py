import datetime
import uuid

from sqlalchemy import ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class SurfaceNode(Base):
    """Ein typisierter Knoten des Attack-Surface-Graphen (REQ-GRAPH-001).

    Abgeleitete Metadaten - materialisiert aus discovered_asset(+parent_id),
    service, dns_record, resolved_host und finding. Bewusst KEINE eigene
    Graph-DB: bei ASM-Groessenordnung genuegt ein Knoten/Kanten-Modell in
    Postgres. `scannable` wird AUSSCHLIESSLICH aus discovered_asset.in_scope
    gesetzt; das Scope Gateway liest diese Tabelle nie (REQ-GRAPH-002)."""

    __tablename__ = "surface_node"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False
    )
    node_type: Mapped[str] = mapped_column(String, nullable=False)
    ref_table: Mapped[str] = mapped_column(String, nullable=False)
    ref_id: Mapped[str] = mapped_column(String, nullable=False)
    label: Mapped[str] = mapped_column(String, nullable=False)
    scannable: Mapped[bool] = mapped_column(nullable=False, default=False)
    attrs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    first_seen: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    last_seen: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class SurfaceEdge(Base):
    """Eine typisierte, gerichtete Kante des Attack-Surface-Graphen (REQ-GRAPH-001)."""

    __tablename__ = "surface_edge"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False
    )
    src_node_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("surface_node.id", ondelete="CASCADE"), nullable=False
    )
    dst_node_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("surface_node.id", ondelete="CASCADE"), nullable=False
    )
    edge_type: Mapped[str] = mapped_column(String, nullable=False)
    attrs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
