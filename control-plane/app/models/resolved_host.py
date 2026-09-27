import datetime
import uuid

from sqlalchemy import ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class ResolvedHost(Base):
    """Auditierte DNS-Materialisierung eines freigegebenen Namens zu einer IP.

    Grundlage fuer raw egress (nmap): Domain-/Wildcard-Scope kann keine
    K8s-NetworkPolicy direkt erlauben. Die control-plane loest die
    freigegebenen Namen auf, wendet deny-Vorrang auf IP-Ebene an und haelt das
    Ergebnis hier fest (s. app/gateway/dns_materialization.py)."""

    __tablename__ = "resolved_host"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False
    )
    scope_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scope_asset.id")
    )
    hostname: Mapped[str] = mapped_column(String, nullable=False)
    ip_address: Mapped[str] = mapped_column(String, nullable=False)
    resolved_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
