import datetime
import uuid

from sqlalchemy import ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class DnsRecord(Base):
    """Passive DNS-Inventar-Metadaten eines in-scope FQDN (Kap. Discovery).

    Beschreibt WIE ein Name aufloest (CNAME-Kette, Terminal, Hosting-Provider,
    Dangling-Status). Bewusst getrennt von der Autorisierung: das hier
    gespeicherte CNAME-Ziel ist NIE ein scanbares Asset und wird NIE nach
    resolved_host materialisiert. Das Scope Gateway bleibt die einzige Instanz,
    die aktives Scannen freigibt. Siehe
    docs/requirements/dns-cname-inventory-and-takeover.md (REQ-DNS-001..003)."""

    __tablename__ = "dns_record"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("discovered_asset.id")
    )
    fqdn: Mapped[str] = mapped_column(String, nullable=False)
    cname_chain: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    terminal_target: Mapped[str | None] = mapped_column(String)
    terminal_ips: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    hosting_provider: Mapped[str | None] = mapped_column(String)
    is_cdn: Mapped[bool] = mapped_column(default=False)
    is_saas: Mapped[bool] = mapped_column(default=False)
    is_idp: Mapped[bool] = mapped_column(default=False)
    is_shared_infra: Mapped[bool] = mapped_column(default=False)
    dns_status: Mapped[str] = mapped_column(String, nullable=False, default="resolved")
    takeover_suspected: Mapped[bool] = mapped_column(default=False)
    resolved_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
