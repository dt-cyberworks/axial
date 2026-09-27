import datetime
import uuid

from sqlalchemy import ForeignKey, Integer, LargeBinary, String, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class Report(Base):
    """Ein generierter Kunden-Report (REQ-REPORT-001, Architektur Kap. 6.1).

    Der Report wird beim Erzeugen persistiert, nicht nur gestreamt: er ist das
    Kundenprodukt und muss danach unveraendert erneut abrufbar sein (der
    Kunde hat GENAU dieses PDF bekommen). Ein spaeterer Scan-Lauf aendert
    Findings - ein bereits ausgelieferter Report darf sich dadurch nicht
    rueckwirkend aendern.

    Der PDF-Inhalt liegt bewusst in Postgres statt in MinIO: diese Dokumente
    sind reiner, gewrappter Text (typisch <100 KB), und der S3-Pfad ist heute
    von keinem Code benutzt - eine neue Abhaengigkeit plus Credentials fuer
    ein paar Kilobyte waere zusaetzliche Ausfallflaeche ohne Gegenwert.
    """

    __tablename__ = "report"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False
    )
    # NULL = manuell angefordert ohne Bezug auf einen bestimmten Lauf.
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_run.id")
    )
    # "queued" -> "done" | "failed". Die Erzeugung selbst ist synchron (reine
    # DB-Reads + Textrendering, kein Netzwerk), der Status bleibt aber im
    # Modell, weil die dokumentierte API (Kap. 6.3) ein Job-Contract ist.
    status: Mapped[str] = mapped_column(String, nullable=False, server_default="queued")
    error: Mapped[str | None] = mapped_column(String)
    # Wer den Report angefordert hat: "user:<email>" oder "pipeline".
    requested_by: Mapped[str] = mapped_column(String, nullable=False)
    filename: Mapped[str] = mapped_column(String, nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    # Integritaetsnachweis: beweist, dass ein spaeterer Download exakt das
    # Dokument ist, dessen Erzeugung im Audit-Trail steht.
    sha256: Mapped[str | None] = mapped_column(String(64))
    content: Mapped[bytes | None] = mapped_column(LargeBinary)
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
