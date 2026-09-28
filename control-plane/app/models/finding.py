import datetime
import uuid

from sqlalchemy import ForeignKey, Numeric, String, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import pg_enum, uuid_pk

FindingCategory = pg_enum("finding_category", "cve", "misconfig", "exposure", "logic")
FindingConfidence = pg_enum("finding_confidence", "inferred", "validated")
FindingStatus = pg_enum("finding_status", "open", "accepted_risk", "resolved", "false_positive")
SeverityLevel = pg_enum("severity_level", "info", "low", "medium", "high", "critical")


class Finding(Base):
    """Der Ergebnis-Kern. confidence='validated' = nicht-destruktiv nachgewiesen (Kap. 2.4)."""

    __tablename__ = "finding"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("discovered_asset.id"))
    service_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("service.id"))
    category: Mapped[str] = mapped_column(FindingCategory, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    cve_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    cvss_base: Mapped[float | None] = mapped_column(Numeric(3, 1))
    epss: Mapped[float | None] = mapped_column(Numeric(5, 4))
    confidence: Mapped[str] = mapped_column(FindingConfidence, nullable=False)
    status: Mapped[str] = mapped_column(FindingStatus, nullable=False, server_default="open")
    # REQ-TRIAGE-001: the last status change - its justification, when, and by whom
    # (an operator e-mail, or "scan" when a re-observation reopened a resolved finding).
    status_note: Mapped[str | None] = mapped_column(String)
    status_changed_at: Mapped[datetime.datetime | None]
    status_changed_by: Mapped[str | None] = mapped_column(String)
    evidence: Mapped[dict | None] = mapped_column(JSONB)
    raw_ref: Mapped[str | None] = mapped_column(String)
    # Persistiert (nicht nur transient bei Erstellung), damit die score-Phase
    # (Kap. 4.1/5.2) den KEV-Override bei jeder Neuberechnung respektieren
    # kann - ohne dieses Feld verliert ein Rescore die KEV-Einstufung.
    is_kev: Mapped[bool] = mapped_column(server_default="false")
    # Persistiert (nicht nur transient bei Erstellung), damit die score-Phase
    # eine explizit gesetzte Severity (Tool- oder Agent-Einschaetzung, z. B.
    # eine kritische PII-Exposure) bei jeder Neuberechnung respektiert statt
    # sie durch eine generische risk_score-Ableitung zu ueberschreiben
    # (REQ-FIDELITY-004). None = keine Override, severity folgt compute_severity.
    severity_override: Mapped[str | None] = mapped_column(String)
    severity: Mapped[str | None] = mapped_column(SeverityLevel)
    risk_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    first_seen: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)


class FindingObservation(Base):
    """Welcher Fingerprint wurde in welchem scan_run beobachtet - Grundlage des
    Scan-Diffs (neu/behoben zwischen Laeufen). Findings sind engagement-weit und
    dedupliziert; DIESE Tabelle gibt die Pro-Lauf-Granularitaet."""

    __tablename__ = "finding_observation"

    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_run.id"), primary_key=True
    )
    fingerprint: Mapped[str] = mapped_column(String, primary_key=True)
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("finding.id"), nullable=False)
    observed_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
