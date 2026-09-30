import datetime
import uuid

from sqlalchemy import ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import pg_enum, uuid_pk

ScanPhase = pg_enum(
    "scan_phase", "discovery", "fingerprint", "correlate", "agent", "validate", "score", "report"
)
ScanState = pg_enum("scan_state", "running", "waiting_approval", "done", "failed", "aborted")


class ScanRun(Base):
    """Phasen-Pipeline als Zustandsmaschine (Architektur Kap. 4.1)."""

    __tablename__ = "scan_run"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False)
    started_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    finished_at: Mapped[datetime.datetime | None]
    # Liveness-Heartbeat (REQ-RAWLEASE-001): der Worker frischt ihn auf, solange
    # der Lauf Fortschritt macht; die control-plane erntet Laeufe mit veraltetem
    # Heartbeat, damit ein abgestuerzter/haengender Lauf neue Scans nicht blockiert.
    heartbeat_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    phase: Mapped[str] = mapped_column(ScanPhase, nullable=False, server_default="discovery")
    state: Mapped[str] = mapped_column(ScanState, nullable=False, server_default="running")
    budget_tool_calls_max: Mapped[int] = mapped_column(server_default="200")
    budget_tool_calls_used: Mapped[int] = mapped_column(server_default="0")
    # Kooperativer Stopp: Operator setzt cancel_requested, der Worker prueft es an
    # Phasengrenzen + in der Agent-Schleife und beendet sauber. state_reason haelt
    # fest, WARUM ein Lauf endete (cancelled_by_operator / failed:<...>).
    cancel_requested: Mapped[bool] = mapped_column(server_default="false")
    state_reason: Mapped[str | None] = mapped_column(String)
    # REQ-FIDELITY-006: welches Tool gerade laeuft (Live-Activity-Banner). Der
    # Worker setzt es unmittelbar vor Dispatch und loescht es (NULL) sobald das
    # Ergebnis vorliegt - best effort, darf den Scan nie beeinflussen.
    current_tool: Mapped[str | None] = mapped_column(String)
    current_target: Mapped[str | None] = mapped_column(String)
    current_started_at: Mapped[datetime.datetime | None]
    # GitHub issue #42 (REQ-RESUME-001): worker takeover after a crash. `attempt`
    # fences every worker write, `checkpoint` carries what the next phase needs.
    attempt: Mapped[int] = mapped_column(server_default="0")
    owner_task_id: Mapped[str | None] = mapped_column(String)
    checkpoint: Mapped[dict | None] = mapped_column(JSONB)
    # REQ-PIPE-005: the scan depth this run was started with (the engagement's
    # setting at that moment; a later change does not rewrite history).
    scan_profile: Mapped[str | None] = mapped_column(String(16))


class AgentStep(Base):
    """Pro Vector-Agent-Iteration: der an das Modell gesendete Kontext und dessen
    Antwort - Grundlage des GUI-Drilldowns (Transparenz, REQ-RUN-006). Der
    api_key wird NIE gespeichert."""

    __tablename__ = "agent_step"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("scan_run.id"), nullable=False)
    iteration: Mapped[int] = mapped_column(nullable=False)
    request_messages: Mapped[list] = mapped_column(JSONB, nullable=False)
    response_text: Mapped[str | None] = mapped_column(String)
    response_tool_calls: Mapped[list | None] = mapped_column(JSONB)
    stop_reason: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
