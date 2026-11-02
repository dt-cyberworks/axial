import datetime
import uuid

from sqlalchemy import Boolean, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk

OPEN_REQUEST_STATES = ("open", "sent", "rejected", "expired", "superseded")


class OpenRequest(Base):
    """A request an unattended run could not get a decision for, kept whole (REQ-RETEST-004).

    `call` is the exact tool call the gateway judged, so that sending it later is a decision about that request and
    nothing else. It is never executed from this row: confirming creates a new approval for a new run
    (REQ-RETEST-006) and the unchanged claim path executes it."""

    __tablename__ = "open_request"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    source_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_run.id", ondelete="SET NULL")
    )
    source_approval_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True))
    tool: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    method: Mapped[str | None] = mapped_column(String)
    path: Mapped[str | None] = mapped_column(String)
    call: Mapped[dict] = mapped_column(JSONB, nullable=False)
    rationale: Mapped[str] = mapped_column(String, nullable=False, server_default="")
    risk: Mapped[dict | None] = mapped_column(JSONB)
    state_changing: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    reason: Mapped[str] = mapped_column(String, nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String, nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False, server_default="open")
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    decided_at: Mapped[datetime.datetime | None]
    decided_by: Mapped[str | None] = mapped_column(String)
    sent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_run.id", ondelete="SET NULL")
    )
    sent_approval_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True))
