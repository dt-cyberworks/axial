import datetime
import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class ApprovalRequest(Base):
    """Human-in-the-loop: einmalige, ablaufende Freigabe (Architektur Kap. 3.3)."""

    __tablename__ = "approval_request"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False)
    tool_call: Mapped[dict] = mapped_column(JSONB, nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False, server_default="requested")
    approved_by: Mapped[str | None] = mapped_column(String)
    approved_at: Mapped[datetime.datetime | None]
    expires_at: Mapped[datetime.datetime]
    execution_started_at: Mapped[datetime.datetime | None]
    execution_finished_at: Mapped[datetime.datetime | None]
    execution_error: Mapped[str | None] = mapped_column(String)
