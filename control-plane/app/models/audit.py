import datetime
import uuid

from sqlalchemy import String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class AuditLog(Base):
    """Append-only, Hash-verkettet (Architektur Kap. 3.4). Kein UPDATE/DELETE, s. Migration."""

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID]
    actor: Mapped[str] = mapped_column(String, nullable=False)     # 'gateway'|'operator:<name>'|'agent'
    action: Mapped[str] = mapped_column(String, nullable=False)    # 'tool_call'|'decision'|'approval'|...
    decision: Mapped[str | None] = mapped_column(String)           # ALLOW|DENY|PENDING
    reason: Mapped[str | None] = mapped_column(String)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    ts: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
