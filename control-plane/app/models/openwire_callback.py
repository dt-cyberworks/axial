import datetime
import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class OpenwireCallbackToken(Base):
    """A single-use callback token for the OpenWire deserialization probe
    (REQ-AGENT-027). Proving the CVE-2023-46604-class RCE requires observing
    that the TARGET fetched a URL we host - there is no in-band response to
    read. This is the entire state the minimal, purpose-built callback
    receiver needs: whether this exact token was fetched, and when. Nothing
    about the calling target (headers, source IP, body) is stored, by
    design - see the migration's own comment for why.
    """

    __tablename__ = "openwire_callback_token"

    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False
    )
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("scan_run.id"))
    created_at: Mapped[datetime.datetime] = mapped_column(nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(nullable=False)
    triggered_at: Mapped[datetime.datetime | None] = mapped_column()
