import datetime
import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class AssetReviewRequest(Base):
    """Post-Discovery-Review-Pause: einmalig, ablaufend, ein Review je scan_run
    (REQ-ASSETREVIEW-002). candidate_assets ist ein Snapshot der zum
    Erstellungszeitpunkt in-scope entdeckten Assets - stabil, auch wenn sich
    discovered_asset danach aendert."""

    __tablename__ = "asset_review_request"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("scan_run.id"), nullable=False, unique=True)
    candidate_assets: Mapped[list] = mapped_column(JSONB, nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False, server_default="pending")
    excluded_values: Mapped[list | None] = mapped_column(JSONB)
    expires_at: Mapped[datetime.datetime] = mapped_column(nullable=False)
    decided_at: Mapped[datetime.datetime | None]
    decided_by: Mapped[str | None] = mapped_column(String)
