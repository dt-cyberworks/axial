import datetime
import uuid

from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RateReservation(Base):
    """GitHub issue #40: a reserved rate-limit slot (see app/gateway/rate_reservation.py)."""

    __tablename__ = "rate_reservation"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    engagement_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False)
    path: Mapped[str] = mapped_column(String, nullable=False)  # 'gateway' | 'proxy'
    ts: Mapped[datetime.datetime] = mapped_column(nullable=False)
