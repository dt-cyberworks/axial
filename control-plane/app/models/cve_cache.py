import datetime
import uuid

from sqlalchemy import Numeric, SmallInteger, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import uuid_pk


class CveLookupCache(Base):
    """Read-through cache of NVD candidate CVEs per product name
    (REQ-CORR-001/004). Cached at product-name granularity: a new detected
    version of an already-cached product needs a local version-range check
    against `candidates`, not a new NVD request."""

    __tablename__ = "cve_lookup_cache"

    id: Mapped[uuid.UUID] = uuid_pk()
    product_key: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    candidates: Mapped[list] = mapped_column(JSONB, nullable=False)
    fetched_at: Mapped[datetime.datetime] = mapped_column(nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False, server_default="nvd")


class EpssScoreCache(Base):
    """Cached current EPSS probability per CVE ID (REQ-CORR-002/004)."""

    __tablename__ = "epss_score_cache"

    cve_id: Mapped[str] = mapped_column(String, primary_key=True)
    epss: Mapped[float] = mapped_column(Numeric(5, 4), nullable=False)
    fetched_at: Mapped[datetime.datetime] = mapped_column(nullable=False)


class KevCatalogCache(Base):
    """Cached CISA KEV catalog snapshot (REQ-CORR-003/004). Singleton row -
    the whole catalog is loaded into memory once per correlation run, so an
    index over per-CVE rows buys nothing."""

    __tablename__ = "kev_catalog_cache"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, default=1)
    cve_ids: Mapped[list] = mapped_column(JSONB, nullable=False)
    catalog_version: Mapped[str | None] = mapped_column(String)
    fetched_at: Mapped[datetime.datetime] = mapped_column(nullable=False)
