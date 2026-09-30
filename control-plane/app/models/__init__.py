"""Alle Modelle hier importieren, damit Base.metadata sie kennt (Alembic-Autogenerate etc.)."""

from app.models.app_setting import AppSetting  # noqa: F401
from app.models.approval import ApprovalRequest  # noqa: F401
from app.models.asset_review import AssetReviewRequest  # noqa: F401
from app.models.asset import DiscoveredAsset, Service  # noqa: F401
from app.models.audit import AuditLog  # noqa: F401
from app.models.cve_cache import CveLookupCache, EpssScoreCache, KevCatalogCache  # noqa: F401
from app.models.dns_record import DnsRecord  # noqa: F401
from app.models.discovery_artifacts import DiscoveredEndpoint, WebScreenshot  # noqa: F401
from app.models.engagement import (  # noqa: F401
    BountyProgram,
    Customer,
    Engagement,
    ScopeAsset,
    ToolApprovalPolicy,
    ToolGrant,
)
from app.models.finding import Finding, FindingObservation  # noqa: F401
from app.models.openwire_callback import OpenwireCallbackToken  # noqa: F401
from app.models.rate_reservation import RateReservation  # noqa: F401
from app.models.report import Report  # noqa: F401
from app.models.resolved_host import ResolvedHost  # noqa: F401
from app.models.scan_plan import ScanCheck, ScanSurface  # noqa: F401
from app.models.scan_run import AgentStep, ScanRun  # noqa: F401
from app.models.surface_graph import SurfaceEdge, SurfaceNode  # noqa: F401
from app.models.user import (  # noqa: F401
    AccountAuditLog,
    LoginChallenge,
    User,
    UserBackupCode,
    UserSession,
)
