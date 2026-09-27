import datetime
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolCallIn(BaseModel):
    """Spiegelt app.gateway.authorize.ToolCall - Wire-Format fuer den Worker."""

    tool: str
    category: str
    mode: str
    target: str
    path: str | None = None
    args: dict = {}
    is_automated: bool = True
    phase: str = "scan"
    rationale: str | None = None
    risk: dict | None = None
    # Required for target-touching pipeline/agent calls. It binds authorization
    # and cancellation to one exact run instead of whichever run is newest.
    scan_run_id: uuid.UUID | None = None


class DecisionOut(BaseModel):
    allowed: bool
    reason: str
    is_pending: bool = False
    approval_request_id: uuid.UUID | None = None
    is_throttled: bool = False
    retry_after_seconds: float | None = None


class ApprovalClaimOut(BaseModel):
    allowed: bool
    reason: str
    is_throttled: bool = False
    retry_after_seconds: float | None = None
    tool_call: dict | None = None


class ApprovalExecutionResult(BaseModel):
    success: bool
    error: str | None = None


class AgentEventIn(BaseModel):
    event: str
    decision: str | None = None
    reason: str | None = None
    payload: dict = {}


class ProxyAuditEventIn(BaseModel):
    decision: str
    reason: str
    payload: dict = {}


class ToolExecutionEventIn(BaseModel):
    scan_run_id: uuid.UUID | None = None
    tool: str = Field(min_length=1, max_length=64)
    phase: str = Field(min_length=1, max_length=32)
    authorized_target: str = Field(min_length=1, max_length=255)
    resolved_target: str | None = Field(default=None, max_length=255)
    port_range: str | None = Field(default=None, max_length=100)
    success: bool
    exit_code: int | None = None
    error_reason: str | None = Field(default=None, max_length=100)
    stderr_summary: str | None = Field(default=None, max_length=1000)
    discovered_services: int = Field(default=0, ge=0, le=65535)
    outcome_summary: dict = {}
    # REQ-AUDIT-003: the exact invocation used, redacted worker-side
    # (REQ-AUDIT-004). Bounded here too - the control-plane never trusts a
    # client-supplied length for something it writes to durable audit storage.
    command: str | None = Field(default=None, max_length=4000)
    # REQ-AUDIT-006/007: the full http_request response, redacted worker-side
    # (command_redaction.redact_http_response). Bounded to match the runner's
    # own already-justified response cap (`head -c 16384`) - this field never
    # legitimately exceeds what the runner itself produced.
    response: str | None = Field(default=None, max_length=16384)


class RawEgressPolicyOut(BaseModel):
    policy: dict
    ip_blocks: list[dict]
    omitted_assets: list[dict]
    warnings: list[str]


class RawEgressLeaseIn(BaseModel):
    scan_run_id: uuid.UUID
    authorized_target: str = Field(min_length=1, max_length=255)
    resolved_target: str = Field(min_length=1, max_length=64)
    phase: Literal["fingerprint", "agent"] = "fingerprint"
    port_profile: Literal[
        "full_tcp", "configured_tcp", "targeted_udp", "raw_tcp_probe", "host_discovery",
    ] = "configured_tcp"
    # REQ-AGENT-025: the real tool the Scope Gateway should authorize against -
    # nmap's own grant/args-safety policy must never be consulted on behalf of
    # a different tool (or vice versa). Only meaningful when port_profile
    # differs from nmap's own three profiles.
    tool: Literal["nmap", "redis-probe", "activemq-banner"] = "nmap"
    # REQ-AGENT-025: only meaningful (and required) for port_profile="raw_tcp_probe" -
    # the single port a curated raw-protocol check (redis-probe/activemq-banner)
    # needs, resolved by the worker (REQ-FIDELITY-007's single_port, or the
    # protocol's own conventional default). Re-validated server-side against
    # the engagement's configured TCP range - never trusted from the caller alone.
    port: int | None = Field(default=None, ge=1, le=65535)


class RawEgressLeaseOut(BaseModel):
    allowed: bool
    reason: str
    is_pending: bool = False
    approval_request_id: uuid.UUID | None = None
    is_throttled: bool = False
    retry_after_seconds: float | None = None
    lease_token: str | None = None
    lease_id: uuid.UUID | None = None
    expires_at: datetime.datetime | None = None
    port_profile: str | None = None
    port_range: str | None = None
    protocol: str | None = None
    udp_discovery_enabled: bool = False
    max_rate: int | None = None
    port: int | None = None


class MaterializeDnsOut(BaseModel):
    resolved: list[dict]      # [{hostname, ip_address, scope_asset_id}]
    denied_ips: list[dict]    # aufgeloest, aber per deny-IP/CIDR verworfen
    unresolved: list[str]     # Namen ohne A/AAAA-Record
    warnings: list[str]


class ScanRunCreate(BaseModel):
    budget_tool_calls_max: int = 200


class ScanRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    phase: str
    state: str
    budget_tool_calls_max: int
    budget_tool_calls_used: int
    # Fuer die Scan-Historie: Start/Ende je Lauf (Dauer wird im Frontend berechnet).
    started_at: datetime.datetime | None = None
    finished_at: datetime.datetime | None = None
    # Kooperativer Stopp (REQ-RUN-001): Stopp angefordert? + warum ein Lauf endete.
    cancel_requested: bool = False
    state_reason: str | None = None
    # REQ-FIDELITY-006: aktuell laufendes Tool (Live-Activity-Banner), NULL
    # wenn gerade kein Tool dispatcht ist.
    current_tool: str | None = None
    current_target: str | None = None
    current_started_at: datetime.datetime | None = None


class ScanRunUpdate(BaseModel):
    phase: str | None = None
    state: str | None = None
    state_reason: str | None = None
    increment_tool_calls: int = 0
    # Optional (REQ-FIDELITY-006): nur angewendet, wenn im Request-Body
    # tatsaechlich gesetzt (model_fields_set) - sonst wuerden bestehende
    # phase/state-only-Aufrufe das aktuelle Tool versehentlich loeschen.
    current_tool: str | None = None
    current_target: str | None = None


class AgentStepIn(BaseModel):
    scan_run_id: uuid.UUID
    iteration: int
    request_messages: list = []
    response_text: str | None = None
    response_tool_calls: list | None = None
    stop_reason: str | None = None


class DiscoveredAssetIn(BaseModel):
    asset_type: str
    value: str
    discovered_via: str
    in_scope: bool
    parent_id: uuid.UUID | None = None


class HttpProbeResultIn(BaseModel):
    live: bool


class AssetReviewCreateIn(BaseModel):
    """REQ-ASSETREVIEW-002: candidate_assets ist der Snapshot der aktuell
    in-scope entdeckten Assets fuer genau diesen scan_run."""
    candidate_assets: list[dict]


class DnsRecordIn(BaseModel):
    asset_id: uuid.UUID | None = None
    fqdn: str
    cname_chain: list[str] = []
    terminal_target: str | None = None
    terminal_ips: list[str] = []
    hosting_provider: str | None = None
    is_cdn: bool = False
    is_saas: bool = False
    is_idp: bool = False
    is_shared_infra: bool = False
    dns_status: str = "resolved"
    takeover_suspected: bool = False


class ServiceIn(BaseModel):
    asset_id: uuid.UUID
    port: int | None = None
    protocol: str | None = None
    transport: str | None = None
    product: str | None = None
    version: str | None = None
    tls_info: dict | None = None
    http_headers: dict | None = None
    tech_stack: dict | None = None


class FindingIn(BaseModel):
    asset_id: uuid.UUID | None = None
    service_id: uuid.UUID | None = None
    category: str
    title: str
    cve_ids: list[str] | None = None
    cvss_base: float | None = None
    epss: float | None = None
    is_kev: bool = False
    confidence: str
    evidence: dict | None = None
    raw_ref: str | None = None
    exposure_factor: float = 1.0
    business_factor: float = 0.5
    # Tool-gelieferte Severity (nuclei/testssl bewerten selbst). Wenn gesetzt,
    # wird sie direkt uebernommen statt aus dem Risk-Score berechnet - der
    # Score wird aber weiterhin gerechnet (fuer Priorisierung/Sortierung).
    severity_override: str | None = None


# --- Live NVD/EPSS/KEV correlation cache (REQ-CORR-001..008) ---

class CveLookupCacheOut(BaseModel):
    product_key: str
    candidates: list[dict]
    fetched_at: datetime.datetime
    source: str


class CveLookupCacheIn(BaseModel):
    product_key: str
    candidates: list[dict]
    source: str = "nvd"


class EpssCacheOut(BaseModel):
    scores: dict[str, float]  # cve_id -> epss, only cache hits
    fetched_at: dict[str, datetime.datetime]


class EpssCacheEntryIn(BaseModel):
    cve_id: str
    epss: float


class EpssCacheBatchIn(BaseModel):
    entries: list[EpssCacheEntryIn]


class KevCatalogCacheOut(BaseModel):
    cve_ids: list[str]
    catalog_version: str | None = None
    fetched_at: datetime.datetime | None = None


class KevCatalogCacheIn(BaseModel):
    cve_ids: list[str]
    catalog_version: str | None = None


class NvdConfigOut(BaseModel):
    api_key: str | None = None
    source: str  # "db" | "env" | "unset"


class OpenwireCallbackTokenCreate(BaseModel):
    scan_run_id: uuid.UUID | None = None


class OpenwireCallbackTokenOut(BaseModel):
    token: str
    callback_url: str
    expires_at: datetime.datetime


class OpenwireCallbackStatusOut(BaseModel):
    triggered: bool
    triggered_at: datetime.datetime | None = None


class BenchmarkEngagementCreate(BaseModel):
    """REQ-BENCH-007: the benchmark harness's own engagement-creation path.
    source is NOT a client-supplied field here - the endpoint forces
    source='benchmark' server-side, unlike the operator-facing EngagementCreate."""
    title: str
    target_host: str
    tcp_port_from: int
    tcp_port_to: int
    tool_categories: list[str] = ["recon", "fingerprint", "vuln"]
