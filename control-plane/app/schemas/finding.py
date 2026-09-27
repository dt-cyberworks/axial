import datetime
import uuid

from pydantic import BaseModel, ConfigDict


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    asset_id: uuid.UUID | None
    service_id: uuid.UUID | None = None
    asset_value: str | None = None
    asset_type: str | None = None
    target_ip: str | None = None
    service_port: int | None = None
    service_protocol: str | None = None
    service_product: str | None = None
    service_version: str | None = None
    category: str
    title: str
    cve_ids: list[str] | None
    cvss_base: float | None
    epss: float | None
    confidence: str
    status: str
    severity: str | None
    risk_score: float | None
    evidence: dict | None = None
    raw_ref: str | None = None
    first_seen: datetime.datetime
    # GitHub issue #15: MAX(finding_observation.observed_at) for this finding -
    # None only for a finding that predates finding_observation tracking or
    # was never re-confirmed by a scan_run (e.g. an inferred/manual finding).
    last_seen: datetime.datetime | None = None


class DnsRecordOut(BaseModel):
    """Passive DNS-Inventar-Metadaten eines FQDN (REQ-DNS-001..003)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID | None
    fqdn: str
    cname_chain: list[str]
    terminal_target: str | None
    terminal_ips: list[str]
    hosting_provider: str | None
    is_cdn: bool
    is_saas: bool
    is_idp: bool
    is_shared_infra: bool
    dns_status: str
    takeover_suspected: bool
    resolved_at: datetime.datetime


class EngagementSummary(BaseModel):
    """GET /engagements/{id}/summary (Architektur Kap. 6.3)."""

    risk_ampel: str  # rot|orange|gelb|blau|gruen
    counts_by_severity: dict[str, int]
    top_actions: list[str]


class FindingExplanationOut(BaseModel):
    finding_id: uuid.UUID
    explanation: str
    source: str
    generated_at: datetime.datetime
    model: str | None = None
    # GitHub issue #14: true when the provider stopped because it hit
    # max_tokens (finish_reason == "length"), not because it finished the
    # answer - the explanation is real but incomplete.
    truncated: bool = False
