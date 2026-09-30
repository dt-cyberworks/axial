import datetime
import uuid

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
    status_note: str | None = None
    status_changed_at: datetime.datetime | None = None
    status_changed_by: str | None = None
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


FINDING_STATUSES = ("open", "accepted_risk", "false_positive", "resolved")
SEVERITIES = ("critical", "high", "medium", "low", "info")
# A decision that makes a finding disappear from the open list must say why.
NOTE_REQUIRED_STATUSES = ("accepted_risk", "false_positive")


class FindingTriageIn(BaseModel):
    """REQ-TRIAGE-001: an operator's decision about one finding."""

    status: Literal["open", "accepted_risk", "false_positive", "resolved"]
    note: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def _note_where_required(self) -> "FindingTriageIn":
        self.note = (self.note or "").strip() or None
        if self.status in NOTE_REQUIRED_STATUSES and (self.note is None or len(self.note) < 3):
            raise ValueError(f"a note of at least 3 characters is required for status {self.status!r}")
        return self


class EngagementSummary(BaseModel):
    """GET /engagements/{id}/summary (Architektur Kap. 6.3)."""

    risk_ampel: str  # rot|orange|gelb|blau|gruen
    counts_by_severity: dict[str, int]
    # REQ-TRIAGE-003: every status, so the console can label its status tabs.
    counts_by_status: dict[str, int] = {}
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


class PortfolioFindingOut(FindingOut):
    """REQ-PORTFOLIO-001: a finding in the cross-engagement list."""

    engagement_title: str


class FindingPage(BaseModel):
    """REQ-PORTFOLIO-001: one page of GET /findings. `total` and the counts
    cover every match the caller may see, not only this page."""

    items: list[PortfolioFindingOut]
    total: int
    limit: int
    offset: int
    counts_by_status: dict[str, int]
    counts_by_severity: dict[str, int]
