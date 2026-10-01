import datetime
import ipaddress
import re
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# GitHub issue #35: deliberately permissive, not a strict RFC-1035 validator.
# This codebase's own lab fixtures use bare internal Docker hostnames with no
# dot at all ("metasploitable2") as legitimate domain-type scope values (see
# worker/app/tasks/discovery.py's own docstring: "ein Scope-Wert ohne Punkt
# kann kein echter DNS-Name sein" is the justification for treating THOSE
# specially, not a claim that a dotless value is invalid input), and existing
# wildcard scope assets use bare fnmatch patterns with no leading "*."
# ("metasploit*", "*.example" - see control-plane/tests/integration/
# test_raw_egress_lease.py and test_asset_review.py). The goal here is
# rejecting obviously-wrong input (a URL, a path, whitespace, a stray "@") at
# create time instead of it silently matching nothing forever - not
# re-validating DNS syntax the rest of the stack never required.
_HOSTNAME_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_HOSTNAME_LABEL}(\.{_HOSTNAME_LABEL})*\.?$")
_WILDCARD_RE = re.compile(r"^[A-Za-z0-9*?.\-\[\]!]+$")
_MAX_HOSTNAME_LENGTH = 253


class EngagementCreate(BaseModel):
    title: str
    source: str = "own_domain"  # internal policy profile; hidden in the default operator wizard
    customer_id: uuid.UUID | None = None
    authorized_from: datetime.datetime
    authorized_until: datetime.datetime
    emergency_contact: str | None = None
    ai_testing_allowed: bool = False
    tcp_port_from: int = Field(default=1, ge=1, le=65535)
    tcp_port_to: int = Field(default=65535, ge=1, le=65535)
    udp_discovery_enabled: bool = False
    asset_review_enabled: bool = False
    subfinder_enabled: bool = True
    crawling_enabled: bool = False
    oob_enabled: bool = False
    screenshots_enabled: bool = False
    scan_profile: Literal["standard", "thorough"] = "standard"

    @model_validator(mode="after")
    def validate_tcp_port_range(self):
        if self.tcp_port_from > self.tcp_port_to:
            raise ValueError("tcp_port_from must be less than or equal to tcp_port_to")
        return self


class EngagementToolOverride(BaseModel):
    tool: str
    enabled: bool | None = None       # None = globale Policy erben
    requires_approval: bool = False   # verschaerft nur (Einzelfreigabe erzwingen)


class EngagementConfigIn(BaseModel):
    """Kampagnen-Overrides (Schicht 4/5)."""
    tools: list[EngagementToolOverride] = []
    # None = agent_prompt_override unveraendert lassen; "" = wieder global erben.
    agent_prompt_override: str | None = None
    # Feld FEHLT im Request -> unveraendert lassen; Feld = null -> Override
    # loeschen (wieder global erben); Feld = Zahl -> Override setzen
    # (REQ-AGENT-008). Unterschieden via model_fields_set, nicht "is not None".
    agent_max_iterations_override: int | None = Field(default=None, ge=1, le=500)
    # Gleiches Muster fuer das Completion-Token-Limit (REQ-AGENT-026).
    agent_max_tokens_override: int | None = Field(default=None, ge=1024, le=32768)
    # Gleiches Muster fuer die Freigabe-Ablauffrist (REQ-APPROVAL-005).
    approval_timeout_seconds_override: int | None = Field(default=None, ge=60, le=86400)


class EngagementUpdate(BaseModel):
    title: str | None = None
    source: str | None = None
    authorized_from: datetime.datetime | None = None
    authorized_until: datetime.datetime | None = None
    emergency_contact: str | None = None
    ai_testing_allowed: bool | None = None
    tcp_port_from: int | None = Field(default=None, ge=1, le=65535)
    tcp_port_to: int | None = Field(default=None, ge=1, le=65535)
    udp_discovery_enabled: bool | None = None
    asset_review_enabled: bool | None = None
    subfinder_enabled: bool | None = None
    crawling_enabled: bool | None = None
    oob_enabled: bool | None = None
    screenshots_enabled: bool | None = None
    scan_profile: Literal["standard", "thorough"] | None = None


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    source: str
    status: str
    ai_testing_allowed: bool = False
    tcp_port_from: int = 1
    tcp_port_to: int = 65535
    udp_discovery_enabled: bool = False
    asset_review_enabled: bool = False
    subfinder_enabled: bool = True
    crawling_enabled: bool = False
    oob_enabled: bool = False
    screenshots_enabled: bool = False
    scan_profile: str = "standard"
    authorized_from: datetime.datetime
    authorized_until: datetime.datetime
    emergency_contact: str | None = None
    created_at: datetime.datetime
    owner_user_id: uuid.UUID | None = None


class EngagementOwnerIn(BaseModel):
    owner_user_id: uuid.UUID


class ScopeAssetCreate(BaseModel):
    rule: Literal["allow", "deny"]
    asset_type: Literal["domain", "wildcard", "ip", "cidr", "cloud_account"]
    value: str
    path_pattern: str | None = None
    active_allowed: bool = False
    authorization_verified: bool = False
    authorization_method: str | None = None
    # REQ-PORTSCOPE-001: None = inherit the engagement's tcp_port_from/to
    # ceiling. When set, both fields are required together and must be a
    # subset of that ceiling (checked in the endpoint, which has the
    # engagement in hand).
    port_from: int | None = Field(default=None, ge=1, le=65535)
    port_to: int | None = Field(default=None, ge=1, le=65535)

    @model_validator(mode="after")
    def validate_port_range(self):
        if (self.port_from is None) != (self.port_to is None):
            raise ValueError("port_from and port_to must be set together")
        if self.port_from is not None and self.port_from > self.port_to:
            raise ValueError("port_from must be less than or equal to port_to")
        return self

    @model_validator(mode="after")
    def validate_and_canonicalize_value(self):
        """GitHub issue #35: rule/asset_type were bare `str` (any string
        accepted) and `value` had no format validation at all - malformed
        input failed, if at all, deep in downstream code (ipaddress.ip_network
        raising ValueError, silently swallowed by several fail-closed
        `except ValueError` branches) rather than being rejected clearly here.
        The maximum-CIDR-size check lives in the endpoint (add_scope_asset),
        not here, since it needs the configured limit from Settings -
        schemas in this codebase stay config-independent (mirrors the
        existing port-range-within-ceiling check, which is also endpoint-side
        for the same reason)."""
        v = self.value.strip()
        if not v:
            raise ValueError("value must not be empty")

        if self.asset_type == "domain":
            if len(v) > _MAX_HOSTNAME_LENGTH or not _DOMAIN_RE.match(v):
                raise ValueError(f"'{v}' is not a valid domain value")
            self.value = v.lower().rstrip(".")
        elif self.asset_type == "wildcard":
            if len(v) > _MAX_HOSTNAME_LENGTH or not _WILDCARD_RE.match(v):
                raise ValueError(f"'{v}' is not a valid wildcard value")
            self.value = v.lower()
        elif self.asset_type == "ip":
            try:
                addr = ipaddress.ip_address(v)
            except ValueError as exc:
                raise ValueError(f"'{v}' is not a valid IP address") from exc
            if addr.version == 6:
                # GitHub issue #35: no test proves an IPv6 scope asset works
                # end-to-end through the raw-egress/nmap chain (the gateway's
                # nftables scaffolding for it is only partial) - rejected
                # explicitly at input time rather than silently accepted and
                # failing somewhere later, per the issue's own acceptable
                # resolutions ("accept-and-test, or reject-with-clear-reason").
                raise ValueError("IPv6 scope is not yet supported end-to-end - use an IPv4 address")
            self.value = str(addr)  # canonical form
        elif self.asset_type == "cidr":
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError as exc:
                raise ValueError(f"'{v}' is not a valid CIDR network") from exc
            if net.version == 6:
                raise ValueError("IPv6 scope is not yet supported end-to-end - use an IPv4 CIDR")
            self.value = str(net)  # canonical form - host bits cleared
        # cloud_account: no canonical/known format anywhere in this codebase
        # (unused beyond exact-string matching in authorize.py) - accepted
        # as-is beyond the empty-string check above.
        return self


class ScopeAssetOut(ScopeAssetCreate):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID


class ScopeAuthorizationVerificationCreate(BaseModel):
    method: str = "operator_attestation"
    verified_by: str = "operator"


ToolCategoryName = Literal["recon", "fingerprint", "vuln", "cred", "exploit"]
ToolGrantMode = Literal["passive", "active"]


class ToolGrantCreate(BaseModel):
    tool_category: ToolCategoryName
    mode: ToolGrantMode
    requires_manual_approval: bool = True
    manual_tools: list[str] = []
    # GitHub issue #48: granting an ACTIVE category on an engagement that has left
    # draft widens what it is authorized to do, so the caller must say it knows.
    confirm_widening: bool = False


class ToolGrantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tool_category: str
    mode: str
    requires_manual_approval: bool = True
    manual_tools: list[str] = []
    engagement_id: uuid.UUID


class BountyProgramCreate(BaseModel):
    platform: str
    program_ref: str
    automation_allowed: bool
    ai_testing_allowed: bool
    max_rps: float = 2.0
    max_concurrency: int = 2
    ident_header_name: str = "X-Bug-Bounty"
    ident_header_value: str | None = None
    ua_suffix: str | None = None
    # GitHub issue #37: explicit, narrow per-program network-scanning
    # capability model. 'none' (default) preserves the pre-existing
    # host_discovery-only blanket policy (REQ-CIDRDISC-005) exactly -
    # opting into anything broader is a deliberate, separate operator
    # action, never inferred from automation_allowed/max_rps alone.
    tcp_syn_scan_profile: Literal["none", "common", "full"] = "none"
    # Deliberately DISTINCT from max_rps (an HTTP request-rate concept) -
    # None falls back to the pre-existing behavior (max_rps used as the raw
    # rate's own proxy) for backward compatibility with programs that never
    # set this.
    raw_max_packets_per_second: float | None = Field(default=None, gt=0, le=1000)
    network_scan_authorization_evidence: str | None = None

    @model_validator(mode="after")
    def validate_full_profile_requires_evidence(self):
        if self.tcp_syn_scan_profile == "full" and not (self.network_scan_authorization_evidence or "").strip():
            raise ValueError(
                "tcp_syn_scan_profile='full' requires network_scan_authorization_evidence "
                "(a recorded reason this is believed authorized) - automation_allowed alone is not sufficient"
            )
        return self


class BountyProgramOut(BountyProgramCreate):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID


class GatewayOverrideCreate(BaseModel):
    reason: str
    tool_call: dict
    approved_by: str = "operator"
    comment: str | None = None


class GatewayOverrideOut(BaseModel):
    applied: list[str]
    message: str
