import datetime
import uuid

from sqlalchemy import ForeignKey, Numeric, String, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import pg_enum, uuid_pk

EngagementStatus = pg_enum(
    "engagement_status",
    "draft", "awaiting_signature", "active", "paused", "completed", "revoked",
)
EngagementSource = pg_enum("engagement_source", "lab", "own_domain", "bug_bounty", "customer", "benchmark")


class Customer(Base):
    __tablename__ = "customer"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String, nullable=False)
    contact_email: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class Engagement(Base):
    """Die Rechtsgrundlage jedes aktiven Scans (Architektur Kap. 2.1)."""

    __tablename__ = "engagement"

    id: Mapped[uuid.UUID] = uuid_pk()
    customer_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("customer.id"))
    title: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(EngagementStatus, nullable=False, server_default="draft")
    source: Mapped[str] = mapped_column(EngagementSource, nullable=False)

    scope_doc_sha256: Mapped[str | None] = mapped_column(String(64))
    scope_signed_by: Mapped[str | None] = mapped_column(String)
    scope_signed_at: Mapped[datetime.datetime | None]

    authorized_from: Mapped[datetime.datetime]
    authorized_until: Mapped[datetime.datetime]
    emergency_contact: Mapped[str | None] = mapped_column(String)
    # Opt-in fuer autonome KI-Aktionen (Vector Agent, phase='agent'), alle sources.
    ai_testing_allowed: Mapped[bool] = mapped_column(server_default="false")
    # Persistierte, rechtlich autorisierte Nmap-Envelopes. Der Worker darf
    # diese Werte nie pro Lauf verbreitern. Gleiche TCP-Grenzen = Einzelport.
    tcp_port_from: Mapped[int] = mapped_column(server_default="1")
    tcp_port_to: Mapped[int] = mapped_column(server_default="65535")
    udp_discovery_enabled: Mapped[bool] = mapped_column(server_default="false")
    # Kampagnen-Override der Agent-Anweisung (Schicht 5). NULL/leer -> globaler
    # Default (app_setting['agent_prompt']) bzw. eingebauter Prompt im Worker.
    agent_prompt_override: Mapped[str | None] = mapped_column(String, nullable=True)
    # Kampagnen-Override des Agent-Iterationsbudgets (REQ-AGENT-008).
    # NULL -> globaler Default (app_setting['agent_max_iterations'], sonst 50).
    agent_max_iterations_override: Mapped[int | None] = mapped_column(nullable=True)
    # Kampagnen-Override des Completion-Token-Limits (REQ-AGENT-026).
    # NULL -> globaler Default (app_setting['agent_max_tokens'], sonst 8192).
    agent_max_tokens_override: Mapped[int | None] = mapped_column(nullable=True)
    # Kampagnen-Override der Freigabe-Ablauffrist (REQ-APPROVAL-005). NULL ->
    # globaler Default (app_setting['approval_timeout_seconds'], sonst 900s).
    approval_timeout_seconds_override: Mapped[int | None] = mapped_column(nullable=True)
    # Opt-in Pause zwischen discovery und fingerprint: Operator prueft die
    # in-scope entdeckten Assets und kann einzelne ausschliessen, bevor der Rest
    # der Pipeline sie beruehrt (REQ-ASSETREVIEW-001). Default false = kein
    # Verhaltensunterschied zu vorher.
    asset_review_enabled: Mapped[bool] = mapped_column(server_default="false")
    # Per-Engagement-Schalter fuer erweiterte Entdeckung (REQ-COVER-007). Sie
    # koennen nur verengen: das Gateway erzwingt sie bei jedem Tool-Aufruf.
    subfinder_enabled: Mapped[bool] = mapped_column(server_default="true")
    crawling_enabled: Mapped[bool] = mapped_column(server_default="false")
    oob_enabled: Mapped[bool] = mapped_column(server_default="false")
    screenshots_enabled: Mapped[bool] = mapped_column(server_default="false")
    # REQ-PIPE-005: scan depth. `standard` selects checks from what the scan
    # observed; `thorough` runs every template on every web surface. Neither
    # widens scope, grants or switches.
    scan_profile: Mapped[str] = mapped_column(String(16), nullable=False, server_default="standard")
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    # REQ-IAM-007/021: wer dieses Engagement angelegt hat/besitzt. Immer gesetzt
    # (NOT NULL, Migration 0038): lesen darf jeder angemeldete Nutzer, aendern nur
    # der Owner oder ein Admin (REQ-IAM-022/023).
    owner_user_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("app_user.id"), nullable=False)


ScopeRule = pg_enum("scope_rule", "allow", "deny")
AssetType = pg_enum("asset_type", "domain", "wildcard", "ip", "cidr", "cloud_account")


class ScopeAsset(Base):
    """Was getestet werden DARF/NICHT DARF. rule='deny' hat immer Vorrang (Kap. 2.1/2.2)."""

    __tablename__ = "scope_asset"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False)
    rule: Mapped[str] = mapped_column(ScopeRule, nullable=False, server_default="allow")
    asset_type: Mapped[str] = mapped_column(AssetType, nullable=False)
    value: Mapped[str] = mapped_column(String, nullable=False)
    path_pattern: Mapped[str | None] = mapped_column(String)
    authorization_verified: Mapped[bool] = mapped_column(server_default="false")
    authorization_method: Mapped[str | None] = mapped_column(String)
    active_allowed: Mapped[bool] = mapped_column(server_default="false")
    # REQ-PORTSCOPE-001: NULL = inherit the engagement's tcp_port_from/to
    # ceiling in full. When set, always re-intersected with that ceiling at
    # every enforcement point (egress-proxy, raw_egress_lease) - never
    # trusted alone, so narrowing the ceiling later narrows this too.
    port_from: Mapped[int | None] = mapped_column(nullable=True)
    port_to: Mapped[int | None] = mapped_column(nullable=True)


ToolCategory = pg_enum("tool_category", "recon", "fingerprint", "vuln", "cred", "exploit")
ScanMode = pg_enum("scan_mode", "passive", "active")


class ToolGrant(Base):
    """Welche Tool-Kategorien fuer diesen Auftrag erlaubt sind (Kap. 2.2)."""

    __tablename__ = "tool_grant"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id"), primary_key=True
    )
    tool_category: Mapped[str] = mapped_column(ToolCategory, primary_key=True)
    mode: Mapped[str] = mapped_column(ScanMode, primary_key=True)
    requires_manual_approval: Mapped[bool] = mapped_column(server_default="true")


class ToolApprovalPolicy(Base):
    """Per-Tool-Kampagnen-Policy (Schicht 4). Ueberschreibt die globale
    Tool-Policy fuer GENAU diese Kampagne: erzwingt Einzel-Freigabe
    (requires_manual_approval) und/oder schaltet das Tool an/aus (enabled).
    enabled=NULL erbt die globale Policy."""

    __tablename__ = "tool_approval_policy"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagement.id"), primary_key=True
    )
    tool_name: Mapped[str] = mapped_column(String, primary_key=True)
    requires_manual_approval: Mapped[bool] = mapped_column(server_default="true")
    enabled: Mapped[bool | None] = mapped_column(nullable=True)  # NULL = globale Policy erben
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class BountyProgram(Base):
    """Maschinenlesbare Programm-Policy fuer source='bug_bounty' (Kap. 2.3)."""

    __tablename__ = "bounty_program"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("engagement.id"), nullable=False)
    platform: Mapped[str] = mapped_column(String, nullable=False)
    program_ref: Mapped[str] = mapped_column(String, nullable=False)
    automation_allowed: Mapped[bool] = mapped_column(nullable=False)
    ai_testing_allowed: Mapped[bool] = mapped_column(nullable=False)
    max_rps: Mapped[float] = mapped_column(Numeric(5, 2), server_default="2.0")
    max_concurrency: Mapped[int] = mapped_column(server_default="2")
    ident_header_name: Mapped[str] = mapped_column(String, server_default="X-Bug-Bounty")
    ident_header_value: Mapped[str | None] = mapped_column(String)
    ua_suffix: Mapped[str | None] = mapped_column(String)
    # GitHub issue #37: explicit, narrow per-program network-scanning
    # capability model - default 'none' preserves the pre-existing blanket
    # host_discovery-only behavior (REQ-CIDRDISC-005) for every row that
    # never sets this. See migration 0029 for the full rationale.
    tcp_syn_scan_profile: Mapped[str] = mapped_column(String, server_default="none")
    # Deliberately DISTINCT from max_rps (an HTTP request-rate concept) -
    # conflating the two was itself part of the gap this issue reports.
    raw_max_packets_per_second: Mapped[float | None] = mapped_column(Numeric(6, 2))
    network_scan_authorization_evidence: Mapped[str | None] = mapped_column(String)
