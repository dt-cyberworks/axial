"""Generated customer report (REQ-REPORT-001, Architektur Kap. 6.1).

Builds the five specified sections from data already in the database, as a
structured `ReportModel` rather than pre-formatted text:

  1. Executive summary      - risk light, trend vs. the previous run, top 3 actions
  2. Risk overview          - counts by severity + NEW/RESOLVED/PERSIST diff
  3. Detailed findings      - per finding: what, where, proof, remediation
  4. Asset inventory        - discovered assets, services, shadow-IT hints
  5. Methodology & scope    - ⚖ mandatory: scope, window, exclusions, authorization

`app/pdf_report.py` (REQ-REPORT-005) turns this model into the styled PDF.
Keeping the split means this module owns *what* the report says - the facts,
already redacted - while the renderer owns *how it looks*; a layout change
never has to touch a database query, and this module stays testable without
reportlab.

Two deliberate boundaries, unchanged from the original text renderer:

* **No raw tool output.** Kap. 6.2 puts raw requests and tool output in the
  evidence store, not the report. Only scalar, redacted evidence fields are
  summarized; the report says where the full evidence lives instead of
  inlining it.
* **No LLM calls.** Cached Lens explanations (already generated and stored on
  the finding) are reused when present, but generating a report never triggers
  a provider call - that would make a customer deliverable depend on an
  external service being up and would silently change cost/latency on a button
  press. A finding without a cached explanation renders its structured facts.

Everything rendered goes through report_redaction (REQ-REPORT-002).
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import scan_diff
from app.models.asset import DiscoveredAsset, Service
from app.models.dns_record import DnsRecord
from app.models.engagement import Engagement, ScopeAsset
from app.models.finding import Finding
from app.models.scan_run import ScanRun
from app.report_redaction import redact_prose, redact_value, safe_evidence_items

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

_AMPEL_BY_SEVERITY = {"critical": "RED", "high": "RED", "medium": "AMBER", "low": "BLUE", "info": "BLUE"}

_ACTION_BY_CATEGORY = {
    "cve": "Apply the vendor patch or upgrade the affected component to a fixed version.",
    "misconfig": "Correct the configuration on the affected service and re-test.",
    "exposure": "Remove or authenticate the exposed resource so it is not reachable anonymously.",
    "logic": "Review the affected application flow and enforce the missing authorization/validation check.",
}

RISK_RATING_EXPLANATION = (
    "Severity reflects how much damage a finding could do if left unaddressed: "
    "critical and high findings allow an attacker to compromise data, accounts, "
    "or systems directly; medium findings weaken defenses or leak information "
    "that helps a later attack; low and info findings are hygiene issues with "
    "limited standalone impact. The risk score (0-100) additionally weighs "
    "confidence, exploit availability, and observed exploitation to rank "
    "findings of the same severity against each other."
)

DIFF_NOTE = (
    "\"No longer observed\" means this run did not see the finding again. It is the "
    "expected signal after a fix, but it is not by itself proof that the underlying "
    "issue was remediated - confirm the fix on the system itself."
)

DEGRADED_WARNING = (
    "At least one run completed without a load-bearing tool ever succeeding. The results "
    "in this report are therefore incomplete: a short findings list does NOT mean the "
    "attack surface is clean. Re-run the scan before drawing conclusions."
)

METHOD_LINES: tuple[str, ...] = (
    "Phases: discovery, fingerprint, correlate, agent, validate, score, report.",
    "Every active tool call was authorized by the Scope Gateway before execution; deny "
    "rules always take precedence over allow rules, and out-of-scope targets are blocked "
    "rather than tested. Autonomous agent activity proposes checks only - it cannot widen "
    "scope or bypass that gateway.",
    "Testing is non-destructive: findings are confirmed by observation, never by exploiting "
    "or altering the target.",
    "Every authorization decision and tool invocation is recorded in a tamper-evident, "
    "hash-chained audit trail available for inspection.",
)


# --- structured model --------------------------------------------------

@dataclass
class ExecutiveSummary:
    risk_light: str
    worst_severity: str | None
    open_count: int
    trend_line: str
    top_actions: list[str] = field(default_factory=list)


@dataclass
class RiskOverview:
    counts: dict[str, int]
    diff_status: str  # "no_run" | "no_baseline" | "available"
    persisting_count: int = 0
    new_items: list[str] = field(default_factory=list)
    new_total: int = 0
    resolved_items: list[str] = field(default_factory=list)
    resolved_total: int = 0


@dataclass
class FindingRow:
    severity: str
    title: str
    location: str
    category: str
    confidence: str
    risk_score: str
    status: str
    cve_line: str | None
    first_seen: str
    inferred: bool
    explanation_paragraphs: list[str] = field(default_factory=list)
    recommended_action: str | None = None
    evidence_items: list[tuple[str, str]] = field(default_factory=list)
    raw_ref: str | None = None


@dataclass
class AssetRow:
    value: str
    asset_type: str
    in_scope: bool
    discovered_via: str
    service_lines: list[str] = field(default_factory=list)


@dataclass
class AssetInventory:
    rows: list[AssetRow] = field(default_factory=list)
    shadow_it: list[str] = field(default_factory=list)
    cert_note: str = ""


@dataclass
class ScopeRow:
    asset_type: str
    value: str
    ports: str
    active: str
    verified: str


@dataclass
class RunRow:
    started_at: str
    state: str
    phase: str
    reason: str | None
    is_report_run: bool


@dataclass
class MethodologyScope:
    engagement_label: str
    source: str
    authorized_from: str
    authorized_until: str
    scope_doc_sha256: str
    scope_signed_by: str
    emergency_contact: str
    ai_testing_allowed: bool
    allow_rows: list[ScopeRow] = field(default_factory=list)
    deny_rows: list[tuple[str, str]] = field(default_factory=list)
    run_rows: list[RunRow] = field(default_factory=list)
    runs_truncated: int = 0
    no_runs: bool = False
    degraded: bool = False


@dataclass
class AcceptedRiskRow:
    """REQ-TRIAGE-004: a finding the operator accepted, with the stated reason.
    Who decided stays internal (audit log), not in the customer document."""
    severity: str
    title: str
    location: str
    justification: str
    accepted_on: str


@dataclass
class ReportModel:
    generated_at: str
    engagement_title: str
    engagement_id: str
    scan_run_id: str
    executive_summary: ExecutiveSummary
    risk_overview: RiskOverview
    findings: list[FindingRow]
    asset_inventory: AssetInventory
    methodology: MethodologyScope
    accepted_risks: list[AcceptedRiskRow] = field(default_factory=list)
    false_positive_count: int = 0


# --- helpers (format-agnostic; unchanged from the original text renderer) --

def _fmt(value: object) -> str:
    return "-" if value is None or value == "" else str(value)


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts


def _sort_key(finding: Finding) -> tuple[int, float]:
    severity_rank = SEVERITY_ORDER.index(finding.severity) if finding.severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
    return (severity_rank, -float(finding.risk_score or 0))


def _cached_explanation(finding: Finding) -> str | None:
    evidence = finding.evidence
    if not isinstance(evidence, dict):
        return None
    lens = evidence.get("lens_agent")
    if isinstance(lens, dict) and isinstance(lens.get("explanation"), str) and lens["explanation"].strip():
        return lens["explanation"].strip()
    return None


# --- section builders ----------------------------------------------------

def _executive_summary(
    findings: list[Finding], counts: dict[str, int], diff: dict | None,
) -> ExecutiveSummary:
    worst = next((sev for sev in SEVERITY_ORDER if counts[sev] > 0), None)
    light = _AMPEL_BY_SEVERITY.get(worst or "", "GREEN")

    if diff is None:
        trend_line = "No scan run has completed for this engagement yet."
    elif not diff.get("has_baseline"):
        trend_line = "This was the first run, so there is no previous run to compare against (baseline)."
    else:
        trend_line = (
            f"{len(diff.get('new') or [])} new, {len(diff.get('resolved') or [])} no longer observed, "
            f"{diff.get('persisting_count', 0)} unchanged vs. the previous run."
        )

    top = sorted(list(findings), key=_sort_key)[:3]
    top_actions = [
        f"[{_fmt(finding.severity).upper()}] {redact_prose(finding.title)} - "
        f"{_ACTION_BY_CATEGORY.get(finding.category, 'Review and remediate the affected component.')}"
        for finding in top
    ]
    return ExecutiveSummary(
        risk_light=light, worst_severity=worst, open_count=sum(counts.values()),
        trend_line=trend_line, top_actions=top_actions,
    )


def _risk_overview(counts: dict[str, int], diff: dict | None) -> RiskOverview:
    if diff is None:
        return RiskOverview(counts=counts, diff_status="no_run")
    if not diff.get("has_baseline"):
        return RiskOverview(counts=counts, diff_status="no_baseline")

    new_items = diff.get("new") or []
    resolved_items = diff.get("resolved") or []
    return RiskOverview(
        counts=counts,
        diff_status="available",
        persisting_count=diff.get("persisting_count", 0),
        new_items=[
            f"[{_fmt(item.get('severity')).upper()}] {redact_prose(_fmt(item.get('title')))} on {_fmt(item.get('target'))}"
            for item in new_items[:20]
        ],
        new_total=len(new_items),
        resolved_items=[
            f"[{_fmt(item.get('severity')).upper()}] {redact_prose(_fmt(item.get('title')))} on {_fmt(item.get('target'))}"
            for item in resolved_items[:20]
        ],
        resolved_total=len(resolved_items),
    )


def _finding_row(db: Session, finding: Finding) -> FindingRow:
    asset = db.get(DiscoveredAsset, finding.asset_id) if finding.asset_id else None
    service = db.get(Service, finding.service_id) if finding.service_id else None

    location = _fmt(asset.value if asset else None)
    if service is not None:
        location += f" port {_fmt(service.port)}/{_fmt(service.transport or 'tcp')}"
        if service.product:
            location += f" ({_fmt(service.product)} {_fmt(service.version)})".rstrip()

    cve_line = None
    if finding.cve_ids:
        cve_line = (
            f"{', '.join(finding.cve_ids)}"
            + (f" | CVSS {finding.cvss_base}" if finding.cvss_base is not None else "")
            + (f" | EPSS {finding.epss}" if finding.epss is not None else "")
            + (" | KNOWN EXPLOITED (CISA KEV)" if finding.is_kev else "")
        )

    explanation = _cached_explanation(finding)
    explanation_paragraphs = (
        [p.strip() for p in redact_prose(explanation).splitlines() if p.strip()] if explanation else []
    )
    recommended_action = (
        None if explanation_paragraphs
        else _ACTION_BY_CATEGORY.get(finding.category, "Review and remediate the affected component.")
    )

    return FindingRow(
        severity=_fmt(finding.severity), title=redact_prose(finding.title), location=location,
        category=_fmt(finding.category), confidence=_fmt(finding.confidence),
        risk_score=_fmt(finding.risk_score), status=_fmt(finding.status), cve_line=cve_line,
        first_seen=_fmt(finding.first_seen), inferred=finding.confidence == "inferred",
        explanation_paragraphs=explanation_paragraphs, recommended_action=recommended_action,
        evidence_items=safe_evidence_items(finding.evidence),
        raw_ref=redact_value("raw_ref", finding.raw_ref) if finding.raw_ref else None,
    )


def _asset_inventory(db: Session, engagement_id: uuid.UUID) -> AssetInventory:
    assets = list(db.scalars(
        select(DiscoveredAsset)
        .where(DiscoveredAsset.engagement_id == engagement_id)
        .order_by(DiscoveredAsset.in_scope.desc(), DiscoveredAsset.value)
    ))
    rows = []
    for asset in assets:
        services = list(db.scalars(select(Service).where(Service.asset_id == asset.id).order_by(Service.port)))
        service_lines = []
        for service in services:
            descriptor = f"{_fmt(service.port)}/{_fmt(service.transport or 'tcp')}"
            if service.product:
                descriptor += f" {_fmt(service.product)} {_fmt(service.version or '')}".rstrip()
            service_lines.append(descriptor)
        rows.append(AssetRow(
            value=_fmt(asset.value), asset_type=_fmt(asset.asset_type), in_scope=bool(asset.in_scope),
            discovered_via=_fmt(asset.discovered_via), service_lines=service_lines,
        ))

    dns_records = list(db.scalars(
        select(DnsRecord).where(DnsRecord.engagement_id == engagement_id).order_by(DnsRecord.fqdn)
    ))
    hints = [r for r in dns_records if r.is_saas or r.is_cdn or r.is_idp or r.is_shared_infra or r.takeover_suspected]
    shadow_it = []
    for record in hints:
        labels = [
            name for name, flag in (
                ("SaaS", record.is_saas), ("CDN", record.is_cdn), ("identity provider", record.is_idp),
                ("shared infrastructure", record.is_shared_infra),
            ) if flag
        ]
        entry = f"{_fmt(record.fqdn)} -> {_fmt(record.terminal_target)} ({_fmt(record.hosting_provider)})"
        if labels:
            entry += f" [{', '.join(labels)}]"
        if record.takeover_suspected:
            entry += " [DANGLING - possible subdomain takeover]"
        shadow_it.append(entry)

    # Certificate expiry is specified in Kap. 6.1 but no scan phase populates
    # service.tls_info today. Say so plainly rather than omitting the section
    # silently - a customer must not read its absence as "nothing expiring".
    tls_seen = any(
        service.tls_info for asset in assets
        for service in db.scalars(select(Service).where(Service.asset_id == asset.id))
    )
    cert_note = (
        "Not collected by this scan. Certificate lifetime monitoring is not part of the "
        "current pipeline; absence here does not mean no certificate is expiring."
        if not tls_seen else
        "See the TLS details recorded per service in the console."
    )
    return AssetInventory(rows=rows, shadow_it=shadow_it, cert_note=cert_note)


def _methodology_and_scope(
    db: Session, eng: Engagement, runs: list[ScanRun], report_run: ScanRun | None,
) -> MethodologyScope:
    """⚖ Mandatory section (Kap. 6.1/6.4): what was tested, when, what was
    excluded, and under which authorization. This closes the loop with the
    audit trail and is what proves to a customer and an insurer that only
    authorized testing took place - it is never omitted, even when empty."""
    assets = list(db.scalars(
        select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id).order_by(ScopeAsset.rule, ScopeAsset.value)
    ))
    allow_assets = [a for a in assets if a.rule == "allow"]
    deny_assets = [a for a in assets if a.rule == "deny"]

    allow_rows = [
        ScopeRow(
            asset_type=_fmt(asset.asset_type), value=_fmt(asset.value),
            ports=(
                f"{asset.port_from}-{asset.port_to}"
                if asset.port_from is not None
                else f"{eng.tcp_port_from}-{eng.tcp_port_to} (default)"
            ),
            active="active checks" if asset.active_allowed else "passive only",
            verified="attested" if asset.authorization_verified else "NOT attested",
        )
        for asset in allow_assets
    ]
    deny_rows = [(_fmt(asset.asset_type), _fmt(asset.value)) for asset in deny_assets]

    run_rows = [
        RunRow(
            started_at=_fmt(run.started_at), state=_fmt(run.state), phase=_fmt(run.phase),
            reason=run.state_reason, is_report_run=report_run is not None and run.id == report_run.id,
        )
        for run in runs[:20]
    ]

    degraded = any((r.state_reason or "").find("coverage_degraded:") >= 0 for r in runs)

    return MethodologyScope(
        engagement_label=f"{redact_prose(_fmt(eng.title))} ({eng.id})",
        source=_fmt(eng.source),
        authorized_from=_fmt(eng.authorized_from),
        authorized_until=_fmt(eng.authorized_until),
        scope_doc_sha256=_fmt(eng.scope_doc_sha256),
        scope_signed_by=_fmt(getattr(eng, "scope_signed_by", None)),
        emergency_contact=redact_prose(_fmt(eng.emergency_contact)),
        ai_testing_allowed=bool(eng.ai_testing_allowed),
        allow_rows=allow_rows, deny_rows=deny_rows, run_rows=run_rows,
        runs_truncated=max(0, len(runs) - 20), no_runs=not runs, degraded=degraded,
    )


def build_report_model(db: Session, eng: Engagement, report_run: ScanRun | None) -> ReportModel:
    """The full report content, in the Kap. 6.1 section order."""
    findings = list(db.scalars(
        select(Finding).where(Finding.engagement_id == eng.id, Finding.status == "open")
    ))
    sorted_findings = sorted(findings, key=_sort_key)
    counts = _severity_counts(findings)
    accepted = sorted(db.scalars(
        select(Finding).where(Finding.engagement_id == eng.id, Finding.status == "accepted_risk")
    ), key=_sort_key)
    false_positive_count = len(list(db.scalars(
        select(Finding.id).where(Finding.engagement_id == eng.id, Finding.status == "false_positive")
    )))
    runs = list(db.scalars(
        select(ScanRun).where(ScanRun.engagement_id == eng.id).order_by(ScanRun.started_at.desc())
    ))
    diff = scan_diff.compute_diff(db, report_run) if report_run is not None else None

    generated_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return ReportModel(
        generated_at=generated_at.isoformat(),
        engagement_title=redact_prose(_fmt(eng.title)),
        engagement_id=str(eng.id),
        scan_run_id=str(report_run.id) if report_run else "n/a (no completed run)",
        executive_summary=_executive_summary(findings, counts, diff),
        risk_overview=_risk_overview(counts, diff),
        findings=[_finding_row(db, finding) for finding in sorted_findings],
        asset_inventory=_asset_inventory(db, eng.id),
        methodology=_methodology_and_scope(db, eng, runs, report_run),
        accepted_risks=[_accepted_risk_row(db, finding) for finding in accepted],
        false_positive_count=false_positive_count,
    )


def _accepted_risk_row(db: Session, finding: Finding) -> AcceptedRiskRow:
    row = _finding_row(db, finding)
    accepted_on = finding.status_changed_at.date().isoformat() if finding.status_changed_at else "n/a"
    return AcceptedRiskRow(
        severity=row.severity, title=row.title, location=row.location,
        justification=redact_prose(finding.status_note or "No justification recorded."), accepted_on=accepted_on,
    )
