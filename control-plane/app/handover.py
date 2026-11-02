"""A deeper test of a monitored target starts from the monitor (REQ-HANDOVER-001..008, GitHub #84).

One action on a monitor creates a DRAFT assessment with what the monitor already knows filled in, links the two, and lets the
assessment's agent read what monitoring found. It authorizes nothing: the window is given by the owner, no attestation, no
permission for active testing, no tool grant and no consent is carried over, and the monitor is never changed. Whatever
activates the draft is the existing wizard and the existing activation rules.

Deny always wins: the monitor's deny rows are copied whatever was chosen, and a host that one of them matches is refused with
the gateway's own matcher, so "denied on the monitor" means here exactly what it means to the gateway.
"""

from __future__ import annotations

import datetime
import ipaddress
import uuid
from collections import defaultdict

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.gateway.audit import append_audit_log
from app.gateway.authorize import _matches_asset_value, _matching_rules  # the one matcher: rules mean the same here as at the gateway
from app.models.asset import DiscoveredAsset, Service
from app.models.engagement import Engagement, ScopeAsset
from app.models.finding import Finding
from app.models.monitoring import RunInventorySnapshot
from app.models.scan_run import ScanRun
from app.models.user import User
from app.schemas.handover import HandoverIn

SOURCE_STATUSES = ("active", "paused")
# A bug-bounty program's rules (identification header, rate caps) are not carried; a draft without them would be looser than
# its origin, so such a monitor is refused. The draft copies the source it is made from; a
# `customer` draft still needs the signed scope document at activation, which is not carried over.
SOURCES = ("own_domain", "lab", "customer")
DEFAULT_SCAN_PROFILE = "thorough"
MAX_FINDINGS_PER_HOST = 15
MAX_SERVICES_PER_HOST = 20
MAX_HOSTS_IN_SUMMARY = 40

CARRIED = (
    "The customer and the emergency contact",
    "The TCP port range ceiling",
    "The hosts you pick (as allow rules of their own), or the monitor's whole scope if you choose that",
    "The monitor's deny rules, always",
    "A starting point for the agent: what the monitor last found on those hosts (read-only, not verified)",
)
NOT_CARRIED = (
    "Authorization: nothing is attested and active testing is not permitted until you do it in the wizard",
    "The test window: you give it here, the monitor's is not reused",
    "The monitor's tool permissions and approvals: the assessment starts from the assessment defaults",
    "The monitor's schedule, its consent to change requests, its host policy and its alert targets",
    "Runs, findings, inventory and held-back requests: they stay with the monitor",
)
NOTE = (
    "This is what an earlier unattended run of the monitoring engagement reported. It is not verified in this engagement: "
    "use it to decide where to look and confirm anything with your own checks before reporting it."
)


# ------------------------------------------------------------------ helpers


def normalize_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def asset_type_for(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"


def _aware(value: datetime.datetime) -> datetime.datetime:
    return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)


def overlap_policy() -> str:
    """`both_may_run` when the installation requires the signed run identity (REQ-EGRESS-011), else the activation of an
    overlapping engagement is refused (REQ-CONCUR-003) and the monitor must be paused first."""
    return "both_may_run" if get_settings().egress_require_token else "monitor_must_pause"


def require_source(monitor: Engagement) -> None:
    if monitor.operating_mode != "monitoring" or monitor.status not in SOURCE_STATUSES:
        raise HTTPException(409, "handover_monitor_not_active")
    if monitor.source not in SOURCES:
        raise HTTPException(409, "handover_source_unsupported")


def latest_healthy_run(db: Session, engagement_id: uuid.UUID) -> ScanRun | None:
    """The most recent run that gave a full picture (REQ-MODE-004): healthy, finished, not a baseline discovery."""
    return db.scalar(
        select(ScanRun)
        .where(ScanRun.engagement_id == engagement_id, ScanRun.health == "ok", ScanRun.trigger != "baseline",
               ScanRun.finished_at.is_not(None))
        .order_by(ScanRun.started_at.desc())
        .limit(1)
    )


def _services_by_host(db: Session, run: ScanRun | None) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = defaultdict(list)
    if run is None:
        return out
    for row in db.scalars(select(RunInventorySnapshot).where(
            RunInventorySnapshot.scan_run_id == run.id, RunInventorySnapshot.kind == "service")):
        host_port, _, protocol = row.key.rpartition("/")
        host, _, port = host_port.rpartition(":")
        if not host or not port.isdigit():
            continue
        out[host.lower()].append({"port": int(port), "protocol": protocol or "tcp",
                                  "product": (row.data or {}).get("product"), "version": (row.data or {}).get("version")})
    for services in out.values():
        services.sort(key=lambda s: (s["port"], s["protocol"]))
    return out


def _open_findings_by_host(db: Session, monitor_id: uuid.UUID) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = defaultdict(list)
    rows = db.execute(
        select(Finding, DiscoveredAsset.value, Service.port)
        .join(DiscoveredAsset, DiscoveredAsset.id == Finding.asset_id)
        .outerjoin(Service, Service.id == Finding.service_id)
        .where(Finding.engagement_id == monitor_id, Finding.status == "open")
        .order_by(Finding.risk_score.desc().nulls_last(), Finding.title)
    ).all()
    for finding, host, port in rows:
        out[str(host).lower()].append({
            "title": finding.title, "severity": finding.severity, "category": finding.category,
            "cve_ids": list(finding.cve_ids) if finding.cve_ids else [], "port": port,
        })
    return out


def _known_hosts(db: Session, monitor: Engagement) -> dict[str, dict]:
    """The hosts of the monitor's in-scope inventory that can become a rule of their own (a name or an address)."""
    out: dict[str, dict] = {}
    for asset in db.scalars(select(DiscoveredAsset).where(
            DiscoveredAsset.engagement_id == monitor.id, DiscoveredAsset.in_scope.is_(True))):
        if asset.asset_type not in ("domain", "ip"):
            continue
        out[normalize_host(asset.value)] = {"asset_type": asset.asset_type, "held": asset.hold_state == "held"}
    return out


def _covers(db: Session, engagement_id: uuid.UUID, host: str) -> bool:
    """Whether an allow rule covers the HOST, whatever path it is limited to: a rule for `/app/*` still makes the host part
    of the scope. (A deny rule, by contrast, blocks the host only when it has no path limit, exactly as at the gateway.)"""
    return any(
        _matches_asset_value(host, rule)
        for rule in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == engagement_id, ScopeAsset.rule == "allow"))
    )


def _denied_by(db: Session, monitor: Engagement, host: str) -> str | None:
    rules = _matching_rules(db, monitor.id, host, None, "deny")
    return rules[0].value if rules else None


# ------------------------------------------------------------------ preview


def preview(db: Session, monitor: Engagement) -> dict:
    run = latest_healthy_run(db, monitor.id)
    services, findings = _services_by_host(db, run), _open_findings_by_host(db, monitor.id)
    hosts = []
    for host, info in sorted(_known_hosts(db, monitor).items()):
        hosts.append({
            "host": host, "asset_type": info["asset_type"], "held": info["held"],
            "services": len(services.get(host, [])), "open_findings": len(findings.get(host, [])),
            "denied_by": _denied_by(db, monitor, host),
        })
    deny_rows = [
        {"asset_type": r.asset_type, "value": r.value, "path_pattern": r.path_pattern}
        for r in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == monitor.id, ScopeAsset.rule == "deny")
                            .order_by(ScopeAsset.value))
    ]
    allow_rows = [
        {"asset_type": r.asset_type, "value": r.value}
        for r in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == monitor.id, ScopeAsset.rule == "allow")
                            .order_by(ScopeAsset.value))
    ]
    return {
        "monitor": {"id": str(monitor.id), "title": monitor.title, "status": monitor.status},
        "hosts": hosts, "deny_rows": deny_rows, "allow_rows": allow_rows,
        "latest_run_at": run.finished_at.isoformat() if run is not None and run.finished_at else None,
        "carried": list(CARRIED), "not_carried": list(NOT_CARRIED),
        "overlap": overlap_policy(),
        "defaults": {"scan_profile": DEFAULT_SCAN_PROFILE, "ai_testing_allowed": True},
        "suggested_title": f"Test: {monitor.title}",
        "emergency_contact": monitor.emergency_contact,
    }


# ------------------------------------------------------------------ create


def _validated_hosts(db: Session, monitor: Engagement, body: HandoverIn) -> list[str]:
    if body.scope_mode == "same_scope":
        if body.hosts:
            raise HTTPException(422, "handover_hosts_not_allowed")
        return []
    if not body.hosts:
        raise HTTPException(422, "handover_hosts_required")
    known = _known_hosts(db, monitor)
    chosen: list[str] = []
    for raw in body.hosts:
        host = normalize_host(raw)
        if not host or host in chosen:
            continue
        # Deny first, and with the gateway's own matcher: deny wins over everything the monitor knows.
        if _matching_rules(db, monitor.id, host, None, "deny"):
            raise HTTPException(422, "handover_host_denied")
        if host not in known and not _covers(db, monitor.id, host):
            raise HTTPException(422, "handover_host_unknown")
        chosen.append(host)
    if not chosen:
        raise HTTPException(422, "handover_hosts_required")
    return chosen


def create(db: Session, monitor: Engagement, user: User, body: HandoverIn) -> Engagement:
    """Everything is validated before anything is written; one commit, with the audit rows of the first append."""
    require_source(monitor)
    if _aware(body.authorized_until) <= _aware(body.authorized_from):
        raise HTTPException(422, "handover_window_invalid")
    hosts = _validated_hosts(db, monitor, body)

    # Only what REQ-HANDOVER-002 lists is set; every other column keeps its default, so nothing that authorizes anything,
    # the monitor's capabilities, schedule, consent or overrides can be carried by accident.
    eng = Engagement(
        title=(body.title or f"Test: {monitor.title}").strip(), source=monitor.source, status="draft", operating_mode="assessment",
        owner_user_id=user.id, handover_from_id=monitor.id, customer_id=monitor.customer_id,
        emergency_contact=body.emergency_contact if body.emergency_contact is not None else monitor.emergency_contact,
        authorized_from=body.authorized_from, authorized_until=body.authorized_until,
        tcp_port_from=monitor.tcp_port_from, tcp_port_to=monitor.tcp_port_to,
        scan_profile=DEFAULT_SCAN_PROFILE, ai_testing_allowed=True,
    )
    db.add(eng)
    db.flush()
    monitor_rows = list(db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == monitor.id).order_by(ScopeAsset.value)))
    new_rows: list[ScopeAsset] = []
    if body.scope_mode == "same_scope":
        for r in monitor_rows:
            if r.rule == "allow":
                new_rows.append(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type=r.asset_type, value=r.value,
                                           path_pattern=r.path_pattern, port_from=r.port_from, port_to=r.port_to))
    else:
        for host in hosts:
            new_rows.append(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type=asset_type_for(host), value=host))
    for r in monitor_rows:  # deny rows always, whatever was chosen
        if r.rule == "deny":
            new_rows.append(ScopeAsset(engagement_id=eng.id, rule="deny", asset_type=r.asset_type, value=r.value,
                                       path_pattern=r.path_pattern, port_from=r.port_from, port_to=r.port_to))
    # authorization_verified / authorization_method / active_allowed are deliberately left at their defaults (not attested).
    db.add_all(new_rows)
    db.flush()

    actor = f"user:{user.email}"
    allow_count = sum(1 for r in new_rows if r.rule == "allow")
    append_audit_log(
        db, engagement_id=eng.id, actor=actor, action="engagement_created", decision=None, reason=None,
        payload={"title": eng.title, "source": eng.source, "operating_mode": "assessment", "scan_profile": eng.scan_profile,
                 "tcp_port_range": f"{eng.tcp_port_from}-{eng.tcp_port_to}"},
    )
    append_audit_log(
        db, engagement_id=eng.id, actor=actor, action="handover_source", decision=None, reason=None,
        payload={"monitor_id": str(monitor.id), "monitor_title": monitor.title, "scope_mode": body.scope_mode,
                 "allow_rows": allow_count, "deny_rows": len(new_rows) - allow_count},
    )
    append_audit_log(
        db, engagement_id=monitor.id, actor=actor, action="handover_created", decision=None, reason=None,
        payload={"assessment_id": str(eng.id), "title": eng.title, "scope_mode": body.scope_mode, "hosts": hosts},
    )
    db.refresh(eng)
    return eng


def notices(overlap: str) -> list[str]:
    if overlap == "monitor_must_pause":
        return ["Activating this assessment will be refused while the monitor is active, because this installation does not "
                "run two engagements on the same host. Pause the monitor first (Pause engagement) or change the installation's "
                "run identity setting."]
    return []


# ------------------------------------------------------------------ the agent's starting point


def known_from_monitor(db: Session, assessment_id: uuid.UUID) -> dict | None:
    """REQ-HANDOVER-005: read-only context for the assessment's agent, or None. Only hosts the ASSESSMENT's own scope allows
    and none of its deny rows matches; no evidence, request, response or credential; capped."""
    eng = db.get(Engagement, assessment_id)
    if eng is None or eng.handover_from_id is None:
        return None
    monitor = db.get(Engagement, eng.handover_from_id)
    if monitor is None or monitor.operating_mode != "monitoring":
        return None
    run = latest_healthy_run(db, monitor.id)
    services, findings = _services_by_host(db, run), _open_findings_by_host(db, monitor.id)
    hosts = []
    for host in sorted(set(services) | set(findings)):
        if not _covers(db, eng.id, host) or _matching_rules(db, eng.id, host, None, "deny"):
            continue
        hosts.append({"host": host, "services": services.get(host, [])[:MAX_SERVICES_PER_HOST],
                      "findings": findings.get(host, [])[:MAX_FINDINGS_PER_HOST]})
        if len(hosts) >= MAX_HOSTS_IN_SUMMARY:
            break
    return {
        "source": {"id": str(monitor.id), "title": monitor.title},
        "as_of": run.finished_at.isoformat() if run is not None and run.finished_at else None,
        "note": NOTE, "hosts": hosts,
    }
