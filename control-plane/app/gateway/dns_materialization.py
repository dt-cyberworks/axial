"""Auditierte DNS-Materialisierung von Namens-Scope zu IPs (raw egress fuer nmap).

Eine Kubernetes-NetworkPolicy kann nur IP/CIDR erlauben, keine Namen. Bevor ein
nmap-/Raw-Scan-Job gegen namensbasierten Scope laufen darf, muessen die
freigegebenen Namen deshalb zu IPs aufgeloest werden. Das ist ein
sicherheitsrelevanter Schritt und passiert bewusst NUR in der control-plane
(Trust-Anchor, einziger DB-Schreiber): Aufloesung, deny-Vorrang und Audit sind
so atomar und nicht von einem weniger vertrauenswuerdigen Akteur beeinflussbar.

Aufgeloest werden:
  - konkrete `domain`-allow-Assets mit active_allowed=true
  - in-scope discovered_assets (von der Discovery-Phase; durch allow/wildcard
    autorisiert, deny bereits auf Namensebene beruecksichtigt)

deny-Vorrang wird nach der Aufloesung zusaetzlich auf IP-Ebene angewandt: eine
aufgeloeste Adresse, die unter eine deny-IP/CIDR-Regel faellt, wird verworfen
(z. B. wenn ein erlaubter Name auf eine ausgenommene IP zeigt).
"""

from __future__ import annotations

import dataclasses
import fnmatch
import ipaddress
import socket
import uuid

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.gateway.audit import append_audit_log
from app.models.asset import DiscoveredAsset
from app.models.engagement import Engagement, ScopeAsset
from app.models.resolved_host import ResolvedHost


@dataclasses.dataclass
class MaterializationResult:
    resolved: list[dict]          # [{hostname, ip_address, scope_asset_id}]
    denied_ips: list[dict]        # aufgeloeste, aber per deny-IP/CIDR verworfene
    unresolved: list[str]         # Namen ohne A/AAAA-Record oder DNS-Fehler
    warnings: list[str]


def _resolve(hostname: str) -> set[str]:
    """A/AAAA-Aufloesung. Leeres Set bei DNS-Fehler (nicht werfen -
    ein einzelner nicht aufloesbarer Name darf die Materialisierung nicht
    abbrechen)."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, socket.herror, OSError):
        return set()
    return {info[4][0] for info in infos}


def _deny_networks(assets: list[ScopeAsset]) -> list:
    nets = []
    for a in assets:
        if a.rule != "deny" or a.asset_type not in ("ip", "cidr"):
            continue
        try:
            nets.append(ipaddress.ip_network(a.value, strict=False))
        except ValueError:
            continue
    return nets


def _ip_denied(ip: str, deny_nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparsebare Adresse: fail-closed verwerfen
    return any(addr.version == n.version and addr in n for n in deny_nets)


def _matches_name_scope(hostname: str, asset: ScopeAsset) -> bool:
    # DNS materialization is host-level. A path-scoped rule must not authorize or
    # deny all IP egress for a host.
    if asset.path_pattern is not None:
        return False
    host = hostname.lower()
    if asset.asset_type == "domain":
        domain = asset.value.lower().rstrip(".")
        host = host.rstrip(".")
        return host == domain or host.endswith("." + domain)
    if asset.asset_type == "wildcard":
        return fnmatch.fnmatch(host, asset.value.lower())
    if asset.asset_type in ("ip", "cidr"):
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(asset.value, strict=False)
        except ValueError:
            return False
    return False


def _name_allowed_by_current_scope(hostname: str, assets: list[ScopeAsset]) -> tuple[bool, uuid.UUID | None]:
    if any(a.rule == "deny" and _matches_name_scope(hostname, a) for a in assets):
        return False, None
    for a in assets:
        if a.rule == "allow" and a.active_allowed and _matches_name_scope(hostname, a):
            return True, a.id
    return False, None


def materialize(db: Session, engagement_id: uuid.UUID, scan_run_id: uuid.UUID | None = None) -> MaterializationResult:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise ValueError("engagement_not_found")
    if eng.status != "active":
        raise ValueError("engagement_not_active")

    assets = db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == engagement_id)).all()
    deny_nets = _deny_networks(assets)

    # Namen sammeln: konkrete domain-allow-Assets (aktiv) + in-scope discovered.
    # Discovered assets are treated as a cache only; they must still match the
    # CURRENT scope rules so stale in_scope rows cannot become fresh IP egress.
    targets: dict[str, uuid.UUID | None] = {}
    for a in assets:
        if a.rule == "allow" and a.active_allowed and a.asset_type == "domain":
            allowed, scope_asset_id = _name_allowed_by_current_scope(a.value, assets)
            if allowed:
                targets.setdefault(a.value.lower(), scope_asset_id)
    discovered = db.scalars(
        select(DiscoveredAsset).where(
            DiscoveredAsset.engagement_id == engagement_id, DiscoveredAsset.in_scope.is_(True)
        )
    ).all()
    for d in discovered:
        allowed, scope_asset_id = _name_allowed_by_current_scope(d.value, assets)
        if allowed:
            targets.setdefault(d.value.lower(), scope_asset_id)

    resolved: list[dict] = []
    denied_ips: list[dict] = []
    unresolved: list[str] = []

    # Frischer Snapshot: alte Materialisierung dieses Auftrags verwerfen.
    db.execute(delete(ResolvedHost).where(ResolvedHost.engagement_id == engagement_id))

    seen: set[tuple[str, str]] = set()
    for hostname, scope_asset_id in sorted(targets.items()):
        ips = _resolve(hostname)
        if not ips:
            unresolved.append(hostname)
            continue
        for ip in sorted(ips):
            if _ip_denied(ip, deny_nets):
                denied_ips.append({"hostname": hostname, "ip_address": ip, "reason": "deny_ip_precedence"})
                continue
            key = (hostname, ip)
            if key in seen:
                continue
            seen.add(key)
            db.add(ResolvedHost(
                engagement_id=engagement_id, scope_asset_id=scope_asset_id,
                hostname=hostname, ip_address=ip,
            ))
            resolved.append({"hostname": hostname, "ip_address": ip, "scope_asset_id": str(scope_asset_id) if scope_asset_id else None})

    db.commit()

    warnings = []
    if unresolved:
        warnings.append(f"{len(unresolved)} Name(n) ohne A/AAAA-Record - nicht materialisiert")
    if denied_ips:
        warnings.append(f"{len(denied_ips)} aufgeloeste IP(s) durch deny-Vorrang verworfen")
    if not resolved:
        warnings.append("keine IPs materialisiert - raw egress bleibt fuer Namen fail-closed")

    # Audit: die Materialisierung ist eine sicherheitsrelevante Handlung.
    # scan_run_id (wenn vorhanden) taggt den Eintrag fuer die Run-Activity-
    # Ansicht (REQ-FIDELITY-002) - ohne das faellt der Eintrag auf den
    # zeitfenster-basierten Fallback zurueck, der bei einem frisch geoeffneten
    # SSE-Stream leer sein kann (siehe audit-run-scoping-completeness.md).
    append_audit_log(
        db, engagement_id=engagement_id, actor="control-plane",
        action="dns_materialization", decision=None, reason=None,
        payload={
            "resolved": resolved, "denied_ips": denied_ips, "unresolved": unresolved,
            **({"scan_run_id": str(scan_run_id)} if scan_run_id else {}),
        },
    )

    return MaterializationResult(resolved=resolved, denied_ips=denied_ips, unresolved=unresolved, warnings=warnings)


def materialized_ips(db: Session, engagement_id: uuid.UUID) -> list[dict]:
    """Aktuelle Materialisierung (fuer den raw-egress-policy-Renderer)."""
    rows = db.scalars(select(ResolvedHost).where(ResolvedHost.engagement_id == engagement_id)).all()
    return [{"hostname": r.hostname, "ip_address": r.ip_address} for r in rows]
