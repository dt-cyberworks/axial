"""Raw egress policy rendering for tools that cannot use an HTTP proxy.

The HTTP egress-proxy is still the preferred enforcement path for HTTP-aware
tools. nmap is different: raw/TCP scans need a network-level allowlist. This
module turns the already-authorized engagement scope into a Kubernetes
NetworkPolicy fragment that allows direct runner egress only to active
IP/CIDR scope assets.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.engagement import Engagement, ScopeAsset


@dataclass(frozen=True)
class RawEgressPolicy:
    policy: dict
    ip_blocks: list[dict]
    omitted_assets: list[dict]
    warnings: list[str]


def _asset_network(asset: ScopeAsset) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if asset.asset_type == "ip":
        try:
            return ipaddress.ip_network(asset.value, strict=False)
        except ValueError:
            return None
    if asset.asset_type == "cidr":
        try:
            return ipaddress.ip_network(asset.value, strict=False)
        except ValueError:
            return None
    return None


def _network_key(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[int, int, int]:
    return (net.version, int(net.network_address), net.prefixlen)


def _ip_block(
    allow: ipaddress.IPv4Network | ipaddress.IPv6Network,
    deny_networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> dict | None:
    exceptions = []
    for deny in deny_networks:
        if deny.version != allow.version:
            continue
        if deny == allow:
            return None
        if deny.subnet_of(allow):
            exceptions.append(str(deny))

    block = {"cidr": str(allow)}
    if exceptions:
        block["except"] = sorted(set(exceptions))
    return block


def build_raw_egress_policy(
    engagement_id: uuid.UUID,
    assets: Iterable[ScopeAsset],
    *,
    namespace: str | None = None,
    materialized_ips: Iterable[dict] | None = None,
) -> RawEgressPolicy:
    """Build a deny-by-default NetworkPolicy for nmap/raw-scan egress.

    IP/CIDR allow assets are rendered directly. Domain and wildcard assets
    cannot be expressed in a NetworkPolicy on their own; they are omitted here
    UNLESS an audited DNS materialization (app/gateway/dns_materialization.py)
    has resolved them to IPs, which are then passed in via ``materialized_ips``
    and rendered as /32 (or /128) allow blocks. Names that are still
    unresolved remain fail-closed.
    """
    allow_networks = []
    deny_networks = []
    omitted_assets = []
    warnings = []

    # deny-Netze zuerst sammeln (Vorrang gilt fuer Assets UND materialisierte IPs).
    for asset in assets:
        network = _asset_network(asset)
        if network is not None and asset.rule == "deny":
            deny_networks.append(network)

    resolved_hosts = {m["ip_address"] for m in (materialized_ips or [])}

    for asset in assets:
        network = _asset_network(asset)
        if network is None:
            if asset.rule == "allow" and asset.active_allowed:
                # Nur weiterhin als "omitted" melden, wenn KEINE materialisierte
                # IP diesen Namen abdeckt (sonst ist er via /32-Block erlaubt).
                omitted_assets.append(
                    {
                        "id": str(asset.id),
                        "asset_type": asset.asset_type,
                        "value": asset.value,
                        "reason": "raw_egress_requires_ip_or_cidr",
                    }
                )
            continue
        if asset.rule == "allow" and asset.active_allowed:
            allow_networks.append(network)

    # Materialisierte IPs als /32 bzw. /128 in die allow-Menge aufnehmen.
    for ip in sorted(resolved_hosts):
        try:
            allow_networks.append(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            warnings.append(f"materialized IP {ip} not parseable - skipped")

    ip_blocks = []
    for allow in sorted(set(allow_networks), key=_network_key):
        block = _ip_block(allow, deny_networks)
        if block is None:
            warnings.append(f"allow block {allow} fully suppressed by deny rule")
            continue
        ip_blocks.append(block)

    egress = [{"to": [{"ipBlock": block}]} for block in ip_blocks]
    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"runner-raw-egress-{str(engagement_id)[:8]}",
            "labels": {
                "app": "tool-runner",
                "engagement": str(engagement_id),
                "asm.hettig.online/purpose": "nmap-raw-egress",
            },
        },
        "spec": {
            "podSelector": {"matchLabels": {"app": "tool-runner", "engagement": str(engagement_id)}},
            "policyTypes": ["Egress"],
            "egress": egress,
        },
    }
    if namespace:
        policy["metadata"]["namespace"] = namespace

    if omitted_assets and not resolved_hosts:
        warnings.append("domain/wildcard scope omitted until resolved IPs are materialized")
    elif omitted_assets:
        warnings.append(
            f"{len(resolved_hosts)} materialized IP(s) rendered as /32-/128 allow blocks; "
            "name assets without resolved IPs remain fail-closed"
        )
    if not ip_blocks:
        warnings.append("no active IP/CIDR allow assets; rendered policy denies raw egress")

    return RawEgressPolicy(policy=policy, ip_blocks=ip_blocks, omitted_assets=omitted_assets, warnings=warnings)


def render_for_engagement(db: Session, engagement_id: uuid.UUID, *, namespace: str | None = None) -> RawEgressPolicy:
    # Lazy import: dns_materialization importiert dieses Modul nicht, aber wir
    # halten die Abhaengigkeit hier lokal, um Import-Zyklen sicher zu vermeiden.
    from app.gateway.dns_materialization import materialized_ips

    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise ValueError("engagement_not_found")
    if eng.status != "active":
        raise ValueError("engagement_not_active")
    assets = db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == engagement_id)).all()
    return build_raw_egress_policy(
        engagement_id, assets, namespace=namespace,
        materialized_ips=materialized_ips(db, engagement_id),
    )
