"""Attack-surface graph builder (REQ-GRAPH-001/002/006).

`materialize_graph(engagement_id, db)` assembles a typed node/edge graph from the
already-collected scan data and upserts it idempotently into `surface_node` /
`surface_edge`. It is read-only against the source tables and writes only to the
graph tables.

Scope-safety invariant (REQ-GRAPH-002): `scannable` is set SOLELY from
`discovered_asset.in_scope`. Every value-derived node (ip from a shared
resolution, technology, cve, finding, dns_artifact) is non-scannable. The builder
never touches `discovered_asset`, `scope_asset`, or `resolved_host`, and the Scope
Gateway never reads these tables.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models.asset import DiscoveredAsset, Service
from app.models.dns_record import DnsRecord
from app.models.finding import Finding
from app.models.resolved_host import ResolvedHost
from app.models.surface_graph import SurfaceEdge, SurfaceNode

# Node key = (node_type, ref_table, ref_id). engagement_id is implicit (one
# graph per engagement). Values match the enumerations in
# docs/requirements/attack-surface-graph.md (REQ-GRAPH-001).
NodeKey = tuple[str, str, str]


class _Accumulator:
    """Collects nodes/edges in memory so `scannable` is a deterministic OR across
    every source that contributes a node, before a single upsert pass."""

    def __init__(self) -> None:
        self.nodes: dict[NodeKey, dict] = {}
        # edge set keyed by (src_key, dst_key, edge_type) -> attrs
        self.edges: dict[tuple[NodeKey, NodeKey, str], dict] = {}

    def add_node(
        self, node_type: str, ref_table: str, ref_id: str, label: str,
        *, scannable: bool = False, attrs: dict | None = None,
    ) -> NodeKey:
        key: NodeKey = (node_type, ref_table, str(ref_id))
        existing = self.nodes.get(key)
        if existing is None:
            self.nodes[key] = {
                "node_type": node_type, "ref_table": ref_table, "ref_id": str(ref_id),
                "label": label, "scannable": bool(scannable), "attrs": dict(attrs or {}),
            }
        else:
            # scannable is monotonic: any in-scope origin makes the node scannable.
            existing["scannable"] = existing["scannable"] or bool(scannable)
            if attrs:
                existing["attrs"].update(attrs)
            if label and not existing["label"]:
                existing["label"] = label
        return key

    def add_edge(self, src: NodeKey, dst: NodeKey, edge_type: str, attrs: dict | None = None) -> None:
        if src == dst:
            return
        self.edges[(src, dst, edge_type)] = dict(attrs or {})


def _host_node_type(asset: DiscoveredAsset) -> str:
    if asset.asset_type in ("ip", "cidr"):
        return "ip"
    # domain / wildcard / cloud_account -> a subdomain when it hangs off a parent,
    # otherwise a top-level domain.
    return "subdomain" if asset.parent_id is not None else "domain"


def _collect(engagement_id: uuid.UUID, db: Session) -> _Accumulator:
    acc = _Accumulator()

    # Root engagement node (REQ-GRAPH-001 node taxonomy). Rendered as the viz
    # origin; intentionally not wired with a scan-relevant edge type.
    acc.add_node("engagement", "engagement", str(engagement_id), "engagement", scannable=False)

    assets = db.scalars(
        select(DiscoveredAsset).where(DiscoveredAsset.engagement_id == engagement_id)
    ).all()
    # Lookups used to wire edges from value-based sources (dns/resolution).
    asset_key_by_id: dict[uuid.UUID, NodeKey] = {}
    host_key_by_value: dict[str, NodeKey] = {}
    node_type_by_asset_id: dict[uuid.UUID, str] = {}

    for a in assets:
        ntype = _host_node_type(a)
        node_type_by_asset_id[a.id] = ntype
        if ntype == "ip":
            # IPs dedupe by VALUE so a discovered in-scope IP and a resolution-
            # derived IP become one node. scannable rides on in_scope.
            key = acc.add_node("ip", "ip", a.value, a.value, scannable=bool(a.in_scope),
                               attrs={"discovered_via": a.discovered_via})
        else:
            key = acc.add_node(ntype, "discovered_asset", str(a.id), a.value,
                               scannable=bool(a.in_scope),
                               attrs={"asset_type": a.asset_type, "in_scope": bool(a.in_scope),
                                      "http_live": a.http_live})
        asset_key_by_id[a.id] = key
        host_key_by_value[a.value.strip().lower()] = key

    # HAS_SUBDOMAIN: parent domain -> subdomain (REQ-GRAPH-006 backbone).
    for a in assets:
        if a.parent_id is not None and a.parent_id in asset_key_by_id:
            acc.add_edge(asset_key_by_id[a.parent_id], asset_key_by_id[a.id], "HAS_SUBDOMAIN")

    # Services + technologies (host -> service -> technology).
    asset_ids = [a.id for a in assets]
    service_key_by_id: dict[uuid.UUID, NodeKey] = {}
    tech_by_service: dict[uuid.UUID, list[NodeKey]] = {}
    if asset_ids:
        services = db.scalars(select(Service).where(Service.asset_id.in_(asset_ids))).all()
        for s in services:
            label = f"{s.port or '?'}/{s.protocol or '?'} {s.product or ''}".strip()
            skey = acc.add_node("service", "service", str(s.id), label, scannable=False,
                                attrs={"port": s.port, "protocol": s.protocol, "product": s.product,
                                       "version": s.version})
            service_key_by_id[s.id] = skey
            if s.asset_id in asset_key_by_id:
                acc.add_edge(asset_key_by_id[s.asset_id], skey, "HAS_SERVICE")
            techs = (s.tech_stack or {}).get("tech") or [] if s.tech_stack else []
            for t in techs:
                name = str(t).strip()
                if not name:
                    continue
                tkey = acc.add_node("technology", "technology", name.lower(), name, scannable=False)
                acc.add_edge(skey, tkey, "RUNS_TECHNOLOGY")
                tech_by_service.setdefault(s.id, []).append(tkey)

    # Findings + CVEs (finding -> host/service; finding/technology -> cve).
    findings = db.scalars(select(Finding).where(Finding.engagement_id == engagement_id)).all()
    for f in findings:
        fkey = acc.add_node("finding", "finding", str(f.id), f.title or "finding", scannable=False,
                            attrs={"category": f.category, "severity": f.severity,
                                   "confidence": f.confidence, "status": f.status,
                                   "risk_score": float(f.risk_score) if f.risk_score is not None else None})
        # FINDING_AT: finding -> service (preferred) or host.
        if f.service_id is not None and f.service_id in service_key_by_id:
            acc.add_edge(fkey, service_key_by_id[f.service_id], "FINDING_AT")
        elif f.asset_id is not None and f.asset_id in asset_key_by_id:
            acc.add_edge(fkey, asset_key_by_id[f.asset_id], "FINDING_AT")
        for cve in (f.cve_ids or []):
            cve_id = str(cve).strip().upper()
            if not cve_id:
                continue
            ckey = acc.add_node("cve", "cve", cve_id, cve_id, scannable=False)
            acc.add_edge(fkey, ckey, "HAS_CVE")
            # technology -> cve makes the tech->CVE fan-out explicit (REQ-GRAPH-003):
            # the finding's service runs these technologies.
            if f.service_id is not None:
                for tkey in tech_by_service.get(f.service_id, []):
                    acc.add_edge(tkey, ckey, "HAS_CVE")

    # DNS artifacts + resolution edges. dns_record is derived metadata; its
    # CNAME target / shared-infra IP are NON-scannable context (REQ-GRAPH-002).
    dns_records = db.scalars(select(DnsRecord).where(DnsRecord.engagement_id == engagement_id)).all()
    # ip -> set(host_value) to detect shared infrastructure.
    hosts_by_ip: dict[str, set[str]] = {}
    for d in dns_records:
        host_key = host_key_by_value.get((d.fqdn or "").strip().lower())
        if d.terminal_target or d.is_shared_infra or d.is_cdn:
            akey = acc.add_node("dns_artifact", "dns_record", str(d.id),
                                d.terminal_target or d.fqdn, scannable=False,
                                attrs={"terminal_target": d.terminal_target,
                                       "hosting_provider": d.hosting_provider,
                                       "is_shared_infra": d.is_shared_infra,
                                       "is_cdn": d.is_cdn,
                                       "takeover_suspected": d.takeover_suspected})
            if host_key is not None:
                acc.add_edge(host_key, akey, "RESOLVES_TO")
        for ip in (d.terminal_ips or []):
            ip_s = str(ip).strip()
            if not ip_s:
                continue
            ipkey = acc.add_node("ip", "ip", ip_s, ip_s, scannable=False)
            if host_key is not None:
                acc.add_edge(host_key, ipkey, "RESOLVES_TO")
                hosts_by_ip.setdefault(ip_s, set()).add((d.fqdn or "").strip().lower())

    # resolved_host: audited name -> ip materialization.
    resolved = db.scalars(select(ResolvedHost).where(ResolvedHost.engagement_id == engagement_id)).all()
    for r in resolved:
        ipkey = acc.add_node("ip", "ip", r.ip_address, r.ip_address, scannable=False)
        host_key = host_key_by_value.get((r.hostname or "").strip().lower())
        if host_key is not None:
            acc.add_edge(host_key, ipkey, "RESOLVES_TO")
            hosts_by_ip.setdefault(r.ip_address, set()).add((r.hostname or "").strip().lower())

    # SHARES_INFRA: an IP hosting >=2 distinct in-scope names links those names.
    for ip_s, host_values in hosts_by_ip.items():
        present = [host_key_by_value[v] for v in host_values if v in host_key_by_value]
        if len(present) >= 2:
            ipkey: NodeKey = ("ip", "ip", ip_s)
            for hk in present:
                acc.add_edge(ipkey, hk, "SHARES_INFRA")

    return acc


def materialize_graph(engagement_id: uuid.UUID, db: Session) -> dict:
    """Idempotently (re)build the attack-surface graph for one engagement.

    Returns {"nodes": n, "edges": m}. Safe to call repeatedly: unchanged source
    data yields the identical node/edge set (upsert on the natural key), never
    duplicates (REQ-GRAPH-001).
    """
    acc = _collect(engagement_id, db)

    key_to_id: dict[NodeKey, uuid.UUID] = {}
    for key, n in acc.nodes.items():
        stmt = (
            pg_insert(SurfaceNode.__table__)
            .values(
                engagement_id=engagement_id,
                node_type=n["node_type"], ref_table=n["ref_table"], ref_id=n["ref_id"],
                label=n["label"], scannable=n["scannable"], attrs=n["attrs"],
            )
            .on_conflict_do_update(
                index_elements=["engagement_id", "node_type", "ref_table", "ref_id"],
                set_={"label": n["label"], "scannable": n["scannable"],
                      "attrs": n["attrs"], "last_seen": func.now()},
            )
            .returning(SurfaceNode.id)
        )
        node_id = db.execute(stmt).scalar_one()
        key_to_id[key] = node_id

    edge_count = 0
    for (src, dst, edge_type), attrs in acc.edges.items():
        if src not in key_to_id or dst not in key_to_id:
            continue
        stmt = (
            pg_insert(SurfaceEdge.__table__)
            .values(
                engagement_id=engagement_id,
                src_node_id=key_to_id[src], dst_node_id=key_to_id[dst],
                edge_type=edge_type, attrs=attrs,
            )
            .on_conflict_do_update(
                index_elements=["engagement_id", "src_node_id", "dst_node_id", "edge_type"],
                set_={"attrs": attrs},
            )
        )
        db.execute(stmt)
        edge_count += 1

    db.commit()
    return {"nodes": len(key_to_id), "edges": edge_count}


def read_graph(engagement_id: uuid.UUID, db: Session) -> dict:
    """Return the persisted graph as {"nodes": [...], "edges": [...]} for the API
    and the agent context. Read-only."""
    nodes = db.scalars(
        select(SurfaceNode).where(SurfaceNode.engagement_id == engagement_id)
    ).all()
    edges = db.scalars(
        select(SurfaceEdge).where(SurfaceEdge.engagement_id == engagement_id)
    ).all()
    return {
        "nodes": [
            {"id": str(n.id), "node_type": n.node_type, "ref_table": n.ref_table,
             "ref_id": n.ref_id, "label": n.label, "scannable": n.scannable, "attrs": n.attrs or {}}
            for n in nodes
        ],
        "edges": [
            {"src": str(e.src_node_id), "dst": str(e.dst_node_id),
             "edge_type": e.edge_type, "attrs": e.attrs or {}}
            for e in edges
        ],
    }
