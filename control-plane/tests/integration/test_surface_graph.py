"""Attack-surface graph builder + API (REQ-GRAPH-001/002/005/006).

Graph-in-Postgres, so these are integration tests against TEST_DATABASE_URL.
The R3 invariant (REQ-GRAPH-002) gets an explicit negative test: the graph is
derived metadata that never creates a scannable asset and never changes an
authorization outcome.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.db.base import get_db
from app.gateway.authorize import ToolCall, authorize
from app.graph.builder import materialize_graph, read_graph
from app.main import app
from app.models.asset import DiscoveredAsset, Service
from app.models.dns_record import DnsRecord
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.finding import Finding
from app.models.surface_graph import SurfaceEdge, SurfaceNode
from app.models.user import User
from app.passwords import hash_secret


def _user(db, *, role="operator", email=None) -> User:
    user = User(
        email=email or f"graph-{dt.datetime.now(dt.timezone.utc).timestamp()}@example.com",
        display_name="Graph Test User", role=role, status="active",
        must_change_password=False, password_hash=hash_secret("irrelevant-not-used"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _seed(db, owner: User) -> Engagement:
    """One engagement with: an in-scope apex + subdomain (subdomain hangs off the
    apex via parent_id), an OUT-OF-SCOPE discovered name, a service with two
    technologies, a shared IP that both in-scope names resolve to, a CNAME
    dns_artifact, and a CVE finding on the service."""
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="Graph", source="own_domain", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
        owner_user_id=owner.id,
    )
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain",
                      value="example.com", active_allowed=True, authorization_verified=True))
    for cat in ("recon", "fingerprint", "vuln"):
        db.add(ToolGrant(engagement_id=eng.id, tool_category=cat, mode="active",
                         requires_manual_approval=False))

    apex = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value="example.com",
                           in_scope=True, discovered_via="scope-direct")
    db.add(apex)
    db.flush()
    sub = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value="api.example.com",
                          in_scope=True, discovered_via="passive-osint", parent_id=apex.id)
    oos = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value="notmine.example.org",
                          in_scope=False, discovered_via="passive-osint")
    db.add_all([sub, oos])
    db.flush()

    svc = Service(asset_id=sub.id, port=443, protocol="https", product="nginx",
                  tech_stack={"tech": ["nginx", "OpenSSH"]})
    db.add(svc)
    db.flush()

    # Both in-scope names resolve to the SAME shared IP -> SHARES_INFRA.
    db.add_all([
        DnsRecord(engagement_id=eng.id, asset_id=apex.id, fqdn="example.com",
                  terminal_ips=["203.0.113.9"], is_shared_infra=True),
        DnsRecord(engagement_id=eng.id, asset_id=sub.id, fqdn="api.example.com",
                  terminal_ips=["203.0.113.9"], terminal_target="x.cdn.example.net",
                  is_shared_infra=True),
    ])
    db.add(Finding(engagement_id=eng.id, asset_id=sub.id, service_id=svc.id, category="cve",
                   title="Outdated nginx", cve_ids=["CVE-2021-1234"], confidence="inferred",
                   status="open", fingerprint="fp-graph-1"))
    db.commit()
    return eng


def _nodes_by_type(graph: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for n in graph["nodes"]:
        out.setdefault(n["node_type"], []).append(n)
    return out


def test_builder_materializes_typed_graph(engine, db):
    """REQ-GRAPH-001: every node type is produced and the topology edges exist."""
    owner = _user(db)
    eng = _seed(db, owner)
    materialize_graph(eng.id, db)

    graph = read_graph(eng.id, db)
    by_type = _nodes_by_type(graph)
    for t in ("engagement", "domain", "subdomain", "ip", "service", "technology", "cve", "finding", "dns_artifact"):
        assert by_type.get(t), f"missing node type {t}"

    edge_types = {e["edge_type"] for e in graph["edges"]}
    assert {"HAS_SUBDOMAIN", "RESOLVES_TO", "HAS_SERVICE", "RUNS_TECHNOLOGY", "HAS_CVE", "FINDING_AT", "SHARES_INFRA"} <= edge_types

    # REQ-GRAPH-006: the subdomain hangs off the apex domain via HAS_SUBDOMAIN.
    label = {n["id"]: n["label"] for n in graph["nodes"]}
    has_sub = [(label[e["src"]], label[e["dst"]]) for e in graph["edges"] if e["edge_type"] == "HAS_SUBDOMAIN"]
    assert ("example.com", "api.example.com") in has_sub

    # SHARES_INFRA links the two names that share 203.0.113.9.
    shared_hosts = {label[e["dst"]] for e in graph["edges"] if e["edge_type"] == "SHARES_INFRA"}
    assert {"example.com", "api.example.com"} <= shared_hosts


def test_only_in_scope_hosts_are_scannable(engine, db):
    """REQ-GRAPH-002: scannable derives SOLELY from discovered_asset.in_scope."""
    owner = _user(db)
    eng = _seed(db, owner)
    materialize_graph(eng.id, db)
    graph = read_graph(eng.id, db)

    scannable = {n["label"] for n in graph["nodes"] if n["scannable"]}
    assert "example.com" in scannable and "api.example.com" in scannable
    assert "notmine.example.org" not in scannable  # discovered but out of scope

    # Every value-derived node type is non-scannable context.
    for n in graph["nodes"]:
        if n["node_type"] in ("ip", "technology", "cve", "finding", "dns_artifact"):
            assert n["scannable"] is False, f"{n['node_type']} {n['label']} must be context-only"


def test_materialize_is_idempotent(engine, db):
    """REQ-GRAPH-001: re-running on unchanged data yields the same set, no dupes."""
    owner = _user(db)
    eng = _seed(db, owner)
    first = materialize_graph(eng.id, db)
    second = materialize_graph(eng.id, db)
    assert first == second
    assert db.scalar(select(func.count()).select_from(SurfaceNode).where(SurfaceNode.engagement_id == eng.id)) == first["nodes"]
    assert db.scalar(select(func.count()).select_from(SurfaceEdge).where(SurfaceEdge.engagement_id == eng.id)) == first["edges"]


def test_graph_never_widens_scope(engine, db):
    """REQ-GRAPH-002 (R3 negative test): materializing the graph creates no
    discovered_asset and never flips an out-of-scope target's authorization."""
    owner = _user(db)
    eng = _seed(db, owner)

    assets_before = db.scalar(select(func.count()).select_from(DiscoveredAsset).where(DiscoveredAsset.engagement_id == eng.id))
    # The shared IP is derived context, NOT an allow-scope target.
    call = ToolCall(engagement_id=eng.id, tool="nmap", category="fingerprint", mode="active", target="203.0.113.9")
    before = authorize(db, call)

    materialize_graph(eng.id, db)

    assets_after = db.scalar(select(func.count()).select_from(DiscoveredAsset).where(DiscoveredAsset.engagement_id == eng.id))
    after = authorize(db, call)

    assert assets_after == assets_before, "graph must not create discovered_asset rows"
    assert before.allowed is False and after.allowed is False, "graph must not authorize an out-of-scope target"


def _client(engine) -> TestClient:
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override_get_db
    return TestClient(app)


def test_operator_endpoint_is_owner_scoped(engine, db):
    """REQ-GRAPH-005 / REQ-IAM-022: the graph is readable by every signed-in user (the same data
    the owner sees); an unauthenticated request and an unknown engagement are refused."""
    owner = _user(db, email="graph-owner@example.com")
    other = _user(db, email="graph-other@example.com")
    eng = _seed(db, owner)
    materialize_graph(eng.id, db)

    client = _client(engine)
    try:
        owner_token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
        resp = client.get(f"/engagements/{eng.id}/surface-graph", headers={"Authorization": f"Bearer {owner_token}"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["nodes"] and body["edges"]

        other_token, _ = auth_service.create_session(db, other, ip=None, user_agent=None)
        other_view = client.get(f"/engagements/{eng.id}/surface-graph", headers={"Authorization": f"Bearer {other_token}"})
        assert other_view.status_code == 200 and other_view.json() == body
        assert client.get(f"/engagements/{eng.id}/surface-graph").status_code == 401
        missing = client.get(f"/engagements/{uuid.uuid4()}/surface-graph", headers={"Authorization": f"Bearer {other_token}"})
        assert missing.status_code == 404
    finally:
        app.dependency_overrides.clear()
