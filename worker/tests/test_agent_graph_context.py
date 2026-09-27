"""Attack-surface graph relationship context for the Vector Agent (REQ-GRAPH-003).

The agent must receive cross-host relationships (shared infra, technology
fan-out, technology->CVE) as a rendered, read-only block - never as a
scope-widening target list, and with a clean fallback when no graph exists.
"""

from __future__ import annotations

from app.tasks import agent


def _graph_fixture() -> dict:
    """Two hosts share an IP; one technology runs on two services; that
    technology is linked to a CVE."""
    return {
        "nodes": [
            {"id": "ip1", "node_type": "ip", "label": "203.0.113.9", "scannable": False},
            {"id": "h1", "node_type": "subdomain", "label": "a.example.com", "scannable": True},
            {"id": "h2", "node_type": "subdomain", "label": "b.example.com", "scannable": True},
            {"id": "s1", "node_type": "service", "label": "443/https nginx", "scannable": False},
            {"id": "s2", "node_type": "service", "label": "8443/https nginx", "scannable": False},
            {"id": "t1", "node_type": "technology", "label": "nginx", "scannable": False},
            {"id": "c1", "node_type": "cve", "label": "CVE-2021-1234", "scannable": False},
        ],
        "edges": [
            {"src": "ip1", "dst": "h1", "edge_type": "SHARES_INFRA"},
            {"src": "ip1", "dst": "h2", "edge_type": "SHARES_INFRA"},
            {"src": "s1", "dst": "t1", "edge_type": "RUNS_TECHNOLOGY"},
            {"src": "s2", "dst": "t1", "edge_type": "RUNS_TECHNOLOGY"},
            {"src": "t1", "dst": "c1", "edge_type": "HAS_CVE"},
        ],
    }


def test_render_relationships_surfaces_cross_host_links():
    block = agent._render_relationships(_graph_fixture())
    assert "Shared infra" in block and "203.0.113.9" in block
    assert "a.example.com" in block and "b.example.com" in block
    assert "Technology fan-out" in block and "nginx" in block
    assert "CVE-2021-1234" in block
    # framed as context, never as a scope-widening target list
    assert "does NOT change what is in scope" in block


def test_render_relationships_empty_graph_is_blank():
    assert agent._render_relationships(None) == ""
    assert agent._render_relationships({"nodes": [], "edges": []}) == ""


def test_initial_context_embeds_relationships(monkeypatch):
    monkeypatch.setattr(agent.client, "get_agent_context",
                        lambda eid: {"hosts": [], "graph": _graph_fixture()})
    ctx = agent._initial_context("11111111-1111-1111-1111-111111111111",
                                 {"a.example.com": "asset-1", "b.example.com": "asset-2"})
    assert "ATTACK-SURFACE RELATIONSHIPS" in ctx
    assert "Shared infra" in ctx


def test_initial_context_without_graph_falls_back(monkeypatch):
    # No graph key at all - the agent must not crash and must omit the block.
    monkeypatch.setattr(agent.client, "get_agent_context", lambda eid: {"hosts": []})
    ctx = agent._initial_context("11111111-1111-1111-1111-111111111111", {"a.example.com": "asset-1"})
    assert "ATTACK-SURFACE RELATIONSHIPS" not in ctx
    assert "a.example.com" in ctx
