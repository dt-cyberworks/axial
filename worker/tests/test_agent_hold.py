"""REQ-MODE-008 (GitHub #79): the Vector Agent never sees, and cannot name, a host the hold policy is holding."""

from __future__ import annotations

from app.tasks import agent

ENG = "11111111-1111-1111-1111-111111111111"
ROWS = [
    {"id": "a-1", "value": "www.example.test", "in_scope": True, "hold_state": None},
    {"id": "a-2", "value": "dev.example.test", "in_scope": True, "hold_state": "held"},
    {"id": "a-3", "value": "api.example.test", "in_scope": True, "hold_state": "released"},
]


def _wire(monkeypatch):
    asked = {}

    def fake(engagement_id, in_scope=None, exclude_held=False):
        asked["exclude_held"] = exclude_held
        return [r for r in ROWS if not (exclude_held and r["hold_state"] == "held")]

    monkeypatch.setattr(agent.client, "list_discovered_assets", fake)
    monkeypatch.setattr(agent.client, "materialize_dns", lambda eid, scan_run_id=None: {"resolved": []})
    return asked


def test_the_agents_host_list_asks_for_the_list_without_held_hosts(monkeypatch):
    asked = _wire(monkeypatch)
    asset_by_host, _ = agent._load_scope(ENG, "r1")
    assert asked["exclude_held"] is True
    assert set(asset_by_host) == {"www.example.test", "api.example.test"}  # a released host stays on the list


def test_negative_a_proposal_that_names_a_held_host_is_rejected_before_the_gateway_is_asked(monkeypatch):
    _wire(monkeypatch)
    asset_by_host, ip_by_host = agent._load_scope(ENG, "r1")
    gateway_calls: list = []
    monkeypatch.setattr(agent, "_authorize_throttled", lambda *a, **k: gateway_calls.append(a) or {"allowed": True})
    monkeypatch.setattr(agent, "_audit_agent_event", lambda *a, **k: None)
    context = agent.SimpleContext(scan_run_id="r1")
    for name, handler, tool_input in (
        ("http_request", agent._handle_http_request, {"target": "dev.example.test", "path": "/", "method": "GET"}),
        ("content_discovery", agent._handle_ffuf, {"target": "dev.example.test", "path": "/FUZZ", "wordlist": "common"}),
    ):
        out = handler(ENG, tool_input, asset_by_host, ip_by_host, context)
        assert out.startswith("REJECTED") and "not in the in-scope list" in out, name
    assert gateway_calls == []
    assert [d["reason"] for d in context.denied] == ["not_in_scope_list"] * 2


def test_the_hold_filter_is_not_applied_to_the_deterministic_listing_default(monkeypatch):
    """The client keeps the old behaviour unless a caller asks: discovery and the pipeline read the full list."""
    sent = {}

    class _R:
        def raise_for_status(self): pass
        def json(self): return []

    monkeypatch.setattr(agent.client._client, "get", lambda url, params=None: sent.update(params=params) or _R())
    agent.client.list_discovered_assets(__import__("uuid").UUID(ENG), in_scope=True)
    assert sent["params"] == {"in_scope": "true"}
    agent.client.list_discovered_assets(__import__("uuid").UUID(ENG), in_scope=True, exclude_held=True)
    assert sent["params"] == {"in_scope": "true", "exclude_held": "true"}
