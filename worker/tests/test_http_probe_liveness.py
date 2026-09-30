"""REQ-AGENT-015: httpx liveness outcome (live or dead) must be recorded
regardless of result - both in the deterministic fingerprint phase and the
agent's own httpx dispatch - and the agent's rendered evidence must tell a
confirmed-dead host apart from one nobody has checked yet. Found live: without
this, the agent re-probed the same confirmed-dead subdomains with httpx in
every one of 3 consecutive scan runs."""

from __future__ import annotations

from app.tasks import agent, dispatch, fingerprint


def test_fingerprint_http_probe_records_dead_result(monkeypatch):
    monkeypatch.setattr(fingerprint, "parse_httpx_json", lambda stdout: [])
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": ""})
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    recorded = []
    monkeypatch.setattr(fingerprint.client, "record_http_probe", lambda eid, aid, live: recorded.append((aid, live)))

    result = fingerprint._http_probe("engagement-1", "asset-1", "dead-host.example.com", "run-1")

    assert result is None
    assert recorded == [("asset-1", False)]


def test_fingerprint_http_probe_records_live_result(monkeypatch):
    monkeypatch.setattr(fingerprint, "parse_httpx_json",
                         lambda stdout: [{"port": 443, "webserver": "nginx", "tech": [], "title": "", "status_code": 200}])
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": ""})
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint.client, "add_service", lambda *a, **k: {"id": "svc-1"})
    recorded = []
    monkeypatch.setattr(fingerprint.client, "record_http_probe", lambda eid, aid, live: recorded.append((aid, live)))

    result = fingerprint._http_probe("engagement-1", "asset-1", "live-host.example.com", "run-1")

    assert result is not None
    assert recorded == [("asset-1", True)]


def test_agent_dispatch_httpx_records_dead_result(monkeypatch):
    monkeypatch.setattr(dispatch, "_run", lambda *a, **k: {"success": True, "stdout": ""})
    monkeypatch.setattr(dispatch, "parse_httpx_json", lambda stdout: [])
    recorded = []
    monkeypatch.setattr(dispatch.client, "record_http_probe", lambda eid, aid, live: recorded.append((aid, live)))

    obs = dispatch._dispatch_httpx("engagement-1", "asset-1", "dead-host.example.com", None, "run-1")

    assert "no live" in obs.summary
    assert recorded == [("asset-1", False)]


def test_agent_dispatch_httpx_records_live_result(monkeypatch):
    monkeypatch.setattr(dispatch, "_run", lambda *a, **k: {"success": True, "stdout": ""})
    monkeypatch.setattr(dispatch, "parse_httpx_json",
                         lambda stdout: [{"port": 443, "webserver": "nginx", "tech": [], "title": "", "status_code": 200}])
    monkeypatch.setattr(dispatch.client, "add_service", lambda *a, **k: None)
    recorded = []
    monkeypatch.setattr(dispatch.client, "record_http_probe", lambda eid, aid, live: recorded.append((aid, live)))

    dispatch._dispatch_httpx("engagement-1", "asset-1", "live-host.example.com", None, "run-1")

    assert recorded == [("asset-1", True)]


def test_render_evidence_flags_a_confirmed_dead_host_distinctly(monkeypatch):
    monkeypatch.setattr(agent.client, "get_agent_context", lambda eid: {"hosts": [
        {"host": "dead-host.example.com", "http_checked_at": "2026-07-28T18:00:00Z", "http_live": False,
         "services": [], "findings": []},
    ]})

    text = agent._render_evidence("11111111-1111-1111-1111-111111111111", {"dead-host.example.com": "asset-1"})

    assert "already confirmed no live HTTP service" in text
    assert "Do not re-run httpx" in text
    assert "(none recorded yet)" not in text


def test_render_evidence_leaves_never_checked_hosts_as_before(monkeypatch):
    monkeypatch.setattr(agent.client, "get_agent_context", lambda eid: {"hosts": [
        {"host": "unknown-host.example.com", "http_checked_at": None, "http_live": None,
         "services": [], "findings": []},
    ]})

    text = agent._render_evidence("11111111-1111-1111-1111-111111111111", {"unknown-host.example.com": "asset-1"})

    assert "(none recorded yet)" in text
    assert "already confirmed" not in text
