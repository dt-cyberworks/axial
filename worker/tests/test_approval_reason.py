"""REQ-APPROVAL-002 (GitHub #80): the reason an agent or the automatic scan has for a request reaches the gateway
call - and with it the approval popup and the audit row - whatever the method. Found on int (2026-10-20): four agent
GETs carried `rationale: null` although the agent had written 142 to 229 characters each."""

from __future__ import annotations

import pytest

from app.tasks import agent, fingerprint

ASSETS = {"app.example.test": "asset-1"}


@pytest.fixture
def sent(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(agent, "_authorize_throttled", lambda eid, payload, proposal, context: calls.append(payload) or {"allowed": False, "reason": "denied"})
    monkeypatch.setattr(agent, "_audit_agent_event", lambda *a, **k: None)
    return calls


def _http(tool_input, **extra):
    context = agent.SimpleContext(scan_run_id="r1")
    return agent._handle_http_request("e1", {"target": "app.example.test", "path": "/", **tool_input, **extra}, ASSETS, {}, context)


def test_an_agent_get_carries_its_reason_and_no_risk_statement(sent):
    _http({"method": "GET", "rationale": "The proxy needs a Host header for a bare IP."})
    assert sent[0]["rationale"] == "The proxy needs a Host header for a bare IP."
    assert "risk" not in sent[0]


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
def test_every_read_method_carries_its_reason(sent, method):
    _http({"method": method, "rationale": "r"})
    assert sent[0]["rationale"] == "r"


def test_a_read_without_a_reason_sends_none_instead_of_an_empty_one(sent):
    _http({"method": "GET"})
    assert "rationale" not in sent[0]


def test_a_write_still_carries_reason_and_risk(sent):
    _http({"method": "POST", "body": "a=1", "rationale": "log in with the demo account", "risk_level": "low", "risk": "establishes a session"})
    assert sent[0]["rationale"] == "log in with the demo account"
    assert sent[0]["risk"] == {"level": "low", "description": "establishes a session"}


def test_a_write_without_a_reason_still_sends_the_empty_one_it_always_did(sent):
    _http({"method": "POST", "body": "a=1", "risk": "x"})
    assert sent[0]["rationale"] == "" and sent[0]["risk"]["description"] == "x"


def test_content_discovery_carries_its_reason(sent):
    context = agent.SimpleContext(scan_run_id="r1")
    agent._handle_ffuf("e1", {"target": "app.example.test", "path": "/FUZZ", "wordlist": "common", "rationale": "look for backups"}, ASSETS, {}, context)
    assert sent[0]["rationale"] == "look for backups"
    agent._handle_ffuf("e1", {"target": "app.example.test", "path": "/FUZZ", "wordlist": "common"}, ASSETS, {}, context)
    assert "rationale" not in sent[1]


# ------------------------------------------------------------- the automatic scan


@pytest.mark.parametrize("tool, args, expected", [
    ("ffuf", {"wordlist": "quickhits"}, "Content discovery (quickhits), part of the automatic scan"),
    ("ffuf", {"wordlist": "raft-medium-dirs"}, "Content discovery (raft-medium-dirs), part of the automatic scan"),
    ("nuclei", {"mode": "select", "group": "generic", "shard": "1/5"}, "Nuclei templates (generic), part of the automatic scan"),
    ("nuclei", {"mode": "takeover"}, "Nuclei templates (takeover), part of the automatic scan"),
    ("testssl", {}, "TLS test, part of the automatic scan"),
    ("wafw00f", {}, "WAF detection, part of the automatic scan"),
    ("somethingnew", {}, "somethingnew, part of the automatic scan"),
])
def test_an_automatic_check_says_what_it_is_for(tool, args, expected):
    assert fingerprint.automatic_scan_reason(tool, args) == expected


def test_the_pipeline_sends_that_reason_with_every_call(monkeypatch):
    seen = []
    monkeypatch.setattr(fingerprint.client, "authorize", lambda eid, payload: seen.append(payload) or {"allowed": True, "reason": "ok"})
    monkeypatch.setattr(fingerprint, "CancelProbe", type("P", (), {"for_run": staticmethod(lambda rid: None)}))
    fingerprint._propose("11111111-1111-1111-1111-111111111111", "ffuf", "vuln", "app.example.test", {"wordlist": "quickhits"}, "r1")
    assert seen[0]["rationale"] == "Content discovery (quickhits), part of the automatic scan"
    assert seen[0]["is_automated"] is True
