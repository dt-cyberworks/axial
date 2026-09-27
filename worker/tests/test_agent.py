"""Vector-Agent-Loop gegen ein OpenAI-kompatibles Interface (gefakt).

Verifiziert die Sicherheits-/Ablaufgarantien ohne echtes LLM:
  - jeder Vorschlag laeuft durch client.authorize (Scope Gateway),
  - out-of-scope-Ziele des LLM werden vom Agenten selbst schon REJECTED,
  - ein DENY vom Gateway fuehrt NICHT zur Ausfuehrung (dispatch),
  - finish beendet sauber; ohne Provider ist die Phase ein No-Op.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from app.tasks import agent


def _tool_call(call_id: str, name: str, args: dict):
    return SimpleNamespace(
        id=call_id, type="function",
        function=SimpleNamespace(name=name, arguments=json.dumps(args)),
    )


def _assistant(tool_calls=None, content="", finish_reason=None):
    msg = SimpleNamespace(content=content, tool_calls=tool_calls)
    reason = finish_reason or ("tool_calls" if tool_calls else "stop")
    return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason=reason)])


class _FakeCompletions:
    def __init__(self, scripted):
        self._scripted = list(scripted)
        self.calls = 0
        self.last_kwargs = None

    def create(self, **kwargs):
        self.calls += 1
        self.last_kwargs = kwargs
        if self._scripted:
            return self._scripted.pop(0)
        # Fallback: keine Aktion -> Loop endet.
        return _assistant(tool_calls=None, content="fertig")


class _FakeOpenAI:
    last_instance = None

    def __init__(self, base_url=None, api_key=None, max_retries=None):
        self.base_url = base_url
        self.api_key = api_key
        self.max_retries = max_retries
        self.chat = SimpleNamespace(completions=_FakeCompletions(_FakeOpenAI._script))
        _FakeOpenAI.last_instance = self


@pytest.fixture
def wired(monkeypatch):
    """Verdrahtet Provider, Scope, DNS, Gateway und Dispatch mit Fakes."""
    monkeypatch.setattr(agent.client, "get_llm_config",
                        lambda: {"base_url": "https://x/v1", "api_key": "k", "model": "m", "is_usable": True})
    monkeypatch.setattr(agent.client, "list_discovered_assets",
                        lambda eid, in_scope=None: [{"id": "asset-1", "value": "example.org", "in_scope": True}])
    monkeypatch.setattr(agent.client, "materialize_dns",
                        lambda eid, scan_run_id=None: {"resolved": [{"hostname": "example.org", "ip_address": "1.2.3.4"}]})
    monkeypatch.setattr(agent.client, "get_agent_config",
                        lambda eid: {"prompt": "", "enabled_tools": ["httpx", "nuclei", "ffuf", "http_request"]})
    monkeypatch.setattr(agent.client, "get_agent_context",
                        lambda eid: {"hosts": [{"host": "example.org",
                                                "services": [{"port": 443, "protocol": "https", "product": "nginx",
                                                              "tech": ["nginx"], "title": "Home", "status": 200}],
                                                "findings": [{"title": "Fehlende Security-Header", "severity": "low",
                                                              "category": "misconfig", "confidence": "validated"}]}]})

    authorize_calls = []

    def fake_authorize(eid, call):
        authorize_calls.append(call)
        # nur In-Scope-Ziel wird freigegeben
        allowed = call["target"] == "example.org"
        return {"allowed": allowed, "is_pending": False,
                "reason": "all_checks_passed" if allowed else "target_out_of_scope"}

    monkeypatch.setattr(agent.client, "authorize", fake_authorize)

    dispatched = []

    def fake_dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None,
                      confirmed_protocol=None):  # REQ-FIDELITY-009 kwarg
        dispatched.append((tool, target, ip))
        return agent.dispatch.Observation(tool, target, "ok", findings=1)

    monkeypatch.setattr(agent.dispatch, "dispatch", fake_dispatch)
    monkeypatch.setattr("openai.OpenAI", _FakeOpenAI)
    return SimpleNamespace(authorize_calls=authorize_calls, dispatched=dispatched)


def test_agent_authorizes_dispatches_and_finishes(wired):
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "run_check", {"tool": "httpx", "target": "example.org"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "nichts weiter."})]),
    ]
    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    assert wired.dispatched == [("httpx", "example.org", "1.2.3.4")]
    assert ctx.exhausted is True
    assert ctx.conclusion == "nichts weiter."
    assert len(ctx.observations) == 1
    # httpx -> fingerprint-Kategorie, phase='agent'
    assert wired.authorize_calls[0]["category"] == "fingerprint"
    assert wired.authorize_calls[0]["phase"] == "agent"


def test_agent_configures_the_llm_client_with_resilient_retries(wired):
    """Found live: the openai SDK's own default (max_retries=2, ~3 total
    attempts within under 2s of backoff) gave up on a transient upstream 502
    that a bit more patience would have survived - the identical provider
    answered 6 prior calls successfully in the same run. The agent phase must
    configure a materially more patient retry budget than the SDK default,
    not rely on it."""
    _FakeOpenAI._script = [_assistant([_tool_call("c1", "finish", {"summary": "done"})])]
    agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    assert _FakeOpenAI.last_instance.max_retries == agent.AGENT_LLM_MAX_RETRIES
    assert agent.AGENT_LLM_MAX_RETRIES > 2  # strictly more patient than the openai SDK's own default


def test_agent_fetches_scan_envelope_and_threads_single_port_to_dispatch(wired, monkeypatch):
    """REQ-FIDELITY-007: the agent must resolve the engagement's configured
    single port ONCE and pass it to every dispatched tool call - otherwise an
    agent-proposed call on a port-restricted engagement silently targets the
    implicit 443 and gets blocked by the egress-proxy's port enforcement
    (REQ-FIDELITY-005), as observed live."""
    monkeypatch.setattr(agent.client, "get_scan_envelope",
                        lambda eid: {"tcp_port_from": 4280, "tcp_port_to": 4280})
    seen_ports = []

    def fake_dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None,
                      confirmed_protocol=None):  # REQ-FIDELITY-009 kwarg
        seen_ports.append(single_port)
        return agent.dispatch.Observation(tool, target, "ok")

    monkeypatch.setattr(agent.dispatch, "dispatch", fake_dispatch)
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "run_check", {"tool": "httpx", "target": "example.org"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "done"})]),
    ]

    agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    assert seen_ports == [4280]


def test_agent_retries_length_limited_response_before_dispatch(wired, monkeypatch):
    monkeypatch.setattr(agent, "AGENT_MAX_TOKENS", 4096)
    monkeypatch.setattr(agent, "AGENT_RETRY_MAX_TOKENS", 8192)
    monkeypatch.setattr(agent, "AGENT_LENGTH_RETRIES", 1)
    _FakeOpenAI._script = [
        _assistant(content="", finish_reason="length"),
        _assistant([_tool_call("c1", "finish", {"summary": "completed after retry"})]),
    ]

    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    completions = _FakeOpenAI.last_instance.chat.completions
    assert completions.calls == 2
    assert completions.last_kwargs["max_tokens"] == 8192
    assert wired.dispatched == []
    assert ctx.conclusion == "completed after retry"
    assert ctx.incomplete_reason is None


def test_agent_exhausted_length_retries_never_concludes_or_dispatches(wired, monkeypatch):
    monkeypatch.setattr(agent, "AGENT_LENGTH_RETRIES", 1)
    _FakeOpenAI._script = [
        _assistant(content="planning", finish_reason="length"),
        _assistant([_tool_call("partial", "run_check", {"tool": "httpx", "target": "example.org"})],
                   finish_reason="length"),
    ]

    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    assert wired.dispatched == []
    assert ctx.conclusion is None
    assert ctx.incomplete_reason == "finish_reason_length"


def test_agent_rejects_out_of_scope_target_without_dispatch(wired):
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "run_check", {"tool": "nikto", "target": "evil.example.com"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "stop."})]),
    ]
    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    # Nicht in der In-Scope-Liste -> gar nicht erst ans Gateway, kein Dispatch.
    assert wired.dispatched == []
    assert wired.authorize_calls == []
    assert ctx.denied and ctx.denied[0]["reason"] == "not_in_scope_list"


def test_agent_respects_gateway_deny(wired, monkeypatch):
    # Ziel ist in-scope-gelistet, aber Gateway verweigert (z. B. budget_exhausted).
    monkeypatch.setattr(agent.client, "authorize",
                        lambda eid, call: {"allowed": False, "is_pending": False, "reason": "budget_exhausted"})
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "run_check", {"tool": "nuclei", "target": "example.org"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "stop."})]),
    ]
    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    assert wired.dispatched == []
    assert ctx.denied and ctx.denied[0]["reason"] == "budget_exhausted"


def test_agent_http_request_authorizes_with_args_and_returns_full_response(wired, monkeypatch):
    """Der roh-HTTP-Primitiv: Header/Pfad gehen als args ans Gateway, die volle
    Antwort kommt als Beobachtung zurueck (Grundlage der PII-Klassifikation)."""
    seen = []

    def fake_dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None,
                      confirmed_protocol=None):  # REQ-FIDELITY-009 kwarg
        seen.append((tool, target, args))
        body = 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n[{"email":"a@b.de"}]'
        return agent.dispatch.Observation(tool, target, body)

    monkeypatch.setattr(agent.dispatch, "dispatch", fake_dispatch)
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "http_request", {
            "target": "example.org", "method": "GET", "path": "/api/users",
            "headers": {"X-Internal": "true"}})]),
        _assistant([_tool_call("c2", "finish", {"summary": "done"})]),
    ]
    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    # Dispatch bekam die vom Agenten geformten args (inkl. Header).
    assert seen and seen[0][0] == "http_request"
    assert seen[0][2]["headers"] == {"X-Internal": "true"} and seen[0][2]["path"] == "/api/users"
    # Das Gateway sah tool=http_request, category=vuln, phase=agent UND die args.
    hr = [c for c in wired.authorize_calls if c["tool"] == "http_request"][0]
    assert hr["category"] == "vuln" and hr["phase"] == "agent"
    assert hr["args"]["method"] == "GET" and hr["args"]["path"] == "/api/users"
    # Die volle Antwort steht in der Beobachtung.
    assert "email" in ctx.observations[-1]["result"]


def test_agent_http_request_out_of_scope_rejected_without_gateway(wired):
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "http_request", {"target": "evil.example.com", "method": "GET", "path": "/"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "stop"})]),
    ]
    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)
    assert [c for c in wired.authorize_calls if c["tool"] == "http_request"] == []
    assert ctx.denied and ctx.denied[0]["reason"] == "not_in_scope_list"


def test_agent_content_discovery_authorizes_with_curated_wordlist(wired, monkeypatch):
    """content_discovery: der Agent waehlt Wortliste/Pfad/Kandidaten; die gehen
    als args ans Gateway, die Trefferliste kommt als Beobachtung zurueck."""
    seen = []

    def fake_dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None,
                      confirmed_protocol=None):  # REQ-FIDELITY-009 kwarg
        seen.append((tool, args))
        return agent.dispatch.Observation(tool, target, "content-discovery: 2 Treffer: 200 /admin; 200 /.git")

    monkeypatch.setattr(agent.dispatch, "dispatch", fake_dispatch)
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "content_discovery", {
            "target": "example.org", "wordlist": "quickhits", "path": "/FUZZ",
            "extensions": ["php"], "extra_candidates": ["backup", "admin"]})]),
        _assistant([_tool_call("c2", "finish", {"summary": "done"})]),
    ]
    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    assert seen and seen[0][0] == "ffuf"
    assert seen[0][1]["wordlist"] == "quickhits" and seen[0][1]["path"] == "/FUZZ"
    assert seen[0][1]["extra_candidates"] == ["backup", "admin"]
    hr = [c for c in wired.authorize_calls if c["tool"] == "ffuf"][0]
    assert hr["category"] == "vuln" and hr["phase"] == "agent"
    assert "admin" in ctx.observations[-1]["result"]


def test_agent_report_finding_records_and_tracks(wired, monkeypatch):
    recorded = []
    monkeypatch.setattr(agent.client, "add_finding",
                        lambda eid, **f: (recorded.append(f), {"id": "f1"})[1])
    _FakeOpenAI._script = [
        # REQ-AGENT-021 added a required evidence_basis. This case is a genuinely
        # demonstrated exposure (the observation returned 200 with real emails),
        # so it declares direct_technical_proof and every assertion below is
        # unchanged - the schema field was added, the expectations were not relaxed.
        _assistant([_tool_call("c1", "report_finding", {
            "target": "example.org", "title": "Unauthenticated PII exposure",
            "severity": "critical", "category": "exposure", "rationale": "200 + emails",
            "evidence_basis": "direct_technical_proof"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "done"})]),
    ]
    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    assert recorded and recorded[0]["title"] == "Unauthenticated PII exposure"
    assert recorded[0]["severity_override"] == "critical" and recorded[0]["confidence"] == "validated"
    assert ctx.reported and ctx.reported[0]["severity"] == "critical"
    # REQ-AGENT-013: must never show as "unknown tool" in the Findings UI.
    assert recorded[0]["evidence"]["tool"] == "vector_agent"


def test_initial_context_embeds_real_evidence(monkeypatch):
    """Der Agent darf nicht im Blindflug raten: Services + Findings der bereits
    gelaufenen Phasen muessen im Start-Kontext stehen."""
    monkeypatch.setattr(agent.client, "get_agent_context",
                        lambda eid: {"hosts": [{"host": "example.org",
                                                "services": [{"port": 443, "protocol": "https", "product": "nginx",
                                                              "tech": ["nginx", "HSTS"], "title": "x", "status": 200}],
                                                "findings": [{"title": "Schwaches TLS 1.0", "severity": "medium",
                                                              "category": "misconfig", "confidence": "validated"}]}]})
    ctx = agent._initial_context("11111111-1111-1111-1111-111111111111", {"example.org": "asset-1"})
    assert "example.org" in ctx
    assert "Port 443" in ctx and "nginx" in ctx
    assert "Schwaches TLS 1.0" in ctx and "medium" in ctx


def test_initial_context_falls_back_when_context_unavailable(monkeypatch):
    def boom(eid):
        raise RuntimeError("control-plane weg")
    monkeypatch.setattr(agent.client, "get_agent_context", boom)
    ctx = agent._initial_context("11111111-1111-1111-1111-111111111111", {"example.org": "asset-1"})
    # Kein Absturz; Hostliste bleibt, Evidenz-Block zeigt "noch keine erfasst".
    assert "example.org" in ctx


def test_agent_uses_effective_prompt_and_enabled_tools(wired, monkeypatch):
    """Der Agent zieht den effektiven Prompt (Kampagne/global) statt des
    eingebauten, und die aktivierten Tools landen im Startkontext."""
    monkeypatch.setattr(agent.client, "get_agent_config",
                        lambda eid: {"prompt": "CUSTOM CAMPAIGN PROMPT", "enabled_tools": ["httpx", "nuclei"]})
    _FakeOpenAI._script = [_assistant([_tool_call("c1", "finish", {"summary": "done"})])]
    agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=5)

    msgs = _FakeOpenAI.last_instance.chat.completions.last_kwargs["messages"]
    assert msgs[0]["role"] == "system" and msgs[0]["content"] == "CUSTOM CAMPAIGN PROMPT"
    assert "ENABLED TOOLS" in msgs[1]["content"] and "httpx" in msgs[1]["content"]


def test_initial_context_includes_engagement_parameters():
    """REQ-AGENT-012: der Agent muss die konkreten Engagement-Parameter dieses
    Laufs sehen (Autorisierungsfenster, Quelle, Portfenster), nicht nur die
    Hostliste - insbesondere den Port-Hinweis, wenn ein Einzelport erzwungen ist."""
    ctx = agent._initial_context(
        "11111111-1111-1111-1111-111111111111", {"pentest-ground.com": "asset-1"},
        engagement_params={
            "title": "Pentest Ground", "source": "own_domain",
            "authorized_from": "2026-01-01T00:00:00Z", "authorized_until": "2026-02-01T00:00:00Z",
            "tcp_port_from": 4280, "tcp_port_to": 4280, "ai_testing_allowed": True,
        },
    )
    assert "ENGAGEMENT PARAMETERS" in ctx
    assert "Pentest Ground" in ctx
    assert "Authorized port: 4280 ONLY" in ctx


def test_initial_context_engagement_parameters_omitted_when_not_provided():
    ctx = agent._initial_context("11111111-1111-1111-1111-111111111111", {"example.org": "asset-1"})
    assert "ENGAGEMENT PARAMETERS" not in ctx


def test_agent_fetches_and_threads_engagement_parameters_from_config(wired, monkeypatch):
    monkeypatch.setattr(agent.client, "get_agent_config", lambda eid: {
        "prompt": "", "enabled_tools": ["httpx"],
        "engagement": {"title": "Concurrent Test", "source": "own_domain",
                       "authorized_from": "2026-01-01T00:00:00Z", "authorized_until": "2026-02-01T00:00:00Z",
                       "tcp_port_from": 80, "tcp_port_to": 1000, "ai_testing_allowed": True},
    })
    _FakeOpenAI._script = [_assistant([_tool_call("c1", "finish", {"summary": "done"})])]
    agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=5)

    msgs = _FakeOpenAI.last_instance.chat.completions.last_kwargs["messages"]
    assert "Concurrent Test" in msgs[1]["content"]
    assert "Authorized ports: standard" in msgs[1]["content"]


def test_agent_falls_back_to_builtin_prompt_when_config_unavailable(wired, monkeypatch):
    def boom(eid):
        raise RuntimeError("control-plane weg")
    monkeypatch.setattr(agent.client, "get_agent_config", boom)
    _FakeOpenAI._script = [_assistant([_tool_call("c1", "finish", {"summary": "done"})])]
    agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=5)

    msgs = _FakeOpenAI.last_instance.chat.completions.last_kwargs["messages"]
    # Eingebauter Notfall-Fallback (die ausfuehrliche Version lebt in der
    # control-plane und ist hier per Definition nicht erreichbar).
    assert msgs[0]["content"] == agent._SYSTEM_PROMPT


def test_agent_records_steps_when_scan_run_id_given(wired, monkeypatch):
    """REQ-RUN-006: pro Iteration werden Prompt + Antwort festgehalten."""
    steps = []
    monkeypatch.setattr(agent.client, "record_agent_step",
                        lambda eid, **f: steps.append(f))
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: False)
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "run_check", {"tool": "httpx", "target": "example.org"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "done"})]),
    ]
    agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10,
              scan_run_id="22222222-2222-2222-2222-222222222222")

    assert len(steps) == 2
    assert steps[0]["iteration"] == 1
    assert steps[0]["request_messages"][0]["role"] == "system"
    assert steps[0]["response_tool_calls"][0]["name"] == "run_check"


def test_agent_step_request_messages_are_append_only_across_iterations(wired, monkeypatch):
    """REQ-RUN-006: each step's request_messages must be a strict superset of
    the previous step's - the frontend's incremental-transcript rendering
    (RunDetail.tsx slicing request_messages against the previous step) relies
    on this invariant to avoid silently dropping or reordering context."""
    steps = []
    monkeypatch.setattr(agent.client, "record_agent_step",
                        lambda eid, **f: steps.append(f))
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: False)
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "run_check", {"tool": "httpx", "target": "example.org"})]),
        _assistant([_tool_call("c2", "run_check", {"tool": "nikto", "target": "example.org"})]),
        _assistant([_tool_call("c3", "finish", {"summary": "done"})]),
    ]
    agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10,
              scan_run_id="22222222-2222-2222-2222-222222222222")

    assert len(steps) == 3
    for prev, cur in zip(steps, steps[1:]):
        prev_msgs, cur_msgs = prev["request_messages"], cur["request_messages"]
        assert len(cur_msgs) > len(prev_msgs), "later steps must strictly grow"
        assert cur_msgs[:len(prev_msgs)] == prev_msgs, "earlier messages must never change or reorder"


def test_agent_events_are_tagged_with_scan_run_id(wired, monkeypatch):
    """REQ-FIDELITY-008: agent_event audit rows must carry a top-level
    scan_run_id when one is known, so the run-scoped Activity stream can
    tag-match them directly instead of relying on its time-window fallback
    (which freezes at SSE-connect time and can otherwise show an active run's
    Activity tab as empty)."""
    events = []
    monkeypatch.setattr(agent.client, "agent_event",
                        lambda eid, **fields: events.append(fields.get("payload") or {}))
    monkeypatch.setattr(agent.client, "record_agent_step", lambda eid, **f: None)
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: False)
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "run_check", {"tool": "httpx", "target": "example.org"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "done"})]),
    ]
    agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10,
              scan_run_id="22222222-2222-2222-2222-222222222222")

    assert events, "expected at least one agent_event during the run"
    assert all(e.get("scan_run_id") == "22222222-2222-2222-2222-222222222222" for e in events), events


def test_agent_stops_on_cancel(wired, monkeypatch):
    """REQ-RUN-001: is_cancel_requested=True bricht die Schleife ab, bevor das
    LLM aufgerufen wird - kein Dispatch."""
    monkeypatch.setattr(agent.client, "record_agent_step", lambda eid, **f: None)
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: True)
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "run_check", {"tool": "httpx", "target": "example.org"})]),
    ]
    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10,
                    scan_run_id="22222222-2222-2222-2222-222222222222")
    assert wired.dispatched == [] and ctx.iterations == 0


def test_await_approval_executes_on_approve(monkeypatch):
    """REQ-APPROVAL-001/003: nach Operator-Freigabe wird der Write ausgefuehrt
    und die Freigabe konsumiert (Einmal-Token)."""
    monkeypatch.setattr(agent.client, "update_scan_run", lambda *a, **k: {})
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: False)
    monkeypatch.setattr(agent.client, "get_approval", lambda aid: {"state": "approved"})
    monkeypatch.setattr(agent.client, "claim_approval", lambda aid: {
        "allowed": True,
        "reason": "all_checks_passed",
        "tool_call": {"target": "example.org", "args": {"method": "POST", "path": "/approved-exact"}},
    })
    completed = []
    monkeypatch.setattr(agent.client, "complete_approval", lambda aid, **kw: completed.append((aid, kw)) or {})
    dispatched = []

    def fake_dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None,
                      confirmed_protocol=None):  # REQ-FIDELITY-009 kwarg
        dispatched.append((tool, args))
        return agent.dispatch.Observation(tool, target, "HTTP/2 200 OK")

    monkeypatch.setattr(agent.dispatch, "dispatch", fake_dispatch)
    ctx = agent.SimpleContext(scan_run_id="11111111-1111-1111-1111-111111111111")
    out = agent._await_approval("22222222-2222-2222-2222-222222222222", "ap1", "asset-1", "example.org",
                                {"method": "POST", "path": "/login"}, None, {"tool": "http_request"}, ctx)
    assert dispatched and dispatched[0][1]["path"] == "/approved-exact"
    assert completed == [("ap1", {"success": True})]
    assert "200" in out


def test_await_approval_records_runner_failure(monkeypatch):
    monkeypatch.setattr(agent.client, "update_scan_run", lambda *a, **k: {})
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: False)
    monkeypatch.setattr(agent.client, "get_approval", lambda aid: {"state": "approved"})
    monkeypatch.setattr(agent.client, "claim_approval", lambda aid: {
        "allowed": True, "tool_call": {"target": "example.org", "args": {"method": "POST", "path": "/x"}},
    })
    completed = []
    monkeypatch.setattr(agent.client, "complete_approval", lambda aid, **kw: completed.append(kw) or {})
    monkeypatch.setattr(agent.dispatch, "dispatch", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("runner down")))
    ctx = agent.SimpleContext(scan_run_id="11111111-1111-1111-1111-111111111111")
    out = agent._await_approval("22222222-2222-2222-2222-222222222222", "ap1", "asset-1", "example.org",
                                {"method": "POST", "path": "/x"}, None, {"tool": "http_request"}, ctx)
    assert completed == [{"success": False, "error": "runner down"}]
    assert "ERROR" in out


def test_await_approval_dispatches_the_exact_approved_tool_not_a_hardcoded_default(monkeypatch):
    """REQ-APPROVAL-006: _await_approval used to always dispatch "http_request"
    regardless of what was actually approved - harmless for the only two
    callers that existed when it was written, but wrong once a third caller
    (run_check, any scanner tool) started using it too."""
    monkeypatch.setattr(agent.client, "update_scan_run", lambda *a, **k: {})
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: False)
    monkeypatch.setattr(agent.client, "get_approval", lambda aid: {"state": "approved"})
    monkeypatch.setattr(agent.client, "claim_approval", lambda aid: {
        "allowed": True, "tool_call": {"tool": "testssl", "target": "example.org", "args": {}},
    })
    monkeypatch.setattr(agent.client, "complete_approval", lambda aid, **kw: {})
    dispatched = []
    monkeypatch.setattr(agent.dispatch, "dispatch",
                        lambda eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None,
                               single_port=None, confirmed_protocol=None:
                            dispatched.append(tool) or agent.dispatch.Observation(tool, target, "clean"))
    ctx = agent.SimpleContext(scan_run_id="11111111-1111-1111-1111-111111111111")
    agent._await_approval("22222222-2222-2222-2222-222222222222", "ap1", "asset-1", "example.org",
                          {}, None, {"tool": "testssl"}, ctx, tool="testssl")
    assert dispatched == ["testssl"]


def test_run_check_pending_approval_includes_the_agents_rationale(monkeypatch):
    """Previously decision_payload never carried "rationale" at all for
    run_check, even though the LLM-facing schema already collects one - the
    operator's approval popup had nothing to show, not because the agent
    didn't provide it, but because it was silently dropped before storage."""
    captured = {}
    monkeypatch.setattr(agent.client, "authorize",
                        lambda eid, call: captured.setdefault("call", call) or {"allowed": True, "is_pending": False})
    monkeypatch.setattr(agent.dispatch, "dispatch",
                        lambda *a, **k: agent.dispatch.Observation("nikto", "example.org", "ok"))
    ctx = agent.SimpleContext(scan_run_id="11111111-1111-1111-1111-111111111111")
    agent._handle_run_check(
        "22222222-2222-2222-2222-222222222222",
        {"tool": "nikto", "target": "example.org", "rationale": "check for missing security headers"},
        {"example.org": "asset-1"}, {"example.org": "1.2.3.4"}, ctx,
    )
    assert captured["call"]["rationale"] == "check for missing security headers"


def test_run_check_pending_approval_waits_instead_of_skipping(monkeypatch):
    """REQ-APPROVAL-006, the core fix: is_pending used to record
    "pending_approval" and return immediately, so approving the popup that
    appeared had no effect - the agent had already moved on. Now waits and
    executes on approval, exactly like http_request already did."""
    monkeypatch.setattr(agent.client, "authorize",
                        lambda eid, call: {"allowed": False, "is_pending": True, "approval_request_id": "ap1"})
    monkeypatch.setattr(agent.client, "update_scan_run", lambda *a, **k: {})
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: False)
    monkeypatch.setattr(agent.client, "get_approval", lambda aid: {"state": "approved"})
    monkeypatch.setattr(agent.client, "claim_approval", lambda aid: {
        "allowed": True, "tool_call": {"tool": "nikto", "target": "example.org", "args": {}},
    })
    monkeypatch.setattr(agent.client, "complete_approval", lambda aid, **kw: {})
    dispatched = []
    monkeypatch.setattr(agent.dispatch, "dispatch",
                        lambda eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None,
                               single_port=None, confirmed_protocol=None:
                            dispatched.append(tool) or agent.dispatch.Observation(tool, target, "clean, no findings"))
    ctx = agent.SimpleContext(scan_run_id="11111111-1111-1111-1111-111111111111")
    out = agent._handle_run_check(
        "22222222-2222-2222-2222-222222222222",
        {"tool": "nikto", "target": "example.org", "rationale": "double-check headers"},
        {"example.org": "asset-1"}, {"example.org": "1.2.3.4"}, ctx,
    )
    assert dispatched == ["nikto"]
    assert "clean, no findings" in out
    assert "skipped" not in out.lower()


def test_await_approval_skips_on_reject(monkeypatch):
    """REQ-APPROVAL-001: bei Ablehnung wird NICHT ausgefuehrt."""
    monkeypatch.setattr(agent.client, "update_scan_run", lambda *a, **k: {})
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: False)
    monkeypatch.setattr(agent.client, "get_approval", lambda aid: {"state": "rejected"})
    dispatched = []
    monkeypatch.setattr(agent.dispatch, "dispatch", lambda *a, **k: dispatched.append(a))
    ctx = agent.SimpleContext(scan_run_id="11111111-1111-1111-1111-111111111111")
    out = agent._await_approval("22222222-2222-2222-2222-222222222222", "ap1", "asset-1", "example.org",
                                {"method": "POST", "path": "/login"}, None, {"tool": "http_request"}, ctx)
    assert dispatched == [] and "rejected" in out.lower()


def test_await_approval_respects_configured_timeout_not_hardcoded(monkeypatch):
    """REQ-APPROVAL-005: the poll ceiling comes from context.approval_timeout_seconds
    (resolved by the control-plane), not a hardcoded module constant - proven
    here with a short (2s) timeout so the test itself stays fast, and the
    auto-rejection wording names the configured timeout explicitly."""
    monkeypatch.setattr(agent.client, "update_scan_run", lambda *a, **k: {})
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: False)
    monkeypatch.setattr(agent.client, "get_approval", lambda aid: {"state": "requested"})
    monkeypatch.setattr(agent, "_APPROVAL_POLL_SECONDS", 1)
    dispatched = []
    monkeypatch.setattr(agent.dispatch, "dispatch", lambda *a, **k: dispatched.append(a))
    ctx = agent.SimpleContext(scan_run_id="11111111-1111-1111-1111-111111111111", approval_timeout_seconds=2)

    start = time.monotonic()
    out = agent._await_approval("22222222-2222-2222-2222-222222222222", "ap1", "asset-1", "example.org",
                                {"method": "POST", "path": "/login"}, None, {"tool": "http_request"}, ctx)
    elapsed = time.monotonic() - start

    assert dispatched == []
    assert elapsed < 10, "must give up around the configured 2s timeout, not the old hardcoded 900s"
    assert "auto-rejected" in out
    assert "2s timeout" in out


def test_await_approval_cancel_aborts_wait(monkeypatch):
    """REQ-RUN-001 x APPROVAL: ein Cancel des Laufs bricht das Warten ab, kein Dispatch."""
    monkeypatch.setattr(agent.client, "update_scan_run", lambda *a, **k: {})
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: True)
    monkeypatch.setattr(agent.client, "get_approval", lambda aid: {"state": "requested"})
    dispatched = []
    monkeypatch.setattr(agent.dispatch, "dispatch", lambda *a, **k: dispatched.append(a))
    ctx = agent.SimpleContext(scan_run_id="11111111-1111-1111-1111-111111111111")
    out = agent._await_approval("22222222-2222-2222-2222-222222222222", "ap1", "asset-1", "example.org",
                                {"method": "POST", "path": "/login"}, None, {"tool": "http_request"}, ctx)
    assert dispatched == [] and "cancelled" in out.lower()


def test_no_provider_is_noop(monkeypatch):
    monkeypatch.setattr(agent.client, "get_llm_config",
                        lambda: {"base_url": "", "api_key": "", "model": "", "is_usable": False})
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)
    assert ctx.iterations == 0 and ctx.observations == []


# --- REQ-AGENT-009: Tool-Name als Funktionsname wird toleriert -------

def test_tool_named_function_call_is_handled_like_run_check(wired, monkeypatch):
    """Das Modell ruft eine Funktion NAMENS 'nuclei' auf statt
    run_check({"tool": "nuclei", ...}). Muss identisch autorisiert/dispatcht
    werden wie ein echter run_check-Vorschlag."""
    events = []
    monkeypatch.setattr(agent.client, "agent_event",
                        lambda eid, **fields: events.append((fields.get("event"), fields.get("reason"), fields.get("payload"))))
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "nuclei", {"target": "example.org"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "done"})]),
    ]

    ctx = agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    assert wired.dispatched == [("nuclei", "example.org", "1.2.3.4")]
    assert wired.authorize_calls[0]["tool"] == "nuclei"
    assert wired.authorize_calls[0]["target"] == "example.org"
    # Auditiert mit eigenem, unterscheidbarem Grund - nicht wie ein normaler run_check.
    normalized = [e for e in events if e[1] == "llm_proposed_tool_as_function_name"]
    assert len(normalized) == 1
    assert normalized[0][2]["proposal"]["tool"] == "nuclei"


def test_tool_named_function_call_out_of_scope_is_denied_same_as_run_check(wired):
    """Die Normalisierung umgeht NICHT die Autorisierung - ein Out-of-Scope-Ziel
    wird genauso abgelehnt wie ueber den echten run_check-Pfad."""
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "nuclei", {"target": "evil.example.com"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "done"})]),
    ]

    agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    assert wired.dispatched == []  # nie ausgefuehrt


def test_pipeline_owned_nmap_as_function_name_is_still_rejected(wired):
    """nmap ist deterministisch/pipeline-eigen und aus ALLOWED_TOOLS ausgeschlossen
    - die Toleranz darf das NICHT unterlaufen."""
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "nmap", {"target": "example.org"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "done"})]),
    ]

    agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    assert wired.dispatched == []


def test_unknown_function_name_is_still_rejected(wired):
    _FakeOpenAI._script = [
        _assistant([_tool_call("c1", "totally_made_up_function", {"target": "example.org"})]),
        _assistant([_tool_call("c2", "finish", {"summary": "done"})]),
    ]

    agent.run("11111111-1111-1111-1111-111111111111", budget_max_iterations=10)

    assert wired.dispatched == []
