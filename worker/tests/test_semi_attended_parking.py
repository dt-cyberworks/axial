"""REQ-MODE-016: a semi-attended run parks on a decision instead of holding a worker
slot, and continues from where it stopped when the decision is made.

Uses the same scripted-LLM harness as test_agent.py. What is verified:
  * the run hands itself back at the first call that needs a person, without polling;
  * what it stores to continue holds no session cookie and not the call's arguments
    (the exact call is read back from the approval when it is claimed);
  * on resume, an approved call runs exactly as stored, a rejected or expired one
    is reported as not executed, and the remaining calls of that turn still run;
  * an attended run is unchanged: it waits in place."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.tasks import agent

ENG = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"


def _tool_call(call_id: str, name: str, args: dict):
    return SimpleNamespace(id=call_id, type="function", function=SimpleNamespace(name=name, arguments=json.dumps(args)))


def _assistant(tool_calls=None, content=""):
    msg = SimpleNamespace(content=content, tool_calls=tool_calls)
    return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason="tool_calls" if tool_calls else "stop")])


class _Completions:
    def __init__(self, script):
        self.script = list(script)
        self.seen: list[list[dict]] = []

    def create(self, **kwargs):
        self.seen.append([dict(m) for m in kwargs["messages"]])
        return self.script.pop(0) if self.script else _assistant(None, "done")


class _FakeOpenAI:
    script: list = []
    instance = None

    def __init__(self, base_url=None, api_key=None, max_retries=None):
        self.chat = SimpleNamespace(completions=_Completions(_FakeOpenAI.script))
        _FakeOpenAI.instance = self


POST = {"target": "example.org", "method": "POST", "path": "/api/items", "body": '{"name": "x"}',
        "risk_level": "low", "risk": "creates one test record"}
EXACT = {"tool": "http_request", "target": "example.org",
         "args": {"method": "POST", "path": "/api/items", "headers": {}, "body": '{"name": "x"}'}}


@pytest.fixture
def world(monkeypatch):
    c = agent.client
    monkeypatch.setattr(c, "get_llm_config", lambda: {"base_url": "https://x/v1", "api_key": "k", "model": "m", "is_usable": True})
    monkeypatch.setattr(c, "list_discovered_assets", lambda eid, in_scope=None: [{"id": "asset-1", "value": "example.org", "in_scope": True}])
    monkeypatch.setattr(c, "materialize_dns", lambda eid, scan_run_id=None: {"resolved": [{"hostname": "example.org", "ip_address": "1.2.3.4"}]})
    monkeypatch.setattr(c, "get_agent_config", lambda eid: {"prompt": "", "enabled_tools": ["httpx", "http_request"]})
    monkeypatch.setattr(c, "get_agent_context", lambda eid: {"hosts": []})
    monkeypatch.setattr(c, "record_agent_step", lambda *a, **k: None)
    monkeypatch.setattr(c, "agent_event", lambda *a, **k: {})
    monkeypatch.setattr(c, "update_scan_run", lambda *a, **k: {})
    monkeypatch.setattr(agent, "CancelProbe", type("CP", (), {
        "for_run": classmethod(lambda cls, rid: type("P", (), {"is_cancelled": lambda self: False})())}))
    monkeypatch.setattr("openai.OpenAI", _FakeOpenAI)

    state = SimpleNamespace(approval="approved", dispatched=[], claimed=[], completed=[], polled=[], withdrawn=[])

    def authorize(eid, call):
        if call["tool"] == "http_request" and call["args"].get("method") == "POST":
            return {"allowed": False, "is_pending": True, "reason": "pending_approval", "approval_request_id": "ap-1"}
        return {"allowed": True, "is_pending": False, "reason": "all_checks_passed"}

    monkeypatch.setattr(c, "authorize", authorize)
    monkeypatch.setattr(c, "get_approval", lambda aid: state.polled.append(aid) or {"state": state.approval})
    monkeypatch.setattr(c, "claim_approval", lambda aid: state.claimed.append(aid) or {"allowed": True, "tool_call": EXACT})
    monkeypatch.setattr(c, "complete_approval", lambda aid, **k: state.completed.append((aid, k)) or {})
    monkeypatch.setattr(c, "withdraw_approval", lambda aid, reason="": state.withdrawn.append(aid))
    monkeypatch.setattr(c, "add_suggestion", lambda *a, **k: None)
    monkeypatch.setattr(agent.time, "sleep", lambda s: pytest.fail("a parked run must not poll"))

    def dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None,
                 confirmed_protocol=None):
        state.dispatched.append((tool, target, (args or {}).get("method"), (args or {}).get("path")))
        return agent.dispatch.Observation(tool, target, "ok", findings=0)

    monkeypatch.setattr(agent.dispatch, "dispatch", dispatch)

    def info(supervision):
        monkeypatch.setattr(c, "run_info", lambda rid: {
            "supervision": supervision, "operating_mode": "assessment", "scan_profile": "standard",
            "scope_hosts": None, "trigger": "manual", "retest_finding_id": None, "approval_timeout_seconds": 900})

    state.supervision = info
    return state


TWO_CALLS = lambda: [  # noqa: E731
    _assistant([_tool_call("c1", "http_request", POST), _tool_call("c2", "run_check", {"tool": "httpx", "target": "example.org"})]),
]


def test_a_semi_attended_run_parks_at_the_first_call_that_needs_a_person(world):
    world.supervision("semi_attended")
    _FakeOpenAI.script = TWO_CALLS()
    ctx = agent.run(ENG, 10, scan_run_id=RUN)

    assert ctx.parked is not None
    assert world.polled == [] and world.dispatched == []
    assert ctx.parked["pending_tool_call_id"] == "c1" and ctx.parked["iterations"] == 1
    assert [t["id"] for t in ctx.parked["remaining"]] == ["c2"]
    assert ctx.parked["park"]["approval_id"] == "ap-1"
    roles = [m["role"] for m in ctx.parked["messages"]]
    assert roles[-1] == "assistant", "the assistant turn is kept; the pending call has no result yet"


def test_what_is_stored_to_continue_holds_no_cookie_and_not_the_call_arguments(world):
    world.supervision("semi_attended")
    _FakeOpenAI.script = TWO_CALLS()
    ctx = agent.run(ENG, 10, scan_run_id=RUN)
    ctx.cookies_by_host["example.org"] = {"primary": {"sid": "s3cr3t"}}  # what the run holds in memory
    park = ctx.parked["park"]
    assert set(park) == {"approval_id", "target", "proposal", "identity", "tool"}
    assert "s3cr3t" not in json.dumps(ctx.parked)
    assert "args" not in park and "headers" not in json.dumps(park)


def test_an_approved_call_is_claimed_and_run_exactly_as_stored_then_the_turn_continues(world):
    world.supervision("semi_attended")
    _FakeOpenAI.script = TWO_CALLS()
    parked = agent.run(ENG, 10, scan_run_id=RUN).parked

    world.approval = "approved"
    _FakeOpenAI.script = [_assistant([_tool_call("c3", "finish", {"summary": "done"})])]
    ctx = agent.run(ENG, 10, scan_run_id=RUN, resume_state=parked)

    assert world.claimed == ["ap-1"]
    assert world.dispatched == [("http_request", "example.org", "POST", "/api/items"), ("httpx", "example.org", None, None)]
    assert world.completed and world.completed[0][1] == {"success": True}
    assert ctx.parked is None and ctx.exhausted is True and ctx.conclusion == "done"
    # The model is told what became of both calls of its turn before it continues.
    sent = _FakeOpenAI.instance.chat.completions.seen[0]
    tool_results = {m["tool_call_id"]: m["content"] for m in sent if m.get("role") == "tool"}
    assert set(tool_results) == {"c1", "c2"}
    assert ctx.iterations == 3  # the two calls of the turn and the finish


@pytest.mark.parametrize("state, wording", [("rejected", "rejected"), ("expired", "auto-rejected"), ("cancelled", "cancelled")])
def test_a_call_that_was_not_approved_is_never_executed_but_the_rest_of_the_turn_is(world, state, wording):
    world.supervision("semi_attended")
    _FakeOpenAI.script = TWO_CALLS()
    parked = agent.run(ENG, 10, scan_run_id=RUN).parked

    world.approval = state
    _FakeOpenAI.script = [_assistant([_tool_call("c3", "finish", {"summary": "done"})])]
    agent.run(ENG, 10, scan_run_id=RUN, resume_state=parked)

    assert world.claimed == [] and world.completed == []
    assert world.dispatched == [("httpx", "example.org", None, None)]
    sent = _FakeOpenAI.instance.chat.completions.seen[0]
    first = next(m for m in sent if m.get("tool_call_id") == "c1")
    assert first["content"].startswith("NOT EXECUTED") and wording in first["content"]


def test_an_unreadable_or_still_open_decision_is_treated_as_not_approved(world):
    world.supervision("semi_attended")
    _FakeOpenAI.script = TWO_CALLS()
    parked = agent.run(ENG, 10, scan_run_id=RUN).parked
    for value in ("requested", "unknown"):
        world.approval = value
        world.dispatched.clear()
        world.claimed.clear()
        _FakeOpenAI.script = [_assistant(None, "done")]
        agent.run(ENG, 10, scan_run_id=RUN, resume_state=parked)
        assert world.claimed == []
        assert ("http_request", "example.org", "POST", "/api/items") not in world.dispatched


def test_a_target_that_left_the_scope_while_parked_is_not_touched(world, monkeypatch):
    world.supervision("semi_attended")
    _FakeOpenAI.script = TWO_CALLS()
    parked = agent.run(ENG, 10, scan_run_id=RUN).parked
    monkeypatch.setattr(agent.client, "list_discovered_assets",
                        lambda eid, in_scope=None: [{"id": "asset-9", "value": "other.example.net", "in_scope": True}])
    monkeypatch.setattr(agent.client, "materialize_dns", lambda eid, scan_run_id=None: {"resolved": []})
    world.approval = "approved"
    _FakeOpenAI.script = [_assistant(None, "done")]
    agent.run(ENG, 10, scan_run_id=RUN, resume_state=parked)
    assert world.dispatched == [] and world.claimed == []


def test_an_attended_run_waits_in_place_and_never_parks(world, monkeypatch):
    world.supervision("attended")
    _FakeOpenAI.script = [_assistant([_tool_call("c1", "http_request", POST)]), _assistant(None, "done")]
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)  # the live wait polls
    ctx = agent.run(ENG, 10, scan_run_id=RUN)
    assert ctx.parked is None
    assert world.polled and world.claimed == ["ap-1"]
    assert world.dispatched[0][:2] == ("http_request", "example.org")


def test_a_second_decision_in_the_rest_of_the_turn_parks_again(world):
    world.supervision("semi_attended")
    two_writes = {**POST, "path": "/api/other"}
    _FakeOpenAI.script = [_assistant([_tool_call("c1", "http_request", POST), _tool_call("c2", "http_request", two_writes)])]
    parked = agent.run(ENG, 10, scan_run_id=RUN).parked

    world.approval = "approved"
    ctx = agent.run(ENG, 10, scan_run_id=RUN, resume_state=parked)
    assert ctx.parked is not None
    assert ctx.parked["pending_tool_call_id"] == "c2" and ctx.parked["remaining"] == []
    assert any(m.get("tool_call_id") == "c1" for m in ctx.parked["messages"])
