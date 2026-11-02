"""REQ-TESTACCT-003/005/007/008 (GitHub #89, R4): the agent phase with test accounts, with every network edge replaced.

The model writes the real value everywhere it can. These tests follow it: what the Scope Gateway receives, what the audit events carry, what
goes to the control plane, what reaches the tool runner - and they fail if the value is anywhere but on the one request that is sent."""

from __future__ import annotations

import json

import httpx
import pytest

from app import test_accounts as ta
from app import tool_execution
from app.control_plane_client import ControlPlaneClient, _PlaceholderClient, client
from app.tasks import agent, dispatch, pipeline

SECRET = "-".join(["S3cret", "Pass", "word", "4711"])
ENG = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
HOST = "shop.example.test"
ACCOUNT = {"label": "shop", "role": "user", "kind": "login_form", "username": "alice", "secret": SECRET, "login_path": "/login",
           "login_paths": {HOST: "/login"}, "can_use_on": [HOST, "blog.example.test"],
           "cannot_use_on": [{"host": "old.example.test", "reason": "held_for_review", "reason_text": "held for review"}]}


@pytest.fixture(autouse=True)
def _accounts():
    ta.register(RUN, [ACCOUNT])
    yield
    ta.unregister(RUN)


@pytest.fixture
def seen(monkeypatch):
    log = {"authorize": [], "events": [], "dispatch": []}

    def authorize(engagement_id, payload, proposal, context):
        log["authorize"].append((payload, proposal))
        return log.get("decision", {"allowed": True, "reason": "all_checks_passed"})

    monkeypatch.setattr(agent, "_authorize_throttled", authorize)
    monkeypatch.setattr(agent, "_audit_agent_event", lambda eid, event, **kw: log["events"].append((event, kw)))

    def fake_dispatch(engagement_id, asset_id, tool, target, ip=None, args=None, **kw):
        log["dispatch"].append(args)
        return type("Obs", (), {"as_text": lambda self: log.get("response", "HTTP/1.1 200 OK\r\n\r\nok")})()

    monkeypatch.setattr(agent.dispatch, "dispatch", fake_dispatch)
    return log


def ctx():
    return agent.SimpleContext(scan_run_id=RUN)


def call(context, **tool_input):
    base = {"target": HOST, "method": "POST", "path": "/login", "body": f"username=alice&password={SECRET}",
            "rationale": f"log in as alice with {SECRET}", "risk_level": "low", "risk": f"uses {SECRET}"}
    base.update(tool_input)
    return agent._handle_http_request(ENG, base, {HOST: "asset-1", "blog.example.test": "asset-2"}, {HOST: "10.0.0.1"}, context)


# --- what leaves the handler ------------------------------------------------------------------------------------------------


def test_the_gateway_the_events_and_the_dispatch_receive_the_placeholder_never_the_value(seen):
    call(ctx(), headers={"X-Debug": f"pw={SECRET}"})
    payload, proposal = seen["authorize"][0]
    wire = json.dumps([payload, proposal, seen["events"], seen["dispatch"]], default=str)
    assert SECRET not in wire
    assert "{{testaccount:shop}}" in json.dumps(payload["args"]) and payload["rationale"].count("{{testaccount:shop}}") == 1
    assert "{{testaccount:shop}}" in payload["risk"]["description"]
    assert seen["dispatch"] == [] or "{{testaccount:shop}}" in json.dumps(seen["dispatch"])


def test_the_path_and_a_nested_header_are_rewritten_too(seen):
    call(ctx(), method="GET", body=None, path=f"/api?token={SECRET}", headers={"Authorization": f"Bearer {SECRET}"})
    args = seen["authorize"][0][0]["args"]
    assert SECRET not in json.dumps(args) and args["headers"]["Authorization"] == "Bearer {{testaccount:shop}}"


def test_a_refusal_that_names_the_account_reaches_the_model_without_the_value(seen):
    seen["decision"] = {"allowed": False, "reason": "credential_host_not_usable",
                        "detail": "test account shop cannot be used on blog.example.test: not assigned to this account"}
    text = call(ctx(), target="blog.example.test")
    assert "credential_host_not_usable" in text and "test account shop cannot be used on blog.example.test" in text
    assert SECRET not in text


def test_identity_keeps_one_accounts_session_apart_from_another(seen):
    context = ctx()
    seen["response"] = "HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: sid=AAA\r\n\r\n"
    call(context, identity="shop")
    assert context.cookies_by_host[HOST] == {"shop": {"sid": "AAA"}}
    seen["response"] = "HTTP/1.1 200 OK\r\n\r\nplain"
    call(context, method="GET", body=None, path="/home", identity="primary")
    assert seen["authorize"][-1][0]["args"]["headers"].get("Cookie") is None, "the primary session does not carry the account's cookie"


# --- login outcomes ---------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("response,expected", [
    ("HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: sid=AAA\r\n\r\n", "session_established"),
    ("HTTP/1.1 401 Unauthorized\r\n\r\nbad", "rejected"),
    ("HTTP/1.1 302 Found\r\nLocation: /login?error=1\r\nSet-Cookie: sid=AAA\r\n\r\n", "rejected"),
])
def test_the_declared_login_is_classified_and_the_audit_event_names_the_account_not_the_value(seen, response, expected):
    context = ctx()
    seen["response"] = response
    call(context)
    assert context.login_outcomes == {("shop", HOST): expected}
    events = [kw for name, kw in seen["events"] if name == "test_account_login"]
    assert events and events[0]["reason"] == expected and events[0]["proposal"]["account"] == "shop"
    assert SECRET not in json.dumps(events, default=str)


@pytest.mark.parametrize("override", [{"path": "/other"}, {"method": "PUT"}, {"body": "q=1"}])
def test_a_request_that_is_not_the_declared_login_is_not_recorded_as_one(seen, override):
    context = ctx()
    call(context, **override)
    assert context.login_outcomes == {}


def test_a_later_attempt_replaces_an_earlier_outcome_for_the_same_host(seen):
    context = ctx()
    seen["response"] = "HTTP/1.1 401 Unauthorized\r\n\r\nbad"
    call(context)
    seen["response"] = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=A\r\n\r\n"
    call(context)
    assert context.login_outcomes[("shop", HOST)] == "session_established"


# --- the last mile: dispatch._run -----------------------------------------------------------------------------------------------


def test_the_value_is_put_back_only_for_the_request_that_goes_to_the_runner(monkeypatch):
    sent = []
    monkeypatch.setattr(dispatch.tool_runner, "run", lambda tool, target, args, **k: sent.append(args) or {"success": True, "stdout": "HTTP/1.1 200 OK\r\n\r\n"})
    monkeypatch.setattr(tool_execution, "record", lambda *a, **k: None)
    args = {"method": "POST", "path": "/login", "body": "u=alice&p={{testaccount:shop}}", "headers": {}}
    dispatch._run(ENG, "http_request", HOST, args, RUN)
    assert sent[0]["body"] == f"u=alice&p={SECRET}"
    assert args["body"] == "u=alice&p={{testaccount:shop}}", "the proposal everyone else holds is untouched"


def test_negative_a_placeholder_that_cannot_be_resolved_is_never_sent(monkeypatch):
    sent, recorded = [], []
    monkeypatch.setattr(dispatch.tool_runner, "run", lambda *a, **k: sent.append(a) or {"success": True, "stdout": ""})
    monkeypatch.setattr(tool_execution, "record", lambda *a, **k: recorded.append(k))
    result = dispatch._run(ENG, "http_request", HOST, {"method": "POST", "path": "/login", "body": "p={{testaccount:ghost}}"}, RUN)
    assert sent == [], "nothing went to the runner"
    assert result["success"] is False and result["error_reason"] == "credential_unresolvable"
    assert recorded and recorded[0]["result"]["error_reason"] == "credential_unresolvable", "the failure is recorded, so it feeds the coverage signal"


def test_negative_after_the_phase_ended_an_approved_call_cannot_be_sent_with_the_placeholder(monkeypatch):
    sent = []
    monkeypatch.setattr(dispatch.tool_runner, "run", lambda *a, **k: sent.append(a) or {"success": True, "stdout": ""})
    monkeypatch.setattr(tool_execution, "record", lambda *a, **k: None)
    ta.unregister(RUN)
    result = dispatch._run(ENG, "http_request", HOST, {"method": "POST", "path": "/login", "body": "p={{testaccount:shop}}"}, RUN)
    assert sent == [] and result["error_reason"] == "credential_unresolvable"


def test_a_request_without_a_placeholder_goes_through_unchanged(monkeypatch):
    sent = []
    monkeypatch.setattr(dispatch.tool_runner, "run", lambda tool, target, args, **k: sent.append(args) or {"success": True, "stdout": ""})
    monkeypatch.setattr(tool_execution, "record", lambda *a, **k: None)
    args = {"method": "GET", "path": "/", "headers": {}}
    dispatch._run(ENG, "http_request", HOST, args, RUN)
    assert sent == [args]


# --- the choke point of everything sent to the control plane ---------------------------------------------------------------------


def test_the_client_replaces_the_value_in_every_json_body_before_it_leaves():
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.content.decode())
        return httpx.Response(200, json={"ok": True})

    c = _PlaceholderClient(base_url="http://control-plane.test", transport=httpx.MockTransport(handler))
    c.post("/x", json={"request_messages": [{"role": "user", "content": f"password {SECRET}"}], "n": 1})
    c.patch("/y", json={"state_reason": f"saw {SECRET}"})
    c.put("/z", json={"deep": {"list": [SECRET]}})
    assert all(SECRET not in body for body in captured) and all("{{testaccount:shop}}" in body for body in captured)


def test_the_client_is_a_no_op_without_registered_accounts():
    ta.unregister(RUN)
    captured = []
    c = _PlaceholderClient(base_url="http://control-plane.test",
                           transport=httpx.MockTransport(lambda r: captured.append(r.content.decode()) or httpx.Response(200, json={})))
    c.post("/x", json={"v": SECRET})
    assert SECRET in captured[0], "nothing is rewritten outside an agent phase that has accounts"


def test_the_real_control_plane_client_uses_the_placeholder_client():
    assert isinstance(ControlPlaneClient()._client, _PlaceholderClient)


# --- the first message ------------------------------------------------------------------------------------------------------------


def test_the_first_message_carries_the_real_value_the_two_lists_and_the_rules(monkeypatch):
    monkeypatch.setattr(agent, "_safe_agent_context", lambda eid: {"hosts": [], "test_accounts": [ACCOUNT]})
    monkeypatch.setattr(agent, "_render_evidence", lambda *a, **k: "(evidence)")
    text = agent._initial_context(ENG, {HOST: "asset-1"})
    assert SECRET in text and "Can be used on: shop.example.test, blog.example.test" in text
    assert "old.example.test (held for review)" in text and "UNTESTED" in text


def test_the_first_message_has_no_block_when_the_engagement_has_no_account(monkeypatch):
    monkeypatch.setattr(agent, "_safe_agent_context", lambda eid: {"hosts": []})
    monkeypatch.setattr(agent, "_render_evidence", lambda *a, **k: "(evidence)")
    assert "TEST ACCOUNTS" not in agent._initial_context(ENG, {HOST: "asset-1"})


# --- the phase: registration, reporting, degraded coverage --------------------------------------------------------------------------


def _phase(monkeypatch, *, outcomes, accounts=(ACCOUNT,), parked=None, report=None):
    ta.unregister(RUN)
    monkeypatch.setattr(agent, "_safe_agent_context", lambda eid: {"test_accounts": list(accounts)})
    reported = []
    seen_during = {}

    def phase(*a, **k):
        seen_during["registered"] = ta.active()
        context = agent.SimpleContext(scan_run_id=RUN)
        context.login_outcomes = dict(outcomes)
        context.parked = parked
        return context

    monkeypatch.setattr(agent, "_run_phase", phase)
    monkeypatch.setattr(client, "record_test_account_outcomes",
                        lambda run_id, outs: reported.append((run_id, outs)) or (report or {"coverage_lost": False}))
    context = agent.run(ENG, 10, scan_run_id=RUN)
    return context, reported, seen_during


def test_the_accounts_exist_only_for_the_phase(monkeypatch):
    _, _, seen_during = _phase(monkeypatch, outcomes={})
    assert seen_during["registered"] is True and not ta.active(), "forgotten when the phase ends"


def test_every_assigned_usable_host_gets_an_outcome_and_a_host_not_tried_reads_not_attempted(monkeypatch):
    _, reported, _ = _phase(monkeypatch, outcomes={("shop", HOST): "session_established"})
    (run_id, outs), = reported
    assert run_id == RUN
    assert sorted((o["host"], o["outcome"]) for o in outs) == [("blog.example.test", "not_attempted"), (HOST, "session_established")]


def test_lost_coverage_is_carried_to_the_pipeline_as_a_degraded_reason(monkeypatch):
    context, _, _ = _phase(monkeypatch, outcomes={("shop", HOST): "rejected"}, report={"coverage_lost": True})
    assert context.auth_coverage_lost is True and context.auth_coverage_note == "coverage_degraded:authenticated_coverage_lost"


def test_negative_a_clean_login_does_not_degrade_the_run(monkeypatch):
    context, _, _ = _phase(monkeypatch, outcomes={("shop", HOST): "session_established"})
    assert context.auth_coverage_lost is False


def test_negative_a_parked_run_reports_nothing_yet(monkeypatch):
    _, reported, _ = _phase(monkeypatch, outcomes={}, parked={"park": {}})
    assert reported == []


def test_without_accounts_nothing_is_registered_or_reported(monkeypatch):
    _, reported, seen_during = _phase(monkeypatch, outcomes={}, accounts=())
    assert reported == [] and seen_during["registered"] is False


def test_negative_a_failed_report_never_breaks_the_scan(monkeypatch):
    ta.unregister(RUN)
    monkeypatch.setattr(agent, "_safe_agent_context", lambda eid: {"test_accounts": [ACCOUNT]})
    monkeypatch.setattr(agent, "_run_phase", lambda *a, **k: agent.SimpleContext(scan_run_id=RUN))

    def boom(*a, **k):
        raise RuntimeError("control plane down")

    monkeypatch.setattr(client, "record_test_account_outcomes", boom)
    assert agent.run(ENG, 10, scan_run_id=RUN).auth_coverage_lost is False


def test_negative_the_accounts_are_forgotten_even_if_the_phase_raises(monkeypatch):
    ta.unregister(RUN)
    monkeypatch.setattr(agent, "_safe_agent_context", lambda eid: {"test_accounts": [ACCOUNT]})

    def explode(*a, **k):
        raise RuntimeError("phase crashed")

    monkeypatch.setattr(agent, "_run_phase", explode)
    with pytest.raises(RuntimeError):
        agent.run(ENG, 10, scan_run_id=RUN)
    assert not ta.active(), "the value must not stay in memory after a crash"


def test_the_pipeline_marks_the_run_degraded_when_the_login_was_lost(monkeypatch):
    updates = []
    base = {"supervision": "attended", "scan_profile": "standard", "trigger": "manual", "scope_hosts": None, "retest_finding_id": None,
            "operating_mode": "assessment", "approval_timeout_seconds": 30, "retest_items": None, "send_approval_ids": [],
            "agent_allowed": True}
    monkeypatch.setattr(client, "run_info", lambda rid: dict(base))
    monkeypatch.setattr(client, "claim_scan_run", lambda *a, **k: {"attempt": 1, "phase": "discovery", "state": "running",
                                                                    "cancel_requested": False, "checkpoint": None})
    monkeypatch.setattr(client, "is_cancel_requested", lambda *a, **k: False)
    monkeypatch.setattr(client, "update_scan_run", lambda *a, **k: updates.append(k) or {})
    monkeypatch.setattr(client, "materialize_graph", lambda *a, **k: None)
    monkeypatch.setattr(pipeline.discovery, "run", lambda *a, **k: [{"value": "a.example.com", "asset_id": "1", "asset_type": "domain"}])
    monkeypatch.setattr(pipeline.asset_review, "gate", lambda e, r, d: d)
    for phase in ("fingerprint", "correlate"):
        monkeypatch.setattr(getattr(pipeline, phase), "run", lambda *a, **k: [])
    monkeypatch.setattr(pipeline.score, "run", lambda *a, **k: None)
    monkeypatch.setattr(pipeline.report, "run", lambda *a, **k: None)

    class Lost:
        incomplete_reason = None
        parked = None
        auth_coverage_lost = True
        auth_coverage_note = "coverage_degraded:authenticated_coverage_lost"

    monkeypatch.setattr(agent, "run", lambda *a, **k: Lost())
    tool_execution.clear_coverage(RUN)
    pipeline.run_scan.run(ENG, RUN)
    final = updates[-1]
    assert final["state"] == "done" and "coverage_degraded:authenticated_coverage_lost" in final["state_reason"]
