"""REQ-TESTACCT-014 (GitHub #89, R4; found by the live run against DVWA): a live session is a placeholder in everything the platform keeps.

Once the agent's session jar works again (REQ-TESTACCT-012) the jar's cookie is merged into the request BEFORE the Scope Gateway sees it (so the
gateway validates the exact request, REQ-AGENT-022). The first live run showed the consequence: the session id of the test account sat in 21 audit
rows (hash-chained, never erased), 2 approvals and 2 open requests. The session is treated like the password that produced it: the worker swaps it
for `{{session:<token>}}` before anything leaves the process, and puts it back only for the one request that is sent."""

from __future__ import annotations

import json

import httpx
import pytest

from app import test_accounts as ta
from app.control_plane_client import _PlaceholderClient
from app.tasks import agent, dispatch

ENG = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
OTHER_RUN = "33333333-3333-3333-3333-333333333333"
HOST = "shop.example.test"
SESSION = "dc6lj7vng1rr5v7njmo4csn0u1"
LOGIN_OK = f"HTTP/1.1 302 Found\r\nLocation: index.php\r\nSet-Cookie: PHPSESSID={SESSION}; path=/\r\nSet-Cookie: security=low; path=/\r\n\r\n"


@pytest.fixture
def wire(monkeypatch):
    """The real redaction, dispatch and placeholder client; only the network is replaced. `to_gateway` is what the control plane would receive."""
    seen = {"to_gateway": [], "to_runner": [], "raw": LOGIN_OK}
    client = _PlaceholderClient(base_url="http://control-plane.test",
                                transport=httpx.MockTransport(lambda r: seen["to_gateway"].append(r.content.decode()) or httpx.Response(200, json={})))

    def authorize(engagement_id, payload, proposal, context):
        client.post("/internal/authorize", json=payload)
        return {"allowed": True, "reason": "all_checks_passed"}

    def run(tool, target, args, **kw):
        seen["to_runner"].append({"args": args, **kw})
        return {"success": True, "stdout": seen["raw"], "stderr": "", "exit_code": 0}

    monkeypatch.setattr(agent, "_authorize_throttled", authorize)
    monkeypatch.setattr(agent, "_audit_agent_event", lambda eid, event, **kw: client.post("/internal/event", json={"event": event, **kw}))
    monkeypatch.setattr(dispatch.tool_runner, "run", run)
    monkeypatch.setattr(dispatch.tool_execution, "record", lambda *a, **kw: None)
    return seen


def handle(context, **tool_input):
    base = {"target": HOST, "method": "GET", "path": "/", "rationale": "test", "risk_level": "low", "risk": "test"}
    base.update(tool_input)
    return agent._handle_http_request(ENG, base, {HOST: "asset-1"}, {}, context)


def context():
    return agent.SimpleContext(scan_run_id=RUN, single_port=443, protocol_by_host={HOST: "https"})


def test_the_control_plane_gets_the_placeholder_and_the_target_gets_the_cookie(wire):
    ctx = context()
    handle(ctx, method="POST", path="/login", body="username=alice&password=x")
    wire["to_gateway"].clear()
    wire["raw"] = "HTTP/1.1 200 OK\r\n\r\nACCOUNT"
    handle(ctx, path="/account")
    body = " ".join(wire["to_gateway"])
    assert SESSION not in body, "the gateway, its audit row and an approval never hold the session id"
    assert "PHPSESSID={{session:" in body and "security=low" in body, "the name stays, a short setting is not a secret"
    sent = wire["to_runner"][-1]["args"]["headers"]["Cookie"]
    assert f"PHPSESSID={SESSION}" in sent and "{{session" not in sent, "the one request that is sent carries the real value"


def test_the_runner_is_told_to_mask_the_session_in_its_own_log(wire):
    ctx = context()
    handle(ctx, method="POST", path="/login", body="x=1")
    wire["raw"] = "HTTP/1.1 200 OK\r\n\r\nACCOUNT"
    handle(ctx, path="/account")
    assert SESSION in wire["to_runner"][-1]["log_mask"]


def test_a_later_login_rotates_the_session_and_both_values_stay_placeholders(wire):
    ctx = context()
    handle(ctx, method="POST", path="/login", body="x=1")
    wire["raw"] = "HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=rotated-session-value-1234; path=/\r\n\r\nok"
    handle(ctx, path="/a")
    wire["to_gateway"].clear()
    wire["raw"] = "HTTP/1.1 200 OK\r\n\r\nok"
    handle(ctx, path="/b")
    assert "rotated-session-value-1234" not in " ".join(wire["to_gateway"]) and SESSION not in " ".join(wire["to_gateway"])
    assert wire["to_runner"][-1]["args"]["headers"]["Cookie"].startswith("PHPSESSID=rotated-session-value-1234")


# --- the registry ---------------------------------------------------------------------------------------------------------------


def test_a_value_is_replaced_in_any_nesting_and_put_back_for_the_same_run_only():
    ta.register_session_values(RUN, [SESSION])
    payload = {"args": {"headers": {"Cookie": f"PHPSESSID={SESSION}; security=low"}}, "list": [f"saw {SESSION}"]}
    masked = ta.to_placeholders(payload)
    assert SESSION not in json.dumps(masked) and "security=low" in json.dumps(masked)
    assert ta.resolve(masked, run_key=RUN) == payload
    with pytest.raises(ta.UnresolvedPlaceholder):
        ta.resolve(masked, run_key=OTHER_RUN)


def test_negative_a_short_cookie_value_is_not_a_session():
    ta.register_session_values(RUN, ["low", "true", "1234567890abcde"])
    text = "security=low flag=true"
    assert ta.to_placeholders(text) == text and not ta._sessions


def test_the_session_is_forgotten_with_the_run():
    ta.register_session_values(RUN, [SESSION])
    token = ta.session_placeholder(SESSION)
    ta.unregister(RUN)
    assert ta.to_placeholders(f"x {SESSION}") == f"x {SESSION}"
    with pytest.raises(ta.UnresolvedPlaceholder):
        ta.resolve(f"Cookie: {token}", run_key=RUN)


def test_dispatch_never_sends_an_unresolvable_session_placeholder(wire):
    ta.register_session_values(RUN, [SESSION])
    token = ta.session_placeholder(SESSION)
    result = dispatch._run(ENG, "http_request", "https://shop.example.test", {"method": "GET", "path": "/", "headers": {"Cookie": f"PHPSESSID={token}"}}, OTHER_RUN)
    assert wire["to_runner"] == [] and result["error_reason"] == "credential_unresolvable"


def test_an_approved_call_stored_with_the_placeholder_is_sent_with_the_current_session(wire):
    ta.register_session_values(RUN, [SESSION])
    token = ta.session_placeholder(SESSION)
    dispatch._run(ENG, "http_request", "https://shop.example.test", {"method": "POST", "path": "/x", "headers": {"Cookie": f"PHPSESSID={token}"}}, RUN)
    assert wire["to_runner"][0]["args"]["headers"]["Cookie"] == f"PHPSESSID={SESSION}"
