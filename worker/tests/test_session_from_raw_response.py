"""REQ-TESTACCT-012 (GitHub #89, R4; a regression of REQ-AGENT-022/023 found by the live verification on the dev stack).

The response of an http_request is REDACTED once, in dispatch (REQ-AUDIT-007: `Set-Cookie: <redacted>`), and that redacted text is what
the model, the audit trail and everything durable receives. The agent's run-scoped session jar was filled by parsing that same text,
so since REQ-AUDIT-007 it never held a cookie: a login worked and the next request was anonymous. Every earlier test fed a hand-built
raw `Set-Cookie` straight into the jar and could not see it.

These tests run the real redaction and the real handler, and replace only the network."""

from __future__ import annotations

import pytest

from app import test_accounts as ta
from app.tasks import agent, dispatch

ENG = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
HOST = "shop.example.test"
SESSION = "LIVE-SESSION-VALUE-9f3a"
PASSWORD = "-".join(["S3cret", "Pass", "word", "4711"])
RAW_LOGIN_OK = f"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: sid={SESSION}; HttpOnly; Path=/\r\n\r\n{{\"ok\": true}}"
ACCOUNT = {"label": "shop", "role": "user", "kind": "login_form", "username": "alice", "secret": PASSWORD, "login_path": "/login",
           "login_paths": {HOST: "/login"}, "can_use_on": [HOST], "cannot_use_on": []}


@pytest.fixture
def network(monkeypatch):
    """The real dispatch and redaction; a runner that answers with `raw` and remembers what it was asked."""
    state = {"raw": RAW_LOGIN_OK, "asked": [], "events": [], "recorded": []}

    def run(tool, target, args, **kw):
        state["asked"].append({"target": target, "args": args})
        return {"success": True, "stdout": state["raw"], "stderr": "", "exit_code": 0}

    monkeypatch.setattr(dispatch.tool_runner, "run", run)
    monkeypatch.setattr(dispatch.tool_execution, "record", lambda *a, **kw: state["recorded"].append(kw))
    monkeypatch.setattr(agent, "_authorize_throttled", lambda *a, **kw: {"allowed": True, "reason": "all_checks_passed"})
    monkeypatch.setattr(agent, "_audit_agent_event", lambda eid, event, **kw: state["events"].append((event, kw)))
    return state


def handle(context, **tool_input):
    base = {"target": HOST, "method": "GET", "path": "/", "rationale": "test", "risk_level": "low", "risk": "test"}
    base.update(tool_input)
    return agent._handle_http_request(ENG, base, {HOST: "asset-1"}, {}, context)


def new_context():
    return agent.SimpleContext(scan_run_id=RUN, single_port=443, protocol_by_host={HOST: "https"})


def test_the_text_is_redacted_and_the_session_is_still_in_the_jar(network):
    context = new_context()
    text = handle(context, method="POST", path="/login", body="username=alice&password=x", identity="primary")
    assert SESSION not in text and "<redacted>" in text, "the model and the audit trail get the redacted response"
    assert context.cookies_by_host[HOST]["primary"] == {"sid": SESSION}, "the jar holds the real value, in memory"
    assert SESSION not in repr([e for e in network["events"]]), "the audit events name the cookie, never its value"
    assert ("session_established", ) == tuple(e[0] for e in network["events"] if e[0] == "session_established")


def test_the_next_request_carries_the_session(network):
    context = new_context()
    handle(context, method="POST", path="/login", body="username=alice&password=x")
    network["raw"] = "HTTP/1.0 200 OK\r\n\r\nACCOUNT-AREA"
    handle(context, path="/account")
    sent = network["asked"][-1]["args"]
    assert sent["headers"]["Cookie"] == f"sid={SESSION}"


def test_the_jar_is_kept_per_identity_and_per_host(network):
    context = new_context()
    handle(context, method="POST", path="/login", body="username=alice&password=x", identity="primary")
    network["raw"] = "HTTP/1.0 200 OK\r\n\r\nplain"
    handle(context, path="/account", identity="secondary")
    assert "Cookie" not in (network["asked"][-1]["args"].get("headers") or {}), "another identity does not get the session"


def test_a_tunneled_https_response_with_two_header_blocks_is_read_too(network):
    network["raw"] = f"HTTP/1.1 200 Connection Established\r\n\r\nHTTP/1.1 200 OK\r\nSet-Cookie: sid={SESSION}\r\n\r\nok"
    context = new_context()
    text = handle(context, method="POST", path="/login", body="username=alice&password=x")
    assert SESSION not in text
    assert context.cookies_by_host[HOST]["primary"] == {"sid": SESSION}


def test_a_login_is_classified_from_the_raw_cookie_not_from_the_redacted_text(network):
    ta.register(RUN, [ACCOUNT])
    try:
        context = new_context()
        handle(context, method="POST", path="/login", body=f"username=alice&password={PASSWORD}", identity="shop")
        assert context.login_outcomes == {("shop", HOST): "session_established"}
        network["raw"] = "HTTP/1.0 401 Unauthorized\r\n\r\nnope"
        handle(context, method="POST", path="/login", body=f"username=alice&password={PASSWORD}", identity="shop")
        assert context.login_outcomes == {("shop", HOST): "rejected"}
    finally:
        ta.unregister(RUN)


def test_a_bare_redirect_proves_nothing_when_no_session_was_held_for_that_identity(network):
    """Found live against DVWA (2026-11-01): the session id is issued by the login FORM, the accepted login answers `302 -> index.php` and issues
    nothing new, a stale CSRF token or a wrong password answers `302 -> login.php`. The first rule read the accepted login as `rejected`."""
    ta.register(RUN, [ACCOUNT])
    try:
        context = new_context()
        network["raw"] = "HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=pre-login-id; path=/\r\n\r\n<form>login</form>"
        handle(context, path="/login", identity="primary")      # the session belongs to the primary identity, the login to shop
        body = f"username=alice&password={PASSWORD}&user_token=abc"
        network["raw"] = "HTTP/1.1 302 Found\r\nLocation: login.php\r\nContent-Length: 0\r\n\r\n"
        handle(context, method="POST", path="/login", body=body, identity="shop")
        assert context.login_outcomes == {("shop", HOST): "rejected"}, "back to the form: a wrong password or a stale token"
        network["raw"] = "HTTP/1.1 302 Found\r\nLocation: index.php\r\nContent-Length: 0\r\n\r\n"
        handle(context, method="POST", path="/login", body=body, identity="shop")
        assert context.login_outcomes == {("shop", HOST): "rejected"}, "no session was held for identity shop before: a bare redirect proves nothing"
    finally:
        ta.unregister(RUN)


def test_the_same_login_with_the_session_held_before_is_established(network):
    ta.register(RUN, [ACCOUNT])
    try:
        context = new_context()
        network["raw"] = "HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=pre-login-id; path=/\r\n\r\n<form>login</form>"
        handle(context, path="/login", identity="shop")
        assert context.cookies_by_host[HOST]["shop"] == {"PHPSESSID": "pre-login-id"}
        body = f"username=alice&password={PASSWORD}&user_token=abc"
        network["raw"] = "HTTP/1.1 302 Found\r\nLocation: login.php\r\nContent-Length: 0\r\n\r\n"
        handle(context, method="POST", path="/login", body=body, identity="shop")
        assert context.login_outcomes == {("shop", HOST): "rejected"}
        network["raw"] = "HTTP/1.1 302 Found\r\nLocation: index.php\r\nContent-Length: 0\r\n\r\n"
        handle(context, method="POST", path="/login", body=body, identity="shop")
        assert context.login_outcomes == {("shop", HOST): "session_established"}, "the later attempt replaces the earlier one"
    finally:
        ta.unregister(RUN)


def test_negative_a_response_without_a_cookie_leaves_the_jar_empty(network):
    network["raw"] = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nno cookie here"
    context = new_context()
    handle(context, path="/")
    assert context.cookies_by_host.get(HOST, {}) == {}


def test_the_observation_does_not_serialize_the_cookies():
    obs = dispatch.Observation("http_request", HOST, "GET / ->\nHTTP/1.0 200 OK\nSet-Cookie: <redacted>", set_cookies={"sid": SESSION})
    assert SESSION not in obs.as_text() and SESSION not in repr(obs.summary)


def test_an_observation_built_by_hand_still_works_through_its_text():
    """The older tests (and any caller that has no raw response) hand the handler an observation whose text holds the cookie."""
    context = new_context()
    agent._capture_session(context, HOST, "HTTP/1.1 200 OK\r\nSet-Cookie: sid=FROM-TEXT\r\n\r\n", ENG, identity="primary", cookies=None)
    assert context.cookies_by_host[HOST]["primary"] == {"sid": "FROM-TEXT"}
