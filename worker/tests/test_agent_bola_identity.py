"""REQ-AGENT-023 / TC-AGENT-023: BOLA/IDOR differential testing via a second,
run-scoped identity.

R4 requirement - this is an active capability that systematically requests
another identity's data on a customer system. The mandatory negative tests
below (cross-identity jar isolation, fail-closed identity parsing, the
synthetic-registration guard) are the actual safety story alongside the
mandatory per-call operator approval already exercised by test_agent.py's
_await_approval tests.
"""

from __future__ import annotations

import pytest

from app import session_state
from app.tasks import agent

EID = "33333333-3333-3333-3333-333333333333"


# --- session_state.looks_synthetic_registration_body -----------------------

def test_body_with_no_email_passes():
    assert session_state.looks_synthetic_registration_body("username=zz9_test_abc123&password=x") is True


def test_empty_body_passes():
    assert session_state.looks_synthetic_registration_body("") is True


def test_real_world_email_domain_is_rejected():
    assert session_state.looks_synthetic_registration_body('{"email": "someone@gmail.com"}') is False


def test_real_world_email_domain_check_is_case_insensitive():
    assert session_state.looks_synthetic_registration_body("email=Someone@GMail.Com") is False


def test_custom_or_example_domain_email_passes():
    assert session_state.looks_synthetic_registration_body("email=zz9test123@example.com") is True


def test_synthetic_username_with_no_email_at_all_passes():
    assert session_state.looks_synthetic_registration_body("username=synthetic_zz9&pw=abc") is True


# --- fixtures / helpers ------------------------------------------------------

@pytest.fixture(autouse=True)
def _no_audit(monkeypatch):
    monkeypatch.setattr(agent.client, "agent_event", lambda *a, **k: None)


def _ctx():
    return agent.SimpleContext(scan_run_id="11111111-1111-1111-1111-111111111111")


def _scope():
    return {"vampi.bench.internal": "asset-1"}, {"vampi.bench.internal": "1.2.3.4"}


def _allow_authorize(monkeypatch):
    monkeypatch.setattr(agent.client, "authorize",
                        lambda eid, call: {"allowed": True, "is_pending": False, "reason": "all_checks_passed"})


# --- _handle_http_request: identity selection -------------------------------

def test_http_request_defaults_to_primary_identity(monkeypatch):
    _allow_authorize(monkeypatch)
    asset_by_host, ip_by_host = _scope()
    ctx = _ctx()
    ctx.cookies_by_host["vampi.bench.internal"] = {"primary": {"sid": "PRIMARY-SESSION"}}
    seen_headers = []

    def fake_dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None,
                      confirmed_protocol=None):
        seen_headers.append(args.get("headers"))
        return agent.dispatch.Observation(tool, target, "HTTP/1.1 200 OK\r\n\r\nok")

    monkeypatch.setattr(agent.dispatch, "dispatch", fake_dispatch)
    agent._handle_http_request(EID, {"target": "vampi.bench.internal", "method": "GET", "path": "/me"},
                               asset_by_host, ip_by_host, ctx)

    assert seen_headers[0]["Cookie"] == "sid=PRIMARY-SESSION"


def test_http_request_with_identity_secondary_uses_secondary_jar_only(monkeypatch):
    """THE load-bearing invariant for BOLA/IDOR proof: a secondary-identity
    request must use the SECONDARY session, never the primary one, even when
    both exist for the same host in the same run."""
    _allow_authorize(monkeypatch)
    asset_by_host, ip_by_host = _scope()
    ctx = _ctx()
    ctx.cookies_by_host["vampi.bench.internal"] = {
        "primary": {"sid": "PRIMARY-SESSION"},
        "secondary": {"sid": "SECONDARY-SESSION"},
    }
    seen_headers = []

    def fake_dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None,
                      confirmed_protocol=None):
        seen_headers.append(args.get("headers"))
        return agent.dispatch.Observation(tool, target, "HTTP/1.1 200 OK\r\n\r\nok")

    monkeypatch.setattr(agent.dispatch, "dispatch", fake_dispatch)
    agent._handle_http_request(EID, {"target": "vampi.bench.internal", "method": "GET", "path": "/me",
                                     "identity": "secondary"},
                               asset_by_host, ip_by_host, ctx)

    assert seen_headers[0]["Cookie"] == "sid=SECONDARY-SESSION"
    assert "PRIMARY-SESSION" not in str(seen_headers[0])


def test_unrecognised_identity_value_fails_closed_to_primary(monkeypatch):
    _allow_authorize(monkeypatch)
    asset_by_host, ip_by_host = _scope()
    ctx = _ctx()
    ctx.cookies_by_host["vampi.bench.internal"] = {"primary": {"sid": "PRIMARY-SESSION"}}
    seen_headers = []

    def fake_dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None,
                      confirmed_protocol=None):
        seen_headers.append(args.get("headers"))
        return agent.dispatch.Observation(tool, target, "HTTP/1.1 200 OK\r\n\r\nok")

    monkeypatch.setattr(agent.dispatch, "dispatch", fake_dispatch)
    agent._handle_http_request(EID, {"target": "vampi.bench.internal", "method": "GET", "path": "/me",
                                     "identity": "tertiary-nonsense"},
                               asset_by_host, ip_by_host, ctx)

    assert seen_headers[0]["Cookie"] == "sid=PRIMARY-SESSION"


def test_response_is_captured_into_the_matching_identity_slot(monkeypatch):
    _allow_authorize(monkeypatch)
    asset_by_host, ip_by_host = _scope()
    ctx = _ctx()

    monkeypatch.setattr(agent.dispatch, "dispatch", lambda *a, **k: agent.dispatch.Observation(
        "http_request", "vampi.bench.internal",
        "HTTP/1.1 200 OK\r\nSet-Cookie: sid=FRESH-SECONDARY\r\n\r\n",
    ))
    agent._handle_http_request(EID, {"target": "vampi.bench.internal", "method": "GET", "path": "/login",
                                     "identity": "secondary"},
                               asset_by_host, ip_by_host, ctx)

    assert ctx.cookies_by_host["vampi.bench.internal"]["secondary"] == {"sid": "FRESH-SECONDARY"}
    # Must not have touched a primary slot that never existed.
    assert "primary" not in ctx.cookies_by_host["vampi.bench.internal"]


# --- _handle_register_test_identity -----------------------------------------

def test_register_test_identity_rejects_non_synthetic_payload_before_authorize(monkeypatch):
    authorize_calls = []
    monkeypatch.setattr(agent.client, "authorize", lambda eid, call: authorize_calls.append(call) or {"allowed": True})
    asset_by_host, ip_by_host = _scope()
    ctx = _ctx()

    out = agent._handle_register_test_identity(
        EID, {"target": "vampi.bench.internal", "path": "/api/v1/users", "method": "POST",
              "body": '{"email": "realperson@gmail.com", "username": "x"}', "rationale": "test"},
        asset_by_host, ip_by_host, ctx,
    )

    assert "REJECTED" in out
    assert authorize_calls == []  # never even proposed to the gateway
    assert ctx.denied and ctx.denied[0]["reason"] == "registration_payload_not_synthetic"


def test_register_test_identity_rejects_invalid_method(monkeypatch):
    asset_by_host, ip_by_host = _scope()
    ctx = _ctx()
    out = agent._handle_register_test_identity(
        EID, {"target": "vampi.bench.internal", "path": "/api/v1/users", "method": "GET",
              "body": "username=zz9synthetic", "rationale": "test"},
        asset_by_host, ip_by_host, ctx,
    )
    assert "REJECTED" in out and "POST or PUT" in out


def test_register_test_identity_rejects_missing_body(monkeypatch):
    asset_by_host, ip_by_host = _scope()
    ctx = _ctx()
    out = agent._handle_register_test_identity(
        EID, {"target": "vampi.bench.internal", "path": "/api/v1/users", "method": "POST", "rationale": "test"},
        asset_by_host, ip_by_host, ctx,
    )
    assert "REJECTED" in out


def test_register_test_identity_rejects_out_of_scope_target(monkeypatch):
    asset_by_host, ip_by_host = _scope()
    ctx = _ctx()
    out = agent._handle_register_test_identity(
        EID, {"target": "evil.example.com", "path": "/api/v1/users", "method": "POST",
              "body": "username=zz9synthetic", "rationale": "test"},
        asset_by_host, ip_by_host, ctx,
    )
    assert "REJECTED" in out
    assert ctx.denied[-1]["reason"] == "not_in_scope_list"


def test_register_test_identity_immediate_allow_dispatches_and_captures_secondary(monkeypatch):
    """Some gateway configs may allow a write immediately rather than route it
    to approval (e.g. a lab/test policy) - the observation must still land in
    the 'secondary' slot, never 'primary', regardless of which gateway path
    granted it."""
    monkeypatch.setattr(agent.client, "authorize",
                        lambda eid, call: {"allowed": True, "is_pending": False, "reason": "all_checks_passed"})
    dispatched = []

    def fake_dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None,
                      confirmed_protocol=None):
        dispatched.append((tool, args))
        return agent.dispatch.Observation(
            tool, target, "HTTP/1.1 201 Created\r\nSet-Cookie: sid=NEWACCOUNT\r\n\r\n",
        )

    monkeypatch.setattr(agent.dispatch, "dispatch", fake_dispatch)
    asset_by_host, ip_by_host = _scope()
    ctx = _ctx()

    out = agent._handle_register_test_identity(
        EID, {"target": "vampi.bench.internal", "path": "/api/v1/users", "method": "POST",
              "body": "username=zz9_synth_92f1&email=zz9_synth_92f1@example.com",
              "rationale": "prove BOLA", "risk_level": "low", "risk": "creates one throwaway account"},
        asset_by_host, ip_by_host, ctx,
    )

    assert dispatched and dispatched[0][0] == "http_request"
    assert ctx.cookies_by_host["vampi.bench.internal"]["secondary"] == {"sid": "NEWACCOUNT"}
    assert "primary" not in ctx.cookies_by_host["vampi.bench.internal"]
    assert "201" in out


def test_register_test_identity_pending_approval_captures_secondary_on_approve(monkeypatch):
    """The normal path: registration is a POST, so it routes to mandatory
    operator approval (REQ-APPROVAL-002/REQ-AGENT-023) exactly like any other
    state-changing http_request."""
    monkeypatch.setattr(agent.client, "authorize",
                        lambda eid, call: {"allowed": False, "is_pending": True, "approval_request_id": "ap-reg-1"})
    monkeypatch.setattr(agent.client, "update_scan_run", lambda *a, **k: {})
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: False)
    monkeypatch.setattr(agent.client, "get_approval", lambda aid: {"state": "approved"})
    monkeypatch.setattr(agent.client, "claim_approval", lambda aid: {
        "allowed": True,
        "tool_call": {"target": "vampi.bench.internal",
                      "args": {"method": "POST", "path": "/api/v1/users",
                               "body": "username=zz9_synth_92f1&email=zz9_synth_92f1@example.com"}},
    })
    monkeypatch.setattr(agent.client, "complete_approval", lambda aid, **kw: {})

    def fake_dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None,
                      confirmed_protocol=None):
        return agent.dispatch.Observation(
            tool, target, "HTTP/1.1 201 Created\r\nSet-Cookie: sid=APPROVEDACCOUNT\r\n\r\n",
        )

    monkeypatch.setattr(agent.dispatch, "dispatch", fake_dispatch)
    asset_by_host, ip_by_host = _scope()
    ctx = _ctx()

    out = agent._handle_register_test_identity(
        EID, {"target": "vampi.bench.internal", "path": "/api/v1/users", "method": "POST",
              "body": "username=zz9_synth_92f1&email=zz9_synth_92f1@example.com",
              "rationale": "prove BOLA", "risk_level": "low", "risk": "creates one throwaway account"},
        asset_by_host, ip_by_host, ctx,
    )

    assert ctx.cookies_by_host["vampi.bench.internal"]["secondary"] == {"sid": "APPROVEDACCOUNT"}
    assert "primary" not in ctx.cookies_by_host["vampi.bench.internal"]
    assert "201" in out


# --- register_test_identity dispatches as tool="http_request" --------------
# (no new gateway/dispatch registry entry - it reuses the fully-validated
# http_request envelope, since a registration is just a POST like any other.)

def test_register_test_identity_is_authorized_as_an_http_request_tool_call(monkeypatch):
    seen = []
    monkeypatch.setattr(agent.client, "authorize", lambda eid, call: seen.append(call) or {
        "allowed": True, "is_pending": False,
    })
    monkeypatch.setattr(agent.dispatch, "dispatch", lambda *a, **k: agent.dispatch.Observation(
        "http_request", "vampi.bench.internal", "HTTP/1.1 201 Created\r\n\r\nok",
    ))
    asset_by_host, ip_by_host = _scope()
    ctx = _ctx()

    agent._handle_register_test_identity(
        EID, {"target": "vampi.bench.internal", "path": "/api/v1/users", "method": "POST",
              "body": "username=zz9_synth", "rationale": "prove BOLA"},
        asset_by_host, ip_by_host, ctx,
    )

    assert seen[0]["tool"] == "http_request"
    assert seen[0]["args"]["method"] == "POST"
