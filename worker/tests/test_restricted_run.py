"""REQ-RETEST-002/006: a restricted run uses the assets already known, runs only the selected checks, does not run
the Vector Agent, and sends the requests a person confirmed - each through the claim of its own approval."""

from __future__ import annotations

import pytest

from app import tool_execution
from app.tasks import open_requests, pipeline

ENG = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
KNOWN = [{"id": "a-1", "value": "app.example.test", "in_scope": True}]
DISCOVERED = [{"value": "app.example.test", "asset_id": "a-1", "asset_type": "domain"}]


class Harness:
    def __init__(self, monkeypatch, *, retest_items, scope_hosts=None, send=()):
        self.ran, self.updates = [], []
        c = pipeline.client
        info = {"supervision": "attended", "scan_profile": "standard", "trigger": "manual", "scope_hosts": scope_hosts,
                "retest_finding_id": None, "operating_mode": "assessment", "approval_timeout_seconds": 900,
                "retest_items": retest_items, "send_approval_ids": list(send)}
        monkeypatch.setattr(c, "claim_scan_run", lambda *a, **k: {
            "attempt": 1, "phase": "discovery", "state": "running", "cancel_requested": False, "checkpoint": None})
        monkeypatch.setattr(c, "run_info", lambda rid: dict(info))
        monkeypatch.setattr(c, "is_cancel_requested", lambda *a, **k: False)
        monkeypatch.setattr(c, "update_scan_run", lambda *a, **k: self.updates.append(k) or {})
        monkeypatch.setattr(c, "materialize_graph", lambda *a, **k: None)
        monkeypatch.setattr(c, "list_discovered_assets", lambda eid, in_scope=None: KNOWN)
        monkeypatch.setattr(pipeline.discovery, "run", lambda *a, **k: self.ran.append("discovery") or DISCOVERED)
        monkeypatch.setattr(pipeline.asset_review, "gate", lambda e, r, d: self.ran.append("gate") or d)
        monkeypatch.setattr(pipeline.fingerprint, "run", lambda e, d, **k: self.ran.append(("fingerprint", d)) or [{"port": 443}])
        monkeypatch.setattr(pipeline.correlate, "run", lambda e, services: self.ran.append("correlate") or [])
        monkeypatch.setattr(pipeline.agent, "run", lambda e, budget, **k: self.ran.append("agent")
                            or type("Ctx", (), {"incomplete_reason": None})())
        monkeypatch.setattr(pipeline.open_requests, "send_confirmed",
                            lambda e, r, ids: self.ran.append(("send", tuple(ids))))
        monkeypatch.setattr(pipeline.score, "run", lambda *a, **k: self.ran.append("score"))
        monkeypatch.setattr(pipeline.report, "run", lambda *a, **k: self.ran.append("report"))

    def go(self):
        return pipeline.run_scan.run(ENG, RUN)


@pytest.fixture(autouse=True)
def _clean():
    tool_execution.clear_coverage(RUN)
    yield
    tool_execution.clear_coverage(RUN)


def test_a_restricted_run_does_not_discover_again_does_not_review_and_does_not_run_the_agent(monkeypatch):
    h = Harness(monkeypatch, retest_items=[{"host": "app.example.test", "check": "ffuf"}], scope_hosts=["app.example.test"])
    h.go()
    assert h.ran == [("fingerprint", DISCOVERED), ("send", ()), "score", "report"]  # no discovery, gate, correlate, agent
    assert h.updates[-1]["state"] == "done"


def test_a_full_run_is_unchanged_by_all_of_this(monkeypatch):
    h = Harness(monkeypatch, retest_items=None)
    h.go()
    assert [r if isinstance(r, str) else r[0] for r in h.ran] == [
        "discovery", "gate", "fingerprint", "correlate", "agent", "score", "report"]


def test_the_correlation_runs_only_when_the_items_ask_for_it(monkeypatch):
    h = Harness(monkeypatch, retest_items=[{"host": "app.example.test", "check": "correlate"}], scope_hosts=["app.example.test"])
    h.go()
    assert "correlate" in h.ran and "agent" not in h.ran


def test_a_run_that_only_sends_confirmed_requests_checks_nothing_and_sends_exactly_those(monkeypatch):
    h = Harness(monkeypatch, retest_items=[], send=["ap-1", "ap-2"])
    h.go()
    assert not any(isinstance(r, tuple) and r[0] == "fingerprint" for r in h.ran)  # nothing to check
    assert h.ran == [("send", ("ap-1", "ap-2")), "score", "report"]
    assert h.updates[-1]["state"] == "done" and not h.updates[-1].get("state_reason")


def test_a_request_that_was_not_sent_never_degrades_the_run(monkeypatch):
    h = Harness(monkeypatch, retest_items=[], send=["ap-1"])
    h.go()
    assert h.updates[-1]["state"] == "done" and "agent_incomplete" not in str(h.updates[-1].get("state_reason"))


# ----------------------------------------------------------- sending the confirmed requests


class Sender:
    def __init__(self, monkeypatch, claims, *, known=True, dispatch_error=None):
        self.claimed, self.completed, self.dispatched, self.events = [], [], [], []
        c = open_requests.client
        monkeypatch.setattr(c, "claim_approval", lambda aid: self.claimed.append(aid) or claims[aid])
        monkeypatch.setattr(c, "complete_approval", lambda aid, **k: self.completed.append((aid, k)) or {})
        monkeypatch.setattr(c, "get_scan_envelope", lambda eid, host=None: {"tcp_port_from": 1, "tcp_port_to": 65535})
        monkeypatch.setattr(open_requests.agent, "_load_scope", lambda eid, rid: ({"app.example.test": "a-1"} if known else {}, {"app.example.test": "1.2.3.4"}))
        monkeypatch.setattr(open_requests.agent, "_audit_agent_event",
                            lambda eid, event, **k: self.events.append((event, k.get("reason"), k.get("approval_id"))))

        def fake_dispatch(eid, asset_id, tool, target, ip=None, args=None, scan_run_id=None, single_port=None, **k):
            if dispatch_error:
                raise dispatch_error
            self.dispatched.append((tool, target, ip, args))
            return open_requests.dispatch.Observation(tool, target, "HTTP 302 session established")

        monkeypatch.setattr(open_requests.dispatch, "dispatch", fake_dispatch)


ARGS = {"method": "POST", "path": "/login", "body": "username=guest&password=guest"}
ALLOWED = {"allowed": True, "reason": "all_checks_passed",
           "tool_call": {"tool": "http_request", "target": "app.example.test", "args": ARGS}}


def test_nothing_is_claimed_or_sent_when_no_request_was_confirmed(monkeypatch):
    s = Sender(monkeypatch, {})
    open_requests.send_confirmed(ENG, RUN, [])
    assert s.claimed == [] and s.dispatched == [] and s.events == []


def test_only_the_call_the_claim_hands_back_is_sent_and_the_approval_is_consumed(monkeypatch):
    s = Sender(monkeypatch, {"ap-1": ALLOWED})
    open_requests.send_confirmed(ENG, RUN, ["ap-1"])
    assert s.claimed == ["ap-1"]
    assert s.dispatched == [("http_request", "app.example.test", "1.2.3.4", ARGS)]
    assert s.completed == [("ap-1", {"success": True})]
    assert [e[0] for e in s.events] == ["open_request_sending", "open_request_sent"]


def test_negative_a_claim_the_gateway_denies_sends_nothing(monkeypatch):
    s = Sender(monkeypatch, {"ap-1": {"allowed": False, "reason": "outside_time_window"}})
    open_requests.send_confirmed(ENG, RUN, ["ap-1"])
    assert s.dispatched == [] and s.completed == []
    assert s.events == [("open_request_not_sent", "outside_time_window", "ap-1")]


def test_negative_a_target_that_is_not_loaded_is_not_sent_and_the_approval_is_closed(monkeypatch):
    s = Sender(monkeypatch, {"ap-1": ALLOWED}, known=False)
    open_requests.send_confirmed(ENG, RUN, ["ap-1"])
    assert s.dispatched == [] and s.completed == [("ap-1", {"success": False, "error": "approved_target_not_loaded"})]
    assert s.events[-1][:2] == ("open_request_not_sent", "approved_target_not_loaded")


def test_one_requests_error_does_not_stop_the_next(monkeypatch):
    s = Sender(monkeypatch, {"ap-1": ALLOWED, "ap-2": ALLOWED}, dispatch_error=RuntimeError("runner down"))
    open_requests.send_confirmed(ENG, RUN, ["ap-1", "ap-2"])
    assert s.claimed == ["ap-1", "ap-2"]
    assert [c[1]["success"] for c in s.completed] == [False, False]
    assert [e[1] for e in s.events if e[0] == "open_request_not_sent"] == ["runner_execution_failed"] * 2
