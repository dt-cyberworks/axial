"""REQ-AGENT-028 (GitHub #86): a Vector Agent that is switched off is not started.

The run that found this (a customer host) started the agent with the engagement's opt-in off; it made real language-model
requests, proposed checks, was refused on every one at the gateway and finished with "no new evidence". These tests drive the
real pipeline and fail if a model client is ever built, so the saving is proven and not assumed."""

from __future__ import annotations

import pytest

from app import tool_execution
from app.control_plane_client import ControlPlaneClient, client
from app.tasks import agent, pipeline

ENG = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"


class _Reply:
    status_code = 200

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body

    def raise_for_status(self):
        return None


def _drive(monkeypatch, *, info, claim=None):
    """Run the whole pipeline once with every network edge replaced. Returns (what ran, every update, skip events)."""
    ran, updates, skipped = [], [], []
    base = {"supervision": "attended", "scan_profile": "standard", "trigger": "manual", "scope_hosts": None,
            "retest_finding_id": None, "operating_mode": "assessment", "approval_timeout_seconds": 30,
            "retest_items": None, "send_approval_ids": []}
    base.update(info)
    monkeypatch.setattr(client, "run_info", lambda rid: dict(base))
    monkeypatch.setattr(client, "claim_scan_run", lambda *a, **k: claim or {
        "attempt": 1, "phase": "discovery", "state": "running", "cancel_requested": False, "checkpoint": None})
    monkeypatch.setattr(client, "is_cancel_requested", lambda *a, **k: False)
    monkeypatch.setattr(client, "update_scan_run", lambda *a, **k: updates.append(k) or {})
    monkeypatch.setattr(client, "materialize_graph", lambda *a, **k: None)
    monkeypatch.setattr(pipeline.discovery, "run", lambda *a, **k: ran.append("discovery") or [
        {"value": "a.example.com", "asset_id": "1", "asset_type": "domain"}])
    monkeypatch.setattr(pipeline.asset_review, "gate", lambda e, r, d: d)
    monkeypatch.setattr(pipeline.fingerprint, "run", lambda *a, **k: ran.append("fingerprint") or [])
    monkeypatch.setattr(pipeline.correlate, "run", lambda *a, **k: ran.append("correlate") or [])
    monkeypatch.setattr(pipeline.score, "run", lambda *a, **k: ran.append("score"))
    monkeypatch.setattr(pipeline.report, "run", lambda *a, **k: ran.append("report"))
    monkeypatch.setattr(agent, "_audit_agent_event", lambda eid, event, **kw: skipped.append((event, kw.get("reason"))))
    tool_execution.clear_coverage(RUN)
    pipeline.run_scan.run(ENG, RUN)
    return ran, updates, skipped


def _model_client_must_never_be_built(monkeypatch):
    """The real agent entry point runs, but any attempt to reach a language model fails the test."""
    def boom(*a, **k):
        pytest.fail("a language-model client was built although the Vector Agent is off")

    import openai

    monkeypatch.setattr(openai, "OpenAI", boom, raising=False)
    monkeypatch.setattr(agent, "OpenAI", boom, raising=False)


def test_with_the_agent_off_it_is_not_started_and_no_model_client_is_built(monkeypatch):
    _model_client_must_never_be_built(monkeypatch)
    started = []
    monkeypatch.setattr(agent, "run", lambda *a, **k: started.append(1) or pytest.fail("the agent was started"))
    ran, updates, skipped = _drive(monkeypatch, info={"agent_allowed": False, "agent_skip_reason": "ai_testing_not_enabled"})
    assert started == []
    assert ran == ["discovery", "fingerprint", "correlate", "score", "report"]
    assert ("agent_phase_skipped", "ai_testing_not_enabled") in skipped
    assert [e for e, _ in skipped].count("agent_phase_skipped") == 1


def test_a_deliberate_setting_is_not_a_failure(monkeypatch):
    monkeypatch.setattr(agent, "run", lambda *a, **k: pytest.fail("the agent was started"))
    _, updates, _ = _drive(monkeypatch, info={"agent_allowed": False, "agent_skip_reason": "ai_testing_not_enabled"})
    final = updates[-1]
    assert final["state"] == "done"
    assert not final.get("state_reason"), "the skip must not mark the run degraded or agent_incomplete"
    agent_update = next(u for u in updates if u.get("phase") == "score")
    assert agent_update["checkpoint"]["agent_skipped"] == "ai_testing_not_enabled"
    assert agent_update["checkpoint"]["agent_warning"] is None
    assert not (agent_update.get("state_reason") or "").startswith("agent_incomplete")


@pytest.mark.parametrize("reason", ["ai_testing_forbidden", "automation_forbidden", "bounty_program_missing"])
def test_a_bug_bounty_program_that_forbids_it_skips_the_agent_with_its_own_reason(monkeypatch, reason):
    monkeypatch.setattr(agent, "run", lambda *a, **k: pytest.fail("the agent was started"))
    _, updates, skipped = _drive(monkeypatch, info={"agent_allowed": False, "agent_skip_reason": reason})
    assert ("agent_phase_skipped", reason) in skipped
    assert next(u for u in updates if u.get("phase") == "score")["checkpoint"]["agent_skipped"] == reason


def test_a_resumed_run_with_saved_agent_state_does_not_start_the_agent_when_it_is_off(monkeypatch):
    monkeypatch.setattr(agent, "run", lambda *a, **k: pytest.fail("the agent was started on a resume"))
    claim = {"attempt": 2, "phase": "agent", "state": "running", "cancel_requested": False,
             "checkpoint": {"agent_resume": {"messages": ["saved"]}}}
    ran, _, skipped = _drive(monkeypatch, info={"agent_allowed": False, "agent_skip_reason": "ai_testing_not_enabled"}, claim=claim)
    assert ("agent_phase_skipped", "ai_testing_not_enabled") in skipped
    assert "report" in ran


def test_an_engagement_with_the_agent_on_starts_it_as_before(monkeypatch):
    started = []

    class _Context:
        incomplete_reason = None
        parked = None

    monkeypatch.setattr(agent, "run", lambda *a, **k: started.append(1) or _Context())
    _, _, skipped = _drive(monkeypatch, info={"agent_allowed": True, "agent_skip_reason": None})
    assert started == [1]
    assert not any(e == "agent_phase_skipped" for e, _ in skipped)


def test_negative_a_reply_without_the_field_never_allows_the_agent():
    """Fail closed: an older or broken control plane that does not answer must not start an agent."""
    c = ControlPlaneClient(base_url="http://control-plane.invalid")
    c._client.post = lambda *a, **k: _Reply({"attempt": 1, "phase": "agent", "state": "running", "cancel_requested": False})
    c.claim_scan_run("33333333-3333-3333-3333-333333333333", task_id="t")
    info = c.run_info("33333333-3333-3333-3333-333333333333")
    assert info["agent_allowed"] is False
    assert info["agent_skip_reason"] == "agent_permission_unreadable"


@pytest.mark.parametrize("value", [None, "true", 1, "yes"])
def test_negative_only_a_real_true_allows_the_agent(value):
    c = ControlPlaneClient(base_url="http://control-plane.invalid")
    c._client.post = lambda *a, **k: _Reply(
        {"attempt": 1, "phase": "agent", "state": "running", "cancel_requested": False, "agent_allowed": value})
    c.claim_scan_run("44444444-4444-4444-4444-444444444444", task_id="t")
    assert c.run_info("44444444-4444-4444-4444-444444444444")["agent_allowed"] is False


def test_the_claim_carries_the_reason_the_control_plane_gave():
    c = ControlPlaneClient(base_url="http://control-plane.invalid")
    c._client.post = lambda *a, **k: _Reply({
        "attempt": 1, "phase": "agent", "state": "running", "cancel_requested": False,
        "agent_allowed": False, "agent_skip_reason": "ai_testing_forbidden"})
    c.claim_scan_run("55555555-5555-5555-5555-555555555555", task_id="t")
    info = c.run_info("55555555-5555-5555-5555-555555555555")
    assert (info["agent_allowed"], info["agent_skip_reason"]) == (False, "ai_testing_forbidden")


def test_an_unclaimed_run_keeps_the_behaviour_it_had_before():
    assert ControlPlaneClient(base_url="http://control-plane.invalid").run_info("66666666-6666-6666-6666-666666666666")["agent_allowed"] is True
