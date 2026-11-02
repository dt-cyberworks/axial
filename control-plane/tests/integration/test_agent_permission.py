"""REQ-AGENT-028 (GitHub #86): the control plane says whether the Vector Agent may run, and says what the gateway would say.

The worker skips the agent phase on this answer. The Scope Gateway stays the boundary: the second half of this file sends a real
agent-phase call to it for every situation and requires the same reason, so the two cannot drift apart unnoticed."""

from __future__ import annotations

import pytest

from app.agent_permission import agent_permission
from app.api.internal import claim_scan_run_endpoint
from app.gateway.authorize import ToolCall, authorize
from app.models.engagement import BountyProgram
from app.models.scan_run import ScanRun
from app.schemas.internal import ScanRunClaimIn

TARGET = "metasploitable2"


def _bounty(db, eng, *, automation=True, ai=True, program=True):
    eng.source = "bug_bounty"
    if program:
        db.add(BountyProgram(engagement_id=eng.id, platform="test", program_ref="p",
                             automation_allowed=automation, ai_testing_allowed=ai))
    db.commit()


def _run(db, eng):
    run = ScanRun(engagement_id=eng.id, phase="agent", state="running", attempt=1)
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _agent_call(eng, run):
    return ToolCall(engagement_id=eng.id, tool="http_request", category="vuln", mode="active", target=TARGET,
                    args={"method": "GET", "path": "/"}, is_automated=True, phase="agent", scan_run_id=run.id)


# (label, how to set the engagement up, the expected answer)
CASES = [
    pytest.param("off", lambda db, e: None, (False, "ai_testing_not_enabled"), id="agent-off"),
    pytest.param("on", lambda db, e: setattr(e, "ai_testing_allowed", True), (True, None), id="agent-on"),
    pytest.param("bounty-no-program", lambda db, e: (setattr(e, "ai_testing_allowed", True), _bounty(db, e, program=False)),
                 (False, "bounty_program_missing"), id="bounty-without-a-program"),
    pytest.param("bounty-no-automation", lambda db, e: (setattr(e, "ai_testing_allowed", True), _bounty(db, e, automation=False)),
                 (False, "automation_forbidden"), id="bounty-forbids-automation"),
    pytest.param("bounty-no-ai", lambda db, e: (setattr(e, "ai_testing_allowed", True), _bounty(db, e, ai=False)),
                 (False, "ai_testing_forbidden"), id="bounty-forbids-ai-testing"),
    pytest.param("bounty-ok", lambda db, e: (setattr(e, "ai_testing_allowed", True), _bounty(db, e)),
                 (True, None), id="bounty-allows-both"),
    # The engagement's own opt-in is needed for every source, also when the program allows AI testing.
    pytest.param("bounty-ok-but-off", lambda db, e: _bounty(db, e), (False, "ai_testing_not_enabled"), id="bounty-allows-but-engagement-off"),
]


@pytest.mark.parametrize("label,setup,expected", CASES)
def test_the_permission_follows_the_engagement_and_its_program(db, lab_engagement, label, setup, expected):
    setup(db, lab_engagement)
    db.commit()
    assert agent_permission(db, lab_engagement) == expected


@pytest.mark.parametrize("label,setup,expected", CASES)
def test_the_claim_reports_the_same_answer_on_every_claim(db, lab_engagement, label, setup, expected):
    setup(db, lab_engagement)
    db.commit()
    run = _run(db, lab_engagement)
    out = claim_scan_run_endpoint(run.id, ScanRunClaimIn(task_id="t1"), db)
    assert (out.agent_allowed, out.agent_skip_reason) == expected


def test_a_resumed_run_is_judged_by_the_setting_as_it_is_now(db, lab_engagement):
    """The opt-in is switched off between two attempts of the same run: the second claim says so."""
    import datetime as dt

    lab_engagement.ai_testing_allowed = True
    db.commit()
    run = _run(db, lab_engagement)
    first = claim_scan_run_endpoint(run.id, ScanRunClaimIn(task_id="t1"), db)
    assert first.agent_allowed is True
    lab_engagement.ai_testing_allowed = False
    run.heartbeat_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=10_000)  # the first worker is gone
    db.commit()
    second = claim_scan_run_endpoint(run.id, ScanRunClaimIn(task_id="t2"), db)
    assert second.attempt == first.attempt + 1, "it must be a new attempt of the same run"
    assert (second.agent_allowed, second.agent_skip_reason) == (False, "ai_testing_not_enabled")


def test_the_schema_default_is_not_allowed():
    """A reply built without the field must read as 'not allowed' (fail closed)."""
    from app.schemas.internal import ScanRunClaimOut

    out = ScanRunClaimOut(attempt=1, phase="agent", state="running", cancel_requested=False)
    assert out.agent_allowed is False


# --- the gateway is still the boundary -------------------------------------------------------------------------------


@pytest.mark.parametrize("label,setup,expected", CASES)
def test_negative_the_gateway_denies_an_agent_call_for_exactly_the_reason_the_permission_gives(db, lab_engagement, label, setup, expected):
    setup(db, lab_engagement)
    db.commit()
    decision = authorize(db, _agent_call(lab_engagement, _run(db, lab_engagement)))
    allowed, reason = expected
    if allowed:
        assert decision.reason not in {"ai_testing_not_enabled", "bounty_program_missing", "automation_forbidden", "ai_testing_forbidden"}
    else:
        assert decision.allowed is False and decision.reason == reason
