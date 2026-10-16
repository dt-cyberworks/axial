"""REQ-BUDGET-002 on the worker: a run whose calls the gateway refused for want of budget is
reported as reduced coverage, counted once at the one funnel every gateway call passes."""

from __future__ import annotations

import httpx
import pytest

from app import tool_execution
from app.control_plane_client import ControlPlaneClient
from app.tasks import pipeline

ENG = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
OTHER = "33333333-3333-3333-3333-333333333333"


@pytest.fixture(autouse=True)
def _clean():
    for run in (RUN, OTHER):
        tool_execution.clear_coverage(run)
    yield
    for run in (RUN, OTHER):
        tool_execution.clear_coverage(run)


def _client(decision: dict) -> tuple[ControlPlaneClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=decision)

    c = ControlPlaneClient()
    c._client = httpx.Client(base_url="http://control-plane:8000", transport=httpx.MockTransport(handler))
    return c, seen


def _ask(c: ControlPlaneClient, run_id: str | None = RUN, tool: str = "nuclei") -> dict:
    return c.authorize(ENG, {"tool": tool, "category": "vuln", "mode": "active", "target": "example.test",
                             "args": {}, "is_automated": True, "scan_run_id": run_id})


# -------------------------------------------------------------- the funnel


def test_a_budget_denial_is_counted_once_per_call():
    c, _ = _client({"allowed": False, "reason": "budget_exhausted"})
    for _ in range(3):
        assert _ask(c)["allowed"] is False
    assert tool_execution.budget_exhausted_calls(RUN) == 3


def test_the_decision_is_returned_unchanged():
    decision = {"allowed": False, "reason": "budget_exhausted", "is_pending": False}
    c, _ = _client(decision)
    assert _ask(c) == decision


@pytest.mark.parametrize("decision", [
    {"allowed": False, "reason": "out_of_scope"},
    {"allowed": False, "reason": "no_tool_grant"},
    {"allowed": False, "reason": "engagement_not_active"},
    {"allowed": False, "reason": "pending_approval", "is_pending": True},
    {"allowed": False, "reason": "throttled", "is_throttled": True, "retry_after_seconds": 1},
    {"allowed": True, "reason": "all_checks_passed"},
])
def test_every_other_outcome_is_not_a_budget_denial(decision):
    c, _ = _client(decision)
    _ask(c)
    assert tool_execution.budget_exhausted_calls(RUN) == 0


def test_a_call_without_a_run_is_not_counted():
    c, _ = _client({"allowed": False, "reason": "budget_exhausted"})
    _ask(c, run_id=None)
    assert tool_execution.budget_exhausted_calls(None) == 0


def test_runs_are_counted_separately_and_cleared_with_the_run():
    c, _ = _client({"allowed": False, "reason": "budget_exhausted"})
    _ask(c, RUN)
    _ask(c, RUN)
    _ask(c, OTHER)
    assert tool_execution.budget_exhausted_calls(RUN) == 2
    assert tool_execution.budget_exhausted_calls(OTHER) == 1
    tool_execution.clear_coverage(RUN)
    assert tool_execution.budget_exhausted_calls(RUN) == 0
    assert tool_execution.budget_exhausted_calls(OTHER) == 1


def test_a_failing_counter_never_fails_the_gateway_call(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("counter broke")

    monkeypatch.setattr(tool_execution, "note_budget_exhausted", boom)
    c, _ = _client({"allowed": False, "reason": "budget_exhausted"})
    assert _ask(c) == {"allowed": False, "reason": "budget_exhausted"}


# ------------------------------------------------- the run's coverage warning


def test_exhaustion_is_reported_as_a_degraded_coverage_reason():
    for _ in range(95):
        tool_execution.note_budget_exhausted(RUN, "nuclei")
    assert pipeline._coverage_warning(RUN) == "coverage_degraded:tool_call_budget=exhausted_95_denied"


def test_it_sits_in_the_same_list_as_a_failed_load_bearing_tool():
    tool_execution.note_budget_exhausted(RUN, "nuclei")
    tool_execution._accumulate_coverage(RUN, "nmap", {"success": False, "error_reason": "runner_dispatch_failed"})
    warning = pipeline._coverage_warning(RUN)
    assert warning.startswith("coverage_degraded:")
    assert "nmap=runner_dispatch_failed" in warning and "tool_call_budget=exhausted_1_denied" in warning
    assert warning.count("coverage_degraded:") == 1


def test_it_does_not_hide_a_partial_check_warning():
    tool_execution.note_budget_exhausted(RUN, "ffuf")
    tool_execution._accumulate_coverage(RUN, "ffuf", {"success": True, "error_reason": "budget_reached"})
    warning = pipeline._coverage_warning(RUN)
    assert "tool_call_budget=exhausted_1_denied" in warning and "coverage_partial:ffuf=1" in warning


def test_a_run_that_used_every_call_but_was_denied_none_is_clean():
    # exactly the maximum used and nothing refused: no budget warning at all
    assert pipeline._coverage_warning(RUN) is None
