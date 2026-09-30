"""TC-PIPE-006/008/015 (worker half): the check executor - honest outcomes,
check-level resume, bounded parallelism, dependencies, cancellation."""

from __future__ import annotations

import threading
import time

import pytest

from app import scan_executor, tool_execution
from app.control_plane_client import ScanRunSuperseded
from tests import plan_fakes

RUN = "22222222-2222-2222-2222-222222222222"
EID = "11111111-1111-1111-1111-111111111111"


def _plan(check_ids, *, states=None, depends=None, host="h.example"):
    """One surface with the given checks (in order), optionally pre-set states."""
    depends = depends or {}
    return [{
        "host": host, "port": 443, "service_class": "web", "scheme": "https", "asset_id": "a1", "profile": [],
        "fingerprint": {"protocol": "https"},
        "checks": [
            {"check_id": c, "tool": c.split(":")[0], "state": "planned", "reason": "r", "args": {}, "depends_on": depends.get(c)}
            for c in check_ids
        ],
    }]


class _Cp:
    """The executor's view of the control plane, backed by the in-memory store."""

    def __init__(self, monkeypatch, plan, states=None):
        self.store = plan_fakes.FakePlanStore()
        self.store.store_scan_plan(RUN, plan)
        for check_id, state in (states or {}).items():
            row = next(c for c in self.store.checks.values() if c["check_id"] == check_id)
            row["state"] = state
        for name in ("get_scan_plan", "update_scan_check"):
            setattr(self, name, getattr(self.store, name))


def _run(cp, handlers, *, parallel=1, cancelled=lambda: False):
    return scan_executor.execute_plan(
        client=cp, scan_run_id=RUN, engagement_id=EID, resolve_handler=lambda check: handlers.get(check["check_id"]),
        max_parallel=parallel, is_cancelled=cancelled,
    )


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch):
    monkeypatch.setattr(tool_execution.client, "record_tool_execution", lambda *a, **k: None)
    tool_execution.clear_coverage(RUN)
    yield
    tool_execution.clear_coverage(RUN)


def _tool_result(**over):
    base = {"success": True, "exit_code": 0, "stdout": "", "stderr": "", "error_reason": None}
    base.update(over)
    return base


def _emit(result, tool="nuclei"):
    tool_execution.record(EID, scan_run_id=RUN, tool=tool, phase="fingerprint", authorized_target="h.example",
                          resolved_target=None, port_range="443", result=result)


# --- REQ-PIPE-006: honest outcomes --------------------------------------------------------

def test_req_pipe_006_a_check_ends_complete_partial_failed_or_skipped(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a", "b", "c", "d", "e"]))
    handlers = {
        "a": lambda r: _emit(_tool_result()),
        "b": lambda r: _emit(_tool_result(success=False, error_reason="budget_reached", exit_code=-1)),
        "c": lambda r: _emit(_tool_result(success=False, error_reason="nonzero_exit", exit_code=2)),
        "d": lambda r: _emit(_tool_result(success=False, error_reason="not_a_tls_service")),
        "e": lambda r: r.skip("no_endpoints"),
    }
    _run(cp, handlers)
    assert cp.store.states("h.example") == {"a": "complete", "b": "partial", "c": "failed", "d": "skipped", "e": "skipped"}
    assert cp.store.check("h.example", "c")["outcome_summary"]["detail"] == "nonzero_exit"
    assert cp.store.check("h.example", "e")["reason"] == "no_endpoints"


def test_negative_req_pipe_006_a_check_that_recorded_a_failure_is_never_complete(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a"]))
    _run(cp, {"a": lambda r: (_emit(_tool_result()), _emit(_tool_result(success=False, error_reason="runner_error")))})
    assert cp.store.check("h.example", "a")["state"] == "failed"


def test_req_pipe_006_a_gateway_denial_is_a_skip_with_its_reason_not_a_clean_result(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a"]))
    _run(cp, {"a": lambda r: tool_execution.note_denied("nuclei", "scope_denied")})
    row = cp.store.check("h.example", "a")
    assert row["state"] == "skipped" and row["reason"] == "gateway_denied:scope_denied"


def test_req_pipe_006_findings_and_duration_are_recorded(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a"]))

    def handler(run):
        _emit(_tool_result())
        tool_execution.note_finding(3)
        run.outcome_summary["templates"] = 42

    _run(cp, {"a": handler})
    row = cp.store.check("h.example", "a")
    assert row["findings"] == 3 and row["outcome_summary"]["templates"] == 42 and row["duration_s"] is not None


def test_req_pipe_006_an_operator_cancel_mid_check_is_recorded_as_skipped(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a"]))
    _run(cp, {"a": lambda r: _emit(_tool_result(success=False, error_reason="cancelled_by_operator"))})
    assert cp.store.check("h.example", "a")["state"] == "skipped"


def test_req_pipe_006_a_handler_may_change_what_is_stored_on_its_row(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a"]))

    def handler(run):
        run.args, run.budget_s, run.reason = {"products": ["nginx"]}, 555, "product:nginx"
        _emit(_tool_result())

    _run(cp, {"a": handler})
    row = cp.store.check("h.example", "a")
    assert (row["args"], row["budget_s"], row["reason"]) == ({"products": ["nginx"]}, 555, "product:nginx")


# --- REQ-PIPE-008: check-level resume ---------------------------------------------------------

def test_req_pipe_008_only_unfinished_checks_run_again(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["done", "part", "skip", "fail", "was_running", "todo"]),
             states={"done": "complete", "part": "partial", "skip": "skipped", "fail": "failed", "was_running": "running"})
    ran = []
    handlers = {c: (lambda r, c=c: ran.append(c)) for c in ("done", "part", "skip", "fail", "was_running", "todo")}
    _run(cp, handlers)
    assert ran == ["was_running", "todo"]
    assert cp.store.states("h.example")["done"] == "complete" and cp.store.states("h.example")["part"] == "partial"
    assert cp.store.check("h.example", "was_running")["attempt"] == 1, "a check that was running runs again"


def test_req_pipe_008_a_finished_plan_runs_nothing(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a", "b"]), states={"a": "complete", "b": "complete"})
    ran = []
    result = _run(cp, {"a": lambda r: ran.append("a"), "b": lambda r: ran.append("b")})
    assert ran == [] and result.ran == 0


def test_negative_req_pipe_008_a_superseded_worker_stops_and_writes_nothing_more(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a", "b"]))
    calls = []

    def fenced(run_id, check_id, **fields):
        calls.append(fields.get("state"))
        raise ScanRunSuperseded("newer attempt")

    cp.update_scan_check = fenced
    with pytest.raises(ScanRunSuperseded):
        _run(cp, {"a": lambda r: None, "b": lambda r: None})
    assert calls == ["running"], "nothing but the refused claim was attempted"


# --- REQ-PIPE-015: at most two at a time -----------------------------------------------------------

def _tracked(handler_time=0.05):
    state = {"now": 0, "max": 0}
    lock = threading.Lock()

    def handler(run):
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        time.sleep(handler_time)
        with lock:
            state["now"] -= 1

    return state, handler


def test_req_pipe_015_two_checks_run_at_once_never_three(monkeypatch):
    ids = [f"c{i}" for i in range(8)]
    cp = _Cp(monkeypatch, _plan(ids))
    state, handler = _tracked()
    _run(cp, {c: handler for c in ids}, parallel=2)
    assert state["max"] == 2
    assert set(cp.store.states("h.example").values()) == {"complete"}


def test_req_pipe_015_one_at_a_time_when_asked_for_one(monkeypatch):
    ids = [f"c{i}" for i in range(4)]
    cp = _Cp(monkeypatch, _plan(ids))
    state, handler = _tracked()
    _run(cp, {c: handler for c in ids}, parallel=1)
    assert state["max"] == 1


def test_negative_req_pipe_015_a_failing_check_never_stops_the_others(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a", "b", "c"]))

    def boom(run):
        raise RuntimeError("bug in one check")

    ran = []
    _run(cp, {"a": boom, "b": lambda r: ran.append("b"), "c": lambda r: ran.append("c")}, parallel=2)
    assert ran == ["b", "c"]
    assert cp.store.check("h.example", "a")["state"] == "failed"
    assert cp.store.check("h.example", "a")["outcome_summary"]["detail"] == "handler_error:RuntimeError"


def test_req_pipe_015_parallel_checks_never_see_each_others_results(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["ok", "bad"]))
    barrier = threading.Barrier(2, timeout=5)

    def ok(run):
        barrier.wait()
        _emit(_tool_result())

    def bad(run):
        barrier.wait()
        _emit(_tool_result(success=False, error_reason="nonzero_exit"))

    _run(cp, {"ok": ok, "bad": bad}, parallel=2)
    assert cp.store.states("h.example") == {"ok": "complete", "bad": "failed"}


# --- dependencies and order ---------------------------------------------------------------------------

def test_a_check_waits_for_its_dependency_and_reads_its_result(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["crawl", "slow", "endpoints"], depends={"endpoints": "crawl"}))
    seen = {}

    def crawl(run):
        time.sleep(0.05)
        run.outcome_summary["candidate_urls"] = ["https://h.example/a?x=1"]

    def endpoints(run):
        seen["urls"] = run.dependencies["crawl"]["outcome_summary"]["candidate_urls"]
        seen["dep_state"] = run.dependencies["crawl"]["state"]

    _run(cp, {"crawl": crawl, "slow": lambda r: None, "endpoints": endpoints}, parallel=2)
    assert seen == {"urls": ["https://h.example/a?x=1"], "dep_state": "complete"}


def test_a_dependency_cycle_is_skipped_not_waited_on_forever(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a", "b"], depends={"a": "b", "b": "a"}))
    _run(cp, {"a": lambda r: None, "b": lambda r: None})
    assert cp.store.states("h.example") == {"a": "skipped", "b": "skipped"}
    assert cp.store.check("h.example", "a")["reason"] == "dependency_never_finished"


def test_checks_run_in_plan_order_across_surfaces(monkeypatch):
    plan = _plan(["a", "b"], host="one.example") + _plan(["c"], host="two.example")
    cp = _Cp(monkeypatch, plan)
    order = []
    handlers = {c: (lambda r, c=c: order.append((r.host, c))) for c in ("a", "b", "c")}
    _run(cp, handlers)
    assert order == [("one.example", "a"), ("one.example", "b"), ("two.example", "c")]


# --- cancellation ------------------------------------------------------------------------------------------

def test_an_operator_stop_leaves_the_remaining_checks_planned(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a", "b", "c"]))
    ran = []
    flag = {"stop": False}

    def first(run):
        ran.append("a")
        flag["stop"] = True

    result = _run(cp, {"a": first, "b": lambda r: ran.append("b"), "c": lambda r: ran.append("c")}, cancelled=lambda: flag["stop"])
    assert ran == ["a"] and result.cancelled
    assert cp.store.states("h.example") == {"a": "complete", "b": "planned", "c": "planned"}


def test_a_check_without_a_handler_fails_honestly(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["mystery"]))
    _run(cp, {})
    row = cp.store.check("h.example", "mystery")
    assert row["state"] == "failed" and row["outcome_summary"]["detail"] == "handler_error:LookupError"
