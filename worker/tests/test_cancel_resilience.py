"""TC-PIPE-020/021 (GitHub issue #49): a control plane that stops answering the
"has the operator cancelled?" question must not crash the run as a bare
pipeline_error. One lost answer is absorbed; sustained silence stops target-facing
work and ends the run with its own reason; an unreadable answer is never read as
"not cancelled"; and the reason an operator sees names the real cause."""

from __future__ import annotations

import httpx
import pytest

from app import cancel_probe, scan_executor, tool_execution
from app.cancel_probe import CancelProbe, CancellationStatusUnavailable
from app.control_plane_client import ScanRunSuperseded
from app.tasks import pipeline
from tests import plan_fakes
from tests.test_pipeline_resume import DISCOVERED, ENG, RUN, SERVICES, Harness
from tests.test_scan_executor import _Cp, _plan, _run

TIMEOUT = httpx.ReadTimeout("timed out")


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(cancel_probe, "CANCEL_POLL_SECONDS", 0)
    monkeypatch.setattr(scan_executor, "_POLL_SECONDS", 0.01)
    monkeypatch.setattr(scan_executor, "_CHECK_WRITE_BACKOFF_SECONDS", 0)
    monkeypatch.setattr(pipeline, "_END_RUN_BACKOFF_SECONDS", (0, 0, 0))
    monkeypatch.setattr(tool_execution.client, "record_tool_execution", lambda *a, **k: None)
    tool_execution.clear_coverage(RUN)
    yield
    tool_execution.clear_coverage(RUN)


def _script(*answers):
    """A fetch that plays back answers (a value, or an exception to raise), then repeats the last."""
    calls = []

    def fetch():
        calls.append(1)
        answer = answers[min(len(calls), len(answers)) - 1]
        if isinstance(answer, Exception):
            raise answer
        return answer

    fetch.calls = calls
    return fetch


# --- the probe ---------------------------------------------------------------------------

def test_negative_an_unreadable_answer_is_unknown_never_not_cancelled():
    probe = CancelProbe(_script(TIMEOUT, False))
    assert probe.check() is None, "a missing answer must not read as False"
    assert probe.check() is False


def test_one_lost_answer_is_absorbed_and_the_failure_count_resets_on_success():
    probe = CancelProbe(_script(TIMEOUT, TIMEOUT, False, TIMEOUT, TIMEOUT, True), tolerance=3)
    results = [probe.check() for _ in range(6)]
    assert results == [None, None, False, None, None, True], "failures are counted consecutively"


def test_negative_sustained_silence_raises_a_dedicated_error_after_the_tolerance():
    probe = CancelProbe(_script(TIMEOUT), tolerance=3)
    assert probe.check() is None and probe.check() is None
    with pytest.raises(CancellationStatusUnavailable):
        probe.check()


@pytest.mark.parametrize("failure", [
    httpx.ConnectError("refused"),
    httpx.HTTPStatusError("boom", request=httpx.Request("GET", "http://x"), response=httpx.Response(500)),
    RuntimeError("anything"),
])
def test_every_kind_of_failed_answer_counts_as_no_answer(failure):
    probe = CancelProbe(_script(failure), tolerance=2)
    assert probe.check() is None
    with pytest.raises(CancellationStatusUnavailable):
        probe.check()


def test_a_run_taken_over_by_a_newer_attempt_is_passed_through_not_absorbed():
    probe = CancelProbe(_script(ScanRunSuperseded("superseded")))
    with pytest.raises(ScanRunSuperseded):
        probe.check()


def test_the_blocking_form_waits_through_a_lost_answer_and_returns_the_real_one():
    fetch = _script(TIMEOUT, TIMEOUT, True)
    assert CancelProbe(fetch, tolerance=3, retry_seconds=0).is_cancelled() is True
    assert len(fetch.calls) == 3


def test_negative_the_blocking_form_raises_instead_of_answering_false():
    with pytest.raises(CancellationStatusUnavailable):
        CancelProbe(_script(TIMEOUT), tolerance=3, retry_seconds=0).is_cancelled()


# --- the plan executor ---------------------------------------------------------------------

def _ok_handlers(ids, started):
    def make(check_id):
        def handler(run):
            started.append(check_id)
            tool_execution.record(ENG, scan_run_id=RUN, tool="nuclei", phase="fingerprint", authorized_target="h.example",
                                  resolved_target=None, port_range="443",
                                  result={"success": True, "exit_code": 0, "stdout": "", "stderr": "", "error_reason": None})
        return handler
    return {c: make(c) for c in ids}


def test_the_executor_survives_one_lost_cancel_answer_and_runs_every_check(monkeypatch):
    ids = ["a", "b", "c"]
    cp, started = _Cp(monkeypatch, _plan(ids)), []
    result = _run(cp, _ok_handlers(ids, started), cancelled=_script(TIMEOUT, False))
    assert started == ids and result.ran == 3 and result.by_state == {"complete": 3}


def test_negative_no_check_is_started_while_the_cancel_answer_is_unknown(monkeypatch):
    ids = ["a", "b"]
    cp, started = _Cp(monkeypatch, _plan(ids)), []
    order = []

    def cancelled():
        order.append(("poll", len(started)))
        if len([o for o in order if o[0] == "poll"]) == 1:
            raise TIMEOUT
        return False

    _run(cp, _ok_handlers(ids, started), cancelled=cancelled)
    assert order[0] == ("poll", 0) and order[1] == ("poll", 0), "nothing ran before the first real answer"
    assert started == ids


def test_negative_sustained_silence_from_the_start_starts_nothing_and_raises(monkeypatch):
    ids = ["a", "b", "c"]
    cp, started = _Cp(monkeypatch, _plan(ids)), []
    with pytest.raises(CancellationStatusUnavailable):
        _run(cp, _ok_handlers(ids, started), cancelled=_script(TIMEOUT))
    assert started == [], "with an unreadable cancel flag no target-facing check may start"
    assert {c["state"] for c in cp.store.checks.values()} == {"planned"}, "unstarted checks stay resumable"


def test_negative_silence_mid_run_lets_the_running_check_finish_starts_no_more_and_raises(monkeypatch):
    ids = ["a", "b", "c"]
    cp, started = _Cp(monkeypatch, _plan(ids)), []
    # readable for the first two polls (a starts, then b would), silent afterwards
    with pytest.raises(CancellationStatusUnavailable):
        _run(cp, _ok_handlers(ids, started), parallel=1, cancelled=_script(False, TIMEOUT))
    states = {c["check_id"]: c["state"] for c in cp.store.checks.values()}
    assert states["a"] == "complete", "work that was already running is recorded, not lost"
    assert "c" not in started, "no new work after the status became unreadable"
    assert states["c"] == "planned"


def test_a_superseded_run_is_not_absorbed_by_the_executor(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a"]))
    with pytest.raises(ScanRunSuperseded):
        _run(cp, _ok_handlers(["a"], []), cancelled=_script(ScanRunSuperseded("superseded")))


def test_a_real_operator_cancel_still_stops_the_plan_without_an_error(monkeypatch):
    cp, started = _Cp(monkeypatch, _plan(["a", "b"])), []
    result = _run(cp, _ok_handlers(["a", "b"], started), cancelled=lambda: True)
    assert result.cancelled and started == []


def test_a_handler_that_cannot_read_the_cancel_flag_fails_the_check_with_that_reason(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a"]))

    def handler(run):
        raise CancellationStatusUnavailable("no answer")

    _run(cp, {"a": handler})
    row = next(iter(cp.store.checks.values()))
    assert row["state"] == "failed" and row["outcome_summary"]["detail"] == "cancellation_status_unavailable"


# --- check-row writes -----------------------------------------------------------------------

def test_a_check_write_that_times_out_is_retried_and_the_run_completes(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a"]))
    real, failures = cp.update_scan_check, [TIMEOUT, TIMEOUT]

    def flaky(*args, **kwargs):
        if failures:
            raise failures.pop(0)
        return real(*args, **kwargs)

    cp.update_scan_check = flaky
    result = _run(cp, _ok_handlers(["a"], []))
    assert result.by_state == {"complete": 1}


def test_negative_a_superseded_write_is_not_retried(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a"]))
    calls = []

    def superseded(*args, **kwargs):
        calls.append(1)
        raise ScanRunSuperseded("superseded")

    cp.update_scan_check = superseded
    with pytest.raises(ScanRunSuperseded):
        _run(cp, _ok_handlers(["a"], []))
    assert len(calls) == 1


def test_negative_a_client_error_answer_is_not_retried(monkeypatch):
    cp = _Cp(monkeypatch, _plan(["a"]))
    calls = []

    def rejected(*args, **kwargs):
        calls.append(1)
        raise httpx.HTTPStatusError("422", request=httpx.Request("PATCH", "http://x"), response=httpx.Response(422))

    cp.update_scan_check = rejected
    with pytest.raises(httpx.HTTPStatusError):
        _run(cp, _ok_handlers(["a"], []))
    assert len(calls) == 1


# --- how a run ends -------------------------------------------------------------------------

def test_negative_sustained_cancel_silence_aborts_the_run_with_its_own_reason_never_pipeline_error(monkeypatch):
    h = Harness(monkeypatch, phase="discovery", checkpoint=None, attempt=1)
    monkeypatch.setattr(pipeline.client, "is_cancel_requested", lambda *a, **k: (_ for _ in ()).throw(TIMEOUT))
    result = h.go()  # must not raise
    assert result["state"] == "aborted"
    assert h.ran == [], "no phase may start while the cancel status is unreadable"
    assert h.updates[-1] == {"state": "aborted", "state_reason": "cancellation_status_unavailable"}
    assert not any(u.get("state_reason", "").startswith("pipeline_error") for u in h.updates)


def test_negative_silence_discovered_inside_a_phase_also_ends_the_run_fail_closed(monkeypatch):
    h = Harness(monkeypatch, phase="fingerprint", checkpoint={"discovered": DISCOVERED, "review_done": True})

    def silent(*args, **kwargs):
        raise CancellationStatusUnavailable("the plan executor could not read the cancel flag")

    monkeypatch.setattr(pipeline.fingerprint, "run", silent)
    assert h.go()["state"] == "aborted"
    assert h.updates[-1] == {"state": "aborted", "state_reason": "cancellation_status_unavailable"}


@pytest.mark.parametrize("phase, patch_target, expected", [
    ("discovery", "discovery", "pipeline_error:ValueError:discovery"),
    ("fingerprint", "fingerprint", "pipeline_error:ValueError:fingerprint"),
    ("correlate", "correlate", "pipeline_error:ValueError:correlate"),
    ("agent", "agent", "pipeline_error:ValueError:agent"),
    ("score", "score", "pipeline_error:ValueError:score"),
])
def test_a_failed_run_names_the_exception_type_and_the_phase(monkeypatch, phase, patch_target, expected):
    checkpoint = {"discovered": DISCOVERED, "review_done": True, "services": SERVICES}
    h = Harness(monkeypatch, phase=phase, checkpoint=checkpoint)

    def boom(*args, **kwargs):
        raise ValueError("http://secret-host/?token=abc")  # the message must never reach the reason

    monkeypatch.setattr(getattr(pipeline, patch_target), "run", boom)
    with pytest.raises(ValueError):
        h.go()
    assert h.updates[-1] == {"state": "failed", "state_reason": expected}
    assert "secret" not in h.updates[-1]["state_reason"] and "token" not in h.updates[-1]["state_reason"]


def test_ending_a_run_is_retried_while_the_control_plane_is_busy(monkeypatch):
    calls = []

    def flaky(*args, **kwargs):
        calls.append(kwargs)
        if len(calls) < 3:
            raise httpx.ConnectError("busy")
        return {}

    monkeypatch.setattr(pipeline.client, "update_scan_run", flaky)
    pipeline._mark_failed(RUN, "pipeline_error:ValueError:agent")
    assert len(calls) == 3 and calls[-1]["state"] == "failed"


def test_negative_ending_a_run_never_raises_even_when_every_attempt_fails(monkeypatch):
    monkeypatch.setattr(pipeline.client, "update_scan_run", lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("down")))
    pipeline._mark_failed(RUN, "pipeline_error:ValueError:agent")  # the reaper resumes or aborts the stale run


# --- what the operator sees -------------------------------------------------------------------

def _collector_with(error_reason, success=False):
    collector = tool_execution.CheckCollector() if hasattr(tool_execution, "CheckCollector") else None
    collector.results.append({"success": success, "error_reason": error_reason, "exit_code": 1, "stdout": "", "stderr": ""})
    return collector


def test_a_tool_stopped_by_an_unreadable_cancel_status_is_a_failed_check_not_an_operator_stop():
    assert tool_execution.check_outcome(_collector_with("cancellation_status_unavailable")) == (
        "failed", "cancellation_status_unavailable")


def test_a_real_operator_stop_is_still_a_skipped_check():
    assert tool_execution.check_outcome(_collector_with("cancelled_by_operator")) == ("skipped", "cancelled_by_operator")
