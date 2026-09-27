"""REQ-SCAN-014 / TC-SCAN-011: a run whose load-bearing detection phase never
succeeded is reported as degraded, not as a clean completion.

The defect this locks down cost several hours of misdiagnosis on 2026-08-03:
the benchmark tool-runner was built from an image that never ran `setcap` on
nmap, so EVERY nmap execution failed. `fingerprint._nmap_scan` recorded the
failure, logged a warning and returned []; `pipeline` carried on and finished
the run with state="done". Nothing anywhere distinguished "scanned the ports
and found nothing" from "never successfully scanned a single port", and the
investigation went looking for a kernel/LSM restriction that did not exist.

The most important test here is the NEGATIVE one: a tool that ran fine and
legitimately found nothing must NOT be flagged. Conflating "no findings" with
"no coverage" would make the signal worthless.
"""

from __future__ import annotations

import pytest

from app import tool_execution
from app.tasks import pipeline

RUN = "11111111-1111-1111-1111-111111111111"


@pytest.fixture(autouse=True)
def _clean():
    tool_execution.clear_coverage(RUN)
    yield
    tool_execution.clear_coverage(RUN)


def _ok():
    return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}


def _fail(reason="zero_targets_scanned"):
    return tool_execution.failed_result(reason)


def _record(tool, result, monkeypatch_client, run=RUN):
    tool_execution.record(
        "22222222-2222-2222-2222-222222222222", scan_run_id=run, tool=tool,
        phase="fingerprint", authorized_target="host.example", resolved_target="1.2.3.4",
        port_range="80", result=result,
    )


@pytest.fixture
def rec(monkeypatch):
    monkeypatch.setattr(tool_execution.client, "record_tool_execution", lambda *a, **k: None)
    return lambda tool, result, run=RUN: _record(tool, result, None, run)


def test_all_nmap_attempts_failed_is_reported_as_degraded(rec):
    rec("nmap", _fail("zero_targets_scanned"))
    rec("nmap", _fail("zero_targets_scanned"))

    warning = pipeline._coverage_warning(RUN)
    assert warning is not None
    assert warning.startswith("coverage_degraded:")
    assert "nmap" in warning and "zero_targets_scanned" in warning


def test_successful_tool_that_found_nothing_is_NOT_degraded(rec):
    """THE critical negative case. A clean scan of a host with no open ports
    produces zero findings and must look completely different from a scan whose
    port-scanner never ran. If this ever starts flagging, the whole signal is
    noise and operators will learn to ignore it."""
    rec("nmap", _ok())
    rec("httpx", _ok())

    assert pipeline._coverage_warning(RUN) is None


def test_a_tool_never_attempted_is_not_degraded(rec):
    """No in-scope asset called for httpx -> not a degradation, just a scan
    shape that did not need it."""
    rec("nmap", _ok())

    assert pipeline._coverage_warning(RUN) is None


def test_partial_success_is_not_degraded(rec):
    """One host unreachable while others scanned fine is normal, not a gutted
    phase - flagging it would fire on almost every real multi-host engagement."""
    rec("nmap", _fail("host_unreachable"))
    rec("nmap", _ok())

    assert pipeline._coverage_warning(RUN) is None


def test_non_load_bearing_tool_failure_is_not_run_level_degradation(rec):
    """nikto failing narrows coverage but leaves nmap/httpx and the rest of the
    web suite intact - deliberately not escalated to a run-level warning."""
    rec("nmap", _ok())
    rec("nikto", _fail("runner_dispatch_failed"))
    rec("testssl", _fail("not_a_tls_service"))

    assert pipeline._coverage_warning(RUN) is None


def test_httpx_total_failure_is_degraded(rec):
    """httpx gates the entire web suite in _web_suite - if it never succeeds,
    nikto/wafw00f/testssl/nuclei are all silently skipped for that host."""
    rec("httpx", _fail("runner_dispatch_failed"))

    warning = pipeline._coverage_warning(RUN)
    assert warning is not None and "httpx" in warning


def test_both_load_bearing_tools_degraded_are_both_named(rec):
    rec("nmap", _fail("zero_targets_scanned"))
    rec("httpx", _fail("runner_dispatch_failed"))

    warning = pipeline._coverage_warning(RUN)
    assert "nmap" in warning and "httpx" in warning


def test_coverage_is_isolated_per_scan_run(rec):
    """A worker process can run concurrent scans; one run's failures must never
    be attributed to another."""
    other = "33333333-3333-3333-3333-333333333333"
    rec("nmap", _fail("zero_targets_scanned"))
    rec("nmap", _ok(), other)

    assert pipeline._coverage_warning(RUN) is not None
    assert pipeline._coverage_warning(other) is None
    tool_execution.clear_coverage(other)


def test_clear_coverage_releases_the_run(rec):
    rec("nmap", _fail())
    assert pipeline._coverage_warning(RUN) is not None

    tool_execution.clear_coverage(RUN)
    assert pipeline._coverage_warning(RUN) is None
    assert tool_execution.coverage_summary(RUN) == {}


def test_distinct_failure_reasons_are_bounded(rec):
    """A large host list must not turn the reason list into an unbounded string
    that then lands in a database column."""
    for i in range(50):
        rec("nmap", _fail(f"reason_{i}"))

    summary = tool_execution.coverage_summary(RUN)
    assert summary["nmap"]["attempted"] == 50
    assert len(summary["nmap"]["reasons"]) <= 5


def test_coverage_and_agent_warnings_are_combined_not_replaced():
    """Independent failures; an operator needs to see both."""
    combined = pipeline._combine_reasons("coverage_degraded:nmap=zero_targets_scanned",
                                         "agent_incomplete:finish_reason_length")
    assert "coverage_degraded" in combined and "agent_incomplete" in combined

    assert pipeline._combine_reasons(None, "agent_incomplete:x") == "agent_incomplete:x"
    assert pipeline._combine_reasons("coverage_degraded:x", None) == "coverage_degraded:x"
    assert pipeline._combine_reasons(None, None) is None


def test_recording_without_a_scan_run_id_is_a_no_op(rec):
    """Some call sites have no run context; they must not crash or pollute."""
    _record("nmap", _fail(), None, run=None)
    assert tool_execution.coverage_summary(None) == {}
