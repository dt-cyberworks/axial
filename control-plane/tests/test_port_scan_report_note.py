"""TC-PORTSCAN-003 (report): a run whose port scan had gaps never produces a report that reads as a
clean port scan (GitHub issue #60)."""

from types import SimpleNamespace

import pytest

from app.report_builder import PORT_SCAN_NOTE, _port_scan_note


def _run(reason):
    return SimpleNamespace(state_reason=reason)


@pytest.mark.parametrize("reason", [
    "coverage_partial:nmap=1",
    "coverage_partial:nmap=4,nuclei=2",
    "coverage_degraded:httpx=runner_dispatch_failed; coverage_partial:nuclei=1,nmap=3",
])
def test_req_portscan_003_a_partial_port_scan_adds_the_note(reason):
    assert _port_scan_note(_run(reason)) == PORT_SCAN_NOTE


@pytest.mark.parametrize("reason", [None, "", "coverage_partial:nuclei=1", "coverage_degraded:nmap=raw_egress_unavailable", "cancelled_by_operator"])
def test_negative_req_portscan_003_other_runs_get_no_port_scan_note(reason):
    assert _port_scan_note(_run(reason)) is None


def test_negative_req_portscan_003_no_report_run_gets_no_note():
    assert _port_scan_note(None) is None


def test_req_portscan_003_the_note_does_not_say_the_port_is_closed():
    assert "does NOT mean it is closed" in PORT_SCAN_NOTE
