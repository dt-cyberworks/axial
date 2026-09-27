"""TC-FIDELITY-007: agent-proposed tool calls (dispatch.py) target the
engagement's configured single port exactly like the deterministic
fingerprint phase, and a port-scope denial from the egress-proxy is surfaced
to the agent as an explicit EGRESS BLOCKED observation, not silent noise."""

from __future__ import annotations

import pytest

from app.tasks import dispatch


@pytest.fixture(autouse=True)
def _mock_tool_execution_telemetry(monkeypatch):
    # REQ-SCAN-014: _run() now records every outcome through
    # tool_execution.record(), which converts engagement_id to a real UUID
    # eagerly as a call argument (so mocking client.record_tool_execution
    # alone still crashes on the placeholder "eid" ids these tests use) and
    # needs a reachable control-plane. Mocked at this level instead, globally
    # rather than per test.
    monkeypatch.setattr(dispatch.tool_execution, "record", lambda *a, **k: None)


def _fake_run(calls):
    def run(tool, target, args, scan_run_id=None, engagement_id=None):
        calls.append((tool, target))
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}
    return run


def test_httpx_dispatch_targets_the_configured_port(monkeypatch):
    # REQ-FIDELITY-003/007/010: httpx gets an explicit http:// target (no
    # other tool here does) - see target_envelope.httpx_target's docstring
    # for why (httpx self-corrects http-> https when needed, but a schemeless
    # target on a non-standard port was found live to never probe https at
    # all, misreporting a TLS-only service as plain HTTP).
    calls = []
    monkeypatch.setattr(dispatch.tool_runner, "run", _fake_run(calls))
    monkeypatch.setattr(dispatch, "parse_httpx_json", lambda stdout: [])

    dispatch.dispatch("eid", "asset-1", "httpx", "pentest-ground.com", single_port=4280)

    assert calls == [("httpx", "http://pentest-ground.com:4280")]


def test_nikto_dispatch_targets_the_configured_port(monkeypatch):
    calls = []
    monkeypatch.setattr(dispatch.tool_runner, "run", _fake_run(calls))
    monkeypatch.setattr(dispatch.client, "add_service", lambda *a, **k: {"id": "svc-1"})
    monkeypatch.setattr(dispatch, "parse_nikto_missing_headers", lambda stdout: [])

    dispatch.dispatch("eid", "asset-1", "nikto", "pentest-ground.com", single_port=4280)

    assert calls == [("nikto", "https://pentest-ground.com:4280")]


def test_nuclei_dispatch_targets_the_configured_port(monkeypatch):
    calls = []
    monkeypatch.setattr(dispatch.tool_runner, "run", _fake_run(calls))
    monkeypatch.setattr(dispatch, "parse_nuclei_jsonl", lambda stdout: [])

    dispatch.dispatch("eid", "asset-1", "nuclei", "pentest-ground.com", single_port=4280)

    assert calls == [("nuclei", "https://pentest-ground.com:4280")]


def test_wafw00f_dispatch_targets_the_configured_port(monkeypatch):
    calls = []
    monkeypatch.setattr(dispatch.tool_runner, "run", _fake_run(calls))
    monkeypatch.setattr(dispatch, "parse_wafw00f", lambda stdout: None)

    dispatch.dispatch("eid", "asset-1", "wafw00f", "pentest-ground.com", single_port=4280)

    assert calls == [("wafw00f", "https://pentest-ground.com:4280")]


def test_testssl_dispatch_targets_the_configured_port(monkeypatch):
    calls = []
    monkeypatch.setattr(dispatch.tool_runner, "run", _fake_run(calls))
    monkeypatch.setattr(dispatch, "parse_testssl_json", lambda stdout: [])

    dispatch.dispatch("eid", "asset-1", "testssl", "pentest-ground.com", ip="1.2.3.4", single_port=4280)

    assert calls == [("testssl", "https://pentest-ground.com:4280")]


def test_http_request_dispatch_targets_the_configured_port(monkeypatch):
    calls = []
    monkeypatch.setattr(dispatch.tool_runner, "run", _fake_run(calls))

    dispatch.dispatch("eid", "asset-1", "http_request", "pentest-ground.com",
                       args={"method": "GET", "path": "/"}, single_port=4280)

    assert calls == [("http_request", "https://pentest-ground.com:4280")]


def test_ffuf_dispatch_targets_the_configured_port(monkeypatch):
    calls = []
    monkeypatch.setattr(dispatch.tool_runner, "run", _fake_run(calls))
    monkeypatch.setattr(dispatch, "parse_ffuf_json", lambda stdout: [])

    dispatch.dispatch("eid", "asset-1", "ffuf", "pentest-ground.com",
                       args={"path": "/FUZZ"}, single_port=4280)

    assert calls == [("ffuf", "https://pentest-ground.com:4280")]


def test_no_single_port_leaves_implicit_443(monkeypatch):
    calls = []
    monkeypatch.setattr(dispatch.tool_runner, "run", _fake_run(calls))
    monkeypatch.setattr(dispatch, "parse_httpx_json", lambda stdout: [])

    dispatch.dispatch("eid", "asset-1", "httpx", "pentest-ground.com", single_port=None)

    assert calls == [("httpx", "http://pentest-ground.com")]


def test_out_of_scope_port_denial_is_surfaced_as_egress_blocked(monkeypatch):
    # The egress-proxy denies with a 403 body of "out_of_scope_port" - simulate
    # the resulting tool stderr containing that literal reason text.
    def blocked_run(tool, target, args, scan_run_id=None, engagement_id=None):
        return {"success": False, "exit_code": -1, "stdout": "", "stderr": "out_of_scope_port"}

    monkeypatch.setattr(dispatch.tool_runner, "run", blocked_run)

    obs = dispatch.dispatch("eid", "asset-1", "httpx", "pentest-ground.com", single_port=None)

    assert "EGRESS BLOCKED" in obs.as_text()
    assert "out_of_scope_port" in obs.as_text()


# REQ-SCAN-014: agent-dispatched tool calls must feed the same coverage
# telemetry the deterministic fingerprint phase already uses - found live
# 2026-08-09, an unreachable tool-runner made every agent-proposed httpx/
# testssl/nuclei/nikto call read as a clean "no findings" result, both in the
# audit trail and in the run's coverage-degraded signal.

def test_negative_a_dispatch_exception_is_recorded_not_silently_swallowed(monkeypatch):
    recorded = []
    monkeypatch.setattr(dispatch.tool_execution, "record", lambda *a, **k: recorded.append(k))

    def raising_run(tool, target, args, scan_run_id=None, engagement_id=None):
        raise ConnectionError("tool-runner unreachable")

    monkeypatch.setattr(dispatch.tool_runner, "run", raising_run)
    monkeypatch.setattr(dispatch, "parse_httpx_json", lambda stdout: [])

    dispatch.dispatch("019649b8-0000-7000-8000-000000000001", "asset-1", "httpx",
                       "pentest-ground.com", ip="192.0.2.10", single_port=4280)

    assert len(recorded) == 1
    assert recorded[0]["tool"] == "httpx"
    assert recorded[0]["phase"] == "agent"
    assert recorded[0]["resolved_target"] == "192.0.2.10"
    assert recorded[0]["result"]["success"] is False
    assert recorded[0]["result"]["error_reason"] == "runner_dispatch_failed"


def test_negative_a_graceful_transport_failure_is_also_recorded(monkeypatch):
    """Not every failure is a raised exception - raw_egress_unavailable and
    similar are normal (success=False) returns from tool_runner.run(). These
    must feed the same telemetry, not just the exception path."""
    recorded = []
    monkeypatch.setattr(dispatch.tool_execution, "record", lambda *a, **k: recorded.append(k))
    monkeypatch.setattr(
        dispatch.tool_runner, "run",
        lambda tool, target, args, scan_run_id=None, engagement_id=None: {
            "success": False, "exit_code": -1, "stdout": "", "stderr": "",
            "error_reason": "raw_egress_unavailable",
        },
    )
    monkeypatch.setattr(dispatch, "parse_nuclei_jsonl", lambda stdout: [])

    dispatch.dispatch("019649b8-0000-7000-8000-000000000001", "asset-1", "nuclei", "pentest-ground.com")

    assert len(recorded) == 1
    assert recorded[0]["result"]["success"] is False
    assert recorded[0]["result"]["error_reason"] == "raw_egress_unavailable"


def test_a_successful_dispatch_is_also_recorded(monkeypatch):
    """Necessary, not just nice-to-have: coverage tracks attempted vs
    succeeded per tool. If only failures were recorded, a tool that failed
    once and then succeeded would still read as fully degraded."""
    recorded = []
    monkeypatch.setattr(dispatch.tool_execution, "record", lambda *a, **k: recorded.append(k))
    monkeypatch.setattr(
        dispatch.tool_runner, "run",
        lambda tool, target, args, scan_run_id=None, engagement_id=None: {
            "success": True, "exit_code": 0, "stdout": "", "stderr": "",
        },
    )
    monkeypatch.setattr(dispatch, "parse_httpx_json", lambda stdout: [])

    dispatch.dispatch("019649b8-0000-7000-8000-000000000001", "asset-1", "httpx", "pentest-ground.com")

    assert len(recorded) == 1
    assert recorded[0]["result"]["success"] is True


# --- REQ-FIDELITY-009 / TC-FIDELITY-009: the CONFIRMED protocol reaches every
# tool that needs an explicit scheme. Verified live 2026-08-03 against a
# plain-HTTP service: nuclei found 2 real template matches with http:// and 0
# with the forced https:// this code used to always send - silently, reported
# as "Scan completed. No results found." A schemeless target is not a fix
# either (nuclei's embedded httpx: "Found 0 URL from httpx", also 0 matches),
# which is why the fix passes the correct scheme rather than dropping it.
#
# The pre-existing tests above deliberately stay unchanged: they cover the
# no-confirmed-protocol case, whose https:// default is still correct. ---

def _wire(monkeypatch, calls):
    monkeypatch.setattr(dispatch.tool_runner, "run", _fake_run(calls))
    monkeypatch.setattr(dispatch.client, "add_service", lambda *a, **k: {"id": "svc-1"})
    monkeypatch.setattr(dispatch.client, "add_finding", lambda *a, **k: {"id": "f-1"})
    monkeypatch.setattr(dispatch, "parse_nikto_missing_headers", lambda stdout: [])
    monkeypatch.setattr(dispatch, "parse_wafw00f", lambda stdout: None)
    monkeypatch.setattr(dispatch, "parse_nuclei_jsonl", lambda stdout: [])
    monkeypatch.setattr(dispatch, "parse_ffuf_json", lambda stdout: [])
    monkeypatch.setattr(dispatch, "parse_testssl_json", lambda stdout: [])


@pytest.mark.parametrize("tool", ["nikto", "wafw00f", "nuclei"])
def test_confirmed_http_reaches_scheme_dependent_tools(monkeypatch, tool):
    calls = []
    _wire(monkeypatch, calls)
    dispatch.dispatch("eid", "asset-1", tool, "target.example", single_port=8080,
                      confirmed_protocol="http")
    assert calls == [(tool, "http://target.example:8080")]


@pytest.mark.parametrize("tool", ["nikto", "wafw00f", "nuclei"])
def test_confirmed_https_still_uses_https(monkeypatch, tool):
    calls = []
    _wire(monkeypatch, calls)
    dispatch.dispatch("eid", "asset-1", tool, "target.example", single_port=8443,
                      confirmed_protocol="https")
    assert calls == [(tool, "https://target.example:8443")]


@pytest.mark.parametrize("tool", ["nikto", "wafw00f", "nuclei"])
def test_unknown_protocol_falls_back_to_https_not_schemeless(monkeypatch, tool):
    """NEGATIVE: when the protocol is genuinely unknown the historical https
    default must be preserved. It must NOT degrade to a schemeless target -
    none of these tools auto-probe, so that would break real HTTPS targets."""
    calls = []
    _wire(monkeypatch, calls)
    for unknown in (None, "", "tcp", "gopher"):
        calls.clear()
        dispatch.dispatch("eid", "asset-1", tool, "target.example", single_port=8443,
                          confirmed_protocol=unknown)
        assert calls == [(tool, "https://target.example:8443")], f"failed for {unknown!r}"


def test_http_request_and_ffuf_receive_the_confirmed_scheme(monkeypatch):
    calls = []
    _wire(monkeypatch, calls)
    dispatch.dispatch("eid", "asset-1", "http_request", "target.example",
                      args={"method": "GET", "path": "/"}, single_port=8080,
                      confirmed_protocol="http")
    assert calls == [("http_request", "http://target.example:8080")]

    calls.clear()
    dispatch.dispatch("eid", "asset-1", "ffuf", "target.example",
                      args={"path": "/FUZZ"}, single_port=8080, confirmed_protocol="http")
    assert calls == [("ffuf", "http://target.example:8080")]


def test_testssl_is_skipped_on_a_confirmed_plain_http_port(monkeypatch):
    """NEGATIVE: the deterministic path already refuses this
    (fingerprint._tls_scan, 'not_a_tls_service'); the agent's ad-hoc call had
    no such gate and produced meaningless 'TLS 1.2/1.3 not offered' findings
    on non-TLS ports, which also polluted the benchmark's negative controls."""
    calls = []
    _wire(monkeypatch, calls)
    obs = dispatch.dispatch("eid", "asset-1", "testssl", "target.example", ip="1.2.3.4",
                            single_port=8080, confirmed_protocol="http")
    assert calls == []
    assert "uebersprungen" in obs.summary


def test_nikto_records_the_confirmed_protocol_not_a_hardcoded_https(monkeypatch):
    """add_service has no upsert - every call INSERTS - so a hardcoded 'https'
    here permanently adds a contradictory second service row for a port httpx
    already identified correctly. Measured before the fix: pentest-ground.com
    :4280 (a real engagement) carried https/http, https/nginx and tcp/nginx
    rows at once, all fed into the agent's own evidence context."""
    calls = []
    services = []
    _wire(monkeypatch, calls)
    monkeypatch.setattr(dispatch.client, "add_service",
                        lambda eid, **kw: (services.append(kw), {"id": "svc-1"})[1])

    dispatch.dispatch("eid", "asset-1", "nikto", "target.example", single_port=8080,
                      confirmed_protocol="http")

    assert services and services[0]["protocol"] == "http"
