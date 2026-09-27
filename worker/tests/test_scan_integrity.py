from types import SimpleNamespace

from app import tool_runner_client
from app.known_vulns import KnownVuln
from app.tasks import fingerprint, pipeline


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_compose_mode_marks_nmap_unavailable_without_dispatch(monkeypatch):
    calls = []
    runner = tool_runner_client.ToolRunnerClient("http://runner")
    monkeypatch.setattr(tool_runner_client, "RAW_NETWORK_MODE", "disabled")
    monkeypatch.setattr(runner._client, "post", lambda *a, **k: calls.append((a, k)))

    result = runner.run("nmap", "192.0.2.10", {"stage": "discovery", "flags": ["-sS"], "ports": "1-65535", "max_rate": 300})

    assert result["success"] is False
    assert result["error_reason"] == "raw_egress_unavailable"
    assert calls == []


def test_nmap_zero_target_is_failure_even_with_exit_zero(monkeypatch):
    runner = tool_runner_client.ToolRunnerClient("http://runner")
    monkeypatch.setattr(tool_runner_client, "RAW_NETWORK_MODE", "scope-restricted")
    monkeypatch.setattr(
        runner._client,
        "post",
        lambda *a, **k: _Response({
            "success": True,
            "return_code": 0,
            "stdout": "# Nmap done -- 0 IP addresses (0 hosts up) scanned",
            "stderr": 'Failed to resolve "example.test".',
        }),
    )

    result = runner.run("nmap", "192.0.2.10", {"stage": "discovery", "flags": ["-sS"], "ports": "1-65535", "max_rate": 300})

    assert result["success"] is False
    assert result["error_reason"] == "dns_resolution_failed"


def test_nmap_zero_target_without_dns_error_is_failure_even_with_exit_zero(monkeypatch):
    runner = tool_runner_client.ToolRunnerClient("http://runner")
    monkeypatch.setattr(tool_runner_client, "RAW_NETWORK_MODE", "scope-restricted")
    monkeypatch.setattr(
        runner._client,
        "post",
        lambda *a, **k: _Response({
            "success": True,
            "return_code": 0,
            "stdout": "# Nmap done -- 0 IP addresses (0 hosts up) scanned",
            "stderr": "",
        }),
    )

    result = runner.run("nmap", "192.0.2.10", {"stage": "discovery", "flags": ["-sS"], "ports": "1-65535", "max_rate": 300})

    assert result["success"] is False
    assert result["error_reason"] == "zero_targets_scanned"


def test_fingerprint_nmap_dispatches_materialized_ip_and_records_outcome(monkeypatch):
    seen = {}
    monkeypatch.setattr(fingerprint.tool_runner, "raw_network_available", lambda: True)
    monkeypatch.setattr(
        fingerprint.raw_egress_gateway, "acquire_reservation",
        lambda *a, **k: {"status": "granted", "reservation_token": "slot-token"},
    )
    monkeypatch.setattr(fingerprint.raw_egress_gateway, "release_reservation", lambda *a, **k: {})
    monkeypatch.setattr(fingerprint.client, "is_cancel_requested", lambda *a, **k: False)
    monkeypatch.setattr(
        fingerprint.client,
        "acquire_raw_egress_lease",
        lambda *a, **k: {
            "allowed": True,
            "lease_token": "signed-lease",
            "max_rate": 300,
            "port_range": "443-8443",
            "udp_discovery_enabled": False,
        },
    )
    monkeypatch.setattr(
        fingerprint,
        "execute_configured_tcp_scan",
        lambda ip, token, reservation_token, max_rate, port_range, scan_run_id: (
            seen.update(
                ip=ip, token=token, reservation_token=reservation_token,
                max_rate=max_rate, port_range=port_range, scan_run_id=scan_run_id,
            )
            or SimpleNamespace(
                result={
                    "success": True, "exit_code": 0, "stderr": "",
                    "error_reason": None, "stdout": "<nmaprun/>",
                },
                services=[{
                    "port": 22, "protocol": "tcp", "service_name": "ssh",
                    "product": "OpenSSH 9.0",
                }],
                port_range="443-8443",
            )
        ),
    )
    monkeypatch.setattr(fingerprint.client, "add_service", lambda *a, **k: {"id": "service-1"})
    monkeypatch.setattr(fingerprint, "lookup_known_vuln", lambda *a: None)
    recorded = []
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k))

    services, _ = fingerprint._execute_port_scan(
        "11111111-1111-1111-1111-111111111111",
        "asset-1",
        "example.test",
        "192.0.2.10",
        "22222222-2222-2222-2222-222222222222",
    )

    assert seen == {
        "ip": "192.0.2.10", "token": "signed-lease", "reservation_token": "slot-token",
        "max_rate": 300, "port_range": "443-8443",
        "scan_run_id": "22222222-2222-2222-2222-222222222222",
    }
    assert services[0]["port"] == 22
    assert recorded[0]["authorized_target"] == "example.test"
    assert recorded[0]["resolved_target"] == "192.0.2.10"
    assert recorded[0]["port_range"] == "443-8443"
    assert recorded[0]["discovered_services"] == 1

def test_known_vuln_finding_from_nmap_is_attributed_to_nmap(monkeypatch):
    """REQ-AGENT-013: a known-vulnerable-version finding derived from nmap's
    product/version banner must be attributed to nmap, not show as 'unknown
    tool' in the Findings UI."""
    monkeypatch.setattr(fingerprint.tool_runner, "raw_network_available", lambda: True)
    monkeypatch.setattr(
        fingerprint.raw_egress_gateway, "acquire_reservation",
        lambda *a, **k: {"status": "granted", "reservation_token": "slot-token"},
    )
    monkeypatch.setattr(fingerprint.raw_egress_gateway, "release_reservation", lambda *a, **k: {})
    monkeypatch.setattr(fingerprint.client, "is_cancel_requested", lambda *a, **k: False)
    monkeypatch.setattr(
        fingerprint.client, "acquire_raw_egress_lease",
        lambda *a, **k: {"allowed": True, "lease_token": "signed-lease", "max_rate": 300,
                         "port_range": "443-8443", "udp_discovery_enabled": False},
    )
    monkeypatch.setattr(
        fingerprint, "execute_configured_tcp_scan",
        lambda ip, token, reservation_token, max_rate, port_range, scan_run_id: SimpleNamespace(
            result={"success": True, "exit_code": 0, "stderr": "", "error_reason": None, "stdout": "<nmaprun/>"},
            services=[{"port": 21, "protocol": "tcp", "service_name": "ftp", "product": "vsftpd 2.3.4"}],
            port_range="443-8443",
        ),
    )
    monkeypatch.setattr(fingerprint.client, "add_service", lambda *a, **k: {"id": "service-1"})
    monkeypatch.setattr(
        fingerprint, "lookup_known_vuln",
        lambda *a: KnownVuln(product_contains="vsftpd 2.3.4", cve_ids=["CVE-2011-2523"],
                             cvss_base=9.8, epss=0.9, is_kev=True, title="vsftpd 2.3.4 backdoor"),
    )
    findings = []
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: findings.append(k))
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)

    # REQ-CORR-006: the inline known_vulns lookup now only fires for lab
    # targets (dot-less hostname) - real targets are correlated live via
    # correlate.py instead. Use a lab-style target to keep exercising this path.
    fingerprint._execute_port_scan(
        "11111111-1111-1111-1111-111111111111", "asset-1", "metasploitable2",
        "192.0.2.10", "22222222-2222-2222-2222-222222222222",
    )

    assert findings and findings[0]["evidence"]["tool"] == "nmap"


def test_known_vuln_lookup_skipped_for_non_lab_target(monkeypatch):
    """REQ-CORR-001/006: a real (dotted) target's nmap-detected service is NOT
    matched against the static known_vulns table - that CVE correlation now
    happens live in correlate.py instead."""
    monkeypatch.setattr(fingerprint.tool_runner, "raw_network_available", lambda: True)
    monkeypatch.setattr(
        fingerprint.raw_egress_gateway, "acquire_reservation",
        lambda *a, **k: {"status": "granted", "reservation_token": "slot-token"},
    )
    monkeypatch.setattr(fingerprint.raw_egress_gateway, "release_reservation", lambda *a, **k: {})
    monkeypatch.setattr(fingerprint.client, "is_cancel_requested", lambda *a, **k: False)
    monkeypatch.setattr(
        fingerprint.client, "acquire_raw_egress_lease",
        lambda *a, **k: {"allowed": True, "lease_token": "signed-lease", "max_rate": 300,
                         "port_range": "443-8443", "udp_discovery_enabled": False},
    )
    monkeypatch.setattr(
        fingerprint, "execute_configured_tcp_scan",
        lambda ip, token, reservation_token, max_rate, port_range, scan_run_id: SimpleNamespace(
            result={"success": True, "exit_code": 0, "stderr": "", "error_reason": None, "stdout": "<nmaprun/>"},
            services=[{"port": 21, "protocol": "tcp", "service_name": "ftp", "product": "vsftpd 2.3.4"}],
            port_range="443-8443",
        ),
    )
    monkeypatch.setattr(fingerprint.client, "add_service", lambda *a, **k: {"id": "service-1"})
    lookup_calls = []
    monkeypatch.setattr(
        fingerprint, "lookup_known_vuln",
        lambda *a: (lookup_calls.append(a) or KnownVuln(
            product_contains="vsftpd 2.3.4", cve_ids=["CVE-2011-2523"],
            cvss_base=9.8, epss=0.9, is_kev=True, title="vsftpd 2.3.4 backdoor",
        )),
    )
    findings = []
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: findings.append(k))
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)

    fingerprint._execute_port_scan(
        "11111111-1111-1111-1111-111111111111", "asset-1", "example.test",
        "192.0.2.10", "22222222-2222-2222-2222-222222222222",
    )

    assert lookup_calls == []
    assert findings == []


def test_pipeline_passes_fingerprint_services_to_correlation(monkeypatch):
    engagement_id = "11111111-1111-1111-1111-111111111111"
    run_id = "22222222-2222-2222-2222-222222222222"
    updates = []
    # GitHub issue #18: the worker no longer creates its own scan_run row -
    # the control plane creates it (race-safe) and hands the ID in, so there
    # is no create_scan_run call for this test to stub anymore.
    monkeypatch.setattr(pipeline.client, "is_cancel_requested", lambda *a, **k: False)
    monkeypatch.setattr(pipeline.client, "update_scan_run", lambda *a, **k: updates.append((a, k)) or {})
    monkeypatch.setattr(pipeline.discovery, "run", lambda eid, **k: [{"asset_id": "a1", "value": "example.test"}])
    services = [{"service_id": "s1", "port": 443}]
    monkeypatch.setattr(pipeline.fingerprint, "run", lambda *a, **k: services)
    correlated = []
    monkeypatch.setattr(pipeline.correlate, "run", lambda eid, services: correlated.extend(services) or [])
    monkeypatch.setattr(pipeline.agent, "run", lambda *a, **k: SimpleNamespace(incomplete_reason=None))
    monkeypatch.setattr(pipeline.validate, "run", lambda *a, **k: [])
    monkeypatch.setattr(pipeline.score, "run", lambda *a, **k: {})
    monkeypatch.setattr(pipeline.report, "run", lambda *a, **k: {})

    result = pipeline.run_scan.run(engagement_id, run_id)

    assert correlated == services
    assert result["scan_run_id"] == run_id


def test_in_flight_tool_is_terminated_for_exact_cancelled_run(monkeypatch):
    import threading

    scan_run_id = "22222222-2222-2222-2222-222222222222"
    runner = tool_runner_client.ToolRunnerClient("http://runner")
    tool_started = threading.Event()
    process_released = threading.Event()
    calls = []

    def post(path, **kwargs):
        calls.append((path, kwargs))
        if path.startswith("/api/processes/terminate-scan-run/"):
            process_released.set()
            return _Response({"success": True, "terminated_count": 1})
        tool_started.set()
        process_released.wait(timeout=2)
        return _Response({"success": False, "return_code": -15, "stdout": "", "stderr": "terminated"})

    monkeypatch.setattr(runner._client, "post", post)
    monkeypatch.setattr(tool_runner_client, "CANCEL_POLL_SECONDS", 0.01)
    monkeypatch.setattr(tool_runner_client, "_cancel_requested", lambda run_id: tool_started.is_set())

    result = runner.run("httpx", "example.test", {}, scan_run_id=scan_run_id)

    assert result["success"] is False
    assert result["error_reason"] == "cancelled_by_operator"
    terminate_paths = [path for path, _ in calls if "terminate-scan-run" in path]
    assert terminate_paths == [f"/api/processes/terminate-scan-run/{scan_run_id}"]
    assert process_released.is_set()


def test_unknown_cancel_state_fails_closed_and_terminates_tool(monkeypatch):
    import threading

    scan_run_id = "33333333-3333-3333-3333-333333333333"
    runner = tool_runner_client.ToolRunnerClient("http://runner")
    released = threading.Event()

    def post(path, **kwargs):
        if "terminate-scan-run" in path:
            released.set()
            return _Response({"success": True, "terminated_count": 1})
        released.wait(timeout=2)
        return _Response({"success": False})

    monkeypatch.setattr(runner._client, "post", post)
    monkeypatch.setattr(tool_runner_client, "CANCEL_POLL_SECONDS", 0.01)
    monkeypatch.setattr(
        tool_runner_client, "_cancel_requested",
        lambda run_id: (_ for _ in ()).throw(RuntimeError("control plane unavailable")),
    )

    result = runner.run("httpx", "example.test", {}, scan_run_id=scan_run_id)

    assert result["error_reason"] == "cancellation_status_unavailable"
    assert released.is_set()


def test_runner_builder_accepts_configured_tcp_and_only_fixed_udp_profile(monkeypatch):
    tcp = tool_runner_client._nmap_body(
        "192.0.2.10", {"stage": "discovery", "flags": ["-sS"], "ports": "443-8443", "max_rate": 300},
    )
    assert tcp["ports"] == "443-8443" and tcp["scan_type"] == "-sS"
    udp = tool_runner_client._nmap_body(
        "192.0.2.10", {
            "stage": "udp_discovery", "flags": ["-sU"],
            "ports": "53,123,161,443,500,1900,4500,5060,5353", "max_rate": 100,
        },
    )
    assert udp["scan_type"] == "-sU"
    import pytest
    with pytest.raises(ValueError):
        tool_runner_client._nmap_body(
            "192.0.2.10", {"stage": "udp_discovery", "flags": ["-sU"], "ports": "1-65535", "max_rate": 100},
        )


def test_host_discovery_body_is_sn_only_no_pn_no_ports(monkeypatch):
    """REQ-CIDRDISC-002: -sn must never be combined with -Pn (which SKIPS
    host discovery, the opposite of the point) - unlike every other nmap
    stage in this module, which uses -Pn deliberately."""
    body = tool_runner_client._nmap_body(
        "203.0.113.0/28", {"stage": "host_discovery", "flags": ["-sn"], "max_rate": 500},
    )
    assert body["target"] == "203.0.113.0/28"
    assert body["scan_type"] == "-sn"
    assert body["ports"] == ""
    assert "-Pn" not in body["additional_args"]
    assert "-PS80,443" in body["additional_args"]
    assert "--max-rate 500" in body["additional_args"]

    import pytest
    with pytest.raises(ValueError):
        tool_runner_client._nmap_body(
            "203.0.113.0/28", {"stage": "host_discovery", "flags": ["-sS"], "max_rate": 500},
        )
    with pytest.raises(ValueError):
        tool_runner_client._nmap_body(
            "203.0.113.0/28", {"stage": "host_discovery", "flags": ["-sn"], "ports": "80,443", "max_rate": 500},
        )
