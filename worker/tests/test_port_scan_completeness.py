"""TC-PORTSCAN-001..004 (GitHub issue #60): a port scan that lost probes, or that no longer finds
a port every recent run found, is never reported as a clean scan."""

from __future__ import annotations

import pytest

from app import raw_nmap, tool_execution, tool_runner_client
from app.nmap_parse import nmap_xml_state_counts
from app.raw_nmap import PORTS_NO_LONGER_OPEN, PROBES_DROPPED, count_dropped_probes

DROP_LINE = (
    "sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 192.0.2.10, 16) => Operation not permitted\n"
    "Offending packet: TCP 172.20.0.3:43539 > 192.0.2.10:443 S ttl=59 id=23454 iplen=44\n"
)


def _xml(open_ports=(), *, closed=0, filtered=0, listed_states=None, total=1):
    nodes = "".join(
        f'<port protocol="tcp" portid="{port}"><state state="open"/><service name="svc{port}" product="p{port}"/></port>'
        for port in open_ports
    ) + "".join(
        f'<port protocol="tcp" portid="{port}"><state state="{state}"/></port>'
        for port, state in (listed_states or {}).items()
    )
    extra = ""
    if closed:
        extra += f'<extraports state="closed" count="{closed}"/>'
    if filtered:
        extra += f'<extraports state="filtered" count="{filtered}"/>'
    return (
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f"<ports>{extra}{nodes}</ports></host>"
        f'<runstats><hosts up="1" down="0" total="{total}"/></runstats></nmaprun>'
    )


def _result(stdout, stderr=""):
    return {"success": True, "exit_code": 0, "stdout": stdout, "stderr": stderr, "error_reason": None}


@pytest.fixture()
def lease(monkeypatch):
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda token, reservation: None)
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "deactivate", lambda token, reservation: None)


def _scan(monkeypatch, run, **kwargs):
    calls = []

    def fake(tool, target, args, **kw):
        calls.append(args)
        return run(args)

    monkeypatch.setattr(raw_nmap.tool_runner, "run", fake)
    outcome = raw_nmap.execute_configured_tcp_scan(
        "192.0.2.10", "signed-lease", reservation_token="slot", max_rate=1000, **kwargs,
    )
    return outcome, calls


# --- REQ-PORTSCAN-001: nmap never runs at the kernel limiter's own rate -----------------------

@pytest.mark.parametrize("lease_rate", [2, 3, 10, 100, 300, 999, 1000])
def test_req_portscan_001_nmap_is_always_below_the_leases_kernel_limit(lease_rate):
    send = tool_runner_client.nmap_send_rate(lease_rate)
    assert 1 <= send < lease_rate


def test_req_portscan_001_the_known_rates():
    assert [tool_runner_client.nmap_send_rate(r) for r in (1000, 300, 100)] == [500, 150, 50]
    assert tool_runner_client.nmap_send_rate(1) == 1  # a limit of 1 cannot be split


@pytest.mark.parametrize("stage,flags,ports,lease_rate", [
    ("discovery", ["-sS"], "1-65535", 1000),
    ("service", ["-sV"], "22,443", 300),
    ("udp_discovery", ["-sU"], "53,123,161,443,500,1900,4500,5060,5353", 100),
    ("host_discovery", ["-sn"], "", 500),
])
def test_req_portscan_001_every_nmap_stage_uses_the_reduced_rate(stage, flags, ports, lease_rate):
    args = {"stage": stage, "flags": flags, "max_rate": lease_rate}
    if ports:
        args["ports"] = ports
    body = tool_runner_client._nmap_body("192.0.2.10" if stage != "host_discovery" else "192.0.2.0/28", args)
    assert f"--max-rate {tool_runner_client.nmap_send_rate(lease_rate)} " in body["additional_args"]
    assert f"--max-rate {lease_rate} " not in body["additional_args"]


@pytest.mark.parametrize("lease_rate", list(range(1, 1001)))
def test_req_portscan_001_evenly_spaced_probes_never_exceed_nmaps_rate(lease_rate):
    send = tool_runner_client.nmap_send_rate(lease_rate)
    delay = tool_runner_client.nmap_scan_delay_ms(send)
    assert delay >= 1 and 1000 / delay <= send  # at most `send` probes in any second, evenly spaced


def test_req_portscan_001_the_known_delays():
    assert [tool_runner_client.nmap_scan_delay_ms(r) for r in (500, 150, 50, 1)] == [2, 7, 20, 1000]


@pytest.mark.parametrize("stage,flags,ports,lease_rate,delay", [
    ("discovery", ["-sS"], "1-65535", 1000, 2),
    ("service", ["-sV"], "22,443", 300, 7),
    ("udp_discovery", ["-sU"], "53,123,161,443,500,1900,4500,5060,5353", 100, 20),
    ("host_discovery", ["-sn"], "", 500, 4),
])
def test_req_portscan_001_every_stage_spaces_its_probes_evenly(stage, flags, ports, lease_rate, delay):
    args = {"stage": stage, "flags": flags, "max_rate": lease_rate}
    if ports:
        args["ports"] = ports
    body = tool_runner_client._nmap_body("192.0.2.10" if stage != "host_discovery" else "192.0.2.0/28", args)
    assert f"--scan-delay {delay}ms" in body["additional_args"]


def test_negative_req_portscan_001_the_lease_rate_range_is_still_enforced():
    for bad in (0, 1001, "x"):
        with pytest.raises(ValueError):
            tool_runner_client._nmap_body(
                "192.0.2.10", {"stage": "discovery", "flags": ["-sS"], "ports": "1-65535", "max_rate": bad},
            )


# --- REQ-PORTSCAN-002: what nmap saw is recorded ---------------------------------------------

def test_req_portscan_002_state_counts_include_the_summarized_ports():
    xml = _xml([465, 587], closed=3, filtered=65530)
    assert nmap_xml_state_counts(xml) == {"open": 2, "closed": 3, "filtered": 65530}


def test_req_portscan_002_state_counts_reject_a_malformed_document():
    for bad in ("", "<nmaprun>", "<other/>"):
        with pytest.raises(ValueError):
            nmap_xml_state_counts(bad)


def test_req_portscan_002_dropped_probes_are_counted_from_nmaps_own_messages():
    assert count_dropped_probes(DROP_LINE * 3) == 3
    assert count_dropped_probes("Starting Nmap\nNmap done") == 0
    assert count_dropped_probes(None) == 0


def test_req_portscan_002_a_clean_scan_records_states_and_no_drops(monkeypatch, lease):
    def run(args):
        if args["stage"] == "discovery":
            return _result(_xml([465, 587], closed=0, filtered=65533))
        return _result(_xml([465, 587]))

    outcome, _ = _scan(monkeypatch, run)
    summary = outcome.result["outcome_summary"]
    assert summary["states"] == {"filtered": 65533, "open": 2}
    assert summary["dropped_probes"] == 0 and "partial_reasons" not in summary
    assert "outcome" not in outcome.result  # complete
    assert tool_execution.outcome_of(outcome.result) == "complete"
    assert "tcp_states:filtered=65533,open=2" in outcome.result["stderr"]


# --- REQ-PORTSCAN-003: a scan with dropped probes is never complete --------------------------

def test_negative_req_portscan_003_dropped_probes_make_the_scan_partial(monkeypatch, lease):
    def run(args):
        if args["stage"] == "discovery":
            return _result(_xml([465, 587], filtered=65533), stderr=DROP_LINE * 4)
        return _result(_xml([465, 587]))

    outcome, _ = _scan(monkeypatch, run)
    assert outcome.result["success"] is True  # the output is real
    assert tool_execution.outcome_of(outcome.result) == "partial"
    assert outcome.result["outcome_summary"]["partial_reasons"] == [PROBES_DROPPED]
    assert outcome.result["outcome_summary"]["dropped_probes"] == 4
    # the explanation must survive the 1000 character bound, in front of nmap's own noise
    assert f"{PROBES_DROPPED}:4" in outcome.result["stderr"][:200]


def test_negative_req_portscan_003_probes_refused_during_version_detection_count_too(monkeypatch, lease):
    def run(args):
        if args["stage"] == "discovery":
            return _result(_xml([465], filtered=65534))
        return _result(_xml([465]), stderr=DROP_LINE * 2)

    outcome, _ = _scan(monkeypatch, run)
    assert outcome.result["outcome_summary"]["dropped_probes"] == 2
    assert tool_execution.outcome_of(outcome.result) == "partial"


def test_negative_req_portscan_003_a_failed_scan_is_failed_not_partial():
    result = {"success": False, "error_reason": "raw_egress_heartbeat_failed", "outcome": "partial"}
    assert tool_execution.outcome_of(result) == "failed"


def test_req_portscan_003_a_partial_scan_counts_as_partial_coverage():
    tool_execution.clear_coverage("run-x")
    result = {"success": True, "outcome": "partial", "outcome_summary": {"partial_reasons": [PROBES_DROPPED]}}
    tool_execution._accumulate_coverage("run-x", "nmap", result)
    assert tool_execution.partial_tools("run-x") == {"nmap": 1}
    tool_execution.clear_coverage("run-x")


def test_req_portscan_003_a_check_with_a_partial_result_names_the_reason():
    collector = tool_execution.CheckCollector()
    collector.results.append({"success": True, "outcome": "partial", "outcome_summary": {"partial_reasons": [PORTS_NO_LONGER_OPEN]}})
    assert tool_execution.check_outcome(collector) == ("partial", PORTS_NO_LONGER_OPEN)
    budget = tool_execution.CheckCollector()
    budget.results.append({"success": False, "error_reason": tool_execution.BUDGET_REACHED})
    assert tool_execution.check_outcome(budget)[0] in {"partial", "failed"}  # unchanged behaviour


# --- REQ-PORTSCAN-004: a port that was always open and is absent now is probed again ---------

def test_req_portscan_004_a_missing_port_is_reprobed_slowly_and_found(monkeypatch, lease):
    def run(args):
        if args["stage"] == "discovery":
            return _result(_xml([465, 587], filtered=65533))
        if args["ports"] == "465,587":
            return _result(_xml([465, 587]))
        assert args["ports"] == "80,443,993"  # exactly the missing ports, sorted
        return _result(_xml([80, 443], listed_states={993: "closed"}))

    outcome, calls = _scan(monkeypatch, run, expected_ports=[993, 80, 443, 465, 587])
    reprobe = calls[-1]
    assert reprobe["stage"] == "service" and reprobe["max_rate"] <= raw_nmap.REPROBE_MAX_RATE
    assert [s["port"] for s in outcome.services] == [80, 443, 465, 587]
    summary = outcome.result["outcome_summary"]
    assert summary["reconfirmed"] == [80, 443] and summary["reprobed"] == {"80": "open", "443": "open", "993": "closed"}
    # 993 is still absent after the second look: not clean, and the state says why (closed, not silent)
    assert summary["partial_reasons"] == [PORTS_NO_LONGER_OPEN]
    assert tool_execution.outcome_of(outcome.result) == "partial"
    assert f"{PORTS_NO_LONGER_OPEN}:993" in outcome.result["stderr"]


def test_req_portscan_004_ports_found_again_leave_a_complete_scan(monkeypatch, lease):
    def run(args):
        if args["stage"] == "discovery":
            return _result(_xml([465], filtered=65534))
        if args["ports"] == "465":
            return _result(_xml([465]))
        return _result(_xml([443]))

    outcome, _ = _scan(monkeypatch, run, expected_ports=[443, 465])
    assert [s["port"] for s in outcome.services] == [443, 465]
    assert "partial_reasons" not in outcome.result["outcome_summary"]
    assert tool_execution.outcome_of(outcome.result) == "complete"
    assert "ports_reconfirmed:443" in outcome.result["stderr"]


def test_req_portscan_004_nothing_is_reprobed_when_every_expected_port_was_found(monkeypatch, lease):
    def run(args):
        return _result(_xml([465, 587], filtered=65533))

    _, calls = _scan(monkeypatch, run, expected_ports=[465, 587])
    assert [c["stage"] for c in calls] == ["discovery", "service"]  # no extra look


def test_negative_req_portscan_004_ports_outside_the_scanned_range_are_ignored(monkeypatch, lease):
    def run(args):
        return _result(_xml([465], filtered=999))

    outcome, calls = _scan(monkeypatch, run, expected_ports=[22, 8080], port_range="400-500")
    assert [c["stage"] for c in calls] == ["discovery", "service"]
    assert "partial_reasons" not in outcome.result["outcome_summary"]


def test_negative_req_portscan_004_a_failed_reprobe_never_reads_as_confirmation(monkeypatch, lease):
    def run(args):
        if args["stage"] == "discovery":
            return _result(_xml([465], filtered=65534))
        if args["ports"] == "465":
            return _result(_xml([465]))
        return {"success": False, "exit_code": -1, "stdout": "", "stderr": "", "error_reason": "runner_dispatch_failed"}

    outcome, _ = _scan(monkeypatch, run, expected_ports=[443, 465])
    assert [s["port"] for s in outcome.services] == [465]
    assert outcome.result["outcome_summary"]["partial_reasons"] == [PORTS_NO_LONGER_OPEN]
    assert "runner_dispatch_failed" in outcome.result["stderr"]


def test_req_portscan_004_the_number_of_reprobed_ports_is_bounded(monkeypatch, lease):
    seen = []

    def run(args):
        if args["stage"] == "discovery":
            return _result(_xml([465], filtered=65534))
        seen.append(args["ports"])
        return _result(_xml([465]))

    _scan(monkeypatch, run, expected_ports=range(1000, 1200))
    reprobe = [p for p in seen if p != "465"][0]
    assert len(reprobe.split(",")) == raw_nmap.MAX_REPROBE_PORTS


# --- the fingerprint phase: partial scans are reused as partial, the comparison is best effort -

from app.tasks import fingerprint  # noqa: E402

EID = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
BROAD = {"tcp_port_from": 1, "tcp_port_to": 65535}


def _fingerprint_harness(monkeypatch, partial_reasons):
    monkeypatch.setattr(fingerprint.client, "add_service", lambda *a, **k: {"id": "svc-1"})
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: {"id": "f-1"})
    monkeypatch.setattr(fingerprint, "lookup_known_vuln", lambda *a: None)
    monkeypatch.setattr(fingerprint.scan_executor, "execute_plan", lambda **k: None)
    monkeypatch.setattr(fingerprint, "_probe_web_surface", lambda *a, **k: (None, None))
    monkeypatch.setattr(
        fingerprint.client, "materialize_dns",
        lambda eid, scan_run_id=None: {"resolved": [{"hostname": h, "ip_address": "192.0.2.10"} for h in ("a.example.com", "b.example.com")]},
    )
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: BROAD)

    def fake_execute(engagement_id, asset_id, target, ip, scan_run_id):
        fingerprint._note_port_scan_partial(list(partial_reasons))
        return ([{"port": 465, "product": "postfix", "protocol": "tcp"}], True)

    monkeypatch.setattr(fingerprint, "_execute_port_scan", fake_execute)
    recorded = []
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k))
    fingerprint.run(EID, [{"asset_id": "a1", "value": "a.example.com"}, {"asset_id": "a2", "value": "b.example.com"}], scan_run_id=RUN)
    return recorded


def test_negative_req_portscan_003_a_reused_partial_scan_is_reused_as_partial(monkeypatch):
    recorded = _fingerprint_harness(monkeypatch, [PROBES_DROPPED])
    reuse = [r for r in recorded if (r["result"].get("outcome_summary") or {}).get("reused_from")]
    assert len(reuse) == 1
    assert tool_execution.outcome_of(reuse[0]["result"]) == "partial"
    assert reuse[0]["result"]["outcome_summary"]["partial_reasons"] == [PROBES_DROPPED]


def test_req_portscan_003_a_reused_clean_scan_stays_complete(monkeypatch):
    recorded = _fingerprint_harness(monkeypatch, [])
    reuse = [r for r in recorded if (r["result"].get("outcome_summary") or {}).get("reused_from")]
    assert len(reuse) == 1 and tool_execution.outcome_of(reuse[0]["result"]) == "complete"


def _port_scan_inputs(monkeypatch, known):
    monkeypatch.setattr(fingerprint.tool_runner, "raw_network_available", lambda: True)
    monkeypatch.setattr(fingerprint.raw_egress_gateway, "acquire_reservation", lambda *a, **k: {"status": "granted", "reservation_token": "slot"})
    monkeypatch.setattr(fingerprint.raw_egress_gateway, "release_reservation", lambda *a, **k: {})
    monkeypatch.setattr(fingerprint.client, "is_cancel_requested", lambda *a, **k: False)
    monkeypatch.setattr(fingerprint.client, "add_service", lambda *a, **k: {"id": "svc-1"})
    monkeypatch.setattr(fingerprint, "lookup_known_vuln", lambda *a: None)
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(
        fingerprint.client, "acquire_raw_egress_lease",
        lambda *a, **k: {"allowed": True, "lease_token": "t", "max_rate": 1000, "port_range": "1-65535", "udp_discovery_enabled": False},
    )
    seen = {}

    def fake_scan(ip, token, **kwargs):
        seen.update(kwargs)
        return raw_nmap.RawNmapOutcome(result=_result(""), services=[], port_range="1-65535")

    monkeypatch.setattr(fingerprint, "execute_configured_tcp_scan", fake_scan)
    if isinstance(known, Exception):
        def lookup(*a, **k):
            raise known
    else:
        def lookup(*a, **k):
            return known
    monkeypatch.setattr(fingerprint.client, "known_open_ports", lookup)
    fingerprint._execute_port_scan(EID, "asset-1", "a.example.com", "192.0.2.10", RUN)
    return seen


def test_req_portscan_004_the_scan_is_given_the_ports_earlier_runs_found_open(monkeypatch):
    assert _port_scan_inputs(monkeypatch, [80, 443, 465])["expected_ports"] == [80, 443, 465]


def test_negative_req_portscan_004_an_unavailable_lookup_never_stops_the_scan(monkeypatch, caplog):
    seen = _port_scan_inputs(monkeypatch, RuntimeError("control plane busy"))
    assert seen["expected_ports"] == []  # the scan ran, only without the comparison
    assert "no comparison with earlier runs" in caplog.text
