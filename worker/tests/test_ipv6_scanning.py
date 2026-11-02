"""REQ-SCAN-016 / REQ-SCAN-017 (GitHub #77): every address of a host is port-scanned, IPv6 included, and a scan that
could not reach an address never reads as "nothing open".

Before: the fingerprint phase kept ONE address per name (the first the resolver answered), so a dual-stack host whose
AAAA record came first was never scanned over IPv4, and a host's IPv6 address was never scanned at all. Nmap also
refuses an IPv6 literal without `-6` and scans nothing."""

from __future__ import annotations

import pytest

from app import raw_nmap, tool_execution, tool_runner_client
from app.raw_nmap import PROBES_DROPPED, count_dropped_probes
from app.tasks import agent, fingerprint

EID = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
BROAD = {"tcp_port_from": 1, "tcp_port_to": 65535}
HOST = "dual.example.com"
V4, V6 = "203.0.113.9", "2001:db8::7"


def _svc(port: int) -> dict:
    return {"port": port, "product": f"p{port}", "protocol": "tcp"}


def _asset(name: str, idx: int = 0) -> dict:
    return {"asset_id": f"asset-{idx}", "value": name}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.delenv("NMAP_SCAN_IPV6", raising=False)
    monkeypatch.setattr(fingerprint.client, "add_service", lambda *a, **k: {"id": "svc-1"})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint, "lookup_known_vuln", lambda *a: None)
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: BROAD)
    tool_execution.clear_coverage(RUN)
    yield
    tool_execution.clear_coverage(RUN)


class Harness:
    def __init__(self, monkeypatch, resolved, scans, *, recorded=None):
        """resolved: [(hostname, address)] in the order the control plane answered; scans: address -> (services, ok)."""
        self.scanned: list[str] = []
        self.findings: list[dict] = []
        self.probe_addresses: list = []
        monkeypatch.setattr(
            fingerprint.client, "materialize_dns",
            lambda eid, scan_run_id=None: {"resolved": [{"hostname": h, "ip_address": ip} for h, ip in resolved]},
        )

        def fake_execute(engagement_id, asset_id, target, ip, scan_run_id):
            self.scanned.append(ip)
            return scans.get(ip, ([], False))

        monkeypatch.setattr(fingerprint, "_execute_port_scan", fake_execute)
        monkeypatch.setattr(fingerprint, "_probe_web_surface",
                            lambda *a, **k: self.probe_addresses.append(a[4]) or (None, None))
        monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: self.findings.append(k) or {"id": "f"})
        if recorded is not None:
            monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k))

    def discover(self, hosts=(HOST,)):
        services, surfaces = fingerprint._discover_surfaces(EID, [_asset(h, i) for i, h in enumerate(hosts)], RUN)
        return services, surfaces


# --- the materialization keeps every address -------------------------------------------------------------------

def test_the_materialization_keeps_every_address_of_a_name_with_ipv4_first(monkeypatch):
    monkeypatch.setattr(
        fingerprint.client, "materialize_dns",
        lambda eid, scan_run_id=None: {"resolved": [
            {"hostname": "A.example.com", "ip_address": V6},
            {"hostname": "a.example.com", "ip_address": "203.0.113.10"},
            {"hostname": "a.example.com", "ip_address": V6},          # a duplicate answer
            {"hostname": "a.example.com", "ip_address": "203.0.113.9"},
            {"hostname": "b.example.com", "ip_address": "2001:db8::9"},
        ]},
    )
    assert fingerprint._materialize(EID, RUN) == {
        "a.example.com": ["203.0.113.10", "203.0.113.9", V6],  # IPv4 first, each family in the order it was answered
        "b.example.com": ["2001:db8::9"],
    }


# --- every address is port-scanned -----------------------------------------------------------------------------

def test_a_dual_stack_host_is_port_scanned_over_both_families_even_when_the_aaaa_record_came_first(monkeypatch):
    h = Harness(monkeypatch, [(HOST, V6), (HOST, V4)], {V4: ([_svc(443)], True), V6: ([_svc(443)], True)})
    h.discover()
    assert h.scanned == [V4, V6]


def test_the_web_surface_is_identified_by_the_ipv4_address_not_the_first_answer(monkeypatch):
    h = Harness(monkeypatch, [(HOST, V6), (HOST, V4)], {V4: ([_svc(443)], True), V6: ([_svc(443)], True)})
    h.discover()
    assert h.probe_addresses and set(h.probe_addresses) == {V4}


def test_an_ipv6_only_host_is_port_scanned_once_over_ipv6(monkeypatch):
    h = Harness(monkeypatch, [(HOST, V6)], {V6: ([_svc(443)], True)})
    services, _ = h.discover()
    assert h.scanned == [V6] and [s["port"] for s in services] == [443]
    assert h.probe_addresses == [V6]


def test_the_open_ports_of_both_families_are_merged_into_the_hosts_services(monkeypatch):
    h = Harness(monkeypatch, [(HOST, V4), (HOST, V6)], {V4: ([_svc(443)], True), V6: ([_svc(443), _svc(8080)], True)})
    services, _ = h.discover()
    assert sorted(s["port"] for s in services) == [443, 8080]  # 443 once, 8080 found only over IPv6


def test_a_second_name_on_the_same_dual_stack_addresses_reuses_both_scans(monkeypatch):
    h = Harness(monkeypatch, [("a.example.com", V4), ("a.example.com", V6), ("b.example.com", V4), ("b.example.com", V6)],
                {V4: ([_svc(443)], True), V6: ([_svc(443)], True)})
    h.discover(("a.example.com", "b.example.com"))
    assert h.scanned == [V4, V6]  # each address scanned once for the run


def test_a_host_without_a_materialized_address_is_still_attempted_and_recorded_as_failed(monkeypatch):
    recorded: list[dict] = []
    h = Harness(monkeypatch, [], {}, recorded=recorded)
    h.discover()
    assert h.scanned == [None]  # the existing "materialized_ip_missing" path in _execute_port_scan records it


# --- a port that is open over IPv6 only ------------------------------------------------------------------------

def test_a_port_open_over_ipv6_only_is_reported_as_an_exposure(monkeypatch):
    h = Harness(monkeypatch, [(HOST, V4), (HOST, V6)], {V4: ([_svc(443)], True), V6: ([_svc(443), _svc(8080)], True)})
    h.discover()
    assert len(h.findings) == 1
    finding = h.findings[0]
    assert finding["title"] == "Port 8080 is open over IPv6 only"
    assert finding["category"] == "exposure" and finding["confidence"] == "validated"
    assert finding["evidence"]["port"] == 8080 and finding["evidence"]["family_difference"] == "ipv6_only"
    assert finding["evidence"]["ipv6_addresses"] == [V6] and finding["evidence"]["ipv4_addresses"] == [V4]


def test_negative_a_port_open_on_both_families_is_not_a_difference(monkeypatch):
    h = Harness(monkeypatch, [(HOST, V4), (HOST, V6)], {V4: ([_svc(443)], True), V6: ([_svc(443)], True)})
    h.discover()
    assert h.findings == []


def test_negative_a_port_open_over_ipv4_only_is_not_reported_as_an_ipv6_finding(monkeypatch):
    h = Harness(monkeypatch, [(HOST, V4), (HOST, V6)], {V4: ([_svc(443), _svc(22)], True), V6: ([_svc(443)], True)})
    h.discover()
    assert h.findings == []


@pytest.mark.parametrize("failed", [V4, V6])
def test_negative_no_difference_is_reported_when_one_family_could_not_be_scanned(monkeypatch, failed):
    """A failed scan shows no open ports; that is a failure, not a fact about the host."""
    scans = {V4: ([_svc(443)], True), V6: ([_svc(443), _svc(8080)], True)}
    scans[failed] = ([], False)
    h = Harness(monkeypatch, [(HOST, V4), (HOST, V6)], scans)
    h.discover()
    assert h.findings == []


def test_negative_ports_a_failed_scan_reported_are_not_evidence_of_a_difference(monkeypatch):
    """A scan that did not succeed is not evidence about the host, whatever it returned."""
    v6_failed = "2001:db8::8"
    h = Harness(monkeypatch, [(HOST, V4), (HOST, V6), (HOST, v6_failed)],
                {V4: ([_svc(443)], True), V6: ([_svc(443)], True), v6_failed: ([_svc(8080)], False)})
    h.discover()
    assert h.findings == []


def test_negative_a_failure_to_store_the_difference_does_not_fail_the_scan(monkeypatch):
    h = Harness(monkeypatch, [(HOST, V4), (HOST, V6)], {V4: ([_svc(443)], True), V6: ([_svc(8080)], True)})

    def boom(*a, **k):
        raise RuntimeError("control plane down")

    monkeypatch.setattr(fingerprint.client, "add_finding", boom)
    services, _ = h.discover()
    assert sorted(s["port"] for s in services) == [443, 8080]


# --- a scan that did not reach an address is never clean -------------------------------------------------------

def test_negative_a_failed_ipv6_scan_beside_a_working_ipv4_scan_is_counted_as_partial_coverage(monkeypatch):
    h = Harness(monkeypatch, [(HOST, V4), (HOST, V6)], {V4: ([_svc(443)], True), V6: ([], False)})
    h.discover()
    assert tool_execution.partial_tools(RUN) == {"nmap": 1}


def test_negative_a_host_none_of_whose_addresses_scanned_is_partial_when_another_host_scanned(monkeypatch):
    h = Harness(monkeypatch, [("a.example.com", V4), ("b.example.com", "203.0.113.20")],
                {V4: ([_svc(443)], True), "203.0.113.20": ([], False)})
    h.discover(("a.example.com", "b.example.com"))
    assert tool_execution.partial_tools(RUN) == {"nmap": 1}


def test_a_name_without_any_materialized_address_is_not_counted_as_a_partial_scan(monkeypatch):
    """Nothing could be scanned for it; its failed nmap record already says so (`materialized_ip_missing`)."""
    h = Harness(monkeypatch, [("a.example.com", V4)], {V4: ([_svc(443)], True)})
    h.discover(("a.example.com", "unresolved.example.com"))
    assert h.scanned == [V4, None]
    assert tool_execution.partial_tools(RUN) == {}


def test_a_run_in_which_no_scan_succeeded_is_left_to_the_degraded_rule(monkeypatch):
    """Every attempt failed: `degraded_tools` already reads that as coverage degraded; no second signal."""
    h = Harness(monkeypatch, [(HOST, V4), (HOST, V6)], {V4: ([], False), V6: ([], False)})
    h.discover()
    assert tool_execution.partial_tools(RUN) == {}


def test_a_fully_scanned_dual_stack_host_adds_no_partial_note(monkeypatch):
    h = Harness(monkeypatch, [(HOST, V4), (HOST, V6)], {V4: ([_svc(443)], True), V6: ([_svc(443)], True)})
    h.discover()
    assert tool_execution.partial_tools(RUN) == {}


def test_note_partial_counts_per_run_and_ignores_a_missing_run():
    tool_execution.note_partial(RUN, "nmap", "address_not_port_scanned")
    tool_execution.note_partial(RUN, "nmap", "address_not_port_scanned")
    tool_execution.note_partial(None, "nmap", "address_not_port_scanned")
    assert tool_execution.partial_tools(RUN) == {"nmap": 2}
    assert tool_execution.partial_tools("another-run") == {}


# --- IPv6 scanning can be switched off on purpose --------------------------------------------------------------

@pytest.mark.parametrize("value, enabled", [
    (None, True), ("true", True), ("1", True), ("yes", True), (" TRUE ", True),
    ("false", False), ("0", False), ("no", False), ("off", False), (" False ", False),
])
def test_nmap_scan_ipv6_switch(monkeypatch, value, enabled):
    if value is not None:
        monkeypatch.setenv("NMAP_SCAN_IPV6", value)
    assert fingerprint.nmap_ipv6_enabled() is enabled


def test_with_ipv6_scanning_off_the_ipv6_address_is_recorded_as_skipped_and_never_scanned(monkeypatch):
    monkeypatch.setenv("NMAP_SCAN_IPV6", "false")
    recorded: list[dict] = []
    h = Harness(monkeypatch, [(HOST, V4), (HOST, V6)], {V4: ([_svc(443)], True), V6: ([_svc(8080)], True)},
                recorded=recorded)
    services, _ = h.discover()
    assert h.scanned == [V4] and [s["port"] for s in services] == [443]
    skipped = [r for r in recorded if r["resolved_target"] == V6]
    assert len(skipped) == 1 and skipped[0]["result"]["outcome"] == "skipped:ipv6_scanning_off"
    assert h.findings == []                                   # no difference is claimed about an address not scanned
    assert tool_execution.partial_tools(RUN) == {}            # a choice, not a hole


def test_negative_switching_ipv6_off_never_stops_the_ipv4_scan_of_an_ipv6_only_names_neighbour(monkeypatch):
    monkeypatch.setenv("NMAP_SCAN_IPV6", "false")
    h = Harness(monkeypatch, [("v4.example.com", V4), ("v6.example.com", V6)], {V4: ([_svc(443)], True)})
    h.discover(("v4.example.com", "v6.example.com"))
    assert h.scanned == [V4]
    assert tool_execution.partial_tools(RUN) == {}  # the IPv6-only name was skipped on purpose, not missed


# --- the agent is given the IPv4 address ------------------------------------------------------------------------

def test_the_agent_gets_the_ipv4_address_of_a_dual_stack_name_whichever_was_answered_first(monkeypatch):
    monkeypatch.setattr(agent.client, "list_discovered_assets", lambda *a, **k: [{"value": HOST, "id": "asset-0"}])
    monkeypatch.setattr(
        agent.client, "materialize_dns",
        lambda eid, scan_run_id=None: {"resolved": [
            {"hostname": HOST, "ip_address": V6}, {"hostname": HOST, "ip_address": V4},
        ]},
    )
    _, ip_by_host = agent._load_scope(EID, RUN)
    assert ip_by_host == {HOST: V4}


def test_the_agent_gets_the_ipv6_address_of_a_name_that_has_only_one(monkeypatch):
    monkeypatch.setattr(agent.client, "list_discovered_assets", lambda *a, **k: [{"value": HOST, "id": "asset-0"}])
    monkeypatch.setattr(
        agent.client, "materialize_dns",
        lambda eid, scan_run_id=None: {"resolved": [{"hostname": HOST, "ip_address": V6}]},
    )
    assert agent._load_scope(EID, RUN)[1] == {HOST: V6}


# --- nmap is told it is an IPv6 target -------------------------------------------------------------------------

DISCOVERY = {"stage": "discovery", "flags": ["-sS"], "ports": "1-65535", "max_rate": 300}
SERVICE = {"stage": "service", "flags": ["-sV"], "ports": "22,443", "max_rate": 300}
UDP = {"stage": "udp_discovery", "flags": ["-sU"], "ports": "53,123,161,443,500,1900,4500,5060,5353", "max_rate": 100}


@pytest.mark.parametrize("args", [DISCOVERY, SERVICE, UDP], ids=["discovery", "service", "udp"])
def test_an_ipv6_target_gets_the_ipv6_flag_in_every_stage(args):
    body = tool_runner_client._nmap_body(V6, args)
    assert body["target"] == V6 and body["additional_args"].startswith("-6 ")


@pytest.mark.parametrize("args", [DISCOVERY, SERVICE, UDP], ids=["discovery", "service", "udp"])
def test_negative_an_ipv4_target_never_gets_the_ipv6_flag(args):
    body = tool_runner_client._nmap_body(V4, args)
    assert "-6" not in body["additional_args"].split()


def test_a_cidr_or_name_target_is_not_taken_for_an_ipv6_literal():
    for target in ("192.0.2.0/28", "example.com", "2001"):
        assert tool_runner_client.is_ipv6_literal(target) is False
    assert tool_runner_client.is_ipv6_literal(V6) is True and tool_runner_client.is_ipv6_literal("::1") is True


@pytest.mark.parametrize("flags", [["-sS", "-6"], ["-6"], ["-sS", "-6", "-sV"]])
def test_negative_the_ipv6_flag_cannot_be_supplied_by_the_caller(flags):
    """The flag is derived from the target by the builder; a caller's arguments still take only the fixed profiles."""
    with pytest.raises(ValueError):
        tool_runner_client._nmap_body(V6, {**DISCOVERY, "flags": flags})


# --- an unreachable network is a hole in the scan, not a silent host -------------------------------------------

UNREACHABLE = (
    "sendto in send_ip_packet_sd: sendto(5, packet, 64, 0, 2001:db8::7, 28) => Network is unreachable\n"
    "Offending packet: TCP [2001:db8::1]:43539 > [2001:db8::7]:443 S ttl=59\n"
)
NO_ROUTE = "sendto in send_ip_packet_sd: sendto(5, packet, 64, 0, 2001:db8::7, 28) => No route to host\n"


def test_unreachable_network_and_no_route_count_as_dropped_probes():
    assert count_dropped_probes(UNREACHABLE * 2) == 2
    assert count_dropped_probes(NO_ROUTE) == 1
    assert count_dropped_probes("Network is unreachable\nNo route to host\nOperation not permitted") == 3
    assert count_dropped_probes("Nmap scan report for dual.example.com\n22/tcp filtered ssh") == 0


@pytest.mark.parametrize("stderr", [UNREACHABLE * 3, NO_ROUTE * 3])
def test_negative_a_scan_whose_probes_could_not_leave_the_network_is_partial_not_clean(monkeypatch, stderr):
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda token, reservation: None)
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "deactivate", lambda token, reservation: None)
    empty = (
        '<?xml version="1.0"?><nmaprun><host><status state="up"/><ports>'
        '<extraports state="filtered" count="65535"/></ports></host>'
        '<runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    )
    monkeypatch.setattr(
        raw_nmap.tool_runner, "run",
        lambda tool, target, args, **kw: {"success": True, "exit_code": 0, "stdout": empty, "stderr": stderr,
                                          "error_reason": None},
    )
    outcome = raw_nmap.execute_configured_tcp_scan(V6, "signed-lease", reservation_token="slot", max_rate=300)
    assert outcome.result["success"] is True
    assert tool_execution.outcome_of(outcome.result) == "partial"
    assert outcome.result["outcome_summary"]["partial_reasons"] == [PROBES_DROPPED]
