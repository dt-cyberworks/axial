from app import raw_nmap


def _xml(ports, *, total=1, protocol="tcp", state="open"):
    port_nodes = "".join(
        (
            f'<port protocol="{protocol}" portid="{port}"><state state="{state}"/>'
            f'<service name="{name}" product="{product}"/></port>'
        )
        for port, name, product in ports
    )
    return (
        '<?xml version="1.0"?>'
        '<nmaprun scanner="nmap"><host><status state="up"/>'
        f"<ports>{port_nodes}</ports></host>"
        f'<runstats><hosts up="{1 if total else 0}" down="0" total="{total}"/></runstats>'
        "</nmaprun>"
    )


def _result(stdout):
    return {
        "success": True,
        "exit_code": 0,
        "stdout": stdout,
        "stderr": "",
        "error_reason": None,
    }


def test_full_discovery_precedes_service_detection_on_open_ports(monkeypatch):
    activations = []
    deactivations = []
    calls = []
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda token, reservation: activations.append((token, reservation)))
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "deactivate", lambda token, reservation: deactivations.append((token, reservation)))

    def run(tool, target, args, **kwargs):
        calls.append((tool, target, args))
        if args["stage"] == "discovery":
            return _result(_xml([(22, "ssh", ""), (8443, "https-alt", "")]))
        return _result(_xml([(22, "ssh", "OpenSSH 9.6"), (8443, "https-alt", "nginx 1.26")]))

    monkeypatch.setattr(raw_nmap.tool_runner, "run", run)

    outcome = raw_nmap.execute_full_tcp_scan("192.0.2.10", "signed-lease", reservation_token="slot-token", max_rate=300)

    assert outcome.result["success"] is True
    assert calls[0] == (
        "nmap",
        "192.0.2.10",
        {"stage": "discovery", "flags": ["-sS"], "ports": "1-65535", "max_rate": 300},
    )
    assert calls[1][2]["stage"] == "service"
    assert calls[1][2]["ports"] == "22,8443"
    assert [service["port"] for service in outcome.services] == [22, 8443]
    assert outcome.services[0]["product"] == "OpenSSH 9.6"
    assert activations == [("signed-lease", "slot-token")]
    assert deactivations == [("signed-lease", "slot-token")]


def test_zero_target_xml_is_failure_and_skips_service_detection(monkeypatch):
    calls = []
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda token, reservation: None)
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "deactivate", lambda token, reservation: None)
    monkeypatch.setattr(
        raw_nmap.tool_runner,
        "run",
        lambda *args, **kwargs: calls.append(args) or _result(_xml([], total=0)),
    )

    outcome = raw_nmap.execute_full_tcp_scan("192.0.2.10", "signed-lease", reservation_token="slot-token", max_rate=300)

    assert outcome.result["success"] is False
    assert outcome.result["error_reason"] == "zero_targets_scanned"
    assert len(calls) == 1


def test_activation_failure_never_dispatches_nmap(monkeypatch):
    calls = []
    monkeypatch.setattr(
        raw_nmap.raw_egress_gateway,
        "activate",
        lambda token, reservation: (_ for _ in ()).throw(RuntimeError("policy installation failed")),
    )
    monkeypatch.setattr(raw_nmap.tool_runner, "run", lambda *args, **kwargs: calls.append(args))

    outcome = raw_nmap.execute_full_tcp_scan("192.0.2.10", "bad-lease", reservation_token="slot-token", max_rate=300)

    assert outcome.result["success"] is False
    assert outcome.result["error_reason"] == "raw_egress_activation_or_dispatch_failed"
    assert calls == []


def test_revoke_failure_is_not_a_clean_scan(monkeypatch):
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda token, reservation: None)
    monkeypatch.setattr(
        raw_nmap.raw_egress_gateway,
        "deactivate",
        lambda token, reservation: (_ for _ in ()).throw(RuntimeError("gateway unavailable")),
    )
    monkeypatch.setattr(raw_nmap.tool_runner, "run", lambda *args, **kwargs: _result(_xml([])))

    outcome = raw_nmap.execute_full_tcp_scan("192.0.2.10", "signed-lease", reservation_token="slot-token", max_rate=300)

    assert outcome.result["success"] is False
    assert outcome.result["error_reason"] == "raw_egress_revoke_failed"


def test_targeted_udp_distinguishes_states_and_fingerprints_only_confirmed_open(monkeypatch):
    calls = []
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda token, reservation: None)
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "deactivate", lambda token, reservation: None)

    discovery_xml = (
        '<?xml version="1.0"?><nmaprun><host><status state="up"/><ports>'
        '<port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>'
        '<port protocol="udp" portid="123"><state state="open|filtered"/><service name="ntp"/></port>'
        '<port protocol="udp" portid="161"><state state="filtered"/><service name="snmp"/></port>'
        '<port protocol="udp" portid="443"><state state="closed"/><service name="quic"/></port>'
        '</ports></host><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    )

    def run(tool, target, args, **kwargs):
        calls.append(args)
        if args["stage"] == "udp_discovery":
            return _result(discovery_xml)
        return _result(_xml([(53, "domain", "BIND 9")], protocol="udp"))

    monkeypatch.setattr(raw_nmap.tool_runner, "run", run)
    outcome = raw_nmap.execute_targeted_udp_scan(
        "192.0.2.10", "udp-lease", reservation_token="slot-token", max_rate=100,
    )

    assert calls[0]["ports"] == raw_nmap.TARGETED_UDP_PORT_RANGE
    assert calls[1]["stage"] == "udp_service" and calls[1]["ports"] == "53"
    assert outcome.state_counts == {"open": 1, "open|filtered": 1, "filtered": 1, "closed": 1}
    assert [(item["protocol"], item["port"]) for item in outcome.services] == [("udp", 53)]
    assert outcome.result["outcome_summary"]["states"]["open|filtered"] == 1

def test_targeted_udp_rejects_worker_port_widening_before_activation(monkeypatch):
    activations = []
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda *args: activations.append(args))
    outcome = raw_nmap.execute_targeted_udp_scan(
        "192.0.2.10", "udp-lease", reservation_token="slot-token", max_rate=100,
        port_range="1-65535",
    )
    assert outcome.result["error_reason"] == "udp_port_profile_invalid"
    assert activations == []


def _sn_xml(live_ips, dead_ips=(), *, total=None):
    hosts = "".join(f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/></host>' for ip in live_ips)
    hosts += "".join(f'<host><status state="down"/><address addr="{ip}" addrtype="ipv4"/></host>' for ip in dead_ips)
    count = total if total is not None else len(live_ips) + len(dead_ips)
    return (
        '<?xml version="1.0"?><nmaprun scanner="nmap">'
        f"{hosts}"
        f'<runstats><hosts up="{len(live_ips)}" down="{len(dead_ips)}" total="{count}"/></runstats>'
        "</nmaprun>"
    )


# REQ-CIDRDISC-001/002: execute_host_discovery_sweep - the liveness-only
# counterpart of execute_full_tcp_scan/execute_targeted_udp_scan above,
# proving the generalized _with_active_lease (dataclasses.replace-based)
# still works correctly for a differently-shaped outcome type.

def test_host_discovery_sweep_returns_only_live_hosts(monkeypatch):
    calls = []
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda token, reservation: None)
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "deactivate", lambda token, reservation: None)

    def run(tool, target, args, **kwargs):
        calls.append((tool, target, args))
        return _result(_sn_xml(["203.0.113.1", "203.0.113.3"], ["203.0.113.2"]))

    monkeypatch.setattr(raw_nmap.tool_runner, "run", run)

    outcome = raw_nmap.execute_host_discovery_sweep(
        "203.0.113.0/28", "signed-lease", reservation_token="slot-token", max_rate=500,
    )

    assert outcome.result["success"] is True
    assert outcome.live_hosts == ["203.0.113.1", "203.0.113.3"]
    assert calls == [(
        "nmap", "203.0.113.0/28",
        {"stage": "host_discovery", "flags": ["-sn"], "max_rate": 500},
    )]


def test_host_discovery_sweep_zero_targets_is_failure_with_no_hosts(monkeypatch):
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda token, reservation: None)
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "deactivate", lambda token, reservation: None)
    monkeypatch.setattr(raw_nmap.tool_runner, "run", lambda *a, **k: _result(_sn_xml([], total=0)))

    outcome = raw_nmap.execute_host_discovery_sweep(
        "203.0.113.0/28", "signed-lease", reservation_token="slot-token", max_rate=500,
    )

    assert outcome.result["success"] is False
    assert outcome.result["error_reason"] == "zero_targets_scanned"
    assert outcome.live_hosts == []


def test_host_discovery_sweep_empty_range_is_a_successful_zero_host_result(monkeypatch):
    """A quiet range (nmap ran, attempted every host, found none up) is a
    SUCCESSFUL result with zero hosts - not an error, unlike zero_targets."""
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda token, reservation: None)
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "deactivate", lambda token, reservation: None)
    monkeypatch.setattr(
        raw_nmap.tool_runner, "run",
        lambda *a, **k: _result(_sn_xml([], ["203.0.113.1", "203.0.113.2"])),
    )

    outcome = raw_nmap.execute_host_discovery_sweep(
        "203.0.113.0/28", "signed-lease", reservation_token="slot-token", max_rate=500,
    )

    assert outcome.result["success"] is True
    assert outcome.live_hosts == []


def test_host_discovery_activation_failure_never_dispatches_nmap(monkeypatch):
    calls = []
    monkeypatch.setattr(
        raw_nmap.raw_egress_gateway, "activate",
        lambda token, reservation: (_ for _ in ()).throw(RuntimeError("policy installation failed")),
    )
    monkeypatch.setattr(raw_nmap.tool_runner, "run", lambda *args, **kwargs: calls.append(args))

    outcome = raw_nmap.execute_host_discovery_sweep(
        "203.0.113.0/28", "bad-lease", reservation_token="slot-token", max_rate=500,
    )

    assert outcome.result["success"] is False
    assert outcome.result["error_reason"] == "raw_egress_activation_or_dispatch_failed"
    assert outcome.live_hosts == []
    assert calls == []


def test_host_discovery_revoke_failure_is_not_a_clean_sweep(monkeypatch):
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda token, reservation: None)
    monkeypatch.setattr(
        raw_nmap.raw_egress_gateway, "deactivate",
        lambda token, reservation: (_ for _ in ()).throw(RuntimeError("gateway unavailable")),
    )
    monkeypatch.setattr(raw_nmap.tool_runner, "run", lambda *a, **k: _result(_sn_xml(["203.0.113.1"])))

    outcome = raw_nmap.execute_host_discovery_sweep(
        "203.0.113.0/28", "signed-lease", reservation_token="slot-token", max_rate=500,
    )

    assert outcome.result["success"] is False
    assert outcome.result["error_reason"] == "raw_egress_revoke_failed"
    # REQ-CIDRDISC-002: the revoke failure must not discard hosts the sweep
    # actually found before the revoke itself failed.
    assert outcome.live_hosts == ["203.0.113.1"]


def test_udp_all_ambiguous_is_not_reported_as_clean(monkeypatch):
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "activate", lambda token, reservation: None)
    monkeypatch.setattr(raw_nmap.raw_egress_gateway, "deactivate", lambda token, reservation: None)
    monkeypatch.setattr(
        raw_nmap.tool_runner, "run",
        lambda *args, **kwargs: _result(_xml([(53, "domain", "")], protocol="udp", state="open|filtered")),
    )
    outcome = raw_nmap.execute_targeted_udp_scan(
        "192.0.2.10", "udp-lease", reservation_token="slot-token", max_rate=100,
    )
    assert outcome.result["success"] is False
    assert outcome.result["error_reason"] == "udp_results_ambiguous"
    assert outcome.state_counts == {"open|filtered": 1}
