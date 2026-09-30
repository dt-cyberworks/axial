"""REQ-SCANQUAL-001..005: discovery breadth and fingerprint tool coverage.

- 001: discovery aggregates multiple passive OSINT sources, fault-isolated.
- 002: nikto runs the non-intrusive broad tuning (123b), not just software-ID.
- 003: web tools cover nmap-discovered HTTP ports, not only 443.
- 004: testssl runs its (non-destructive) vulnerability checks.
- 005: ffuf content discovery runs automatically in the fingerprint baseline.
"""

from __future__ import annotations

import httpx

from app import tool_runner_client as trc
from app.tasks import discovery, fingerprint

EID = "11111111-1111-1111-1111-111111111111"


# --- REQ-SCANQUAL-001: multi-source passive OSINT --------------------------

def test_passive_subdomains_merges_all_sources(monkeypatch):
    monkeypatch.setattr(discovery, "_query_crtsh", lambda d: {"a." + d})
    monkeypatch.setattr(discovery, "_query_certspotter", lambda d: {"b." + d})
    monkeypatch.setattr(discovery, "_query_hackertarget", lambda d: {"c." + d, "a." + d})
    monkeypatch.setattr(discovery, "_PASSIVE_SOURCES",
                        (discovery._query_crtsh, discovery._query_certspotter, discovery._query_hackertarget))
    out = discovery._passive_subdomains("example.com")
    assert out == {"a.example.com", "b.example.com", "c.example.com"}


def test_passive_subdomains_is_fault_isolated(monkeypatch):
    def boom(d):
        raise RuntimeError("source down")
    monkeypatch.setattr(discovery, "_query_crtsh", lambda d: {"good." + d})
    monkeypatch.setattr(discovery, "_query_certspotter", boom)
    monkeypatch.setattr(discovery, "_query_hackertarget", lambda d: {"also." + d})
    monkeypatch.setattr(discovery, "_PASSIVE_SOURCES",
                        (discovery._query_crtsh, discovery._query_certspotter, discovery._query_hackertarget))
    # one source raising must not lose the others or fail discovery
    out = discovery._passive_subdomains("example.com")
    assert out == {"good.example.com", "also.example.com"}


def _resp(payload):
    return httpx.Response(200, json=payload, request=httpx.Request("GET", "https://osint.test"))


def test_certspotter_source_parses_and_scopes(monkeypatch):
    payload = [
        {"dns_names": ["sub1.example.com", "*.wild.example.com"]},
        {"dns_names": ["other.test"]},
    ]
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _resp(payload))
    assert discovery._query_certspotter("example.com") == {"sub1.example.com", "wild.example.com"}


def test_hackertarget_source_parses_csv_and_scopes(monkeypatch):
    csv = "example.com,93.1.1.1\ncloud.example.com,93.1.1.2\nother.test,1.2.3.4\n"
    monkeypatch.setattr(httpx, "get",
                        lambda *a, **k: httpx.Response(200, text=csv, request=httpx.Request("GET", "https://osint.test")))
    assert discovery._query_hackertarget("example.com") == {"example.com", "cloud.example.com"}


def test_hackertarget_rate_limit_message_yields_nothing(monkeypatch):
    msg = "API count exceeded - Increase Quota with Membership"
    monkeypatch.setattr(httpx, "get",
                        lambda *a, **k: httpx.Response(200, text=msg, request=httpx.Request("GET", "https://osint.test")))
    assert discovery._query_hackertarget("example.com") == set()


def test_osint_source_survives_http_error(monkeypatch):
    def raise_http(*a, **k):
        raise httpx.ConnectError("no route")
    monkeypatch.setattr(httpx, "get", raise_http)
    assert discovery._query_certspotter("example.com") == set()
    assert discovery._query_hackertarget("example.com") == set()


# --- REQ-SCANQUAL-002 (superseded by REQ-PIPE-013, johannes 2026-09-29) ------
# The automatic pipeline no longer runs nikto; its removal and the header
# findings that replace it are tested in test_scan_pipeline_v2.py.


# --- REQ-SCANQUAL-003: web tools cover nmap-discovered ports ----------------

def test_web_candidate_ports_keeps_443_and_adds_web_ports():
    svcs = [
        {"port": 8080, "product": "nginx"},
        {"port": 22, "product": "OpenSSH 8.9"},
        {"port": 8443, "product": "Apache httpd"},
    ]
    assert fingerprint._web_candidate_ports(svcs) == [443, 8080, 8443]


def test_web_candidate_ports_never_drops_443_to_the_cap():
    svcs = [{"port": p, "product": "nginx"} for p in (81, 82, 83, 84, 85)]
    ports = fingerprint._web_candidate_ports(svcs)
    assert ports[0] == 443
    assert len(ports) <= fingerprint._WEB_PORT_CAP


def test_run_web_enumerates_each_nmap_web_port_when_window_is_broad(monkeypatch):
    monkeypatch.setattr(fingerprint.client, "materialize_dns", lambda eid, scan_run_id=None: {"resolved": []})
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: {"tcp_port_from": 1, "tcp_port_to": 65535})
    # A real scan of a live HTTPS host reports 443 among its open ports;
    # REQ-FPEFF-003 now derives the candidates from exactly that evidence.
    monkeypatch.setattr(fingerprint, "_nmap_scan",
                        lambda *a, **k: ([{"port": 443, "product": "nginx", "protocol": "tcp"},
                                          {"port": 8080, "product": "nginx", "protocol": "tcp"}], True))

    suite_ports = []
    monkeypatch.setattr(fingerprint, "_probe_web_surface",
                        lambda ctx, eid, aid, host, ip, run, single_port, nmap_services: suite_ports.append(single_port) or (None, None))

    fingerprint.run(EID, [{"asset_id": "asset-1", "value": "host.example.com"}], scan_run_id="run-1")

    # 443 (probe_port None) plus the nmap-discovered 8080.
    assert suite_ports == [None, 8080]


def test_run_single_port_still_pins_all_web_tools_to_that_port(monkeypatch):
    monkeypatch.setattr(fingerprint.client, "materialize_dns", lambda eid, scan_run_id=None: {"resolved": []})
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: {"tcp_port_from": 4280, "tcp_port_to": 4280})
    monkeypatch.setattr(fingerprint, "_nmap_scan",
                        lambda *a, **k: ([{"port": 8080, "product": "nginx", "protocol": "tcp"}], True))

    suite_ports = []
    monkeypatch.setattr(fingerprint, "_probe_web_surface",
                        lambda ctx, eid, aid, host, ip, run, single_port, nmap_services: suite_ports.append(single_port) or (None, None))

    fingerprint.run(EID, [{"asset_id": "asset-1", "value": "host.example.com"}], scan_run_id="run-1")

    # A configured single port pins to exactly that port; nmap ports are ignored.
    assert suite_ports == [4280]


# --- REQ-SCANQUAL-004: testssl vulnerability checks ------------------------

def test_testssl_command_runs_vulnerability_checks():
    cmd = trc._testssl_command("host.example.com", {"ip": "203.0.113.10"})
    assert "--vulnerable" in cmd


# --- REQ-SCANQUAL-005: ffuf content discovery in the fingerprint baseline --

def test_content_discovery_runs_with_quickhits_wordlist(monkeypatch):
    captured = {}

    def fake_run(tool, target, args, scan_run_id=None, engagement_id=None):
        captured["tool"], captured["args"] = tool, args
        return {"success": True, "stdout": ""}

    monkeypatch.setattr(fingerprint.tool_runner, "run", fake_run)
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)

    fingerprint._content_discovery(EID, "aid", "host.example.com", "run-1", single_port=None)

    assert captured["tool"] == "ffuf"
    assert captured["args"] == {"wordlist": "quickhits"}


def test_content_discovery_skipped_when_host_not_live(monkeypatch):
    calls = []
    monkeypatch.setattr(fingerprint.client, "materialize_dns", lambda eid, scan_run_id=None: {
        "resolved": [{"hostname": "host.example.com", "ip_address": "192.0.2.10"}]})
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: {"tcp_port_from": 1, "tcp_port_to": 65535})
    monkeypatch.setattr(fingerprint, "_nmap_scan", lambda *a, **k: ([], False))
    monkeypatch.setattr(fingerprint, "_http_probe", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint.tool_runner, "run",
                        lambda tool, *a, **k: calls.append(tool) or {"success": True, "stdout": ""})

    fingerprint.run(EID, [{"asset_id": "asset-1", "value": "host.example.com"}], scan_run_id="run-1")

    assert "ffuf" not in calls


def test_content_discovery_aggregates_hits_into_one_finding(monkeypatch):
    findings = []
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": "{}"})
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint, "parse_ffuf_json", lambda s: [
        {"word": "admin", "url": "http://host.example.com/admin", "status": 200, "length": 512},
        {"word": ".git/config", "url": "http://host.example.com/.git/config", "status": 200, "length": 45},
    ])
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda eid, **kw: findings.append(kw) or {"id": "f1"})

    fingerprint._content_discovery(EID, "aid", "host.example.com", "run-1", single_port=None)

    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "exposure"
    assert f["confidence"] == "inferred"
    assert len(f["evidence"]["hits"]) == 2
    assert f["evidence"]["wordlist"] == "quickhits"


def test_content_discovery_no_hits_no_finding(monkeypatch):
    findings = []
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": '{"results": []}'})
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda eid, **kw: findings.append(kw) or {"id": "f1"})

    fingerprint._content_discovery(EID, "aid", "host.example.com", "run-1", single_port=None)

    assert findings == []


def test_content_discovery_failure_is_fail_open(monkeypatch):
    findings = []

    def boom(*a, **k):
        raise RuntimeError("tool-runner unreachable")

    monkeypatch.setattr(fingerprint.tool_runner, "run", boom)
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda eid, **kw: findings.append(kw) or {"id": "f1"})

    # must not raise - matches the other four _web_suite siblings' fail-open behavior
    fingerprint._content_discovery(EID, "aid", "host.example.com", "run-1", single_port=None)

    assert findings == []
