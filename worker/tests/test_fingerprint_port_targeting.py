"""TC-FIDELITY-003: httpx/nikto/wafw00f/testssl/nuclei target the engagement's
configured single non-default port instead of an implicit 443; a full/multi-
port envelope (the common case) leaves current behavior unchanged."""

from __future__ import annotations

from app.tasks import fingerprint


# --- _single_port_from_envelope / _target_url (pure helpers) ---------------

def test_single_custom_port_is_detected():
    assert fingerprint._single_port_from_envelope({"tcp_port_from": 4280, "tcp_port_to": 4280}) == 4280


def test_full_range_envelope_yields_no_single_port():
    assert fingerprint._single_port_from_envelope({"tcp_port_from": 1, "tcp_port_to": 65535}) is None


def test_multi_port_envelope_yields_no_single_port():
    assert fingerprint._single_port_from_envelope({"tcp_port_from": 80, "tcp_port_to": 443}) is None


def test_explicit_default_port_443_yields_no_single_port():
    assert fingerprint._single_port_from_envelope({"tcp_port_from": 443, "tcp_port_to": 443}) is None


def test_explicit_default_port_80_yields_no_single_port():
    assert fingerprint._single_port_from_envelope({"tcp_port_from": 80, "tcp_port_to": 80}) is None


def test_target_url_appends_custom_port():
    assert fingerprint._target_url("host.example.com", 4280) == "https://host.example.com:4280"


def test_target_url_defaults_to_443_without_single_port():
    assert fingerprint._target_url("host.example.com", None) == "https://host.example.com"


def test_target_url_leaves_an_existing_scheme_untouched():
    assert fingerprint._target_url("https://host.example.com:8443", 4280) == "https://host.example.com:8443"


# --- Wiring: run() fetches the envelope and threads single_port through ----

def test_http_probe_targets_the_configured_port(monkeypatch):
    # REQ-FIDELITY-003/010: httpx gets an explicit http:// target, which it
    # self-corrects to https when needed - see target_envelope.httpx_target's
    # docstring for why a schemeless target (tried first, 2026-08-03) was
    # wrong: found live it never even probes https on a non-standard port.
    calls = []
    added_services = []
    monkeypatch.setattr(fingerprint.client, "add_service", lambda *a, **k: added_services.append(k) or {"id": "svc-1"})
    monkeypatch.setattr(fingerprint, "parse_httpx_json", lambda stdout: [
        {"port": None, "webserver": "nginx", "tech": [], "title": "", "status_code": 200, "url": "http://host.example.com:4280/"},
    ])

    def fake_run(tool, target, args, scan_run_id=None, engagement_id=None):
        calls.append((tool, target))
        return {"success": True, "stdout": "irrelevant"}

    monkeypatch.setattr(fingerprint.tool_runner, "run", fake_run)
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    recorded = []
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k))

    fingerprint._http_probe("11111111-1111-1111-1111-111111111111", "asset-1", "host.example.com", "run-1", single_port=4280)

    assert calls == [("httpx", "http://host.example.com:4280")]
    assert recorded[0]["port_range"] == "4280"
    # the service is recorded with the scheme httpx ACTUALLY used (http here),
    # not a hardcoded "https" - the bug this fix corrects.
    assert added_services[0]["protocol"] == "http"


def test_http_probe_defaults_to_443_when_no_single_port(monkeypatch):
    calls = []
    monkeypatch.setattr(fingerprint.client, "add_service", lambda *a, **k: {"id": "svc-1"})
    monkeypatch.setattr(fingerprint, "parse_httpx_json", lambda stdout: [])

    def fake_run(tool, target, args, scan_run_id=None, engagement_id=None):
        calls.append((tool, target))
        return {"success": True, "stdout": ""}

    monkeypatch.setattr(fingerprint.tool_runner, "run", fake_run)
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)

    fingerprint._http_probe("11111111-1111-1111-1111-111111111111", "asset-1", "host.example.com", "run-1", single_port=None)

    assert calls == [("httpx", "http://host.example.com")]


def test_http_probe_records_https_when_that_is_what_httpx_actually_used(monkeypatch):
    # the common case (a real HTTPS service) must still be recorded correctly
    # - this fix must not flip the default, only stop assuming it blindly.
    added_services = []
    monkeypatch.setattr(fingerprint.client, "add_service", lambda *a, **k: added_services.append(k) or {"id": "svc-1"})
    monkeypatch.setattr(fingerprint, "parse_httpx_json", lambda stdout: [
        {"port": None, "webserver": "nginx", "tech": [], "title": "", "status_code": 200, "url": "https://host.example.com:4280/"},
    ])
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": "irrelevant"})
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)

    fingerprint._http_probe("11111111-1111-1111-1111-111111111111", "asset-1", "host.example.com", "run-1", single_port=4280)

    assert added_services[0]["protocol"] == "https"


def test_run_fetches_envelope_and_threads_single_port_to_all_web_tools(monkeypatch):
    from tests import plan_fakes

    store = plan_fakes.install(monkeypatch, fingerprint.client)
    monkeypatch.setattr(fingerprint.client, "materialize_dns", lambda eid, scan_run_id=None: {
        "resolved": [{"hostname": "host.example.com", "ip_address": "192.0.2.10"}]})
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: {"tcp_port_from": 4280, "tcp_port_to": 4280})
    monkeypatch.setattr(fingerprint, "_nmap_scan", lambda *a, **k: ([], False))
    monkeypatch.setattr(fingerprint.client, "is_cancel_requested", lambda run_id: False)

    seen_ports = {}
    # REQ-FIDELITY-009: also capture the confirmed protocol each web tool
    # receives, so this test proves BOTH the port and the scheme are threaded.
    seen_protocols = {}

    def fake_http_probe(engagement_id, asset_id, host, scan_run_id, single_port=None):
        seen_ports["http_probe"] = single_port
        # httpx reports the URL it actually reached the target with; a plain-HTTP
        # service on a non-standard port is exactly the case that used to break.
        return {"port": single_port, "asset_id": asset_id, "url": f"http://host:{single_port}"}

    def fake_header_findings(engagement_id, asset_id, host, live, single_port=None, confirmed_protocol=None):
        seen_ports["header_findings"] = single_port
        seen_protocols["header_findings"] = confirmed_protocol

    def fake_waf_detect(engagement_id, asset_id, host, scan_run_id, single_port=None, confirmed_protocol=None):
        seen_ports["waf_detect"] = single_port
        seen_protocols["waf_detect"] = confirmed_protocol

    def fake_nuclei_pass(engagement_id, asset_id, host, url, args, scan_run_id, single_port, budget_s=None):
        seen_ports.setdefault("nuclei", set()).add(single_port)
        seen_protocols.setdefault("nuclei", set()).add(url.split("://", 1)[0])

    def fake_content_discovery(engagement_id, asset_id, host, scan_run_id, single_port=None, confirmed_protocol=None):
        seen_ports["content_discovery"] = single_port
        seen_protocols["content_discovery"] = confirmed_protocol

    monkeypatch.setattr(fingerprint, "_http_probe", fake_http_probe)
    monkeypatch.setattr(fingerprint, "_header_findings", fake_header_findings)
    monkeypatch.setattr(fingerprint, "_waf_detect", fake_waf_detect)
    monkeypatch.setattr(fingerprint, "_tls_scan", lambda *a, **k: pytest.fail("plain HTTP is never planned for testssl"))
    monkeypatch.setattr(fingerprint, "_nuclei_pass", fake_nuclei_pass)
    monkeypatch.setattr(fingerprint, "_content_discovery", fake_content_discovery)

    fingerprint.run(
        "11111111-1111-1111-1111-111111111111",
        [{"asset_id": "asset-1", "value": "host.example.com"}],
        scan_run_id="11111111-2222-3333-4444-555555555555",
    )

    assert seen_ports == {
        "http_probe": 4280, "header_findings": 4280, "waf_detect": 4280,
        "nuclei": {4280}, "content_discovery": 4280,
    }
    # REQ-FIDELITY-009: httpx confirmed plain HTTP above, so every web tool must
    # be told that - not left to the blanket https:// default that silently
    # produced zero results against such a target.
    assert seen_protocols == {
        "header_findings": "http", "waf_detect": "http", "nuclei": {"http"}, "content_discovery": "http",
    }
    # ...and there is no TLS layer to be missing versions from: testssl is planned as skipped, not run.
    assert store.check("host.example.com", "testssl") ["state"] == "skipped"
    assert store.check("host.example.com", "testssl")["reason"] == "not_a_tls_service"


def test_run_resolves_the_envelope_per_host_not_once_for_the_whole_engagement(monkeypatch):
    """REQ-PORTSCOPE-004: two targets in the same engagement can have
    different per-target port overrides - the single_port passed to each
    target's own web tools must reflect ITS range, not a value fetched once
    up front for the whole run."""
    from tests import plan_fakes

    plan_fakes.install(monkeypatch, fingerprint.client)
    monkeypatch.setattr(fingerprint.client, "materialize_dns", lambda eid, scan_run_id=None: {
        "resolved": [{"hostname": "a.example.com", "ip_address": "192.0.2.10"},
                     {"hostname": "b.example.com", "ip_address": "192.0.2.11"}]})
    monkeypatch.setattr(fingerprint, "_nmap_scan", lambda *a, **k: ([], False))
    monkeypatch.setattr(fingerprint.client, "is_cancel_requested", lambda run_id: False)

    envelope_calls = []

    def fake_get_scan_envelope(eid, host=None):
        envelope_calls.append(host)
        return {"a.example.com": {"tcp_port_from": 4280, "tcp_port_to": 4280},
                "b.example.com": {"tcp_port_from": 9443, "tcp_port_to": 9443}}[host]

    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", fake_get_scan_envelope)

    seen_ports = {}

    def fake_http_probe(engagement_id, asset_id, host, scan_run_id, single_port=None):
        seen_ports[host] = single_port
        return {"port": single_port, "asset_id": asset_id, "url": f"https://host:{single_port}"}

    for name in ("_header_findings", "_waf_detect", "_tls_scan", "_nuclei_pass", "_content_discovery"):
        monkeypatch.setattr(fingerprint, name, lambda *a, **k: None)
    monkeypatch.setattr(fingerprint, "_http_probe", fake_http_probe)

    fingerprint.run(
        "11111111-1111-1111-1111-111111111111",
        [{"asset_id": "asset-1", "value": "a.example.com"}, {"asset_id": "asset-2", "value": "b.example.com"}],
        scan_run_id="11111111-2222-3333-4444-555555555555",
    )

    assert envelope_calls == ["a.example.com", "b.example.com"]
    assert seen_ports == {"a.example.com": 4280, "b.example.com": 9443}


# --- _tls_scan confirmed_protocol gating: fixed 2026-08-03. Found live: a
# confirmed plain-HTTP service on a non-standard port got "TLS 1.2/1.3 not
# offered" findings from testssl - true, but meaningless noise (there is no
# TLS layer to be missing versions from). ---

def test_tls_scan_skips_testssl_when_httpx_confirmed_plain_http(monkeypatch):
    calls = []
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: calls.append(a) or {"success": True, "stdout": ""})
    recorded = []
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k))
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})

    fingerprint._tls_scan(
        "11111111-1111-1111-1111-111111111111", "asset-1", "host.example.com", "1.2.3.4", "run-1",
        single_port=18080, confirmed_protocol="http",
    )

    assert calls == []  # testssl never actually ran
    assert recorded[0]["result"]["error_reason"] == "not_a_tls_service"


def test_tls_scan_still_runs_when_httpx_confirmed_https(monkeypatch):
    calls = []
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: calls.append(a) or {"success": True, "stdout": ""})
    monkeypatch.setattr(fingerprint, "parse_testssl_json", lambda stdout: [])
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})

    fingerprint._tls_scan(
        "11111111-1111-1111-1111-111111111111", "asset-1", "host.example.com", "1.2.3.4", "run-1",
        single_port=443, confirmed_protocol="https",
    )

    assert len(calls) == 1  # testssl ran normally


def test_tls_scan_still_runs_when_protocol_unknown(monkeypatch):
    # no regression for existing behavior when the caller has no httpx result
    # to go on (confirmed_protocol=None, the default) - must not skip blind.
    calls = []
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: calls.append(a) or {"success": True, "stdout": ""})
    monkeypatch.setattr(fingerprint, "parse_testssl_json", lambda stdout: [])
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})

    fingerprint._tls_scan(
        "11111111-1111-1111-1111-111111111111", "asset-1", "host.example.com", "1.2.3.4", "run-1",
        single_port=443,
    )

    assert len(calls) == 1


def test_the_confirmed_protocol_decides_whether_testssl_is_planned_and_reaches_it(monkeypatch):
    from app.planner import IndexInfo, Options
    from app.scan_executor import CheckRun

    ctx = fingerprint._RunContext()
    monkeypatch.setattr(fingerprint, "_http_probe", lambda *a, **k: {"url": "http://host.example.com:18080/", "port": 18080})
    _, plain = fingerprint._probe_web_surface(ctx, "eid", "asset-1", "host.example.com", "1.2.3.4", "run-1", 18080, [])
    monkeypatch.setattr(fingerprint, "_http_probe", lambda *a, **k: {"url": "https://host.example.com:8443/", "port": 8443,
                                                                   "status_code": 200, "title": "t"})
    _, tls = fingerprint._probe_web_surface(ctx, "eid", "asset-2", "host2.example.com", "1.2.3.5", "run-1", 8443, [])

    assert plain["scheme"] == "http" and tls["scheme"] == "https"
    plain_row, tls_row = fingerprint._plan_payload([plain, tls], Options(), IndexInfo())
    assert {c["check_id"]: c["state"] for c in plain_row["checks"]}["testssl"] == "skipped"
    assert {c["check_id"]: c["state"] for c in tls_row["checks"]}["testssl"] == "planned"

    seen = {}
    monkeypatch.setattr(fingerprint, "_tls_scan", lambda *a, confirmed_protocol=None, **k: seen.setdefault("protocol", confirmed_protocol))
    run = CheckRun("eid", "run-1", {**tls, "id": "s2"}, {"check_id": "testssl", "tool": "testssl", "args": {}}, {})
    fingerprint.resolve_handler(run.check)(run)
    assert seen["protocol"] == "https"
