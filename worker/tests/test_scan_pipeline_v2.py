"""Evidence-driven scan pipeline, increment 1 (docs/requirements/scan-pipeline.md).

TC-PIPE-001 web_alias, TC-PIPE-004 no network/javascript on web, TC-PIPE-006
honest outcomes, TC-PIPE-007 declared budgets (worker half), TC-PIPE-013 nikto
retired + header findings, TC-PIPE-014 validate phase removed.

trc is always referenced through the module at call time (see the note in
test_tool_invocation_audit.py: test_runner_auth_header reloads it).
"""

from __future__ import annotations

import pytest

from app import httpx_parse, planner, security_headers, surfaces, tool_execution
from app import tool_runner_client as trc
from app.tasks import fingerprint

EID = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
_REAL_RECORD = tool_execution.record  # before any test replaces it


def _raw(**over):
    body = {"stdout": "", "stderr": "", "return_code": 0, "success": True, "timed_out": False, "execution_time": 5.0}
    body.update(over)
    return body


def _runner_returning(monkeypatch, raw: dict, seen: dict | None = None):
    class R:
        def raise_for_status(self):
            return None

        def json(self):
            return raw

    def fake_post(self, path, payload, scan_run_id, budget_s=None):
        if seen is not None:
            seen.update(path=path, payload=payload, budget_s=budget_s)
        return R()

    monkeypatch.setattr(trc.ToolRunnerClient, "_post_cancellable", fake_post)
    return trc.tool_runner


# --- REQ-PIPE-006: honest outcomes -------------------------------------------------

def test_req_pipe_006_a_runner_kill_at_the_budget_is_partial_and_keeps_the_output(monkeypatch):
    runner = _runner_returning(monkeypatch, _raw(stdout='{"template-id":"x"}', return_code=-1, success=True, timed_out=True))
    result = runner.run("nuclei", "https://h.example", {"mode": "select", "group": "generic", "shard": "1/2"})
    assert result["success"] is False
    assert result["error_reason"] == tool_execution.BUDGET_REACHED
    assert result["stdout"] == '{"template-id":"x"}'
    assert tool_execution.outcome_of(result) == "partial"


def test_req_pipe_006_a_tools_own_timeout_exit_124_is_partial_too(monkeypatch):
    runner = _runner_returning(monkeypatch, _raw(return_code=124, success=False))
    result = runner.run("nuclei", "https://h.example", {"mode": "endpoints", "urls": ["https://h.example/a?x=1"]})
    assert result["error_reason"] == tool_execution.BUDGET_REACHED


def test_req_pipe_006_a_self_limiting_tool_that_ran_its_whole_deadline_is_partial(monkeypatch):
    # ffuf -maxtime = budget - margin; it exits 0 when it stops there.
    deadline = trc._inner_deadline_s({"_budget_s": trc.check_budget_s("ffuf")}, 90)
    runner = _runner_returning(monkeypatch, _raw(stdout="{}", execution_time=float(deadline)))
    assert runner.run("ffuf", "https://h.example", {"wordlist": "quickhits"})["error_reason"] == tool_execution.BUDGET_REACHED
    runner = _runner_returning(monkeypatch, _raw(stdout="{}", execution_time=float(deadline) - 30))
    finished = runner.run("ffuf", "https://h.example", {"wordlist": "quickhits"})
    assert finished["success"] is True and tool_execution.outcome_of(finished) == "complete"


def test_req_pipe_006_katana_stopping_at_its_crawl_duration_is_partial(monkeypatch):
    runner = _runner_returning(monkeypatch, _raw(stdout="{}", execution_time=float(trc.KATANA_CRAWL_S)))
    assert runner.run("katana", "https://h.example", {})["error_reason"] == tool_execution.BUDGET_REACHED
    runner = _runner_returning(monkeypatch, _raw(stdout="{}", execution_time=39.0))
    assert runner.run("katana", "https://h.example", {})["success"] is True


def test_req_pipe_006_outcome_vocabulary():
    assert tool_execution.outcome_of({"success": True}) == "complete"
    assert tool_execution.outcome_of({"success": False, "error_reason": "budget_reached"}) == "partial"
    assert tool_execution.outcome_of({"success": False, "error_reason": "nonzero_exit"}) == "failed"
    assert tool_execution.outcome_of({"success": False, "error_reason": "not_a_tls_service"}) == "skipped:not_a_tls_service"
    assert tool_execution.outcome_of(tool_execution.skipped_result("web_alias")) == "skipped:web_alias"


def test_negative_req_pipe_006_a_partial_or_failed_result_never_reads_as_complete():
    for reason in ("budget_reached", "nonzero_exit", "runner_dispatch_failed", "egress_proxy_blocked"):
        assert tool_execution.outcome_of({"success": False, "error_reason": reason}) != "complete"


def test_req_pipe_006_record_stores_the_outcome_and_counts_partial_checks(monkeypatch):
    stored = []
    monkeypatch.setattr(tool_execution.client, "record_tool_execution", lambda *a, **k: stored.append(k))
    tool_execution.clear_coverage(RUN)
    partial = {"success": False, "exit_code": -1, "error_reason": "budget_reached", "stdout": "x"}
    tool_execution.record(EID, scan_run_id=RUN, tool="nuclei", phase="fingerprint", authorized_target="h",
                          resolved_target=None, port_range="443", result=partial)
    tool_execution.record(EID, scan_run_id=RUN, tool="nuclei", phase="fingerprint", authorized_target="h",
                          resolved_target=None, port_range="443", result={"success": True, "exit_code": 0})
    assert [row["outcome_summary"]["outcome"] for row in stored] == ["partial", "complete"]
    assert tool_execution.partial_tools(RUN) == {"nuclei": 1}
    tool_execution.clear_coverage(RUN)


def test_req_pipe_006_a_nuclei_pass_cut_by_its_budget_keeps_its_hits_and_is_recorded_partial(monkeypatch):
    hit = '{"template-id":"t1","info":{"name":"N","severity":"low","classification":{}},"matched-at":"https://h/x","type":"http"}'
    recorded, findings = [], []
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {
        "success": False, "error_reason": "budget_reached", "exit_code": -1, "stdout": hit, "stderr": ""})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k["result"]))
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: findings.append(k))
    fingerprint._nuclei_pass(EID, "asset", "h", "https://h", {"part": "other"}, RUN, None)
    assert len(findings) == 1
    assert tool_execution.outcome_of(recorded[0]) == "partial"


# --- REQ-PIPE-007: declared budgets (worker half) ----------------------------------

def test_req_pipe_007_every_run_sends_its_declared_budget_and_gives_the_http_call_room(monkeypatch):
    seen: dict = {}
    runner = _runner_returning(monkeypatch, _raw(), seen)
    runner.run("testssl", "https://h.example", {"ip": "192.0.2.1"})
    assert seen["budget_s"] == trc.CHECK_BUDGET_S["testssl"]
    runner.run("nuclei", "https://h.example", {"mode": "select", "group": "generic", "shard": "1/2"})
    assert seen["budget_s"] == trc.NUCLEI_BUDGET_S["select"]
    runner.run("nuclei", "https://h.example", {"mode": "select", "group": "generic", "shard": "1/2"}, budget_s=1320)
    assert seen["budget_s"] == 1320
    runner.run("nuclei", "https://h.example", {"mode": "headless"})
    assert seen["budget_s"] == trc.NUCLEI_BUDGET_S["headless"]


def test_req_pipe_007_an_explicit_budget_overrides_the_table_and_is_clamped_to_the_runner_maximum():
    assert trc.check_budget_s("httpx") == trc.CHECK_BUDGET_S["httpx"]
    assert trc.check_budget_s("httpx", override=120) == 120
    assert trc.check_budget_s("httpx", override=10**7) == trc.RUNNER_MAX_BUDGET_S == 1800
    assert trc.check_budget_s("some-unlisted-tool") == trc.RUNNER_DEFAULT_BUDGET_S


def test_negative_req_pipe_007_no_declared_budget_exceeds_the_runner_maximum():
    for tool in trc.CHECK_BUDGET_S:
        assert 0 < trc.check_budget_s(tool) <= trc.RUNNER_MAX_BUDGET_S
    for mode in trc.NUCLEI_BUDGET_S:
        assert 0 < trc.check_budget_s("nuclei", {"mode": mode}) <= trc.RUNNER_MAX_BUDGET_S


def test_req_pipe_007_the_http_request_carries_the_header_and_a_read_timeout_above_the_budget(monkeypatch):
    sent = {}

    class _Client:
        def post(self, path, json=None, headers=None, timeout=None):
            sent.update(path=path, headers=headers, timeout=timeout)
            raise RuntimeError("stop here")

    runner = trc.ToolRunnerClient()
    runner._client = _Client()
    with pytest.raises(RuntimeError):
        runner._post_cancellable("/api/command", {"command": "true"}, None, 240)
    assert sent["headers"][trc.BUDGET_HEADER] == "240"
    assert sent["timeout"] == 270.0


def test_req_pipe_007_inner_tool_deadlines_follow_the_budget_minus_a_margin():
    args = {"_budget_s": 900, "urls": ["https://h.example/a?x=1"], "mode": "endpoints"}
    assert "timeout 880 nuclei" in trc._nuclei_command("https://h.example", args)
    assert " -maxtime 220 " in trc._ffuf_command("https://h.example", {"_budget_s": 240, "wordlist": "quickhits"}) + " "
    # No budget passed (legacy callers): the historical defaults still apply.
    assert "timeout 200 " in trc._katana_command("https://h.example", {})


# --- REQ-PIPE-013: nikto retired, header findings from httpx -------------------------

_FULL = {
    "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer",
}


def test_req_pipe_013_all_five_headers_present_yields_no_finding():
    assert security_headers.missing_security_headers(_FULL, scheme="https", status_code=200) == []


def test_req_pipe_013_each_missing_header_is_reported():
    for name in security_headers.CHECKED_HEADERS:
        headers = {k: v for k, v in _FULL.items() if k != name}
        assert security_headers.missing_security_headers(headers, scheme="https", status_code=200) == [name]


def test_req_pipe_013_frame_ancestors_satisfies_x_frame_options():
    headers = {**_FULL, "content-security-policy": "frame-ancestors 'none'"}
    del headers["x-frame-options"]
    assert security_headers.missing_security_headers(headers, scheme="https", status_code=200) == []


def test_req_pipe_013_hsts_is_only_judged_over_https():
    headers = {k: v for k, v in _FULL.items() if k != "strict-transport-security"}
    assert security_headers.missing_security_headers(headers, scheme="http", status_code=200) == []
    assert security_headers.missing_security_headers(headers, scheme="https", status_code=200) == ["strict-transport-security"]


def test_negative_req_pipe_013_a_redirect_or_a_response_without_recorded_headers_is_not_judged():
    assert security_headers.missing_security_headers({}, scheme="https", status_code=200) is None
    assert security_headers.missing_security_headers({"server": "nginx"}, scheme="https", status_code=301) is None
    assert security_headers.missing_security_headers({"server": "nginx"}, scheme="https", status_code=308) is None


def test_req_pipe_013_the_finding_matches_what_nikto_produced_and_costs_no_request(monkeypatch):
    findings = []
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: pytest.fail("no request to the target"))
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: findings.append(k))
    live = {"status_code": 200, "headers": {"server": "nginx"}, "service_id": "svc-1"}
    fingerprint._header_findings(EID, "asset", "h.example", live, None, confirmed_protocol="https")
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == ("Missing security headers: strict-transport-security, content-security-policy, "
                          "x-content-type-options, x-frame-options, referrer-policy")
    assert f["category"] == "misconfig" and f["confidence"] == "validated" and f["service_id"] == "svc-1"
    assert f["evidence"]["tool"] == "httpx" and f["evidence"]["port"] == 443


def test_negative_req_pipe_013_a_complete_header_set_or_unjudgeable_response_adds_no_finding(monkeypatch):
    findings = []
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: findings.append(k))
    fingerprint._header_findings(EID, "a", "h", {"status_code": 200, "headers": _FULL}, None, "https")
    fingerprint._header_findings(EID, "a", "h", {"status_code": 301, "headers": {"server": "x"}}, None, "https")
    fingerprint._header_findings(EID, "a", "h", {"status_code": 200}, None, "https")
    assert findings == []


def test_req_pipe_013_no_scan_step_runs_nikto(monkeypatch):
    from tests import plan_fakes

    store = plan_fakes.install(monkeypatch, fingerprint.client)
    ran: list[str] = []
    monkeypatch.setattr(fingerprint.client, "materialize_dns", lambda eid, scan_run_id=None: {
        "resolved": [{"hostname": "h.example", "ip_address": "192.0.2.1"}]})
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: {"tcp_port_from": 443, "tcp_port_to": 443})
    monkeypatch.setattr(fingerprint.client, "get_discovery_options",
                        lambda eid: {"subfinder": True, "crawling": False, "oob": False, "screenshots": False})
    monkeypatch.setattr(fingerprint.client, "is_cancel_requested", lambda run_id: False)
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: {"id": "f"})
    monkeypatch.setattr(fingerprint.client, "authorize", lambda eid, call: ran.append(call["tool"]) or {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint, "_nmap_scan", lambda *a, **k: ([], False))
    monkeypatch.setattr(fingerprint, "_http_probe", lambda *a, **k: {
        "url": "https://h.example", "status_code": 200, "headers": _FULL, "port": 443, "service_id": "s1"})
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda tool, *a, **k: ran.append("run:" + tool) or {
        "success": True, "stdout": "", "exit_code": 0})
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    assert ran, "the scan still runs its other tools"
    assert not [t for t in ran if "nikto" in t], ran
    assert "nikto" not in {c["tool"] for c in store.checks.values()}
    assert not hasattr(fingerprint, "_web_enum")


def test_req_pipe_013_httpx_output_carries_normalized_headers_and_the_redirect_target():
    line = ('{"url":"http://h.example","input":"http://h.example","status_code":301,"location":"https://h.example/",'
            '"header":{"strict_transport_security":"max-age=1","X_Frame_Options":"DENY","set_cookie":["a=1","b=2"]}}')
    row = httpx_parse.parse_httpx_json(line)[0]
    assert row["headers"]["strict-transport-security"] == "max-age=1"
    assert row["headers"]["x-frame-options"] == "DENY"
    assert row["headers"]["set-cookie"] == "a=1, b=2"
    assert row["location"] == "https://h.example/"


# --- REQ-PIPE-001/003: a redirect-only port is an alias ------------------------------

def test_req_pipe_001_http_redirecting_to_the_live_https_surface_is_an_alias():
    assert surfaces.redirect_alias_port(301, "https://h.example/", "h.example", 80, {443}) == 443
    assert surfaces.redirect_alias_port(308, "HTTPS://H.Example:8443/x", "h.example", 80, {8443}) == 8443
    assert surfaces.redirect_alias_port(302, "https://h.example./", "h.example", 80, {443}) == 443


def test_negative_req_pipe_001_anything_unclear_stays_a_full_surface():
    live = {443}
    assert surfaces.redirect_alias_port(200, "https://h.example/", "h.example", 80, live) is None      # not a redirect
    assert surfaces.redirect_alias_port(301, "/login", "h.example", 80, live) is None                  # relative
    assert surfaces.redirect_alias_port(301, "https://www.h.example/", "h.example", 80, live) is None  # other host
    assert surfaces.redirect_alias_port(301, "https://h.example/", "h.example", 80, set()) is None      # target not live
    assert surfaces.redirect_alias_port(301, "http://h.example/x", "h.example", 80, {80}) is None       # same surface
    assert surfaces.redirect_alias_port(301, "ftp://h.example/", "h.example", 80, live) is None
    assert surfaces.redirect_alias_port(301, "", "h.example", 80, live) is None
    assert surfaces.redirect_alias_port(301, "https://h.example:notaport/", "h.example", 80, live) is None
    assert surfaces.redirect_alias_port("x", "https://h.example/", "h.example", 80, live) is None


def _http_redirect():
    return {"url": "http://h.example", "status_code": 301, "location": "https://h.example/",
            "headers": {"server": "nginx"}, "service_id": "s80"}


def _https_app():
    return {"url": "https://h.example", "status_code": 200, "headers": _FULL, "service_id": "s443",
            "webserver": "nginx", "title": "app", "content_length": 5}


def _surfaces(monkeypatch, probes: dict, ports, options=None):
    """Probe `ports` (None = 443) of h.example in order and return their plan rows by port."""
    from app.planner import IndexInfo, Options

    monkeypatch.setattr(fingerprint, "_http_probe", lambda eid, aid, host, run, port=None: probes[port])
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    ctx = fingerprint._RunContext()
    rows = []
    for port in ports:
        _, surface = fingerprint._probe_web_surface(ctx, EID, "a", "h.example", "192.0.2.1", RUN, port, [])
        if surface is not None:
            rows.append(surface)
    opts = options or Options(crawling=True, screenshots=True)
    return {row["port"]: row for row in fingerprint._plan_payload(rows, opts, IndexInfo())}


def test_req_pipe_003_port_80_redirecting_to_scanned_443_gets_no_deep_checks_and_says_why(monkeypatch):
    rows = _surfaces(monkeypatch, {None: _https_app(), 80: _http_redirect()}, [None, 80])
    assert rows[443]["service_class"] == "web" and rows[80]["service_class"] == "web_alias"
    assert rows[80]["alias_of"] == "h.example:443"
    checks = {c["check_id"]: c for c in rows[80]["checks"]}
    assert not [c for c in checks.values() if c["state"] == "planned"], "the alias runs no check of its own"
    for check_id in ("wafw00f", "testssl", "header_findings", "ffuf", "screenshot", "katana", "nuclei"):
        assert checks[check_id]["state"] == "skipped"
        assert checks[check_id]["reason"] == "web_alias_of:h.example:443"
    assert [c for c in rows[443]["checks"] if c["state"] == "planned" and c["tool"] == "nuclei"], "the target gets them once"


def test_negative_req_pipe_003_a_redirect_to_a_surface_not_scanned_in_this_run_is_scanned_fully(monkeypatch):
    rows = _surfaces(monkeypatch, {80: _http_redirect()}, [80])
    assert rows[80]["service_class"] == "web"
    planned = {c["check_id"] for c in rows[80]["checks"] if c["state"] == "planned"}
    assert {"ffuf", "nuclei:tech", "nuclei:headless"} <= planned


def test_negative_req_pipe_003_a_normal_port_80_application_is_scanned_fully(monkeypatch):
    app80 = {**_https_app(), "url": "http://h.example", "content_length": 6}
    rows = _surfaces(monkeypatch, {None: _https_app(), 80: app80}, [None, 80])
    assert rows[80]["service_class"] == "web"
    assert "nuclei:tech" in {c["check_id"] for c in rows[80]["checks"] if c["state"] == "planned"}


# --- REQ-PIPE-001/002/004/008: discovery -> plan -> execution through the fingerprint phase ---------------

_OPEN_443 = [{"port": 443, "protocol": "tcp", "service_name": "https", "product": "", "product_name": None}]


def _install_run(monkeypatch, *, probe=None, nmap_services=None, options=None):
    from tests import plan_fakes

    store = plan_fakes.install(monkeypatch, fingerprint.client)
    monkeypatch.setattr(fingerprint.client, "materialize_dns", lambda eid, scan_run_id=None: {
        "resolved": [{"hostname": "h.example", "ip_address": "192.0.2.1"}]})
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: {"tcp_port_from": 1, "tcp_port_to": 65535})
    monkeypatch.setattr(fingerprint.client, "get_discovery_options", lambda eid: options or {
        "subfinder": True, "crawling": False, "oob": False, "screenshots": False})
    monkeypatch.setattr(fingerprint.client, "is_cancel_requested", lambda run_id: False)
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: {"id": "f"})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint, "_nmap_scan",
                        lambda *a, **k: (list(_OPEN_443 if nmap_services is None else nmap_services), True))
    monkeypatch.setattr(fingerprint, "_http_probe", probe or (lambda *a, **k: None))
    return store


def _app_probe(**over):
    live = {"url": "https://h.example", "status_code": 200, "headers": {"server": "nginx"}, "port": 443, "service_id": "s1",
            "tech": ["Nextcloud", "Nginx", "PHP", "HSTS"], "webserver": "nginx", "title": "app", "content_length": 5}
    live.update(over)
    return lambda *a, **k: dict(live)


def test_req_pipe_001_every_open_port_becomes_one_classified_surface(monkeypatch):
    nmap = [
        {"port": 443, "protocol": "tcp", "service_name": "https", "product": "nginx", "product_name": "nginx", "version": "1.25.3"},
        {"port": 25, "protocol": "tcp", "service_name": "smtp", "product": "Postfix smtpd", "product_name": "Postfix smtpd"},
        {"port": 993, "protocol": "tcp", "service_name": "imaps", "product": "Dovecot imapd"},
        {"port": 22, "protocol": "tcp", "service_name": "ssh", "product": "OpenSSH 9.6"},
        {"port": 9999, "protocol": "tcp", "service_name": "unknown", "product": "unknown"},
        {"port": 53, "protocol": "udp", "service_name": "domain", "product": "dns"},
    ]
    store = _install_run(monkeypatch, probe=_app_probe(), nmap_services=nmap)
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": "", "exit_code": 0})
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    classes = {s["port"]: s["service_class"] for s in store.surfaces.values()}
    assert classes == {443: "web", 25: "tls_service", 993: "tls_service", 22: "service", 9999: "unknown"}, "UDP is not a surface"


def test_negative_req_pipe_001_a_port_nmap_proved_closed_never_becomes_a_surface(monkeypatch):
    store = _install_run(monkeypatch, probe=_app_probe(), nmap_services=[
        {"port": 8080, "protocol": "tcp", "service_name": "http-proxy", "product": "nginx"}])
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": "", "exit_code": 0})
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    # A successful scan found only 8080 open: 443 is not probed, so it is not a surface.
    assert {s["port"] for s in store.surfaces.values()} == {8080}


def test_req_pipe_002_the_surface_stores_its_profile_and_no_session_headers(monkeypatch):
    nmap = [{"port": 443, "protocol": "tcp", "service_name": "https", "product": "nginx", "product_name": "nginx", "version": "1.25.3"}]
    store = _install_run(monkeypatch, probe=_app_probe(headers={"server": "nginx", "set_cookie": "sid=secret", "Set-Cookie": "x=y"}),
                         nmap_services=nmap)
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": "", "exit_code": 0})
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    surface = next(iter(store.surfaces.values()))
    assert surface["profile"][:1] == ["nginx@1.25.3"] and "nextcloud" in surface["profile"] and "php" in surface["profile"]
    assert "hsts" not in surface["profile"], "noise is not a technology"
    assert "set-cookie" not in surface["fingerprint"]["headers"] and "set_cookie" not in surface["fingerprint"]["headers"]


def test_req_pipe_004_the_product_check_follows_the_profile_the_technology_check_left(monkeypatch):
    store = _install_run(monkeypatch, probe=_app_probe(tech=["Nginx"], webserver="nginx"))
    calls: list[tuple[str, dict]] = []
    counts = {"products": 12, "generic": 400}
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})

    def fake_run(tool, url, args, scan_run_id=None, engagement_id=None, **kw):
        calls.append((args.get("mode"), dict(args)))
        if args.get("mode") == "tech":
            return {"success": True, "exit_code": 0, "stderr": "", "stdout":
                    '{"template-id":"nextcloud-detect","info":{"metadata":{"vendor":"nextcloud","product":"nextcloud_server"}}}'}
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(fingerprint.tool_runner, "run", fake_run)
    monkeypatch.setattr(fingerprint.tool_runner, "nuclei_selection_count",
                        lambda selection: counts["products" if selection["group"] == "products" else "generic"])
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    products = next(a for m, a in calls if m == "select" and a["group"] == "products")
    assert products["products"] == ["nginx", "nextcloud_server", "nextcloud"], "the technology check's finds are used"
    row = store.check("h.example", "nuclei:products")
    assert row["state"] == "complete" and row["reason"] == "product:nginx,nextcloud_server,nextcloud"
    assert row["outcome_summary"]["templates"] == 12 and row["budget_s"] == trc.nuclei_select_budget_s(12)
    assert row["args"]["from_profile"] is True and row["args"]["products"] == products["products"]


def test_req_pipe_004_an_empty_profile_runs_the_common_products_and_says_so(monkeypatch):
    store = _install_run(monkeypatch, probe=_app_probe(tech=[], webserver="", headers={}))
    seen = []
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_runner, "run",
                        lambda tool, url, args, **k: seen.append(args) or {"success": True, "exit_code": 0, "stdout": "", "stderr": ""})
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    products = next(a for a in seen if a.get("group") == "products")
    assert products["products"] == list(planner.COMMON_PRODUCTS)
    assert store.check("h.example", "nuclei:products")["reason"] == "no_product_identified:common_products"


def test_req_pipe_004_a_selection_that_matches_no_template_is_skipped_not_run(monkeypatch):
    store = _install_run(monkeypatch, probe=_app_probe())
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    ran = []
    monkeypatch.setattr(fingerprint.tool_runner, "run",
                        lambda tool, url, args, **k: ran.append(args.get("group")) or {"success": True, "exit_code": 0, "stdout": "", "stderr": ""})
    monkeypatch.setattr(fingerprint.tool_runner, "nuclei_selection_count", lambda selection: 0)
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    assert "products" not in ran and "generic" not in ran
    assert store.check("h.example", "nuclei:products")["state"] == "skipped"
    assert store.check("h.example", "nuclei:products")["reason"] == "no_matching_templates"


def test_req_pipe_004_an_unreadable_index_fails_the_check_honestly_never_clean(monkeypatch):
    store = _install_run(monkeypatch, probe=_app_probe())
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "exit_code": 0, "stdout": "", "stderr": ""})

    def broken(selection):
        raise RuntimeError("index missing")

    monkeypatch.setattr(fingerprint.tool_runner, "nuclei_selection_count", broken)
    monkeypatch.setattr(fingerprint.tool_execution, "record", _REAL_RECORD)  # feed the check collector
    monkeypatch.setattr(tool_execution.client, "record_tool_execution", lambda *a, **k: None)
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    assert store.check("h.example", "nuclei:products")["state"] == "failed"
    assert store.check("h.example", "nuclei:generic:1of5")["state"] == "failed"


def test_req_pipe_004_the_plan_falls_back_to_measured_counts_when_the_runner_cannot_answer(monkeypatch):
    def unreachable():
        raise RuntimeError("runner down")

    monkeypatch.setattr(fingerprint.tool_runner, "nuclei_index_summary", unreachable)
    info = fingerprint._index_info()
    assert (info.generic, info.total, info.known) == (planner.FALLBACK_GENERIC_TEMPLATES, planner.FALLBACK_ALL_TEMPLATES, False)


def test_req_pipe_008_a_resumed_run_continues_the_stored_plan_without_scanning_again(monkeypatch):
    store = _install_run(monkeypatch, probe=_app_probe())
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "exit_code": 0, "stdout": "", "stderr": ""})
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    assert store.checkpoint["fp_services"], "the services are stored for a resume"
    # The worker dies part-way: some checks are finished, one was running, the rest not started.
    order = sorted(store.checks.values(), key=lambda c: c["seq"])
    for check in order[:4]:
        check["state"] = "complete"
    order[4]["state"] = "running"
    for check in order[5:]:
        check["state"] = "planned"
    finished_ids = {c["id"] for c in order[:4]}

    monkeypatch.setattr(fingerprint, "_discover_surfaces", lambda *a, **k: pytest.fail("discovery must not repeat"))
    ran = []
    monkeypatch.setattr(fingerprint, "resolve_handler", lambda check: (lambda r: ran.append(r.check["id"])))
    services = fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN,
                               resume_services=store.checkpoint["fp_services"])
    assert services == store.checkpoint["fp_services"]
    assert not finished_ids & set(ran), "a finished check never runs again"
    assert order[4]["id"] in ran and {c["id"] for c in order[5:]} <= set(ran)


def test_req_pipe_008_a_resume_without_a_stored_plan_discovers_again(monkeypatch):
    store = _install_run(monkeypatch, probe=_app_probe())
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "exit_code": 0, "stdout": "", "stderr": ""})
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN, resume_services=[{"stale": True}])
    assert store.surfaces, "no plan existed, so the phase started from the beginning"


def test_req_pipe_005_the_engagements_scan_depth_reaches_the_plan(monkeypatch):
    store = _install_run(monkeypatch, probe=_app_probe())
    monkeypatch.setattr(fingerprint.client, "get_scan_settings", lambda eid: {"scan_profile": "thorough", "max_parallel_checks": 1})
    monkeypatch.setattr(fingerprint.scan_executor, "execute_plan", lambda **k: None)
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    ids = set(store.states("h.example"))
    assert any(i.startswith("nuclei:all:") for i in ids)
    assert not any(i.startswith(("nuclei:generic:", "nuclei:products")) for i in ids)


def test_req_pipe_015_the_engagements_parallel_limit_reaches_the_executor(monkeypatch):
    _install_run(monkeypatch, probe=_app_probe())
    monkeypatch.setattr(fingerprint.client, "get_scan_settings", lambda eid: {"scan_profile": "standard", "max_parallel_checks": 1})
    seen = {}
    monkeypatch.setattr(fingerprint.scan_executor, "execute_plan", lambda **k: seen.update(k))
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    assert seen["max_parallel"] == 1


def test_req_pipe_015_settings_fail_toward_one_check_and_standard_depth(monkeypatch):
    from app.control_plane_client import ControlPlaneClient
    import httpx

    c = ControlPlaneClient(base_url="http://cp")
    c._client = httpx.Client(base_url="http://cp", transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    assert c.get_scan_settings(EID) == {"scan_profile": "standard", "max_parallel_checks": 1, "disabled_tools": []}
    c._client = httpx.Client(base_url="http://cp", transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"scan_profile": "bogus", "max_parallel_checks": 99,
                                            "disabled_tools": ["testssl", 7, None, "ffuf"]})))
    assert c.get_scan_settings(EID) == {"scan_profile": "standard", "max_parallel_checks": 2,
                                        "disabled_tools": ["testssl", "ffuf"]}


def test_req_pipe_006_the_run_warning_names_partial_checks(monkeypatch):
    from app.tasks import pipeline

    monkeypatch.setattr(tool_execution.client, "record_tool_execution", lambda *a, **k: None)
    tool_execution.clear_coverage(RUN)
    tool_execution.record(EID, scan_run_id=RUN, tool="nuclei", phase="fingerprint", authorized_target="h", resolved_target=None,
                          port_range="443", result={"success": False, "error_reason": "budget_reached", "exit_code": -1})
    tool_execution.record(EID, scan_run_id=RUN, tool="nuclei", phase="fingerprint", authorized_target="h", resolved_target=None,
                          port_range="443", result={"success": False, "error_reason": "budget_reached", "exit_code": -1})
    assert pipeline._coverage_warning(RUN) == "coverage_partial:nuclei=2"
    tool_execution.clear_coverage(RUN)
    assert pipeline._coverage_warning(RUN) is None


# --- REQ-PIPE-009: TLS on non-web services ---------------------------------------------------------

def test_req_pipe_009_starttls_and_implicit_tls_commands():
    smtp = trc._testssl_command("h.example:587", {"ip": "192.0.2.1", "starttls": "smtp"})
    assert "--starttls smtp " in smtp and " h.example:587 " in smtp + " " and "https://" not in smtp
    assert "--ip 192.0.2.1" in smtp and "--vulnerable" in smtp, "the same non-destructive checks as for a web service"
    implicit = trc._testssl_command("h.example:993", {"ip": "192.0.2.1"})
    assert "--starttls" not in implicit and "h.example:993" in implicit and "https://" not in implicit
    web = trc._testssl_command("https://h.example:8443", {"ip": "192.0.2.1"})
    assert "https://h.example:8443" in web and "--starttls" not in web, "web services are unchanged"
    assert "https://h.example" in trc._testssl_command("h.example", {})


@pytest.mark.parametrize("bad", ["smtp; id", "SMTP", "x", "", "--all", "$(id)", "tls"])
def test_negative_req_pipe_009_the_starttls_protocol_is_a_fixed_set(bad):
    if bad == "":
        return  # empty means no STARTTLS
    with pytest.raises(ValueError):
        trc._testssl_command("h.example:25", {"starttls": bad})


def test_req_pipe_009_the_scan_checks_mail_ports_and_names_service_and_port(monkeypatch):
    findings, recorded, gateway = [], [], []
    nmap = [
        {"port": 25, "protocol": "tcp", "service_name": "smtp", "product": "Postfix smtpd"},
        {"port": 465, "protocol": "tcp", "service_name": "smtps", "product": "Postfix smtpd"},
        {"port": 993, "protocol": "tcp", "service_name": "imaps", "product": "Dovecot imapd"},
    ]
    store = _install_run(monkeypatch, probe=_app_probe(), nmap_services=nmap + _OPEN_443)
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: findings.append(k) or {"id": "f"})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k))
    monkeypatch.setattr(fingerprint, "_propose", lambda eid, tool, cat, target, args, run: gateway.append((tool, dict(args))) or {"allowed": True})
    sent = []
    record = '[{"id":"LUCKY13","severity":"LOW","finding":"potentially vulnerable"}]'

    def fake_run(tool, target, args, **kw):
        sent.append((tool, target, dict(args)))
        return {"success": True, "exit_code": 0, "stderr": "", "stdout": record if tool == "testssl" else ""}

    monkeypatch.setattr(fingerprint.tool_runner, "run", fake_run)
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    tls = {t for tool, t, _ in sent if tool == "testssl" and ":" in t and not t.startswith("http")}
    assert tls == {"h.example:25", "h.example:465", "h.example:993"}
    starttls = {t: a.get("starttls") for tool, t, a in sent if tool == "testssl" and not t.startswith("http")}
    assert starttls == {"h.example:25": "smtp", "h.example:465": None, "h.example:993": None}
    assert ("testssl", {"starttls": "smtp"}) in gateway and ("testssl", {}) in gateway
    titles = {f["title"] for f in findings if f["evidence"].get("port") in (25, 465, 993)}
    assert any(t.endswith("(smtp on port 25)") for t in titles) and any(t.endswith("(smtps on port 465)") for t in titles)
    assert len(titles) == 3, "the same weakness on three ports is three findings"
    assert all(f["evidence"]["tool"] == "testssl" for f in findings if f["evidence"].get("port") in (25, 465, 993))
    assert store.check("h.example", "testssl", port=25)["state"] == "complete"
    assert "wafw00f" not in store.states("h.example", port=25), "no web check on a mail port"


def test_negative_req_pipe_009_a_service_that_is_not_tls_is_skipped_never_clean(monkeypatch):
    for output, expected in (
        ('[{"id":"scanProblem","severity":"FATAL","finding":"Oops: doesn\'t seem to be a TLS/SSL enabled server"}]',
         ("not_a_tls_service", "skipped")),
        ('[{"id":"scanProblem-out","severity":"FATAL","finding":"connect problem"}]', ("tls_scan_problem", "failed")),
        ("", ("tls_scan_problem", "failed")),
    ):
        recorded = []
        monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
        monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, _o=output, **k: {"success": True, "exit_code": 0, "stdout": _o, "stderr": ""})
        monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k["result"]))
        monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: pytest.fail("no finding from a service testssl could not test"))
        fingerprint._tls_service_scan(EID, "a1", "h.example", "192.0.2.1", RUN, 9999, None)
        assert recorded[0]["error_reason"] == expected[0]
        assert tool_execution.outcome_of(recorded[0]).split(":")[0] == expected[1]


def test_negative_req_pipe_009_a_tls_scan_of_an_unresolved_host_is_recorded_not_run(monkeypatch):
    recorded = []
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k["result"]))
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: pytest.fail("must not run"))
    fingerprint._tls_service_scan(EID, "a1", "h.example", None, RUN, 25, "smtp")
    assert recorded[0]["error_reason"] == "materialized_ip_missing"


# --- the engagement's tool list decides which tools run (testssl included) ------------------------------

def test_the_tool_list_a_tool_the_campaign_switched_off_is_planned_as_skipped_with_that_reason():
    surface = planner.SurfaceInput("h.example", 587, "tls_service", starttls="smtp")
    (check,) = planner.plan_surface(surface, planner.Options(disabled_tools=frozenset({"testssl"})), planner.IndexInfo())
    assert (check.check_id, check.state, check.reason) == ("testssl", "skipped", "tool_disabled")
    (enabled,) = planner.plan_surface(surface, planner.Options(), planner.IndexInfo())
    assert enabled.state == "planned", "selected in the tool list means it runs, with no further step"


def test_the_tool_list_disabling_testssl_switches_it_off_for_web_services_too_and_nothing_else():
    web = planner.SurfaceInput("h.example", 443, "web", "https", ("nginx",))
    checks = {c.check_id: c for c in planner.plan_surface(
        web, planner.Options(disabled_tools=frozenset({"testssl"})), planner.IndexInfo())}
    assert (checks["testssl"].state, checks["testssl"].reason) == ("skipped", "tool_disabled")
    assert checks["wafw00f"].state == "planned" and checks["ffuf"].state == "planned"
    assert checks["nuclei:tech"].state == "planned" and checks["header_findings"].state == "planned"


def test_the_tool_list_disabling_nuclei_skips_every_nuclei_check_but_not_the_header_findings():
    web = planner.SurfaceInput("h.example", 443, "web", "https")
    for profile in planner.SCAN_PROFILES:
        checks = planner.plan_surface(
            web, planner.Options(scan_profile=profile, crawling=True, disabled_tools=frozenset({"nuclei", "httpx"})),
            planner.IndexInfo())
        nuclei = [c for c in checks if c.tool == "nuclei"]
        assert nuclei and all(c.state == "skipped" for c in nuclei)
        header = next(c for c in checks if c.check_id == "header_findings")
        assert header.state == "planned", "it reads headers httpx already recorded and sends nothing"


def test_negative_the_tool_list_never_turns_a_skipped_check_back_on():
    alias = planner.SurfaceInput("h.example", 80, "web_alias", "http", alias_of="h.example:443")
    checks = planner.plan_surface(alias, planner.Options(disabled_tools=frozenset({"testssl"})), planner.IndexInfo())
    assert {c.reason for c in checks} == {"web_alias_of:h.example:443"}


def test_the_disabled_tools_of_the_engagement_reach_the_stored_plan(monkeypatch):
    nmap = [{"port": 25, "protocol": "tcp", "service_name": "smtp", "product": "Postfix smtpd"},
            {"port": 993, "protocol": "tcp", "service_name": "imaps", "product": "Dovecot imapd"}]
    store = _install_run(monkeypatch, probe=_app_probe(), nmap_services=nmap + _OPEN_443)
    monkeypatch.setattr(fingerprint.client, "get_scan_settings", lambda eid: {
        "scan_profile": "standard", "max_parallel_checks": 2, "disabled_tools": ["testssl"]})
    gateway = []
    monkeypatch.setattr(fingerprint, "_propose", lambda eid, tool, *a, **k: gateway.append(tool) or {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda tool, *a, **k: {"success": True, "exit_code": 0, "stdout": "", "stderr": ""})
    fingerprint.run(EID, [{"asset_id": "a1", "value": "h.example"}], scan_run_id=RUN)
    for port in (25, 993, 443):
        row = store.check("h.example", "testssl", port=port)
        assert (row["state"], row["reason"]) == ("skipped", "tool_disabled"), port
    assert "testssl" not in gateway, "a switched-off tool is not even proposed"
    assert store.check("h.example", "wafw00f", port=443)["state"] == "complete"
