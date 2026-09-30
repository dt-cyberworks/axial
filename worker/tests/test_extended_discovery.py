"""REQ-COVER-001/003/004/006 (worker side): subfinder, crawling + URL history,
the self-hosted interaction server pass, and screenshots.

Every optional capability is behind a per-engagement switch and must fail
CLOSED: a missing answer from the control plane means "off". Nothing here
weakens the Scope Gateway - the worker only proposes.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import uuid
from types import SimpleNamespace

import pytest

from app import discovery_parse as dp
from app import tool_runner_client as trc
from app.tasks import discovery, fingerprint

EID = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
PNG = b"\x89PNG\r\n\x1a\n" + b"x" * 64


# --- parsers ---------------------------------------------------------------

def _katana_line(endpoint: str, method: str = "GET") -> str:
    return json.dumps({"request": {"method": method, "endpoint": endpoint}})


def test_katana_output_is_normalised_merged_and_filtered():
    out = "\n".join([
        _katana_line("https://a.example.com/item?id=1&sort=asc"),
        _katana_line("https://a.example.com/item?id=2&debug=1"),
        _katana_line("https://a.example.com/static/logo.png"),
        _katana_line("https://user:pw@a.example.com/secret"),
        _katana_line("ftp://a.example.com/x"),
        _katana_line("https://a.example.com/login", "POST"),
        "not json",
    ])
    endpoints = dp.parse_katana_jsonl(out)
    by_key = {(e["method"], e["url"]): e for e in endpoints}
    assert set(by_key) == {("GET", "https://a.example.com/item"), ("POST", "https://a.example.com/login")}
    assert by_key[("GET", "https://a.example.com/item")]["param_names"] == ["debug", "id", "sort"]
    assert all("?" not in e["url"] for e in endpoints)


def test_negative_overlong_and_credentialed_urls_are_dropped():
    assert dp.parse_url_list("https://a.example.com/" + "x" * 2100, "wayback") == []
    assert dp.parse_url_list("https://u:p@a.example.com/", "wayback") == []


def test_candidate_urls_are_parameterized_get_only_and_capped():
    eps = dp.parse_url_list(
        "\n".join(f"https://a.example.com/p{i}?q=1" for i in range(80)) + "\nhttps://a.example.com/plain", "wayback")
    urls = dp.nuclei_candidate_urls(eps)
    assert len(urls) == 50 and all("?" in u for u in urls)


# --- command builders ------------------------------------------------------

@pytest.fixture(autouse=True)
def _proxy(monkeypatch):
    monkeypatch.setattr(trc, "EGRESS_PROXY_URL", "http://egress-proxy:3128")


def test_katana_command_is_bounded_and_proxied():
    cmd = trc._katana_command("https://a.example.com", {})
    assert "-proxy http://egress-proxy:3128" in cmd
    assert "-d 2" in cmd and "-ct 90s" in cmd and "-fs fqdn" in cmd
    assert "-aff" not in cmd and "-fx" not in cmd, "no form filling / no form submission"
    assert "head -n 1000" in cmd and cmd.startswith("timeout 200 ")


def test_katana_command_uses_only_flag_values_katana_1_7_accepts_and_keeps_stderr():
    # Live run 2026-09-29: `-kf robotstxt,sitemapxml` is rejected by katana
    # v1.7.0 (single value only); the command still reported success with 0
    # endpoints because stderr was discarded.
    cmd = trc._katana_command("https://a.example.com", {})
    assert "-kf all " in cmd and "robotstxt" not in cmd
    assert "2>&1" not in cmd, "katana's own errors must reach stderr_summary"


def test_katana_carries_the_bounty_identity_and_the_tighter_rate():
    cmd = trc._katana_command("https://a.example.com", {
        "_bounty_ident_header_name": "X-Bug-Bounty", "_bounty_ident_header_value": "researcher",
        "_bounty_max_rps": 2,
    })
    assert "'X-Bug-Bounty: researcher'" in cmd or "X-Bug-Bounty: researcher" in cmd
    assert "-rl 2" in cmd


def test_screenshot_command_is_proxied_sandbox_free_and_size_checked():
    cmd = trc._screenshot_command("https://a.example.com", {})
    assert "--proxy-server=http://egress-proxy:3128" in cmd
    assert "--no-sandbox" in cmd and "--headless=new" in cmd
    assert "-le 1900000" in cmd and "base64 -w0" in cmd
    assert "rm -rf" in cmd


def test_nuclei_endpoints_command_quotes_every_url():
    evil = "https://a.example.com/x?id=1;touch${IFS}/tmp/pwned"
    cmd = trc._nuclei_command("https://a.example.com", {"mode": "endpoints", "urls": [evil]})
    assert "-dast" in cmd and "-etags intrusive,dos,fuzz,csp-bypass" in cmd
    assert "'" + evil + "'" in cmd, "the URL must reach the shell single-quoted"
    assert "-p http://egress-proxy:3128" in cmd


def test_negative_nuclei_endpoints_without_urls_is_refused():
    with pytest.raises(ValueError):
        trc._nuclei_command("https://a.example.com", {"mode": "endpoints", "urls": []})


def test_nuclei_oob_command_reads_the_token_from_the_runner_environment():
    cmd = trc._nuclei_command("https://a.example.com", {"mode": "oob", "_oob_server": "http://interactsh:8080"})
    assert '-itoken "$OOB_TOKEN"' in cmd and "-iserver http://interactsh:8080" in cmd
    assert "-no-interactsh" not in cmd
    assert "-etags intrusive,dos,fuzz,csp-bypass" in cmd, "OOB never re-admits an excluded template"


def test_oob_parts_are_disjoint_cover_the_template_set_and_are_all_bounded():
    # Live 2026-09-29: the whole blind-vulnerability set in ONE pass timed out
    # (exit 124) at the proxy's per-engagement rate; each part is a subset.
    parts = trc.NUCLEI_OOB_PARTS
    # Shards of one dir set partition it by index; different dir sets never share a directory.
    keys = [(paths, shards, index) for paths, shards, index in parts.values()]
    assert len(keys) == len(set(keys))
    by_dirs: dict = {}
    for paths, shards, index in parts.values():
        by_dirs.setdefault(paths, []).append((shards, index))
    for shard_list in by_dirs.values():
        n = shard_list[0][0]
        assert sorted(shard_list) == [(n, i) for i in range(n)], "shards cover every index exactly once"
    all_dirs = [d for paths in by_dirs for d in paths]
    assert len(all_dirs) == len(set(all_dirs)), "no template directory belongs to two sets"
    for name in parts:
        cmd = trc._nuclei_command("https://a.example.com", {"mode": "oob", "part": name, "_oob_server": "http://x:8080"})
        assert "-tags oast" in cmd and cmd.startswith(f"timeout {trc.NUCLEI_OOB_TIMEOUT_S} nuclei -u ")
        assert "-t /opt/nuclei-templates " not in cmd, "never the whole template tree"
    with pytest.raises(ValueError):
        trc._nuclei_command("https://a.example.com", {"mode": "oob", "part": "../x", "_oob_server": "http://x:8080"})
    cmd = trc._nuclei_command("https://a.example.com", {"mode": "oob", "part": "generic_b", "_oob_server": "http://x:8080"})
    assert "awk 'NR%3==1'" in cmd and "find " in cmd


def test_negative_nuclei_oob_without_a_valid_server_is_refused():
    for bad in ("", "http://x; rm -rf /", "$(id)"):
        with pytest.raises(ValueError):
            trc._nuclei_command("https://a.example.com", {"mode": "oob", "_oob_server": bad})


def test_the_tech_and_headless_passes_still_disable_interactsh():
    for mode in ("tech", "headless"):
        args = trc._nuclei_body("a.example.com", {"mode": mode})["additional_args"]
        assert "-no-interactsh" in args


def _fake_runner(monkeypatch, captured):
    runner = trc.ToolRunnerClient()

    def post(path, payload, scan_run_id, budget_s=None):
        captured.update(path=path, payload=payload)
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"stdout": "", "stderr": "", "return_code": 0, "success": True},
        )

    monkeypatch.setattr(runner, "_post_cancellable", post)
    return runner


def test_run_routes_command_modes_through_api_command_and_injects_the_server(monkeypatch):
    monkeypatch.setattr(trc, "OOB_SERVER_URL", "http://interactsh:8080")
    captured: dict = {}
    result = _fake_runner(monkeypatch, captured).run("nuclei", "https://a.example.com", {"mode": "oob"})
    assert captured["path"] == "/api/command"
    assert "-iserver http://interactsh:8080" in captured["payload"]["command"]
    assert "OOB_TOKEN" in result["command"] and "secret" not in result["command"]


def test_run_gives_katana_the_bounty_identity(monkeypatch):
    monkeypatch.setattr(trc, "_bounty_ident_for", lambda eid: {
        "ident_header_name": "X-Id", "ident_header_value": "abc", "ua_suffix": None, "max_rps": 3})
    captured: dict = {}
    _fake_runner(monkeypatch, captured).run("katana", "https://a.example.com", {}, engagement_id=EID)
    assert "X-Id: abc" in captured["payload"]["command"]


# --- control-plane client fails closed -------------------------------------

def test_negative_a_failed_options_lookup_turns_everything_off_including_subfinder(monkeypatch):
    from app.control_plane_client import client

    def boom(*a, **k):
        raise RuntimeError("control plane down")

    monkeypatch.setattr(client._client, "get", boom)
    assert client.get_discovery_options(uuid.UUID(EID)) == {
        "subfinder": False, "crawling": False, "oob": False, "screenshots": False}


# --- the plan carries the switches --------------------------------------------

_LIVE_A = {"url": "https://a.example.com", "status_code": 200, "webserver": "nginx", "title": "a",
           "content_length": 10, "headers": {}, "service_id": "svc-a"}


def _plan(monkeypatch, options, *, oob_server="http://interactsh:8080", duplicate=False):
    """The plan of one live web surface under the given switches."""
    from app.planner import IndexInfo, Options

    monkeypatch.setattr(fingerprint, "OOB_SERVER_URL", oob_server)
    monkeypatch.setattr(fingerprint, "_http_probe", lambda *a, **k: dict(_LIVE_A))
    ctx = fingerprint._RunContext()
    if duplicate:
        fingerprint._probe_web_surface(ctx, EID, "asset-1", "a.example.com", "1.2.3.4", RUN, None, [])
    host = "b.example.com" if duplicate else "a.example.com"
    _, surface = fingerprint._probe_web_surface(ctx, EID, "asset-2", host, "1.2.3.4", RUN, None, [])
    opts = Options(crawling=options["crawling"], screenshots=options["screenshots"], oob=options["oob"],
                   oob_available=bool(oob_server))
    (row,) = fingerprint._plan_payload([surface], opts, IndexInfo())
    return {c["check_id"]: (c["state"], c["reason"]) for c in row["checks"]}, [c["check_id"] for c in row["checks"]]


def test_all_switches_off_plans_none_of_the_optional_steps(monkeypatch):
    checks, _ = _plan(monkeypatch, {"crawling": False, "oob": False, "screenshots": False})
    for optional in ("screenshot", "katana", "nuclei:endpoints", *[f"nuclei:oob:{p}" for p in trc.NUCLEI_OOB_PARTS]):
        assert checks[optional] == ("skipped", "switch_off"), optional
    assert all(checks[c][0] == "planned" for c in ("wafw00f", "testssl", "header_findings", "ffuf", "nuclei:tech"))


def test_all_switches_on_keeps_nuclei_last_and_orders_the_extras(monkeypatch):
    checks, order = _plan(monkeypatch, {"crawling": True, "oob": True, "screenshots": True})
    planned = [c for c in order if checks[c][0] == "planned"]
    generic = [c for c in planned if c.startswith("nuclei:generic:")]
    assert planned[:7] == ["wafw00f", "testssl", "header_findings", "ffuf", "screenshot", "katana", "nuclei:tech"]
    assert planned[7:] == [
        *generic, "nuclei:products", "nuclei:headless", "nuclei:takeover", "nuclei:endpoints",
        *[f"nuclei:oob:{p}" for p in sorted(trc.NUCLEI_OOB_PARTS)],
    ]


def test_the_endpoints_pass_waits_for_the_crawl(monkeypatch):
    from app.planner import IndexInfo, Options, SurfaceInput, plan_surface

    checks = plan_surface(SurfaceInput("a.example.com", 443, "web", "https"), Options(crawling=True), IndexInfo())
    by_id = {c.check_id: c for c in checks}
    assert by_id["nuclei:endpoints"].depends_on == "katana" and by_id["nuclei:products"].depends_on == "nuclei:tech"


def test_a_duplicate_vhost_plans_the_enabled_extras_as_skipped_with_the_reason(monkeypatch):
    checks, _ = _plan(monkeypatch, {"crawling": True, "oob": False, "screenshots": True}, duplicate=True)
    reason = "duplicate_vhost_of:a.example.com"
    for skipped in ("header_findings", "ffuf", "screenshot", "katana", "nuclei", "nuclei:endpoints"):
        assert checks[skipped] == ("skipped", reason), skipped
    # Per-name checks still run: a certificate or WAF verdict for one name says nothing about another.
    assert checks["wafw00f"][0] == "planned" and checks["testssl"][0] == "planned"


def test_oob_without_a_deployed_server_is_planned_as_skipped(monkeypatch):
    checks, _ = _plan(monkeypatch, {"crawling": False, "oob": True, "screenshots": False}, oob_server="")
    for part in trc.NUCLEI_OOB_PARTS:
        assert checks[f"nuclei:oob:{part}"] == ("skipped", "oob_unavailable")


def test_crawl_stores_endpoints_without_queries_and_offers_same_host_parameterized_urls(monkeypatch):
    stored: list = []
    out = "\n".join([
        _katana_line("https://a.example.com/item?id=1"),
        _katana_line("https://a.example.com/about"),
        _katana_line("https://other.example.com/x?id=9"),
    ])
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": out})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint.client, "add_discovered_endpoints", lambda eid, run, eps: stored.extend(eps))
    urls = fingerprint._crawl(EID, "asset-1", "a.example.com", RUN, None, "https")
    assert urls == ["https://a.example.com/item?id=1"], "a cross-host URL is never handed to the DAST pass"
    assert all("?" not in e["url"] for e in stored)
    assert {e["url"] for e in stored} == {
        "https://a.example.com/item", "https://a.example.com/about", "https://other.example.com/x"}


def test_negative_a_gateway_denial_runs_no_crawl(monkeypatch):
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: pytest.fail("denied call must not run"))
    assert fingerprint._crawl(EID, "asset-1", "a.example.com", RUN, None, "https") == []


def test_a_failed_endpoint_store_never_fails_the_scan(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("409")

    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_runner, "run",
                        lambda *a, **k: {"success": True, "stdout": _katana_line("https://a.example.com/p?x=1")})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint.client, "add_discovered_endpoints", boom)
    assert fingerprint._crawl(EID, "asset-1", "a.example.com", RUN, None, "https") == ["https://a.example.com/p?x=1"]


def test_endpoints_pass_is_a_nuclei_call_with_the_url_list(monkeypatch):
    passes: list = []
    monkeypatch.setattr(fingerprint, "_nuclei_pass", lambda *a: passes.append(a))
    fingerprint._nuclei_endpoints_pass(EID, "asset-1", "a.example.com", RUN, None, "https", [])
    assert passes == [], "no candidate URLs -> no pass"
    fingerprint._nuclei_endpoints_pass(EID, "asset-1", "a.example.com", RUN, None, "https", ["https://a.example.com/x?a=1"])
    assert passes[0][4] == {"mode": "endpoints", "urls": ["https://a.example.com/x?a=1"]}


def test_screenshot_is_stored_and_an_empty_result_is_an_honest_failure(monkeypatch):
    stored: list = []
    records: list = []
    b64 = base64.b64encode(PNG).decode()
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: records.append(k))
    monkeypatch.setattr(fingerprint.client, "add_web_screenshot", lambda eid, run, url, png: stored.append((url, png)))

    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": b64 + "\n"})
    fingerprint._screenshot(EID, "asset-1", "a.example.com", RUN, None, "https")
    assert stored == [("https://a.example.com", b64)]

    stored.clear()
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": ""})
    fingerprint._screenshot(EID, "asset-1", "a.example.com", RUN, None, "https")
    assert stored == [] and records[-1]["result"]["error_reason"] == "screenshot_empty"


# --- discovery: subfinder --------------------------------------------------

class _Client:
    def __init__(self, scope, options, *, allow=True):
        self._scope, self.options, self.allow = scope, options, allow
        self.assets: list[dict] = []
        self.authorized: list[dict] = []
        self.endpoints: list = []

    def list_scope_assets(self, eid):
        return self._scope

    def list_discovered_assets(self, eid, in_scope=None):
        return []

    def add_discovered_asset(self, eid, **f):
        self.assets.append(f)
        return {"id": f"a{len(self.assets)}"}

    def get_discovery_options(self, eid):
        return self.options

    def get_subfinder_config(self):
        return {"virustotal": "vt-secret-key"}

    def authorize(self, eid, call):
        self.authorized.append(call)
        return {"allowed": self.allow, "reason": "ok" if self.allow else "recon_passive_not_granted"}

    def add_discovered_endpoints(self, eid, run, eps):
        self.endpoints.extend(eps)


SCOPE = [
    {"rule": "allow", "asset_type": "domain", "value": "example.com", "active_allowed": True},
    {"rule": "deny", "asset_type": "domain", "value": "old.example.com", "active_allowed": False},
]


def _discover(monkeypatch, options, *, allow=True, sub_stdout="", returncode=0, capture=None):
    cl = _Client(SCOPE, options, allow=allow)
    records: list = []
    monkeypatch.setattr(discovery, "client", cl)
    monkeypatch.setattr(discovery, "_enrich_dns", lambda *a, **k: None)
    monkeypatch.setattr(discovery, "_passive_subdomains", lambda d: set())
    monkeypatch.setattr(discovery.tool_execution, "record", lambda *a, **k: records.append(k))
    monkeypatch.setattr(discovery, "_collect_url_history", lambda *a, **k: 0)

    def fake_run(cmd, **kw):
        if capture is not None:
            capture.update(cmd=cmd, **kw)
            cfg = cmd[cmd.index("-pc") + 1] if "-pc" in cmd else None
            capture["config_text"] = open(cfg).read() if cfg else None
            capture["config_mode"] = oct(os.stat(cfg).st_mode & 0o777) if cfg else None
            capture["config_path"] = cfg
        return subprocess.CompletedProcess(cmd, returncode, stdout=sub_stdout, stderr="")

    monkeypatch.setattr(discovery.subprocess, "run", fake_run)
    discovery.run(EID, RUN)
    return cl, records


def test_subfinder_names_join_the_scope_filter_and_deny_wins(monkeypatch):
    out = "www.example.com\nold.example.com\nx.evil.org\nbadexample.com\n*.api.example.com\n"
    cl, records = _discover(monkeypatch, {"subfinder": True, "crawling": False}, sub_stdout=out)
    by_value = {a["value"]: a for a in cl.assets}
    assert by_value["www.example.com"]["in_scope"] is True
    assert by_value["www.example.com"]["discovered_via"] == "subfinder"
    assert by_value["api.example.com"]["in_scope"] is True
    assert by_value["old.example.com"]["in_scope"] is False, "deny beats allow"
    assert "x.evil.org" not in by_value and "badexample.com" not in by_value, "out-of-scope names are dropped"
    assert records[0]["tool"] == "subfinder" and records[0]["phase"] == "discovery"


def test_negative_switch_off_means_subfinder_is_never_authorized_or_run(monkeypatch):
    cl, records = _discover(monkeypatch, {"subfinder": False, "crawling": False}, sub_stdout="www.example.com\n")
    assert cl.authorized == [] and records == []
    assert "www.example.com" not in {a["value"] for a in cl.assets}


def test_negative_a_gateway_denial_runs_nothing_and_is_audited(monkeypatch):
    cl, records = _discover(monkeypatch, {"subfinder": True, "crawling": False}, allow=False,
                            sub_stdout="www.example.com\n")
    assert cl.authorized[0]["tool"] == "subfinder" and cl.authorized[0]["mode"] == "passive"
    assert records[0]["result"]["error_reason"] == "gateway_denied:recon_passive_not_granted"
    assert "www.example.com" not in {a["value"] for a in cl.assets}


def test_subfinder_is_passive_keys_go_to_a_private_temp_file_and_are_removed(monkeypatch):
    seen: dict = {}
    monkeypatch.setenv("INTERNAL_API_TOKEN", "must-not-leak")
    _discover(monkeypatch, {"subfinder": True, "crawling": False}, capture=seen)
    assert "-active" not in seen["cmd"] and "-recursive" not in seen["cmd"]
    assert seen["config_mode"] == "0o600"
    assert 'virustotal:\n  - "vt-secret-key"' in seen["config_text"]
    assert not os.path.exists(seen["config_path"]), "the key file must not outlive the run"
    assert "INTERNAL_API_TOKEN" not in seen["env"] and set(seen["env"]) == {"PATH", "HOME"}
    assert "vt-secret-key" not in " ".join(seen["cmd"])
    assert seen["timeout"] == discovery.SUBFINDER_TIMEOUT_S


def test_negative_a_timeout_or_missing_binary_never_fails_discovery(monkeypatch):
    def timeout(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)

    cl = _Client(SCOPE, {"subfinder": True, "crawling": False})
    records: list = []
    monkeypatch.setattr(discovery, "client", cl)
    monkeypatch.setattr(discovery, "_enrich_dns", lambda *a, **k: None)
    monkeypatch.setattr(discovery, "_passive_subdomains", lambda d: set())
    monkeypatch.setattr(discovery.tool_execution, "record", lambda *a, **k: records.append(k))
    monkeypatch.setattr(discovery.subprocess, "run", timeout)
    discovery.run(EID, RUN)
    assert records[0]["result"]["error_reason"] == "subfinder_timeout"

    def missing(cmd, **kw):
        raise FileNotFoundError("subfinder")

    monkeypatch.setattr(discovery.subprocess, "run", missing)
    discovery.run(EID, RUN)
    assert records[-1]["result"]["error_reason"] == "subfinder_not_installed"
    assert "example.com" in {a["value"] for a in cl.assets}, "the apex target still made it through"


def test_negative_unsafe_domain_is_not_passed_to_the_binary(monkeypatch):
    monkeypatch.setattr(discovery.subprocess, "run", lambda *a, **k: pytest.fail("must not run"))
    names, result = discovery._run_subfinder("exa mple.com; id", {})
    assert names == set() and result["error_reason"] == "unsafe_domain"


# --- discovery: URL history ------------------------------------------------

def test_url_history_is_scope_and_deny_filtered_before_storage(monkeypatch):
    cl = _Client(SCOPE, {})
    monkeypatch.setattr(discovery, "client", cl)
    text = "\n".join([
        "https://www.example.com/a?x=1",
        "https://old.example.com/denied",
        "https://evil.org/out",
        "https://badexample.com/out",
    ])
    monkeypatch.setattr(discovery, "_URL_HISTORY_SOURCES", (("wayback", lambda d: text),))
    allow = [a for a in SCOPE if a["rule"] == "allow"]
    deny = [a for a in SCOPE if a["rule"] == "deny"]
    sent = discovery._collect_url_history(EID, RUN, "example.com", allow, deny)
    assert sent == 1 and [e["url"] for e in cl.endpoints] == ["https://www.example.com/a"]
    assert cl.endpoints[0]["param_names"] == ["x"] and cl.endpoints[0]["source"] == "wayback"


def test_url_history_runs_only_with_the_crawling_switch(monkeypatch):
    called: list = []
    cl = _Client(SCOPE, {"subfinder": False, "crawling": True})
    monkeypatch.setattr(discovery, "client", cl)
    monkeypatch.setattr(discovery, "_enrich_dns", lambda *a, **k: None)
    monkeypatch.setattr(discovery, "_passive_subdomains", lambda d: set())
    monkeypatch.setattr(discovery, "_collect_url_history", lambda *a, **k: called.append(a[2]))
    discovery.run(EID, RUN)
    assert called == ["example.com"]
    called.clear()
    cl.options = {"subfinder": False, "crawling": False}
    discovery.run(EID, RUN)
    assert called == []


def test_a_failing_history_source_does_not_break_the_others(monkeypatch):
    cl = _Client(SCOPE, {})
    monkeypatch.setattr(discovery, "client", cl)

    def boom(d):
        raise RuntimeError("archive down")

    monkeypatch.setattr(discovery, "_URL_HISTORY_SOURCES", (("wayback", boom), ("commoncrawl", lambda d: "https://www.example.com/ok")))
    allow = [a for a in SCOPE if a["rule"] == "allow"]
    assert discovery._collect_url_history(EID, RUN, "example.com", allow, []) == 1
