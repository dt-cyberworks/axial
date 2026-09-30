"""TC-AUTH-001 / REQ-AUTH-006: a bug-bounty engagement's mandatory self-
identification (and optional User-Agent suffix) must reach every HTTP-
proxied tool's actual command, including HTTPS - the egress-proxy can only
inject it for plain HTTP. Covers both the per-tool command builders (given
the injected keys directly, matching what run() would add) and run()'s own
lookup/caching/injection wiring.

TC-RATE-001 / REQ-RATE-004: a bug-bounty program's configured max_rps must
also be honored inside nuclei/ffuf's own internal rate flag, not only at
gateway/proxy dispatch - see _bounty_rate_cap and its two call sites."""

from __future__ import annotations

from app import tool_runner_client as trc

_BOUNTY_ARGS = {
    "_bounty_ident_header_name": "X-Bug-Bounty",
    "_bounty_ident_header_value": "researcher-42",
    "_bounty_ua_suffix": "asm-scanner (+contact: r@example.com)",
}


def setup_function(_):
    trc._bounty_ident_cache.clear()


# --- Per-tool command builders: identification present when configured -----

def test_httpx_command_injects_ident_header_and_disables_random_agent():
    cmd = trc._httpx_command("http://host.example.com", _BOUNTY_ARGS)
    assert "-H 'X-Bug-Bounty: researcher-42'" in cmd
    assert "-H 'User-Agent: asm-scanner (+contact: r@example.com)'" in cmd
    assert "-random-agent=false" in cmd


def test_httpx_command_omits_bounty_flags_when_not_configured():
    cmd = trc._httpx_command("http://host.example.com", {})
    assert "-H " not in cmd
    assert "-random-agent" not in cmd


def test_nuclei_body_injects_ident_header():
    body = trc._nuclei_body("host.example.com", {**_BOUNTY_ARGS, "mode": "tech"})
    assert "-H 'X-Bug-Bounty: researcher-42'" in body["additional_args"]
    assert "-H 'User-Agent: asm-scanner (+contact: r@example.com)'" in body["additional_args"]


def test_nuclei_body_omits_bounty_flags_when_not_configured():
    body = trc._nuclei_body("host.example.com", {"mode": "tech"})
    assert "-H " not in body["additional_args"]
    assert "-rate-limit 50" in body["additional_args"]


def test_nuclei_body_tightens_rate_limit_to_a_stricter_bounty_cap():
    body = trc._nuclei_body("host.example.com", {**_BOUNTY_ARGS, "_bounty_max_rps": 7, "mode": "tech"})
    assert "-rate-limit 7 " in body["additional_args"]
    assert "-rate-limit 50" not in body["additional_args"]


def test_nuclei_body_headless_mode_also_tightens_rate_limit():
    body = trc._nuclei_body("host.example.com", {**_BOUNTY_ARGS, "_bounty_max_rps": 7, "mode": "headless"})
    assert "-rate-limit 7 " in body["additional_args"]


def test_negative_nuclei_body_never_loosens_rate_limit_above_default():
    """A misconfigured/generous program cap must never make nuclei MORE
    aggressive than our own default - only tighten, never loosen."""
    body = trc._nuclei_body("host.example.com", {**_BOUNTY_ARGS, "_bounty_max_rps": 500, "mode": "tech"})
    assert "-rate-limit 50" in body["additional_args"]


def test_negative_nuclei_body_ignores_a_missing_bounty_cap():
    body = trc._nuclei_body("host.example.com", {"mode": "tech"})
    assert "-rate-limit 50" in body["additional_args"]


def test_ffuf_command_injects_ident_header():
    cmd = trc._ffuf_command("http://host.example.com", {**_BOUNTY_ARGS, "path": "/FUZZ"})
    assert "-H 'X-Bug-Bounty: researcher-42'" in cmd or "X-Bug-Bounty: researcher-42" in cmd
    assert "User-Agent: asm-scanner" in cmd


def test_ffuf_command_omits_bounty_flags_when_not_configured():
    cmd = trc._ffuf_command("http://host.example.com", {"path": "/FUZZ"})
    assert "Bug-Bounty" not in cmd
    assert "-rate 20" in cmd


def test_ffuf_command_tightens_rate_to_a_stricter_bounty_cap():
    cmd = trc._ffuf_command("http://host.example.com", {**_BOUNTY_ARGS, "path": "/FUZZ", "_bounty_max_rps": 7})
    assert "-rate 7 " in cmd
    assert "-rate 20" not in cmd


def test_negative_ffuf_command_never_loosens_rate_above_default():
    cmd = trc._ffuf_command("http://host.example.com", {**_BOUNTY_ARGS, "path": "/FUZZ", "_bounty_max_rps": 500})
    assert "-rate 20" in cmd


def test_negative_ffuf_command_ignores_a_missing_bounty_cap():
    cmd = trc._ffuf_command("http://host.example.com", {"path": "/FUZZ"})
    assert "-rate 20" in cmd


# --- _bounty_rate_cap helper -------------------------------------------

def test_bounty_rate_cap_tightens_to_the_program_cap():
    assert trc._bounty_rate_cap({"_bounty_max_rps": 7}, 50) == 7


def test_bounty_rate_cap_floors_at_one():
    assert trc._bounty_rate_cap({"_bounty_max_rps": 0.2}, 50) == 1


def test_negative_bounty_rate_cap_never_exceeds_default():
    assert trc._bounty_rate_cap({"_bounty_max_rps": 500}, 50) == 50


def test_negative_bounty_rate_cap_uses_default_when_unset():
    assert trc._bounty_rate_cap({}, 50) == 50
    assert trc._bounty_rate_cap({"_bounty_max_rps": None}, 50) == 50


def test_nikto_body_injects_add_header_and_useragent():
    body = trc._nikto_body("host.example.com", _BOUNTY_ARGS)
    assert '-Add-header "X-Bug-Bounty: researcher-42"' in body["additional_args"]
    assert '-useragent "asm-scanner (+contact: r@example.com)"' in body["additional_args"]


def test_nikto_body_omits_bounty_flags_when_not_configured():
    body = trc._nikto_body("host.example.com", {})
    assert "Add-header" not in body["additional_args"]


def test_testssl_command_injects_reqheader_and_user_agent():
    cmd = trc._testssl_command("host.example.com", _BOUNTY_ARGS)
    assert "--reqheader 'X-Bug-Bounty: researcher-42'" in cmd
    assert "--user-agent 'asm-scanner (+contact: r@example.com)'" in cmd or "--user-agent" in cmd


def test_testssl_command_omits_bounty_flags_when_not_configured():
    cmd = trc._testssl_command("host.example.com", {})
    assert "--reqheader" not in cmd
    assert "--user-agent" not in cmd


def test_wafw00f_command_writes_a_full_header_file_not_just_the_ident_header():
    """The load-bearing wafw00f case: -H takes a FILE that REPLACES wafw00f's
    own default header set (verified against the real installed binary's
    source) - a naive single-header file would make every request look like
    a bare, obviously-automated probe. The realistic defaults must still be
    present alongside the mandatory identification."""
    cmd = trc._wafw00f_command("http://host.example.com", _BOUNTY_ARGS)
    assert "printf '%s\\n'" in cmd
    assert "X-Bug-Bounty: researcher-42" in cmd
    assert "Accept:" in cmd  # one of wafw00f's own realistic defaults, still present
    assert "-H /tmp/wafw00f-headers-" in cmd
    assert "; rm -f /tmp/wafw00f-headers-" in cmd  # cleaned up after


def test_wafw00f_command_uses_the_suffix_as_the_user_agent_when_configured():
    cmd = trc._wafw00f_command("http://host.example.com", _BOUNTY_ARGS)
    assert "User-Agent: asm-scanner (+contact: r@example.com)" in cmd
    # The plain default UA must not ALSO be present once overridden.
    assert "rv:130.0" not in cmd


def test_wafw00f_command_is_the_plain_form_when_not_configured():
    cmd = trc._wafw00f_command("http://host.example.com", {})
    assert cmd == "wafw00f http://host.example.com"
    assert "printf" not in cmd


def test_http_request_command_injects_ident_header_and_ua():
    cmd = trc._http_request_command("https://host.example.com", {**_BOUNTY_ARGS, "path": "/"})
    assert "X-Bug-Bounty: researcher-42" in cmd
    assert "User-Agent: asm-scanner (+contact: r@example.com)" in cmd


def test_negative_http_request_ident_header_supersedes_an_agent_supplied_conflict():
    """THE load-bearing negative test: the agent must never be able to make
    its own header value win over the platform's mandatory identification,
    whether by accident or by proposing the exact same header name itself."""
    args = {**_BOUNTY_ARGS, "path": "/", "headers": {"X-Bug-Bounty": "agent-supplied-fake-value", "User-Agent": "curl/agent-fake"}}
    cmd = trc._http_request_command("https://host.example.com", args)
    assert "researcher-42" in cmd
    assert "agent-supplied-fake-value" not in cmd
    assert "asm-scanner (+contact: r@example.com)" in cmd
    assert "curl/agent-fake" not in cmd
    # Exactly one X-Bug-Bounty header line reaches curl, never two.
    assert cmd.count("X-Bug-Bounty:") == 1


def test_http_request_command_omits_bounty_flags_when_not_configured():
    cmd = trc._http_request_command("https://host.example.com", {"path": "/"})
    assert "Bug-Bounty" not in cmd


# --- run()'s own lookup/caching/injection wiring ---------------------------

def _patch_dispatch(monkeypatch, *, ident):
    """Bypasses the real network call inside run() (_post_cancellable) and
    the real control-plane lookup (_bounty_ident_for's own httpx client),
    capturing exactly what args reached the tool's command builder."""
    captured = {}

    def fake_httpx_command(target, args):
        captured["args"] = args
        return "httpx --fake"

    monkeypatch.setattr(trc, "_COMMANDS", {**trc._COMMANDS, "httpx": fake_httpx_command})
    monkeypatch.setattr(
        trc.ToolRunnerClient, "_post_cancellable",
        lambda self, endpoint, payload, scan_run_id, budget_s=None: {"success": True, "stdout": "", "stderr": "", "exit_code": 0},
    )
    lookups = []

    def fake_get_bounty_ident(engagement_id):
        lookups.append(engagement_id)
        return ident

    import app.control_plane_client as cpc
    monkeypatch.setattr(cpc.client, "get_bounty_ident", fake_get_bounty_ident)
    return captured, lookups


def test_run_injects_ident_for_an_http_proxied_tool_on_a_bug_bounty_engagement(monkeypatch):
    import uuid
    eid = str(uuid.uuid4())
    captured, lookups = _patch_dispatch(monkeypatch, ident={
        "ident_header_name": "X-Bug-Bounty", "ident_header_value": "researcher-42", "ua_suffix": None,
    })
    runner = trc.ToolRunnerClient()

    runner.run("httpx", "http://host.example.com", {}, engagement_id=eid)

    assert captured["args"]["_bounty_ident_header_name"] == "X-Bug-Bounty"
    assert captured["args"]["_bounty_ident_header_value"] == "researcher-42"
    assert len(lookups) == 1


def test_run_injects_max_rps_for_an_http_proxied_tool_on_a_bug_bounty_engagement(monkeypatch):
    import uuid
    eid = str(uuid.uuid4())
    captured, _lookups = _patch_dispatch(monkeypatch, ident={
        "ident_header_name": "X-Bug-Bounty", "ident_header_value": "researcher-42", "ua_suffix": None,
        "max_rps": 7.0,
    })
    runner = trc.ToolRunnerClient()

    runner.run("httpx", "http://host.example.com", {}, engagement_id=eid)

    assert captured["args"]["_bounty_max_rps"] == 7.0


def test_run_caches_the_lookup_across_calls_for_the_same_engagement(monkeypatch):
    import uuid
    eid = str(uuid.uuid4())
    captured, lookups = _patch_dispatch(monkeypatch, ident={
        "ident_header_name": "X-Bug-Bounty", "ident_header_value": "researcher-42", "ua_suffix": None,
    })
    runner = trc.ToolRunnerClient()

    runner.run("httpx", "http://a.example.com", {}, engagement_id=eid)
    runner.run("httpx", "http://b.example.com", {}, engagement_id=eid)

    assert len(lookups) == 1  # second call reused the cached result


def test_run_applies_max_rps_for_a_policy_with_no_identification_header_configured(monkeypatch):
    """REQ-AUTH-006 (amended 2026-08-12): not every program requires a custom
    header (e.g. Port of Antwerp-Bruges identifies via an out-of-band email
    alias, not a header) - a header-less policy must still get its max_rps
    tightening (REQ-RATE-004) applied to nuclei/ffuf. Regression test for a
    bug caught before shipping: the old gating logic treated "no header" as
    "no policy at all", silently dropping the rate cap too."""
    import uuid
    eid = str(uuid.uuid4())
    captured, _lookups = _patch_dispatch(monkeypatch, ident={
        "ident_header_name": "X-Bug-Bounty", "ident_header_value": None, "ua_suffix": None,
        "max_rps": 5.0,
    })
    runner = trc.ToolRunnerClient()

    runner.run("httpx", "http://host.example.com", {}, engagement_id=eid)

    assert captured["args"]["_bounty_max_rps"] == 5.0
    assert trc._bounty_h_flags(captured["args"]) == ""  # no header to inject


def test_negative_run_injects_nothing_for_a_non_bug_bounty_engagement(monkeypatch):
    import uuid
    eid = str(uuid.uuid4())
    captured, lookups = _patch_dispatch(monkeypatch, ident={
        "ident_header_name": None, "ident_header_value": None, "ua_suffix": None,
    })
    runner = trc.ToolRunnerClient()

    runner.run("httpx", "http://host.example.com", {}, engagement_id=eid)

    assert "_bounty_ident_header_name" not in captured["args"]


def test_negative_run_injects_nothing_when_no_engagement_id_is_given(monkeypatch):
    captured, lookups = _patch_dispatch(monkeypatch, ident={
        "ident_header_name": "X-Bug-Bounty", "ident_header_value": "researcher-42", "ua_suffix": None,
    })
    runner = trc.ToolRunnerClient()

    runner.run("httpx", "http://host.example.com", {})

    assert "_bounty_ident_header_name" not in captured["args"]
    assert lookups == []  # never even looked up - no engagement context at all


def test_negative_run_never_injects_for_a_raw_network_tool(monkeypatch):
    """redis-probe/activemq-* speak their own binary protocols, not HTTP -
    there is no header to identify with, and _HTTP_PROXIED_TOOLS deliberately
    excludes them."""
    import uuid
    eid = str(uuid.uuid4())
    captured = {}

    def fake_redis_probe_command(target, args):
        captured["args"] = args
        return "python3 -c fake"

    monkeypatch.setattr(trc, "_COMMANDS", {**trc._COMMANDS, "redis-probe": fake_redis_probe_command})
    monkeypatch.setattr(
        trc.ToolRunnerClient, "_post_cancellable",
        lambda self, endpoint, payload, scan_run_id, budget_s=None: {"success": True, "stdout": "", "stderr": "", "exit_code": 0},
    )
    monkeypatch.setattr(trc.ToolRunnerClient, "raw_network_available", staticmethod(lambda: True))
    lookups = []

    def fake_get_bounty_ident(engagement_id):
        lookups.append(engagement_id)
        return {"ident_header_name": "X-Bug-Bounty", "ident_header_value": "researcher-42", "ua_suffix": None}

    import app.control_plane_client as cpc
    monkeypatch.setattr(cpc.client, "get_bounty_ident", fake_get_bounty_ident)
    runner = trc.ToolRunnerClient()

    runner.run("redis-probe", "host.example.com", {"port": 6379}, engagement_id=eid)

    assert "_bounty_ident_header_name" not in captured["args"]
    assert lookups == []


def test_negative_a_bounty_ident_lookup_failure_degrades_to_no_injection(monkeypatch):
    """A control-plane hiccup must never abort a scan - it just means this
    one call goes out unidentified, same as a non-bug_bounty engagement."""
    import uuid
    eid = str(uuid.uuid4())
    captured = {}

    def fake_httpx_command(target, args):
        captured["args"] = args
        return "httpx --fake"

    monkeypatch.setattr(trc, "_COMMANDS", {**trc._COMMANDS, "httpx": fake_httpx_command})
    monkeypatch.setattr(
        trc.ToolRunnerClient, "_post_cancellable",
        lambda self, endpoint, payload, scan_run_id, budget_s=None: {"success": True, "stdout": "", "stderr": "", "exit_code": 0},
    )

    def raising_get_bounty_ident(engagement_id):
        raise ConnectionError("control-plane unreachable")

    import app.control_plane_client as cpc
    monkeypatch.setattr(cpc.client, "get_bounty_ident", raising_get_bounty_ident)
    runner = trc.ToolRunnerClient()

    result = runner.run("httpx", "http://host.example.com", {}, engagement_id=eid)

    assert "_bounty_ident_header_name" not in captured["args"]
    assert result["success"] is True  # the call itself still went through
