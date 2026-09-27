"""REQ-AGENT-016/018: nuclei runs in two separate passes.

REQ-AGENT-016 (main pass): includes the baked-in 'dast' generic vulnerability
templates (xss, sqli incl. blind/time-based, redirect, lfi, rfi, cmdi, ssrf,
ssti, xxe, crlf - none tagged 'fuzz', so unaffected by the existing
intrusive/dos/fuzz exclusion). Found live: a scan against a real, documented
training target (DVWA) never triggered a single XSS/SQLi/redirect detection
via nuclei, even though the site had a live, unauthenticated reflected-XSS
page - because 'dast' was simply never in the tag allowlist.

REQ-AGENT-018 (why TWO passes, corrected after live measurement): HexStrike's
command executor kills every single command hard at 300s (COMMAND_TIMEOUT,
not overridable per call). A combined full-tag-set + `-headless` run against a
real, proxied target blew past 300s and got killed (nonzero_exit, only partial
findings) - while the non-headless run reliably completed under 300s before
(5/5). So nuclei now runs as a fast non-headless MAIN pass (full tag set) plus
a tiny separate HEADLESS pass ('-headless -tags domxss' = exactly one generic
template, ~5-30s). Each pass stays safely under the hard 300s cap. mode is
selected via args; the deterministic fingerprint phase runs both, an agent
proposal (args without mode) gets the fast main pass.

The main pass deliberately excludes 'csp-bypass' (~192 vendor-specific
domain-whitelist templates, also headless-only): measured ~530s for just the
24 templates in nuclei's headless/ directory against a single target -
disproportionate for a generic ASM baseline. The headless pass deliberately
uses the precise 'domxss' tag (exactly one generic template), not the broad
'headless' tag (would pull in a DVWA-specific template nuclei itself ships) or
'xss' (1411, mostly product-specific).

-system-chrome uses the image's own installed Chromium (no runtime download -
the isolated runtime image has no internet access). --no-sandbox is required
because the container drops all capabilities (cap_drop: ALL) that Chrome's own
internal sandbox needs; the container's own isolation substitutes for it.
Concurrency is capped low (2/2, default 10/10) for the small deployed host."""

from __future__ import annotations

from app import tool_runner_client as trc


# --- Main (non-headless) pass -------------------------------------------------

def test_main_pass_includes_dast_tag():
    body = trc._nuclei_body("host.example.com", {})
    tags_part = body["additional_args"].split("-tags", 1)[1].split("-severity", 1)[0]
    assert "dast" in tags_part


def test_main_pass_is_not_headless():
    body = trc._nuclei_body("host.example.com", {})
    assert "-headless" not in body["additional_args"]
    assert "domxss" not in body["additional_args"]


def test_main_pass_still_excludes_intrusive_dos_fuzz_and_csp_bypass():
    body = trc._nuclei_body("host.example.com", {})
    etags_part = body["additional_args"].split("-etags", 1)[1]
    for tag in ("intrusive", "dos", "fuzz", "csp-bypass"):
        assert tag in etags_part


# --- Headless pass ------------------------------------------------------------

def test_headless_pass_uses_precise_domxss_tag_only():
    body = trc._nuclei_body("host.example.com", {"mode": "headless"})
    tags_part = body["additional_args"].split("-tags", 1)[1].split("-severity", 1)[0]
    assert "domxss" in tags_part
    # Precision: broad nets that would each pull in far more than intended, or
    # re-run the whole expensive main set.
    assert "headless" not in tags_part
    assert "dast" not in tags_part
    assert not any(t.strip() == "xss" for t in tags_part.split(","))


def test_headless_pass_enables_headless_with_system_chrome_and_no_sandbox():
    body = trc._nuclei_body("host.example.com", {"mode": "headless"})
    args = body["additional_args"]
    assert "-headless" in args
    assert "-system-chrome" in args
    assert "--no-sandbox" in args


def test_headless_pass_caps_concurrency_for_the_small_host():
    body = trc._nuclei_body("host.example.com", {"mode": "headless"})
    args = body["additional_args"]
    assert "-hbs 2" in args
    assert "-headc 2" in args


def test_both_passes_disable_hexstrike_cache():
    for args in ({}, {"mode": "headless"}):
        assert trc._nuclei_body("host.example.com", args)["use_cache"] is False


# --- fingerprint phase dispatches BOTH passes ---------------------------------

def test_fingerprint_nuclei_scan_runs_main_then_headless(monkeypatch):
    """REQ-AGENT-018: the deterministic fingerprint phase must dispatch nuclei
    twice - the fast non-headless main pass AND the tiny headless domxss pass -
    each a separate sub-300s HexStrike command."""
    from app.tasks import fingerprint

    calls = []
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint, "parse_nuclei_jsonl", lambda stdout: [])

    def fake_run(tool, url, args, scan_run_id=None, engagement_id=None):
        calls.append(args.get("mode", "main"))
        return {"success": True, "stdout": ""}

    monkeypatch.setattr(fingerprint.tool_runner, "run", fake_run)

    fingerprint._nuclei_scan("eng-1", "asset-1", "host.example.com", "run-1", single_port=4280)

    assert calls == ["main", "headless"]


# --- REQ-FPEFF-007: no redundant re-derivation of a purpose-built tool -----

def test_redundant_templates_are_excluded_by_id_in_both_passes():
    """Excluded by id, not by tag: both templates carry broad tags whose
    removal would drop large unrelated parts of the set."""
    for args in ({}, {"mode": "headless"}):
        extra = trc._nuclei_body("host.example.com", args)["additional_args"]
        assert "-eid " in extra, f"no id-exclusion in {args or 'main'} pass"
        for template_id in ("waf-detect", "http-missing-security-headers"):
            assert template_id in extra, f"{template_id} not excluded in {args or 'main'} pass"


def test_negative_the_exclusion_list_names_only_the_two_redundant_templates():
    """Guards against this becoming a general-purpose 'quieten nuclei' list.

    Every entry must be redundant with a tool that runs in the SAME per-host
    suite - wafw00f for WAF detection, nikto for missing security headers.
    Adding an id here without that justification silently reduces coverage.
    """
    assert trc.REDUNDANT_NUCLEI_TEMPLATE_IDS == (
        "waf-detect",
        "http-missing-security-headers",
    )


def test_negative_excluding_by_id_does_not_drop_the_tags_those_templates_share():
    """waf-detect carries `waf`; http-missing-security-headers carries
    `misconfig`. Both tags must still be REQUESTED - other templates under
    them are unaffected, which is exactly why exclusion is by id."""
    extra = trc._nuclei_body("host.example.com", {})["additional_args"]
    tags = extra.split("-tags ", 1)[1].split(" ", 1)[0]
    assert "waf" in tags.split(",")
    assert "misconfig" in tags.split(",")


# --- REQ-FPEFF-008: no time wasted on OOB templates that cannot function ---
# without internet egress -----------------------------------------------

def test_no_interactsh_is_set_in_both_passes():
    """The tool-runner has no internet egress by design, so every template
    that needs an Interactsh OOB callback fails deterministically every run.
    Measured live: without this flag, one such template alone (CVE-2023-46604)
    took 60-90s (nuclei retrying registration against 6 public interactsh.*
    servers) before giving up; with it, 2ms."""
    for args in ({}, {"mode": "headless"}):
        extra = trc._nuclei_body("host.example.com", args)["additional_args"]
        assert "-no-interactsh" in extra, f"missing in {args or 'main'} pass"
