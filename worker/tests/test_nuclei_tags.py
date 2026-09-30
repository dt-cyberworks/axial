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

import pytest

from app import tool_runner_client as trc


# --- Main (non-headless) pass: a selection from the template index -----------
# REQ-PIPE-004: the main pass is `mode: select` (a shell command that resolves the
# selection against the image's index). Everything the former single main pass
# guaranteed about its invocation is asserted on that command.

def _select(**over):
    args = {"mode": "select", "group": "generic", "shard": "1/1", **over}
    return trc._nuclei_command("host.example.com", args)


def _select_tags(command: str) -> list[str]:
    return command.split("-tags ", 1)[1].split(" ", 1)[0].split(",")


def test_main_pass_includes_dast_tag():
    assert "dast" in _select_tags(_select())


def test_takeover_pass_runs_the_takeover_tag_and_the_main_pass_does_not():
    """REQ-COVER-002: service fingerprints for dangling CNAMEs, in a pass of
    their own - live 2026-09-29 the main pass plus this tag exceeded HexStrike's
    hard 300s command limit (nonzero_exit)."""
    def tags(args):
        body = trc._nuclei_body("host.example.com", args)
        return [t.strip() for t in body["additional_args"].split("-tags", 1)[1].split("-severity", 1)[0].split(",")]
    assert tags({"mode": "takeover"}) == ["takeover"]
    assert "takeover" not in _select_tags(_select())
    take = trc._nuclei_body("host.example.com", {"mode": "takeover"})["additional_args"]
    assert "-etags intrusive,dos,fuzz,csp-bypass" in take and "-headless" not in take


def test_negative_takeover_does_not_relax_the_exclusions_or_leak_into_the_headless_pass():
    assert "-etags intrusive,dos,fuzz,csp-bypass" in _select()
    headless = trc._nuclei_body("host.example.com", {"mode": "headless"})["additional_args"]
    assert "takeover" not in headless


def test_main_pass_is_not_headless():
    command = _select()
    assert "-headless" not in command
    assert "domxss" not in command


def test_main_pass_still_excludes_intrusive_dos_fuzz_and_csp_bypass():
    etags_part = _select().split("-etags", 1)[1]
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


def test_all_passes_disable_hexstrike_cache(monkeypatch):
    for args in ({"mode": "tech"}, {"mode": "headless"}, {"mode": "takeover"}):
        assert trc._nuclei_body("host.example.com", args)["use_cache"] is False
    # The select pass is a generic /api/command call, which run() always sends uncached.
    sent = {}

    class R:
        def raise_for_status(self):
            return None

        def json(self):
            return {"stdout": "", "return_code": 0, "success": True}

    monkeypatch.setattr(trc.ToolRunnerClient, "_post_cancellable",
                        lambda self, path, payload, run_id, budget_s=None: sent.update(path=path, payload=payload) or R())
    trc.tool_runner.run("nuclei", "https://host.example.com", {"mode": "select", "group": "generic", "shard": "1/2"})
    assert sent["path"] == "/api/command" and sent["payload"]["use_cache"] is False


# --- the plan runs the selection, then headless, then takeover ------------------

def test_the_plan_runs_selection_then_headless_then_takeover():
    """REQ-AGENT-018: nuclei's passes are separate calls - the selection (a few
    shards, then the product templates), the tiny headless domxss pass and the
    takeover pass - each with its own budget."""
    from app.planner import Options, SurfaceInput, plan_surface

    checks = plan_surface(SurfaceInput("h.example", 443, "web", "https", ("nginx",)), Options())
    nuclei = [c.check_id for c in checks if c.tool == "nuclei" and c.state == "planned"]
    generic = [c for c in nuclei if c.startswith("nuclei:generic:")]
    assert nuclei == ["nuclei:tech", *generic, "nuclei:products", "nuclei:headless", "nuclei:takeover"]


# --- REQ-FPEFF-007: no redundant re-derivation of a purpose-built tool -----

def test_redundant_templates_are_excluded_by_id_in_every_pass():
    """Excluded by id, not by tag: both templates carry broad tags whose
    removal would drop large unrelated parts of the set."""
    commands = [_select()] + [
        trc._nuclei_body("host.example.com", {"mode": m})["additional_args"] for m in ("tech", "headless", "takeover")
    ]
    for extra in commands:
        assert "-eid " in extra
        for template_id in ("waf-detect", "http-missing-security-headers"):
            assert template_id in extra, f"{template_id} not excluded"


def test_negative_the_exclusion_list_names_only_the_two_redundant_templates():
    """Guards against this becoming a general-purpose 'quieten nuclei' list.

    Every entry must be redundant with a tool that runs in the SAME per-host
    suite - wafw00f for WAF detection, the httpx header check for missing
    security headers (REQ-PIPE-013). Adding an id here without that
    justification silently reduces coverage.
    """
    assert trc.REDUNDANT_NUCLEI_TEMPLATE_IDS == (
        "waf-detect",
        "http-missing-security-headers",
    )


def test_negative_excluding_by_id_does_not_drop_the_tags_those_templates_share():
    """waf-detect carries `waf`; http-missing-security-headers carries
    `misconfig`. Both tags must still be REQUESTED - other templates under
    them are unaffected, which is exactly why exclusion is by id."""
    tags = _select_tags(_select())
    assert "waf" in tags
    assert "misconfig" in tags


# --- REQ-FPEFF-008: no time wasted on OOB templates that cannot function ---
# without internet egress -----------------------------------------------

def test_no_interactsh_is_set_in_every_pass():
    """The tool-runner has no internet egress by design, so every template
    that needs an Interactsh OOB callback fails deterministically every run.
    Measured live: without this flag, one such template alone (CVE-2023-46604)
    took 60-90s (nuclei retrying registration against 6 public interactsh.*
    servers) before giving up; with it, 2ms."""
    commands = [_select()] + [
        trc._nuclei_body("host.example.com", {"mode": m})["additional_args"] for m in ("tech", "headless", "takeover")
    ]
    for extra in commands:
        assert "-no-interactsh" in extra


# --- REQ-PIPE-004: selection arguments ------------------------------------------

def test_the_main_pass_can_only_be_asked_for_through_the_selection_command():
    with pytest.raises(ValueError):
        trc._nuclei_body("host.example.com", {})
    with pytest.raises(ValueError):
        trc._nuclei_body("host.example.com", {"mode": "select", "group": "generic"})


def test_every_selection_keeps_the_conservative_invocation():
    for args in (
        {"group": "generic", "shard": "2/5"}, {"group": "all", "shard": "1/15"},
        {"group": "products", "products": ["nextcloud", "nginx"]},
    ):
        command = _select(**args)
        assert "-etags intrusive,dos,fuzz,csp-bypass" in command
        assert "-no-interactsh" in command and "-eid " in command and "-rate-limit" in command
        assert "-tags cve,misconfig,exposure,exposures,default-login,waf,dast" in command
        assert "nuclei_index.py select" in command


def test_a_selection_resolves_through_the_index_and_runs_nothing_when_it_is_empty():
    command = _select(group="products", products=["nextcloud"])
    assert "--group products" in command and "--products nextcloud" in command
    assert "-s /tmp/nuclei-sel-" in command and "exit 0" in command


@pytest.mark.parametrize("bad", [
    {"group": "everything"}, {"group": "../../etc"}, {"group": None},
    {"group": "generic", "shard": "0/3"}, {"group": "generic", "shard": "4/3"}, {"group": "generic", "shard": "1/65"},
    {"group": "generic", "shard": "1/3; id"}, {"group": "generic", "shard": "a/b"},
    {"group": "products"}, {"group": "products", "products": []}, {"group": "products", "products": "nginx"},
    {"group": "products", "products": ["ng inx"]}, {"group": "products", "products": ["a;id"]},
    {"group": "products", "products": ["$(id)"]}, {"group": "products", "products": ["../x"]},
    {"group": "products", "products": [f"p{i}" for i in range(25)]}, {"group": "products", "products": ["N"]},
    {"group": "generic", "products": ["nginx"]},
])
def test_negative_a_malformed_selection_never_becomes_a_command(bad):
    with pytest.raises(ValueError):
        trc._nuclei_command("host.example.com", {"mode": "select", **bad})


def test_the_selection_tag_set_matches_the_template_index():
    """The index in the runner image is built from the same tags, exclusions and
    directories as the flags above; if either changes alone, the selection
    would silently stop matching what nuclei runs."""
    import importlib.util
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[2] / "tool-runner" / "nuclei_index.py"
    spec = importlib.util.spec_from_file_location("nuclei_index_under_test", path)
    index = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(index)
    assert set(trc._ALL_TAGS.split(",")) == set(index.SELECTION_TAGS)
    assert set(trc.REDUNDANT_NUCLEI_TEMPLATE_IDS) == set(index.EXCLUDED_IDS)
    assert set(index.EXCLUDED_TAGS) == {"intrusive", "dos", "fuzz", "csp-bypass"}
    assert set(index.NEVER_ON_WEB_DIRS) == {"network", "javascript"}
    assert trc.NUCLEI_INDEX_TOOL == "/opt/asm/nuclei_index.py"
    assert trc.MAX_SELECT_PRODUCTS == index.MAX_PRODUCTS


def test_partial_hits_survive_a_timed_out_pass(monkeypatch):
    """A nuclei pass killed at its budget still printed real matches; they
    become findings while the pass is recorded as not complete."""
    from app.tasks import fingerprint

    recorded, findings = [], []
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k["result"]))
    hit = {"category": "x", "title": "t", "severity": "high", "cve_ids": [], "cvss_base": None,
           "template_id": "tpl", "matched_at": "https://h"}
    monkeypatch.setattr(fingerprint, "parse_nuclei_jsonl", lambda stdout: [hit] if stdout else [])
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: findings.append(k))
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {
        "success": False, "error_reason": "nonzero_exit", "stdout": "{}", "timed_out": True})

    fingerprint._nuclei_pass("e", "a", "h", "https://h", {"mode": "select", "group": "generic"}, "r", None)

    assert len(findings) == 1
    assert recorded[0]["success"] is False
