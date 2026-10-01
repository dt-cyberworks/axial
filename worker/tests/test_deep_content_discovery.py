"""TC-PIPE-017/018 (worker half): the thorough profile's deep content-discovery
sweep and its wordlist-sized budget, and what the Vector Agent is told about the
checks the pipeline already ran and about a sweep its time limit cut short."""

from __future__ import annotations

import json
import types

import pytest

from app import planner
from app import tool_runner_client as trc
from app.planner import IndexInfo, Options, SurfaceInput, plan_surface
from app.tasks import agent, dispatch, fingerprint

EID = "11111111-1111-1111-1111-111111111111"


def _web(**over):
    return SurfaceInput(host="h.example", port=443, service_class="web", scheme="https", **over)


def _by_id(checks):
    return {c.check_id: c for c in checks}


THOROUGH = Options(scan_profile="thorough")


# --- REQ-PIPE-017: the plan ---------------------------------------------------------------

def test_req_pipe_017_thorough_plans_the_deep_sweep_after_the_quickhits_check():
    checks = plan_surface(_web(), THOROUGH, IndexInfo())
    ids = [c.check_id for c in checks if c.state == "planned"]
    deep = _by_id(checks)["ffuf:deep"]
    assert (deep.tool, deep.state, deep.args) == ("ffuf", "planned", {"wordlist": "raft-medium-dirs"})
    assert deep.reason == "thorough:deep_content_discovery"
    assert ids.index("ffuf") < ids.index("nuclei:takeover") < ids.index("ffuf:deep"), (
        "cheap and nuclei checks first, the 25-minute sweep after them")
    assert _by_id(checks)["ffuf"].args == {"wordlist": "quickhits"}, "the baseline check stays"


def test_req_pipe_017_the_standard_profile_plans_no_deep_sweep():
    checks = plan_surface(_web(), Options(scan_profile="standard", crawling=True, screenshots=True), IndexInfo())
    assert "ffuf:deep" not in _by_id(checks)


def test_req_pipe_017_the_deep_sweep_declares_a_budget_that_fits_its_list():
    deep = _by_id(plan_surface(_web(), THOROUGH, IndexInfo()))["ffuf:deep"]
    assert deep.budget_s == trc.ffuf_budget_s("raft-medium-dirs")
    assert deep.budget_s - trc._INNER_MARGIN_S >= trc.FFUF_WORDLIST_ENTRIES["raft-medium-dirs"] / trc.FFUF_RATE_RPS
    assert deep.budget_s <= trc.RUNNER_MAX_BUDGET_S


def test_negative_req_pipe_017_no_deep_sweep_where_no_deep_check_runs():
    dup = _by_id(plan_surface(_web(duplicate_of="a.example"), THOROUGH, IndexInfo()))
    assert (dup["ffuf:deep"].state, dup["ffuf:deep"].reason) == ("skipped", "duplicate_vhost_of:a.example")
    alias = _by_id(plan_surface(SurfaceInput("h.example", 80, "web_alias", "http", alias_of="h.example:443"),
                                THOROUGH, IndexInfo()))
    assert (alias["ffuf:deep"].state, alias["ffuf:deep"].reason) == ("skipped", "web_alias_of:h.example:443")
    for surface in (SurfaceInput("h", 25, "tls_service", starttls="smtp"), SurfaceInput("h", 22, "service"),
                    SurfaceInput("h", 9, "unknown")):
        assert "ffuf:deep" not in _by_id(plan_surface(surface, THOROUGH, IndexInfo())), surface.service_class


def test_negative_req_pipe_017_a_campaign_that_switched_ffuf_off_skips_both_ffuf_checks():
    checks = _by_id(plan_surface(_web(), Options(scan_profile="thorough", disabled_tools=frozenset({"ffuf"})), IndexInfo()))
    for cid in ("ffuf", "ffuf:deep"):
        assert (checks[cid].state, checks[cid].reason) == ("skipped", "tool_disabled"), cid


def test_req_pipe_017_every_planned_ffuf_check_uses_an_allowlisted_wordlist_key():
    for profile in ("standard", "thorough"):
        for c in plan_surface(_web(), Options(scan_profile=profile), IndexInfo()):
            if c.tool == "ffuf" and c.state == "planned":
                assert set(c.args) == {"wordlist"} and c.args["wordlist"] in trc.FFUF_WORDLISTS, (profile, c.check_id)


# --- REQ-PIPE-017: the budget --------------------------------------------------------------

def test_req_pipe_017_the_budget_table_covers_exactly_the_allowed_wordlists():
    assert set(trc.FFUF_WORDLIST_ENTRIES) == set(trc.FFUF_WORDLISTS)


def test_req_pipe_017_the_gateway_and_the_worker_agree_on_the_wordlist_keys():
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[2] / "control-plane/app/gateway/args_safety.py").read_text()
    namespace: dict = {}
    start = src.index("_FFUF_WORDLISTS = {")
    exec(src[start:src.index("}", start) + 1], namespace)  # a literal set, nothing else
    assert namespace["_FFUF_WORDLISTS"] == set(trc.FFUF_WORDLISTS)


def test_req_pipe_017_a_whole_pass_fits_the_budget_of_every_list_that_can_fit_the_maximum():
    for key, entries in trc.FFUF_WORDLIST_ENTRIES.items():
        budget = trc.ffuf_budget_s(key)
        assert trc.CHECK_BUDGET_S["ffuf"] <= budget <= trc.RUNNER_MAX_BUDGET_S, key
        if entries / trc.FFUF_RATE_RPS + trc._FFUF_SETUP_S + trc._INNER_MARGIN_S <= trc.RUNNER_MAX_BUDGET_S:
            assert budget - trc._INNER_MARGIN_S >= entries / trc.FFUF_RATE_RPS, key


def test_req_pipe_017_the_budget_of_a_list_larger_than_the_maximum_is_the_maximum_never_more():
    assert trc.ffuf_budget_s("directory-list-medium") == trc.RUNNER_MAX_BUDGET_S


def test_negative_req_pipe_017_candidates_an_unknown_key_or_no_list_keep_the_fixed_floor():
    floor = trc.CHECK_BUDGET_S["ffuf"]
    assert trc.ffuf_budget_s("raft-medium-dirs", has_candidates=True) == floor
    assert trc.ffuf_budget_s("not-a-list") == floor
    assert trc.ffuf_budget_s(None) == floor
    assert trc.ffuf_budget_s("quickhits") == floor, "the baseline check keeps its 240 s"


def test_req_pipe_017_check_budget_s_sizes_ffuf_by_its_wordlist_but_honours_an_override():
    assert trc.check_budget_s("ffuf", {"wordlist": "raft-medium-dirs"}) == trc.ffuf_budget_s("raft-medium-dirs")
    assert trc.check_budget_s("ffuf", {"wordlist": "raft-medium-dirs"}, override=240) == 240
    assert trc.check_budget_s("ffuf", {"wordlist": "raft-medium-dirs"}, override=99999) == trc.RUNNER_MAX_BUDGET_S


def test_req_pipe_017_ffuf_is_told_a_deadline_that_lets_the_whole_list_finish():
    budget = trc.check_budget_s("ffuf", {"wordlist": "raft-medium-dirs"})
    command = trc._ffuf_command("https://h.example", {"wordlist": "raft-medium-dirs", "_budget_s": budget})
    tokens = command.split()
    maxtime = int(tokens[tokens.index("-maxtime") + 1])
    assert maxtime >= trc.FFUF_WORDLIST_ENTRIES["raft-medium-dirs"] / trc.FFUF_RATE_RPS
    assert "raft-medium-directories.txt" in command
    assert tokens[tokens.index("-rate") + 1] == str(trc.FFUF_RATE_RPS)


def test_negative_req_pipe_017_a_bug_bounty_cap_still_only_lowers_the_rate():
    command = trc._ffuf_command("https://h.example", {"wordlist": "raft-medium-dirs", "_budget_s": 1700, "_bounty_max_rps": 5})
    tokens = command.split()
    assert tokens[tokens.index("-rate") + 1] == "5"
    command = trc._ffuf_command("https://h.example", {"wordlist": "raft-medium-dirs", "_budget_s": 1700, "_bounty_max_rps": 500})
    assert command.split()[command.split().index("-rate") + 1] == str(trc.FFUF_RATE_RPS)


# --- REQ-PIPE-017: the check ---------------------------------------------------------------

def _check_run(args):
    return types.SimpleNamespace(engagement_id=EID, asset_id="a1", host="h.example", scan_run_id="run-1",
                                 single_port=None, protocol="https", check={"tool": "ffuf", "args": args})


@pytest.mark.parametrize("args, expected", [
    ({"wordlist": "raft-medium-dirs"}, {"wordlist": "raft-medium-dirs"}),
    ({"wordlist": "quickhits"}, {}),
    ({}, {}),
    ({"wordlist": "../../etc/passwd"}, {}),
    ({"wordlist": ["raft-medium-dirs"]}, {}),
])
def test_req_pipe_017_the_handler_uses_the_stored_wordlist_only_when_the_runner_knows_it(monkeypatch, args, expected):
    seen = {}
    monkeypatch.setattr(fingerprint, "_content_discovery", lambda *a, **k: seen.update(k))
    fingerprint._h_ffuf(_check_run(args))
    assert {k: v for k, v in seen.items() if k == "wordlist"} == expected


def test_req_pipe_017_both_ffuf_checks_resolve_to_the_same_handler():
    assert fingerprint.resolve_handler({"tool": "ffuf", "check_id": "ffuf:deep", "args": {"wordlist": "raft-medium-dirs"}}) \
        is fingerprint.resolve_handler({"tool": "ffuf", "check_id": "ffuf", "args": {"wordlist": "quickhits"}})


def _stub_discovery(monkeypatch, result, hits):
    calls, findings = [], []

    def fake_run(tool, target, args, scan_run_id=None, engagement_id=None, **kw):
        calls.append((tool, dict(args)))
        return result

    monkeypatch.setattr(fingerprint.tool_runner, "run", fake_run)
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint, "parse_ffuf_json", lambda s: hits)
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda eid, **kw: findings.append(kw) or {"id": "f"})
    return calls, findings


HITS = [{"word": "admin", "url": "https://h.example/admin", "status": 200, "length": 512},
        {"word": "backup", "url": "https://h.example/backup", "status": 403, "length": 199}]


def test_req_pipe_017_the_deep_sweep_reports_one_inferred_finding_naming_its_wordlist(monkeypatch):
    calls, findings = _stub_discovery(monkeypatch, {"success": True, "stdout": "{}"}, HITS)
    fingerprint._content_discovery(EID, "a1", "h.example", "run-1", None, "https", wordlist="raft-medium-dirs")
    assert calls == [("ffuf", {"wordlist": "raft-medium-dirs"})]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"].endswith("(raft-medium-dirs)") and finding["confidence"] == "inferred"
    assert finding["evidence"]["wordlist"] == "raft-medium-dirs"


def test_req_pipe_017_a_sweep_cut_short_by_its_budget_keeps_and_reports_its_hits(monkeypatch):
    partial = {"success": False, "error_reason": "budget_reached", "stdout": "{}"}
    _, findings = _stub_discovery(monkeypatch, partial, HITS)
    fingerprint._content_discovery(EID, "a1", "h.example", "run-1", None, "https", wordlist="raft-medium-dirs")
    assert len(findings) == 1 and len(findings[0]["evidence"]["hits"]) == 2


def test_negative_req_pipe_017_a_failed_sweep_reports_no_finding(monkeypatch):
    failed = {"success": False, "error_reason": "runner_error", "stdout": ""}
    _, findings = _stub_discovery(monkeypatch, failed, HITS)
    fingerprint._content_discovery(EID, "a1", "h.example", "run-1", None, "https", wordlist="raft-medium-dirs")
    assert findings == []


def test_req_pipe_017_a_catch_all_answer_is_still_discarded(monkeypatch):
    same = [{"word": f"w{i}", "url": f"https://h.example/w{i}", "status": 200, "length": 396} for i in range(40)]
    _, findings = _stub_discovery(monkeypatch, {"success": True, "stdout": "{}"}, same)
    fingerprint._content_discovery(EID, "a1", "h.example", "run-1", None, "https", wordlist="raft-medium-dirs")
    assert findings == []


# --- REQ-PIPE-018: what the agent is told -----------------------------------------------------

def _agent_ffuf(monkeypatch, result, hits_json="{}", args=None):
    seen = {}

    def fake_run(tool, target, args, scan_run_id=None, engagement_id=None, **kw):
        seen["budget_s"] = kw.get("budget_s")
        return result

    monkeypatch.setattr(dispatch.tool_runner, "run", fake_run)
    monkeypatch.setattr(dispatch.tool_execution, "record", lambda *a, **k: None)
    obs = dispatch.dispatch("eid", "asset-1", "ffuf", "h.example",
                            args=args or {"wordlist": "raft-medium-dirs", "path": "/FUZZ"})
    return obs.as_text(), seen


FFUF_JSON = json.dumps({"results": [
    {"input": {"FUZZ": "admin"}, "status": 200, "length": 512, "words": 30, "url": "https://h.example/admin"},
    {"input": {"FUZZ": "backup"}, "status": 403, "length": 199, "words": 5, "url": "https://h.example/backup"},
]})


def test_req_pipe_018_a_sweep_stopped_by_its_limit_returns_its_hits_marked_partial(monkeypatch):
    """The defect found on int: this used to read 'no hits' and drop the output."""
    text, _ = _agent_ffuf(monkeypatch, {"success": False, "error_reason": "budget_reached", "exit_code": 0,
                                        "stdout": FFUF_JSON, "duration_s": 219.9})
    assert "2 hits" in text and "/admin" in text and "/backup" in text
    assert "PARTIAL" in text
    assert "no hits" not in text


def test_req_pipe_018_the_partial_note_gives_an_upper_bound_of_the_list_tried(monkeypatch):
    text, _ = _agent_ffuf(monkeypatch, {"success": False, "error_reason": "budget_reached", "exit_code": 0,
                                        "stdout": FFUF_JSON, "duration_s": 219.9})
    assert "4,398 of 29,999" in text and "15%" in text and "NOT a complete pass" in text
    assert "thorough" in text


def test_req_pipe_018_a_partial_sweep_with_no_hits_says_so_instead_of_claiming_absence(monkeypatch):
    text, _ = _agent_ffuf(monkeypatch, {"success": False, "error_reason": "budget_reached", "exit_code": 0,
                                        "stdout": '{"results": []}', "duration_s": 220.0})
    assert text.startswith("[ffuf h.example] content-discovery: no hits")
    assert "PARTIAL" in text


def test_req_pipe_018_a_partial_run_with_the_agents_own_candidates_makes_no_list_claim(monkeypatch):
    text, _ = _agent_ffuf(monkeypatch, {"success": False, "error_reason": "budget_reached", "exit_code": 0,
                                        "stdout": FFUF_JSON, "duration_s": 220.0},
                          args={"path": "/FUZZ", "extra_candidates": ["admin", "backup"]})
    assert "PARTIAL" in text and "entries of" not in text


def test_req_pipe_018_a_complete_sweep_carries_no_partial_note(monkeypatch):
    text, _ = _agent_ffuf(monkeypatch, {"success": True, "exit_code": 0, "stdout": FFUF_JSON, "duration_s": 128.0},
                          args={"wordlist": "quickhits", "path": "/FUZZ"})
    assert "2 hits" in text and "PARTIAL" not in text


def test_negative_req_pipe_018_a_failed_run_reports_no_hits_and_no_partial_claim(monkeypatch):
    text, _ = _agent_ffuf(monkeypatch, {"success": False, "error_reason": "runner_error", "exit_code": -1,
                                        "stdout": FFUF_JSON, "duration_s": 3.0})
    assert "no hits" in text and "PARTIAL" not in text


def test_req_pipe_018_the_agents_ffuf_keeps_its_interactive_cap_whatever_list_it_names(monkeypatch):
    _, seen = _agent_ffuf(monkeypatch, {"success": True, "exit_code": 0, "stdout": "{}", "duration_s": 5})
    assert seen["budget_s"] == trc.CHECK_BUDGET_S["ffuf"] == dispatch.AGENT_FFUF_BUDGET_S == 240


# --- REQ-PIPE-018: the evidence block ---------------------------------------------------------

def _checks():
    return [
        {"port": 80, "check_id": "wafw00f", "tool": "wafw00f", "state": "skipped", "reason": "web_alias_of:h.example:443"},
        {"port": 80, "check_id": "ffuf", "tool": "ffuf", "state": "skipped", "reason": "web_alias_of:h.example:443"},
        {"port": 443, "check_id": "wafw00f", "tool": "wafw00f", "state": "complete"},
        {"port": 443, "check_id": "testssl", "tool": "testssl", "state": "complete"},
        {"port": 443, "check_id": "ffuf", "tool": "ffuf", "state": "complete", "wordlist": "quickhits"},
        {"port": 443, "check_id": "ffuf:deep", "tool": "ffuf", "state": "partial", "wordlist": "raft-medium-dirs"},
        {"port": 443, "check_id": "nuclei:generic:1of5", "tool": "nuclei", "state": "complete"},
        {"port": 443, "check_id": "nuclei:generic:2of5", "tool": "nuclei", "state": "complete"},
        {"port": 443, "check_id": "nuclei:takeover", "tool": "nuclei", "state": "failed"},
        {"port": 443, "check_id": "screenshot", "tool": "screenshot", "state": "skipped", "reason": "switch_off"},
    ]


def test_req_pipe_018_the_evidence_lists_what_ran_per_port_with_the_wordlist_and_outcome():
    text = "\n".join(agent._render_pipeline_checks(_checks()))
    assert "do not repeat a completed check with the same tool and wordlist" in text
    assert "ffuf[quickhits]=complete" in text
    assert "ffuf:deep[raft-medium-dirs]=partial" in text
    assert "nuclei x2=complete" in text and "nuclei x1=failed" in text
    assert "wafw00f=complete" in text and "testssl=complete" in text


def test_req_pipe_018_a_redirect_only_port_says_where_its_coverage_lives_and_lists_no_checks():
    lines = agent._render_pipeline_checks(_checks())
    port80 = next(line for line in lines if "port 80" in line)
    assert "redirect to h.example:443" in port80 and "ffuf" not in port80


def test_req_pipe_018_skipped_switch_offs_are_not_listed_as_done():
    text = "\n".join(agent._render_pipeline_checks(_checks()))
    assert "screenshot" not in text


def test_req_pipe_018_no_checks_adds_nothing_to_the_evidence():
    assert agent._render_pipeline_checks([]) == []
    assert agent._render_pipeline_checks([{"port": 80, "check_id": "ffuf", "tool": "ffuf", "state": "skipped",
                                           "reason": "switch_off"}]) == []


def test_req_pipe_018_the_evidence_block_renders_the_checks_of_the_host(monkeypatch):
    ctx = {"hosts": [{"host": "h.example", "services": [], "findings": [], "checks": _checks()}]}
    text = agent._render_evidence(EID, {"h.example": "a1"}, ctx)
    assert "Pipeline checks already run" in text and "ffuf[quickhits]=complete" in text


def test_req_pipe_018_an_older_control_plane_without_checks_still_renders():
    ctx = {"hosts": [{"host": "h.example", "services": [], "findings": []}]}
    assert "Pipeline checks" not in agent._render_evidence(EID, {"h.example": "a1"}, ctx)


def test_req_pipe_018_the_prompt_and_the_tool_description_tell_the_agent_not_to_repeat_the_baseline():
    from pathlib import Path
    prompt = (Path(__file__).resolve().parents[2] / "control-plane/app/default_prompts.py").read_text()
    assert "Do not repeat a completed check with the same tool and wordlist" in prompt
    assert "thorough" in prompt and "PARTIAL" in prompt
    spec = next(t for t in agent._TOOLS if t["function"]["name"] == "content_discovery")
    assert "quickhits baseline" in spec["function"]["description"]

