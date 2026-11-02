"""REQ-LENS-005..008 (GitHub #88): a Lens Agent analysis is complete, bounded, budgeted and accounted for.

The regression this guards (found on a customer's host, a testssl `cert_trust` finding on port 993): the analysis stopped in the
middle of the first section, with the provider reporting `finish_reason: "length"`. #14 had raised the budget from 700 to 2000 and
added the flag, but with a reasoning model the cap also counts hidden reasoning, so about 120 visible words used all of it; and the
cut-off text was cached for good. The provider stub below is shaped like that model: it uses the budget up to a threshold on hidden
reasoning and writes the visible answer from what is left."""

from __future__ import annotations

import datetime as dt
import json

import httpx
import pytest

from app.api import findings as findings_api
from app.models.audit import AuditLog
from app.models.finding import Finding
from app.settings_store import (
    DEFAULT_LENS_MAX_TOKENS, MAX_LENS_MAX_TOKENS, MIN_LENS_MAX_TOKENS,
    get_global_lens_max_tokens, set_global_lens_max_tokens,
)
from tests.integration.test_lens_agent import COMPLETE, _seed_finding

API_KEY = "-".join(["key", "must", "never", "be", "logged", "4711"])
VISIBLE_WORDS_NEEDED = 250          # what a complete, brief analysis needs
HIDDEN_REASONING_TOKENS = 3000      # what the model spends before it writes a word


class Provider:
    """A chat-completions stub. `script` decides the answer for a given max_tokens: (text, finish_reason, usage)."""

    def __init__(self, monkeypatch, script):
        self.requests: list[dict] = []
        self.script = script
        outer = self

        class _Response:
            def __init__(self, body):
                self._body = body

            def raise_for_status(self):
                return None

            def json(self):
                return self._body

        class _Client:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def post(self, url, headers=None, json=None, **k):
                outer.requests.append({"url": url, "headers": headers, "json": json})
                result = outer.script(json["max_tokens"], len(outer.requests))
                if isinstance(result, Exception):
                    raise result
                text, finish, usage = result
                return _Response({"choices": [{"message": {"content": text}, "finish_reason": finish}], "usage": usage})

        monkeypatch.setattr(httpx, "Client", _Client)
        monkeypatch.setattr(findings_api, "get_llm_config", lambda db: type("Cfg", (), {
            "is_usable": True, "base_url": "https://llm.example.test/v1", "model": "glm-test", "api_key": API_KEY})())

    @property
    def budgets(self):
        return [r["json"]["max_tokens"] for r in self.requests]


def reasoning_model(max_tokens, call_no):
    """Spends HIDDEN_REASONING_TOKENS on reasoning first; what is left is the visible answer. Cut off if it is not enough."""
    left = max(0, max_tokens - HIDDEN_REASONING_TOKENS)
    usage = {"prompt_tokens": 900, "completion_tokens": max_tokens if left < 400 else HIDDEN_REASONING_TOKENS + 400,
             "completion_tokens_details": {"reasoning_tokens": min(max_tokens, HIDDEN_REASONING_TOKENS)}}
    if left < 400:
        return ("## What it is\nA certificate whose names do not include the name that was tested. This is a configuration issue, not a software vulnerability (no CVE/CV",
                "length", usage)
    return COMPLETE, "stop", usage


def always_cut_off(max_tokens, call_no):
    return "## What it is\nCut off in the mid", "length", {"prompt_tokens": 500, "completion_tokens": max_tokens}


def _ask(db, eng, finding):
    return findings_api.explain_finding_with_lens(eng.id, finding.id, db)


def _headings_in(text):
    return [h for h in findings_api.LENS_HEADINGS if h.lower() in text.lower()]


# --- the regression of this case ------------------------------------------------------------------------------------


def test_regression_a_reasoning_model_at_the_old_budget_still_ends_with_a_complete_analysis(db, monkeypatch):
    """Exactly #88: at 2000 tokens (the old fixed budget) the model hides 3000 tokens of reasoning and the visible text is cut
    off. The platform must retry once with a larger budget and return all four sections."""
    eng, finding = _seed_finding(db)
    set_global_lens_max_tokens(db, 2000)
    provider = Provider(monkeypatch, reasoning_model)

    out = _ask(db, eng, finding)

    assert out.truncated is False
    assert _headings_in(out.explanation) == list(findings_api.LENS_HEADINGS), "all four sections must be present"
    assert provider.budgets == [2000, 4000], "one retry with a larger budget, and no more"
    db.refresh(finding)
    assert finding.evidence["lens_agent"]["truncated"] is False


def test_the_default_budget_already_fits_this_model(db, monkeypatch):
    eng, finding = _seed_finding(db)
    provider = Provider(monkeypatch, reasoning_model)
    out = _ask(db, eng, finding)
    assert DEFAULT_LENS_MAX_TOKENS == 4096
    assert provider.budgets == [4096] and out.truncated is False


# --- a cut-off analysis is not final ----------------------------------------------------------------------------------


def test_negative_an_analysis_still_cut_off_after_the_retry_is_flagged_not_cached_as_complete_and_asked_again(db, monkeypatch):
    eng, finding = _seed_finding(db)
    provider = Provider(monkeypatch, always_cut_off)

    first = _ask(db, eng, finding)
    assert first.truncated is True
    assert len(provider.requests) == 2, "the first call and exactly one retry"
    db.refresh(finding)
    assert finding.evidence["lens_agent"]["truncated"] is True, "kept so the page shows it, but flagged"

    second = _ask(db, eng, finding)  # "Regenerate"
    assert second.source == "llm", "a second click must call the provider again, not read the cut-off text from the cache"
    assert len(provider.requests) == 4


def test_a_regenerated_analysis_replaces_the_cut_off_one(db, monkeypatch):
    eng, finding = _seed_finding(db)
    Provider(monkeypatch, always_cut_off)
    assert _ask(db, eng, finding).truncated is True
    Provider(monkeypatch, lambda max_tokens, n: (COMPLETE, "stop", {}))

    fixed = _ask(db, eng, finding)

    assert fixed.truncated is False and fixed.source == "llm" and fixed.explanation == COMPLETE
    db.refresh(finding)
    assert finding.evidence["lens_agent"]["explanation"] == COMPLETE
    assert finding.evidence["lens_agent"]["truncated"] is False


def test_a_complete_cached_analysis_makes_no_provider_call(db, monkeypatch):
    eng, finding = _seed_finding(db)
    provider = Provider(monkeypatch, lambda m, n: (COMPLETE, "stop", {}))
    _ask(db, eng, finding)
    again = _ask(db, eng, finding)
    assert again.source == "cached" and len(provider.requests) == 1


# --- at most two provider calls ----------------------------------------------------------------------------------------


def test_negative_a_request_never_makes_more_than_two_provider_calls(db, monkeypatch):
    eng, finding = _seed_finding(db)
    provider = Provider(monkeypatch, always_cut_off)
    _ask(db, eng, finding)
    assert len(provider.requests) == 2


def test_at_the_ceiling_there_is_no_larger_budget_to_retry_with(db, monkeypatch):
    eng, finding = _seed_finding(db)
    set_global_lens_max_tokens(db, MAX_LENS_MAX_TOKENS)
    provider = Provider(monkeypatch, always_cut_off)
    _ask(db, eng, finding)
    assert provider.budgets == [MAX_LENS_MAX_TOKENS], "nothing larger exists, so no pointless second call"


def test_a_failed_retry_still_returns_the_first_partial_answer_flagged(db, monkeypatch):
    eng, finding = _seed_finding(db)
    calls = []

    def script(max_tokens, n):
        calls.append(n)
        return ("## What it is\nPartial", "length", {}) if n == 1 else RuntimeError("provider timeout")

    Provider(monkeypatch, script)
    out = _ask(db, eng, finding)
    assert out.truncated is True and out.explanation.startswith("## What it is")
    assert calls == [1, 2]


# --- the backstop: no finish reason, but a section is missing ----------------------------------------------------------


@pytest.mark.parametrize("missing", list(findings_api.LENS_HEADINGS))
def test_negative_an_answer_without_one_of_the_four_headings_is_incomplete_even_if_the_provider_said_stop(db, monkeypatch, missing):
    eng, finding = _seed_finding(db)
    text = "\n\n".join(f"## {h}\nSomething." for h in findings_api.LENS_HEADINGS if h != missing)
    provider = Provider(monkeypatch, lambda m, n: (text, "stop", {}))
    out = _ask(db, eng, finding)
    assert out.truncated is True
    assert len(provider.requests) == 1, "only 'length' triggers a retry; a missing heading alone does not spend a second call"


def test_four_headings_and_a_stop_is_complete(db, monkeypatch):
    eng, finding = _seed_finding(db)
    Provider(monkeypatch, lambda m, n: (COMPLETE, "stop", {}))
    assert _ask(db, eng, finding).truncated is False


# --- precise: the prompt and the input are bounded --------------------------------------------------------------------


def test_the_prompt_sets_a_size_per_section_and_a_total(db):
    prompt = findings_api._lens_prompt({"title": "x"})
    for needle in ("two sentences at most", "one sentence", "three sentences at most", "five bullet points at most", "250 words"):
        assert needle in prompt
    for heading in findings_api.LENS_HEADINGS:
        assert heading in prompt


def test_the_real_finding_shape_gives_a_prompt_under_the_stated_bound(db):
    """The cert_trust finding of #88, through the real context builder."""
    eng, finding = _seed_finding(db)
    finding.title = "TLS: cert_trust - certificate does not match supplied URI (same w/o SNI) (imaps on port 993)"
    finding.severity = "high"
    finding.evidence = {"tool": "testssl", "id": "cert_trust", "finding": "certificate does not match supplied URI (same w/o SNI)",
                        "severity": "HIGH", "port": 993, "service": "imaps"}
    db.commit()
    context = findings_api._lens_context(findings_api._finding_out(db, finding))
    prompt = findings_api._lens_prompt(context)
    assert len(prompt) < 2500, f"the prompt for a normal finding is {len(prompt)} characters"


def test_negative_a_huge_evidence_object_is_cut_to_a_bound_and_the_earlier_analysis_is_left_out(db):
    eng, finding = _seed_finding(db)
    finding.evidence = {
        "tool": "nuclei",
        "raw": "A" * 400_000,
        "hits": [{"url": f"https://app.example.com/{i}", "body": "B" * 5000} for i in range(500)],
        "nested": {"deep": {"blob": "C" * 100_000}},
        "lens_agent": {"explanation": "THE EARLIER CUT-OFF TEXT", "truncated": True},
    }
    db.commit()
    context = findings_api._lens_context(findings_api._finding_out(db, finding))
    evidence_json = json.dumps(context["evidence"], sort_keys=True)
    assert len(evidence_json) <= findings_api.LENS_EVIDENCE_BUDGET_CHARS
    assert "THE EARLIER CUT-OFF TEXT" not in json.dumps(context), "the previous analysis must not be fed back into the prompt"
    assert context["evidence"].get("tool") == "nuclei" or "nuclei" in evidence_json, "the facts survive the trimming"


def test_a_small_evidence_object_is_passed_unchanged(db):
    eng, finding = _seed_finding(db)
    context = findings_api._lens_context(findings_api._finding_out(db, finding))
    assert context["evidence"] == {"tool": "nikto", "missing_headers": ["content-security-policy"]}


# --- the budget is a global setting ----------------------------------------------------------------------------------------


def test_the_setting_has_the_stated_default_and_range(db):
    assert (DEFAULT_LENS_MAX_TOKENS, MIN_LENS_MAX_TOKENS, MAX_LENS_MAX_TOKENS) == (4096, 1024, 16384)
    assert get_global_lens_max_tokens(db) == 4096
    assert set_global_lens_max_tokens(db, 6000) == 6000
    assert get_global_lens_max_tokens(db) == 6000


@pytest.mark.parametrize("bad", [0, 100, 1023, 16385, 99999])
def test_negative_a_value_outside_the_range_is_refused(db, bad):
    with pytest.raises(ValueError):
        set_global_lens_max_tokens(db, bad)
    assert get_global_lens_max_tokens(db) == 4096


@pytest.mark.parametrize("stored", ["abc", None, 50, 10**9, {"nested": 1}])
def test_negative_a_corrupt_stored_value_falls_back_to_the_default(db, stored):
    from app.models.app_setting import AppSetting
    from app.settings_store import LENS_MAX_TOKENS_KEY

    db.merge(AppSetting(key=LENS_MAX_TOKENS_KEY, value={"value": stored}))
    db.commit()
    assert get_global_lens_max_tokens(db) == DEFAULT_LENS_MAX_TOKENS


def test_the_budget_sent_to_the_provider_is_the_setting(db, monkeypatch):
    eng, finding = _seed_finding(db)
    set_global_lens_max_tokens(db, 7000)
    provider = Provider(monkeypatch, lambda m, n: (COMPLETE, "stop", {}))
    _ask(db, eng, finding)
    assert provider.budgets == [7000]


# --- accounted for -----------------------------------------------------------------------------------------------------------


def test_the_audit_event_carries_the_token_counts_and_never_the_key(db, monkeypatch):
    eng, finding = _seed_finding(db)
    set_global_lens_max_tokens(db, 2000)
    Provider(monkeypatch, reasoning_model)
    _ask(db, eng, finding)
    row = db.query(AuditLog).filter(AuditLog.engagement_id == eng.id, AuditLog.actor == "lens_agent").one()
    payload = row.payload
    assert payload["attempts"] == 2 and payload["max_tokens"] == [2000, 4000]
    assert payload["prompt_tokens"] == 1800 and payload["completion_tokens"] > 0
    assert payload["reasoning_tokens"] == 2000 + 3000, "the hidden reasoning is reported, so the cause of a cut-off is visible"
    assert API_KEY not in json.dumps(payload) and API_KEY not in json.dumps(row.payload, default=str)
    assert API_KEY not in (row.reason or "")


def test_a_provider_that_reports_no_usage_still_works(db, monkeypatch):
    eng, finding = _seed_finding(db)
    Provider(monkeypatch, lambda m, n: (COMPLETE, "stop", None))
    out = _ask(db, eng, finding)
    assert out.truncated is False
    row = db.query(AuditLog).filter(AuditLog.engagement_id == eng.id, AuditLog.actor == "lens_agent").one()
    assert "prompt_tokens" not in row.payload and row.payload["attempts"] == 1


def test_a_failed_request_saves_nothing_and_can_be_repeated(db, monkeypatch):
    eng, finding = _seed_finding(db)
    Provider(monkeypatch, lambda m, n: RuntimeError("down"))
    with pytest.raises(Exception):
        _ask(db, eng, finding)
    db.refresh(finding)
    assert "lens_agent" not in (finding.evidence or {})
