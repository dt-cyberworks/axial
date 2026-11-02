"""REQ-RETEST-009: the agent is told what was wrong with its ffuf arguments.

Found live on int (2026-10-20): one of 21 `extra_candidates` was " Procfile" (a leading space), the gateway's strict
validator refused the whole proposal with a bare `unsafe_arguments`, and the agent could not tell what to change.
"""

from __future__ import annotations

from app import agent_args
from app.tasks import agent

PROPOSED_ON_INT = [
    ".git", ".git/config", ".git/HEAD", ".env", ".env.local", "config.py", "config.json", "settings.py", "backup",
    "backup.zip", "db.sqlite", "app.py", "Dockerfile", "docker-compose.yml", "requirements.txt", " Procfile", "debug",
    "console", "admin", "robots.txt", "sitemap.xml",
]


def test_whitespace_around_an_entry_is_removed_and_empty_entries_dropped():
    cleaned = agent_args.normalize_ffuf_args({"extra_candidates": [" Procfile", "admin ", "  ", ""], "extensions": [" php"]})
    assert cleaned["extra_candidates"] == ["Procfile", "admin"]
    assert cleaned["extensions"] == ["php"]
    assert agent_args.describe_ffuf_problem({"wordlist": "common", "path": "/FUZZ", **cleaned}) is None


def test_the_proposal_from_int_passes_after_normalizing():
    raw = {"path": "/FUZZ", "wordlist": "common", "extensions": [], "extra_candidates": PROPOSED_ON_INT}
    assert agent_args.describe_ffuf_problem(raw) is not None
    assert agent_args.describe_ffuf_problem(agent_args.normalize_ffuf_args(raw)) is None


def test_the_problem_names_the_argument_and_the_rule():
    text = agent_args.describe_ffuf_problem({"extra_candidates": ["ok", "a b"]})
    assert "extra_candidates" in text and "'a b'" in text and "no spaces" in text
    assert "wordlist" in agent_args.describe_ffuf_problem({"wordlist": "/etc/passwd"})
    assert "FUZZ" in agent_args.describe_ffuf_problem({"path": "/nothing-to-fuzz"})
    assert "extensions" in agent_args.describe_ffuf_problem({"extensions": ["php;id"]})
    assert "not allowed" in agent_args.describe_ffuf_problem({"headers": {"X": "y"}})


def test_negative_metacharacters_are_never_normalized_away():
    # Only whitespace at the edges is harmless. Anything else stays and is still refused.
    for bad in ("a;b", "$(id)", "a|b", "`id`", "x\ny", "a\tb", "a b"):
        cleaned = agent_args.normalize_ffuf_args({"extra_candidates": [bad]})
        assert cleaned["extra_candidates"] == [bad], bad
        problem = agent_args.describe_ffuf_problem({"extra_candidates": cleaned["extra_candidates"]})
        assert problem is not None and "extra_candidates" in problem, bad


def test_the_handler_sends_the_normalized_arguments_and_returns_the_reason_text(monkeypatch):
    sent: list[dict] = []

    def fake_authorize(engagement_id, payload, proposal, context):
        sent.append(payload)
        return {"allowed": False, "reason": "unsafe_arguments"}

    monkeypatch.setattr(agent, "_authorize_throttled", fake_authorize)
    monkeypatch.setattr(agent, "_audit_agent_event", lambda *a, **k: None)
    context = agent.SimpleContext(scan_run_id="r1")

    text = agent._handle_ffuf(
        "e1", {"target": "example.org", "path": "/FUZZ", "wordlist": "common", "extra_candidates": [" Procfile", "a b"]},
        {"example.org": "asset-1"}, {}, context,
    )
    assert sent[0]["args"]["extra_candidates"] == ["Procfile", "a b"]  # the stray space went, the real problem stayed
    assert text.startswith("DENIED by the Scope Gateway: unsafe_arguments.")
    assert "'a b'" in text and "propose again" in text


def test_a_denial_for_another_reason_is_not_given_an_argument_explanation(monkeypatch):
    monkeypatch.setattr(agent, "_authorize_throttled", lambda *a, **k: {"allowed": False, "reason": "budget_exhausted"})
    monkeypatch.setattr(agent, "_audit_agent_event", lambda *a, **k: None)
    text = agent._handle_ffuf(
        "e1", {"target": "example.org", "path": "/FUZZ", "wordlist": "common", "extra_candidates": ["a b"]},
        {"example.org": "asset-1"}, {}, agent.SimpleContext(scan_run_id="r1"),
    )
    assert text == "DENIED by the Scope Gateway: budget_exhausted."
