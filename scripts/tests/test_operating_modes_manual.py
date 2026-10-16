"""TC-MODE-019 (REQ-MODE-019): the manual describes the two uses, and no longer says that
nothing is scheduled or alerted in a way that is false."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("check_manual", ROOT / "scripts" / "check_manual.py")
cm = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("check_manual", cm)
_spec.loader.exec_module(cm)

MANUAL = ROOT / "docs" / "manual"


def read(rel: str) -> str:
    return (MANUAL / rel).read_text(encoding="utf-8")


def test_the_manual_passes_its_own_checks():
    assert cm.check_all(ROOT) == []


def test_concepts_explains_the_two_uses_and_supervision():
    text = read("concepts.md")
    assert "## Operating modes" in text
    for word in ("Monitoring", "assessment", "supervised", "semi-attended", "never widens"):
        assert word in text, word


def test_there_is_a_guide_and_a_reference_page_and_both_are_indexed():
    assert (MANUAL / "guides" / "monitor-an-attack-surface.md").is_file()
    assert (MANUAL / "reference" / "inbox.md").is_file()
    assert "monitor-an-attack-surface.md" in read("guides/README.md")
    assert "inbox.md" in read("reference/README.md")


def test_the_guide_says_what_a_monitor_does_not_do():
    text = read("guides/monitor-an-attack-surface.md")
    for sentence in (
        "Wait for a person during a run",
        "Test credentials or exploit anything",
        "A time of day, windows or several schedules.",
        "never reports something as gone or fixed",
    ):
        assert sentence in text.replace("A short run never reports something as gone or fixed", "never reports something as gone or fixed"), sentence


def test_the_guide_explains_automatic_runs_with_the_real_rules():
    # REQ-MON-001/003/004: what the scheduler does, in the words the product keeps to.
    text = read("guides/monitor-an-attack-surface.md")
    assert "## Automatic runs" in text
    for sentence in (
        "whole days, from 1 to 90",
        "Setting the interval never starts a run at once",
        "restarts the count",
        "never waits for a person",
        "A failed run is not retried by the schedule",
        "twice its interval",
    ):
        assert sentence in text, sentence
    # the old claim must not come back while the scheduler exists
    assert "is not available yet" not in text


def test_the_limits_page_does_not_claim_more_than_the_product_does():
    text = read("safety-legal-limits.md")
    assert "No scheduled scans or alerts" not in text
    assert "No scheduled scans yet" not in text  # the scheduler exists (REQ-MON-001)
    assert "every so many days" in text
    assert "never waits for a person" in text
    assert "alerts are not sent by e-mail" in text
    assert "monitoring" in text.lower()


def test_the_approval_guide_covers_being_away_and_unattended_runs():
    text = read("guides/approve-or-deny-a-tool-call.md")
    assert "## When you are not there" in text
    assert "Notify me when you need me" in text
