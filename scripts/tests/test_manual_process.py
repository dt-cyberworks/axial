"""TC-MANUAL-006: the process names the manual and not the removed in-app page (REQ-MANUAL-006).

Only files the public export keeps are asserted for sure; CLAUDE.md and the Definition of Done
(a private engineering record, GitHub issue #56) are private and are checked when present."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ["AGENTS.md"]
PRIVATE = ["definition-of-done.md"]  # a private engineering record since GitHub issue #56
REMOVED_PAGE = re.compile(r"Documentation\.tsx|in-app docs? page|in-app documentation page", re.I)


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


@pytest.mark.parametrize("rel", PUBLIC)
def test_the_process_files_name_the_manual_and_its_check(rel):
    text = read(rel)
    assert "docs/manual/" in text, f"{rel} must send a user-visible change to the manual"
    assert "make manual-check" in text, f"{rel} must require `make manual-check`"


@pytest.mark.parametrize("rel", PRIVATE)
def test_the_private_process_files_name_the_manual_and_its_check_when_present(rel):
    if not (ROOT / "CLAUDE.md").is_file():
        pytest.skip("the private process records are not part of this tree")
    text = (ROOT / "docs" / "engineering" / rel).read_text(encoding="utf-8")  # a missing file fails here, it is not a skip
    assert "docs/manual/" in text, f"{rel} must send a user-visible change to the manual"
    assert "make manual-check" in text, f"{rel} must require `make manual-check`"
    assert not REMOVED_PAGE.search(text), f"{rel} still names the in-app documentation page"


@pytest.mark.parametrize("rel", PUBLIC + ["Makefile", ".github/workflows/sdlc.yml"])
def test_negative_no_process_file_names_the_removed_in_app_page(rel):
    assert not REMOVED_PAGE.search(read(rel)), f"{rel} still names the in-app documentation page"


def test_the_private_instructions_name_the_manual_when_present():
    claude = ROOT / "CLAUDE.md"
    if not claude.is_file():
        pytest.skip("CLAUDE.md is not part of this tree")
    text = claude.read_text(encoding="utf-8")
    assert "docs/manual/" in text and "make manual-check" in text
    assert not REMOVED_PAGE.search(text)


def test_make_has_the_manual_targets_and_verify_runs_the_check():
    makefile = read("Makefile")
    assert re.search(r"^manual-check:", makefile, re.M)
    # REQ-INSTALL-006: regenerating the screenshots needs the private UAT harness, so that target
    # lives in Makefile.private, which the public export omits (it could not work there).
    private = ROOT / "Makefile.private"
    if private.is_file():
        assert re.search(r"^manual-screenshots:", private.read_text(encoding="utf-8"), re.M)
    verify = re.search(r"^verify:(.*)$", makefile, re.M)
    assert verify and "manual-check" in verify.group(1).split("##")[0].split()


def test_the_sdlc_workflow_runs_the_manual_check():
    assert "python3 scripts/check_manual.py" in read(".github/workflows/sdlc.yml")


@pytest.mark.parametrize("phrase", [
    "update frontend/src/pages/Documentation.tsx",
    "update the in-app docs page",
    "the in-app documentation page lists it",
])
def test_negative_the_removed_page_pattern_matches_the_phrasings_it_guards_against(phrase):
    assert REMOVED_PAGE.search(phrase)
