"""The project committed to avoiding the trademarked phrase "Red Agent"
(renamed to "Vector Agent"). A naive single-line grep misses an occurrence
split across a line wrap (e.g. a docstring reading "...Worker/Red\\n    Agent
..."), which is exactly how one survived an earlier rename pass
(control-plane/app/api/internal.py, traced to commit 19f9ffb). This guard
normalizes whitespace/newlines before matching, so a wrapped occurrence
cannot hide, while leaving ordinary colour usage (e.g. CSS `--red`) alone -
it matches the two-word phrase, never bare "red"."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Binary/generated paths a text grep should never open.
_SKIP_SUFFIXES = {".docx", ".png", ".jpg", ".jpeg", ".ico", ".pdf", ".woff", ".woff2"}
_SKIP_DIR_PARTS = {"node_modules", "dist", "__pycache__", ".git"}

# Matches "red" and "agent" as whole words with arbitrary whitespace (incl.
# newlines) between them - exactly what a line-wrapped docstring collapses to.
_PHRASE = re.compile(r"\bred\s+agent\b", re.IGNORECASE)


def _tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True,
    )
    paths = []
    for line in out.stdout.splitlines():
        p = ROOT / line
        if p.resolve() == Path(__file__).resolve():
            continue  # this file's own regression-proof string is expected to match
        if p.suffix.lower() in _SKIP_SUFFIXES:
            continue
        if _SKIP_DIR_PARTS & set(p.parts):
            continue
        paths.append(p)
    return paths


def test_no_line_wrapped_or_inline_red_agent_occurrence():
    hits = []
    for path in _tracked_files():
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue  # not a text file this guard can meaningfully scan
        if _PHRASE.search(re.sub(r"\s+", " ", text)):
            hits.append(str(path.relative_to(ROOT)))
    assert not hits, f"trademarked phrase 'Red Agent' found in: {hits}"


def test_guard_does_not_false_positive_on_colour_usage():
    """Regression proof for the guard itself: ordinary colour references
    ("--red", "red 500", "background: red") must never trip it."""
    samples = [
        "--red: #dc2626;",
        ".badge-red { color: red; }",
        "severity: red\ncolor scale: red, orange, green",
        "the alert banner is red and the icon is a small red dot",
    ]
    for sample in samples:
        assert not _PHRASE.search(re.sub(r"\s+", " ", sample)), sample
    # the guard itself must still catch the exact wrapped shape that slipped
    # through the original rename pass.
    assert _PHRASE.search(re.sub(r"\s+", " ", "the Worker/Red\n    Agent boundary"))
