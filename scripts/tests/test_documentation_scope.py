"""TC-DOCS-001/002/003 (GitHub issues #52, #54, #55): the documentation carries no maturity path,
keeps its legal wording in one place, and has no document-version stamps."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", "dist", ".pytest_cache", "secrets"}
BINARY = {".png", ".jpg", ".pdf", ".ico", ".woff", ".woff2", ".gz", ".zip", ".pyc", ".db", ".lock"}
NOTICE = "This is a technical document, not legal advice. Only test systems you are authorized to test; see `docs/legal.md`."
SPECS = ["technical-architecture", "scanner-specification", "deployment-architecture",
         "rules-of-engagement", "tool-allowlist", "operator-console-ui"]

# Files that may quote the removed wording: shipped migrations, the generated matrix, the licence
# text, and the records and this test, which have to name what they forbid.
QUOTES = {"scripts/tests/test_documentation_scope.py", "LICENSE"}
RECORD_DIRS = {"design", "engineering", "requirements", "test-cases", "traceability"}


def is_record(rel: str) -> bool:
    """The engineering records exist only in the private repository (GitHub issue #56) and quote
    the wording they forbid; the generated matrix lists their titles."""
    parts = rel.split("/")
    return len(parts) > 2 and parts[0] == "docs" and parts[1] in RECORD_DIRS
LEGAL_KEEP_LIST = {"README.md", "SECURITY.md", "docs/legal.md", "docs/manual/safety-legal-limits.md", "LICENSE"}


def files():
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() in BINARY:
            continue
        rel = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        rel_s = rel.as_posix()
        if rel_s.startswith("control-plane/migrations/") or rel_s.startswith("frontend/package-lock"):
            continue
        yield rel_s, path


def hits(pattern: re.Pattern, allowed: set[str] = frozenset()) -> list[str]:
    found = []
    for rel, path in files():
        if rel in QUOTES or rel in allowed or is_record(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                found.append(f"{rel}:{number}: {line.strip()[:90]}")
    return found


def test_negative_no_maturity_stage_label_is_left():
    stage = re.compile(r"\bM[1-6]\b")  # case-sensitive: `m2` is an ordinary identifier
    path = re.compile(r"maturity (path|stage)", re.IGNORECASE)
    found = hits(stage) + hits(path)
    assert not found, "\n".join(found[:20])


def test_the_roadmap_page_and_its_anchor_remain():
    roadmap = (ROOT / "docs/roadmap.md").read_text(encoding="utf-8")
    assert re.search(r"^## Where the project stands$", roadmap, re.MULTILINE)
    assert re.search(r"^## What's next$", roadmap, re.MULTILINE)


def test_the_customer_value_is_described_only_as_dormant_schema():
    for name in ("docs/spec/technical-architecture.md", "docs/spec/operator-console-ui.md",
                 "docs/spec/rules-of-engagement.md", "docs/legal.md", "docs/manual/troubleshooting.md",
                 "docs/manual/guides/authorize-and-activate.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert not re.search(r"customer (type|operation|view|role)|source = customer|`customer` —", text), name
    assert "Dormant schema" in (ROOT / "docs/data-model.md").read_text(encoding="utf-8")


def test_negative_no_legal_marker_glyph_is_left():
    assert not hits(re.compile("⚖"))


def test_negative_legal_conclusions_stay_out_of_the_specifications():
    pattern = re.compile(r"legally|legal basis|legal implication|Rechtsgrundlage|rechtlich", re.IGNORECASE)
    found = hits(pattern, allowed={"docs/legal.md"})
    assert not found, "\n".join(found[:20])


def test_negative_no_employment_advice_is_left():
    pattern = re.compile(r"secondary.employ|employer|employment contract|conflict.of.interest", re.IGNORECASE)
    found = hits(pattern)
    assert not found, "\n".join(found[:20])


def test_counsel_wording_stays_in_the_keep_list():
    pattern = re.compile(r"criminal offen[cs]e|jurisdiction|legal counsel|criminal-law", re.IGNORECASE)
    found = hits(pattern, allowed=LEGAL_KEEP_LIST)
    assert not found, "\n".join(found[:20])


def test_the_essential_disclaimers_are_still_there():
    for name in ("README.md", "docs/legal.md", "docs/manual/safety-legal-limits.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert re.search(r"not legal advice", text, re.IGNORECASE), name
        assert re.search(r"criminal offen[cs]e", text, re.IGNORECASE), name


def test_every_specification_ends_with_the_same_notice():
    for name in SPECS:
        text = (ROOT / "docs/spec" / f"{name}.md").read_text(encoding="utf-8")
        assert text.rstrip().endswith(NOTICE), name
        assert text.count(NOTICE) == 1, name


def test_negative_no_version_stamp_is_left():
    pattern = re.compile(
        r"Version [0-9]+\.[0-9]+ ·|Companion document|Relationship to (document|the other documents)|"
        r"Architecture v2\.1|Deployment v1\.0|\(v2\.1\)|\(v1\.0\)")
    found = hits(pattern)
    assert not found, "\n".join(found[:20])


def test_the_stack_table_lists_no_unbuilt_component_as_running():
    arch = (ROOT / "docs/architecture.md").read_text(encoding="utf-8")
    table = arch.split("## Technology stack", 1)[1].split("\n\n", 2)[1]
    assert "Vault" not in table and "MCP server" not in table
    assert not re.search(r"swappable|reference implementation", arch, re.IGNORECASE)
    spec = (ROOT / "docs/spec/technical-architecture.md").read_text(encoding="utf-8")
    assert not re.search(r"swappable|reference implementation", spec, re.IGNORECASE)


def test_relative_markdown_links_resolve():
    link = re.compile(r"\]\((?!https?:|mailto:|#)([^)\s#]+)")
    missing = []
    for rel, path in files():
        if path.suffix != ".md" or is_record(rel) or rel.startswith("docs/benchmarking/"):
            continue
        text = re.sub(r"```.*?```", "", path.read_text(encoding="utf-8"), flags=re.S)
        for target in link.findall(text):
            if not (path.parent / target).exists():
                missing.append(f"{rel}: {target}")
    assert not missing, "\n".join(missing[:20])
