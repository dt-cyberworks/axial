#!/usr/bin/env python3
"""Checks for the user manual in docs/manual (REQ-MANUAL-001..004).

Standard library only, so it runs in the public CI and in the exported tree.

  * structure   every required page exists; every page names who it is for and
                what the reader can do afterwards
  * links       every relative link in docs/ and the root README/INSTALL resolves,
                anchors inside the manual too; a link from the manual may only
                point at something the public export keeps
  * routes      every route of the console is mentioned in the screen reference
  * labels      every UI label a page quotes (`<!-- ui-labels: A | B -->`) exists
                in the frontend source
  * codes       every readiness blocker, gateway denial, run reason and check
                reason the console can show is explained in troubleshooting.md
  * images      every referenced image exists; no image is unused or too large
  * privacy     no real hostname, account, address or contact in the manual

Run:  python3 scripts/check_manual.py        (make manual-check)
"""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANUAL = "docs/manual"

REQUIRED_PAGES = [
    "README.md", "quickstart.md", "concepts.md", "tools.md", "operations.md",
    "safety-legal-limits.md", "troubleshooting.md", "glossary.md",
    "guides/README.md", "guides/define-an-engagement.md", "guides/authorize-and-activate.md",
    "guides/control-which-tools-run.md", "guides/run-a-scan.md", "guides/tune-a-scan.md",
    "guides/approve-or-deny-a-tool-call.md", "guides/triage-findings.md", "guides/compare-runs.md",
    "guides/reports.md", "guides/users-and-mfa.md", "guides/configure-the-llm.md",
    "reference/README.md", "reference/overview.md", "reference/engagement.md", "reference/run-detail.md",
    "reference/wizard.md", "reference/settings.md", "reference/audit.md", "reference/account-and-admin.md",
]
# Pages that quote labels of the console and therefore must list them.
ENTRY_POINTS = ("README.md", "docs/README.md")
LABEL_PAGES = ("quickstart.md", "guides/", "reference/")
# Where the screen reference has to mention every route.
ROUTE_FILES = "docs/manual/reference"
TROUBLESHOOTING = "docs/manual/troubleshooting.md"
# Run reasons that the code builds without a plain `state_reason="..."` literal.
RUN_REASONS = (
    "cancelled_by_operator", "cancellation_status_unavailable", "reaped_stale_heartbeat", "asset_review_expired",
    "task_time_limit_exceeded", "pipeline_error", "coverage_degraded", "coverage_partial", "agent_incomplete",
)
# Check reasons shown on the plan tab that no single constant lists.
CHECK_REASONS = (
    "switch_off", "tool_disabled", "no_tool_grant", "not_a_tls_service", "not_a_web_service", "no_endpoints",
    "no_matching_templates", "oob_unavailable", "materialized_ip_missing", "dependency_never_finished",
    "budget_reached", "web_alias_of", "duplicate_vhost_of", "gateway_denied", "handler_error",
)
MAX_IMAGE_BYTES = 1_000_000
# Strings that must never appear in a public manual: the maintainers' own hosts, accounts and tooling.
PRIVATE_MARKERS_FILE = "scripts/manual-private-markers.txt"
DOC_NETWORKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8", "0.0.0.0/32")]
SAFE_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")


# ---------------------------------------------------------------------------------------------------- helpers

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def manual_pages(root: Path) -> list[Path]:
    base = root / MANUAL
    return sorted(base.rglob("*.md")) if base.is_dir() else []


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


_FENCE = re.compile(r"^(```|~~~).*?^\1[ \t]*$", re.S | re.M)
_INLINE_CODE = re.compile(r"`[^`\n]*`")


def prose(text: str) -> str:
    """The markdown without fenced and inline code, where a `[x](y)` is not a link."""
    return _INLINE_CODE.sub("", _FENCE.sub("", text))


_HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t#]*$", re.M)


def github_slug(heading: str) -> str:
    """The anchor GitHub gives a heading: lower case, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # a link keeps its text
    text = text.replace("`", "").strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(markdown: str) -> set[str]:
    seen: dict[str, int] = {}
    result: set[str] = set()
    for match in _HEADING.finditer(_FENCE.sub("", markdown)):
        slug = github_slug(match.group(2))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        result.add(slug if count == 0 else f"{slug}-{count}")
    return result


# ------------------------------------------------------------------------------------------ export visibility

def _rules(path: Path) -> list[str]:
    rules = []
    for line in _read(path).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rules.append(line)
    return rules


def _rule_matches(rel: str, rule: str) -> bool:
    if rule.endswith("/"):
        return rel == rule[:-1] or rel.startswith(rule)
    return rel == rule


def export_visibility(root: Path):
    """A function telling whether a repo-relative path survives the public export, or None when the
    export rules are not part of this tree (the exported tree itself)."""
    allow_file, deny_file = root / "scripts/oss-public-paths.txt", root / "scripts/oss-public-paths.deny.txt"
    if not (allow_file.is_file() and deny_file.is_file()):
        return None
    allow, deny = _rules(allow_file), _rules(deny_file)
    return lambda rel: any(_rule_matches(rel, r) for r in allow) and not any(_rule_matches(rel, r) for r in deny)


# ------------------------------------------------------------------------------------------------ structure

def check_structure(root: Path, required: list[str] | None = None) -> list[str]:
    problems = []
    base = root / MANUAL
    for page in REQUIRED_PAGES if required is None else required:
        if not (base / page).is_file():
            problems.append(f"{MANUAL}/{page}: required page is missing")
    for entry in ENTRY_POINTS:
        page = root / entry
        if not page.is_file() or not re.search(r"\]\((?:\./)?(?:docs/)?manual/README\.md\)", _read(page)):
            problems.append(f"{entry}: must link to the manual (manual/README.md)")
    for path in manual_pages(root):
        head = "\n".join(_read(path).splitlines()[:12])
        rel = _rel(root, path)
        if not _read(path).lstrip().startswith("# "):
            problems.append(f"{rel}: must start with a level-1 heading")
        if not re.search(r"^\*\*Who this is for:\*\* \S", head, re.M):
            problems.append(f"{rel}: must say who it is for (`**Who this is for:** ...`)")
        if not re.search(r"^\*\*After this page you can:\*\* \S", head, re.M):
            problems.append(f"{rel}: must say what the reader can do afterwards (`**After this page you can:** ...`)")
    return problems


# --------------------------------------------------------------------------------------------------- links

_LINK = re.compile(r"(?<!\\)!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def _link_files(root: Path) -> list[Path]:
    files = sorted((root / "docs").rglob("*.md")) if (root / "docs").is_dir() else []
    files += [p for p in (root / "README.md", root / "INSTALL.md") if p.is_file()]
    return files


def check_links(root: Path) -> list[str]:
    problems = []
    visible = export_visibility(root)
    root_resolved = root.resolve()
    anchor_cache: dict[Path, set[str]] = {}
    for path in _link_files(root):
        rel = _rel(root, path)
        in_manual = rel.startswith(MANUAL + "/")
        for target in sorted(set(_LINK.findall(prose(_read(path))))):
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                continue  # an absolute URL or mailto
            file_part, _, fragment = target.partition("#")
            resolved = path if not file_part else (path.parent / file_part).resolve()
            try:
                resolved.relative_to(root_resolved)
            except ValueError:
                problems.append(f"{rel}: link leaves the repository: {target}")
                continue
            if not resolved.exists():
                problems.append(f"{rel}: dead link: {target}")
                continue
            if in_manual and visible is not None and resolved.is_file():
                target_rel = resolved.relative_to(root_resolved).as_posix()
                if not visible(target_rel):
                    problems.append(f"{rel}: links to {target_rel}, which the public export does not keep")
            if in_manual and fragment and resolved.suffix == ".md":
                if resolved not in anchor_cache:
                    anchor_cache[resolved] = anchors(_read(resolved))
                if fragment.lower() not in anchor_cache[resolved]:
                    problems.append(f"{rel}: no heading for the anchor in {target}")
    return problems


# --------------------------------------------------------------------------------------------------- routes

def console_routes(root: Path) -> list[str]:
    app = root / "frontend/src/App.tsx"
    if not app.is_file():
        return []
    paths = re.findall(r'<Route\s+path="([^"]+)"', _read(app))
    return sorted({p for p in paths if p not in ("*", "/*")})


def check_routes(root: Path) -> list[str]:
    reference = root / ROUTE_FILES
    text = "\n".join(_read(p) for p in sorted(reference.rglob("*.md"))) if reference.is_dir() else ""
    return [f"{ROUTE_FILES}: the route `{route}` of the console is not mentioned"
            for route in console_routes(root) if f"`{route}`" not in text and f"`{route}?" not in text]


# ---------------------------------------------------------------------------------------------------- labels

def _frontend_corpus(root: Path) -> str:
    src = root / "frontend/src"
    parts = [_read(p) for p in sorted(src.rglob("*")) if p.suffix in (".tsx", ".ts")] if src.is_dir() else []
    corpus = "\n".join(parts).replace("&amp;", "&").replace("&apos;", "'").replace("&quot;", '"')
    return re.sub(r"[ \t]*\n[ \t]*", " ", corpus)  # a label split over lines in JSX is one string


_LABELS = re.compile(r"<!--\s*ui-labels:(.*?)-->", re.S)


def check_labels(root: Path) -> list[str]:
    problems = []
    corpus = _frontend_corpus(root)
    for path in manual_pages(root):
        rel = _rel(root, path)
        short = rel[len(MANUAL) + 1:]
        match = _LABELS.search(_read(path))
        if match is None:
            if short.startswith(LABEL_PAGES) and not short.endswith("README.md"):
                problems.append(f"{rel}: list the console labels it quotes in `<!-- ui-labels: A | B -->`")
            continue
        for label in [part.strip() for part in match.group(1).split(" | ")]:
            if label and label not in corpus:
                problems.append(f"{rel}: the label \"{label}\" does not exist in the console")
    return problems


# ----------------------------------------------------------------------------------------------------- codes

def _source_codes(root: Path) -> list[str]:
    codes: set[str] = set(RUN_REASONS) | set(CHECK_REASONS)
    blockers = root / "control-plane/app/scan_readiness.py"
    if blockers.is_file():
        codes |= set(re.findall(r'Blocker\(\s*"([a-z_]+)"', _read(blockers)))
    gateway = root / "control-plane/app/gateway/authorize.py"
    if gateway.is_file():
        codes |= set(re.findall(r'DENY\("([a-z_]+)"', _read(gateway)))
    skips = root / "worker/app/tool_execution.py"
    if skips.is_file():
        block = re.search(r"SKIP_REASONS = frozenset\(\{(.*?)\}\)", _read(skips), re.S)
        if block:
            codes |= set(re.findall(r'"([a-z_]+)"', block.group(1)))
    for directory in ("control-plane/app", "worker/app"):
        base = root / directory
        if base.is_dir():
            for path in base.rglob("*.py"):
                codes |= set(re.findall(r'state_reason\s*=\s*"([a-z_]+)"', _read(path)))
    return sorted(codes)


def check_codes(root: Path) -> list[str]:
    page = root / TROUBLESHOOTING
    if not page.is_file():
        return [f"{TROUBLESHOOTING}: missing"]
    text = _read(page)
    return [f"{TROUBLESHOOTING}: the code `{code}` is not explained"
            for code in _source_codes(root) if not re.search(rf"`{re.escape(code)}[`:=<]", text)]


# ---------------------------------------------------------------------------------------------------- tools

TOOLS_PAGE = "docs/manual/tools.md"
REGISTRY = "control-plane/app/tools/registry.py"
_TOOL = re.compile(r'ToolSpec\(\s*"([^"]+)",\s*"[^"]+",\s*"[^"]+",\s*installed=(True|False)')


def installed_tools(root: Path) -> list[str]:
    """Every tool the scan can use: registered and present in the runner image."""
    registry = root / REGISTRY
    if not registry.is_file():
        return []
    return [name for name, installed in _TOOL.findall(_read(registry)) if installed == "True"]


def check_tools(root: Path) -> list[str]:
    page = root / TOOLS_PAGE
    if not page.is_file():
        return [f"{TOOLS_PAGE}: missing"]
    text = _read(page).lower()
    return [f"{TOOLS_PAGE}: the tool `{tool}` is not described"
            for tool in installed_tools(root) if not re.search(rf"(?<![\w-]){re.escape(tool.lower())}(?![\w-])", text)]


# ---------------------------------------------------------------------------------------------------- images

_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)")


def check_images(root: Path) -> list[str]:
    problems = []
    base = root / MANUAL
    referenced: set[Path] = set()
    for path in manual_pages(root):
        for target in _IMAGE.findall(prose(_read(path))):
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                continue
            image = (path.parent / target.partition("#")[0]).resolve()
            referenced.add(image)
            if not image.is_file():
                problems.append(f"{_rel(root, path)}: the image {target} does not exist")
    img_dir = base / "img"
    if img_dir.is_dir():
        for image in sorted(img_dir.iterdir()):
            if image.suffix.lower() not in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"):
                continue
            if image.resolve() not in referenced:
                problems.append(f"{_rel(root, image)}: the image is not used by any page")
            if image.stat().st_size > MAX_IMAGE_BYTES:
                problems.append(f"{_rel(root, image)}: the image is larger than {MAX_IMAGE_BYTES // 1000} KB")
    return problems


# --------------------------------------------------------------------------------------------------- privacy

_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\w|\.\d)")
_EMAIL = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


def load_private_markers(root: Path = ROOT) -> tuple[str, ...]:
    """The maintainers' own names, from a file the public export leaves out so that a public
    copy of this checker does not list them. Absent there: only the generic rules apply."""
    path = root / PRIVATE_MARKERS_FILE
    if not path.is_file():
        return ()
    lines = (line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines())
    return tuple(line for line in lines if line and not line.startswith("#"))


def private_content(text: str, markers: tuple[str, ...] | None = None) -> list[str]:
    """What in `text` must not be public: a maintainer marker, an address outside the
    documentation ranges, an email address outside the reserved example domains. One
    rule set for the pages and for the screenshots' leak guard (REQ-MANUAL-004)."""
    found = []
    lowered = text.lower()
    for marker in load_private_markers() if markers is None else markers:
        if marker in lowered:
            found.append(f"contains \"{marker}\", which must not be in a public manual")
    for raw in sorted(set(_IPV4.findall(text))):
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if not any(address in network for network in DOC_NETWORKS):
            found.append(f"contains the address {raw}; use a documentation range (203.0.113.0/24)")
    for domain in sorted(set(_EMAIL.findall(text))):
        if domain.lower() not in SAFE_EMAIL_DOMAINS:
            found.append(f"contains an email address at {domain}; use example.com")
    return found


def check_privacy(root: Path) -> list[str]:
    problems = []
    for path in manual_pages(root):
        rel = _rel(root, path)
        problems += [f"{rel}: {finding}" for finding in private_content(_read(path), load_private_markers(root))]
    return problems


# -------------------------------------------------------------------------------------------------------- main

CHECKS = (
    ("structure", check_structure), ("links", check_links), ("routes", check_routes),
    ("labels", check_labels), ("codes", check_codes), ("tools", check_tools), ("images", check_images), ("privacy", check_privacy),
)


def check_all(root: Path = ROOT) -> list[str]:
    problems: list[str] = []
    for name, check in CHECKS:
        problems += [f"[{name}] {problem}" for problem in check(root)]
    return problems


def main() -> int:
    problems = check_all(ROOT)
    if problems:
        print(f"{len(problems)} problem(s) in the user manual:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    pages = len(manual_pages(ROOT))
    print(f"user manual ok: {pages} pages, {len(console_routes(ROOT))} routes, {len(_source_codes(ROOT))} codes checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
