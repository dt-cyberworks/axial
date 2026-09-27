#!/usr/bin/env python3
"""Validate and render the repository's requirements-as-code traceability."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQ_DIR = ROOT / "docs" / "requirements"
TC_DIR = ROOT / "docs" / "test-cases"
OUTPUT = ROOT / "docs" / "traceability" / "requirements-to-tests.md"

REQ_RE = re.compile(r"^## (REQ-[A-Z][A-Z0-9]*-\d{3}):\s+(.+?)\s*$", re.MULTILINE)
TC_RE = re.compile(r"^## (TC-[A-Z][A-Z0-9]*-\d{3}):\s+(.+?)\s*$", re.MULTILINE)
REQ_TOKEN_RE = re.compile(r"\bREQ-[A-Z][A-Z0-9]*-\d{3}\b")
PATH_RE = re.compile(r"`([^`\n]+)`")
ALLOWED_STATUS = {
    "backlog",
    "draft",
    "reviewed",
    "approved",
    "implemented",
    "verified",
    "retired",
    "ready",
}
ALLOWED_RISK = {"R0", "R1", "R2", "R3", "R4"}
NON_IMPLEMENTING_STATUS = {"backlog", "draft"}
BACKLOG_IMPL_AUTH_RE = re.compile(
    r"Implementation authorization:\s*(.*?)(?=\n## |\nSecurity invariants:|\Z)",
    re.DOTALL | re.IGNORECASE,
)
BACKLOG_IMPL_AUTH_NONE_RE = re.compile(
    r"^\s*-\s+None\b.*promot",
    re.IGNORECASE | re.MULTILINE,
)
BACKLOG_DECISION_RE = re.compile(
    r"Backlog decision log:\s*(.*?)(?=\n## |\nSecurity invariants:|\Z)",
    re.DOTALL | re.IGNORECASE,
)
SKIP_REQ_FILES = {"README.md", "_template.md", "_template-backlog.md"}


@dataclass
class Requirement:
    identifier: str
    title: str
    source: Path
    acceptance_count: int
    status: str
    risk: str
    test_cases: list[str] = field(default_factory=list)


@dataclass
class TestCase:
    identifier: str
    title: str
    source: Path
    requirements: list[str]
    automated_tests: list[Path]


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _front_matter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}
    values: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    return values


def _section(text: str, start: int, next_start: int) -> str:
    return text[start:next_start]


def load_requirements(errors: list[str]) -> dict[str, Requirement]:
    requirements: dict[str, Requirement] = {}
    for path in sorted(REQ_DIR.rglob("*.md")):
        if path.name in SKIP_REQ_FILES:
            continue
        text = path.read_text(encoding="utf-8")
        meta = _front_matter(text)
        # Existing specifications predate the pipeline. They are treated as
        # implemented/R2 until touched; new documents must use front matter.
        status = meta.get("status", "implemented")
        risk = meta.get("risk", "R2")
        if status not in ALLOWED_STATUS:
            errors.append(f"{_relative(path)}: invalid status {status!r}")
        if risk not in ALLOWED_RISK:
            errors.append(f"{_relative(path)}: invalid risk {risk!r}")
        matches = list(REQ_RE.finditer(text))
        if not matches:
            errors.append(f"{_relative(path)}: no REQ-* heading")
        for index, match in enumerate(matches):
            identifier, title = match.groups()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            body = _section(text, match.end(), end)
            acceptance = re.search(
                r"Acceptance criteria:\s*(.*?)(?=\n(?:#{1,3} |[A-Z][A-Za-z ]+:\s*$)|\Z)",
                body,
                re.DOTALL | re.IGNORECASE | re.MULTILINE,
            )
            count = len(re.findall(r"^\s*-\s+\S", acceptance.group(1), re.MULTILINE)) if acceptance else 0
            if count == 0:
                errors.append(f"{_relative(path)}:{identifier}: no acceptance criteria bullets")
            if identifier in requirements:
                errors.append(f"duplicate requirement ID {identifier}")
                continue
            requirements[identifier] = Requirement(identifier, title, path, count, status, risk)
        if status == "backlog":
            auth = BACKLOG_IMPL_AUTH_RE.search(text)
            if not auth or not BACKLOG_IMPL_AUTH_NONE_RE.search(auth.group(1)):
                errors.append(
                    f"{_relative(path)}: backlog documents need "
                    "'Implementation authorization:' with a bullet starting "
                    "'- None' and mentioning promotion"
                )
            decision_log = BACKLOG_DECISION_RE.search(text)
            if not decision_log or not re.search(r"^\s*-\s+\S", decision_log.group(1), re.MULTILINE):
                errors.append(f"{_relative(path)}: backlog documents need a non-empty Backlog decision log")
    return requirements


def _list_between(body: str, label: str, next_labels: tuple[str, ...]) -> list[str]:
    following = "|".join(re.escape(item) for item in next_labels)
    match = re.search(
        rf"{re.escape(label)}:\s*(.*?)(?=\n(?:{following}):|\n## |\Z)",
        body,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return []
    return [line.strip()[1:].strip() for line in match.group(1).splitlines() if line.strip().startswith("-")]


def load_test_cases(errors: list[str], requirements: dict[str, Requirement]) -> dict[str, TestCase]:
    cases: dict[str, TestCase] = {}
    for path in sorted(TC_DIR.rglob("*.md")):
        if path.name in {"README.md", "_template.md"}:
            continue
        text = path.read_text(encoding="utf-8")
        meta = _front_matter(text)
        if not meta:
            errors.append(f"{_relative(path)}: front matter is required")
        elif meta.get("status") not in ALLOWED_STATUS or meta.get("risk") not in ALLOWED_RISK:
            errors.append(f"{_relative(path)}: invalid status or risk")
        matches = list(TC_RE.finditer(text))
        if not matches:
            errors.append(f"{_relative(path)}: no TC-* heading")
        for index, match in enumerate(matches):
            identifier, title = match.groups()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            body = _section(text, match.end(), end)
            req_items = _list_between(body, "Requirements", ("Automated tests", "Objective", "Expected results"))
            req_ids = [token for item in req_items for token in REQ_TOKEN_RE.findall(item)]
            test_items = _list_between(body, "Automated tests", ("Objective", "Expected results", "Requirements"))
            test_paths = [ROOT / value for item in test_items for value in PATH_RE.findall(item)]
            if not req_ids:
                errors.append(f"{_relative(path)}:{identifier}: no requirements")
            if not test_paths:
                errors.append(f"{_relative(path)}:{identifier}: no automated tests")
            if "Objective:" not in body or "Expected results:" not in body:
                errors.append(f"{_relative(path)}:{identifier}: objective and expected results are required")
            for req_id in req_ids:
                if req_id not in requirements:
                    errors.append(f"{_relative(path)}:{identifier}: unknown requirement {req_id}")
                else:
                    requirements[req_id].test_cases.append(identifier)
            for test_path in test_paths:
                if not test_path.is_file():
                    errors.append(f"{_relative(path)}:{identifier}: missing test {_relative(test_path)}")
            if identifier in cases:
                errors.append(f"duplicate test-case ID {identifier}")
            else:
                cases[identifier] = TestCase(identifier, title, path, req_ids, test_paths)
    return cases


def validate() -> tuple[dict[str, Requirement], dict[str, TestCase], list[str]]:
    errors: list[str] = []
    requirements = load_requirements(errors)
    cases = load_test_cases(errors, requirements)
    for requirement in requirements.values():
        if (
            requirement.status in {"approved", "implemented", "verified"}
            and not requirement.test_cases
        ):
            errors.append(
                f"{requirement.identifier}: {requirement.status} requirement has no test case"
            )
    return requirements, cases, errors


def render(requirements: dict[str, Requirement], cases: dict[str, TestCase]) -> str:
    lines = [
        "# Requirements-to-Tests Traceability",
        "",
        "<!-- Generated by scripts/requirements_pipeline.py; do not edit manually. -->",
        "",
        f"Requirements: **{len(requirements)}** · Test cases: **{len(cases)}**",
        "",
        "| Requirement | Status | Risk | Acceptance criteria | Test cases | Executable tests |",
        "|---|---|---:|---:|---|---|",
    ]
    for req in sorted(requirements.values(), key=lambda item: item.identifier):
        linked_cases = [cases[case_id] for case_id in sorted(req.test_cases)]
        case_links = "<br>".join(
            f"[{case.identifier}](../test-cases/{case.source.relative_to(TC_DIR).as_posix()})"
            for case in linked_cases
        ) or "—"
        test_links = sorted({_relative(test) for case in linked_cases for test in case.automated_tests})
        tests = "<br>".join(f"`{path}`" for path in test_links) or "—"
        req_link = f"[{req.identifier}](../requirements/{req.source.relative_to(REQ_DIR).as_posix()})"
        lines.append(
            f"| {req_link} — {req.title} | {req.status} | {req.risk} | "
            f"{req.acceptance_count} | {case_links} | {tests} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "generate"))
    args = parser.parse_args()
    requirements, cases, errors = validate()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"{len(errors)} requirements pipeline error(s)", file=sys.stderr)
        return 1
    rendered = render(requirements, cases)
    if args.command == "generate":
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(rendered, encoding="utf-8")
        print(f"generated {_relative(OUTPUT)}")
        return 0
    if not OUTPUT.is_file():
        print(f"ERROR: missing generated file {_relative(OUTPUT)}", file=sys.stderr)
        return 1
    if OUTPUT.read_text(encoding="utf-8") != rendered:
        print("ERROR: traceability is stale; run `make traceability`", file=sys.stderr)
        return 1
    print(f"validated {len(requirements)} requirements and {len(cases)} test cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

