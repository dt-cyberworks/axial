"""REQ-BENCHSEP-001 (GitHub #90): nothing in the ASM system behaves differently because something is being measured.

A benchmark has to prove the unaltered configuration of a real engagement. A product that knows it is being benchmarked can behave
differently when it is (the way a car's software can know it is on a test bench), and the score then describes a product nobody
runs. This is the permanent protection against such a defeat device being added: no *code* of the product may name a benchmark.

What is checked, and what is not. Python: identifiers (names, attributes, arguments, function and class names, keyword arguments) and
string constants that are not docstrings. Console sources: code with comments removed. Prose is free: a comment or a docstring may say
that a finding was first seen on "the OWASP Benchmark" target (a third-party vulnerable application that happens to have that name), because
prose cannot change behaviour. Migrations that already ran are history and are not edited."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRODUCT_DIRS = ("control-plane/app", "worker/app", "tool-runner", "frontend/src", "scripts", "uat", "lab", "docker-compose.yml",
                ".env.example", "Makefile", "Makefile.private")
SKIP_PARTS = {"__pycache__", "node_modules", ".venv", "migrations"}
THIS_TEST = Path(__file__).resolve()
# Files that are about benchmarks as a subject, not product behaviour: the release exporter's deny list names the directory
# it keeps out of the public repository, and the documentation checks name it as a path.
SUBJECT_FILES = {
    "scripts/oss-public-paths.deny.txt", "scripts/tests/test_oss_publish.py", "scripts/tests/test_install_docs.py",
    "scripts/tests/test_compose_only_deployment.py", "scripts/tests/test_documentation_scope.py",
}
WORD = re.compile(r"benchmark", re.IGNORECASE)


def _files():
    for entry in PRODUCT_DIRS:
        base = ROOT / entry
        if base.is_file():
            yield base
            continue
        for path in base.rglob("*"):
            if path.is_file() and not (SKIP_PARTS & set(path.parts)) and path.suffix in {".py", ".ts", ".tsx", ".js", ".mjs", ".yml", ".yaml", ".sh", ".sql", ".conf", ""}:
                yield path


def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                ids.add(id(body[0].value))
    return ids


def python_findings(source: str, name: str = "<source>") -> list[str]:
    tree = ast.parse(source, filename=name)
    docs = _docstring_nodes(tree)
    found = []
    for node in ast.walk(tree):
        label = None
        if isinstance(node, ast.Name):
            label = node.id
        elif isinstance(node, ast.Attribute):
            label = node.attr
        elif isinstance(node, ast.arg):
            label = node.arg
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            label = node.name
        elif isinstance(node, ast.keyword) and node.arg:
            label = node.arg
        elif isinstance(node, ast.alias):
            label = node.name + (node.asname or "")
        elif isinstance(node, ast.ImportFrom):
            label = node.module or ""
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
            label = node.value
        if label and WORD.search(label):
            found.append(f"{name}:{getattr(node, 'lineno', '?')}: {label[:80]}")
    return found


def script_findings(source: str, name: str = "<source>") -> list[str]:
    """Console and shell sources: the text with comments removed (// and /* */ for the console, # for shell and compose)."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), source, flags=re.DOTALL)
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        code = re.sub(r"(^|\s)(//|#)\s.*$|^\s*(//|#).*$", "", line)
        if WORD.search(code):
            found.append(f"{name}:{number}: {code.strip()[:80]}")
    return found


def product_findings() -> list[str]:
    offenders = []
    for path in _files():
        rel = path.relative_to(ROOT).as_posix()
        if path.resolve() == THIS_TEST or rel in SUBJECT_FILES:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if path.suffix == ".py":
            # test files of the product are behaviour specifications of the product too, but a test may name the thing it
            # proves absent; the guard's own tests below are the proof it still bites.
            offenders += python_findings(text, rel)
        else:
            offenders += script_findings(text, rel)
    return offenders


def test_no_code_of_the_product_names_a_benchmark():
    offenders = product_findings()
    assert not offenders, "the ASM system must not know about benchmarks:\n  " + "\n  ".join(offenders)


# --- the guard itself bites ----------------------------------------------------------------------------------------------


def test_the_guard_catches_a_branch_on_a_benchmark_source():
    assert python_findings('if engagement.source == "benchmark":\n    allow_more()\n')


def test_the_guard_catches_a_function_a_variable_an_import_a_keyword_and_an_environment_variable():
    assert python_findings("def run_benchmark_mode():\n    pass\n")
    assert python_findings("benchmark_mode = True\n")
    assert python_findings("from benchmark.orchestration import sweep\n")
    assert python_findings("f(benchmark=True)\n")
    assert python_findings('import os\nos.environ.get("BENCHMARK_ONLY")\n')


def test_the_guard_catches_a_console_branch_and_a_compose_setting():
    assert script_findings('if (engagement.source === "benchmark") { relax(); }\n')
    assert script_findings("services:\n  worker:\n    image: x-benchmark\n")


def test_the_guard_leaves_prose_alone():
    assert not python_findings('"""Found live on the OWASP Benchmark target."""\n# the benchmark VM is on the same host\nx = 1\n')
    assert not python_findings('def f():\n    """A benchmark pilot found this."""\n    return 1\n')
    assert not script_findings("// seen on the OWASP Benchmark target\nconst x = 1; // the benchmark VM\n/* a benchmark note */\n")
    assert not script_findings("# benchmark VM\nservices: {}\n")
