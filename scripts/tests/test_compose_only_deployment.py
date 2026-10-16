"""TC-COMPOSE-001/003: Docker Compose is the only deployment model (GitHub issue #51). No
tracked file brings the Kubernetes model back, and the security documents do not cite a control
that exists in no deployment."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", "dist", ".pytest_cache", "secrets"}
BINARY = {".png", ".jpg", ".pdf", ".ico", ".woff", ".woff2", ".gz", ".zip", ".pyc", ".db"}
TERMS = re.compile(r"kubernetes|k8s|networkpolicy|kubectl", re.IGNORECASE)
# The only places allowed to name it: the one-sentence note, the benchmark documents that
# evaluate Kubernetes as a benchmark option, this change's own records, the generated matrix,
# and a comment in a shipped migration (shipped migrations are never edited).
ALLOWED = {
    "INSTALL.md",
    "control-plane/migrations/0001_init_schema.sql",
    "scripts/tests/test_compose_only_deployment.py",
    "control-plane/tests/test_no_kubernetes_surface.py",
}
ALLOWED_PREFIXES = ("docs/benchmarking/", "benchmark/")
# This change's own records name what they forbid; they exist only in the private repository.
RECORD_DIRS = {"design", "engineering", "requirements", "test-cases", "traceability"}


def is_own_record(rel: str) -> bool:
    parts = rel.split("/")
    return len(parts) > 2 and parts[0] == "docs" and parts[1] in RECORD_DIRS and "compose-only-deployment" in parts[-1] \
        or rel.endswith("requirements-to-tests.md")


def tracked_text_files():
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() in BINARY:
            continue
        rel = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        yield rel.as_posix(), path


def test_negative_no_tracked_file_brings_the_kubernetes_model_back():
    offenders = []
    for rel, path in tracked_text_files():
        if rel in ALLOWED or rel.startswith(ALLOWED_PREFIXES) or is_own_record(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if TERMS.search(line):
                offenders.append(f"{rel}:{number}: {line.strip()[:90]}")
    assert not offenders, "Kubernetes terms outside the allowed places:\n" + "\n".join(offenders[:20])


def test_the_manifest_directory_and_its_exceptions_are_gone():
    assert not (ROOT / "deployment" / "k8s").exists()
    # The export rules are private (not published), so they are checked where they exist.
    for name in (".trivyignore.yaml", "scripts/oss-content-exceptions.txt", "scripts/oss-public-paths.txt"):
        path = ROOT / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert "deployment/k8s" not in text and "deployment/" not in text.replace("docs/deployment", ""), name
    assert (ROOT / ".trivyignore.yaml").is_file()


def test_the_security_documents_cite_no_removed_control():
    for name in ("docs/security-model.md", "docs/security/tool-catalog.md", "docs/security/rogue-agent-threat-model.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert not TERMS.search(text), name
    model = (ROOT / "docs/security-model.md").read_text(encoding="utf-8")
    assert not re.search(r"ephemeral runner|fresh per engagement|destroyed afterward", model)
    assert "deny-all" in model  # the control that does exist is named


def test_install_says_in_one_sentence_that_there_is_no_kubernetes_deployment():
    install = (ROOT / "INSTALL.md").read_text(encoding="utf-8")
    lines = [line for line in install.splitlines() if TERMS.search(line)]
    assert len(lines) == 1 and "no Kubernetes deployment" in lines[0], lines
    assert "separate Compose stack" in install
