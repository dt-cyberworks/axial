"""REQ-SUPPLY-003 (GitHub issue #43, follow-up 06): the tool-runner image
installs HexStrike's dependencies only from a hash-locked file, builds on
Kali's current Python, and CI emits an SBOM per image."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = (ROOT / "tool-runner" / "runner.Dockerfile").read_text()
LOCK = ROOT / "tool-runner" / "hexstrike-requirements.lock.txt"
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text()


def _lock_entries() -> dict[str, list[str]]:
    """name==version -> list of hashes, from the pip-compile output."""
    entries: dict[str, list[str]] = {}
    current = None
    for raw in LOCK.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        requirement = re.match(r"^([A-Za-z0-9_.\-\[\]]+)(==|>=|<=|~=|!=|<|>)?([^\s\\]*)", line)
        if line.startswith("--hash=") and current:
            entries[current].append(line.split("=", 1)[1].rstrip(" \\"))
        elif requirement:
            current = f"{requirement.group(1)}{requirement.group(2) or ''}{requirement.group(3)}"
            entries[current] = []
    return entries


def test_the_dockerfile_installs_only_from_the_hash_locked_file():
    assert "--require-hashes" in DOCKERFILE
    assert "-r /tmp/hexstrike-requirements.lock.txt" in DOCKERFILE
    assert "COPY hexstrike-requirements.lock.txt" in DOCKERFILE


def _instructions() -> list[str]:
    """Dockerfile instructions with comments dropped and continuations joined."""
    code = "\n".join(l for l in DOCKERFILE.splitlines() if not l.lstrip().startswith("#"))
    return [" ".join(part.split()) for part in code.replace("\\\n", " ").splitlines() if part.strip()]


def test_negative_the_dockerfile_never_installs_from_the_live_requirements_file():
    installs = [i for i in _instructions() if "pip install" in i]
    assert installs
    for instruction in installs:
        assert "--require-hashes" in instruction, instruction
        assert "-r requirements.txt" not in instruction, instruction


def test_negative_every_locked_package_is_pinned_and_hashed():
    entries = _lock_entries()
    assert len(entries) > 50, "lock file looks empty or unparsed"
    for name, hashes in entries.items():
        assert "==" in name, f"{name} is not pinned to an exact version"
        assert hashes and all(re.fullmatch(r"sha256:[0-9a-f]{64}", h) for h in hashes), f"{name} has no valid hash"


def test_negative_excluded_packages_are_not_in_the_lock():
    names = {n.split("==")[0].lower() for n in _lock_entries()}
    assert not names & {"pwntools", "angr", "capstone", "unicorn", "z3-solver", "ropgadget"}


def test_the_image_installs_the_libffi_headers_with_a_reason():
    assert re.search(r"libffi-dev", DOCKERFILE)
    assert "ffi.h" in DOCKERFILE  # the comment explains why


def test_the_lock_can_be_regenerated_from_the_pinned_sha():
    script = ROOT / "scripts" / "regenerate_hexstrike_lock.sh"
    assert script.exists() and script.stat().st_mode & 0o111
    text = script.read_text()
    assert "HEXSTRIKE_SHA" in text and "--generate-hashes" in text
    assert "regenerate_hexstrike_lock.sh" in DOCKERFILE  # the bump procedure is written down


def test_ci_builds_every_image_and_emits_an_sbom_for_each():
    built = set(re.findall(r"-t asm/([a-z\-]+):ci", CI))
    assert {"control-plane", "worker", "egress-proxy", "tool-runner", "raw-egress-gateway", "edge"} <= built
    for image in built:
        assert f"image-ref: asm/{image}:ci" in CI, f"no SBOM step for {image}"
    assert "format: cyclonedx" in CI and "actions/upload-artifact" in CI


def _lock_version(name: str) -> tuple[int, ...]:
    for entry in _lock_entries():
        if entry.lower().startswith(f"{name}=="):
            return tuple(int(x) for x in entry.split("==")[1].split(".") if x.isdigit())
    raise AssertionError(f"{name} is not in the lock")


def test_negative_versions_held_back_by_mitmproxy_are_overridden_past_their_cves():
    """mitmproxy 10.4.2 caps tornado<=6.4.1 and pyOpenSSL<24.3, both with known
    HIGH CVEs; the overrides file lifts them and the lock must honour it."""
    overrides = (ROOT / "tool-runner" / "hexstrike-overrides.txt").read_text()
    assert "--override" in (ROOT / "scripts" / "regenerate_hexstrike_lock.sh").read_text()
    assert "hexstrike-overrides.txt" in overrides or overrides.strip()
    assert _lock_version("tornado") >= (6, 5, 8)
    assert _lock_version("pyopenssl") >= (26, 0, 0)
    assert _lock_version("cryptography") >= (46, 0, 0)
