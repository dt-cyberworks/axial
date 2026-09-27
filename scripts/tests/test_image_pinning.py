"""REQ-SUPPLY-001: every container image the stack builds from or runs must be
pinned by digest (@sha256:...), never a floating tag. This is a pure-text guard
(no Docker needed) so it runs in the normal unit suite and blocks any
regression that reintroduces an unpinned base image or a `:latest` service."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Every Dockerfile plus the compose files that reference images.
DOCKERFILES = sorted(ROOT.glob("**/Dockerfile")) + sorted(ROOT.glob("**/*.Dockerfile"))
COMPOSE_FILES = [ROOT / "docker-compose.yml", ROOT / "docker-compose.prod.yml"]

_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\b")
_FROM = re.compile(r"^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE)
_IMAGE = re.compile(r"^\s*image:\s*(\S+)\s*$")


def _from_stage_names(text: str) -> set[str]:
    return {m.group(2) for m in _FROM.finditer(text) if m.group(2)}


def test_all_dockerfile_bases_are_digest_pinned():
    unpinned: list[str] = []
    for df in DOCKERFILES:
        if "node_modules" in df.parts:
            continue
        text = df.read_text(encoding="utf-8")
        stages = _from_stage_names(text)
        for line in text.splitlines():
            m = _FROM.match(line)
            if not m:
                continue
            ref = m.group(1)
            # A FROM that references an earlier build stage by name is not an
            # external image and needs no digest.
            if ref in stages:
                continue
            if not _DIGEST.search(ref):
                unpinned.append(f"{df.relative_to(ROOT)}: FROM {ref}")
    assert not unpinned, "unpinned base image(s):\n" + "\n".join(unpinned)


def test_all_compose_images_are_digest_pinned():
    unpinned: list[str] = []
    for cf in COMPOSE_FILES:
        if not cf.exists():
            continue
        for line in cf.read_text(encoding="utf-8").splitlines():
            m = _IMAGE.match(line)
            if not m:
                continue
            ref = m.group(1)
            if not _DIGEST.search(ref):
                unpinned.append(f"{cf.relative_to(ROOT)}: image: {ref}")
    assert not unpinned, "unpinned compose image(s):\n" + "\n".join(unpinned)


def test_no_floating_latest_without_digest():
    """A belt-and-suspenders check: `:latest` is only acceptable when a digest
    also pins the content."""
    offenders: list[str] = []
    for f in DOCKERFILES + COMPOSE_FILES:
        if not f.exists() or "node_modules" in f.parts:
            continue
        for line in f.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if ":latest" in stripped and "@sha256:" not in stripped and (
                _FROM.match(line) or _IMAGE.match(line)
            ):
                offenders.append(f"{f.relative_to(ROOT)}: {stripped}")
    assert not offenders, "floating :latest without digest:\n" + "\n".join(offenders)
