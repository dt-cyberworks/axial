"""REQ-OOB-001 (GitHub #76): the interaction-server passes select templates by what they contain.

Before, the passes ran `-tags oast`, so a callback template that carries no `oast` tag (about 190 of the CVE
templates, for example CVE-2019-6793) ran nowhere: the main passes use `-no-interactsh`, which makes nuclei drop it,
and the tag filter dropped it here. These tests run the generated shell selection against a real directory tree with
a stand-in `nuclei` that records what it was asked to run."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from app import tool_runner_client as trc

CALLBACK_TAGGED = "id: tagged\ninfo:\n  tags: cve,oast\nhttp:\n  - raw:\n      - GET /?u={{interactsh-url}}\n"
CALLBACK_UNTAGGED = "id: untagged\ninfo:\n  tags: cve,rce\nhttp:\n  - raw:\n      - GET /?u={{interactsh-url}}\n    matchers:\n      - part: interactsh_protocol\n"
PLAIN = "id: plain\ninfo:\n  tags: cve,exposure\nhttp:\n  - path:\n      - '{{BaseURL}}/x'\n"
NOT_YAML = "interactsh mentioned in a text file\n"


@pytest.fixture()
def tree(tmp_path):
    """Two template directories and a fake `nuclei` that writes its `-t` value to a file."""
    for rel, body in {
        "a/CVE-1.yaml": CALLBACK_TAGGED, "a/CVE-2.yaml": CALLBACK_UNTAGGED, "a/CVE-3.yaml": PLAIN,
        "a/sub/CVE-4.yaml": CALLBACK_UNTAGGED, "b/blind-1.yaml": CALLBACK_TAGGED, "b/blind-2.yaml": CALLBACK_UNTAGGED,
        "b/note.txt": NOT_YAML, "b/other.yaml": PLAIN,
    }.items():
        path = tmp_path / "templates" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    nuclei = bindir / "nuclei"
    nuclei.write_text(
        '#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  if [ "$1" = "-t" ]; then printf "%s" "$2" > "$NUCLEI_RECORD"; fi\n  shift\ndone\n'
    )
    nuclei.chmod(nuclei.stat().st_mode | stat.S_IEXEC)
    return tmp_path


def _run(tree: Path, monkeypatch, dirs: tuple[str, ...], shards: int, index: int) -> list[str] | None:
    monkeypatch.setattr(trc, "NUCLEI_OOB_PARTS", {"t": (tuple(str(tree / "templates" / d) for d in dirs), shards, index)})
    command = trc._nuclei_command("https://a.example.com", {"mode": "oob", "part": "t", "_oob_server": "http://x:8080"})
    record = tree / "record.txt"
    record.unlink(missing_ok=True)  # one answer per run
    env = {**os.environ, "PATH": f"{tree / 'bin'}:{os.environ['PATH']}", "NUCLEI_RECORD": str(record), "OOB_TOKEN": "t"}
    done = subprocess.run(["bash", "-c", command], env=env, capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    if not record.exists():
        return None
    return sorted(Path(p).relative_to(tree / "templates").as_posix() for p in record.read_text().split(","))


def test_a_callback_template_is_selected_with_or_without_the_oast_tag(tree, monkeypatch):
    chosen = _run(tree, monkeypatch, ("a", "b"), 1, 0)
    assert chosen == ["a/CVE-1.yaml", "a/CVE-2.yaml", "a/sub/CVE-4.yaml", "b/blind-1.yaml", "b/blind-2.yaml"]


def test_negative_a_template_that_does_not_use_the_interaction_server_is_never_selected(tree, monkeypatch):
    chosen = _run(tree, monkeypatch, ("a", "b"), 1, 0)
    assert "a/CVE-3.yaml" not in chosen and "b/other.yaml" not in chosen
    assert not any(p.endswith(".txt") for p in chosen), "only template files"


def test_only_the_named_directories_are_searched(tree, monkeypatch):
    assert _run(tree, monkeypatch, ("b",), 1, 0) == ["b/blind-1.yaml", "b/blind-2.yaml"]


def test_shards_are_an_exact_partition_of_the_callback_templates(tree, monkeypatch):
    everything = _run(tree, monkeypatch, ("a", "b"), 1, 0)
    shards = [_run(tree, monkeypatch, ("a", "b"), 3, i) or [] for i in range(3)]
    flat = [p for shard in shards for p in shard]
    assert sorted(flat) == everything and len(flat) == len(set(flat)), "every template once, none twice"
    assert all(shards), "this tree has enough templates for every shard to hold one"


def test_negative_a_pass_with_nothing_to_run_starts_no_scan(tree, monkeypatch):
    """No callback template in the directories: the pass is an empty success, not a nuclei call with an empty list."""
    assert _run(tree, monkeypatch, ("b",), 1, 0) is not None
    (tree / "templates" / "empty").mkdir()
    (tree / "templates" / "empty" / "p.yaml").write_text(PLAIN)
    assert _run(tree, monkeypatch, ("empty",), 1, 0) is None


def test_the_real_parts_keep_their_fixed_directories_and_the_interaction_server_flags():
    for name in trc.NUCLEI_OOB_PARTS:
        command = trc._nuclei_command("https://a.example.com", {"mode": "oob", "part": name, "_oob_server": "http://x:8080"})
        assert "/opt/nuclei-templates/" in command and "-tags oast" not in command
        assert "-iserver http://x:8080" in command and '-itoken "$OOB_TOKEN"' in command
        assert "-etags intrusive,dos,fuzz,csp-bypass" in command, "an excluded template is never re-admitted"
