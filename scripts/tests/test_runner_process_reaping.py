"""REQ-PIPE-007: processes killed at a check's time budget are reaped.

HexStrike terminates a command's process group when its budget runs out but
never waits for the orphans, and the Python server as PID 1 does not adopt
them: 8 defunct nuclei processes were left behind by one scan. Running the
runner with an init process as PID 1 reaps them. This asserts the compose
definition keeps that setting; the live check (no defunct processes after a
budget kill) is in the scan-pipeline test case."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "docker-compose.yml").read_text()


def _service_block(name: str) -> str:
    match = re.search(rf"^  {re.escape(name)}:\n(?P<body>(?:    .*\n|\n|  #.*\n)*)", COMPOSE, re.MULTILINE)
    assert match, f"service {name} not found in docker-compose.yml"
    return match.group("body")


def test_the_tool_runner_runs_with_an_init_process_that_reaps_killed_children():
    assert re.search(r"^    init: true\s*$", _service_block("tool-runner"), re.MULTILINE)


def test_negative_the_init_setting_is_not_an_accident_of_another_service():
    # Only the runner needs it; a copy-paste onto every service would hide a
    # missing setting on the one that matters.
    block = _service_block("tool-runner")
    assert block.count("init: true") == 1
    for other in ("control-plane", "worker"):
        assert "init: true" not in _service_block(other)


def test_the_runner_stays_read_only_and_capability_free_with_the_init_process():
    block = _service_block("tool-runner")
    assert re.search(r"^    read_only: true\s*$", block, re.MULTILINE)
    assert "cap_drop: [ALL]" in block
