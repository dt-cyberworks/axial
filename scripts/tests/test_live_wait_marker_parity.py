"""REQ-APPROVAL-008: the worker's live-wait reason and the control plane's must be the same string.

The control plane accepts calls of a run that is `waiting_approval` ONLY with this exact reason
(control-plane/app/models/scan_run.py, LIVE_WAIT_REASON); the worker writes it (worker/app/approval_wait.py). They are
separate packages that are both called `app`, so neither can import the other; a reason that drifted would make the
control plane refuse every call of a run that waits for a decision - the very fault of GitHub #83."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _constant(relative: str, name: str) -> str:
    for node in ast.parse((ROOT / relative).read_text()).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in {relative}")


def test_the_worker_writes_the_reason_the_control_plane_accepts():
    worker = _constant("worker/app/approval_wait.py", "LIVE_WAIT_REASON")
    control_plane = _constant("control-plane/app/models/scan_run.py", "LIVE_WAIT_REASON")
    assert worker == control_plane == "approval_wait"
