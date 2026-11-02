"""REQ-OOB-001 (GitHub #76): the passes that need the interaction server are named in three places.

The worker defines them (NUCLEI_OOB_PARTS), the Scope Gateway accepts only those names (args_safety), and the control
plane gives each a name for the plan and the report (scan_plan.OOB_CLASSES). They are separate processes, so the names
are copies: a pass added in one place and not the others would run unnamed or be refused. The files are read, not
imported (the worker and the control plane are both packages called `app`)."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _literal_keys(relative: str, name: str) -> set[str]:
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        target = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target, value = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target, value = node.target.id, node.value
        if target == name and value is not None:
            if isinstance(value, ast.Dict):
                return {k.value for k in value.keys if isinstance(k, ast.Constant)}
            if isinstance(value, ast.Set):
                return {e.value for e in value.elts if isinstance(e, ast.Constant)}
    raise AssertionError(f"{name} not found as a literal in {relative}")


WORKER = _literal_keys("worker/app/tool_runner_client.py", "NUCLEI_OOB_PARTS")
GATEWAY = _literal_keys("control-plane/app/gateway/args_safety.py", "NUCLEI_OOB_PARTS")
CLASSES = _literal_keys("control-plane/app/scan_plan.py", "OOB_CLASSES")


def test_the_worker_the_gateway_and_the_plan_name_the_same_passes():
    assert WORKER and WORKER == GATEWAY == CLASSES, (sorted(WORKER), sorted(GATEWAY), sorted(CLASSES))


def test_the_reader_finds_a_literal_and_fails_loudly_when_there_is_none():
    import pytest

    with pytest.raises(AssertionError):
        _literal_keys("control-plane/app/scan_plan.py", "NO_SUCH_NAME")
