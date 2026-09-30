"""TC-FIDELITY-006: every tool dispatch reports itself as the scan_run's
current activity before running and clears it afterward - best effort, so a
telemetry failure never affects the tool's own result."""

from __future__ import annotations

from app import control_plane_client as cpc
from app import tool_runner_client as trc

_RUN_ID = "33333333-3333-3333-3333-333333333333"


def _runner(monkeypatch, post_result):
    runner = trc.ToolRunnerClient()
    monkeypatch.setattr(runner, "_post_cancellable", lambda path, payload, scan_run_id, budget_s=None: post_result)
    return runner


def test_run_reports_current_activity_before_and_clears_after(monkeypatch):
    calls = []
    monkeypatch.setattr(cpc.client, "update_scan_run", lambda scan_run_id, **fields: calls.append(fields))
    runner = _runner(monkeypatch, {"success": True, "exit_code": 0, "stdout": "", "stderr": ""})

    runner.run("wafw00f", "host.example.com", {}, scan_run_id=_RUN_ID)

    assert calls == [
        {"current_tool": "wafw00f", "current_target": "host.example.com"},
        {"current_tool": None, "current_target": None},
    ]


def test_activity_reporting_failure_does_not_affect_tool_result(monkeypatch):
    def flaky(scan_run_id, **fields):
        raise RuntimeError("control-plane unreachable")

    monkeypatch.setattr(cpc.client, "update_scan_run", flaky)
    result = {"success": True, "exit_code": 0, "stdout": "found", "stderr": ""}
    runner = _runner(monkeypatch, result)

    out = runner.run("wafw00f", "host.example.com", {}, scan_run_id=_RUN_ID)

    assert out["success"] is True
    assert out["stdout"] == "found"


def test_no_scan_run_id_means_no_activity_reporting(monkeypatch):
    calls = []
    monkeypatch.setattr(cpc.client, "update_scan_run", lambda scan_run_id, **fields: calls.append(fields))
    runner = _runner(monkeypatch, {"success": True, "exit_code": 0, "stdout": "", "stderr": ""})

    runner.run("wafw00f", "host.example.com", {}, scan_run_id=None)

    assert calls == []


def test_activity_is_cleared_even_when_the_tool_call_raises(monkeypatch):
    calls = []
    monkeypatch.setattr(cpc.client, "update_scan_run", lambda scan_run_id, **fields: calls.append(fields))
    runner = trc.ToolRunnerClient()

    def boom(path, payload, scan_run_id, budget_s=None):
        raise RuntimeError("dispatch thread failure")

    monkeypatch.setattr(runner, "_post_cancellable", boom)

    try:
        runner.run("wafw00f", "host.example.com", {}, scan_run_id=_RUN_ID)
    except RuntimeError:
        pass

    assert calls == [
        {"current_tool": "wafw00f", "current_target": "host.example.com"},
        {"current_tool": None, "current_target": None},
    ]
