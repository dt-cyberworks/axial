"""REQ-REPORT-003: the pipeline's report phase produces a real, run-scoped
report and never turns a reporting failure into a failed scan."""

from __future__ import annotations

import uuid

import pytest

from app.tasks import report

ENGAGEMENT_ID = "019fe768-acdf-77d8-bb63-3ce9e9cb4c23"
RUN_ID = "019fe769-1111-7000-8000-aaaaaaaaaaaa"


def test_the_run_id_is_passed_through_so_the_report_describes_that_run(monkeypatch):
    """Without this the report falls back to "the newest finished run", which
    for a re-run engagement is not necessarily the one that just completed -
    and the diff section would then describe the wrong comparison."""
    seen = {}

    def fake_request_report(engagement_id, scan_run_id=None):
        seen["engagement_id"] = engagement_id
        seen["scan_run_id"] = scan_run_id
        return {"status": "done", "report_id": "r1"}

    monkeypatch.setattr(report.client, "request_report", fake_request_report)

    result = report.run(ENGAGEMENT_ID, scan_run_id=RUN_ID)

    assert result["status"] == "done"
    assert seen["engagement_id"] == uuid.UUID(ENGAGEMENT_ID)
    assert seen["scan_run_id"] == uuid.UUID(RUN_ID)


def test_without_a_run_id_the_control_plane_picks_the_run_itself(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        report.client, "request_report",
        lambda engagement_id, scan_run_id=None: seen.update(scan_run_id=scan_run_id) or {"status": "done"},
    )

    report.run(ENGAGEMENT_ID)

    assert seen["scan_run_id"] is None


def test_negative_a_report_failure_does_not_propagate_and_fail_the_scan(monkeypatch):
    """The scan's findings are already persisted and visible by this phase. A
    reporting problem must be recorded, not escalated into a failed run."""
    def boom(engagement_id, scan_run_id=None):
        raise RuntimeError("control-plane unreachable")

    monkeypatch.setattr(report.client, "request_report", boom)

    result = report.run(ENGAGEMENT_ID, scan_run_id=RUN_ID)

    assert result["status"] == "failed"
    assert "control-plane unreachable" in result["error"]


def test_negative_the_failure_reason_is_bounded(monkeypatch):
    def boom(engagement_id, scan_run_id=None):
        raise RuntimeError("x" * 5000)

    monkeypatch.setattr(report.client, "request_report", boom)

    assert len(report.run(ENGAGEMENT_ID)["error"]) <= 500


def test_pipeline_calls_the_report_phase_with_the_current_run(monkeypatch):
    """Guards the wiring itself: the phase can only scope a report to the run
    if the pipeline actually hands it the id."""
    import inspect

    from app.tasks import pipeline

    source = inspect.getsource(pipeline)
    assert "report.run(engagement_id, scan_run_id=str(scan_run_id))" in source
