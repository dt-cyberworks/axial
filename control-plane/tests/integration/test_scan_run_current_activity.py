"""TC-FIDELITY-006: the Run detail Activity view shows what's currently
executing. update_scan_run() applies current_tool/current_target only when
the request body actually sets them, so unrelated phase/state transitions
never clobber (or accidentally clear) the live activity, and pure activity
updates don't add scan_run_transition audit noise."""

from __future__ import annotations

from sqlalchemy import select

from app.api.internal import update_scan_run
from app.models.audit import AuditLog
from app.models.scan_run import ScanRun
from app.schemas.internal import ScanRunUpdate


def _audit_count(db, engagement_id):
    return len(db.scalars(
        select(AuditLog.id).where(
            AuditLog.engagement_id == engagement_id, AuditLog.action == "scan_run_transition",
        )
    ).all())


def test_setting_current_tool_records_tool_target_and_start_time(db, lab_engagement):
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run); db.commit(); db.refresh(run)

    out = update_scan_run(
        run.id, ScanRunUpdate(current_tool="nmap", current_target="10.0.0.5:4280"), db
    )

    assert out.current_tool == "nmap"
    assert out.current_target == "10.0.0.5:4280"
    assert out.current_started_at is not None


def test_clearing_current_tool_resets_start_time(db, lab_engagement):
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run); db.commit(); db.refresh(run)
    update_scan_run(run.id, ScanRunUpdate(current_tool="nmap", current_target="10.0.0.5:4280"), db)

    out = update_scan_run(run.id, ScanRunUpdate(current_tool=None, current_target=None), db)

    assert out.current_tool is None
    assert out.current_target is None
    assert out.current_started_at is None


def test_phase_only_update_does_not_clear_current_activity(db, lab_engagement):
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run); db.commit(); db.refresh(run)
    update_scan_run(run.id, ScanRunUpdate(current_tool="httpx", current_target="host.example.com"), db)

    out = update_scan_run(run.id, ScanRunUpdate(phase="correlate"), db)

    assert out.phase == "correlate"
    assert out.current_tool == "httpx"
    assert out.current_target == "host.example.com"


def test_activity_only_update_does_not_write_transition_audit_row(db, lab_engagement):
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run); db.commit(); db.refresh(run)
    before = _audit_count(db, lab_engagement.id)

    update_scan_run(run.id, ScanRunUpdate(current_tool="nuclei", current_target="host.example.com"), db)
    update_scan_run(run.id, ScanRunUpdate(current_tool=None, current_target=None), db)

    assert _audit_count(db, lab_engagement.id) == before


def test_phase_update_still_writes_transition_audit_row(db, lab_engagement):
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run); db.commit(); db.refresh(run)
    before = _audit_count(db, lab_engagement.id)

    update_scan_run(run.id, ScanRunUpdate(phase="correlate"), db)

    assert _audit_count(db, lab_engagement.id) == before + 1
