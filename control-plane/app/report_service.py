"""Generate and persist a customer report (REQ-REPORT-001).

Shared by the operator route (api/findings.py) and the worker's pipeline
report phase (api/internal.py) so both produce the identical document through
one code path.

Generation is synchronous. It is pure database reads plus text rendering -
no network calls, no LLM - so it completes in well under a second, and the
`job_id`/`status` shape documented in Kap. 6.3 is preserved for the API
contract (and for a future move to a queue) without inventing a queue that
would only add moving parts to a sub-second operation.
"""

from __future__ import annotations

import hashlib
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.gateway.audit import append_audit_log
from app.models.engagement import Engagement
from app.models.report import Report
from app.models.scan_run import ScanRun
from app.pdf_report import render_report_pdf
from app.report_builder import build_report_model

logger = logging.getLogger(__name__)


def _latest_finished_run(db: Session, engagement_id: uuid.UUID) -> ScanRun | None:
    """The run a report describes: the most recent one that actually finished.

    A still-running run is deliberately not used - its findings are mid-flight
    and its diff would compare against a moving target.
    """
    return db.scalar(
        select(ScanRun)
        .where(ScanRun.engagement_id == engagement_id, ScanRun.state.in_(("done", "aborted", "failed")))
        .order_by(ScanRun.started_at.desc())
        .limit(1)
    )


def generate_report(
    db: Session,
    engagement_id: uuid.UUID,
    *,
    requested_by: str,
    scan_run_id: uuid.UUID | None = None,
) -> Report:
    """Build, persist, and audit one report. Always returns a Report row.

    A rendering failure is recorded as `status="failed"` with the reason rather
    than raised: the operator must be able to see that the report failed and
    why, and for the pipeline's report phase a failed report must never fail an
    otherwise-successful scan run.
    """
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise ValueError("engagement not found")

    run: ScanRun | None = None
    if scan_run_id is not None:
        run = db.get(ScanRun, scan_run_id)
        if run is not None and run.engagement_id != engagement_id:
            raise ValueError("scan_run does not belong to this engagement")
    if run is None:
        run = _latest_finished_run(db, engagement_id)

    report = Report(
        id=uuid.uuid4(),
        engagement_id=engagement_id,
        scan_run_id=run.id if run is not None else None,
        status="queued",
        requested_by=requested_by,
        filename="",
        byte_size=0,
    )

    try:
        model = build_report_model(db, eng, run)
        pdf = render_report_pdf(model)
        report.content = pdf
        report.byte_size = len(pdf)
        report.sha256 = hashlib.sha256(pdf).hexdigest()
        report.filename = f"asm-report-{engagement_id}-{report.id}.pdf"
        report.status = "done"
    except Exception as exc:  # noqa: BLE001 - surfaced as a failed report, never as a broken scan
        logger.exception("report generation failed for engagement %s", engagement_id)
        report.status = "failed"
        report.error = str(exc)[:500]
        report.filename = f"asm-report-{engagement_id}-failed.pdf"

    db.add(report)
    append_audit_log(
        db,
        engagement_id=engagement_id,
        actor=requested_by,
        action="report_generated",
        decision="ALLOW" if report.status == "done" else "DENY",
        reason="customer_report_generated" if report.status == "done" else "report_generation_failed",
        payload={
            "report_id": str(report.id),
            "scan_run_id": str(report.scan_run_id) if report.scan_run_id else None,
            "status": report.status,
            "bytes": report.byte_size,
            "sha256": report.sha256,
            "error": report.error,
        },
    )
    db.commit()
    db.refresh(report)
    return report
