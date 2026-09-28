import datetime as dt
import json
import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import report_service
from app.db.base import get_db
from app.gateway.audit import append_audit_log
from app.models.asset import DiscoveredAsset, Service
from app.models.dns_record import DnsRecord
from app.models.engagement import Engagement
from app.models.finding import Finding, FindingObservation
from app.models.report import Report
from app.models.resolved_host import ResolvedHost
from app.schemas.finding import (
    FINDING_STATUSES,
    DnsRecordOut,
    EngagementSummary,
    FindingExplanationOut,
    FindingOut,
    FindingTriageIn,
)
from app.models.user import User
from app.security import require_user
from app.settings_store import get_llm_config

router = APIRouter(prefix="/engagements", tags=["findings"])

_AMPEL_BY_SEVERITY = {"critical": "rot", "high": "rot", "medium": "gelb", "low": "blau", "info": "blau"}


def _normalize_chat_base_url(base_url: str) -> str:
    normalized = base_url.strip().rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized[: -len("/chat/completions")]
    if normalized.endswith("/responses"):
        return normalized[: -len("/responses")]
    return normalized


def _safe_lens_error(exc: Exception) -> str:
    return str(exc)[:500]


def _cached_lens(evidence: dict | None) -> dict | None:
    if not isinstance(evidence, dict):
        return None
    value = evidence.get("lens_agent")
    if isinstance(value, dict) and isinstance(value.get("explanation"), str) and value["explanation"].strip():
        return value
    return None


def _lens_context(finding: FindingOut) -> dict:
    return {
        "finding_id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity,
        "category": finding.category,
        "confidence": finding.confidence,
        "risk_score": finding.risk_score,
        "target": {
            "asset_value": finding.asset_value,
            "asset_type": finding.asset_type,
            "target_ip": finding.target_ip,
            "service_port": finding.service_port,
            "service_protocol": finding.service_protocol,
            "service_product": finding.service_product,
            "service_version": finding.service_version,
        },
        "vulnerability": {
            "cve_ids": finding.cve_ids or [],
            "cvss_base": finding.cvss_base,
            "epss": finding.epss,
        },
        "evidence": finding.evidence or {},
        "raw_ref": finding.raw_ref,
        "first_seen": finding.first_seen.isoformat(),
    }


def _call_lens_agent(db: Session, context: dict) -> tuple[str, str, bool]:
    cfg = get_llm_config(db)
    if not cfg.is_usable:
        raise HTTPException(status_code=409, detail="Lens Agent provider is not configured. Set base URL, model, and API key in Settings.")

    base_url = _normalize_chat_base_url(cfg.base_url)
    prompt = (
        "You are Lens Agent for an authorized external attack-surface management scan. "
        "Explain the provided finding for a security operator and a customer. "
        "Use only the supplied finding data; do not invent proof, exploit steps, or affected systems. "
        "Return concise Markdown with exactly these headings: What it is, Where it was found, Why it matters, What to do. "
        "Keep remediation practical and non-alarmist. If evidence is weak or inferred, say so clearly.\n\n"
        f"Finding JSON:\n{json.dumps(context, sort_keys=True, default=str)}"
    )
    try:
        with httpx.Client(timeout=45.0) as client:
            resp = client.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json"},
                json={
                    "model": cfg.model,
                    "messages": [
                        {"role": "system", "content": "You are Lens Agent, the explanatory analyst for ASM findings."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    # GitHub issue #14: 700 is not enough headroom for four
                    # Markdown sections (What it is / Where it was found / Why
                    # it matters / What to do) - a real BREACH/testssl finding
                    # was observed cut off mid-sentence in "Why it matters",
                    # with "What to do" never appearing at all. 2000 gives
                    # comfortable room (~1500 words) while staying bounded;
                    # finish_reason is still checked below as a backstop for
                    # whatever finding eventually needs more than that.
                    "max_tokens": 2000,
                },
            )
            resp.raise_for_status()
            payload = resp.json()
            choice = payload["choices"][0]
            explanation = choice["message"]["content"].strip()
            # GitHub issue #14: a partial response was previously treated
            # exactly like a complete one - cached, returned, and rendered
            # with no indication anything was missing. finish_reason=="length"
            # means the provider stopped ONLY because it hit the token cap,
            # not because it finished the answer.
            truncated = choice.get("finish_reason") == "length"
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - provider errors become operator-visible API errors
        raise HTTPException(status_code=502, detail=f"Lens Agent provider call failed: {_safe_lens_error(exc)}") from exc

    if not explanation:
        raise HTTPException(status_code=502, detail="Lens Agent provider returned an empty explanation")
    return explanation, cfg.model, truncated


def _finding_out(db: Session, finding: Finding, last_seen: dt.datetime | None = None) -> FindingOut:
    asset = db.get(DiscoveredAsset, finding.asset_id) if finding.asset_id else None
    service = db.get(Service, finding.service_id) if finding.service_id else None
    target_ip = None
    if asset and asset.asset_type == "domain":
        resolved = db.scalar(
            select(ResolvedHost)
            .where(
                ResolvedHost.engagement_id == finding.engagement_id,
                ResolvedHost.hostname == asset.value,
            )
            .order_by(ResolvedHost.resolved_at.desc())
            .limit(1)
        )
        target_ip = resolved.ip_address if resolved else None
    elif asset and asset.asset_type == "ip":
        target_ip = asset.value

    return FindingOut(
        id=finding.id,
        engagement_id=finding.engagement_id,
        asset_id=finding.asset_id,
        service_id=finding.service_id,
        asset_value=asset.value if asset else None,
        asset_type=asset.asset_type if asset else None,
        target_ip=target_ip,
        service_port=service.port if service else None,
        service_protocol=service.protocol if service else None,
        service_product=service.product if service else None,
        service_version=service.version if service else None,
        category=finding.category,
        title=finding.title,
        cve_ids=finding.cve_ids,
        cvss_base=float(finding.cvss_base) if finding.cvss_base is not None else None,
        epss=float(finding.epss) if finding.epss is not None else None,
        confidence=finding.confidence,
        status=finding.status,
        status_note=finding.status_note,
        status_changed_at=finding.status_changed_at,
        status_changed_by=finding.status_changed_by,
        severity=finding.severity,
        risk_score=float(finding.risk_score) if finding.risk_score is not None else None,
        evidence=finding.evidence or None,
        raw_ref=finding.raw_ref,
        first_seen=finding.first_seen,
        last_seen=last_seen,
    )


@router.get("/{engagement_id}/findings", response_model=list[FindingOut])
def list_findings(
    engagement_id: uuid.UUID,
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    stmt = select(Finding).where(Finding.engagement_id == engagement_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status:
        stmt = stmt.where(Finding.status == status)
    rows = db.scalars(stmt.order_by(Finding.risk_score.desc().nulls_last())).all()
    # GitHub issue #15: one extra grouped query for the whole page rather than
    # one per finding - finding_observation already records exactly this
    # (one row per (scan_run_id, fingerprint) actually observed), so no new
    # tracking/migration is needed, just reading what's already collected.
    last_seen_by_finding_id = dict(
        db.execute(
            select(FindingObservation.finding_id, func.max(FindingObservation.observed_at))
            .where(FindingObservation.engagement_id == engagement_id)
            .group_by(FindingObservation.finding_id)
        ).all()
    )
    return [_finding_out(db, finding, last_seen_by_finding_id.get(finding.id)) for finding in rows]


@router.patch("/{engagement_id}/findings/{finding_id}", response_model=FindingOut)
def triage_finding(
    engagement_id: uuid.UUID, finding_id: uuid.UUID, body: FindingTriageIn,
    user: User = Depends(require_user), db: Session = Depends(get_db),
):
    """REQ-TRIAGE-001: mark a finding open / accepted risk / false positive /
    resolved. The engagement's ownership is checked router-wide; the finding
    must belong to that engagement. Every change is written to the
    engagement's hash-chained audit log."""
    finding = db.get(Finding, finding_id)
    if finding is None or finding.engagement_id != engagement_id:
        raise HTTPException(404, "finding not found")
    previous = finding.status
    finding.status = body.status
    finding.status_note = body.note
    finding.status_changed_at = dt.datetime.now(dt.timezone.utc)
    finding.status_changed_by = user.email
    db.commit()
    append_audit_log(
        db, engagement_id=engagement_id, actor=f"user:{user.email}", action="finding_triage",
        decision=body.status, reason=body.note,
        payload={"finding_id": str(finding.id), "title": finding.title, "from": previous, "to": body.status},
    )
    db.refresh(finding)
    return _finding_out(db, finding, _last_seen(db, finding))


def _last_seen(db: Session, finding: Finding) -> dt.datetime | None:
    return db.scalar(
        select(func.max(FindingObservation.observed_at)).where(FindingObservation.finding_id == finding.id)
    )


@router.get("/{engagement_id}/dns-records", response_model=list[DnsRecordOut])
def list_dns_records(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """DNS/Hosting-Inventar (CNAME-Ketten, Provider, Dangling-Status) fuer die
    Operator-Konsole. Reines Metadatum - siehe REQ-DNS-001..003. Dangling zuerst,
    dann alphabetisch."""
    rows = db.scalars(
        select(DnsRecord)
        .where(DnsRecord.engagement_id == engagement_id)
        .order_by(DnsRecord.takeover_suspected.desc(), DnsRecord.fqdn)
    ).all()
    return list(rows)


@router.get("/{engagement_id}/summary", response_model=EngagementSummary)
def summary(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """GET /engagements/{id}/summary (Architektur Kap. 6.3): Risiko-Ampel + Top-Handlungen."""
    findings = db.scalars(
        select(Finding).where(Finding.engagement_id == engagement_id, Finding.status == "open")
    ).all()

    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity:
            counts[f.severity] = counts.get(f.severity, 0) + 1

    worst = next((sev for sev in ("critical", "high", "medium", "low", "info") if counts[sev] > 0), "info")
    top_actions = [
        f.title
        for f in sorted(findings, key=lambda f: f.risk_score or 0, reverse=True)[:3]
    ]
    by_status = dict.fromkeys(FINDING_STATUSES, 0)
    for status, count in db.execute(
        select(Finding.status, func.count()).where(Finding.engagement_id == engagement_id).group_by(Finding.status)
    ).all():
        by_status[status] = count
    return EngagementSummary(
        risk_ampel=_AMPEL_BY_SEVERITY.get(worst, "blau"),
        counts_by_severity=counts,
        counts_by_status=by_status,
        top_actions=top_actions,
    )


@router.post("/{engagement_id}/findings/{finding_id}/lens-explanation", response_model=FindingExplanationOut)
def explain_finding_with_lens(engagement_id: uuid.UUID, finding_id: uuid.UUID, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if finding is None or finding.engagement_id != engagement_id:
        raise HTTPException(status_code=404, detail="finding not found")

    cached = _cached_lens(finding.evidence)
    if cached:
        return FindingExplanationOut(
            finding_id=finding.id,
            explanation=cached["explanation"],
            source="cached",
            generated_at=dt.datetime.fromisoformat(cached["generated_at"]),
            model=cached.get("model"),
            truncated=bool(cached.get("truncated", False)),
        )

    finding_out = _finding_out(db, finding)
    context = _lens_context(finding_out)
    try:
        explanation, model, truncated = _call_lens_agent(db, context)
    except HTTPException as exc:
        append_audit_log(
            db,
            engagement_id=engagement_id,
            actor="lens_agent",
            action="lens_explanation",
            decision="DENY",
            reason="lens_provider_failed" if exc.status_code >= 500 else "lens_provider_missing",
            payload={"finding_id": str(finding_id), "status_code": exc.status_code, "detail": str(exc.detail)[:500]},
        )
        raise

    generated_at = dt.datetime.now(dt.timezone.utc)
    evidence = dict(finding.evidence or {})
    evidence["lens_agent"] = {
        "explanation": explanation,
        "generated_at": generated_at.isoformat(),
        "model": model,
        "truncated": truncated,
    }
    finding.evidence = evidence
    db.add(finding)
    append_audit_log(
        db,
        engagement_id=engagement_id,
        actor="lens_agent",
        action="lens_explanation",
        decision="ALLOW",
        reason="finding_explained",
        payload={"finding_id": str(finding_id), "model": model, "truncated": truncated},
    )
    db.commit()
    return FindingExplanationOut(
        finding_id=finding.id,
        explanation=explanation,
        source="llm",
        generated_at=generated_at,
        model=model,
        truncated=truncated,
    )


def _report_out(report: Report) -> dict:
    """Job-shaped view (Architektur Kap. 6.3). `job_id` IS the report id, so a
    caller can poll or download with the identifier it already has."""
    return {
        "job_id": str(report.id),
        "report_id": str(report.id),
        "status": report.status,
        "scan_run_id": str(report.scan_run_id) if report.scan_run_id else None,
        "filename": report.filename,
        "byte_size": report.byte_size,
        "sha256": report.sha256,
        "error": report.error,
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }


@router.post("/{engagement_id}/report", status_code=202)
def request_report(
    engagement_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """POST /engagements/{id}/report (Architektur Kap. 6.3): generates the
    customer PDF (REQ-REPORT-001, structure per Kap. 6.1 including the
    mandatory methodology & scope section).

    Generation is synchronous - it is DB reads plus text rendering, no network
    calls - so the returned job is already terminal (`done` or `failed`). The
    job-shaped response is kept so the documented contract holds and a future
    move to a queue needs no client change.
    """
    if db.get(Engagement, engagement_id) is None:
        raise HTTPException(404, "engagement not found")
    report = report_service.generate_report(db, engagement_id, requested_by=f"user:{user.email}")
    return _report_out(report)


@router.get("/{engagement_id}/reports")
def list_reports(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """Previously generated reports, newest first. Metadata only - the PDF
    bytes are fetched per report via the download route."""
    rows = db.scalars(
        select(Report).where(Report.engagement_id == engagement_id).order_by(Report.created_at.desc())
    ).all()
    return [_report_out(report) for report in rows]


@router.get("/{engagement_id}/reports/{report_id}")
def download_report(
    engagement_id: uuid.UUID, report_id: uuid.UUID,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    report = db.get(Report, report_id)
    # Checking engagement ownership of the row (not just the id) keeps a report
    # id from another engagement from being readable through this path.
    if report is None or report.engagement_id != engagement_id:
        raise HTTPException(404, "report not found")
    if report.status != "done" or not report.content:
        raise HTTPException(409, f"report is not available (status: {report.status})")

    append_audit_log(
        db,
        engagement_id=engagement_id,
        actor=f"user:{user.email}",
        action="report_downloaded",
        decision="ALLOW",
        reason="customer_report_downloaded",
        payload={"report_id": str(report.id), "sha256": report.sha256, "bytes": report.byte_size},
    )
    db.commit()
    return Response(
        content=bytes(report.content),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{report.filename}"'},
    )
