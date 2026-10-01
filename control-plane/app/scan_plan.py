"""Persisted scan plan (REQ-PIPE-003/006/008/010).

The worker's planner decides what runs; this module only stores the plan and the
progress of its checks. Storing a plan never authorizes anything: every check is
still one Scope-Gateway-authorized tool call at execution time.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.scan_plan import ScanCheck, ScanSurface
from app.schemas.internal import ScanCheckUpdate, ScanPlanIn, ScanSurfaceUpdate

TERMINAL_STATES = ("complete", "partial", "failed", "skipped")
# A check that was `running` when its worker died is run again; a finished one
# never is (REQ-PIPE-008).
UNFINISHED_STATES = ("planned", "running")

# Set-cookie and friends can carry session identifiers of the target; they are
# never stored or shown (the audit trail redacts them for the same reason).
_HIDDEN_HEADERS = {"set-cookie", "cookie", "authorization", "proxy-authorization", "www-authenticate"}
_PUBLIC_FINGERPRINT_KEYS = ("url", "status_code", "title", "webserver", "tech", "protocol", "content_length")


def scrub_fingerprint(fingerprint: dict) -> dict:
    """Bound and clean a fingerprint before it is stored."""
    cleaned = dict(fingerprint or {})
    headers = cleaned.get("headers")
    if isinstance(headers, dict):
        cleaned["headers"] = {
            str(k)[:64].lower(): str(v)[:300]
            for k, v in list(headers.items())[:60]
            if str(k).strip().lower() not in _HIDDEN_HEADERS
        }
    return cleaned


def store_plan(db: Session, scan_run_id: uuid.UUID, engagement_id: uuid.UUID, body: ScanPlanIn) -> dict:
    """Idempotent: a surface or check that already exists keeps its state, so
    posting the same plan again after a worker restart never resets progress."""
    next_seq = (db.scalar(select(func.coalesce(func.max(ScanCheck.seq), 0)).where(ScanCheck.scan_run_id == scan_run_id)) or 0) + 1
    created_surfaces = created_checks = 0
    for item in body.surfaces:
        surface = db.scalar(select(ScanSurface).where(
            ScanSurface.scan_run_id == scan_run_id, ScanSurface.host == item.host, ScanSurface.port == item.port,
        ))
        if surface is None:
            surface = ScanSurface(
                scan_run_id=scan_run_id, engagement_id=engagement_id, asset_id=item.asset_id, host=item.host,
                ip=item.ip, port=item.port, scheme=item.scheme, service_class=item.service_class,
                alias_of=item.alias_of, profile=list(item.profile), fingerprint=scrub_fingerprint(item.fingerprint),
            )
            db.add(surface)
            db.flush()
            created_surfaces += 1
        existing = {c for (c,) in db.execute(select(ScanCheck.check_id).where(ScanCheck.surface_id == surface.id))}
        for check in item.checks:
            if check.check_id in existing:
                continue
            db.add(ScanCheck(
                scan_run_id=scan_run_id, engagement_id=engagement_id, surface_id=surface.id, seq=next_seq,
                check_id=check.check_id, tool=check.tool, args=check.args, depends_on=check.depends_on,
                state=check.state, reason=check.reason, budget_s=check.budget_s,
                finished_at=datetime.datetime.now(datetime.timezone.utc) if check.state == "skipped" else None,
            ))
            next_seq += 1
            created_checks += 1
    db.commit()
    return {"surfaces_created": created_surfaces, "checks_created": created_checks}


def apply_check_update(check: ScanCheck, body: ScanCheckUpdate) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    if body.state is not None:
        check.state = body.state
        if body.state == "running":
            check.attempt += 1
            check.started_at = now
            check.finished_at = None
        elif body.state in TERMINAL_STATES:
            check.finished_at = now
    if body.reason is not None:
        check.reason = body.reason
    if body.args is not None:
        check.args = body.args
    if body.budget_s is not None:
        check.budget_s = body.budget_s
    if body.findings is not None:
        check.findings = body.findings
    if body.duration_s is not None:
        check.duration_s = body.duration_s
    if body.outcome_summary is not None:
        check.outcome_summary = {str(k)[:64]: v for k, v in list(body.outcome_summary.items())[:30]}


def apply_surface_update(surface: ScanSurface, body: ScanSurfaceUpdate) -> None:
    if body.profile is not None:
        surface.profile = list(dict.fromkeys(body.profile))[:64]
    if body.fingerprint is not None:
        surface.fingerprint = scrub_fingerprint({**(surface.fingerprint or {}), **body.fingerprint})


def check_out(check: ScanCheck) -> dict:
    return {
        "id": str(check.id), "seq": check.seq, "check_id": check.check_id, "tool": check.tool,
        "state": check.state, "reason": check.reason, "args": check.args or {}, "depends_on": check.depends_on,
        "budget_s": check.budget_s, "attempt": check.attempt,
        "started_at": check.started_at.isoformat() if check.started_at else None,
        "finished_at": check.finished_at.isoformat() if check.finished_at else None,
        "duration_s": float(check.duration_s) if check.duration_s is not None else None,
        "findings": check.findings, "outcome_summary": check.outcome_summary or {},
    }


def surface_out(surface: ScanSurface, checks: list[ScanCheck], *, internal: bool) -> dict:
    fingerprint = surface.fingerprint or {}
    if not internal:
        fingerprint = {k: fingerprint[k] for k in _PUBLIC_FINGERPRINT_KEYS if k in fingerprint}
    return {
        "id": str(surface.id), "asset_id": str(surface.asset_id) if surface.asset_id else None,
        "host": surface.host, "ip": surface.ip, "port": surface.port, "scheme": surface.scheme,
        "service_class": surface.service_class, "alias_of": surface.alias_of,
        "profile": surface.profile or [], "fingerprint": fingerprint,
        "checks": [check_out(c) for c in sorted(checks, key=lambda c: c.seq)],
    }


def read_plan(db: Session, scan_run_id: uuid.UUID, *, internal: bool = False) -> dict:
    surfaces = db.scalars(
        select(ScanSurface).where(ScanSurface.scan_run_id == scan_run_id).order_by(ScanSurface.host, ScanSurface.port)
    ).all()
    checks = db.scalars(select(ScanCheck).where(ScanCheck.scan_run_id == scan_run_id).order_by(ScanCheck.seq)).all()
    by_surface: dict[uuid.UUID, list[ScanCheck]] = {}
    for check in checks:
        by_surface.setdefault(check.surface_id, []).append(check)
    counts: dict[str, int] = {}
    for check in checks:
        counts[check.state] = counts.get(check.state, 0) + 1
    return {
        "scan_run_id": str(scan_run_id),
        "summary": {"checks": len(checks), "by_state": counts, "surfaces": len(surfaces)},
        "surfaces": [surface_out(s, by_surface.get(s.id, []), internal=internal) for s in surfaces],
    }


# REQ-PIPE-018: what the Vector Agent is told about the run's own checks. Kept
# small on purpose (LLM context) and free of anything the target returned.
AGENT_CHECKS_PER_HOST = 60
_AGENT_REASON_MAX = 80


def agent_check_summary(db: Session, scan_run_id: uuid.UUID) -> dict[str, list[dict]]:
    """host -> the run's finished or skipped checks, for the agent's evidence.

    Only what the agent needs to avoid repeating work: port, tool, outcome and,
    for ffuf, the wordlist key. A check that has not finished (planned or
    running) is left out - it is still to come, not something to skip."""
    rows = db.execute(
        select(ScanSurface.host, ScanSurface.port, ScanCheck)
        .join(ScanCheck, ScanCheck.surface_id == ScanSurface.id)
        .where(ScanCheck.scan_run_id == scan_run_id, ScanCheck.state.in_(TERMINAL_STATES))
        .order_by(ScanSurface.host, ScanSurface.port, ScanCheck.seq)
    ).all()
    out: dict[str, list[dict]] = {}
    for host, port, check in rows:
        items = out.setdefault(str(host).lower(), [])
        if len(items) >= AGENT_CHECKS_PER_HOST:
            continue
        item = {"port": port, "check_id": check.check_id, "tool": check.tool, "state": check.state}
        wordlist = (check.args or {}).get("wordlist") if check.tool == "ffuf" else None
        if isinstance(wordlist, str):
            item["wordlist"] = wordlist[:40]
        if check.state == "skipped":
            item["reason"] = str(check.reason or "")[:_AGENT_REASON_MAX]
        items.append(item)
    return out
