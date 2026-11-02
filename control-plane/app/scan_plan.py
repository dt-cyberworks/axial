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

from app.models.asset import DiscoveredAsset
from app.models.dns_record import DnsRecord
from app.models.scan_plan import ScanCheck, ScanSurface
from app.models.scan_run import ScanRun
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


# REQ-OOB-001 (GitHub #76): the template classes that confirm through the platform's interaction server, by the pass
# that runs them (worker tool_runner_client.NUCLEI_OOB_PARTS; scripts/tests/test_oob_classes_parity.py keeps the pass
# names equal). A pass skipped for lack of the server is named by what it would have tested, not only "interaction
# server not deployed". Templates that do not use the server (every other nuclei pass) are not in these classes.
OOB_CHECK_PREFIX = "nuclei:oob:"
_BLIND = "Blind-vulnerability templates (blind injection, SSRF, XXE and similar)"
OOB_CLASSES = {
    "generic_a": _BLIND, "generic_b": _BLIND, "generic_c": _BLIND,
    "cves_recent": "CVE templates 2023-2026 that confirm through a callback",
    "cves_legacy": "CVE templates 2015-2022 that confirm through a callback",
}


def oob_class_of(check_id: str | None) -> str | None:
    """The template class of an interaction-server pass (`nuclei:oob:cves_recent`), else None."""
    if not check_id or not check_id.startswith(OOB_CHECK_PREFIX):
        return None
    return OOB_CLASSES.get(check_id[len(OOB_CHECK_PREFIX):])


def not_run_classes(db: Session, scan_run_id: uuid.UUID) -> list[dict]:
    """[{"label", "services"}] for each template class whose interaction-server pass was skipped as
    `oob_unavailable` in this run, with the number of services it was skipped on. Empty when the server was there,
    or the switch was off (then nothing was asked for)."""
    rows = db.execute(
        select(ScanCheck.check_id, ScanCheck.surface_id).where(
            ScanCheck.scan_run_id == scan_run_id, ScanCheck.state == "skipped", ScanCheck.reason == "oob_unavailable",
            ScanCheck.check_id.like(OOB_CHECK_PREFIX + "%"),
        )
    ).all()
    surfaces: dict[str, set] = {}
    for check_id, surface_id in rows:
        label = oob_class_of(check_id)
        if label:
            surfaces.setdefault(label, set()).add(surface_id)
    order = list(dict.fromkeys(OOB_CLASSES.values()))
    return [{"label": label, "services": len(surfaces[label])} for label in order if label in surfaces]


def check_out(check: ScanCheck) -> dict:
    return {
        "id": str(check.id), "seq": check.seq, "check_id": check.check_id, "tool": check.tool,
        "state": check.state, "reason": check.reason, "args": check.args or {}, "depends_on": check.depends_on,
        "budget_s": check.budget_s, "attempt": check.attempt,
        "started_at": check.started_at.isoformat() if check.started_at else None,
        "finished_at": check.finished_at.isoformat() if check.finished_at else None,
        "duration_s": float(check.duration_s) if check.duration_s is not None else None,
        "findings": check.findings, "outcome_summary": check.outcome_summary or {},
        # GitHub #76: what an interaction-server pass tests, in words (None for every other check).
        "template_class": oob_class_of(check.check_id),
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


# REQ-BASE-008: why a host that is in scope had no surface in a run.
UNTESTED_REASONS = {
    "held": "held back by the monitor's hold policy until the owner releases it",
    "no_address": "the name has no DNS address",
    "no_open_port": "no open port was found on it",
}


def _norm(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


def untested_hosts(db: Session, run: ScanRun | None) -> list[dict]:
    """In-scope hosts that this run did not test, and why. A host the owner chose that is silently left out
    (the case of GitHub #78: held, so the pipeline dropped it) must show up as such in the run and the report,
    whatever the reason. Only a finished full or host-limited run is judged: a discovery run, a passive run, a
    restricted retest and a run that is still going say nothing about hosts."""
    if run is None or run.state != "done" or run.trigger == "baseline" or run.retest_items is not None:
        return []
    if (run.scan_profile or "") == "passive":
        return []
    wanted = {_norm(h) for h in run.scope_hosts} if run.scope_hosts else None
    tested = {_norm(h) for (h,) in db.execute(select(ScanSurface.host).where(ScanSurface.scan_run_id == run.id))}
    latest: dict[str, DnsRecord] = {}
    for rec in db.scalars(select(DnsRecord).where(DnsRecord.engagement_id == run.engagement_id).order_by(DnsRecord.resolved_at)):
        latest[_norm(rec.fqdn)] = rec
    out: list[dict] = []
    for asset in db.scalars(
        select(DiscoveredAsset).where(DiscoveredAsset.engagement_id == run.engagement_id, DiscoveredAsset.in_scope.is_(True))
        .order_by(DiscoveredAsset.value)
    ):
        host = _norm(asset.value)
        if host in tested or (wanted is not None and host not in wanted):
            continue
        if run.finished_at is not None and asset.first_seen is not None and asset.first_seen > run.finished_at:
            continue  # found after this run: it could not have been tested by it
        if asset.hold_state == "held":
            reason = "held"
        elif asset.asset_type == "domain" and not (latest.get(host) is not None and (latest[host].terminal_ips or [])):
            reason = "no_address"
        else:
            reason = "no_open_port"
        out.append({"host": host, "reason": reason, "text": UNTESTED_REASONS[reason]})
    return out


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
        # REQ-BASE-008: not for the worker, which reads the plan to execute it.
        "untested_hosts": [] if internal else untested_hosts(db, db.get(ScanRun, scan_run_id)),
        # GitHub #76: template classes skipped for lack of an interaction server, by name. Not for the worker.
        "not_run_classes": [] if internal else not_run_classes(db, scan_run_id),
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
