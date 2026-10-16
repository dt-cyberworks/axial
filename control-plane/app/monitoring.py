"""What a finished run leaves behind in a monitoring engagement
(REQ-MODE-008, -012, -013, -014, REQ-MON-002).

The change feed is a set difference of two snapshots of what runs saw, so it does
not depend on how the live tables are updated. Rules that keep it trustworthy:

  * the baseline is the last *healthy* run, never the last run;
  * a degraded or failed run produces no "gone", "closed" or "resolved" event;
  * "resolved" needs the finding absent from two consecutive healthy runs;
  * the first healthy run is the baseline and produces no events.

Alerts never carry evidence, credentials or raw tool output: a kind, a title, a
severity and a link.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.config import get_settings
from app.gateway.audit import append_audit_log
from app.models.asset import DiscoveredAsset
from app.models.engagement import Engagement, ScopeAsset
from app.models.finding import Finding, FindingObservation
from app.models.monitoring import (
    AlertEvent,
    ChangeEvent,
    InboxItem,
    NotificationTarget,
    RunInventorySnapshot,
)
from app.models.scan_run import ScanRun

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
# Events that are worth a message right away; the rest goes into the daily digest.
IMMEDIATE_KINDS = {
    "target_degraded", "missed_run", "authorization_expiring", "run_failed", "run_degraded", "schedule_stopped",
}
DIGEST_HOUR_UTC = 8
MISSED_RUN_FACTOR = 2.0
REVIEW_WARNING_DAYS = 14


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------------------------------------------- inbox items


def open_inbox_item(
    db: Session, engagement_id: uuid.UUID, kind: str, dedupe_key: str, summary: str, detail: dict | None = None,
) -> InboxItem | None:
    """One open item per (engagement, dedupe_key): raising the same thing twice is a no-op."""
    stmt = (
        pg_insert(InboxItem)
        .values(engagement_id=engagement_id, kind=kind, dedupe_key=dedupe_key, summary=summary[:500], detail=detail or {})
        .on_conflict_do_nothing(index_elements=["engagement_id", "dedupe_key"], index_where=InboxItem.state == "open")
        .returning(InboxItem.id)
    )
    new_id = db.execute(stmt).scalar()
    return db.get(InboxItem, new_id) if new_id is not None else None


def resolve_inbox_items(db: Session, engagement_id: uuid.UUID, dedupe_prefix: str, by: str) -> int:
    rows = db.scalars(
        select(InboxItem).where(
            InboxItem.engagement_id == engagement_id, InboxItem.state == "open",
            InboxItem.dedupe_key.like(f"{dedupe_prefix}%"),
        )
    ).all()
    for row in rows:
        row.state = "resolved"
        row.resolved_at = _now()
        row.resolved_by = by
    return len(rows)


def add_suggestion(db: Session, engagement_id: uuid.UUID, tool: str, target: str, rationale: str) -> InboxItem | None:
    """REQ-MODE-007: a proposal that needed a person's decision, which an unattended
    run cannot get. It is kept as a suggestion for a manual test."""
    summary = f"Suggested manual test: {tool} on {target}"
    return open_inbox_item(
        db, engagement_id, "suggestion", f"suggestion:{tool}:{target.lower()}", summary,
        {"tool": tool, "target": target, "rationale": (rationale or "")[:500]},
    )


# ------------------------------------------------------------------- alerts


def next_digest_time(now: dt.datetime | None = None) -> dt.datetime:
    now = now or _now()
    slot = now.replace(hour=DIGEST_HOUR_UTC, minute=0, second=0, microsecond=0)
    return slot if slot > now else slot + dt.timedelta(days=1)


def _console_link(engagement_id: uuid.UUID, tab: str | None = None) -> str:
    base = (get_settings().public_base_url or "").rstrip("/")
    path = f"/engagements/{engagement_id}" + (f"?tab={tab}" if tab else "")
    return f"{base}{path}"


def queue_alert(
    db: Session, eng: Engagement, kind: str, title: str, *, severity: str | None = None,
    run_id: uuid.UUID | None = None, tab: str | None = None, immediate: bool | None = None,
) -> int:
    """Queue one alert per enabled target. The body holds no evidence, secrets or raw
    tool output. A finding event only reaches a target whose threshold it meets."""
    targets = db.scalars(
        select(NotificationTarget).where(NotificationTarget.engagement_id == eng.id, NotificationTarget.enabled.is_(True))
    ).all()
    if immediate is None:
        immediate = kind in IMMEDIATE_KINDS or severity == "critical"
    queued = 0
    for target in targets:
        if kind.startswith("finding_") and severity is not None:
            if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK.get(target.min_severity, 3):
                continue
        db.add(AlertEvent(
            engagement_id=eng.id, target_id=target.id, event_kind=kind, immediate=bool(immediate),
            payload={
                "event": kind, "engagement": {"id": str(eng.id), "title": eng.title},
                "title": title[:300], "severity": severity,
                "run_id": str(run_id) if run_id else None, "link": _console_link(eng.id, tab),
            },
            deliver_after=_now() if immediate else next_digest_time(),
        ))
        queued += 1
    return queued


# --------------------------------------------------------- run-finished hook


def health_of(run: ScanRun) -> str:
    """ok | degraded | failed (REQ-MODE-012)."""
    if run.state in ("failed", "aborted"):
        return "failed"
    reason = run.state_reason or ""
    if "coverage_degraded" in reason or "coverage_partial" in reason:
        return "degraded"
    return "ok"


def _last_healthy_runs(db: Session, run: ScanRun, limit: int = 2) -> list[ScanRun]:
    return list(db.scalars(
        select(ScanRun)
        .where(
            ScanRun.engagement_id == run.engagement_id, ScanRun.id != run.id, ScanRun.health == "ok",
            ScanRun.started_at < run.started_at,
        )
        .order_by(ScanRun.started_at.desc())
        .limit(limit)
    ))


def _observed(db: Session, run_id: uuid.UUID) -> set[str]:
    return set(db.scalars(select(FindingObservation.fingerprint).where(FindingObservation.scan_run_id == run_id)))


def build_snapshot(db: Session, run: ScanRun) -> int:
    """Store what this run saw: the in-scope assets seen during it and the services
    its fingerprint phase found. Idempotent."""
    rows: dict[tuple[str, str], dict] = {}
    for asset in db.scalars(
        select(DiscoveredAsset).where(
            DiscoveredAsset.engagement_id == run.engagement_id, DiscoveredAsset.in_scope.is_(True),
            DiscoveredAsset.last_seen >= run.started_at,
        )
    ):
        rows[("asset", asset.value.lower())] = {"asset_type": asset.asset_type, "held": asset.hold_state == "held"}
    services = (run.checkpoint or {}).get("services") or []
    for svc in services if isinstance(services, list) else []:
        if not isinstance(svc, dict) or not svc.get("target") or svc.get("port") is None:
            continue
        key = f"{str(svc['target']).lower()}:{svc['port']}/{svc.get('protocol') or 'tcp'}"
        rows[("service", key)] = {
            "product": svc.get("product_name") or svc.get("product"), "version": svc.get("version"),
        }
    existing = {
        (r.kind, r.key) for r in db.scalars(select(RunInventorySnapshot).where(RunInventorySnapshot.scan_run_id == run.id))
    }
    for (kind, key), data in rows.items():
        if (kind, key) not in existing:
            db.add(RunInventorySnapshot(
                scan_run_id=run.id, engagement_id=run.engagement_id, kind=kind, key=key, data=data,
            ))
    db.flush()
    return len(rows)


def _snapshot(db: Session, run_id: uuid.UUID, kind: str) -> dict[str, dict]:
    return {
        r.key: r.data for r in db.scalars(
            select(RunInventorySnapshot).where(
                RunInventorySnapshot.scan_run_id == run_id, RunInventorySnapshot.kind == kind
            )
        )
    }


def _event(db: Session, run: ScanRun, kind: str, subject: str, severity: str | None = None, detail: dict | None = None) -> ChangeEvent:
    ev = ChangeEvent(
        engagement_id=run.engagement_id, scan_run_id=run.id, kind=kind, subject=subject[:300],
        severity=severity, detail=detail or {},
    )
    db.add(ev)
    return ev


def compute_changes(db: Session, run: ScanRun) -> list[ChangeEvent]:
    """The events of one run against the last healthy run (see the module note)."""
    previous = _last_healthy_runs(db, run, limit=2)
    if not previous:
        return []  # this is the baseline
    baseline = previous[0]
    healthy = run.health == "ok"
    events: list[ChangeEvent] = []

    now_assets, base_assets = _snapshot(db, run.id, "asset"), _snapshot(db, baseline.id, "asset")
    for key in sorted(set(now_assets) - set(base_assets)):
        events.append(_event(db, run, "asset_new", key, "info", {"held": bool(now_assets[key].get("held"))}))
    if healthy:
        for key in sorted(set(base_assets) - set(now_assets)):
            events.append(_event(db, run, "asset_gone", key, "info"))

    now_svc, base_svc = _snapshot(db, run.id, "service"), _snapshot(db, baseline.id, "service")
    for key in sorted(set(now_svc) - set(base_svc)):
        events.append(_event(db, run, "port_opened", key, "low", now_svc[key]))
    if healthy:
        for key in sorted(set(base_svc) - set(now_svc)):
            events.append(_event(db, run, "port_closed", key, "info", base_svc[key]))
    for key in sorted(set(now_svc) & set(base_svc)):
        before, after = base_svc[key], now_svc[key]
        if (before.get("product"), before.get("version")) != (after.get("product"), after.get("version")):
            events.append(_event(db, run, "service_changed", key, "low", {"from": before, "to": after}))

    now_obs, base_obs = _observed(db, run.id), _observed(db, baseline.id)
    new_fps = now_obs - base_obs
    if new_fps:
        for finding in db.scalars(
            select(Finding).join(FindingObservation, FindingObservation.finding_id == Finding.id).where(
                FindingObservation.scan_run_id == run.id, FindingObservation.fingerprint.in_(new_fps),
            )
        ):
            events.append(_event(
                db, run, "finding_new", finding.title, finding.severity,
                {"finding_id": str(finding.id), "confidence": finding.confidence, "category": finding.category,
                 "is_kev": bool(finding.is_kev)},
            ))
    for finding in db.scalars(
        select(Finding).join(FindingObservation, FindingObservation.finding_id == Finding.id).where(
            FindingObservation.scan_run_id == run.id, Finding.status_changed_by == "scan",
            Finding.status_changed_at >= run.started_at, Finding.status == "open",
        )
    ):
        events.append(_event(db, run, "finding_regressed", finding.title, finding.severity, {"finding_id": str(finding.id)}))
    if healthy and len(previous) == 2:
        gone_twice = _observed(db, previous[1].id) - base_obs - now_obs
        if gone_twice:
            for finding in db.scalars(select(Finding).where(
                Finding.engagement_id == run.engagement_id, Finding.fingerprint.in_(gone_twice),
            )):
                events.append(_event(db, run, "finding_resolved", finding.title, finding.severity, {"finding_id": str(finding.id)}))
    db.flush()
    return events


def _alert_for_event(db: Session, eng: Engagement, run: ScanRun, ev: ChangeEvent) -> None:
    if ev.kind in ("asset_gone", "port_closed", "finding_resolved"):
        return  # good or neutral news is in the feed, not in a message
    if ev.kind == "finding_new":
        # An inferred, agent-derived lead does not wake anyone; a validated finding or a
        # correlated CVE does.
        if ev.detail.get("confidence") != "validated" and ev.detail.get("category") != "cve":
            return
        immediate = ev.severity == "critical" or bool(ev.detail.get("is_kev"))
        queue_alert(db, eng, ev.kind, f"New finding: {ev.subject}", severity=ev.severity, run_id=run.id,
                    tab="findings", immediate=immediate)
    elif ev.kind == "finding_regressed":
        queue_alert(db, eng, ev.kind, f"Regression: {ev.subject}", severity=ev.severity, run_id=run.id, tab="findings",
                    immediate=ev.severity in ("critical", "high"))
    elif ev.kind == "asset_new":
        queue_alert(db, eng, ev.kind, f"New asset: {ev.subject}", run_id=run.id, tab="changes", immediate=False)
    elif ev.kind == "port_opened":
        queue_alert(db, eng, ev.kind, f"New open port: {ev.subject}", run_id=run.id, tab="changes", immediate=False)
    elif ev.kind == "service_changed":
        queue_alert(db, eng, ev.kind, f"Service changed: {ev.subject}", run_id=run.id, tab="changes", immediate=False)


def apply_retest(db: Session, run: ScanRun) -> None:
    """REQ-MODE-017: a retest run resolves its finding when this run, which gave a full
    picture, did not observe it. A finding that is still there keeps its state."""
    if run.retest_finding_id is None or run.health != "ok":
        return
    finding = db.get(Finding, run.retest_finding_id)
    if finding is None or finding.engagement_id != run.engagement_id or finding.status != "open":
        return
    still_there = finding.fingerprint in _observed(db, run.id)
    if not still_there:
        finding.status = "resolved"
        finding.status_note = "retest: not observed in the retest run"
        finding.status_changed_at = _now()
        finding.status_changed_by = run.initiated_by or "retest"
    append_audit_log(
        db, engagement_id=run.engagement_id, actor=f"user:{run.initiated_by}" if run.initiated_by else "control-plane",
        action="finding_retest", decision="ALLOW", reason="not_observed" if not still_there else "still_present",
        payload={"finding_id": str(finding.id), "scan_run_id": str(run.id)},
    )


def on_run_finished(db: Session, run: ScanRun) -> dict:
    """Called once when a run reaches a terminal state. Never raises into the
    caller's transition: bookkeeping must not be what fails a run."""
    summary: dict = {"health": None, "events": 0}
    try:
        eng = db.get(Engagement, run.engagement_id)
        if eng is None:
            return summary
        run.health = health_of(run)
        summary["health"] = run.health
        apply_retest(db, run)
        if eng.operating_mode != "monitoring":
            db.commit()
            return summary
        if run.health != "failed":
            build_snapshot(db, run)
        events = compute_changes(db, run)
        summary["events"] = len(events)
        for ev in events:
            _alert_for_event(db, eng, run, ev)

        if run.health == "ok":
            resolve_inbox_items(db, eng.id, "run_degraded", "system")
            resolve_inbox_items(db, eng.id, "run_failed", "system")
            resolve_inbox_items(db, eng.id, "missed_run", "system")
        elif run.health == "degraded":
            open_inbox_item(
                db, eng.id, "run_degraded", f"run_degraded:{run.id}",
                f"The run of {run.started_at:%Y-%m-%d %H:%M} had reduced coverage: nothing was concluded as fixed from it.",
                {"scan_run_id": str(run.id), "reason": run.state_reason},
            )
            queue_alert(db, eng, "run_degraded", f"A run of {eng.title} had reduced coverage", run_id=run.id, tab="runs")
        else:
            open_inbox_item(
                db, eng.id, "run_failed", f"run_failed:{run.id}",
                f"The run of {run.started_at:%Y-%m-%d %H:%M} did not finish: {run.state_reason or run.state}.",
                {"scan_run_id": str(run.id), "reason": run.state_reason},
            )
            queue_alert(db, eng, "run_failed", f"A run of {eng.title} did not finish", run_id=run.id, tab="runs")

        append_audit_log(
            db, engagement_id=eng.id, actor="control-plane", action="run_evaluated", decision=None,
            reason=run.health, payload={"scan_run_id": str(run.id), "health": run.health, "events": len(events)},
        )
        db.commit()
    except Exception:  # noqa: BLE001
        logger.exception("run-finished bookkeeping failed for %s", run.id)
        db.rollback()
    return summary


# ---------------------------------------------------- held assets (hold policy)


def evaluate_hold(db: Session, run: ScanRun, candidates: list[dict]) -> dict:
    """REQ-MODE-008. `candidates` are the in-scope assets discovery found
    ({asset_id, value}). Returns {"released": [asset_id], "held": [asset_id]}.

    Only assets created during this run can be held: an asset that existed before the
    policy was switched on is not suddenly taken away. A host that is itself a scope
    row value was declared by the owner and is never held."""
    eng = db.get(Engagement, run.engagement_id)
    ids = [c.get("asset_id") for c in candidates if c.get("asset_id")]
    if eng is None or eng.operating_mode != "monitoring" or eng.new_asset_policy != "hold":
        return {"released": ids, "held": []}

    declared = {
        (a.value or "").lower().rstrip(".")
        for a in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "allow"))
    }
    released: list[str] = []
    held: list[str] = []
    now = _now()
    for cand in candidates:
        raw_id = cand.get("asset_id")
        if not raw_id:
            continue
        asset = db.get(DiscoveredAsset, uuid.UUID(str(raw_id)))
        if asset is None or asset.engagement_id != eng.id:
            continue
        value = asset.value.lower().rstrip(".")
        if asset.hold_state == "held":
            held.append(str(asset.id))
        elif asset.hold_state == "released" or value in declared or asset.first_seen < run.started_at:
            released.append(str(asset.id))
        else:
            asset.hold_state = "held"
            asset.held_at = now
            held.append(str(asset.id))
            open_inbox_item(
                db, eng.id, "held_asset", f"held_asset:{value}",
                f"New host {asset.value} was found and is held: it is not tested until you release it.",
                {"asset_id": str(asset.id), "value": asset.value, "scan_run_id": str(run.id)},
            )
    db.commit()
    return {"released": released, "held": held}


def release_asset(db: Session, engagement_id: uuid.UUID, asset_id: uuid.UUID, by: str) -> bool:
    asset = db.get(DiscoveredAsset, asset_id)
    if asset is None or asset.engagement_id != engagement_id or asset.hold_state != "held":
        return False
    asset.hold_state = "released"
    asset.released_at = _now()
    asset.released_by = by
    resolve_inbox_items(db, engagement_id, f"held_asset:{asset.value.lower().rstrip('.')}", by)
    return True


# -------------------------------------------- missed runs, authorization review


def housekeeping(db: Session, now: dt.datetime | None = None) -> dict:
    """Missed-run and authorization-review checks for every monitoring engagement.
    Safe to call often: every item is raised once until it is resolved."""
    now = now or _now()
    result = {"missed_runs": 0, "expiring": 0}
    engagements = db.scalars(
        select(Engagement).where(Engagement.operating_mode == "monitoring", Engagement.status == "active")
    ).all()
    for eng in engagements:
        if eng.schedule_every_days:
            window = dt.timedelta(days=int(eng.schedule_every_days)) * MISSED_RUN_FACTOR
            last_ok = db.scalar(
                select(ScanRun.finished_at)
                .where(ScanRun.engagement_id == eng.id, ScanRun.health == "ok")
                .order_by(ScanRun.finished_at.desc()).limit(1)
            )
            since = last_ok or eng.schedule_set_at or eng.created_at
            if now - since > window:
                created = open_inbox_item(
                    db, eng.id, "missed_run", "missed_run",
                    f"No healthy run of {eng.title} finished in the last {int(window.total_seconds() // 3600)} hours.",
                    {"last_ok_run": last_ok.isoformat() if last_ok else None},
                )
                if created is not None:
                    queue_alert(db, eng, "missed_run", f"{eng.title}: no healthy run for {int(window.days)} day(s)", tab="runs")
                    result["missed_runs"] += 1
        end = min(x for x in (eng.review_at, eng.authorized_until) if x is not None)
        if timedelta_days(end - now) <= REVIEW_WARNING_DAYS and end > now:
            created = open_inbox_item(
                db, eng.id, "authorization_expiring", "authorization_expiring",
                f"The authorization of {eng.title} needs review by {end:%Y-%m-%d}; schedules stop then.",
                {"ends_at": end.isoformat()},
            )
            if created is not None:
                queue_alert(db, eng, "authorization_expiring", f"{eng.title}: authorization review due {end:%Y-%m-%d}", tab="settings")
                result["expiring"] += 1
    db.commit()
    return result


def timedelta_days(delta: dt.timedelta) -> float:
    return delta.total_seconds() / 86400.0


def notify_run_needs_you(db: Session, eng: Engagement, run: ScanRun, approval, what: str) -> None:
    """REQ-MODE-017: a semi-attended run parked on a decision. The tester is told
    (inbox and any notification target), because nobody is watching the screen."""
    open_inbox_item(
        db, eng.id, "run_needs_you", f"run_needs_you:{approval.id}",
        f"A run of {eng.title} is waiting for your decision: {what}.",
        {"scan_run_id": str(run.id), "approval_id": str(approval.id), "link": f"/engagements/{eng.id}/runs/{run.id}"},
    )
    queue_alert(
        db, eng, "run_needs_you", f"{eng.title}: a run is waiting for your decision", run_id=run.id, tab="runs",
        immediate=True,
    )
    db.commit()
