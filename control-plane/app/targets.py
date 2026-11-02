"""The target baseline of a monitoring engagement (REQ-BASE-001..005).

Activating a monitor starts a passive discovery. When it has finished the owner sees what was found
and chooses which hosts are monitored; the deny list is updated with that choice, and only then the
first scan runs. Nothing here is a rule: a host that does not exist yet is never decided about, and a
decision is an ordinary `deny` row of the scope, which the Scope Gateway enforces as it always did.

Narrowing is free. Widening (taking a host out of the deny list again) is confirmed and never done
while a run is active, like every other widening of an active engagement.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import uuid

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import monitoring, operating_modes
from app.gateway.audit import append_audit_logs
from app.models.asset import DiscoveredAsset
from app.models.dns_record import DnsRecord
from app.models.engagement import Engagement, ScopeAsset
from app.models.resolved_host import ResolvedHost
from app.models.scan_run import ScanRun

PENDING_STATES = ("discovering", "awaiting_selection", "discovery_failed")
ACTIVE_RUN_STATES = ("running", "waiting_approval")


class TargetsError(Exception):
    def __init__(self, status: int, detail):
        super().__init__(str(detail))
        self.status = status
        self.detail = detail


@dataclasses.dataclass
class Candidate:
    asset_id: uuid.UUID
    value: str
    ips: list[str]
    provider: str | None
    dns_status: str
    discovered_via: str
    first_seen: dt.datetime | None
    denied: bool
    is_root: bool
    flag: str  # same_address | other_address | unresolved
    suggested: bool
    # REQ-BASE-007: the monitor's hold policy kept this host out of the tests until the owner releases it.
    held: bool = False


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _norm(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


# --------------------------------------------------------------- the list


def candidates(db: Session, eng: Engagement) -> list[Candidate]:
    """Discovered hosts that are covered by an allow row, or explicitly denied, with their addresses
    and a flag saying whether they resolve where the allowed roots resolve."""
    rules = db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id)).all()
    denied = {_norm(r.value) for r in rules if r.rule == "deny" and r.asset_type == "domain"}
    roots = {_norm(r.value) for r in rules if r.rule == "allow" and r.asset_type == "domain"}

    latest: dict[str, DnsRecord] = {}
    for rec in db.scalars(select(DnsRecord).where(DnsRecord.engagement_id == eng.id).order_by(DnsRecord.resolved_at)):
        latest[_norm(rec.fqdn)] = rec  # later rows win

    root_ips: set[str] = set()
    for root in roots:
        rec = latest.get(root)
        if rec is not None:
            root_ips.update(str(ip) for ip in (rec.terminal_ips or []))

    out: list[Candidate] = []
    seen: set[str] = set()
    for asset in db.scalars(
        select(DiscoveredAsset).where(DiscoveredAsset.engagement_id == eng.id, DiscoveredAsset.asset_type == "domain")
        .order_by(DiscoveredAsset.value)
    ):
        value = _norm(asset.value)
        if value in seen or not (asset.in_scope or value in denied):
            continue
        seen.add(value)
        rec = latest.get(value)
        ips = sorted({str(ip) for ip in (rec.terminal_ips or [])}) if rec is not None else []
        resolved = bool(ips) and (rec is None or rec.dns_status == "resolved")
        if not resolved:
            flag = "unresolved"
        elif root_ips and set(ips) <= root_ips:
            flag = "same_address"
        else:
            flag = "other_address"
        is_root = value in roots
        is_denied = value in denied
        out.append(Candidate(
            asset_id=asset.id, value=value, ips=ips, provider=(rec.hosting_provider if rec is not None else None),
            dns_status=(rec.dns_status if rec is not None else "unresolved"), discovered_via=asset.discovered_via,
            first_seen=asset.first_seen, denied=is_denied, is_root=is_root, flag=flag,
            suggested=(not is_denied) and (is_root or flag == "same_address"),
            held=asset.hold_state == "held",
        ))
    return out


def _active_run(db: Session, engagement_id: uuid.UUID) -> bool:
    return db.scalar(
        select(ScanRun.id).where(ScanRun.engagement_id == engagement_id, ScanRun.state.in_(ACTIVE_RUN_STATES)).limit(1)
    ) is not None


# --------------------------------------------------------- discovery runs


def start_discovery(db: Session, eng: Engagement, *, initiated_by: str, activation: bool = False, enqueue=None):
    """Start the passive discovery (REQ-BASE-001). Returns the run, or None when it could not start
    (the reason is in `eng`'s state `discovery_failed` and in the returned error)."""
    if eng.operating_mode != "monitoring":
        raise TargetsError(409, "target discovery belongs to a monitoring engagement")
    if eng.target_review_state == "discovering" and not activation:
        heal(db, eng)  # a run that was stopped by a pause or a revoke never reported back
        if eng.target_review_state == "discovering":
            raise TargetsError(409, "a discovery is already running")
    try:
        started = operating_modes.begin_scan(
            db, eng.id, trigger="baseline", initiated_by=initiated_by, enqueue=enqueue,
        )
    except operating_modes.ScanNotStartable as exc:
        if activation or eng.target_review_state in (None, "awaiting_selection", "discovery_failed"):
            eng.target_review_state = "discovery_failed"
            db.commit()
        raise TargetsError(exc.status, exc.detail) from None
    eng = db.get(Engagement, eng.id)
    # A review of a confirmed monitor refreshes the list and blocks nothing.
    if eng.target_review_state != "confirmed":
        eng.target_review_state = "discovering"
    eng.target_review_run_id = started.run.id
    db.commit()
    return started.run


def heal(db: Session, eng: Engagement) -> None:
    """`discovering` with a review run that is already over (stopped by a pause or a revoke, which
    end runs directly) is settled as if it had reported: `awaiting_selection` or `discovery_failed`."""
    if eng.target_review_state != "discovering" or eng.target_review_run_id is None:
        return
    run = db.get(ScanRun, eng.target_review_run_id)
    if run is not None and run.state in ("done", "failed", "aborted"):
        on_discovery_finished(db, eng, run)
        db.commit()


def on_discovery_finished(db: Session, eng: Engagement, run: ScanRun) -> None:
    """A baseline run reached a terminal state (called from monitoring.on_run_finished)."""
    if eng.target_review_state != "discovering":
        return  # a refresh of an already confirmed monitor: nothing changes
    if run.state == "done":
        eng.target_review_state = "awaiting_selection"
        monitoring.open_inbox_item(
            db, eng.id, "targets_to_select", "targets_to_select",
            f"{eng.title}: discovery finished. Choose the targets to monitor; nothing is scanned until you do.",
            {"scan_run_id": str(run.id)},
        )
        monitoring.queue_alert(
            db, eng, "targets_to_select", f"{eng.title}: discovery finished, choose the targets to monitor", run_id=run.id,
        )
    else:
        eng.target_review_state = "discovery_failed"
        monitoring.open_inbox_item(
            db, eng.id, "discovery_failed", "discovery_failed",
            f"{eng.title}: the discovery did not finish ({run.state_reason or run.state}). Run it again.",
            {"scan_run_id": str(run.id), "reason": run.state_reason},
        )


# ------------------------------------------------------------- confirming


@dataclasses.dataclass
class ConfirmResult:
    excluded: int
    included: int
    kept: int
    policy: str
    first_run_id: uuid.UUID | None
    first_run_error: object | None
    released: int = 0


def confirm(
    db: Session, eng: Engagement, *, selected_ids: list[uuid.UUID], policy: str | None, actor_email: str,
    confirm_widening: bool = False, enqueue=None,
) -> ConfirmResult:
    """REQ-BASE-003. Atomic: nothing changes unless the whole request is acceptable."""
    if eng.operating_mode != "monitoring":
        raise TargetsError(409, "targets are chosen for a monitoring engagement")
    if eng.status in ("completed", "revoked"):
        raise TargetsError(409, f"engagement is {eng.status}")
    if eng.target_review_state == "discovering":
        raise TargetsError(409, "the discovery is still running; choose the targets when it has finished")
    if eng.target_review_state == "discovery_failed":
        raise TargetsError(409, "the discovery did not finish; run it again first")
    if policy is not None and policy not in ("auto", "hold"):
        raise TargetsError(422, "new_asset_policy must be auto or hold")

    first_confirmation = eng.target_review_state == "awaiting_selection"
    cand = {c.asset_id: c for c in candidates(db, eng)}
    selected = list(dict.fromkeys(selected_ids))
    unknown = [i for i in selected if i not in cand]
    if unknown:
        raise TargetsError(404, "every selected id must be a discovered host of this engagement")
    chosen = set(selected)

    excluded = [c for c in cand.values() if c.asset_id not in chosen and not c.denied]
    included = [c for c in cand.values() if c.asset_id in chosen and c.denied]
    # REQ-BASE-007: choosing a host that the hold policy is holding releases it. Without this the screen showed the
    # host ticked and the scan silently skipped it. Releasing widens what is tested, like including a denied host.
    released = [c for c in cand.values() if c.asset_id in chosen and c.held]
    if any(c.is_root for c in excluded):
        raise TargetsError(422, "a host that is an allow row of this engagement cannot be left out; remove the row instead")

    widening = bool(included) or bool(released) or (policy == "auto" and eng.new_asset_policy == "hold" and not first_confirmation)
    if widening and eng.status == "active":
        if _active_run(db, eng.id):
            raise TargetsError(409, "scan_run_active: targets cannot be widened while a run is active")
        if not confirm_widening:
            raise TargetsError(409, "confirmation_required: this widens what the monitor tests; confirm to proceed")

    now = _now()
    actor = f"user:{actor_email}"
    bulk_id = uuid.uuid4()
    entries: list[dict] = []
    for c in excluded:
        db.add(ScopeAsset(engagement_id=eng.id, rule="deny", asset_type="domain", value=c.value, active_allowed=False))
        asset = db.get(DiscoveredAsset, c.asset_id)
        if asset is not None:
            asset.in_scope = False
        entries.append({
            "actor": actor, "action": "target_excluded", "decision": "DENY", "reason": "targets_confirmed",
            "payload": {"host": c.value, "asset_id": str(c.asset_id), "addresses": c.ips, "flag": c.flag,
                        "bulk_id": str(bulk_id)},
        })
    for c in included:
        db.execute(delete(ScopeAsset).where(
            ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "deny", ScopeAsset.asset_type == "domain",
            ScopeAsset.value.ilike(c.value),
        ))
        asset = db.get(DiscoveredAsset, c.asset_id)
        if asset is not None:
            asset.in_scope = True
        entries.append({
            "actor": actor, "action": "target_included", "decision": "ALLOW", "reason": "targets_confirmed",
            "payload": {"host": c.value, "asset_id": str(c.asset_id), "bulk_id": str(bulk_id)},
        })
    for c in released:
        if monitoring.release_asset(db, eng.id, c.asset_id, actor_email):
            entries.append({
                "actor": actor, "action": "asset_released", "decision": "ALLOW", "reason": "targets_confirmed",
                "payload": {"host": c.value, "asset_id": str(c.asset_id), "bulk_id": str(bulk_id)},
            })
    if excluded or included:
        # A changed scope invalidates the name -> address materialization (see add_scope_asset).
        db.execute(delete(ResolvedHost).where(ResolvedHost.engagement_id == eng.id))

    previous_policy = eng.new_asset_policy
    if policy is not None:
        eng.new_asset_policy = policy
    eng.target_review_state = "confirmed"
    eng.targets_confirmed_at = now
    eng.targets_confirmed_by = actor_email
    entries.append({
        "actor": actor, "action": "targets_confirmed", "decision": None, "reason": None,
        "payload": {
            "bulk_id": str(bulk_id), "monitored": len(chosen), "excluded": len(excluded), "included": len(included),
            "released": len(released),
            "candidates": len(cand), "new_asset_policy": eng.new_asset_policy, "previous_policy": previous_policy,
            "first_confirmation": first_confirmation,
        },
    })
    monitoring.resolve_inbox_items(db, eng.id, "targets_to_select", actor_email)
    monitoring.resolve_inbox_items(db, eng.id, "discovery_failed", actor_email)
    append_audit_logs(db, engagement_id=eng.id, entries=entries)  # one transaction, commits

    first_run_id: uuid.UUID | None = None
    first_run_error = None
    if first_confirmation:
        try:
            started = operating_modes.begin_scan(
                db, eng.id, trigger="manual", initiated_by=actor_email, enqueue=enqueue,
            )
            first_run_id = started.run.id
        except operating_modes.ScanNotStartable as exc:
            first_run_error = exc.detail  # the targets stay confirmed; the owner can fix it and Run now
    return ConfirmResult(
        excluded=len(excluded), included=len(included), kept=len(chosen), policy=eng.new_asset_policy,
        first_run_id=first_run_id, first_run_error=first_run_error, released=len(released),
    )
