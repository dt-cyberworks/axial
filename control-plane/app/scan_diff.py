"""Scan-Diff: neu / behoben / bestehend zwischen einem Lauf und seinem Vorgaenger.

Grundlage ist finding_observation (welcher Fingerprint wurde in welchem Lauf
beobachtet). Der Diff ist damit eine exakte Mengendifferenz, nicht geschaetzt:
  neu      = im Lauf beobachtet, im Vorgaenger nicht
  behoben  = im Vorgaenger beobachtet, im Lauf nicht mehr ("no longer observed")
  bestehend= in beiden

'behoben' ist bewusst als "nicht mehr beobachtet" zu lesen: das Finding kann in
der DB weiter 'open' sein - der Diff sagt nur, dass es dieser Lauf nicht mehr
gesehen hat (typischerweise weil es behoben wurde).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.asset import DiscoveredAsset
from app.models.finding import Finding, FindingObservation
from app.models.monitoring import RunInventorySnapshot
from app.models.scan_run import ScanRun

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _coverage_warning(run: ScanRun) -> bool:
    reason = run.state_reason or ""
    return "coverage_degraded" in reason or "coverage_partial" in reason


def _not_a_json_array(column):
    """A full run has no restriction. The column holds SQL NULL or, when the ORM was handed None, the JSON value
    null; a restriction is always a JSON array."""
    return func.coalesce(func.jsonb_typeof(column), "null") != "array"


def _previous_run(db: Session, run: ScanRun) -> ScanRun | None:
    """REQ-MODE-004: the baseline is the last earlier run that gave a full picture:
    `done`, without a coverage warning. A failed, aborted, degraded or partial run
    is never the baseline - comparing with it reports everything it missed as new."""
    candidates = db.scalars(
        select(ScanRun)
        .where(
            ScanRun.engagement_id == run.engagement_id,
            ScanRun.started_at < run.started_at,
            ScanRun.state == "done",
            ScanRun.trigger != "baseline",  # REQ-BASE-001: a discovery run is not a full picture
            # REQ-RETEST-002: neither is a run limited to some hosts or checks.
            _not_a_json_array(ScanRun.scope_hosts),
            _not_a_json_array(ScanRun.retest_items),
        )
        .order_by(ScanRun.started_at.desc())
    )
    for candidate in candidates:
        if not _coverage_warning(candidate):
            return candidate
    return None


def _observed(db: Session, run_id: uuid.UUID) -> dict[str, uuid.UUID]:
    return {
        o.fingerprint: o.finding_id
        for o in db.scalars(select(FindingObservation).where(FindingObservation.scan_run_id == run_id))
    }


def _detail(db: Session, finding_id: uuid.UUID) -> dict:
    f = db.get(Finding, finding_id)
    if f is None:
        return {"finding_id": str(finding_id), "title": "(unknown)", "severity": None,
                "category": None, "target": None, "status": None}
    asset = db.get(DiscoveredAsset, f.asset_id) if f.asset_id else None
    return {
        "finding_id": str(f.id), "title": f.title, "severity": f.severity,
        "category": f.category, "target": asset.value if asset else None,
        "status": f.status, "first_seen": f.first_seen.isoformat() if f.first_seen else None,
    }


def _by_severity(item: dict) -> int:
    return _SEV_ORDER.get(item.get("severity") or "info", 4)


def compute_diff(db: Session, run: ScanRun) -> dict:
    """Diff des uebergebenen Laufs gegen seinen unmittelbaren Vorgaenger."""
    prev = _previous_run(db, run)
    now_obs = _observed(db, run.id)

    # Ohne Vorgaenger gibt es keinen Delta: der erste Lauf ist die Baseline,
    # nicht "alles neu". new/resolved bleiben leer; has_baseline=false signalisiert
    # der GUI, den Vergleich gar nicht erst anzuzeigen.
    if prev is None:
        return {
            "run_id": str(run.id), "previous_run_id": None, "has_baseline": False,
            "observed_count": len(now_obs), "new": [], "resolved": [], "persisting_count": 0,
            "run_coverage_reduced": _coverage_warning(run),
            "inventory": compute_inventory_diff(db, run),
        }

    prev_obs = _observed(db, prev.id)
    new = sorted((_detail(db, now_obs[fp]) for fp in now_obs if fp not in prev_obs), key=_by_severity)
    resolved = sorted((_detail(db, prev_obs[fp]) for fp in prev_obs if fp not in now_obs), key=_by_severity)
    persisting = [fp for fp in now_obs if fp in prev_obs]

    return {
        "run_id": str(run.id),
        "previous_run_id": str(prev.id),
        "has_baseline": True,
        "inventory": compute_inventory_diff(db, run, prev),
        "observed_count": len(now_obs),
        "new": new,
        "resolved": resolved,
        "persisting_count": len(persisting),
        # REQ-MODE-004: a run with reduced coverage cannot say "fixed": the console
        # shows that "no longer seen" may only mean "not looked at".
        "run_coverage_reduced": _coverage_warning(run),
    }


def _inventory(db: Session, run_id: uuid.UUID, kind: str) -> dict[str, dict]:
    return {
        r.key: r.data for r in db.scalars(
            select(RunInventorySnapshot).where(RunInventorySnapshot.scan_run_id == run_id, RunInventorySnapshot.kind == kind)
        )
    }


def compute_inventory_diff(db: Session, run: ScanRun, prev: ScanRun | None = None) -> dict:
    """REQ-DIFF-001..004: which hosts and ports appeared, disappeared or changed since the previous run.

    Compared against the SAME run as the findings diff (`_previous_run`: the last earlier run that gave a full
    picture), so the two panels of the Diff tab never answer for different baselines. The data is what each run
    stored (`run_inventory_snapshot`), a set difference and not an estimate.

    Never claims that something is gone when the run did not look everywhere: a run with reduced coverage, or one
    limited to some hosts, reports what is new and what changed, but nothing as "no longer seen" or "closed".
    A run or baseline with no stored snapshot (it finished before snapshots were taken for every engagement) is
    "not recorded", never "everything is gone"."""
    prev = prev or _previous_run(db, run)
    reduced = _coverage_warning(run) or bool(run.scope_hosts)
    out = {"available": False, "reason": None, "previous_run_id": str(prev.id) if prev else None,
           "run_coverage_reduced": reduced, "assets_new": [], "assets_gone": [], "ports_opened": [],
           "ports_closed": [], "services_changed": []}
    if prev is None:
        out["reason"] = "no_baseline"
        return out
    now_a, base_a = _inventory(db, run.id, "asset"), _inventory(db, prev.id, "asset")
    now_s, base_s = _inventory(db, run.id, "service"), _inventory(db, prev.id, "service")
    if not (now_a or now_s) or not (base_a or base_s):
        out["reason"] = "no_snapshot"
        return out
    out["available"] = True
    out["assets_new"] = [{"key": k, "held": bool(now_a[k].get("held"))} for k in sorted(set(now_a) - set(base_a))]
    out["ports_opened"] = [{"key": k, **{f: now_s[k].get(f) for f in ("product", "version")}} for k in sorted(set(now_s) - set(base_s))]
    out["services_changed"] = [
        {"key": k, "from": {"product": base_s[k].get("product"), "version": base_s[k].get("version")},
         "to": {"product": now_s[k].get("product"), "version": now_s[k].get("version")}}
        for k in sorted(set(now_s) & set(base_s))
        if (base_s[k].get("product"), base_s[k].get("version")) != (now_s[k].get("product"), now_s[k].get("version"))
    ]
    if not reduced:
        out["assets_gone"] = [{"key": k} for k in sorted(set(base_a) - set(now_a))]
        out["ports_closed"] = [{"key": k, **{f: base_s[k].get(f) for f in ("product", "version")}} for k in sorted(set(base_s) - set(now_s))]
    return out
