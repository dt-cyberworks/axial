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

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import DiscoveredAsset
from app.models.finding import Finding, FindingObservation
from app.models.scan_run import ScanRun

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _previous_run(db: Session, run: ScanRun) -> ScanRun | None:
    return db.scalar(
        select(ScanRun)
        .where(ScanRun.engagement_id == run.engagement_id, ScanRun.started_at < run.started_at)
        .order_by(ScanRun.started_at.desc())
        .limit(1)
    )


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
        }

    prev_obs = _observed(db, prev.id)
    new = sorted((_detail(db, now_obs[fp]) for fp in now_obs if fp not in prev_obs), key=_by_severity)
    resolved = sorted((_detail(db, prev_obs[fp]) for fp in prev_obs if fp not in now_obs), key=_by_severity)
    persisting = [fp for fp in now_obs if fp in prev_obs]

    return {
        "run_id": str(run.id),
        "previous_run_id": str(prev.id),
        "has_baseline": True,
        "observed_count": len(now_obs),
        "new": new,
        "resolved": resolved,
        "persisting_count": len(persisting),
    }
