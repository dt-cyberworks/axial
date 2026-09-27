"""Scan-Diff: neu/behoben/bestehend zwischen aufeinanderfolgenden Laeufen,
plus die Aufzeichnung der Beobachtungen durch add_finding."""

from __future__ import annotations

import datetime as dt
import uuid

from app import scan_diff
from app.api.internal import add_finding
from app.models.asset import DiscoveredAsset
from app.models.finding import Finding, FindingObservation
from app.models.scan_run import ScanRun
from app.schemas.internal import FindingIn


def _run(db, eng, days_ago, state="done"):
    now = dt.datetime.now(dt.timezone.utc)
    r = ScanRun(engagement_id=eng.id, phase="report", state=state,
                started_at=now - dt.timedelta(days=days_ago))
    db.add(r); db.flush()
    return r


def _finding(db, eng, title, fp, severity="high"):
    f = Finding(engagement_id=eng.id, category="misconfig", title=title, confidence="validated",
                status="open", severity=severity, fingerprint=fp,
                first_seen=dt.datetime.now(dt.timezone.utc))
    db.add(f); db.flush()
    return f


def _observe(db, run, eng, finding, fp):
    db.add(FindingObservation(scan_run_id=run.id, engagement_id=eng.id, fingerprint=fp, finding_id=finding.id))


def test_diff_new_resolved_persisting(db, lab_engagement):
    eng = lab_engagement
    run1 = _run(db, eng, days_ago=2)
    run2 = _run(db, eng, days_ago=1)
    fa = _finding(db, eng, "Finding A", "fpA", "medium")
    fb = _finding(db, eng, "Finding B", "fpB", "high")
    fc = _finding(db, eng, "Finding C", "fpC", "critical")
    # run1 sah A + B; run2 sah B + C  -> neu: C, behoben: A, bestehend: B
    _observe(db, run1, eng, fa, "fpA"); _observe(db, run1, eng, fb, "fpB")
    _observe(db, run2, eng, fb, "fpB"); _observe(db, run2, eng, fc, "fpC")
    db.commit()

    diff = scan_diff.compute_diff(db, run2)
    assert diff["has_baseline"] is True
    assert diff["previous_run_id"] == str(run1.id)
    assert [x["title"] for x in diff["new"]] == ["Finding C"]
    assert [x["title"] for x in diff["resolved"]] == ["Finding A"]
    assert diff["persisting_count"] == 1
    # neu ist nach Severity sortiert (critical zuerst)
    assert diff["new"][0]["severity"] == "critical"


def test_diff_first_run_has_no_baseline(db, lab_engagement):
    eng = lab_engagement
    run1 = _run(db, eng, days_ago=1)
    fa = _finding(db, eng, "Finding A", "fpA")
    _observe(db, run1, eng, fa, "fpA")
    db.commit()

    diff = scan_diff.compute_diff(db, run1)
    assert diff["has_baseline"] is False
    assert diff["previous_run_id"] is None
    # Ohne Vorgaenger gibt es kein "neu/behoben" - alles ist einfach beobachtet.
    assert diff["new"] == [] and diff["resolved"] == []
    assert diff["observed_count"] == 1


def test_add_finding_records_observation_for_running_run(db, lab_engagement):
    eng = lab_engagement
    asset = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value="metasploitable2",
                            in_scope=True, discovered_via="scope-direct",
                            first_seen=dt.datetime.now(dt.timezone.utc), last_seen=dt.datetime.now(dt.timezone.utc))
    db.add(asset)
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running",
                  started_at=dt.datetime.now(dt.timezone.utc))
    db.add(run); db.commit()

    add_finding(eng.id, FindingIn(asset_id=asset.id, category="misconfig",
                                  title="Missing header", confidence="validated"), db)

    obs = db.scalars(select_observations(run.id)).all()
    assert len(obs) == 1 and obs[0].finding_id is not None


def select_observations(run_id: uuid.UUID):
    from sqlalchemy import select
    return select(FindingObservation).where(FindingObservation.scan_run_id == run_id)
