"""GitHub issue #15: the findings list exposes last_seen (MAX(observed_at)
over a finding's finding_observation rows), computed from data the scan-diff
machinery already collects - no new tracking, no migration."""

from __future__ import annotations

import datetime as dt

from app.api.findings import list_findings
from app.models.finding import Finding, FindingObservation
from app.models.scan_run import ScanRun


def _run(db, eng, days_ago):
    now = dt.datetime.now(dt.timezone.utc)
    r = ScanRun(engagement_id=eng.id, phase="report", state="done",
                started_at=now - dt.timedelta(days=days_ago))
    db.add(r); db.flush()
    return r


def _finding(db, eng, title, fp):
    f = Finding(engagement_id=eng.id, category="misconfig", title=title, confidence="validated",
                status="open", severity="high", fingerprint=fp,
                first_seen=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10))
    db.add(f); db.flush()
    return f


def _observe(db, run, eng, finding, fp, when):
    db.add(FindingObservation(
        scan_run_id=run.id, engagement_id=eng.id, fingerprint=fp, finding_id=finding.id, observed_at=when,
    ))


def test_last_seen_is_the_most_recent_observation(db, lab_engagement):
    eng = lab_engagement
    run1 = _run(db, eng, days_ago=5)
    run2 = _run(db, eng, days_ago=1)
    finding = _finding(db, eng, "Repeated finding", "fp-repeat")
    older = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=5)
    newer = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    _observe(db, run1, eng, finding, "fp-repeat", older)
    _observe(db, run2, eng, finding, "fp-repeat", newer)
    db.commit()

    out = list_findings(eng.id, None, None, db)

    row = next(f for f in out if f.title == "Repeated finding")
    assert row.last_seen is not None
    assert abs((row.last_seen - newer).total_seconds()) < 1
    assert row.last_seen != row.first_seen


def test_last_seen_is_none_when_no_observation_exists(db, lab_engagement):
    """A finding created outside the scan pipeline (e.g. inferred/manual, or
    one that predates finding_observation tracking) has no observation rows -
    must surface as None, not crash or fabricate a value."""
    eng = lab_engagement
    _finding(db, eng, "Never observed", "fp-unobserved")
    db.commit()

    out = list_findings(eng.id, None, None, db)

    row = next(f for f in out if f.title == "Never observed")
    assert row.last_seen is None


def test_last_seen_does_not_leak_across_engagements(db, lab_engagement, test_user):
    """A second engagement's observations must never bleed into the first's
    last_seen - the grouped query is scoped by engagement_id."""
    import datetime as dt2
    from app.models.engagement import Engagement

    other = Engagement(
        title="Other", source="lab", status="active",
        authorized_from=dt2.datetime.now(dt2.timezone.utc) - dt2.timedelta(hours=1),
        authorized_until=dt2.datetime.now(dt2.timezone.utc) + dt2.timedelta(days=1),
        owner_user_id=test_user.id,
    )
    db.add(other); db.flush()

    eng = lab_engagement
    finding = _finding(db, eng, "Scoped finding", "fp-scoped")
    other_finding = _finding(db, other, "Other engagement finding", "fp-scoped")  # same fingerprint, different engagement
    run = _run(db, eng, days_ago=1)
    other_run = _run(db, other, days_ago=0)
    _observe(db, run, eng, finding, "fp-scoped", dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))
    _observe(db, other_run, other, other_finding, "fp-scoped", dt.datetime.now(dt.timezone.utc))
    db.commit()

    out = list_findings(eng.id, None, None, db)

    row = next(f for f in out if f.title == "Scoped finding")
    assert row.last_seen is not None
    # must reflect eng's own (older) observation, not other's (newer) one.
    assert abs((row.last_seen - (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))).total_seconds()) < 5
