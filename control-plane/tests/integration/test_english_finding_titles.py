"""REQ-TEXT-001: finding titles are English now, without breaking continuity.

A finding recorded under its old German title must still be the same finding
(same row, same triage decision) when a later scan reports the English title,
and migration 0032 must rename the stored titles without touching fingerprints.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from sqlalchemy import select, text

from app.api.internal import add_finding
from app.models.engagement import Engagement
from app.models.finding import Finding
from app.schemas.internal import FindingIn

MIGRATION = Path(__file__).resolve().parents[2] / "migrations" / "0032_english_finding_titles.sql"

PAIRS = [
    ("WAF erkannt: Cloudflare", "WAF detected: Cloudflare"),
    ("Fehlende Security-Header: content-security-policy, x-frame-options",
     "Missing security headers: content-security-policy, x-frame-options"),
    ("OpenSSH - veraltete Version", "OpenSSH - outdated version"),
    ("Apache Tomcat - veraltete Version", "Apache Tomcat - outdated version"),
    ("MySQL - Authentication Bypass bei wiederholtem Login", "MySQL - authentication bypass on repeated login"),
]


def _engagement(db) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(title="Titles", source="own_domain", status="active",
                     authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1))
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _report(db, eng: Engagement, title: str) -> Finding:
    resp = add_finding(eng.id, FindingIn(asset_id=None, service_id=None, category="misconfig", title=title,
                                         confidence="validated", evidence={"tool": "test"}), db)
    return db.get(Finding, resp["id"])


@pytest.mark.parametrize("german,english", PAIRS)
def test_a_finding_recorded_under_the_german_title_is_matched_by_the_english_one(db, german, english):
    eng = _engagement(db)
    old = _report(db, eng, german)
    old.status, old.status_note = "accepted_risk", "known, behind VPN"
    db.commit()
    new = _report(db, eng, english)
    assert new.id == old.id
    db.expire_all()
    rows = db.scalars(select(Finding).where(Finding.engagement_id == eng.id)).all()
    assert len(rows) == 1 and rows[0].status == "accepted_risk"


def test_negative_other_titles_are_not_mapped(db):
    eng = _engagement(db)
    a = _report(db, eng, "WAF detected: Cloudflare")
    b = _report(db, eng, "WAF detected: Akamai")
    c = _report(db, eng, "Missing HSTS header")
    assert len({a.id, b.id, c.id}) == 3


def test_migration_renames_stored_titles_keeps_fingerprints_and_is_idempotent(db):
    eng = _engagement(db)
    findings = [_report(db, eng, german) for german, _ in PAIRS]
    before = {f.id: f.fingerprint for f in findings}
    sql = MIGRATION.read_text()
    for _ in range(2):  # the second run must change nothing
        db.execute(text(sql))
        db.commit()
    db.expire_all()
    rows = {f.id: f for f in db.scalars(select(Finding).where(Finding.engagement_id == eng.id))}
    assert sorted(f.title for f in rows.values()) == sorted(english for _, english in PAIRS)
    assert {fid: f.fingerprint for fid, f in rows.items()} == before
    # ... and a re-scan with the English titles still lands on the same rows.
    for _, english in PAIRS:
        assert _report(db, eng, english).id in before
