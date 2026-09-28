"""REQ-TRIAGE-001..004 (docs/requirements/finding-triage.md).

HTTP cases go through a TestClient because engagement ownership is enforced
by a router-level dependency. Re-observation goes through the same internal
add_finding the worker calls after every scan.
"""

from __future__ import annotations

import datetime as dt
import io

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.api.internal import add_finding
from app.db.base import get_db
from app.main import app
from app.models.audit import AuditLog
from app.models.engagement import Engagement
from app.models.finding import Finding, FindingObservation
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
from app.pdf_report import render_report_pdf
from app.report_builder import build_report_model
from app.schemas.internal import FindingIn


@pytest.fixture()
def client(engine):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def _user(db, role: str = "operator") -> User:
    user = User(email=f"{role}-{dt.datetime.now(dt.timezone.utc).timestamp()}@example.com",
                display_name="Triage Test", role=role, status="active", must_change_password=False,
                password_hash=hash_secret("irrelevant-not-used"))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _auth(db, user: User) -> dict[str, str]:
    raw_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    return {"Authorization": f"Bearer {raw_token}"}


def _engagement(db, owner: User) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(title="Triage", source="own_domain", status="active",
                     authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
                     owner_user_id=owner.id)
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _observe(db, eng: Engagement, title: str = "Directory listing enabled") -> Finding:
    """What the worker does after a scan: report a raw finding."""
    resp = add_finding(eng.id, FindingIn(
        asset_id=None, service_id=None, category="misconfig", title=title, confidence="validated",
        evidence={"tool": "nikto"}, exposure_factor=1.0, business_factor=0.5, severity_override="medium",
    ), db)
    return db.get(Finding, resp["id"])


def _findings(db, eng: Engagement) -> list[Finding]:
    db.expire_all()
    return list(db.scalars(select(Finding).where(Finding.engagement_id == eng.id)))


# --- REQ-TRIAGE-001: the triage API -------------------------------------------

def test_owner_marks_a_false_positive_with_a_note(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    finding = _observe(db, eng)
    resp = client.patch(f"/engagements/{eng.id}/findings/{finding.id}",
                        json={"status": "false_positive", "note": "Test fixture, not production"},
                        headers=_auth(db, owner))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "false_positive"
    assert body["status_note"] == "Test fixture, not production"
    assert body["status_changed_by"] == owner.email
    assert body["status_changed_at"] is not None
    audit = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id,
                                              AuditLog.action == "finding_triage")).all()
    assert len(audit) == 1
    assert audit[0].payload["from"] == "open" and audit[0].payload["to"] == "false_positive"
    assert audit[0].actor == f"user:{owner.email}"


@pytest.mark.parametrize("status", ["false_positive", "accepted_risk"])
@pytest.mark.parametrize("note", [None, "", "  ", "ok"])
def test_negative_dismissing_a_finding_requires_a_reason(client, db, status, note):
    owner = _user(db)
    eng = _engagement(db, owner)
    finding = _observe(db, eng)
    resp = client.patch(f"/engagements/{eng.id}/findings/{finding.id}", json={"status": status, "note": note},
                        headers=_auth(db, owner))
    assert resp.status_code == 422
    assert _findings(db, eng)[0].status == "open"


def test_resolved_and_reopen_need_no_note(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    finding = _observe(db, eng)
    headers = _auth(db, owner)
    for status in ("resolved", "open"):
        resp = client.patch(f"/engagements/{eng.id}/findings/{finding.id}", json={"status": status}, headers=headers)
        assert resp.status_code == 200 and resp.json()["status"] == status


def test_negative_unknown_status_is_rejected(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    finding = _observe(db, eng)
    resp = client.patch(f"/engagements/{eng.id}/findings/{finding.id}", json={"status": "deleted"},
                        headers=_auth(db, owner))
    assert resp.status_code == 422


def test_negative_another_operator_cannot_triage(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    finding = _observe(db, eng)
    resp = client.patch(f"/engagements/{eng.id}/findings/{finding.id}",
                        json={"status": "false_positive", "note": "hide it"}, headers=_auth(db, _user(db)))
    assert resp.status_code == 404
    assert _findings(db, eng)[0].status == "open"


def test_negative_a_finding_of_another_engagement_is_not_reachable_through_mine(client, db):
    attacker = _user(db)
    mine = _engagement(db, attacker)
    victim_finding = _observe(db, _engagement(db, _user(db)))
    resp = client.patch(f"/engagements/{mine.id}/findings/{victim_finding.id}",
                        json={"status": "false_positive", "note": "hide it"}, headers=_auth(db, attacker))
    assert resp.status_code == 404
    db.expire_all()
    assert db.get(Finding, victim_finding.id).status == "open"


# --- REQ-TRIAGE-002: decisions survive the next scan ---------------------------

@pytest.mark.parametrize("status", ["false_positive", "accepted_risk"])
def test_a_triaged_finding_stays_triaged_when_seen_again(db, status):
    eng = _engagement(db, _user(db))
    finding = _observe(db, eng)
    finding.status, finding.status_note = status, "decided"
    run = ScanRun(engagement_id=eng.id, state="running")  # the next scan
    db.add(run)
    db.commit()

    again = _observe(db, eng)

    rows = _findings(db, eng)
    assert len(rows) == 1, "a re-observation must not create an open duplicate"
    assert again.id == finding.id and rows[0].status == status and rows[0].status_note == "decided"
    # Recorded as seen in this run, so the scan diff does not report it as fixed.
    observed = db.scalars(select(FindingObservation.scan_run_id).where(FindingObservation.finding_id == finding.id)).all()
    assert observed == [run.id]


def test_a_resolved_finding_seen_again_reopens_and_is_audited(db):
    eng = _engagement(db, _user(db))
    finding = _observe(db, eng)
    finding.status = "resolved"
    db.commit()

    _observe(db, eng)

    rows = _findings(db, eng)
    assert len(rows) == 1
    assert rows[0].status == "open" and rows[0].status_changed_by == "scan"
    audit = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id,
                                              AuditLog.action == "finding_triage")).all()
    assert [a.payload["from"] for a in audit] == ["resolved"] and audit[0].actor == "scan"


def test_a_different_finding_is_still_created_normally(db):
    eng = _engagement(db, _user(db))
    first = _observe(db, eng, title="A")
    first.status, first.status_note = "false_positive", "decided"
    db.commit()
    _observe(db, eng, title="B")
    assert sorted((f.title, f.status) for f in _findings(db, eng)) == [("A", "false_positive"), ("B", "open")]


# --- REQ-TRIAGE-003: summary counts -------------------------------------------

def test_summary_counts_open_findings_and_every_status(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    for title, status in (("a", "open"), ("b", "false_positive"), ("c", "accepted_risk"), ("d", "resolved")):
        f = _observe(db, eng, title=title)
        f.status = status
    db.commit()
    body = client.get(f"/engagements/{eng.id}/summary", headers=_auth(db, owner)).json()
    assert sum(body["counts_by_severity"].values()) == 1
    assert body["counts_by_status"] == {"open": 1, "false_positive": 1, "accepted_risk": 1, "resolved": 1}


# --- REQ-TRIAGE-004: the report -----------------------------------------------

def test_report_lists_accepted_risks_and_only_counts_false_positives(db):
    eng = _engagement(db, _user(db))
    _observe(db, eng, title="Still open issue")
    accepted = _observe(db, eng, title="Legacy TLS on the kiosk")
    accepted.status, accepted.status_note = "accepted_risk", "Kiosk is replaced in Q1; compensating VLAN"
    accepted.status_changed_at = dt.datetime(2026, 9, 28, tzinfo=dt.timezone.utc)
    fp = _observe(db, eng, title="Scanner artefact")
    fp.status, fp.status_note = "false_positive", "Not reproducible"
    db.commit()

    model = build_report_model(db, eng, None)
    assert [f.title for f in model.findings] == ["Still open issue"]
    assert [(r.title, r.justification, r.accepted_on) for r in model.accepted_risks] == [
        ("Legacy TLS on the kiosk", "Kiosk is replaced in Q1; compensating VLAN", "2026-09-28")]
    assert model.false_positive_count == 1

    text = " ".join(page.extract_text() for page in PdfReader(io.BytesIO(render_report_pdf(model))).pages)
    text = " ".join(text.split())
    assert "Accepted risks" in text and "compensating VLAN" in text
    assert "1 finding was reviewed and marked as false positive" in text
    assert "Scanner artefact" not in text
