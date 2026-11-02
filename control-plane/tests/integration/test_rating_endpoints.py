"""REQ-SCORE-002/004/005 (GitHub #87) against a real PostgreSQL: the rule is applied where a finding is written and where it is
re-scored, a triaged finding keeps its status, nothing with its own proof is lowered, and what reads the severity (alerts, reports)
now sees the rated value.

The finding that started it: `TLS: cert_trust - certificate does not match supplied URI (same w/o SNI) (imaps on port 993)`,
severity high, score 70.0, category misconfig, confidence validated, detected by testssl."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.api.internal import add_finding, rescore_all_engagements, rescore_open_findings
from app.models.engagement import Engagement
from app.models.finding import Finding
from app.models.monitoring import AlertEvent, NotificationTarget
from app.monitoring import queue_alert
from app.report_builder import _severity_counts
from app.schemas.internal import FindingIn

TITLE = "TLS: cert_trust - certificate does not match supplied URI (same w/o SNI) (imaps on port 993)"


def _testssl_finding(eng, check="cert_trust", label="high", title=TITLE, **kw):
    return FindingIn(
        category="misconfig", title=title, confidence="validated", severity_override=label, exposure_factor=1.0, business_factor=0.4,
        evidence={"check": check, "tool": "testssl", "port": 993, "service": "imaps", **kw.pop("evidence", {})}, **kw,
    )


def _row(db, finding_id):
    db.expire_all()
    return db.get(Finding, finding_id)


def test_the_cert_trust_finding_of_the_issue_is_informational_with_a_class_score(db, lab_engagement):
    out = add_finding(lab_engagement.id, _testssl_finding(lab_engagement), db)
    f = _row(db, out["id"])
    assert (f.severity, float(f.risk_score)) == ("info", 5.0)
    assert f.severity_override == "high", "the tool's label is kept as evidence, not as the rating"
    assert f.evidence["rating"]["class"] == "hygiene" and f.evidence["rating"]["tool_label"] == "high"
    assert "no demonstrated exploit" in f.evidence["rating"]["why"]
    assert f.evidence["check"] == "cert_trust", "the rest of the evidence is untouched"


def test_it_is_still_info_when_the_same_finding_is_seen_again(db, lab_engagement):
    first = add_finding(lab_engagement.id, _testssl_finding(lab_engagement), db)
    again = add_finding(lab_engagement.id, _testssl_finding(lab_engagement), db)
    assert again["id"] == first["id"] and again["diff"] == "persist"
    f = _row(db, first["id"])
    assert (f.severity, float(f.risk_score)) == ("info", 5.0)
    assert f.evidence["rating"]["class"] == "hygiene"


@pytest.mark.parametrize("check,label,severity,score", [
    ("HSTS", "medium", "low", 25.0),
    ("SSLv3", "high", "medium", 55.0),
    ("cipherlist_NULL", "critical", "medium", 55.0),
])
def test_the_other_classes_are_applied_the_same_way(db, lab_engagement, check, label, severity, score):
    out = add_finding(lab_engagement.id, _testssl_finding(lab_engagement, check=check, label=label, title=f"TLS: {check} - x"), db)
    f = _row(db, out["id"])
    assert (f.severity, float(f.risk_score)) == (severity, score)


# --- NEGATIVE: what must never be lowered ---------------------------------------------------------------------------------


def test_negative_a_kev_finding_with_a_cve_is_not_lowered(db, lab_engagement):
    out = add_finding(lab_engagement.id, FindingIn(
        category="cve", title="Apache ActiveMQ OpenWire RCE (CVE-2023-46604)", confidence="validated", severity_override="critical",
        cve_ids=["CVE-2023-46604"], cvss_base=9.8, is_kev=True, evidence={"tool": "activemq-openwire-probe", "port": 61616}), db)
    f = _row(db, out["id"])
    assert f.severity == "critical" and float(f.risk_score) >= 85.0
    assert "rating" not in f.evidence


def test_negative_an_agent_finding_with_direct_proof_keeps_its_own_severity_and_floor(db, lab_engagement):
    out = add_finding(lab_engagement.id, FindingIn(
        category="exposure", title="Personal data readable without login", confidence="validated", severity_override="critical",
        evidence={"tool": "agent", "proof": "GET /api/users returned 200 with email addresses"}), db)
    f = _row(db, out["id"])
    assert (f.severity, float(f.risk_score)) == ("critical", 85.0)


def test_negative_a_nuclei_template_hit_keeps_its_label(db, lab_engagement):
    out = add_finding(lab_engagement.id, FindingIn(
        category="misconfig", title="Exposed .git directory", confidence="validated", severity_override="high",
        evidence={"tool": "nuclei", "template_id": "git-config"}), db)
    assert _row(db, out["id"]).severity == "high"


def test_negative_a_testssl_vulnerability_that_names_a_cve_keeps_its_label(db, lab_engagement):
    out = add_finding(lab_engagement.id, _testssl_finding(
        lab_engagement, check="heartbleed", label="critical", title="TLS: heartbleed - VULNERABLE (CVE-2014-0160)",
        evidence={"cve": ["CVE-2014-0160"]}), db)
    f = _row(db, out["id"])
    assert f.severity == "critical" and float(f.risk_score) >= 85.0


# --- the re-score ----------------------------------------------------------------------------------------------------------


def _old_row(db, eng, *, status="open", check="cert_trust", label="high", severity="high", score=70.0):
    """A finding exactly as the old code wrote it: the label copied into the severity, the score pinned to the floor."""
    f = Finding(engagement_id=eng.id, category="misconfig", title=f"TLS: {check} - old", confidence="validated", status=status,
                severity=severity, severity_override=label, risk_score=score, fingerprint=f"old-{check}-{status}",
                evidence={"check": check, "tool": "testssl", "port": 993})
    db.add(f)
    db.commit()
    return f


def test_the_rescore_rerates_an_existing_row_and_is_idempotent(db, lab_engagement):
    f = _old_row(db, lab_engagement)
    assert rescore_open_findings(lab_engagement.id, db)["rescored"] >= 1
    db.refresh(f)
    assert (f.severity, float(f.risk_score)) == ("info", 5.0)
    first_evidence = dict(f.evidence)
    rescore_open_findings(lab_engagement.id, db)
    db.refresh(f)
    assert (f.severity, float(f.risk_score), f.evidence) == ("info", 5.0, first_evidence), "a second run changes nothing"


@pytest.mark.parametrize("status", ["false_positive", "accepted_risk", "resolved"])
def test_negative_the_rescore_rerates_a_triaged_finding_but_leaves_its_status_alone(db, lab_engagement, status):
    f = _old_row(db, lab_engagement, status=status)
    f.status_note = "decided by the owner"
    db.commit()
    rescore_open_findings(lab_engagement.id, db)
    db.refresh(f)
    assert f.status == status and f.status_note == "decided by the owner"
    assert f.severity == "info"


def test_negative_the_rescore_leaves_findings_with_their_own_proof_alone(db, lab_engagement):
    kev = Finding(engagement_id=lab_engagement.id, category="cve", title="RCE", confidence="validated", status="open", severity="critical",
                  severity_override="critical", risk_score=95.0, is_kev=True, cve_ids=["CVE-2023-46604"], fingerprint="kev-1",
                  evidence={"tool": "activemq-openwire-probe"})
    agent = Finding(engagement_id=lab_engagement.id, category="exposure", title="PII", confidence="validated", status="open",
                    severity="critical", severity_override="critical", risk_score=85.0, fingerprint="agent-1", evidence={"tool": "agent"})
    db.add_all([kev, agent])
    db.commit()
    rescore_open_findings(lab_engagement.id, db)
    db.refresh(kev)
    db.refresh(agent)
    assert (kev.severity, agent.severity) == ("critical", "critical")


def test_rescore_all_covers_every_engagement(db, lab_engagement, test_user):
    other = Engagement(title="Other", source="lab", status="active", owner_user_id=test_user.id,
                       authorized_from=lab_engagement.authorized_from, authorized_until=lab_engagement.authorized_until)
    db.add(other)
    db.commit()
    a, b = _old_row(db, lab_engagement), _old_row(db, other)
    assert rescore_all_engagements(db)["rescored"] >= 2
    db.refresh(a)
    db.refresh(b)
    assert (a.severity, b.severity) == ("info", "info")


# --- what reads the severity -----------------------------------------------------------------------------------------------


def test_an_info_finding_raises_no_alert_where_the_old_high_one_did(db, lab_engagement):
    db.add(NotificationTarget(engagement_id=lab_engagement.id, kind="webhook", url="https://hooks.example.test/x", min_severity="high"))
    db.commit()
    assert queue_alert(db, lab_engagement, "finding_new", "New finding: cert_trust", severity="high") == 1, "the old rating alerted"
    out = add_finding(lab_engagement.id, _testssl_finding(lab_engagement), db)
    rated = _row(db, out["id"]).severity
    assert queue_alert(db, lab_engagement, "finding_new", "New finding: cert_trust", severity=rated) == 0
    assert db.scalars(select(AlertEvent).where(AlertEvent.engagement_id == lab_engagement.id)).all().__len__() == 1


def test_the_report_counts_an_info_finding_as_informational_not_high(db, lab_engagement):
    out = add_finding(lab_engagement.id, _testssl_finding(lab_engagement), db)
    counts = _severity_counts([_row(db, out["id"])])
    assert counts["info"] == 1 and counts["high"] == 0
