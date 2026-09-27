"""TC-FIDELITY-004: an explicit severity assessment (agent- or tool-reported)
must survive rescore_open_findings, not be silently downgraded on the next
scan's scoring pass."""

from __future__ import annotations

from app.api.internal import add_finding, rescore_open_findings
from app.models.finding import Finding
from app.schemas.internal import FindingIn


def _finding_in(**overrides) -> FindingIn:
    base = dict(
        asset_id=None, service_id=None, category="exposure", title="Unauthenticated PII exposure",
        confidence="validated", evidence={}, exposure_factor=1.0, business_factor=0.5,
    )
    base.update(overrides)
    return FindingIn(**base)


def test_severity_override_persists_and_survives_rescore(db, lab_engagement):
    resp = add_finding(lab_engagement.id, _finding_in(severity_override="critical"), db)
    finding = db.get(Finding, resp["id"])
    assert finding.severity_override == "critical"
    assert finding.severity == "critical"

    rescore_open_findings(lab_engagement.id, db)
    db.refresh(finding)

    assert finding.severity == "critical"  # NOT downgraded by rescoring


def test_finding_without_override_still_rescores_normally(db, lab_engagement):
    resp = add_finding(lab_engagement.id, _finding_in(title="Generic low-signal finding"), db)
    finding = db.get(Finding, resp["id"])
    assert finding.severity_override is None
    original_severity = finding.severity

    rescore_open_findings(lab_engagement.id, db)
    db.refresh(finding)

    # No override -> compute_severity path still applies (value itself may be
    # the same, but it must NOT have been frozen by an override that doesn't exist).
    assert finding.severity_override is None
    assert finding.severity == original_severity


def test_re_observation_without_override_does_not_clear_earlier_override(db, lab_engagement):
    first = add_finding(lab_engagement.id, _finding_in(severity_override="critical"), db)
    # Same fingerprint (asset/category/title/cve_ids unchanged) observed again,
    # this time WITHOUT an override (e.g. a generic tool re-ran and re-detected it).
    second = add_finding(lab_engagement.id, _finding_in(), db)

    assert first["id"] == second["id"]  # same finding (dedup by fingerprint)
    finding = db.get(Finding, first["id"])
    assert finding.severity_override == "critical"  # NOT cleared
    assert finding.severity == "critical"
    # REQ-AGENT-010: risk_score must stay consistent with the retained severity
    # even though THIS observation carried no override of its own.
    assert finding.risk_score >= 85.0


# --- REQ-AGENT-010: risk_score must vary with (and stay consistent with) an --
# --- explicit severity assessment, not collapse to one constant value for   --
# --- every non-CVE (misconfig/exposure/agent-reported) finding.             --

def test_severity_override_produces_a_consistent_risk_score(db, lab_engagement):
    resp = add_finding(lab_engagement.id, _finding_in(severity_override="critical"), db)
    finding = db.get(Finding, resp["id"])
    assert finding.risk_score >= 85.0


def test_different_severities_produce_different_risk_scores(db, lab_engagement):
    """The exact bug reported live: every agent/tool finding without CVE data
    used the same hardcoded exposure/business factors and therefore always
    scored 37.5, regardless of its actual (agent-assessed) severity."""
    critical = add_finding(lab_engagement.id, _finding_in(title="Critical one", severity_override="critical"), db)
    low = add_finding(lab_engagement.id, _finding_in(title="Low one", severity_override="low"), db)

    critical_finding = db.get(Finding, critical["id"])
    low_finding = db.get(Finding, low["id"])

    assert critical_finding.risk_score > low_finding.risk_score
    assert critical_finding.risk_score >= 85.0
    assert 15.0 <= low_finding.risk_score < 40.0


def test_rescore_keeps_risk_score_consistent_with_overridden_severity(db, lab_engagement):
    resp = add_finding(lab_engagement.id, _finding_in(severity_override="high"), db)
    finding = db.get(Finding, resp["id"])

    rescore_open_findings(lab_engagement.id, db)
    db.refresh(finding)

    assert finding.severity == "high"
    assert 70.0 <= finding.risk_score < 85.0
