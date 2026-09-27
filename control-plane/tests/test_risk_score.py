from app.scoring.risk_score import compute_risk_score, compute_severity, risk_score_floor_for_severity


def test_kev_forces_critical_regardless_of_score():
    score = compute_risk_score(
        epss=0.1, cvss_base=7.0, exposure_factor=0.2, business_factor=0.2, confidence="inferred"
    )
    assert compute_severity(risk_score=score, is_kev=True) == "critical"


def test_high_epss_dominates_over_low_cvss():
    high_epss = compute_risk_score(
        epss=0.9, cvss_base=5.0, exposure_factor=1.0, business_factor=0.5, confidence="validated"
    )
    low_epss = compute_risk_score(
        epss=0.05, cvss_base=9.8, exposure_factor=1.0, business_factor=0.5, confidence="validated"
    )
    assert high_epss > low_epss


def test_severity_thresholds():
    assert compute_severity(risk_score=90, is_kev=False) == "critical"
    assert compute_severity(risk_score=75, is_kev=False) == "high"
    assert compute_severity(risk_score=50, is_kev=False) == "medium"
    assert compute_severity(risk_score=20, is_kev=False) == "low"
    assert compute_severity(risk_score=5, is_kev=False) == "info"


def test_severity_floor_matches_severity_thresholds():
    """REQ-AGENT-010: the floor for each band must land the resulting score
    back inside that same band via compute_severity - otherwise the floor
    itself would produce an inconsistent severity/score pair."""
    for severity in ("critical", "high", "medium", "low", "info"):
        floor = risk_score_floor_for_severity(severity)
        assert compute_severity(risk_score=floor, is_kev=False) == severity


def test_unknown_severity_floors_to_zero():
    assert risk_score_floor_for_severity("not-a-severity") == 0.0


def test_unproven_agent_finding_is_not_scored_as_critical():
    """REQ-AGENT-021 / TC-AGENT-021: an agent finding reported without direct
    technical proof arrives with confidence='inferred' and NO severity_override,
    so it must be scored by the platform rather than by the agent's own claim.

    Measured pre-fix behaviour this locks out: the agent asserted
    severity='critical' on an unproven claim, `_handle_report_finding` passed it
    through as severity_override, and REQ-AGENT-010's floor lifted the score from
    37.5 to 85.0 - rendering a guess identically to a demonstrated exploit.
    """
    score = compute_risk_score(
        epss=None, cvss_base=None, exposure_factor=1.0, business_factor=0.5,
        confidence="inferred",
    )
    severity = compute_severity(risk_score=score, is_kev=False)
    assert severity != "critical"
    assert score < risk_score_floor_for_severity("critical")


def test_proven_agent_finding_still_reaches_its_asserted_band():
    """The other half of REQ-AGENT-021: a genuinely demonstrated finding keeps
    confidence='validated' and its severity_override, so REQ-AGENT-010's floor
    must still apply. Proof must remain worth more than inference."""
    score = compute_risk_score(
        epss=None, cvss_base=None, exposure_factor=1.0, business_factor=0.5,
        confidence="validated",
    )
    floored = max(score, risk_score_floor_for_severity("critical"))
    assert compute_severity(risk_score=floored, is_kev=False) == "critical"
