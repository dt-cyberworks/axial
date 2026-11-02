"""REQ-SCORE-001..003 (GitHub #87): a tool's severity label about a configuration is evidence, not the rating.

The finding that started it: `TLS: cert_trust - certificate does not match supplied URI (imaps on port 993)` was shown as high, 70.0,
because testssl rates any trust failure HIGH, the platform copied the label, and the score was then pinned to the floor of the band.
These are pure tests of the rule; the endpoints that apply it are in tests/integration/test_rating_endpoints.py."""

from __future__ import annotations

import pytest

from app.scoring.rating import (
    CLASS_CEILING, CLASS_SCORE, SEVERITY_RANK, TESTSSL_CLASS, normalize_check_id, rate_finding,
)
from app.scoring.risk_score import compute_severity


def _testssl(check, label, **kw):
    ev = {"tool": "testssl", "check": check, **kw.pop("evidence", {})}
    return rate_finding(label=label, evidence=ev, cve_ids=kw.pop("cve_ids", None), is_kev=kw.pop("is_kev", False),
                        epss=kw.pop("epss", None))


# --- the example of the issue and each class ---------------------------------------------------------------------------------


def test_the_cert_trust_note_on_port_993_is_informational_not_high_70():
    r = _testssl("cert_trust", "high", evidence={"port": 993, "service": "imaps"})
    assert (r.severity, r.risk_score, r.rating_class) == ("info", 5.0, "hygiene")
    assert r.tool_label == "high"
    assert "no demonstrated exploit" in r.why and "(high)" in r.why, "the detail text says why it is rated as it is"


@pytest.mark.parametrize("check,label,expected_class,expected_severity", [
    # hygiene -> info
    ("cert_trust", "high", "hygiene", "info"),
    ("cert_chain_of_trust", "high", "hygiene", "info"),
    ("cert_commonName", "high", "hygiene", "info"),
    ("cert_subjectAltName", "medium", "hygiene", "info"),
    ("LUCKY13", "low", "hygiene", "info"),
    ("BEAST_CBC_TLS1", "medium", "hygiene", "info"),
    ("banner_server", "low", "hygiene", "info"),
    # hardening -> at most low
    ("HSTS", "medium", "hardening", "low"),
    ("cert_expirationStatus", "critical", "hardening", "low"),
    ("TLS1", "high", "hardening", "low"),
    ("TLS1_1", "medium", "hardening", "low"),
    ("cipherlist_3DES_IDEA", "high", "hardening", "low"),
    # weakness -> at most medium
    ("SSLv3", "high", "weakness", "medium"),
    ("cipherlist_NULL", "critical", "weakness", "medium"),
    ("cipherlist_EXPORT", "high", "weakness", "medium"),
    ("cert_keySize", "high", "weakness", "medium"),
    # a label below the ceiling is not raised
    ("SSLv3", "low", "weakness", "low"),
    ("HSTS", "low", "hardening", "low"),
])
def test_each_class_caps_the_label_at_its_ceiling(check, label, expected_class, expected_severity):
    r = _testssl(check, label)
    assert (r.rating_class, r.severity) == (expected_class, expected_severity)
    assert r.risk_score == CLASS_SCORE[expected_severity]


def test_the_score_of_a_class_lies_in_the_band_of_its_severity():
    """The number must never contradict the word (REQ-SCORE-003)."""
    for severity, score in CLASS_SCORE.items():
        assert compute_severity(risk_score=score, is_kev=False) == severity


def test_the_ceilings_are_the_ones_written_down():
    assert CLASS_CEILING == {"proven": None, "weakness": "medium", "hardening": "low", "hygiene": "info"}


def test_check_ids_are_matched_by_their_plain_lower_case_form():
    assert normalize_check_id("cert_trust <cert#1>") == "cert_trust"
    assert normalize_check_id("Cert_Trust") == "cert_trust"
    assert normalize_check_id("cert_trust #2") == "cert_trust"
    assert _testssl("cert_trust <cert#2>", "high").severity == "info"
    assert all(k == k.lower() for k in TESTSSL_CLASS), "table keys are lower case"


# --- NEGATIVE: what the rule must never lower ---------------------------------------------------------------------------------


@pytest.mark.parametrize("label", ["high", "critical"])
def test_negative_a_testssl_vulnerability_that_names_a_cve_keeps_its_label(label):
    """Heartbleed-class checks: not in the table, testssl names a CVE -> `proven`, the label stands."""
    r = _testssl("heartbleed", label, evidence={"cve": ["CVE-2014-0160"]})
    assert r.rating_class == "proven" and r.severity == label and r.risk_score is None


def test_negative_a_known_exploited_finding_is_never_lowered_even_if_the_table_calls_it_a_weakness():
    r = _testssl("cipherlist_NULL", "critical", is_kev=True)
    assert (r.rating_class, r.severity) == ("proven", "critical")


def test_negative_a_likely_exploited_finding_is_never_lowered():
    r = _testssl("SSLv3", "high", epss=0.5)
    assert (r.rating_class, r.severity) == ("proven", "high")
    assert _testssl("SSLv3", "high", epss=0.05).severity == "medium", "below the EPSS threshold the class applies"


def test_negative_a_note_stays_a_note_even_when_the_finding_is_flagged_known_exploited():
    """The table is explicit about notes (the issue's LUCKY13 example); a note is not a vulnerability."""
    assert _testssl("cert_trust", "high", is_kev=True).severity == "info"


@pytest.mark.parametrize("tool", ["nuclei", "redis-probe", "activemq-openwire-probe", "activemq-banner", "agent", None])
def test_negative_findings_with_their_own_proof_are_not_touched_by_the_rule(tool):
    """An agent finding with direct technical proof, a curated probe's confirmed result and a nuclei template hit keep their label."""
    assert rate_finding(label="critical", evidence={"tool": tool, "check": "cert_trust"} if tool else {"check": "cert_trust"},
                        cve_ids=["CVE-2023-46604"], is_kev=True, epss=0.9) is None
    assert rate_finding(label="high", evidence={"tool": tool}, cve_ids=None, is_kev=False, epss=None) is None


def test_negative_a_finding_without_a_label_or_with_an_unknown_label_is_left_alone():
    assert rate_finding(label=None, evidence={"tool": "testssl", "check": "cert_trust"}, cve_ids=None, is_kev=False, epss=None) is None
    assert rate_finding(label="severe", evidence={"tool": "testssl", "check": "cert_trust"}, cve_ids=None, is_kev=False, epss=None) is None
    assert rate_finding(label="high", evidence=None, cve_ids=None, is_kev=False, epss=None) is None


def test_an_unknown_check_without_a_cve_cannot_claim_more_than_medium():
    r = _testssl("some_new_testssl_check", "critical")
    assert (r.rating_class, r.severity) == ("weakness", "medium")


def test_an_unknown_check_with_a_cve_keeps_the_label():
    assert _testssl("some_new_vuln", "high", evidence={"cve": ["CVE-2030-0001"]}).severity == "high"


def test_a_tool_label_can_no_longer_raise_a_finding_above_its_class():
    """The core of #87: every label up to critical, for every class, ends at or below the class ceiling."""
    for check, cls in TESTSSL_CLASS.items():
        ceiling = CLASS_CEILING[cls]
        for label in ("low", "medium", "high", "critical"):
            r = _testssl(check, label)
            assert SEVERITY_RANK[r.severity] <= SEVERITY_RANK[ceiling], (check, label, r.severity)
