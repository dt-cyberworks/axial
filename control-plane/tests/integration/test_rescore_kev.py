"""Regressionstest: score-Phase darf den KEV-Override nicht verlieren.

Gefunden im Live-Test gegen echtes Metasploitable2 (vsftpd 2.3.4, CVE-2011-2523,
CISA-KEV): die rescore-Route rechnete Severity mit is_kev fest auf False neu,
weil is_kev nur transient bei der Erstellung genutzt, aber nie persistiert
wurde - jeder Rescore stufte KEV-Findings von 'critical' auf ihren
Score-basierten Wert zurueck. Seither ist is_kev eine echte Spalte
(Finding.is_kev), die rescore ausliest statt anzunehmen.
"""

from __future__ import annotations

from app.api.internal import add_finding, rescore_open_findings
from app.schemas.internal import FindingIn


def test_rescore_preserves_kev_critical(db, lab_engagement):
    body = FindingIn(
        category="cve", title="vsftpd 2.3.4 - Backdoor Command Execution",
        cve_ids=["CVE-2011-2523"], cvss_base=9.8, epss=0.94, is_kev=True,
        confidence="inferred", exposure_factor=1.0, business_factor=0.5,
    )
    created = add_finding(lab_engagement.id, body, db)
    assert created["diff"] == "new"

    from app.models.finding import Finding
    finding = db.get(Finding, created["id"])
    assert finding.is_kev is True
    assert finding.severity == "critical"

    # score-Phase laeuft erneut (z. B. periodischer Re-Scan) - KEV muss bleiben.
    result = rescore_open_findings(lab_engagement.id, db)
    assert result["rescored"] == 1

    db.refresh(finding)
    assert finding.severity == "critical", "KEV-Override ging beim Rescore verloren"


def test_rescore_non_kev_uses_score_thresholds(db, lab_engagement):
    body = FindingIn(
        category="cve", title="Harmlose alte Version", cvss_base=3.0, epss=0.01,
        is_kev=False, confidence="inferred", exposure_factor=0.2, business_factor=0.2,
    )
    created = add_finding(lab_engagement.id, body, db)

    from app.models.finding import Finding
    finding = db.get(Finding, created["id"])
    assert finding.severity in ("info", "low")

    rescore_open_findings(lab_engagement.id, db)
    db.refresh(finding)
    assert finding.severity in ("info", "low")
