"""Risk-Score-Modell: EPSS-dominiert, KEV als harter Override (Architektur Kap. 5.2/5.3)."""

from __future__ import annotations

W_EPSS = 0.35
W_CVSS = 0.20
W_EXPOSURE = 0.20
W_CONTEXT = 0.15
W_VALID = 0.10

EXPOSURE_PUBLIC = 1.0
EXPOSURE_AUTH = 0.5
EXPOSURE_INTERNAL = 0.2


def compute_risk_score(
    *,
    epss: float | None,
    cvss_base: float | None,
    exposure_factor: float,
    business_factor: float,
    confidence: str,
) -> float:
    """0..100. Referenz-Gewichte summieren zu 1.0 (Kap. 5.2)."""
    valid = 1.0 if confidence == "validated" else 0.0
    raw = (
        W_EPSS * (epss or 0.0)
        + W_CVSS * ((cvss_base or 0.0) / 10)
        + W_EXPOSURE * exposure_factor
        + W_CONTEXT * business_factor
        + W_VALID * valid
    )
    return round(100 * raw, 2)


def compute_severity(*, risk_score: float, is_kev: bool) -> str:
    """Severity-Mapping Kap. 5.3: critical bei Score>=85 ODER KEV (harter Override)."""
    if is_kev or risk_score >= 85:
        return "critical"
    if risk_score >= 70:
        return "high"
    if risk_score >= 40:
        return "medium"
    if risk_score >= 15:
        return "low"
    return "info"


# REQ-AGENT-010: dieselben Bandgrenzen wie compute_severity, als Untergrenze fuer
# Findings mit einer expliziten severity_override (Tool-/Agent-Einschaetzung ohne
# EPSS/CVSS-Signal, z. B. eine vom Agenten bestaetigte PII-Exposure). Ohne das
# landeten SAEMTLICHE nicht-CVE-Findings (misconfig/exposure/logic) beim exakt
# gleichen risk_score (mit den Default-Faktoren exposure=1.0/business=0.5 immer
# 37.5), unabhaengig von ihrer tatsaechlichen Schwere - der Score widersprach der
# angezeigten Severity, statt sie zu stuetzen.
SEVERITY_FLOOR = {"critical": 85.0, "high": 70.0, "medium": 40.0, "low": 15.0, "info": 0.0}


def risk_score_floor_for_severity(severity: str) -> float:
    return SEVERITY_FLOOR.get(severity, 0.0)
