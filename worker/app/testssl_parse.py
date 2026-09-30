"""Parser fuer testssl.sh JSON-Ausgabe -> TLS-/Zertifikats-Findings.

testssl.sh (--jsonfile) schreibt ein JSON-Array von Checks mit id/severity/
finding. Reine, DB-freie Funktion. Wir uebernehmen nur nennenswerte
Ergebnisse (severity LOW..CRITICAL) - das sind die handlungsrelevanten
TLS-Hygiene-Befunde (schwache Protokolle, abgelaufene Zertifikate, bekannte
Schwaechen). OK/INFO/WARN werden ausgefiltert.
"""

from __future__ import annotations

import json

# testssl-Severity -> unsere Skala. testssl nutzt Grossbuchstaben.
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def parse_testssl_json(stdout: str) -> list[dict]:
    # testssl kann Banner/Progress vor das JSON schreiben; wir suchen das Array.
    start = stdout.find("[")
    if start == -1:
        return []
    try:
        records = json.loads(stdout[start:])
    except json.JSONDecodeError:
        # Fallback: zeilenweise JSON-Objekte einsammeln
        records = []
        for line in stdout.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{") and line.endswith("}"):
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        sev = _SEVERITY_MAP.get(str(rec.get("severity", "")).upper())
        if sev is None:
            continue
        check_id = str(rec.get("id", "tls"))
        finding_text = str(rec.get("finding", "")).strip()
        key = (check_id, finding_text)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "id": check_id,
            "severity": sev,
            "title": f"TLS: {check_id} - {finding_text}"[:200],
        })
    return findings


_NOT_TLS_MARKERS = ("doesn't seem to be a tls/ssl enabled server", "does not seem to be a tls", "no ssl/tls", "not a tls")


def testssl_scan_problem(stdout: str) -> tuple[str, str] | None:
    """(`not_a_tls_service` | `tls_scan_problem`, text) when testssl itself could
    not test the service, else None. A service that is not TLS at all is not a
    failure of the scan, but an empty result from one must never read as clean."""
    start = stdout.find("[")
    if start == -1:
        return ("tls_scan_problem", "testssl produced no output") if not stdout.strip() else None
    try:
        records = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return None
    for rec in records if isinstance(records, list) else []:
        if isinstance(rec, dict) and str(rec.get("id", "")).lower().startswith("scanproblem"):
            text = str(rec.get("finding", "")).strip()[:300]
            if any(marker in text.lower() for marker in _NOT_TLS_MARKERS):
                return ("not_a_tls_service", text)
            return ("tls_scan_problem", text)
    return None
