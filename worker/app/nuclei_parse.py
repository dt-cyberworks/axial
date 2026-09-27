"""Parser fuer nuclei JSONL-Ausgabe (-j -silent) -> strukturierte Findings.

nuclei schreibt pro Treffer eine JSON-Zeile. Reine, DB-freie Funktion
(ohne Infra testbar). Uebersetzt jeden Treffer in ein Finding-Dict, das
worker/app/tasks/fingerprint.py an die control-plane weiterreicht.
"""

from __future__ import annotations

import json


def _category(info: dict, cve_ids: list[str]) -> str:
    if cve_ids:
        return "cve"
    tags = {str(t).lower() for t in info.get("tags", [])}
    if "misconfig" in tags or "misconfiguration" in tags:
        return "misconfig"
    return "exposure"


def parse_nuclei_jsonl(stdout: str) -> list[dict]:
    findings: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = rec.get("info", {})
        classification = info.get("classification") or {}
        cve_ids = [c for c in (classification.get("cve-id") or []) if c]
        cvss = classification.get("cvss-score")

        findings.append({
            "template_id": rec.get("template-id", ""),
            "title": info.get("name") or rec.get("template-id", "nuclei finding"),
            "severity": str(info.get("severity", "info")).lower(),
            "category": _category(info, cve_ids),
            "cve_ids": cve_ids or None,
            "cvss_base": float(cvss) if isinstance(cvss, (int, float)) else None,
            "matched_at": rec.get("matched-at") or rec.get("host", ""),
        })
    return findings
