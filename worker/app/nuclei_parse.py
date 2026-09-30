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


# --- Technology detection (REQ-PIPE-002) ------------------------------------------

_TECH_ID_SUFFIXES = (
    "-detect", "-detection", "-version", "-panel", "-login", "-exposure", "-installed", "-default-login",
    "-discovery", "-info", "-fingerprint",
)


def _id_stem(template_id: str) -> str:
    stem = str(template_id or "").lower()
    changed = True
    while changed:
        changed = False
        for suffix in _TECH_ID_SUFFIXES:
            if stem.endswith(suffix) and len(stem) > len(suffix):
                stem = stem[: -len(suffix)]
                changed = True
    return stem


def parse_nuclei_tech(stdout: str) -> list[str]:
    """Technology names one technology-detection run found (raw, not yet
    normalized): the template's own product/vendor metadata when it has any, the
    matcher name of a multi-technology template (`tech-detect`), else the
    template id without its `-detect`/`-version`/`-panel` suffix. Duplicates
    are dropped, order kept."""
    names: dict[str, None] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = rec.get("info") or {}
        meta = info.get("metadata") or {}
        template_id = str(rec.get("template-id", ""))
        found = [str(meta.get("product") or ""), str(meta.get("vendor") or "")]
        matcher = str(rec.get("matcher-name") or "")
        if matcher and template_id in ("tech-detect", "wappalyzer-technology-detection"):
            found.append(matcher)
        if not any(found):
            found.append(_id_stem(template_id))
        for name in found:
            if name.strip():
                names.setdefault(name.strip(), None)
    return list(names)
