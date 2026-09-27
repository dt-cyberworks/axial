"""Parser fuer ffuf-JSON-Ausgabe (-of json).

ffuf schreibt bei -of json ein Objekt mit einem "results"-Array; jeder Treffer
traegt den gefuzzten Wert (input.FUZZ), die volle URL, Status und Groesse. Wir
reduzieren das auf das, was der Agent zum Urteilen braucht (welcher Pfad
existiert, mit welchem Status/welcher Groesse) - die Bewertung, ob ein Treffer
ein Befund ist (z. B. exponiertes /admin, /.git), macht der Agent.
"""

from __future__ import annotations

import collections
import json

# REQ-DISCO-001: below this many hits, uniformity is unremarkable - two or
# three same-sized 200s are a plausible real result, not evidence of a
# catch-all. The observed failures were 1677/1677, 1676/1677 and 1800/1800.
_UNIFORMITY_MIN_HITS = 10
# Share of hits collapsing onto a single (status, length) that marks the
# response as a catch-all rather than discovery. Not 1.0: a real catch-all
# often has one or two genuine outliers (observed: 1676 of 1677 identical,
# with a single 0-length straggler).
_UNIFORMITY_THRESHOLD = 0.95


def is_catch_all(hits: list[dict]) -> bool:
    """True when the hits are one response repeated, not distinct discoveries.

    Independent of ffuf's own -ac calibration, which runs per invocation and
    cannot be assumed to catch every shape (it did not catch our egress
    proxy's uniform denial). One response repeated N times is one observation,
    never N findings - regardless of whether the uniform responder is an SPA
    fallback, a WAF block page, a wildcard vhost, or our own proxy.
    """
    if len(hits) < _UNIFORMITY_MIN_HITS:
        return False
    signature = collections.Counter((h.get("status"), h.get("length")) for h in hits)
    _, most_common = signature.most_common(1)[0]
    return (most_common / len(hits)) >= _UNIFORMITY_THRESHOLD


def parse_ffuf_json(stdout: str) -> list[dict]:
    stdout = (stdout or "").strip()
    if not stdout:
        return []
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return []

    hits: list[dict] = []
    for r in data.get("results", []) or []:
        if not isinstance(r, dict):
            continue
        word = ""
        inp = r.get("input")
        if isinstance(inp, dict):
            word = str(inp.get("FUZZ") or "")
        hits.append({
            "word": word,
            "url": str(r.get("url") or ""),
            "status": r.get("status"),
            "length": r.get("length"),
        })
    return hits
