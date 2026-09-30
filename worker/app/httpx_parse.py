"""Parser fuer httpx JSON-Ausgabe (-json) -> Service-/Tech-Info je Host.

httpx (projectdiscovery) schreibt mit -json pro Host eine JSON-Zeile mit
Status, Titel, Webserver und erkanntem Tech-Stack. Reine, DB-freie Funktion.
Liefert je erreichbarem Host ein Dict fuer einen service-Eintrag (Kap. 2.4);
httpx bestaetigt zudem, welche entdeckten Hosts ueberhaupt LEBEN (Liveness).
"""

from __future__ import annotations

import json

# REQ-DISCO-003: the header the egress proxy stamps on responses it generates
# ITSELF (egress-proxy/app/proxy.py::DENIAL_MARKER_HEADER). Duplicated here
# rather than imported: the worker and the proxy are independently deployed
# services, and this codebase keeps such contracts duplicated across service
# boundaries on purpose (see the raw_egress_lease / egress-proxy precedent)
# instead of coupling them through a shared package.
EGRESS_DENIAL_HEADER = "x-asm-egress-denied"


def _is_egress_denial(rec: dict) -> bool:
    """True when this response was synthesised by our own egress proxy.

    httpx reports headers under `header` (with -include-response-header) and
    exposes the raw response under `response`; both are checked, and header
    names are compared case-insensitively since HTTP header names are.
    """
    headers = rec.get("header") or rec.get("headers")
    if isinstance(headers, dict):
        if any(str(name).strip().lower() == EGRESS_DENIAL_HEADER for name in headers):
            return True
    raw = rec.get("response") or rec.get("raw_response") or ""
    return EGRESS_DENIAL_HEADER in str(raw).lower()


def _normalized_headers(rec: dict) -> dict[str, str]:
    """Response headers as {lowercase-dashed-name: value}. httpx reports them
    snake_cased (`strict_transport_security`); other versions keep the dashes."""
    raw = rec.get("header") or rec.get("headers")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for name, value in raw.items():
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value)
        out[str(name).strip().lower().replace("_", "-")] = str(value)
    return out


def parse_httpx_json(stdout: str) -> list[dict]:
    results: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        # httpx meldet nur erreichbare Hosts (mit -probe). Kein status_code =
        # kein lebender HTTP-Dienst -> ueberspringen.
        status = rec.get("status_code") or rec.get("status-code")
        if status is None:
            continue

        # REQ-DISCO-003: our own egress proxy answers a refused request with
        # `403 Blocked`, which is otherwise indistinguishable from a target's
        # 403. Observed live: an NXDOMAIN host was recorded as a live service
        # with status 403 because of exactly this. A response carrying the
        # proxy's denial marker is the PLATFORM talking, never the target, and
        # is therefore not evidence of anything at the other end.
        if _is_egress_denial(rec):
            continue

        results.append({
            "url": rec.get("url", ""),
            "host": rec.get("input") or rec.get("host", ""),
            "port": rec.get("port"),
            "status_code": status,
            "title": rec.get("title", ""),
            "webserver": rec.get("webserver") or rec.get("web-server", ""),
            "tech": rec.get("tech") or rec.get("technologies") or [],
            # REQ-FPEFF-004: part of the web-surface fingerprint that decides
            # whether two hostnames on one IP are the same vhost. Absent when
            # httpx does not report it, which makes the surface
            # un-deduplicable rather than wrongly equal to another.
            "content_length": rec.get("content_length", rec.get("content-length")),
            # REQ-PIPE-013 / REQ-PIPE-001: the response headers (security-header
            # findings without a second request) and the redirect target (a port
            # that only redirects to another scanned surface is an alias).
            "headers": _normalized_headers(rec),
            "location": str(rec.get("location") or ""),
        })
    return results
