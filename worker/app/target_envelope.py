"""Engagement-TCP-Portfenster -> HTTP-Ziel-URL (REQ-FIDELITY-003/007).

Geteilt zwischen der deterministischen Fingerprint-Phase (fingerprint.py) und
dem Agent-Dispatch (dispatch.py): BEIDE Pfade fuehren HTTP-Tools gegen
denselben in-scope Host aus und muessen daher denselben, engagement-
konfigurierten Port treffen - sonst landet ein Agent-Vorschlag auf einem
Port-restriktiven Auftrag stumpf auf dem impliziten 443 und wird vom
Egress-Proxy (REQ-FIDELITY-005) legitim, aber unnoetig geblockt.
"""

from __future__ import annotations


def single_port_from_envelope(envelope: dict) -> int | None:
    """Nur bei einem EINZELNEN, ausdruecklich autorisierten Nicht-Standard-Port
    liefert dies etwas zurueck - ein voller/mehrteiliger Bereich (der
    Normalfall) aendert das bisherige Verhalten nicht, da sich aus einem
    Bereich kein einzelner HTTP-Port ableiten laesst."""
    port_from = envelope.get("tcp_port_from")
    port_to = envelope.get("tcp_port_to")
    if port_from is None or port_to is None or port_from != port_to:
        return None
    if port_from in (80, 443):
        return None
    return int(port_from)


def target_url(host: str, single_port: int | None, protocol: str | None = None) -> str:
    """URL for the tools that need an EXPLICIT scheme (nikto, wafw00f, testssl,
    nuclei, ffuf, http_request). Unlike httpx (see httpx_target below), none of
    these auto-probe the other scheme.

    `protocol` (REQ-FIDELITY-009, 2026-08-03): the scheme the fingerprint phase
    actually CONFIRMED for this host/port via httpx's own reported URL
    (protocol_from_httpx_url). When absent - the protocol is genuinely unknown,
    e.g. a target the fingerprint phase never reached - the historical
    https-default is kept, which is the right guess for the public web and
    preserves every pre-existing behaviour.

    Why this matters, measured live against a plain-HTTP target (2026-08-03):
    nuclei with `http://` found 2 real template matches; the SAME target with
    the forced `https://` this function used to always produce found 0, silently
    ("Scan completed. No results found." - no error, no warning). A schemeless
    target is NOT a workaround either: nuclei's embedded httpx reported "Found 0
    URL from httpx" and also scored 0. Only the correct explicit scheme works,
    which is why this takes a protocol rather than dropping the scheme.
    """
    scheme = "http" if str(protocol or "").lower() == "http" else "https"
    if "://" in host:
        return host
    if ":" in host:
        # Bereits ein explizites host:port (z. B. wenn der Agent den Port selbst
        # erraten/eingesetzt hat, bevor dieser Helfer griff) - kein zweites Anhaengen.
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{single_port}" if single_port else f"{scheme}://{host}"


def httpx_target(host: str, single_port: int | None) -> str:
    """Target string specifically for httpx (REQ-FIDELITY-003/007/010).
    Unlike target_url() above, this always starts from an explicit http://,
    never a bare/schemeless host.

    History: originally (2026-08-03) this returned a bare, schemeless
    host[:port], reasoning that "httpx natively auto-probes https-then-http
    when given a bare host[:port] with no scheme". That claim was never
    verified against a non-standard port and turned out to be wrong -
    CORRECTED 2026-08-04, found live deploying OWASP Benchmark (a TLS-only,
    self-signed-cert target on a non-standard port): a schemeless httpx
    target on a non-standard port does NOT probe https at all, it assumes
    http outright and takes whatever answers - here, Tomcat's own "This
    combination of host and port requires TLS" 400 response, misreported as
    a confirmed plain-HTTP service. Every downstream consumer of that
    confirmed protocol (testssl's skip-if-not-tls gate, the agent's
    http_request/ffuf calls) was then misdirected at the wrong scheme, and
    the entire real application went untested behind a wall of identical 400s.

    Verified empirically which direction actually auto-corrects, against two
    real, live, opposite-shaped targets: an explicit `http://` input against
    the TLS-only OWASP Benchmark target correctly auto-upgraded itself to
    https (real Tomcat response, not the 400); an explicit `https://` input
    against DVWA (plain-HTTP-only) did NOT fall back to http at all (no
    result, silently). So the fix is not "no scheme" and not "start from
    https" - it is specifically "start from an explicit http://", which is
    the one direction that is empirically self-correcting both ways.
    """
    if "://" in host:
        return host
    if ":" in host:
        return f"http://{host}"
    return f"http://{host}:{single_port}" if single_port else f"http://{host}"


def protocol_from_httpx_url(url: str, default: str = "https") -> str:
    """The scheme httpx actually used to reach the target (REQ-FIDELITY-003),
    read from its own reported result - not assumed. httpx's JSON output
    includes the real url it connected with; storing that (not a hardcoded
    "https") keeps service.protocol accurate for any downstream consumer
    (testssl gating, reporting, the attack-surface graph)."""
    if "://" in url:
        scheme = url.split("://", 1)[0].strip().lower()
        if scheme in ("http", "https"):
            return scheme
    return default
