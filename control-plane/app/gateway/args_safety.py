"""Argument-Haertung je Tool (Architektur Kap. 3.2, Tool-Allowlist Kap. 4.1).

Selbst ein whitelisted Tool kann durch Argumente gefaehrlich werden. Diese
Grenzen sind unabhaengig davon, was das Modell vorschlaegt oder wie es
formuliert - reine Werte-Pruefung auf dem strukturierten ToolCall.
"""

from __future__ import annotations

import re

# HTTP-Header-Name: RFC-7230-Token, konservativ. Verhindert Injektion in die
# Header-Zeile und unsinnige Namen aus LLM-Vorschlaegen.
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")

# http_request-Envelope (REQ-HTTP-002 / REQ-APPROVAL-001):
#   - LESENDE (safe) Methoden laufen AUTONOM.
#   - ZUSTANDSAENDERNDE Methoden sind well-formed erlaubt, laufen aber NIE autonom
#     - das Gateway routet sie in die manuelle Freigabe (nicht deny).
# args_safety prueft nur die STRUKTURELLE Gueltigkeit (Injektions-/Groessen-
# sicherheit) fuer ALLE Methoden; die read/write-Policy entscheidet das Gateway.
_SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}
_WRITE_HTTP_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
_ALL_HTTP_METHODS = _SAFE_HTTP_METHODS | _WRITE_HTTP_METHODS
_MAX_BODY_LEN = 16384


def http_request_is_state_changing(args: dict) -> bool:
    """Zustandsaendernd = schreibende Methode ODER ein Request-Body. Nur diese
    brauchen manuelle Freigabe (REQ-APPROVAL-001); Reads laufen autonom."""
    method = str(args.get("method", "GET")).upper()
    return method in _WRITE_HTTP_METHODS or bool(args.get("body"))

# ffuf-Content-Discovery: der Agent waehlt eine Wortliste ueber einen SCHLUESSEL
# (nicht einen rohen Pfad!) - so kann er nie -w /etc/passwd o. Ae. lesen. Diese
# Schluesselmenge MUSS mit FFUF_WORDLISTS in worker/app/tool_runner_client.py
# uebereinstimmen (bewusste Duplizierung ueber die Prozessgrenze).
_FFUF_WORDLISTS = {
    "common", "raft-medium-dirs", "raft-medium-files", "quickhits", "directory-list-medium",
}
# Request-Pfad MUSS den FUZZ-Platzhalter enthalten und sonst nur harmlose
# Pfad-Zeichen (kein Whitespace/CRLF, keine Shell-Metazeichen).
_FUZZ_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*FUZZ[A-Za-z0-9._~!$&'()*+,;=:@/%-]*$")
_EXT_RE = re.compile(r"^\.?[A-Za-z0-9]{1,8}$")
# Vom Agenten begruendete Zusatz-Kandidaten (Intruder-artig): reine Pfad-/
# Dateinamen-Tokens, KEINE Shell-Metazeichen (auch wenn spaeter shlex-gequotet
# wird - Defense-in-Depth). Erlaubt Pfadfragmente wie ".git/config".
_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9._~/-]{1,128}$")


def _nmap_args_safe(args: dict) -> bool:
    if set(args) - {"flags", "ports", "max_rate", "port_profile"}:
        return False
    if not args:
        return True
    flags = {str(flag).lower() for flag in args.get("flags", [])}
    if any("--script=exploit" in flag for flag in flags):
        return False
    profile = str(args.get("port_profile", ""))
    ports = str(args.get("ports", ""))
    # Preserve the narrow, profile-free service proposal envelope. The worker
    # still constructs actual service ports exclusively from discovery output.
    if not profile and not ports and "max_rate" not in args:
        return flags <= {"-sv", "-ss", "-p"} and "-su" not in flags
    try:
        max_rate = int(args.get("max_rate"))
    except (TypeError, ValueError):
        return False

    # REQ-CIDRDISC-002: liveness-only host-discovery sweep - exactly -sn, no
    # port scan at all (ports must be empty; the discovery-probe ports 80/443
    # are fixed server-side in tool_runner_client, never operator/agent input).
    if profile == "host_discovery":
        return flags == {"-sn"} and ports == "" and 1 <= max_rate <= 1000

    if profile in {"full_tcp", "configured_tcp"}:
        if flags != {"-ss", "-p"} or not 1 <= max_rate <= 1000:
            return False
        # REQ-PORTSCOPE-003: configured_tcp scans one segment per matched
        # per-target scope range (each already bounds-checked against the
        # engagement ceiling before this call) - a comma-separated list is
        # standard nmap -p syntax. Capped at 8 segments; a sane number of
        # scope-asset matches for one target, never operator/LLM-controlled
        # directly.
        segments = ports.split(",")
        if not 1 <= len(segments) <= 8:
            return False
        parsed: list[tuple[int, int]] = []
        for segment in segments:
            match = re.fullmatch(r"([1-9][0-9]{0,4})(?:-([1-9][0-9]{0,4}))?", segment)
            if not match:
                return False
            first = int(match.group(1))
            last = int(match.group(2) or first)
            if not 1 <= first <= last <= 65535:
                return False
            parsed.append((first, last))
        return profile != "full_tcp" or parsed == [(1, 65535)]

    if profile == "targeted_udp":
        return (
            flags == {"-su", "-p"}
            and ports == "53,123,161,443,500,1900,4500,5060,5353"
            and 1 <= max_rate <= 100
        )
    return False


def _nuclei_args_safe(args: dict) -> bool:
    # Die konservative Invocation (nicht-intrusive Templates, -etags
    # intrusive,dos,fuzz, Rate-Limit) wird im worker/tool_runner_client._nuclei_body
    # ERZWUNGEN. Hier wird geprueft, dass ein Aufrufer keine gefaehrlichen Tags
    # anfordert. Leere args sind sicher (Standardpfad des deterministischen
    # Pipeline-Dispatch); ein spaeterer Vector Agent darf keine dos/intrusive/
    # fuzz-Tags einschleusen.
    tags = {str(t).lower() for t in args.get("tags", [])}
    return not (tags & {"intrusive", "dos", "fuzz"})


def _httpx_args_safe(args: dict) -> bool:
    method = str(args.get("method", "GET")).upper()
    return method in {"GET", "HEAD", "OPTIONS"}


def _raw_tcp_probe_args_safe(args: dict) -> bool:
    """REQ-AGENT-025: redis-probe/activemq-banner take NO structured args -
    the exact bytes sent (or none) are a fixed, server-side registry entry
    keyed by tool name (worker/app/raw_tcp_probe.py), never agent-supplied.
    Explicit (rather than relying on args_are_safe's no-validator-entry
    default) so this envelope is visible and independently testable, same as
    every other curated tool's validator."""
    return not args


def _default_cred_check_args_safe(args: dict) -> bool:
    max_attempts = int(args.get("max_attempts", 0))
    wordlist = args.get("wordlist", "default")
    return max_attempts <= 3 and wordlist == "default"


def _http_request_args_safe(args: dict) -> bool:
    """STRUKTURELLE Gueltigkeit eines http_request (REQ-HTTP-002): erlaubte
    Methode, injektions-/groessensichere Header/Pfad/Body. Gilt fuer LESENDE
    UND SCHREIBENDE Methoden gleichermassen - ob ein Schreibzugriff autonom laeuft
    oder in die Freigabe geht, entscheidet das Gateway (nicht hier). Malformed ->
    False (deny), nie 'zur Freigabe'."""
    method = str(args.get("method", "GET")).upper()
    if method not in _ALL_HTTP_METHODS:
        return False

    path = args.get("path", "/")
    if not isinstance(path, str) or not path or len(path) > 2048:
        return False
    if "\n" in path or "\r" in path or " " in path:
        return False

    headers = args.get("headers", {})
    if not isinstance(headers, dict) or len(headers) > 30:
        return False
    for name, value in headers.items():
        if not isinstance(name, str) or not _HEADER_NAME_RE.match(name):
            return False
        if not isinstance(value, str) or len(value) > 1024 or "\n" in value or "\r" in value:
            return False

    body = args.get("body", "")
    if body is not None and not isinstance(body, str):
        return False
    if isinstance(body, str) and len(body) > _MAX_BODY_LEN:
        return False

    # Keine weiteren, unbekannten Argumente (Defense-in-Depth gegen LLM-Kreativitaet).
    return set(args) <= {"method", "path", "headers", "body"}


def _ffuf_args_safe(args: dict) -> bool:
    """Content-Discovery: der Agent kuratiert (Wortliste waehlen + wenige eigene
    Kandidaten), ffuf leistet die Fleissarbeit. Nicht-destruktiv (nur GET-
    Discovery); Wortliste NUR ueber Allowlist-Schluessel; Pfad muss FUZZ
    enthalten; Extensions/Kandidaten streng validiert."""
    if set(args) - {"wordlist", "path", "extensions", "extra_candidates"}:
        return False

    if str(args.get("wordlist", "common")) not in _FFUF_WORDLISTS:
        return False

    path = args.get("path", "/FUZZ")
    if not isinstance(path, str) or len(path) > 512 or not _FUZZ_PATH_RE.match(path):
        return False

    exts = args.get("extensions", [])
    if not isinstance(exts, list) or len(exts) > 10:
        return False
    if not all(isinstance(e, str) and _EXT_RE.match(e) for e in exts):
        return False

    cands = args.get("extra_candidates", [])
    if not isinstance(cands, list) or len(cands) > 200:
        return False
    if not all(isinstance(c, str) and _CANDIDATE_RE.match(c) for c in cands):
        return False

    return True


# Tool -> Kap. 3.2/4.1 Validator. Tools ohne Eintrag hier sind konservativ
# nur mit leeren Argumenten zulaessig.
_VALIDATORS = {
    "nmap": _nmap_args_safe,
    "nuclei": _nuclei_args_safe,
    "httpx": _httpx_args_safe,
    "default-cred-check": _default_cred_check_args_safe,
    "http_request": _http_request_args_safe,
    "ffuf": _ffuf_args_safe,
    "redis-probe": _raw_tcp_probe_args_safe,
    "activemq-banner": _raw_tcp_probe_args_safe,
    # REQ-AGENT-027: same guarantee - the exact packet bytes are built
    # server-side from a curated table (worker/app/openwire_payload.py) plus
    # a callback URL the worker itself requests, never agent-supplied.
    "activemq-openwire-probe": _raw_tcp_probe_args_safe,
}


def args_are_safe(tool: str, args: dict) -> bool:
    validator = _VALIDATORS.get(tool)
    if validator is None:
        return not args
    return validator(args)
