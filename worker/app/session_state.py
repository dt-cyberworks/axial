"""Scan-run-scoped HTTP session state for the Vector Agent (REQ-AGENT-022).

Why this exists: every `http_request` the agent makes is independent and
unauthenticated. Measured live against DVWA (docs/benchmarking/
benchmark-design.md §14): all four of that suite's curated vulnerabilities
(SQLi, command injection, reflected XSS, CSRF) sit behind a login form, so
the scanner reached none of them - 100% of that suite's false negatives came
from this one gap, not from failing to recognise a weakness it could see.
Real customer applications gate their interesting functionality the same way.

What this is NOT:
  - not persistence: the jar lives in the scan run's in-memory context and is
    dropped when the run ends. Nothing is written to the database.
  - not a new grant: the Scope Gateway still authorizes every single call.
    Cookies are merged into the proposed args BEFORE authorize(), so the
    gateway sees (and size/injection-checks) the exact request that will be
    sent - this never routes anything around it.
  - not credential storage: sourcing credentials is deliberately separate and
    unbuilt (see the requirement's "Part B" note).

Security invariant, tested in both directions: a cookie observed from host A
is NEVER attached to a request for host B. Session material is the classic
cross-host leak, and an ASM scanner holding a customer's authenticated
session must not replay it anywhere except the exact host that issued it.
"""

from __future__ import annotations

import re

# Response header parsing. curl -sS -i emits the full response head, so
# Set-Cookie lines are already present in what dispatch returns to the agent.
_SET_COOKIE_RE = re.compile(r"^set-cookie:\s*(?P<pair>[^;\r\n]+)", re.IGNORECASE | re.MULTILINE)

# A cookie name=value pair we are willing to store/replay.
_COOKIE_PAIR_RE = re.compile(r"^\s*(?P<name>[A-Za-z0-9!#$%&'*+\-.^_`|~]+)=(?P<value>[^;,\s]*)\s*$")

# Bounds. The gateway's own envelope caps a header value at 1024 bytes
# (args_safety._http_request_args_safe); staying well under that keeps a long
# jar from silently pushing an otherwise-valid request over the limit and
# getting it denied.
MAX_COOKIES_PER_HOST = 12
MAX_COOKIE_VALUE_LEN = 512
MAX_HEADER_LEN = 900


def extract_cookies(response_text: str) -> dict[str, str]:
    """name -> value for every Set-Cookie in a raw HTTP response head.

    Attributes (Path, Domain, Secure, HttpOnly, Expires, ...) are deliberately
    dropped: this jar is only ever replayed to the exact host it came from, so
    the attributes that scope a cookie in a browser add no safety here, and
    honouring Domain would be an active risk (it is the one attribute that
    could widen replay beyond the issuing host).
    """
    jar: dict[str, str] = {}
    if not response_text:
        return jar
    for match in _SET_COOKIE_RE.finditer(response_text):
        pair = _COOKIE_PAIR_RE.match(match.group("pair"))
        if not pair:
            continue
        value = pair.group("value")
        if len(value) > MAX_COOKIE_VALUE_LEN:
            continue
        jar[pair.group("name")] = value
    return jar


def merge_cookies(existing: dict[str, str], fresh: dict[str, str]) -> dict[str, str]:
    """Later Set-Cookie wins (a re-login rotates the session id), bounded."""
    merged = {**existing, **fresh}
    if len(merged) <= MAX_COOKIES_PER_HOST:
        return merged
    # Keep the most recently set ones; an app that sets dozens of cookies must
    # not let the jar grow without limit inside a long run.
    keep = list(merged)[-MAX_COOKIES_PER_HOST:]
    return {name: merged[name] for name in keep}


def cookie_header(jar: dict[str, str]) -> str | None:
    """RFC 6265 request-header form, or None when there is nothing to send."""
    if not jar:
        return None
    header = "; ".join(f"{name}={value}" for name, value in jar.items())
    if len(header) > MAX_HEADER_LEN:
        return None
    return header


def apply_to_headers(headers: dict, jar: dict[str, str]) -> dict:
    """Return headers with the jar merged in.

    An explicit Cookie header from the agent always wins: the model may be
    deliberately testing what happens with a forged, downgraded or absent
    session, and silently overwriting that would both corrupt the test and
    hide it from the operator.
    """
    if not jar:
        return headers
    if any(name.lower() == "cookie" for name in headers):
        return headers
    header = cookie_header(jar)
    if header is None:
        return headers
    return {**headers, "Cookie": header}


# --- Second-identity self-registration guard (REQ-AGENT-023) ---------------
#
# `register_test_identity` lets the agent create a SECOND, synthetic account
# to prove BOLA/IDOR by comparing what identity A vs identity B can access.
# This is defense-in-depth on top of the mandatory per-call operator approval
# (REQ-APPROVAL-002) every state-changing request already goes through, which
# remains the real safety mechanism - the operator sees and approves the
# exact registration payload before anything is sent. This check exists so an
# obviously-wrong payload (a real-looking email) never even reaches approval.
_REAL_EMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "icloud.com", "me.com", "aol.com", "protonmail.com", "proton.me",
    "gmx.com", "gmx.net", "mail.com", "yandex.com", "zoho.com",
})
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def looks_synthetic_registration_body(body: str) -> bool:
    """False only if `body` contains an email address on a well-known
    real-world public mail provider domain. A body with no email at all
    passes (nothing to check) - deliberately conservative rather than
    clever, since the operator approval this request already requires is the
    actual safety mechanism."""
    if not body:
        return True
    for match in _EMAIL_RE.finditer(body):
        if match.group(1).lower() in _REAL_EMAIL_DOMAINS:
            return False
    return True
