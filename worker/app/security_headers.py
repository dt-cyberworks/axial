"""REQ-PIPE-013: missing-security-header findings from the response headers httpx
already recorded, so the check costs no request to the target (it replaces the
nikto run, which spent its whole 40 s budget to report the same thing).

Pure functions, no I/O."""

from __future__ import annotations

# Order is the display order of the finding title.
CHECKED_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)


def _has(headers: dict[str, str], name: str) -> bool:
    return bool(str(headers.get(name, "")).strip())


def missing_security_headers(headers: dict[str, str], *, scheme: str, status_code: int | None) -> list[str] | None:
    """The security headers a `web` surface's response lacks, or None when the
    response cannot be judged.

    - A redirect (3xx) is not the application's own response: its headers say
      nothing reliable, so it is not judged.
    - No headers at all means httpx did not record any (not "all missing").
    - HSTS is only meaningful over https.
    - X-Frame-Options is satisfied by a CSP `frame-ancestors` directive.
    """
    if status_code is not None and 300 <= int(status_code) < 400:
        return None
    if not headers:
        return None
    missing: list[str] = []
    for name in CHECKED_HEADERS:
        if name == "strict-transport-security" and scheme != "https":
            continue
        if name == "x-frame-options" and "frame-ancestors" in str(headers.get("content-security-policy", "")).lower():
            continue
        if not _has(headers, name):
            missing.append(name)
    return missing
