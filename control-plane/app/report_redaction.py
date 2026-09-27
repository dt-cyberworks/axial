"""Credential redaction for generated customer reports (REQ-REPORT-002).

A report is the one artifact that deliberately LEAVES the platform: an
operator sends the PDF to a customer, an insurer, or an auditor. Everything
rendered into it therefore gets a redaction pass, even though the report
deliberately never dumps raw tool output (spec Kap. 6.2: raw requests and tool
output stay in the evidence store, not the report text).

This mirrors `worker/app/command_redaction.py` rather than importing it: the
worker and control plane are independently deployed services and this codebase
duplicates safety logic across service boundaries on purpose (see the
egress-proxy / raw_egress_lease.py precedent) instead of coupling them through
a shared package.

The threat is concrete: the Lens Agent's plain-language explanation is
generated from a context that includes the finding's full `evidence` blob
(api/findings.py::_lens_context), which for an `http_request` finding can
contain an Authorization header, a session cookie, or a login body. The model
is instructed not to echo them, but "the model was asked nicely" is not a
control. This is.
"""

from __future__ import annotations

import re

REDACTED = "<redacted>"

# Scalar evidence keys whose VALUE is a credential. Substring, case-insensitive
# - a key is only redacted, never dropped, so over-matching costs readability
# while under-matching costs a leaked credential.
_SENSITIVE_KEY_TOKENS: tuple[str, ...] = (
    "password", "passwd", "pwd", "token", "secret", "api_key", "apikey",
    "auth", "cookie", "session", "credential", "private_key",
)

# Credential shapes that can appear anywhere inside free prose (the Lens
# explanation), where there is no key to match on. Each pattern keeps the
# recognizable label and replaces only the secret itself, so the sentence
# still reads sensibly.
_PROSE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Authorization: Bearer <token> / Basic <base64>
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}"), rf"\1 {REDACTED}"),
    # Cookie / Set-Cookie header values, up to the statement end.
    (re.compile(r"(?i)\b(set-cookie|cookie)\s*[:=]\s*[^\s;,)]+"), rf"\1: {REDACTED}"),
    # Header-style credential assignments: X-Api-Key: abc, api_key=abc.
    (re.compile(
        r"(?i)\b((?:x-)?(?:api[-_]?key|auth[-_]?token|access[-_]?token|session[-_]?token|password|passwd|pwd|secret))"
        r"\s*[:=]\s*[\"']?[^\s\"',;)]+"
    ), rf"\1: {REDACTED}"),
    # JWTs, which are self-identifying regardless of surrounding text.
    (re.compile(r"\beyJ[A-Za-z0-9._\-]{16,}"), REDACTED),
)

# Bounds a single rendered value so one pathological evidence field cannot
# push the real content off the page.
MAX_VALUE_CHARS = 200


def is_sensitive_key(name: str) -> bool:
    # Separators are normalized first: real evidence keys are a mix of header
    # names and field names, so the same credential appears as `x-api-key`,
    # `x_api_key`, `X Api Key` and `apiKey`. Found by the negative test below -
    # `api_key` alone silently missed the hyphenated header form.
    lowered = re.sub(r"[\s\-.]+", "_", str(name).strip().lower())
    return any(token in lowered for token in _SENSITIVE_KEY_TOKENS)


def redact_prose(value: str) -> str:
    """Redact credential shapes inside free text (Lens explanations, titles)."""
    out = str(value)
    for pattern, replacement in _PROSE_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def redact_value(key: str, value: object) -> str:
    """Render one evidence field for the report: redacted, bounded, one line."""
    if is_sensitive_key(key):
        return REDACTED
    rendered = redact_prose(str(value)).replace("\r", " ").replace("\n", " ").strip()
    if len(rendered) > MAX_VALUE_CHARS:
        rendered = rendered[:MAX_VALUE_CHARS] + "…"
    return rendered


def safe_evidence_items(evidence: object, limit: int = 8) -> list[tuple[str, str]]:
    """Scalar, redacted, bounded evidence fields suitable for the report.

    Only scalars are considered: nested structures are exactly the raw
    request/response captures the spec keeps out of the report, and flattening
    them would smuggle that content back in one key at a time. `lens_agent` is
    excluded because it is rendered separately as prose.
    """
    if not isinstance(evidence, dict):
        return []
    items: list[tuple[str, str]] = []
    for key, value in evidence.items():
        if key == "lens_agent" or not isinstance(value, (str, int, float, bool)):
            continue
        items.append((str(key), redact_value(str(key), value)))
        if len(items) >= limit:
            break
    return items
