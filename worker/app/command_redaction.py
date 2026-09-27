"""Redaction of secrets from tool invocations before they enter the audit trail
(REQ-AUDIT-004).

Deliberately operates on the STRUCTURED arguments, never on an already-built
command string. Pattern-matching a built command would have to re-parse
`shlex.quote`'s output (single-quoted, with inner quotes escaped as `'"'"'`),
and any gap in that parsing writes a live credential into durable,
hash-chained storage that cannot be rewritten afterwards. Redacting the args
and then handing them to the SAME builder used for execution makes the logged
invocation structurally identical to the real one by construction - only the
secret values differ - with no parsing involved at all.

The rule mirrors what session capture already does for cookies
(`app/tasks/agent.py::_capture_session`, REQ-AGENT-022): keep the NAME, drop
the value. Seeing that an `Authorization` header was sent, and to where, is
exactly the transparency this is for; the token itself has no audit value and
is a liability once written.
"""

from __future__ import annotations

import json
import re
from typing import Any

REDACTED = "<redacted>"

# Header names whose value is a credential. Compared case-insensitively - HTTP
# header names are case-insensitive and the agent composes these freely, so
# `authorization`, `Authorization` and `AUTHORIZATION` must all redact.
SENSITIVE_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
})

# Body field names that carry a credential. Substring match (case-insensitive)
# so `password`, `user_password` and `passwordConfirm` are all caught - a body
# field is only redacted, never dropped, so over-matching costs readability
# rather than safety, and under-matching costs a leaked credential.
_SENSITIVE_FIELD_TOKENS: tuple[str, ...] = (
    "password", "passwd", "pwd", "token", "secret", "api_key", "apikey", "auth",
)

# `key=value` pairs in a form-encoded body, captured so only the VALUE is
# replaced and the field name stays readable.
_FORM_PAIR_RE = re.compile(r"([^=&]+)=([^&]*)")


def _is_sensitive_field(name: str) -> bool:
    lowered = name.strip().lower()
    return any(token in lowered for token in _SENSITIVE_FIELD_TOKENS)


def redact_headers(headers: dict[str, Any]) -> dict[str, Any]:
    """Replace sensitive header VALUES, always preserving the header name."""
    return {
        name: (REDACTED if str(name).strip().lower() in SENSITIVE_HEADERS else value)
        for name, value in headers.items()
    }


def _redact_json_body(body: str) -> str | None:
    """Returns the redacted JSON body, or None if `body` is not a JSON object."""
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    redacted = {
        key: (REDACTED if _is_sensitive_field(str(key)) else value)
        for key, value in parsed.items()
    }
    # separators/sort_keys omitted deliberately: this is read by a human in the
    # audit view, not compared byte-for-byte against the executed body.
    return json.dumps(redacted)


def _redact_form_body(body: str) -> str:
    def replace(match: re.Match[str]) -> str:
        name, value = match.group(1), match.group(2)
        return f"{name}={REDACTED}" if _is_sensitive_field(name) else f"{name}={value}"

    return _FORM_PAIR_RE.sub(replace, body)


def redact_body(body: Any) -> Any:
    """Redact credential-named fields in a request body, leaving the rest
    readable. A body is where a login password lives, but it is ALSO where an
    XSS test marker lives (the agent's own prompt tells it to send one) -
    blanking the whole body would defeat the point of recording it at all, so
    only credential-named fields are touched."""
    if not isinstance(body, str) or not body:
        return body
    as_json = _redact_json_body(body)
    if as_json is not None:
        return as_json
    return _redact_form_body(body)


def redact_http_response(raw: str) -> str:
    """Redact a raw `curl -i` response (status line + headers + body) before
    it reaches the LLM or durable audit storage (REQ-AUDIT-007).

    Applies the SAME name-kept/value-dropped rule as the request side
    (REQ-AUDIT-004): a `Set-Cookie` (or other sensitive) header's value is
    replaced but the header line itself stays, and a JSON body's
    credential-named fields are redacted the same way `redact_body` already
    does for request bodies. Found live on int (2026-08-10): real session
    cookie values from Nextcloud and DVWA responses were sitting unredacted
    in the hash-chained audit trail via this exact path.

    A `curl -i` capture of an HTTPS request tunneled through the egress
    proxy's `CONNECT` is NOT one status-line+headers+body block - it is
    `HTTP/1.1 200 Connection Established` (the tunnel handshake), a blank
    line, and then the real response. A single-boundary parser treats
    everything after the FIRST blank line as body, so the real response's
    headers - including its `Set-Cookie` - were never scanned at all. Found
    live on int 2026-08-11: a real DVWA `PHPSESSID` value reached the audit
    trail this exact way, through the first version of this function, which
    only handled a single status-line block. This loops over every leading
    `HTTP/...` block (there can be more than one; there is no upper bound
    assumed) and redacts each one's headers independently, stopping at the
    first chunk that is not itself a status line - that remainder is the
    body.

    Header redaction runs over every line of a block unconditionally, NOT
    only after a header/body boundary is found - the runner caps the
    response at 16 KB (`head -c 16384`), which can cut mid-header or before
    the blank line that separates headers from body. A response truncated
    before that boundary must still have every header line it does contain
    checked and redacted; bailing out unredacted just because the boundary
    was not found would silently let a truncated capture ship a live
    Set-Cookie value.
    """
    if not raw:
        return raw
    remaining = raw.replace("\r\n", "\n")
    blocks: list[str] = []
    while remaining.startswith("HTTP/"):
        boundary = remaining.find("\n\n")
        head = remaining if boundary == -1 else remaining[:boundary]
        lines = head.split("\n")
        redacted_lines = lines[:1]
        for line in lines[1:]:
            name, sep, _value = line.partition(":")
            if sep and name.strip().lower() in SENSITIVE_HEADERS:
                redacted_lines.append(f"{name}: {REDACTED}")
            else:
                redacted_lines.append(line)
        blocks.append("\n".join(redacted_lines))
        if boundary == -1:
            remaining = ""
            break
        remaining = remaining[boundary + 2:]
    if not remaining:
        return "\n\n".join(blocks)
    redacted_body = redact_body(remaining)
    blocks.append(redacted_body if isinstance(redacted_body, str) else remaining)
    return "\n\n".join(blocks)


def redact_args(args: dict[str, Any] | None) -> dict[str, Any]:
    """Redact an args dict in the shape the worker's command builders consume.

    Returns a new dict - the caller must keep passing the ORIGINAL args to the
    real execution path, and this copy only to the logging path.
    """
    if not args:
        return {}
    redacted = dict(args)
    headers = redacted.get("headers")
    if isinstance(headers, dict):
        redacted["headers"] = redact_headers(headers)
    if "body" in redacted:
        redacted["body"] = redact_body(redacted["body"])
    return redacted
