"""Verifies the signed run identity that names the engagement of a request (REQ-EGRESS-006/007, GitHub #81).

A copy of `verify` in control-plane/app/gateway/egress_identity.py, which also mints: the control plane and this proxy
are separate processes with separate packages, and scripts/tests/test_egress_token_parity.py fails when the two accept
or refuse different tokens. This module can verify and cannot mint.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import hmac
import json
import os
import time
import uuid

VERSION = "v1"
CONTEXT = b"asm-egress-run-token-v1"
LEEWAY_SECONDS = 5
# The user name of the proxy credentials: `Proxy-Authorization: Basic base64("asm:<token>")`.
PROXY_USER = "asm"
_RAW_CLIENT_SCHEMES = ("http://", "https://")

DEV_DEFAULT_SECRET = "egress-run-token-change-me-in-dev"
SECRET = os.environ.get("EGRESS_RUN_TOKEN_SECRET", DEV_DEFAULT_SECRET)
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()
if ENVIRONMENT == "production" and SECRET in {"", DEV_DEFAULT_SECRET}:
    raise RuntimeError("insecure production configuration: egress_run_token_secret")


class TokenInvalid(Exception):
    """A credential that must not be trusted. `reason` never carries any of its content."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class RunIdentity:
    engagement_id: str
    scan_run_id: str
    issued_at: int
    expires_at: int


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(secret: str, payload_b64: str) -> str:
    return _b64url(hmac.new(secret.encode("utf-8"), CONTEXT + b"." + payload_b64.encode("ascii"), hashlib.sha256).digest())


def _uuid_text(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("not a string")
    return str(uuid.UUID(value))


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("not an integer")
    return value


def verify(secret: str, token: str, *, now: float | None = None) -> RunIdentity:
    """The identity a token proves, or `TokenInvalid`. Nothing else is ever raised for a bad token."""
    if not secret or not isinstance(token, str) or len(token) > 1024:
        raise TokenInvalid("malformed")
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenInvalid("malformed")
    version, body, signature = parts
    if version != VERSION:
        raise TokenInvalid("unsupported_version")
    if not body or not signature:
        raise TokenInvalid("malformed")
    try:
        expected = _mac(secret, body)
    except (UnicodeEncodeError, ValueError):
        raise TokenInvalid("malformed") from None
    if not hmac.compare_digest(expected.encode("ascii"), signature.encode("utf-8", "replace")):
        raise TokenInvalid("bad_signature")
    try:
        claims = json.loads(_unb64url(body))
        identity = RunIdentity(
            engagement_id=_uuid_text(claims["e"]), scan_run_id=_uuid_text(claims["r"]),
            issued_at=_integer(claims["i"]), expires_at=_integer(claims["x"]),
        )
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise TokenInvalid("bad_claims") from None
    if identity.expires_at <= identity.issued_at:
        raise TokenInvalid("bad_claims")
    if (time.time() if now is None else now) > identity.expires_at + LEEWAY_SECONDS:
        raise TokenInvalid("expired")
    return identity


def verify_proxy_authorization(header_value: str, secret: str | None = None, *, now: float | None = None) -> RunIdentity:
    """The identity in a `Proxy-Authorization` header value. Any credential that is present but is not a valid run
    token - another scheme, another user name, a password that is not a token - is refused: the caller must not fall
    back to anything else when this raises."""
    scheme, _, rest = (header_value or "").strip().partition(" ")
    if scheme.lower() != "basic" or not rest.strip():
        raise TokenInvalid("malformed")
    try:
        decoded = base64.b64decode(rest.strip(), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeError):
        raise TokenInvalid("malformed") from None
    # nuclei's raw HTTP client (every `unsafe: true` template) base64-encodes the proxy URL's userinfo WITH the scheme in
    # front - `Basic base64("http://asm:<token>")` - instead of `base64("asm:<token>")`. Measured against the real
    # nuclei in the runner image. The credential is the same and is verified the same way; only that one prefix is
    # accepted, so a mangled credential of any other shape is still refused.
    for scheme in _RAW_CLIENT_SCHEMES:
        if decoded.startswith(scheme):
            decoded = decoded[len(scheme):]
            break
    user, sep, password = decoded.partition(":")
    if not sep or user != PROXY_USER:
        raise TokenInvalid("malformed")
    return verify(SECRET if secret is None else secret, password, now=now)
