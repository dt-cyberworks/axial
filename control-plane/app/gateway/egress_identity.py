"""Signed identity of one run for the egress proxy (REQ-EGRESS-006, GitHub #81).

The shared egress proxy has to know which engagement a request belongs to. It used to guess from the destination, so
two engagements covering one host refused each other. A plain engagement id in a header would let the caller choose its
own scope. This is the proof instead: a short-lived token, signed by the control plane for one engagement and one run,
which the proxy verifies with a key only the two of them hold.

    v1.<b64url(canonical json {e, r, i, x})>.<b64url(HMAC-SHA256(secret, CONTEXT + "." + payload_b64))>

The proxy has its own copy of `verify` (egress-proxy/app/run_token.py): the two are separate processes with separate
packages, and scripts/tests/test_egress_token_parity.py fails when they disagree. Minting exists only here.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import time
import uuid

VERSION = "v1"
# Part of the MAC input: a MAC made for another purpose with the same key can never be replayed as a run token.
CONTEXT = b"asm-egress-run-token-v1"
# A verifier tolerates this much clock difference between the process that minted and the one that checks.
LEEWAY_SECONDS = 5


class TokenInvalid(Exception):
    """A token that must not be trusted. `reason` is one of the classes below and never carries token content."""

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


def mint(
    secret: str, engagement_id: uuid.UUID | str, scan_run_id: uuid.UUID | str, ttl_seconds: int, *, now: float | None = None,
) -> str:
    if not secret:
        raise ValueError("egress run token secret is not configured")
    if not 1 <= int(ttl_seconds) <= 86400:
        raise ValueError("egress run token lifetime out of range")
    issued = int(time.time() if now is None else now)
    payload = {
        "e": str(uuid.UUID(str(engagement_id))), "r": str(uuid.UUID(str(scan_run_id))),
        "i": issued, "x": issued + int(ttl_seconds),
    }
    body = _b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return f"{VERSION}.{body}.{_mac(secret, body)}"


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


def _uuid_text(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("not a string")
    return str(uuid.UUID(value))


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("not an integer")
    return value
