"""Server-side, revocable session tokens (REQ-IAM-005).

The raw token is a high-entropy random value, sent to the client exactly
once at creation. Only its SHA-256 hash is ever stored (sha256 - not
Argon2id - is deliberate and correct here: the token itself already has
~256 bits of entropy from secrets.token_urlsafe, so a fast hash is safe and
lets lookup-by-hash stay a simple indexed equality check, unlike a password
which needs a slow hash BECAUSE it has low entropy)."""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets

IDLE_TIMEOUT = dt.timedelta(hours=12)
ABSOLUTE_MAX_LIFETIME = dt.timedelta(days=7)


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()
