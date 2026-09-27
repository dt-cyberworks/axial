"""Shared envelope-encryption helper for secrets at rest (GitHub issue #25).

Fernet (AES-128-CBC + HMAC); the key is supplied via environment/secret
manager and is NEVER stored in the database. Two independent consumers share
this module but use DISTINCT keys - app/mfa.py (TOTP secrets,
settings.mfa_encryption_key) and app/settings_store.py (LLM/NVD provider API
keys, settings.settings_encryption_key) - so a leak of one key does not
expose the other secret's ciphertext.

MultiFernet with a single key behaves identically to a plain Fernet (same
wire format, same decrypt semantics): it exists purely so a consumer can opt
into key-rotation support (the primary key always encrypts; any of the
"previous" keys can still decrypt values written before a rotation) without
changing its own encrypt/decrypt call sites.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

__all__ = ["InvalidToken", "build_cipher", "encrypt", "decrypt"]


def build_cipher(primary_key: str, previous_keys: list[str] | None = None) -> MultiFernet:
    """Raises ValueError if primary_key (or any previous_keys entry) is not a
    valid Fernet key - this is deliberately NOT caught here, so a malformed
    key fails loudly at the call site rather than silently degrading."""
    keys = [Fernet(primary_key.encode())]
    for raw in previous_keys or []:
        raw = raw.strip()
        if raw:
            keys.append(Fernet(raw.encode()))
    return MultiFernet(keys)


def encrypt(cipher: MultiFernet, plaintext: str) -> str:
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt(cipher: MultiFernet, token: str) -> str:
    """Raises InvalidToken if no key in the cipher can open it. Deliberately
    not caught here: a caller that swallows this into an empty/default value
    would make a wrong/rotated-out key indistinguishable from 'no value was
    ever stored', defeating the point of failing loud on a bad key."""
    return cipher.decrypt(token.encode()).decode()
