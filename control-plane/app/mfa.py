"""TOTP second factor (REQ-IAM-003/004): RFC 6238, 30s step, 6 digits, +-1
step clock-skew tolerance, single-use-per-step (no immediate replay).

Secrets are encrypted at rest with a Fernet key SEPARATE from the database
credential (settings.mfa_encryption_key) - a compromised DB dump alone must
not yield usable MFA secrets.
"""

from __future__ import annotations

import time

import pyotp
from cryptography.fernet import MultiFernet

from app.config import get_settings
from app.crypto import InvalidToken, build_cipher, decrypt as _crypto_decrypt, encrypt as _crypto_encrypt

ISSUER = "ASM Console"


def _fernet() -> MultiFernet:
    return build_cipher(get_settings().mfa_encryption_key)


def generate_secret() -> str:
    return pyotp.random_base32()


def encrypt_secret(raw_secret: str) -> bytes:
    return _crypto_encrypt(_fernet(), raw_secret).encode()


def decrypt_secret(encrypted: bytes) -> str | None:
    try:
        return _crypto_decrypt(_fernet(), encrypted.decode())
    except InvalidToken:
        return None


def provisioning_uri(raw_secret: str, email: str) -> str:
    return pyotp.TOTP(raw_secret).provisioning_uri(name=email, issuer_name=ISSUER)


def verify_code(raw_secret: str, code: str, last_used_step: int | None) -> int | None:
    """Returns the step number the code matched at (to persist as
    last_used_step, blocking replay of that exact step), or None if invalid.
    Accepts the current step and one step on either side (~90s window
    total), rejecting a step already consumed."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(raw_secret)
    current_step = int(time.time() // 30)
    for step in (current_step - 1, current_step, current_step + 1):
        if last_used_step is not None and step <= last_used_step:
            continue
        if totp.at(step * 30) == code:
            return step
    return None
