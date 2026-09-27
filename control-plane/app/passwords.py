"""Password and backup-code hashing (REQ-IAM-002/004). Argon2id (OWASP
current recommendation) - memory-hard, resists GPU/ASIC cracking far better
than bcrypt/PBKDF2. Same primitive for backup codes: they are credentials
too and get the same treatment as a password, not a weaker one."""

from __future__ import annotations

import secrets
import string

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()


def hash_secret(raw: str) -> str:
    return _hasher.hash(raw)


def verify_secret(raw: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, raw)
    except VerifyMismatchError:
        return False
    except Exception:  # noqa: BLE001 - malformed hash must never raise into a 500
        return False


_TEMP_PASSWORD_ALPHABET = string.ascii_letters + string.digits


def generate_temp_password(length: int = 20) -> str:
    """One-time password for a freshly invited account (REQ-IAM-008) - the
    admin relays it out-of-band; must_change_password forces a real one on
    first login."""
    return "".join(secrets.choice(_TEMP_PASSWORD_ALPHABET) for _ in range(length))


_BACKUP_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # no 0/O/1/I - fewer transcription errors


def generate_backup_codes(count: int = 10) -> list[str]:
    return [
        "-".join(
            "".join(secrets.choice(_BACKUP_CODE_ALPHABET) for _ in range(4))
            for _ in range(2)
        )
        for _ in range(count)
    ]
