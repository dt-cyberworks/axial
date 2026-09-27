"""GitHub issue #25: the shared envelope-encryption helper (app/crypto.py)
used by both app/mfa.py (TOTP secrets) and app/settings_store.py (LLM/NVD
provider API keys), each with its own distinct key."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet, InvalidToken

from app.crypto import build_cipher, decrypt, encrypt


def _key() -> str:
    return Fernet.generate_key().decode()


def test_round_trip():
    cipher = build_cipher(_key())
    ciphertext = encrypt(cipher, "s3cret-value")
    assert ciphertext != "s3cret-value"
    assert decrypt(cipher, ciphertext) == "s3cret-value"


def test_ciphertext_is_not_a_substring_of_the_plaintext():
    cipher = build_cipher(_key())
    ciphertext = encrypt(cipher, "sk-live-abcdef1234567890")
    assert "sk-live-abcdef1234567890" not in ciphertext


def test_decrypt_with_wrong_key_raises_invalid_token():
    cipher_a = build_cipher(_key())
    cipher_b = build_cipher(_key())
    ciphertext = encrypt(cipher_a, "value")
    with pytest.raises(InvalidToken):
        decrypt(cipher_b, ciphertext)


def test_malformed_primary_key_raises_value_error():
    with pytest.raises(ValueError):
        build_cipher("not-a-valid-fernet-key")


def test_two_ciphers_with_the_same_key_produce_interchangeable_results():
    """DISTINCT MultiFernet instances built from the same key string must
    decrypt each other's ciphertext (proves the key, not object identity,
    determines decryptability - relevant since settings_store.py builds a
    fresh cipher per call)."""
    key = _key()
    ciphertext = encrypt(build_cipher(key), "value")
    assert decrypt(build_cipher(key), ciphertext) == "value"


def test_rotation_write_new_read_old():
    """Key-rotation contract: a value encrypted under an old key must still
    decrypt once that key moves from "primary" to "previous", while new
    encryptions use the new primary key."""
    old_key = _key()
    new_key = _key()

    old_ciphertext = encrypt(build_cipher(old_key), "value-from-before-rotation")

    # Post-rotation: new_key is primary, old_key is listed as previous.
    rotated_cipher = build_cipher(new_key, previous_keys=[old_key])
    assert decrypt(rotated_cipher, old_ciphertext) == "value-from-before-rotation"

    new_ciphertext = encrypt(rotated_cipher, "value-from-after-rotation")
    assert decrypt(rotated_cipher, new_ciphertext) == "value-from-after-rotation"
    # The new ciphertext must NOT be decryptable by the old key alone -
    # otherwise "rotation" would not actually be retiring the old key.
    with pytest.raises(InvalidToken):
        decrypt(build_cipher(old_key), new_ciphertext)


def test_rotation_drops_a_fully_retired_key():
    """Once an old key is removed from previous_keys entirely (not just
    demoted), values it alone encrypted can no longer be read - this is the
    expected end state of a completed rotation, not a bug."""
    retired_key = _key()
    current_key = _key()
    ciphertext = encrypt(build_cipher(retired_key), "value")

    fully_rotated_cipher = build_cipher(current_key)  # no previous_keys at all
    with pytest.raises(InvalidToken):
        decrypt(fully_rotated_cipher, ciphertext)


def test_blank_previous_key_entries_are_ignored():
    """SETTINGS_ENCRYPTION_KEY_PREVIOUS is a comma-separated env var - an
    empty/unset value split on ',' must not attempt to construct a Fernet
    from an empty string."""
    build_cipher(_key(), previous_keys=["", "  ", ""])  # must not raise
