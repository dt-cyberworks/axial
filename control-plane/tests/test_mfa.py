import pyotp

from app import mfa


def test_encrypt_decrypt_roundtrip():
    secret = mfa.generate_secret()
    encrypted = mfa.encrypt_secret(secret)
    assert encrypted != secret.encode()
    assert mfa.decrypt_secret(encrypted) == secret


def test_decrypt_garbage_returns_none():
    assert mfa.decrypt_secret(b"not-a-real-fernet-token") is None


def test_provisioning_uri_contains_issuer_and_account():
    secret = mfa.generate_secret()
    uri = mfa.provisioning_uri(secret, "someone@example.com")
    assert uri.startswith("otpauth://totp/")
    assert "someone%40example.com" in uri or "someone@example.com" in uri
    assert "ASM" in uri


def test_verify_code_accepts_current_step():
    secret = mfa.generate_secret()
    code = pyotp.TOTP(secret).now()
    step = mfa.verify_code(secret, code, last_used_step=None)
    assert step is not None


def test_verify_code_rejects_wrong_code():
    secret = mfa.generate_secret()
    assert mfa.verify_code(secret, "000000", last_used_step=None) is None


def test_verify_code_rejects_malformed_input():
    secret = mfa.generate_secret()
    assert mfa.verify_code(secret, "abcdef", last_used_step=None) is None
    assert mfa.verify_code(secret, "12345", last_used_step=None) is None
    assert mfa.verify_code(secret, "", last_used_step=None) is None


def test_verify_code_rejects_replay_of_same_step():
    secret = mfa.generate_secret()
    code = pyotp.TOTP(secret).now()
    step = mfa.verify_code(secret, code, last_used_step=None)
    assert step is not None
    # Same code, same step, now marked as already used - must be rejected.
    assert mfa.verify_code(secret, code, last_used_step=step) is None


def test_verify_code_accepts_a_step_after_the_last_used_one():
    secret = mfa.generate_secret()
    totp = pyotp.TOTP(secret)
    step = mfa.verify_code(secret, totp.now(), last_used_step=None)
    # A later step's code must still work (last_used_step only blocks <= itself).
    later_code = totp.at((step + 1) * 30)
    assert mfa.verify_code(secret, later_code, last_used_step=step) == step + 1
