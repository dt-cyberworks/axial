"""Test-wide setup.

The MFA encryption key (REQ-IAM-004) no longer ships as a source default - a
real Fernet key must come from the environment (app default is now empty). Tests
that enroll/verify TOTP need a valid key, so generate one per session here. It is
created in-process, never leaves the test run, and is not a real credential.
"""

import os

from cryptography.fernet import Fernet

os.environ.setdefault("MFA_ENCRYPTION_KEY", Fernet.generate_key().decode())
"""(setdefault so an explicit MFA_ENCRYPTION_KEY in the environment still wins.)"""

# GitHub issue #25: same reasoning as MFA_ENCRYPTION_KEY above, but a
# DISTINCT generated key - tests that set/read an LLM or NVD provider API
# key need a valid SETTINGS_ENCRYPTION_KEY.
os.environ.setdefault("SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_login_rate_limit(monkeypatch):
    """REQ-IAM-016: many tests sign in from the same test client address. Each
    test starts with empty windows, and never counts against a Redis that
    happens to run on this machine (test_login_rate_limit.py tests the Redis
    path against its own throwaway Redis)."""
    from app import rate_limit

    rate_limit.reset_for_tests()
    monkeypatch.setattr(rate_limit, "_redis_skip_until", float("inf"))
    yield
    rate_limit.reset_for_tests()
