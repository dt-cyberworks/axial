"""GitHub issue #22: the raw-egress gateway's reservation/lease API rejects
any request that does not carry the shared secret, fails closed when
misconfigured, and never runs an insecure production boundary. Health
probes stay open. Mirrors tool-runner/tests/test_runner_auth.py exactly."""

from __future__ import annotations

import pytest

from app.raw_egress_auth import enforce_production_token, is_authorized
from app import raw_egress_auth

TOKEN = "s3cret-raw-egress-token"


def test_reservation_endpoints_require_matching_token():
    for path in ("/v1/reservations/acquire", "/v1/reservations/release"):
        assert is_authorized(path, TOKEN, TOKEN) is True
        assert is_authorized(path, "wrong", TOKEN) is False
        assert is_authorized(path, None, TOKEN) is False
        assert is_authorized(path, "", TOKEN) is False


def test_lease_endpoints_also_require_matching_token():
    for path in ("/v1/leases/activate", "/v1/leases/heartbeat", "/v1/leases/deactivate"):
        assert is_authorized(path, TOKEN, TOKEN) is True
        assert is_authorized(path, "nope", TOKEN) is False


def test_health_is_always_open():
    assert is_authorized("/health", None, TOKEN) is True
    assert is_authorized("/health", None, None) is True


def test_unconfigured_token_denies_everything_but_health():
    assert is_authorized("/v1/reservations/acquire", None, None) is False
    assert is_authorized("/v1/reservations/acquire", "anything", None) is False
    assert is_authorized("/v1/reservations/acquire", "anything", "") is False
    assert is_authorized("/health", None, None) is True


def test_production_startup_rejects_missing_or_default_token():
    with pytest.raises(RuntimeError, match="raw_egress_api_token"):
        enforce_production_token("production", None)
    with pytest.raises(RuntimeError, match="raw_egress_api_token"):
        enforce_production_token("production", "")
    with pytest.raises(RuntimeError, match="raw_egress_api_token"):
        enforce_production_token("production", raw_egress_auth._DEV_DEFAULT_TOKEN)


def test_production_startup_accepts_real_token_and_dev_is_lenient():
    enforce_production_token("production", "a-real-strong-secret")  # no raise
    enforce_production_token("development", None)                   # no raise
    enforce_production_token(None, None)                            # no raise
