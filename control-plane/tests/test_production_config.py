"""Settings.reject_insecure_production_defaults: a production-shaped
Settings instance must refuse to start on any secret/config still at its
insecure dev default. GitHub issue #21 added the public_base_url check;
this file did not exist before, so it also pins the pre-existing checks."""

from __future__ import annotations

import pytest

from app.config import Settings

_SECURE_KWARGS = dict(
    environment="production",
    operator_api_token="t-operator",
    internal_api_token="t-internal",
    runner_api_token="t-runner",
    raw_egress_api_token="t-raw-egress-api",
    scope_signing_secret="t-scope",
    raw_egress_signing_secret="t-rawegress",
    mfa_encryption_key="not-the-dev-default-key=",
    settings_encryption_key="KUX7ADnLj8eEdXJGw-F9-rjiLPnNWw9l82jFw4RluRc=",
    raw_egress_lease_ttl_seconds=900,
    nmap_max_rate=300,
    database_url="postgresql+psycopg://asm_prod:secret@postgres:5432/asm_prod",
    s3_access_key="asm-prod-access",
    s3_secret_key="prod-object-secret",
    public_base_url="https://scan.example.test",
)


def test_secure_production_config_is_accepted():
    Settings(**_SECURE_KWARGS)  # must not raise


def test_development_environment_is_unchecked():
    Settings(environment="development", public_base_url="http://localhost:8000")  # must not raise


@pytest.mark.parametrize("bad_url", [
    "http://localhost:8000",  # the literal dev default
    "http://scan.example.test",  # https required
    "https://localhost:8000",
    "https://127.0.0.1:8000",
    "",
])
def test_negative_insecure_public_base_url_fails_closed(bad_url):
    """GitHub issue #21: an unreachable-from-the-internet public_base_url
    makes REQ-AGENT-027's OpenWire callback URLs unusable - the generated
    URL would tell the TARGET to call itself, silently defeating
    CVE-2023-46604 confirmation rather than failing loudly at startup."""
    with pytest.raises(ValueError, match="public_base_url"):
        Settings(**{**_SECURE_KWARGS, "public_base_url": bad_url})


def test_a_real_https_public_base_url_is_accepted():
    Settings(**{**_SECURE_KWARGS, "public_base_url": "https://scan-int.example.org"})


@pytest.mark.parametrize("field,bad_value", [
    ("operator_api_token", "change-me-in-dev"),
    ("internal_api_token", "change-me-in-dev"),
    ("runner_api_token", "runner-change-me-in-dev"),
    ("raw_egress_api_token", "raw-egress-api-change-me-in-dev"),
    ("scope_signing_secret", "change-me-in-dev"),
    ("raw_egress_signing_secret", "raw-egress-change-me-in-dev"),
    ("mfa_encryption_key", ""),
    ("s3_access_key", "minioadmin"),
    ("s3_secret_key", "minioadmin"),
])
def test_negative_each_preexisting_dev_default_fails_closed(field, bad_value):
    with pytest.raises(ValueError, match="insecure production configuration"):
        Settings(**{**_SECURE_KWARGS, field: bad_value})


def test_negative_runner_api_token_default_fails_closed():
    """GitHub issue #17: control-plane doesn't call the tool-runner itself,
    but reads RUNNER_API_TOKEN purely so its own enforced production
    validator catches it left at the dev default too - tool-runner's own
    separate startup guard (runner_auth.enforce_production_token) only fires
    when ENVIRONMENT actually reaches that container, which the deployment
    topology gap this issue fixes had been silently failing to do."""
    with pytest.raises(ValueError, match="runner_api_token"):
        Settings(**{**_SECURE_KWARGS, "runner_api_token": "runner-change-me-in-dev"})


def test_negative_dev_default_database_url_fails_closed():
    with pytest.raises(ValueError, match="database_url"):
        Settings(**{**_SECURE_KWARGS, "database_url": "postgresql+psycopg://asm:asm@localhost:5432/asm"})


@pytest.mark.parametrize("bad_key", [
    "",  # never set
    "not-a-valid-fernet-key",  # wrong length / not base64
    "short",
])
def test_negative_settings_encryption_key_missing_or_malformed_fails_closed(bad_key):
    """GitHub issue #25: 'startup with a missing/incorrect encryption key
    fails loudly' - a key that merely looks non-empty but cannot construct a
    Fernet cipher must be caught here too, not only the literal empty case."""
    with pytest.raises(ValueError, match="settings_encryption_key"):
        Settings(**{**_SECURE_KWARGS, "settings_encryption_key": bad_key})
