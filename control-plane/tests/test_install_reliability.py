"""REQ-INSTALL-003/004/005: what a first-time installer hits.

Found 2026-10-01 by following the published install guide on a clean VM:
  * the production generator had fallen behind the production gate (it emitted
    no SETTINGS_ENCRYPTION_KEY and no https PUBLIC_BASE_URL), so the stack it
    configured refused to start;
  * an empty MFA key made POST /auth/mfa/enroll answer 500 although /health was
    green - nobody could ever finish enrollment;
  * bootstrap_admin created an administrator whose address the sign-in form
    rejects, so that account could never log in.
"""

from __future__ import annotations

import importlib.util
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI

from app import mfa
from app.config import Settings, get_settings
from app.schemas.auth import LoginIn

REPO = Path(__file__).resolve().parents[2]
GENERATOR = REPO / "scripts" / "gen_production_env.py"
BOOTSTRAP = REPO / "control-plane" / "scripts" / "bootstrap_admin.py"

needs_repo_scripts = pytest.mark.skipif(not GENERATOR.exists(), reason="repository scripts/ not available (running inside the image)")


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# REQ-INSTALL-003: the generator cannot fall behind the production gate again
# --------------------------------------------------------------------------

# Every setting the production gate (Settings.reject_insecure_production_defaults)
# refuses to leave at its default. If the gate learns a new one, add it here AND to
# the generator - the first test below fails until both agree.
GATE_FIELDS = (
    "operator_api_token", "internal_api_token", "runner_api_token", "raw_egress_api_token",
    "scope_signing_secret", "raw_egress_signing_secret", "mfa_encryption_key",
    "settings_encryption_key", "database_url", "s3_access_key", "s3_secret_key", "public_base_url",
)


@pytest.fixture(scope="module")
def generated():
    gen = _load(GENERATOR, "gen_production_env_under_test")
    return gen, gen.build_env("scan.example.test")


def _settings_kwargs(env: dict[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in env.items()}


@needs_repo_scripts
def test_the_generated_production_env_passes_the_real_production_gate(generated):
    _, env = generated
    settings = Settings(**_settings_kwargs(env))  # raises ValueError if the gate is unhappy
    assert settings.environment == "production"


@needs_repo_scripts
@pytest.mark.parametrize("field", GATE_FIELDS)
def test_negative_removing_any_gate_required_setting_makes_the_gate_refuse(generated, field, monkeypatch):
    """The generator is only "complete" because the gate fails closed on every omission."""
    _, env = generated
    kwargs = _settings_kwargs(env)
    assert field in kwargs, f"the generator no longer emits {field.upper()} - the gate requires it"
    del kwargs[field]
    # conftest.py puts valid MFA/settings keys into the process environment; an
    # omitted setting must not be rescued by it, so model "omitted" faithfully.
    for gate_field in GATE_FIELDS:
        monkeypatch.delenv(gate_field.upper(), raising=False)
    with pytest.raises(ValueError, match="insecure production configuration"):
        Settings(**kwargs)


@needs_repo_scripts
def test_the_two_encryption_keys_differ_and_public_url_is_https(generated):
    _, env = generated
    assert env["MFA_ENCRYPTION_KEY"] != env["SETTINGS_ENCRYPTION_KEY"]
    assert env["PUBLIC_BASE_URL"] == "https://scan.example.test"


@needs_repo_scripts
def test_object_store_settings_match_the_seaweedfs_service_and_leave_no_minio_behind(generated):
    _, env = generated
    assert env["S3_ENDPOINT"] == "http://seaweedfs:8333"
    assert not [key for key in env if key.startswith("MINIO_")], "removed settings must not be emitted"
    for default in ("minioadmin", "asm-dev-access", "asm-dev-secret-change-me"):
        assert default not in (env["S3_ACCESS_KEY"], env["S3_SECRET_KEY"])


@needs_repo_scripts
def test_database_urls_use_the_generated_passwords(generated):
    _, env = generated
    assert f":{env['POSTGRES_PASSWORD']}@" in env["DATABASE_URL"]
    assert f":{env['PROXY_DB_PASSWORD']}@" in env["PROXY_DATABASE_URL"]


@needs_repo_scripts
def test_every_variable_the_production_compose_files_require_is_generated(generated):
    """`docker compose config` fails on `${VAR:?...}` when VAR is unset (the 2026-10-01
    OOB_TOKEN failure); parsing the files keeps this check independent of Docker."""
    _, env = generated
    required: set[str] = set()
    for name in ("docker-compose.yml", "docker-compose.prod.yml"):
        required |= set(re.findall(r"\$\{([A-Z0-9_]+):\?", (REPO / name).read_text()))
    assert required, "expected the production overlay to require variables"
    missing = sorted(required - set(env))
    assert not missing, f"required by the compose files but not generated: {missing}"


@needs_repo_scripts
def test_cli_writes_a_private_file_and_refuses_to_overwrite_without_force(tmp_path):
    out = tmp_path / ".env"
    cmd = [sys.executable, str(GENERATOR), "--domain", "scan.example.test", "--out", str(out)]
    first = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert first.returncode == 0, first.stderr
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    original = out.read_text()

    second = subprocess.run(cmd, capture_output=True, text=True, timeout=30)  # [Negative test]
    assert second.returncode == 1 and "refusing to overwrite" in second.stderr
    assert out.read_text() == original

    out.chmod(0o644)
    forced = subprocess.run(cmd + ["--force"], capture_output=True, text=True, timeout=30)
    assert forced.returncode == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600, "--force must not leave a looser mode behind"
    assert out.read_text() != original  # fresh secrets


@needs_repo_scripts
def test_the_removed_console_port_flag_is_accepted_and_ignored(tmp_path):
    """Existing runbooks pass --minio-console-port; they must keep working."""
    out = tmp_path / ".env"
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--domain", "scan.example.test", "--out", str(out), "--minio-console-port", "9001"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0 and "ignored" in result.stderr
    assert "MINIO_CONSOLE" not in out.read_text()


# --------------------------------------------------------------------------
# REQ-INSTALL-004: a missing encryption key is a 503 with a fix, not a 500
# --------------------------------------------------------------------------

def test_negative_an_empty_mfa_key_raises_the_dedicated_error_not_a_value_error(monkeypatch):
    monkeypatch.setattr(get_settings(), "mfa_encryption_key", "")
    with pytest.raises(mfa.MfaKeyUnavailable) as caught:
        mfa.encrypt_secret("JBSWY3DPEHPK3PXP")
    message = str(caught.value)
    assert "MFA_ENCRYPTION_KEY" in message and "make env" in message


def test_negative_a_malformed_mfa_key_raises_the_dedicated_error_without_echoing_it(monkeypatch):
    sentinel = "SENTINEL-this-is-not-a-fernet-key"
    monkeypatch.setattr(get_settings(), "mfa_encryption_key", sentinel)
    with pytest.raises(mfa.MfaKeyUnavailable) as caught:
        mfa.encrypt_secret("JBSWY3DPEHPK3PXP")
    assert sentinel not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__  # `from None`


def test_negative_decrypting_with_an_unavailable_key_is_also_the_dedicated_error(monkeypatch):
    token = mfa.encrypt_secret("JBSWY3DPEHPK3PXP")  # with the valid key conftest.py generated
    monkeypatch.setattr(get_settings(), "mfa_encryption_key", "")
    with pytest.raises(mfa.MfaKeyUnavailable):
        mfa.decrypt_secret(token)


def test_with_a_valid_key_the_roundtrip_is_unchanged():
    secret = mfa.generate_secret()
    assert mfa.decrypt_secret(mfa.encrypt_secret(secret)) == secret


def test_negative_the_app_turns_the_error_into_a_503_that_names_the_fix_and_leaks_nothing(monkeypatch):
    """Exercises the REAL handler registered on app.main.app, through a temporary route."""
    from fastapi.testclient import TestClient

    from app.main import app

    sentinel = "SENTINEL-not-a-key-0123456789"
    monkeypatch.setattr(get_settings(), "mfa_encryption_key", sentinel)

    def _raises():
        mfa.encrypt_secret("JBSWY3DPEHPK3PXP")

    app.add_api_route("/__test_mfa_key_unavailable", _raises)
    try:
        response = TestClient(app, raise_server_exceptions=False).get("/__test_mfa_key_unavailable")
    finally:
        app.router.routes[:] = [r for r in app.router.routes if getattr(r, "path", "") != "/__test_mfa_key_unavailable"]
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert "MFA_ENCRYPTION_KEY" in detail and "make env" in detail
    assert sentinel not in response.text


# --------------------------------------------------------------------------
# REQ-INSTALL-005: the first administrator can always log in
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def bootstrap():
    return _load(BOOTSTRAP, "bootstrap_admin_under_test")


VALID = ["you@example.com", "Admin.Name+tag@sub.example.org", "o'brien@example.co.uk"]
REJECTED_BY_SIGN_IN = [
    "admin@example.test",        # the address that produced a 422 at sign-in on 2026-10-01
    "admin@localhost", "me@host.local", "me@asm.invalid", "me@thing.localhost",
    "nodomain", "name@", "@example.com", "a b@example.com", "",
]


@pytest.mark.parametrize("email", VALID)
def test_valid_addresses_are_accepted(bootstrap, email):
    assert bootstrap.check_login_email(email) is None


@pytest.mark.parametrize("email", [e for e in REJECTED_BY_SIGN_IN if e])
def test_negative_addresses_the_sign_in_form_rejects_are_refused_with_a_reason(bootstrap, email):
    reason = bootstrap.check_login_email(email)
    assert reason, f"{email!r} must be refused"


@pytest.mark.parametrize("email", VALID + [e for e in REJECTED_BY_SIGN_IN if e])
def test_bootstrap_and_sign_in_agree_on_every_address(bootstrap, email):
    """The point of the requirement: the SAME validator, so the two can never disagree."""
    from pydantic import ValidationError

    try:
        LoginIn(email=email, password="unused")
        sign_in_accepts = True
    except ValidationError:
        sign_in_accepts = False
    assert (bootstrap.check_login_email(email) is None) == sign_in_accepts


def test_negative_an_unusable_address_exits_1_and_creates_nothing(bootstrap, monkeypatch, capsys):
    def _no_database(*_a, **_k):
        raise AssertionError("the database must not be touched for an unusable address")

    monkeypatch.setattr(bootstrap, "SessionLocal", _no_database)
    monkeypatch.setenv("INITIAL_ADMIN_EMAIL", "admin@example.test")
    assert bootstrap.main() == 1
    err = capsys.readouterr().err
    assert "cannot be used" in err and "you@example.com" in err
    assert "temporary password" not in err


def test_a_missing_address_still_exits_1(bootstrap, monkeypatch, capsys):
    monkeypatch.delenv("INITIAL_ADMIN_EMAIL", raising=False)
    assert bootstrap.main() == 1
    assert "INITIAL_ADMIN_EMAIL is not set" in capsys.readouterr().err
