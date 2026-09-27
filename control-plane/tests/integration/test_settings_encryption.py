"""GitHub issue #25: LLM/NVD provider API keys must be encrypted at rest in
app_setting.value (JSONB), not stored in the clear. Exercises the real
encrypt/decrypt round trip against a real Postgres (unlike test_settings_llm.py,
which predates this fix and only asserts values, not what actually lands on
disk), the legacy-plaintext migration-on-read path, key-rotation, the
fail-loud behaviour on a missing/wrong key, and - the acceptance criterion
stated most literally in the issue - that a real `pg_dump` of a configured
instance contains no substring of a stored key."""

from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

from app import config
from app.models.app_setting import AppSetting
from app.settings_store import (
    LLM_CONFIG_KEY,
    NVD_CONFIG_KEY,
    SettingsCipherUnavailable,
    get_llm_config,
    get_nvd_config,
    set_llm_config,
    set_nvd_config,
)


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    """Several tests below monkeypatch SETTINGS_ENCRYPTION_KEY(_PREVIOUS) -
    get_settings() is lru_cache'd, so every test must start and end clean."""
    config.get_settings.cache_clear()
    yield
    config.get_settings.cache_clear()


def _raw_value(db, key: str) -> dict:
    db.expire_all()
    row = db.get(AppSetting, key)
    return row.value


def test_llm_api_key_is_not_stored_in_the_clear(db):
    set_llm_config(db, base_url="https://api.example.test/v1", model="m", api_key="sk-live-should-never-be-plaintext")
    stored = _raw_value(db, LLM_CONFIG_KEY)
    assert "api_key_enc" in stored
    assert "api_key" not in stored
    assert "sk-live-should-never-be-plaintext" not in str(stored)

    # ...but the round trip still returns the original plaintext.
    cfg = get_llm_config(db)
    assert cfg.api_key == "sk-live-should-never-be-plaintext"


def test_nvd_api_key_is_not_stored_in_the_clear(db):
    set_nvd_config(db, api_key="nvd-key-should-never-be-plaintext")
    stored = _raw_value(db, NVD_CONFIG_KEY)
    assert "api_key_enc" in stored
    assert "api_key" not in stored
    assert "nvd-key-should-never-be-plaintext" not in str(stored)

    cfg = get_nvd_config(db)
    assert cfg.api_key == "nvd-key-should-never-be-plaintext"


def test_legacy_plaintext_llm_key_is_migrated_on_read(db):
    """A row written before this fix (a bare 'api_key' plaintext field, as
    set_llm_config used to write it) must still work AND get migrated to
    encrypted storage the first time it is read, per the issue's acceptance
    criterion ('existing plaintext values are migrated')."""
    db.add(AppSetting(key=LLM_CONFIG_KEY, value={
        "base_url": "https://legacy.example.test/v1", "model": "legacy-model", "api_key": "legacy-plaintext-key",
    }))
    db.commit()

    cfg = get_llm_config(db)
    assert cfg.api_key == "legacy-plaintext-key"

    migrated = _raw_value(db, LLM_CONFIG_KEY)
    assert "api_key" not in migrated
    assert "api_key_enc" in migrated
    assert "legacy-plaintext-key" not in str(migrated)

    # A second read (now purely from the encrypted field) must still work.
    assert get_llm_config(db).api_key == "legacy-plaintext-key"


def test_legacy_plaintext_nvd_key_is_migrated_on_read(db):
    db.add(AppSetting(key=NVD_CONFIG_KEY, value={"api_key": "legacy-nvd-plaintext"}))
    db.commit()

    cfg = get_nvd_config(db)
    assert cfg.api_key == "legacy-nvd-plaintext"

    migrated = _raw_value(db, NVD_CONFIG_KEY)
    assert "api_key" not in migrated
    assert "api_key_enc" in migrated


def test_set_api_key_none_leaves_the_encrypted_value_unchanged(db):
    set_llm_config(db, base_url="https://x/v1", model="m", api_key="secret")
    cfg = set_llm_config(db, base_url="https://y/v1", model="m2", api_key=None)
    assert cfg.api_key == "secret"


def test_set_empty_api_key_clears_the_stored_value(db):
    set_llm_config(db, base_url="https://x/v1", model="m", api_key="secret")
    cfg = set_llm_config(db, base_url="https://x/v1", model="m", api_key="")
    assert cfg.api_key == ""
    stored = _raw_value(db, LLM_CONFIG_KEY)
    assert "api_key_enc" not in stored


def test_negative_missing_encryption_key_fails_loud_on_write(db, monkeypatch):
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", "")
    config.get_settings.cache_clear()
    with pytest.raises(SettingsCipherUnavailable):
        set_llm_config(db, base_url="https://x/v1", model="m", api_key="secret")


def test_negative_missing_encryption_key_fails_loud_on_read_of_existing_ciphertext(db, monkeypatch):
    set_llm_config(db, base_url="https://x/v1", model="m", api_key="secret")
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", "")
    config.get_settings.cache_clear()
    with pytest.raises(SettingsCipherUnavailable):
        get_llm_config(db)


def test_negative_wrong_encryption_key_fails_loud_rather_than_returning_empty(db, monkeypatch):
    """A key that IS present but cannot open the stored ciphertext (e.g. a
    botched rotation, or a DB restored into the wrong environment) must
    raise - NOT silently behave as if no key had ever been set. Silently
    returning "" here would be indistinguishable from an unconfigured
    provider and could mask a real incident."""
    from cryptography.fernet import Fernet

    set_llm_config(db, base_url="https://x/v1", model="m", api_key="secret")
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    config.get_settings.cache_clear()
    with pytest.raises(SettingsCipherUnavailable):
        get_llm_config(db)


def test_rotation_write_new_read_old(db, monkeypatch):
    from cryptography.fernet import Fernet

    old_key = os.environ["SETTINGS_ENCRYPTION_KEY"]
    new_key = Fernet.generate_key().decode()

    set_llm_config(db, base_url="https://x/v1", model="m", api_key="pre-rotation-secret")

    # Rotate: new_key becomes primary, old_key is kept as "previous".
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", new_key)
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY_PREVIOUS", old_key)
    config.get_settings.cache_clear()

    # Still readable via the old (now "previous") key.
    assert get_llm_config(db).api_key == "pre-rotation-secret"

    # A fresh write now re-encrypts under the new primary key.
    set_llm_config(db, base_url="https://x/v1", model="m", api_key="post-rotation-secret")
    assert get_llm_config(db).api_key == "post-rotation-secret"

    # Drop the old key entirely (rotation complete) - the post-rotation
    # value (written under new_key) must still be readable.
    monkeypatch.delenv("SETTINGS_ENCRYPTION_KEY_PREVIOUS", raising=False)
    config.get_settings.cache_clear()
    assert get_llm_config(db).api_key == "post-rotation-secret"


def _pg_dump_available() -> bool:
    return shutil.which("pg_dump") is not None and bool(os.environ.get("TEST_DATABASE_URL"))


def _as_dsn(sqlalchemy_url: str) -> str:
    """pg_dump doesn't understand SQLAlchemy's '+psycopg' driver suffix."""
    return re.sub(r"^postgresql\+\w+://", "postgresql://", sqlalchemy_url)


def test_pg_dump_of_a_configured_instance_contains_no_plaintext_key(db, engine):
    """The acceptance criterion from the issue, taken literally: a real
    pg_dump of app_setting must not contain the stored key anywhere - not
    as the JSONB value, not in any other column/format pg_dump might emit
    it in (e.g. --inserts vs. COPY)."""
    if not _pg_dump_available():
        pytest.skip("pg_dump or TEST_DATABASE_URL not available")

    unique_marker = "sk-pgdump-acceptance-4f9c2a7e1b6d"
    set_llm_config(db, base_url="https://x/v1", model="m", api_key=unique_marker)
    set_nvd_config(db, api_key=unique_marker)

    dsn = _as_dsn(os.environ["TEST_DATABASE_URL"])
    result = subprocess.run(
        ["pg_dump", "--no-owner", "--no-privileges", dsn],
        capture_output=True, text=True, timeout=60, check=True,
    )
    assert unique_marker not in result.stdout, "pg_dump output contains a plaintext provider API key"
