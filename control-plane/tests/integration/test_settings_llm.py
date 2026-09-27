"""LLM-Provider-Konfig: DB (app_setting) ueberschreibt Env-Defaults, api_key
wird in der oeffentlichen Sicht maskiert, bleibt intern aber verfuegbar."""

from __future__ import annotations

from app.settings_store import get_llm_config, set_llm_config


def test_defaults_to_env_when_no_db_row(db, monkeypatch):
    from app import config
    config.get_settings.cache_clear()
    monkeypatch.setenv("LLM_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("LLM_API_KEY", "env-key")
    config.get_settings.cache_clear()

    cfg = get_llm_config(db)
    assert cfg.source == "env"
    assert cfg.base_url == "https://api.openai.com/v1"
    assert cfg.model == "gpt-4o-mini"
    assert cfg.api_key == "env-key"
    assert cfg.is_usable
    config.get_settings.cache_clear()


def test_db_overrides_env(db, monkeypatch):
    from app import config
    monkeypatch.setenv("LLM_BASE_URL", "https://env.example/v1")
    monkeypatch.setenv("LLM_MODEL", "env-model")
    monkeypatch.setenv("LLM_API_KEY", "env-key")
    config.get_settings.cache_clear()

    set_llm_config(db, base_url="https://api.edenai.run/v2/openai", model="openai/gpt-4o", api_key="db-key")
    cfg = get_llm_config(db)
    assert cfg.source == "db"
    assert cfg.base_url == "https://api.edenai.run/v2/openai"
    assert cfg.model == "openai/gpt-4o"
    assert cfg.api_key == "db-key"
    config.get_settings.cache_clear()


def test_api_key_preserved_when_update_omits_it(db):
    set_llm_config(db, base_url="https://x/v1", model="m", api_key="secret")
    # Folge-Update ohne Schluessel (GUI sendet ihn nicht erneut) -> bleibt erhalten.
    cfg = set_llm_config(db, base_url="https://y/v1", model="m2", api_key=None)
    assert cfg.base_url == "https://y/v1"
    assert cfg.model == "m2"
    assert cfg.api_key == "secret"


def test_public_endpoint_masks_key(db):
    """GET /settings/llm darf den Schluessel nie zurueckgeben, nur api_key_set."""
    from app.api.settings import _to_out

    set_llm_config(db, base_url="https://x/v1", model="m", api_key="topsecret")
    out = _to_out(get_llm_config(db))
    dumped = out.model_dump()
    assert dumped["api_key_set"] is True
    assert "api_key" not in dumped
    assert "topsecret" not in str(dumped)
