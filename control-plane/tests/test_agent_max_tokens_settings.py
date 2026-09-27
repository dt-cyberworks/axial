"""REQ-AGENT-026: the agent's completion-token cap is a bounded, configurable
setting rather than a container env var read at process start.

Uses an in-memory stand-in for the AppSetting store so these stay unit tests;
the layered resolution against real engagement rows is covered by the
integration suite's config-layer tests.
"""

import pytest

from app import settings_store
from app.settings_store import (
    DEFAULT_AGENT_MAX_TOKENS,
    MAX_AGENT_MAX_TOKENS,
    MIN_AGENT_MAX_TOKENS,
    get_global_agent_max_tokens,
    set_global_agent_max_tokens,
)


class _Row:
    def __init__(self, value):
        self.value = value


class _FakeDb:
    """Minimal db.get(AppSetting, key) / _put_setting stand-in."""
    def __init__(self, rows=None):
        self.rows = rows or {}

    def get(self, _model, key):
        return self.rows.get(key)


@pytest.fixture
def db(monkeypatch):
    fake = _FakeDb()

    def _put(_db, key, value):
        fake.rows[key] = _Row(value)

    monkeypatch.setattr(settings_store, "_put_setting", _put)
    return fake


def test_defaults_to_8192_when_unset(db):
    assert get_global_agent_max_tokens(db) == 8192
    assert DEFAULT_AGENT_MAX_TOKENS == 8192


def test_documented_bounds_match_the_workers_own_clamp(db):
    assert (MIN_AGENT_MAX_TOKENS, MAX_AGENT_MAX_TOKENS) == (1024, 32768)


def test_a_valid_value_round_trips(db):
    assert set_global_agent_max_tokens(db, 16384) == 16384
    assert get_global_agent_max_tokens(db) == 16384


def test_boundary_values_are_accepted(db):
    assert set_global_agent_max_tokens(db, MIN_AGENT_MAX_TOKENS) == MIN_AGENT_MAX_TOKENS
    assert set_global_agent_max_tokens(db, MAX_AGENT_MAX_TOKENS) == MAX_AGENT_MAX_TOKENS


@pytest.mark.parametrize("value", [0, 1, 1023, 32769, 100000, -4096])
def test_negative_out_of_range_values_are_rejected_not_silently_clamped(db, value):
    with pytest.raises(ValueError):
        set_global_agent_max_tokens(db, value)
    # Nothing was persisted, so the effective value is still the default.
    assert get_global_agent_max_tokens(db) == DEFAULT_AGENT_MAX_TOKENS


@pytest.mark.parametrize("stored", [
    {"value": "not-a-number"},
    {"value": None},
    {"value": 99999},   # out of range in storage (e.g. written before bounds changed)
    {"value": 10},
    {},
    "not-a-dict",
])
def test_negative_a_corrupt_stored_value_falls_back_to_the_default(db, stored):
    db.rows[settings_store.AGENT_MAX_TOKENS_KEY] = _Row(stored)
    assert get_global_agent_max_tokens(db) == DEFAULT_AGENT_MAX_TOKENS
