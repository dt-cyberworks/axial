"""REQ-BUDGET-001: the tool-call budget of a run is one bounded, global setting.

Unit level, with an in-memory stand-in for the AppSetting store; the API, the run that records
the value and the gateway's enforcement are covered by the integration suite."""

import pytest

from app import settings_store
from app.settings_store import (
    DEFAULT_TOOL_CALL_BUDGET,
    MAX_TOOL_CALL_BUDGET,
    MIN_TOOL_CALL_BUDGET,
    TOOL_CALL_BUDGET_KEY,
    get_global_tool_call_budget,
    set_global_tool_call_budget,
)


class _Row:
    def __init__(self, value):
        self.value = value


class _FakeDb:
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


def test_unset_reads_the_value_every_run_had_before(db):
    assert get_global_tool_call_budget(db) == 200 == DEFAULT_TOOL_CALL_BUDGET


def test_the_bounds_are_documented(db):
    assert (MIN_TOOL_CALL_BUDGET, MAX_TOOL_CALL_BUDGET) == (20, 5000)


def test_a_value_round_trips(db):
    assert set_global_tool_call_budget(db, 500) == 500
    assert get_global_tool_call_budget(db) == 500


@pytest.mark.parametrize("value", [20, 5000])
def test_the_bounds_themselves_are_accepted(db, value):
    assert set_global_tool_call_budget(db, value) == value


@pytest.mark.parametrize("value", [19, 0, -1, 5001, 100000, True])
def test_an_out_of_range_value_is_refused_and_not_stored(db, value):
    with pytest.raises(ValueError):
        set_global_tool_call_budget(db, value)
    assert TOOL_CALL_BUDGET_KEY not in db.rows


@pytest.mark.parametrize("stored", [{"value": "abc"}, {"value": None}, {"value": 3}, {"value": 99999}, {}, "junk", None])
def test_a_damaged_stored_value_falls_back_to_the_default_not_an_error(db, stored):
    db.rows[TOOL_CALL_BUDGET_KEY] = _Row(stored)
    assert get_global_tool_call_budget(db) == DEFAULT_TOOL_CALL_BUDGET
