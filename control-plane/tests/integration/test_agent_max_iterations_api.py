"""TC-AGENT-BUDGET-001: globale Settings-/Engagement-Config-Endpunkte fuer das
Agent-Iterationsbudget (REQ-AGENT-008)."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.engagements import get_engagement_config, put_engagement_config
from app.api.settings import (
    AgentMaxIterationsIn,
    read_agent_max_iterations,
    update_agent_max_iterations,
)
from app.schemas.engagement import EngagementConfigIn


def test_global_get_defaults_and_put_roundtrips(db):
    assert read_agent_max_iterations(db).value == 50
    out = update_agent_max_iterations(AgentMaxIterationsIn(value=75), db)
    assert out.value == 75
    assert read_agent_max_iterations(db).value == 75


def test_global_put_rejects_out_of_range(db):
    with pytest.raises(Exception):  # pydantic ValidationError at the Field(ge=,le=) boundary
        AgentMaxIterationsIn(value=0)
    with pytest.raises(Exception):
        AgentMaxIterationsIn(value=501)


def test_engagement_config_reports_effective_value_and_override_flag(db, lab_engagement, test_user):
    cfg = get_engagement_config(lab_engagement.id, db)
    assert cfg["agent_max_iterations"] == 50
    assert cfg["agent_max_iterations_overridden"] is False

    put_engagement_config(lab_engagement.id, EngagementConfigIn(agent_max_iterations_override=90), db, user=test_user)
    cfg = get_engagement_config(lab_engagement.id, db)
    assert cfg["agent_max_iterations"] == 90
    assert cfg["agent_max_iterations_overridden"] is True


def test_engagement_config_clears_override_when_field_explicitly_null(db, lab_engagement, test_user):
    put_engagement_config(lab_engagement.id, EngagementConfigIn(agent_max_iterations_override=90), db, user=test_user)
    assert get_engagement_config(lab_engagement.id, db)["agent_max_iterations_overridden"] is True

    # Feld explizit auf None gesetzt (nicht weggelassen) -> Override geloescht.
    body = EngagementConfigIn.model_validate({"agent_max_iterations_override": None})
    put_engagement_config(lab_engagement.id, body, db, user=test_user)
    cfg = get_engagement_config(lab_engagement.id, db)
    assert cfg["agent_max_iterations_overridden"] is False
    assert cfg["agent_max_iterations"] == 50


def test_engagement_config_omitted_field_leaves_override_untouched(db, lab_engagement, test_user):
    put_engagement_config(lab_engagement.id, EngagementConfigIn(agent_max_iterations_override=90), db, user=test_user)
    # Feld komplett weggelassen (nicht im Request) -> bleibt unveraendert.
    put_engagement_config(lab_engagement.id, EngagementConfigIn(), db, user=test_user)
    cfg = get_engagement_config(lab_engagement.id, db)
    assert cfg["agent_max_iterations_overridden"] is True
    assert cfg["agent_max_iterations"] == 90
