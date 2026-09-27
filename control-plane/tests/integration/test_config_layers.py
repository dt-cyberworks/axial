"""Durchgaengiges Konfigurationsmodell: Registry-Boden -> global -> Kampagne.

Verifiziert die Aufloesungsreihenfolge UND dass das Gateway die effektive
Config durchsetzt (tool_disabled, per-Tool-Approval), ohne den Sicherheitsboden
aufweichbar zu machen.
"""

from __future__ import annotations

from app import config_resolver
from app.default_prompts import DEFAULT_AGENT_PROMPT
from app.gateway.authorize import ToolCall, authorize
from app.models.engagement import ToolApprovalPolicy
from app.settings_store import (
    set_global_agent_max_iterations,
    set_global_agent_prompt,
    set_global_approval_timeout_seconds,
    set_global_tool_policy,
)


def _call(eng, tool="nuclei", category="vuln"):
    return ToolCall(engagement_id=eng.id, tool=tool, category=category,
                    mode="active", target="metasploitable2", args={})


# --- Resolver-Layering: enabled ------------------------------------------

def test_enabled_defaults_to_registry(db, lab_engagement):
    cfg = config_resolver.effective_tool_config(db, lab_engagement.id, "nuclei")
    assert cfg.enabled is True and cfg.enabled_source == "registry"


def test_global_can_disable(db, lab_engagement):
    set_global_tool_policy(db, {"nuclei": {"enabled": False}})
    cfg = config_resolver.effective_tool_config(db, lab_engagement.id, "nuclei")
    assert cfg.enabled is False and cfg.enabled_source == "global"


def test_campaign_override_beats_global(db, lab_engagement):
    set_global_tool_policy(db, {"nuclei": {"enabled": False}})
    db.add(ToolApprovalPolicy(engagement_id=lab_engagement.id, tool_name="nuclei",
                              requires_manual_approval=False, enabled=True))
    db.commit()
    cfg = config_resolver.effective_tool_config(db, lab_engagement.id, "nuclei")
    assert cfg.enabled is True and cfg.enabled_source == "campaign"


def test_registry_floor_uninstalled_never_enabled(db, lab_engagement):
    # dnsx ist in der Registry, aber installed=False -> nie aktivierbar.
    set_global_tool_policy(db, {"dnsx": {"enabled": True}})
    cfg = config_resolver.effective_tool_config(db, lab_engagement.id, "dnsx")
    assert cfg.enabled is False


# --- Gateway setzt enabled durch -----------------------------------------

def test_gateway_denies_disabled_tool(db, lab_engagement):
    set_global_tool_policy(db, {"nuclei": {"enabled": False}})
    decision = authorize(db, _call(lab_engagement))
    assert not decision.allowed and decision.reason == "tool_disabled"


def test_gateway_allows_enabled_tool(db, lab_engagement):
    decision = authorize(db, _call(lab_engagement))
    assert decision.allowed, decision.reason


# --- Approval: global oder Kampagne erzwingt Einzelfreigabe ---------------

def test_global_requires_approval_makes_pending(db, lab_engagement):
    set_global_tool_policy(db, {"nuclei": {"enabled": True, "requires_approval": True}})
    decision = authorize(db, _call(lab_engagement))
    assert not decision.allowed and decision.is_pending
    assert decision.approval_request_id is not None


def test_campaign_requires_approval_makes_pending(db, lab_engagement):
    db.add(ToolApprovalPolicy(engagement_id=lab_engagement.id, tool_name="nuclei",
                              requires_manual_approval=True, enabled=None))
    db.commit()
    decision = authorize(db, _call(lab_engagement))
    assert not decision.allowed and decision.is_pending


# --- Agent-Prompt: Kampagne > global > eingebauter Default (REQ-AGENT-011) --

def test_agent_prompt_resolution_order(db, lab_engagement):
    assert config_resolver.effective_agent_prompt(db, lab_engagement.id) == DEFAULT_AGENT_PROMPT
    set_global_agent_prompt(db, "GLOBAL PROMPT")
    assert config_resolver.effective_agent_prompt(db, lab_engagement.id) == "GLOBAL PROMPT"
    lab_engagement.agent_prompt_override = "CAMPAIGN PROMPT"
    db.commit()
    assert config_resolver.effective_agent_prompt(db, lab_engagement.id) == "CAMPAIGN PROMPT"


# --- Agent-Iterationsbudget: Kampagne > global > eingebauter Default (50) ---

def test_agent_max_iterations_resolution_order(db, lab_engagement):
    assert config_resolver.effective_agent_max_iterations(db, lab_engagement.id) == 50
    set_global_agent_max_iterations(db, 80)
    assert config_resolver.effective_agent_max_iterations(db, lab_engagement.id) == 80
    lab_engagement.agent_max_iterations_override = 120
    db.commit()
    assert config_resolver.effective_agent_max_iterations(db, lab_engagement.id) == 120


def test_set_global_agent_max_iterations_rejects_out_of_range(db):
    import pytest
    with pytest.raises(ValueError):
        set_global_agent_max_iterations(db, 0)
    with pytest.raises(ValueError):
        set_global_agent_max_iterations(db, 501)


def test_approval_timeout_seconds_resolution_order(db, lab_engagement):
    assert config_resolver.effective_approval_timeout_seconds(db, lab_engagement.id) == 900
    set_global_approval_timeout_seconds(db, 1800)
    assert config_resolver.effective_approval_timeout_seconds(db, lab_engagement.id) == 1800
    lab_engagement.approval_timeout_seconds_override = 120
    db.commit()
    assert config_resolver.effective_approval_timeout_seconds(db, lab_engagement.id) == 120


def test_set_global_approval_timeout_seconds_rejects_out_of_range(db):
    import pytest
    with pytest.raises(ValueError):
        set_global_approval_timeout_seconds(db, 59)
    with pytest.raises(ValueError):
        set_global_approval_timeout_seconds(db, 86401)
