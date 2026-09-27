"""REQ-AGENT-012: the worker's /internal/engagements/{id}/agent-config must
also return the engagement's own parameters (title, source, authorized
window, port envelope, ai_testing_allowed) so the Vector Agent can be told
what campaign it is actually operating under, not just the in-scope hosts."""

from __future__ import annotations

from app.api.internal import internal_agent_config


def test_agent_config_includes_engagement_parameters(db, lab_engagement):
    out = internal_agent_config(lab_engagement.id, db)

    eng = out["engagement"]
    assert eng["title"] == lab_engagement.title
    assert eng["source"] == lab_engagement.source
    assert eng["tcp_port_from"] == lab_engagement.tcp_port_from
    assert eng["tcp_port_to"] == lab_engagement.tcp_port_to
    assert eng["ai_testing_allowed"] == lab_engagement.ai_testing_allowed
    assert eng["authorized_from"] == lab_engagement.authorized_from.isoformat()
    assert eng["authorized_until"] == lab_engagement.authorized_until.isoformat()


def test_agent_config_prompt_is_never_empty(db, lab_engagement):
    """REQ-AGENT-011: the effective prompt must never be an empty string -
    the Settings GUI must always be able to display something real."""
    out = internal_agent_config(lab_engagement.id, db)
    assert out["prompt"].strip() != ""
