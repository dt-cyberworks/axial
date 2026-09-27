"""REQ-AUDITUI-001/002: the read-only searchable audit projection returns this
engagement's entries newest-first, supports free-text + field filters and
cursor pagination, exposes filter facets, and never mutates the log."""

from __future__ import annotations

import datetime as dt

from app.api.stream import audit_facets, list_audit
from app.gateway.audit import append_audit_log
from app.models.audit import AuditLog


def _seed(db, engagement_id):
    append_audit_log(db, engagement_id=engagement_id, actor="gateway", action="tool_call",
                     decision="ALLOW", reason="gateway_allowed",
                     payload={"tool": "nuclei", "target": "app.example.com", "category": "vuln"})
    append_audit_log(db, engagement_id=engagement_id, actor="egress-proxy", action="network_request",
                     decision="DENY", reason="blocked_link_local_address",
                     payload={"method": "GET", "host": "metadata.internal"})
    append_audit_log(db, engagement_id=engagement_id, actor="agent", action="agent_event",
                     decision=None, reason="llm_proposed_tool",
                     payload={"event": "proposal", "proposal": {"tool": "httpx", "target": "shop.example.com"}})


def test_returns_entries_newest_first(db, lab_engagement):
    _seed(db, lab_engagement.id)
    out = list_audit(lab_engagement.id, db=db)
    assert [e["action"] for e in out["entries"]] == ["agent_event", "network_request", "tool_call"]
    assert out["has_more"] is False


def test_free_text_search_matches_payload(db, lab_engagement):
    _seed(db, lab_engagement.id)
    # A hostname buried in the JSON payload is searchable.
    out = list_audit(lab_engagement.id, q="metadata.internal", db=db)
    assert len(out["entries"]) == 1
    assert out["entries"][0]["reason"] == "blocked_link_local_address"

    out2 = list_audit(lab_engagement.id, q="nuclei", db=db)
    assert len(out2["entries"]) == 1
    assert out2["entries"][0]["payload"]["tool"] == "nuclei"


def test_decision_and_actor_filters(db, lab_engagement):
    _seed(db, lab_engagement.id)
    denies = list_audit(lab_engagement.id, decision="deny", db=db)
    assert len(denies["entries"]) == 1
    assert denies["entries"][0]["actor"] == "egress-proxy"

    agent = list_audit(lab_engagement.id, actor="agent", db=db)
    assert len(agent["entries"]) == 1
    assert agent["entries"][0]["action"] == "agent_event"


def test_cursor_pagination(db, lab_engagement):
    _seed(db, lab_engagement.id)
    page1 = list_audit(lab_engagement.id, limit=2, db=db)
    assert len(page1["entries"]) == 2
    assert page1["has_more"] is True
    assert page1["next_before"] is not None

    cursor = dt.datetime.fromisoformat(page1["next_before"])
    page2 = list_audit(lab_engagement.id, limit=2, before=cursor, db=db)
    # The remaining older entry, no overlap with page 1.
    assert len(page2["entries"]) == 1
    page1_ids = {e["id"] for e in page1["entries"]}
    assert page2["entries"][0]["id"] not in page1_ids


def test_facets_lists_present_actors_and_actions(db, lab_engagement):
    _seed(db, lab_engagement.id)
    facets = audit_facets(lab_engagement.id, db=db)
    assert set(facets["actors"]) >= {"gateway", "egress-proxy", "agent"}
    assert set(facets["actions"]) >= {"tool_call", "network_request", "agent_event"}


def test_scoped_to_engagement_only(db, lab_engagement):
    _seed(db, lab_engagement.id)
    # An unrelated engagement id sees nothing.
    import uuid
    out = list_audit(uuid.uuid4(), db=db)
    assert out["entries"] == []


def test_projection_does_not_mutate_the_log(db, lab_engagement):
    _seed(db, lab_engagement.id)
    before = db.query(AuditLog).filter(AuditLog.engagement_id == lab_engagement.id).count()
    list_audit(lab_engagement.id, q="example", db=db)
    list_audit(lab_engagement.id, decision="ALLOW", db=db)
    after = db.query(AuditLog).filter(AuditLog.engagement_id == lab_engagement.id).count()
    assert before == after == 3
