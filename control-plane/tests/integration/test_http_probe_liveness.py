"""REQ-AGENT-015: the deterministic fingerprint phase's httpx probe outcome
(live or dead) must be recorded regardless of result, and surfaced through
agent-context, so the agent phase can tell "never checked" apart from
"already checked, no live HTTP service" - found live: without this, the agent
re-probed the same confirmed-dead subdomains with httpx in every one of 3
consecutive scan runs, wasting iteration budget."""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi import HTTPException

from app.api.internal import agent_context, record_http_probe
from app.models.asset import DiscoveredAsset
from app.schemas.internal import HttpProbeResultIn


def _asset(db, engagement_id, value: str) -> DiscoveredAsset:
    asset = DiscoveredAsset(
        engagement_id=engagement_id, asset_type="domain", value=value,
        in_scope=True, discovered_via="passive-osint",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def test_never_checked_host_has_no_liveness_fields(db, lab_engagement):
    _asset(db, lab_engagement.id, "never-checked.example.com")
    ctx = agent_context(lab_engagement.id, db)
    host = next(h for h in ctx["hosts"] if h["host"] == "never-checked.example.com")
    assert host["http_checked_at"] is None
    assert host["http_live"] is None


def test_dead_probe_is_recorded_and_surfaced(db, lab_engagement):
    asset = _asset(db, lab_engagement.id, "dead-host.example.com")
    record_http_probe(lab_engagement.id, asset.id, HttpProbeResultIn(live=False), db)

    ctx = agent_context(lab_engagement.id, db)
    host = next(h for h in ctx["hosts"] if h["host"] == "dead-host.example.com")
    assert host["http_live"] is False
    assert host["http_checked_at"] is not None


def test_live_probe_is_recorded_and_surfaced(db, lab_engagement):
    asset = _asset(db, lab_engagement.id, "live-host.example.com")
    record_http_probe(lab_engagement.id, asset.id, HttpProbeResultIn(live=True), db)

    ctx = agent_context(lab_engagement.id, db)
    host = next(h for h in ctx["hosts"] if h["host"] == "live-host.example.com")
    assert host["http_live"] is True


def test_http_probe_rejects_asset_from_another_engagement(db, lab_engagement, test_user):
    from app.models.engagement import Engagement

    now = dt.datetime.now(dt.timezone.utc)
    other = Engagement(
        title="Other", source="lab", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
        owner_user_id=test_user.id,
    )
    db.add(other)
    db.commit()
    asset = _asset(db, other.id, "cross-engagement.example.com")

    with pytest.raises(HTTPException) as exc_info:
        record_http_probe(lab_engagement.id, asset.id, HttpProbeResultIn(live=False), db)
    assert exc_info.value.status_code == 404
