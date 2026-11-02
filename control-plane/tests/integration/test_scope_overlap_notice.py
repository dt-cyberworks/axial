"""REQ-EGRESS-011 (GitHub #81): once the egress proxy requires a signed run token it never guesses the engagement from
the destination, so two engagements covering the same host can both run. Activation then tells the owner instead of
refusing; while the proxy does not require the token, REQ-CONCUR-003's refusal stays exactly as it was."""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api.engagements import activate_engagement, add_scope_asset, create_engagement
from app.config import get_settings
from app.models.audit import AuditLog
from app.models.engagement import ScopeAsset
from app.models.user import User
from app.passwords import hash_secret
from app.schemas.engagement import EngagementCreate, ScopeAssetCreate


def _owner(db, name="Test Owner") -> User:
    user = User(
        email=f"owner-{dt.datetime.now(dt.timezone.utc).timestamp()}@example.com", display_name=name, role="operator",
        status="active", must_change_password=False, password_hash=hash_secret("irrelevant-not-used"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _draft(db, owner, title):
    now = dt.datetime.now(dt.timezone.utc)
    return create_engagement(
        EngagementCreate(title=title, source="own_domain", authorized_from=now - dt.timedelta(hours=1),
                         authorized_until=now + dt.timedelta(days=1)),
        user=owner, db=db,
    )


def _allow(db, engagement_id, value, asset_type="domain"):
    db.add(ScopeAsset(engagement_id=engagement_id, rule="allow", asset_type=asset_type, value=value,
                      active_allowed=True, authorization_verified=True))
    db.commit()


def _active(db, owner, title, value, asset_type="domain"):
    eng = _draft(db, owner, title)
    _allow(db, eng.id, value, asset_type)
    return activate_engagement(eng.id, db, user=owner)


@pytest.fixture()
def tokens_required(monkeypatch):
    monkeypatch.setattr(get_settings(), "egress_require_token", True)


@pytest.mark.parametrize("first, second, first_type, second_type", [
    ("shared.example.test", "shared.example.test", "domain", "domain"),
    ("example.test", "www.example.test", "domain", "domain"),
    ("www.example.test", "example.test", "domain", "domain"),
    ("203.0.113.0/24", "203.0.113.9", "cidr", "ip"),
])
def test_an_overlapping_engagement_activates_with_a_notice_that_names_the_other_one(db, tokens_required, first, second, first_type, second_type):
    other_owner = _owner(db, "Other Person")
    first_eng = _active(db, other_owner, "Monitoring of the main site", first, first_type)
    mine = _draft(db, _owner(db), "Manual test")
    _allow(db, mine.id, second, second_type)

    answer = activate_engagement(mine.id, db, user=_owner(db))

    assert answer.status == "active"
    notice = answer.scope_overlap_notice
    assert "Monitoring of the main site" in notice and "Other Person" in notice and other_owner.email in notice
    assert "Both can run" in notice
    db.refresh(first_eng)
    assert first_eng.status == "active", "the engagement that was there first is not disturbed"


def test_the_overlap_is_recorded_in_the_audit_trail_of_the_activated_engagement(db, tokens_required):
    first = _active(db, _owner(db), "First", "shared.example.test")
    mine = _draft(db, _owner(db), "Second")
    _allow(db, mine.id, "shared.example.test")
    activate_engagement(mine.id, db, user=_owner(db))
    row = db.scalars(select(AuditLog).where(AuditLog.engagement_id == mine.id, AuditLog.action == "engagement_activated")).one()
    assert row.payload["overlaps"] == [str(first.id)]


def test_no_overlap_means_no_notice_and_no_overlap_entry(db, tokens_required):
    _active(db, _owner(db), "First", "a.example.test")
    mine = _draft(db, _owner(db), "Second")
    _allow(db, mine.id, "b.example.test")
    answer = activate_engagement(mine.id, db, user=_owner(db))
    assert answer.status == "active" and answer.scope_overlap_notice is None
    row = db.scalars(select(AuditLog).where(AuditLog.engagement_id == mine.id, AuditLog.action == "engagement_activated")).one()
    assert "overlaps" not in row.payload


def test_negative_an_engagement_that_is_not_active_is_no_overlap(db, tokens_required):
    draft_only = _draft(db, _owner(db), "Still a draft")
    _allow(db, draft_only.id, "shared.example.test")
    mine = _draft(db, _owner(db), "Second")
    _allow(db, mine.id, "shared.example.test")
    assert activate_engagement(mine.id, db, user=_owner(db)).scope_overlap_notice is None


def test_adding_overlapping_active_scope_to_an_active_engagement_is_allowed_and_audited(db, tokens_required):
    _active(db, _owner(db), "First", "shared.example.test")
    mine_owner = _owner(db)
    mine = _active(db, mine_owner, "Second", "other.example.test")
    add_scope_asset(
        mine.id, ScopeAssetCreate(rule="allow", asset_type="domain", value="shared.example.test", active_allowed=True,
                                  authorization_verified=True),
        user=mine_owner, db=db,
    )
    assert db.scalars(select(AuditLog).where(AuditLog.engagement_id == mine.id, AuditLog.action == "scope_overlap_noted")).one()


# --- the refusal stays where the proxy does not require the token --------------------------------------------------

@pytest.mark.parametrize("first, second", [("shared.example.test", "shared.example.test"), ("example.test", "www.example.test")])
def test_negative_without_the_requirement_the_overlap_is_refused_exactly_as_before(db, first, second):
    assert get_settings().egress_require_token is False
    _active(db, _owner(db), "First", first)
    mine = _draft(db, _owner(db), "Second")
    _allow(db, mine.id, second)
    with pytest.raises(HTTPException) as caught:
        activate_engagement(mine.id, db, user=_owner(db))
    assert caught.value.status_code == 409 and "overlaps another currently active engagement" in caught.value.detail
    db.refresh(mine)
    assert mine.status == "draft"


def test_negative_without_the_requirement_adding_overlapping_scope_to_an_active_engagement_is_refused(db):
    _active(db, _owner(db), "First", "shared.example.test")
    owner = _owner(db)
    mine = _active(db, owner, "Second", "other.example.test")
    with pytest.raises(HTTPException) as caught:
        add_scope_asset(
            mine.id, ScopeAssetCreate(rule="allow", asset_type="domain", value="shared.example.test", active_allowed=True,
                                      authorization_verified=True),
            user=owner, db=db,
        )
    assert caught.value.status_code == 409
    assert not db.scalars(select(AuditLog).where(AuditLog.engagement_id == mine.id, AuditLog.action == "scope_overlap_noted")).all()


def test_the_setting_is_read_from_the_same_environment_variable_as_the_proxys():
    from app.config import Settings

    assert Settings(egress_require_token=True).egress_require_token is True
    assert Settings().egress_require_token is False
