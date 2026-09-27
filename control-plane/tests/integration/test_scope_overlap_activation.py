"""REQ-CONCUR-003: activating an engagement (or adding active-mode allow scope
to an already-active one) is refused if its allow-scope overlaps another
currently active engagement's allow-scope - any owner. This catches the
conflict at the source instead of as a confusing ambiguous_host scan failure
well into a run. It is a creation/activation-time check only: the
egress-proxy's own fail-closed runtime resolution remains the actual
enforcement boundary."""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi import HTTPException

from app.api.engagements import activate_engagement, add_scope_asset, create_engagement
from app.models.engagement import ScopeAsset
from app.models.user import User
from app.passwords import hash_secret
from app.schemas.engagement import EngagementCreate, ScopeAssetCreate


def _owner(db) -> User:
    user = User(
        email=f"owner-{dt.datetime.now(dt.timezone.utc).timestamp()}@example.com",
        display_name="Test Owner", role="operator", status="active",
        must_change_password=False, password_hash=hash_secret("irrelevant-not-used"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _draft_engagement(db, owner, *, title: str):
    now = dt.datetime.now(dt.timezone.utc)
    return create_engagement(
        EngagementCreate(
            title=title, source="own_domain",
            authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
        ),
        user=owner, db=db,
    )


def _add_allow(db, engagement_id, *, asset_type="domain", value):
    db.add(ScopeAsset(
        engagement_id=engagement_id, rule="allow", asset_type=asset_type, value=value,
        active_allowed=True, authorization_verified=True,
    ))
    db.commit()


def test_activation_succeeds_with_no_overlap(db):
    a = _draft_engagement(db, _owner(db), title="A")
    _add_allow(db, a.id, value="a.example.test")
    activated_a = activate_engagement(a.id, db, user=_owner(db))
    assert activated_a.status == "active"

    b = _draft_engagement(db, _owner(db), title="B")
    _add_allow(db, b.id, value="b.example.test")
    activated_b = activate_engagement(b.id, db, user=_owner(db))
    assert activated_b.status == "active"


def test_activation_is_rejected_on_exact_domain_overlap_with_another_active_engagement(db):
    a = _draft_engagement(db, _owner(db), title="A")
    _add_allow(db, a.id, value="shared.example.test")
    activate_engagement(a.id, db, user=_owner(db))

    b = _draft_engagement(db, _owner(db), title="B")
    _add_allow(db, b.id, value="shared.example.test")
    with pytest.raises(HTTPException) as exc:
        activate_engagement(b.id, db, user=_owner(db))
    assert exc.value.status_code == 409
    db.refresh(b)
    assert b.status == "draft"


def test_activation_detects_subdomain_overlap(db):
    a = _draft_engagement(db, _owner(db), title="A")
    _add_allow(db, a.id, value="example.test")
    activate_engagement(a.id, db, user=_owner(db))

    b = _draft_engagement(db, _owner(db), title="B")
    _add_allow(db, b.id, value="sub.example.test")
    with pytest.raises(HTTPException) as exc:
        activate_engagement(b.id, db, user=_owner(db))
    assert exc.value.status_code == 409


def test_activation_detects_cidr_overlap(db):
    a = _draft_engagement(db, _owner(db), title="A")
    _add_allow(db, a.id, asset_type="cidr", value="203.0.113.0/28")
    activate_engagement(a.id, db, user=_owner(db))

    b = _draft_engagement(db, _owner(db), title="B")
    _add_allow(db, b.id, asset_type="cidr", value="203.0.113.8/30")
    with pytest.raises(HTTPException) as exc:
        activate_engagement(b.id, db, user=_owner(db))
    assert exc.value.status_code == 409


def test_activation_ignores_overlap_with_a_non_active_engagement(db):
    a = _draft_engagement(db, _owner(db), title="A")
    _add_allow(db, a.id, value="shared2.example.test")
    # A is left in draft - never activated.

    b = _draft_engagement(db, _owner(db), title="B")
    _add_allow(db, b.id, value="shared2.example.test")
    activated_b = activate_engagement(b.id, db, user=_owner(db))
    assert activated_b.status == "active"


def test_add_active_allow_scope_asset_to_active_engagement_rejects_overlap(db):
    a = _draft_engagement(db, _owner(db), title="A")
    _add_allow(db, a.id, value="shared3.example.test")
    activate_engagement(a.id, db, user=_owner(db))

    b = _draft_engagement(db, _owner(db), title="B")
    _add_allow(db, b.id, value="b-only.example.test")
    activate_engagement(b.id, db, user=_owner(db))

    owner_b = _owner(db)
    with pytest.raises(HTTPException) as exc:
        add_scope_asset(
            b.id, ScopeAssetCreate(rule="allow", asset_type="domain", value="shared3.example.test",
                                    active_allowed=True, authorization_verified=True),
            db, user=owner_b,
        )
    assert exc.value.status_code == 409
    assert db.query(ScopeAsset).filter(
        ScopeAsset.engagement_id == b.id, ScopeAsset.value == "shared3.example.test",
    ).count() == 0


def test_add_passive_allow_scope_asset_to_active_engagement_is_not_checked(db):
    """Only ACTIVE-mode allow scope triggers the overlap check (REQ-CONCUR-003
    text) - a passive-only allow addition never executes active checks, so it
    cannot itself create ambiguous_host at scan time."""
    a = _draft_engagement(db, _owner(db), title="A")
    _add_allow(db, a.id, value="shared4.example.test")
    activate_engagement(a.id, db, user=_owner(db))

    b = _draft_engagement(db, _owner(db), title="B")
    _add_allow(db, b.id, value="b-only-2.example.test")
    activate_engagement(b.id, db, user=_owner(db))

    owner_b = _owner(db)
    created = add_scope_asset(
        b.id, ScopeAssetCreate(rule="allow", asset_type="domain", value="shared4.example.test",
                                active_allowed=False, authorization_verified=False),
        db, user=owner_b,
    )
    assert created.value == "shared4.example.test"
