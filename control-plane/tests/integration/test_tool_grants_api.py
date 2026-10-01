"""GitHub issue #16: EngagementDetail.tsx needs to show which tool
categories are already granted for a draft engagement (so a page that
resumes an engagement outside the one-time creation wizard does not have
to assume a blank slate). This exercises the new read path
(list_tool_grants) alongside the existing write path (add_tool_grant) that
the wizard already used."""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi import HTTPException

from app.api.engagements import add_tool_grant, create_engagement, list_tool_grants
from app.models.user import User
from app.passwords import hash_secret
from app.schemas.engagement import EngagementCreate, ToolGrantCreate


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


def _draft_engagement(db, owner, *, title="Draft"):
    now = dt.datetime.now(dt.timezone.utc)
    return create_engagement(
        EngagementCreate(
            title=title, source="own_domain",
            authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
        ),
        user=owner, db=db,
    )


def test_list_tool_grants_is_empty_for_a_fresh_draft(db):
    eng = _draft_engagement(db, _owner(db))
    assert list_tool_grants(eng.id, db) == []


def test_list_tool_grants_reflects_a_passive_grant(db):
    owner = _owner(db)
    eng = _draft_engagement(db, owner)
    add_tool_grant(eng.id, ToolGrantCreate(tool_category="recon", mode="passive", requires_manual_approval=False), db, user=owner)

    grants = list_tool_grants(eng.id, db)
    assert len(grants) == 1
    assert grants[0].tool_category == "recon"
    assert grants[0].mode == "passive"
    assert grants[0].manual_tools == []


def test_list_tool_grants_reflects_active_grant_with_manual_tools_scoped_to_its_own_category(db):
    owner = _owner(db)
    eng = _draft_engagement(db, owner)
    add_tool_grant(eng.id, ToolGrantCreate(
        tool_category="fingerprint", mode="active", requires_manual_approval=False, manual_tools=["nmap"],
    ), db, user=owner)
    # A second category's active grant, with no manual tools of its own -
    # its manual_tools list must not pick up "nmap" from the other category.
    add_tool_grant(eng.id, ToolGrantCreate(
        tool_category="recon", mode="active", requires_manual_approval=False, manual_tools=[],
    ), db, user=owner)

    grants = {(g.tool_category, g.mode): g for g in list_tool_grants(eng.id, db)}
    assert grants[("fingerprint", "active")].manual_tools == ["nmap"]
    assert grants[("recon", "active")].manual_tools == []


def test_list_tool_grants_reflects_an_upsert_not_a_duplicate(db):
    owner = _owner(db)
    eng = _draft_engagement(db, owner)
    add_tool_grant(eng.id, ToolGrantCreate(
        tool_category="fingerprint", mode="active", requires_manual_approval=False, manual_tools=["nmap"],
    ), db, user=owner)
    # Resubmitting the same category+mode (as the GUI does on every "Save
    # tool grants" click) must replace, not duplicate, the manual-tool set.
    add_tool_grant(eng.id, ToolGrantCreate(
        tool_category="fingerprint", mode="active", requires_manual_approval=False, manual_tools=["httpx"],
    ), db, user=owner)

    grants = list_tool_grants(eng.id, db)
    assert len(grants) == 1
    assert grants[0].manual_tools == ["httpx"]


def test_list_tool_grants_404s_for_an_unknown_engagement(db):
    import uuid
    with pytest.raises(HTTPException) as exc:
        list_tool_grants(uuid.uuid4(), db)
    assert exc.value.status_code == 404
