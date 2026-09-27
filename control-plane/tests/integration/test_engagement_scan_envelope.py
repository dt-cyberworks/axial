import datetime as dt

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.engagements import create_engagement, update_engagement
from app.models.user import User
from app.passwords import hash_secret
from app.schemas.engagement import EngagementCreate, EngagementUpdate

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

def _body(**overrides):
    now = dt.datetime.now(dt.timezone.utc)
    values = {
        "title": "Narrow scan", "source": "own_domain",
        "authorized_from": now, "authorized_until": now + dt.timedelta(days=1),
        "tcp_port_from": 443, "tcp_port_to": 443,
        "udp_discovery_enabled": False,
    }
    values.update(overrides)
    return EngagementCreate(**values)

def test_create_persists_single_tcp_port_and_udp_default(db):
    engagement = create_engagement(_body(), user=_owner(db), db=db)
    assert engagement.tcp_port_from == 443
    assert engagement.tcp_port_to == 443
    assert engagement.udp_discovery_enabled is False

def test_create_rejects_invalid_or_reversed_port_range():
    with pytest.raises(ValidationError):
        _body(tcp_port_from=8443, tcp_port_to=443)
    with pytest.raises(ValidationError):
        _body(tcp_port_from=0)
    with pytest.raises(ValidationError):
        _body(tcp_port_to=65536)

def test_scan_envelope_can_change_only_while_draft(db):
    owner = _owner(db)
    engagement = create_engagement(_body(), user=owner, db=db)
    updated = update_engagement(
        engagement.id, EngagementUpdate(tcp_port_from=80, tcp_port_to=443, udp_discovery_enabled=True), db,
        user=owner,
    )
    assert (updated.tcp_port_from, updated.tcp_port_to) == (80, 443)
    assert updated.udp_discovery_enabled is True
    updated.status = "active"
    db.commit()
    with pytest.raises(HTTPException) as exc:
        update_engagement(updated.id, EngagementUpdate(tcp_port_from=1), db, user=owner)
    assert exc.value.status_code == 409
