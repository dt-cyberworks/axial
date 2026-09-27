"""REQ-IAM-008: admin-only user management, invite-only provisioning. These
call app.api.admin functions directly (dependencies=[Depends(require_admin)]
lives at the router level in app/api/__init__.py, not in the handler body -
see tests/integration/test_engagement_ownership_http.py for the HTTP-level
enforcement proof via TestClient)."""

from __future__ import annotations

from fastapi import HTTPException
import pytest

from app import auth_service
from app.api.admin import create_user, list_users, reset_mfa, reset_password, update_user
from app.models.user import User, UserSession
from app.schemas.auth import AdminCreateUserIn, AdminUpdateUserIn


class _Req:
    def __init__(self):
        self.headers = {}
        self.client = None


def test_admin_creates_invited_user(db, admin_user):
    out = create_user(AdminCreateUserIn(email="invitee@example.com", display_name="Invitee", role="operator"),
                      _Req(), actor=admin_user, db=db)
    assert out.user.status == "invited"
    assert out.user.role == "operator"
    assert len(out.temporary_password) >= 16
    stored = db.get(User, out.user.id)
    assert stored.must_change_password is True
    assert stored.created_by_user_id == admin_user.id


def test_duplicate_email_is_rejected(db, admin_user):
    create_user(AdminCreateUserIn(email="dupe@example.com", display_name="A", role="operator"), _Req(), actor=admin_user, db=db)
    with pytest.raises(HTTPException) as exc:
        create_user(AdminCreateUserIn(email="dupe@example.com", display_name="B", role="operator"), _Req(), actor=admin_user, db=db)
    assert exc.value.status_code == 409


def test_invalid_role_is_rejected(db, admin_user):
    with pytest.raises(HTTPException) as exc:
        create_user(AdminCreateUserIn(email="badrole@example.com", display_name="A", role="superuser"), _Req(), actor=admin_user, db=db)
    assert exc.value.status_code == 422


def test_list_users_includes_created_accounts(db, admin_user):
    create_user(AdminCreateUserIn(email="listed@example.com", display_name="Listed", role="operator"), _Req(), actor=admin_user, db=db)
    users = list_users(db)
    assert any(u.email == "listed@example.com" for u in users)


def test_update_user_role_and_status(db, admin_user):
    out = create_user(AdminCreateUserIn(email="promote@example.com", display_name="A", role="operator"), _Req(), actor=admin_user, db=db)
    updated = update_user(out.user.id, AdminUpdateUserIn(role="admin"), _Req(), actor=admin_user, db=db)
    assert updated.role == "admin"

    disabled = update_user(out.user.id, AdminUpdateUserIn(status="disabled"), _Req(), actor=admin_user, db=db)
    assert disabled.status == "disabled"


def test_disabling_a_user_revokes_their_sessions(db, admin_user):
    out = create_user(AdminCreateUserIn(email="tobedisabled@example.com", display_name="A", role="operator"), _Req(), actor=admin_user, db=db)
    target = db.get(User, out.user.id)
    raw_token, _ = auth_service.create_session(db, target, ip=None, user_agent=None)
    assert auth_service.resolve_session(db, raw_token) is not None

    update_user(out.user.id, AdminUpdateUserIn(status="disabled"), _Req(), actor=admin_user, db=db)

    assert auth_service.resolve_session(db, raw_token) is None


def test_update_unknown_user_404s(db, admin_user):
    import uuid
    with pytest.raises(HTTPException) as exc:
        update_user(uuid.uuid4(), AdminUpdateUserIn(role="admin"), _Req(), actor=admin_user, db=db)
    assert exc.value.status_code == 404


def test_admin_reset_password_forces_change_and_revokes_sessions(db, admin_user):
    out = create_user(AdminCreateUserIn(email="resetme@example.com", display_name="A", role="operator"), _Req(), actor=admin_user, db=db)
    target = db.get(User, out.user.id)
    raw_token, _ = auth_service.create_session(db, target, ip=None, user_agent=None)

    result = reset_password(out.user.id, _Req(), actor=admin_user, db=db)

    db.refresh(target)
    assert target.must_change_password is True
    assert len(result.temporary_password) >= 16
    assert auth_service.resolve_session(db, raw_token) is None


def test_admin_reset_mfa(db, admin_user):
    out = create_user(AdminCreateUserIn(email="mfareset@example.com", display_name="A", role="operator"), _Req(), actor=admin_user, db=db)
    target = db.get(User, out.user.id)
    target.totp_secret_encrypted = b"placeholder"
    import datetime as dt
    target.totp_confirmed_at = dt.datetime.now(dt.timezone.utc)
    db.commit()

    reset_mfa(out.user.id, _Req(), actor=admin_user, db=db)

    db.refresh(target)
    assert target.totp_secret_encrypted is None
    assert target.totp_confirmed_at is None
