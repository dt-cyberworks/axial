"""REQ-CONCUR-005: an admin must never be able to demote or disable the last
remaining active admin account through the application - that would leave no
one able to manage users without server access to re-run bootstrap_admin.py."""

from __future__ import annotations

from fastapi import HTTPException
import pytest

from app.api.admin import create_user, update_user
from app.models.user import User
from app.schemas.auth import AdminCreateUserIn, AdminUpdateUserIn


class _Req:
    def __init__(self):
        self.headers = {}
        self.client = None


def test_disabling_the_sole_active_admin_is_rejected(db, admin_user):
    with pytest.raises(HTTPException) as exc:
        update_user(admin_user.id, AdminUpdateUserIn(status="disabled"), _Req(), actor=admin_user, db=db)
    assert exc.value.status_code == 409
    db.refresh(admin_user)
    assert admin_user.status == "active"


def test_demoting_the_sole_active_admin_is_rejected(db, admin_user):
    with pytest.raises(HTTPException) as exc:
        update_user(admin_user.id, AdminUpdateUserIn(role="operator"), _Req(), actor=admin_user, db=db)
    assert exc.value.status_code == 409
    db.refresh(admin_user)
    assert admin_user.role == "admin"


def test_demoting_an_admin_is_allowed_when_another_active_admin_remains(db, admin_user):
    out = create_user(AdminCreateUserIn(email="second-admin@example.com", display_name="B", role="admin"), _Req(), actor=admin_user, db=db)
    second = db.get(User, out.user.id)
    second.status = "active"
    db.commit()

    updated = update_user(admin_user.id, AdminUpdateUserIn(role="operator"), _Req(), actor=admin_user, db=db)
    assert updated.role == "operator"


def test_disabling_an_admin_is_allowed_when_another_active_admin_remains(db, admin_user):
    out = create_user(AdminCreateUserIn(email="second-admin-2@example.com", display_name="B", role="admin"), _Req(), actor=admin_user, db=db)
    second = db.get(User, out.user.id)
    second.status = "active"
    db.commit()

    updated = update_user(admin_user.id, AdminUpdateUserIn(status="disabled"), _Req(), actor=admin_user, db=db)
    assert updated.status == "disabled"


def test_guard_does_not_block_unrelated_changes_to_the_sole_admin(db, admin_user):
    # Promoting/keeping the sole admin as admin+active (a no-op-ish update) must
    # never be blocked by the last-admin guard.
    updated = update_user(admin_user.id, AdminUpdateUserIn(role="admin", status="active"), _Req(), actor=admin_user, db=db)
    assert updated.role == "admin"
    assert updated.status == "active"


def test_guard_does_not_block_changes_to_a_non_admin_user(db, admin_user):
    out = create_user(AdminCreateUserIn(email="operator-only@example.com", display_name="C", role="operator"), _Req(), actor=admin_user, db=db)
    updated = update_user(out.user.id, AdminUpdateUserIn(status="disabled"), _Req(), actor=admin_user, db=db)
    assert updated.status == "disabled"


def test_concurrent_demotion_of_the_last_two_admins_leaves_exactly_one(db, engine, admin_user):
    """GitHub issue #24: with exactly two active admins A and B, concurrent
    requests demoting A and demoting B could each count the OTHER as proof an
    admin remains (READ COMMITTED - neither sees the other's uncommitted
    write) and both succeed, leaving zero active admins. Genuine concurrency
    (real threads, each its own DB session/transaction, released via a
    barrier so they overlap) - not a sequential simulation."""
    import threading

    from sqlalchemy.orm import sessionmaker

    from app.models.user import User as UserModel

    out = create_user(AdminCreateUserIn(email="second-admin-concurrent@example.com", display_name="B", role="admin"), _Req(), actor=admin_user, db=db)
    second_id = out.user.id
    second = db.get(User, second_id)
    second.status = "active"
    db.commit()

    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)
    barrier = threading.Barrier(2)
    results: list[tuple[bool, object]] = [None, None]  # type: ignore[list-item]

    def demote(index: int, target_id, session) -> None:
        try:
            barrier.wait(timeout=10)
            try:
                actor = session.get(UserModel, admin_user.id)
                value = update_user(target_id, AdminUpdateUserIn(role="operator"), _Req(), actor=actor, db=session)
                results[index] = (True, value.role)
            except Exception as exc:  # noqa: BLE001
                results[index] = (False, exc)
        finally:
            session.rollback()
            session.close()

    session_a, session_b = SessionLocal(), SessionLocal()
    t_a = threading.Thread(target=demote, args=(0, admin_user.id, session_a))
    t_b = threading.Thread(target=demote, args=(1, second_id, session_b))
    t_a.start(); t_b.start()
    t_a.join(timeout=30); t_b.join(timeout=30)

    successes = [r for ok, r in results if ok]
    failures = [(ok, r) for ok, r in results if not ok]
    assert len(successes) == 1, f"expected exactly one demotion to succeed, got: {results}"
    assert len(failures) == 1
    assert isinstance(failures[0][1], HTTPException) and failures[0][1].status_code == 409

    remaining_admins = db.query(User).filter(User.role == "admin", User.status == "active").count()
    assert remaining_admins == 1, f"expected exactly one active admin left, got {remaining_admins}"


def test_guard_does_not_block_an_invited_not_yet_active_admin_being_disabled(db, admin_user):
    # A newly-invited admin (status="invited") is not yet an active admin, so
    # disabling them never touches the "last active admin" invariant.
    out = create_user(AdminCreateUserIn(email="invited-admin@example.com", display_name="D", role="admin"), _Req(), actor=admin_user, db=db)
    assert db.get(User, out.user.id).status == "invited"
    updated = update_user(out.user.id, AdminUpdateUserIn(status="disabled"), _Req(), actor=admin_user, db=db)
    assert updated.status == "disabled"
