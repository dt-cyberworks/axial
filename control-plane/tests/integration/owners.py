"""Every engagement has an owner (REQ-IAM-021, migration 0038), also in tests that
build one straight through the ORM. `make_owner` is the one-line way to get a real
user to put in `owner_user_id`."""

from __future__ import annotations

import uuid

from app.models.user import User
from app.passwords import hash_secret


def make_owner(db, *, role: str = "operator") -> User:
    user = User(
        email=f"owner-{uuid.uuid4().hex[:12]}@example.com", display_name="Test Owner",
        role=role, status="active", must_change_password=False,
        password_hash=hash_secret("irrelevant-not-used"),
    )
    db.add(user)
    db.commit()
    return user
