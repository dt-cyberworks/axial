#!/usr/bin/env python3
"""One-shot first-admin bootstrap (REQ-IAM-008/011).

Deliberately NOT an HTTP endpoint - there is no "first user becomes admin"
implicit rule reachable at runtime. Run once, inside the control-plane
container/image, after the auth migration has been applied:

    docker compose exec control-plane python scripts/bootstrap_admin.py

Reads INITIAL_ADMIN_EMAIL (required) and INITIAL_ADMIN_DISPLAY_NAME
(optional) from the environment. Prints the one-time temporary password to
stdout exactly once - it is never stored or logged anywhere else. Safe to
re-run: if that email already has an account, it does nothing and exits 0.

REQ-INSTALL-005: the address is checked with the SAME validator the sign-in
endpoint uses (pydantic's EmailStr). An address the sign-in form would reject -
a reserved name such as `.test`, `.local`, `.localhost`, or no domain at all -
used to create an administrator who could never log in; now it exits 1 before
anything is created.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pydantic import EmailStr, TypeAdapter, ValidationError  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app import passwords  # noqa: E402
from app.db.base import SessionLocal  # noqa: E402
from app.models.user import User  # noqa: E402

_LOGIN_EMAIL = TypeAdapter(EmailStr)


def check_login_email(email: str) -> str | None:
    """None when the sign-in endpoint would accept this address, else the reason."""
    try:
        _LOGIN_EMAIL.validate_python(email)
    except ValidationError as exc:
        return str(exc.errors()[0].get("msg", "not a valid email address")).removeprefix("value is not a valid email address: ")
    return None


def main() -> int:
    email = os.environ.get("INITIAL_ADMIN_EMAIL", "").strip().lower()
    if not email:
        print("INITIAL_ADMIN_EMAIL is not set - nothing to do.", file=sys.stderr)
        return 1
    problem = check_login_email(email)
    if problem is not None:
        print(f"INITIAL_ADMIN_EMAIL {email!r} cannot be used: {problem}", file=sys.stderr)
        print("The sign-in form would reject this address, so the administrator could never log in.", file=sys.stderr)
        print("Use a real address, for example INITIAL_ADMIN_EMAIL=you@example.com", file=sys.stderr)
        return 1
    display_name = os.environ.get("INITIAL_ADMIN_DISPLAY_NAME", "Admin").strip() or "Admin"

    db = SessionLocal()
    try:
        existing = db.scalar(select(User).where(User.email == email))
        if existing is not None:
            print(f"an account for {email} already exists (id={existing.id}) - nothing to do.")
            return 0

        temp_password = passwords.generate_temp_password()
        user = User(
            email=email, display_name=display_name, role="admin", status="invited",
            must_change_password=True, password_hash=passwords.hash_secret(temp_password),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        print("Bootstrap admin account created.")
        print(f"  email:             {email}")
        print(f"  temporary password: {temp_password}")
        print("Relay this password to the admin out-of-band. It will not be shown again;")
        print("use POST /admin/users/{id}/reset-password later if it's lost before first login.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
