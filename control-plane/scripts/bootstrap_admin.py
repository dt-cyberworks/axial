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
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select  # noqa: E402

from app import passwords  # noqa: E402
from app.db.base import SessionLocal  # noqa: E402
from app.models.user import User  # noqa: E402


def main() -> int:
    email = os.environ.get("INITIAL_ADMIN_EMAIL", "").strip().lower()
    if not email:
        print("INITIAL_ADMIN_EMAIL is not set - nothing to do.", file=sys.stderr)
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
