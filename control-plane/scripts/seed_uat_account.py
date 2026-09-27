#!/usr/bin/env python3
"""One-shot UAT service-account seeding (REQ-UAT-001).

Mirrors `scripts/bootstrap_admin.py`'s pattern exactly: a direct DB insert,
not an HTTP endpoint - there is no "create the UAT account" API for the same
reason there is no "first user becomes admin" one. Run once, inside the
control-plane container/image, after the auth migration has been applied:

    docker compose exec control-plane python scripts/seed_uat_account.py

Reads UAT_ACCOUNT_EMAIL (required) and UAT_ACCOUNT_DISPLAY_NAME (optional)
from the environment. Prints the one-time temporary password to stdout
exactly once - feed it into `uat/bootstrap_credentials.py` (run outside the
container, against the real HTTP API) to complete first-login/MFA
enrollment. Safe to re-run: if that email already has an account, it does
nothing and exits 0.

The account is created with the `operator` role, never `admin` - see
REQ-UAT-001's least-privilege requirement.
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
    email = os.environ.get("UAT_ACCOUNT_EMAIL", "").strip().lower()
    if not email:
        print("UAT_ACCOUNT_EMAIL is not set - nothing to do.", file=sys.stderr)
        return 1
    display_name = os.environ.get("UAT_ACCOUNT_DISPLAY_NAME", "UAT Service Account").strip() or "UAT Service Account"

    db = SessionLocal()
    try:
        existing = db.scalar(select(User).where(User.email == email))
        if existing is not None:
            print(f"an account for {email} already exists (id={existing.id}) - nothing to do.")
            return 0

        temp_password = passwords.generate_temp_password()
        user = User(
            email=email, display_name=display_name, role="operator", status="invited",
            must_change_password=True, password_hash=passwords.hash_secret(temp_password),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        print("UAT service account created.")
        print(f"  email:             {email}")
        print(f"  temporary password: {temp_password}")
        print("Feed this into 'python uat/bootstrap_credentials.py --env <env>' (outside the")
        print("container) to complete first-login and MFA enrollment. It will not be shown")
        print("again; use POST /admin/users/{id}/reset-password later if it's lost first.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
