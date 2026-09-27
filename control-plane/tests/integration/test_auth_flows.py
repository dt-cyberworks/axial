"""REQ-IAM-002..006: individual accounts, mandatory TOTP MFA, sessions,
brute-force protection. Exercises app.auth_service directly (same pattern as
the rest of this suite - see e.g. test_scan_run_control.py calling
app.api.internal functions directly)."""

from __future__ import annotations

import datetime as dt
import time

import pyotp
import pytest

from app import auth_service, passwords
from app.api.admin import create_user
from app.models.user import User, UserBackupCode
from app.schemas.auth import AdminCreateUserIn


class _Req:
    """Minimal stand-in for FastAPI's Request, only what admin.create_user's
    _client_info() reads."""
    def __init__(self):
        self.headers = {}
        self.client = None


def _invite(db, admin_user, email="new.operator@example.com") -> tuple[User, str]:
    out = create_user(AdminCreateUserIn(email=email, display_name="New Operator", role="operator"),
                      _Req(), actor=admin_user, db=db)
    user = db.get(User, out.user.id)
    return user, out.temporary_password


def _totp_code(user: User, db) -> str:
    db.refresh(user)
    from app import mfa
    secret = mfa.decrypt_secret(user.totp_secret_encrypted)
    return pyotp.TOTP(secret).now()


def test_full_first_login_flow(db, admin_user):
    user, temp_password = _invite(db, admin_user)

    # Step 1: password login with the temp password -> must change password.
    logged_in, status = auth_service.authenticate_password(db, user.email, temp_password, ip=None, user_agent=None)
    assert status == "set_password"
    challenge = auth_service.create_login_challenge(db, logged_in, status)

    # Step 2: set a real password.
    user = auth_service.set_first_password(db, challenge.id, "a-strong-real-password-123", ip=None, user_agent=None)
    assert user.must_change_password is False

    # Step 3: enroll MFA.
    next_challenge = auth_service.create_login_challenge(db, user, "mfa_enroll")
    user, raw_secret, uri = auth_service.begin_mfa_enrollment(db, next_challenge.id)
    assert uri.startswith("otpauth://")
    code = pyotp.TOTP(raw_secret).now()

    # Step 4: confirm enrollment -> session + backup codes.
    user, raw_token, backup_codes = auth_service.confirm_mfa_enrollment(
        db, next_challenge.id, code, ip="1.2.3.4", user_agent="pytest",
    )
    assert len(backup_codes) == 10
    assert user.totp_confirmed_at is not None
    assert user.status == "active"

    resolved = auth_service.resolve_session(db, raw_token)
    assert resolved is not None and resolved.id == user.id


def test_normal_login_after_enrollment(db, admin_user):
    user, temp_password = _invite(db, admin_user, email="already.enrolled@example.com")
    challenge = auth_service.create_login_challenge(db, user, "set_password")
    user = auth_service.set_first_password(db, challenge.id, "a-strong-real-password-123", ip=None, user_agent=None)
    enroll_challenge = auth_service.create_login_challenge(db, user, "mfa_enroll")
    user, raw_secret, _ = auth_service.begin_mfa_enrollment(db, enroll_challenge.id)
    auth_service.confirm_mfa_enrollment(db, enroll_challenge.id, pyotp.TOTP(raw_secret).now(), ip=None, user_agent=None)

    # Now log in normally. Enrollment just consumed the CURRENT 30s step's
    # code (anti-replay, REQ-IAM-003) - a real user's next login happens
    # later and naturally lands on a different step; simulate that here
    # instead of racing the same step in a tight test loop.
    user, status = auth_service.authenticate_password(db, user.email, "a-strong-real-password-123", ip=None, user_agent=None)
    assert status == "mfa_verify"
    login_challenge = auth_service.create_login_challenge(db, user, "mfa_verify")
    next_step_code = pyotp.TOTP(raw_secret).at(int(time.time()) + 30)
    logged_in_user, raw_token = auth_service.verify_mfa_login(db, login_challenge.id, next_step_code, ip=None, user_agent=None)
    assert auth_service.resolve_session(db, raw_token) is not None


def test_wrong_password_fails_generically(db, admin_user):
    user, _ = _invite(db, admin_user, email="wrongpw@example.com")
    with pytest.raises(auth_service.AuthError):
        auth_service.authenticate_password(db, user.email, "totally-wrong", ip=None, user_agent=None)


def test_unknown_email_fails_the_same_way_as_wrong_password(db):
    with pytest.raises(auth_service.AuthError):
        auth_service.authenticate_password(db, "nobody@example.com", "whatever", ip=None, user_agent=None)


def test_disabled_account_cannot_login(db, admin_user):
    user, temp_password = _invite(db, admin_user, email="disabled@example.com")
    user.status = "disabled"
    db.commit()
    with pytest.raises(auth_service.AuthError):
        auth_service.authenticate_password(db, user.email, temp_password, ip=None, user_agent=None)


def _enrolled_user(db, admin_user, email="enrolled2@example.com") -> tuple[User, str]:
    user, temp_password = _invite(db, admin_user, email=email)
    challenge = auth_service.create_login_challenge(db, user, "set_password")
    user = auth_service.set_first_password(db, challenge.id, "a-strong-real-password-123", ip=None, user_agent=None)
    enroll_challenge = auth_service.create_login_challenge(db, user, "mfa_enroll")
    user, raw_secret, _ = auth_service.begin_mfa_enrollment(db, enroll_challenge.id)
    auth_service.confirm_mfa_enrollment(db, enroll_challenge.id, pyotp.TOTP(raw_secret).now(), ip=None, user_agent=None)
    return user, "a-strong-real-password-123"


def test_login_with_backup_code_succeeds_and_is_single_use(db, admin_user):
    user, password = _enrolled_user(db, admin_user)
    # We don't have the raw code (only its hash) from the fixture path - mint
    # a fresh, known set to test against directly.
    raw_codes = passwords.generate_backup_codes(1)
    db.query(UserBackupCode).filter(UserBackupCode.user_id == user.id).delete()
    db.add(UserBackupCode(user_id=user.id, code_hash=passwords.hash_secret(raw_codes[0])))
    db.commit()

    user, status = auth_service.authenticate_password(db, user.email, password, ip=None, user_agent=None)
    challenge = auth_service.create_login_challenge(db, user, "mfa_verify")
    logged_in, raw_token = auth_service.verify_mfa_login(db, challenge.id, raw_codes[0], ip=None, user_agent=None)
    assert auth_service.resolve_session(db, raw_token) is not None

    # Second use of the same backup code must fail.
    challenge2 = auth_service.create_login_challenge(db, user, "mfa_verify")
    with pytest.raises(auth_service.AuthError):
        auth_service.verify_mfa_login(db, challenge2.id, raw_codes[0], ip=None, user_agent=None)


def test_wrong_mfa_code_repeated_kills_the_challenge(db, admin_user):
    user, password = _enrolled_user(db, admin_user, email="deadchallenge@example.com")
    user, status = auth_service.authenticate_password(db, user.email, password, ip=None, user_agent=None)
    challenge = auth_service.create_login_challenge(db, user, "mfa_verify")
    for _ in range(auth_service.MAX_CHALLENGE_ATTEMPTS):
        with pytest.raises(auth_service.AuthError):
            auth_service.verify_mfa_login(db, challenge.id, "000000", ip=None, user_agent=None)
    # Challenge is now dead even if a correct code is supplied.
    with pytest.raises(auth_service.AuthError):
        auth_service.verify_mfa_login(db, challenge.id, _totp_code(user, db), ip=None, user_agent=None)


def test_password_lockout_after_repeated_failures(db, admin_user):
    user, temp_password = _invite(db, admin_user, email="lockout@example.com")
    for _ in range(auth_service.LOCKOUT_THRESHOLD):
        with pytest.raises(auth_service.AuthError):
            auth_service.authenticate_password(db, user.email, "wrong", ip=None, user_agent=None)
    db.refresh(user)
    assert user.locked_until is not None and user.locked_until > dt.datetime.now(dt.timezone.utc)
    # Even the CORRECT password is rejected while locked.
    with pytest.raises(auth_service.AuthError):
        auth_service.authenticate_password(db, user.email, temp_password, ip=None, user_agent=None)


def test_successful_login_resets_failed_password_count(db, admin_user):
    user, temp_password = _invite(db, admin_user, email="resetcount@example.com")
    with pytest.raises(auth_service.AuthError):
        auth_service.authenticate_password(db, user.email, "wrong", ip=None, user_agent=None)
    db.refresh(user)
    assert user.failed_password_count == 1
    auth_service.authenticate_password(db, user.email, temp_password, ip=None, user_agent=None)
    db.refresh(user)
    assert user.failed_password_count == 0


def test_session_logout_revokes_it(db, admin_user):
    user, password = _enrolled_user(db, admin_user, email="logout@example.com")
    raw_token, session = auth_service.create_session(db, user, ip=None, user_agent=None)
    assert auth_service.resolve_session(db, raw_token) is not None
    auth_service.revoke_session_by_token(db, raw_token)
    assert auth_service.resolve_session(db, raw_token) is None


def test_expired_session_is_rejected(db, admin_user):
    user, _ = _enrolled_user(db, admin_user, email="expired@example.com")
    raw_token, session = auth_service.create_session(db, user, ip=None, user_agent=None)
    session.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
    db.commit()
    assert auth_service.resolve_session(db, raw_token) is None


def test_disabling_a_user_revokes_all_their_sessions(db, admin_user):
    user, _ = _enrolled_user(db, admin_user, email="willbedisabled@example.com")
    raw_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    assert auth_service.resolve_session(db, raw_token) is not None
    auth_service.revoke_all_sessions(db, user.id)
    assert auth_service.resolve_session(db, raw_token) is None


def test_mfa_reenrollment_requires_current_password(db, admin_user):
    user, password = _enrolled_user(db, admin_user, email="reenroll@example.com")
    with pytest.raises(auth_service.AuthError):
        auth_service.start_mfa_reenrollment(db, user, "wrong-password")


def test_mfa_reenrollment_replaces_secret_and_backup_codes(db, admin_user):
    user, password = _enrolled_user(db, admin_user, email="reenroll2@example.com")
    old_secret_enc = user.totp_secret_encrypted
    raw_secret, uri = auth_service.start_mfa_reenrollment(db, user, password)
    assert user.totp_secret_encrypted != old_secret_enc
    new_codes, _ = auth_service.confirm_mfa_reenrollment(db, user, pyotp.TOTP(raw_secret).now(), ip=None, user_agent=None)
    assert len(new_codes) == 10


def test_admin_reset_mfa_revokes_sessions_and_clears_enrollment(db, admin_user):
    user, _ = _enrolled_user(db, admin_user, email="adminreset@example.com")
    raw_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    auth_service.admin_reset_mfa(db, user, actor_user_id=admin_user.id, ip=None, user_agent=None)
    db.refresh(user)
    assert user.totp_confirmed_at is None
    assert user.totp_secret_encrypted is None
    assert auth_service.resolve_session(db, raw_token) is None
    assert db.query(UserBackupCode).filter(UserBackupCode.user_id == user.id).count() == 0


# --- GitHub issue #26: password change / MFA re-enrollment must evict any --
# other still-valid session (the standard response to "I think my account
# was compromised" must actually do something), while rotating - not just
# dropping - the CALLING session so that action doesn't also lock the user
# themselves out.

def test_change_password_rejects_wrong_current_password(db, admin_user):
    user, password = _enrolled_user(db, admin_user, email="changepw-wrong@example.com")
    with pytest.raises(auth_service.AuthError):
        auth_service.change_password(db, user, "not-the-real-password", "a-new-password-123456", ip=None, user_agent=None)
    # Nothing must have changed on a rejected attempt.
    db.refresh(user)
    assert passwords.verify_secret(password, user.password_hash)


def test_change_password_updates_the_hash(db, admin_user):
    user, password = _enrolled_user(db, admin_user, email="changepw-updates@example.com")
    auth_service.change_password(db, user, password, "a-brand-new-password-987654", ip=None, user_agent=None)
    db.refresh(user)
    assert passwords.verify_secret("a-brand-new-password-987654", user.password_hash)
    assert not passwords.verify_secret(password, user.password_hash)


def test_change_password_revokes_other_sessions(db, admin_user):
    user, password = _enrolled_user(db, admin_user, email="changepw-revokes@example.com")
    other_device_token, _ = auth_service.create_session(db, user, ip="9.9.9.9", user_agent="other-device")
    assert auth_service.resolve_session(db, other_device_token) is not None

    auth_service.change_password(db, user, password, "a-new-password-changepw-1", ip=None, user_agent=None)

    assert auth_service.resolve_session(db, other_device_token) is None


def test_change_password_rotates_the_calling_session_to_a_new_token(db, admin_user):
    user, password = _enrolled_user(db, admin_user, email="changepw-rotates@example.com")
    calling_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)

    new_token = auth_service.change_password(db, user, password, "a-new-password-changepw-2", ip=None, user_agent=None)

    assert new_token != calling_token
    # The OLD token used to make the call is dead too - not just other
    # devices' sessions - and the NEW one is a fully working replacement.
    assert auth_service.resolve_session(db, calling_token) is None
    resolved = auth_service.resolve_session(db, new_token)
    assert resolved is not None and resolved.id == user.id


def test_change_password_records_sessions_revoked_count_in_the_audit_log(db, admin_user):
    from sqlalchemy import select

    from app.models.user import AccountAuditLog

    user, password = _enrolled_user(db, admin_user, email="changepw-audit@example.com")
    auth_service.create_session(db, user, ip=None, user_agent=None)
    auth_service.create_session(db, user, ip=None, user_agent=None)

    auth_service.change_password(db, user, password, "a-new-password-changepw-3", ip="1.1.1.1", user_agent="pytest")

    entry = db.scalars(
        select(AccountAuditLog).where(
            AccountAuditLog.actor_user_id == user.id, AccountAuditLog.action == "password_change",
        ).order_by(AccountAuditLog.ts.desc())
    ).first()
    assert entry is not None
    assert entry.outcome == "success"
    # 3 pre-existing sessions were revoked: the 2 created explicitly above,
    # plus the one _enrolled_user's own confirm_mfa_enrollment already
    # created. The new post-rotation session did not exist yet when the
    # count was taken, so it must not be included.
    assert entry.payload.get("sessions_revoked") == 3


def test_mfa_reenrollment_confirm_revokes_other_sessions_and_rotates_the_caller(db, admin_user):
    user, password = _enrolled_user(db, admin_user, email="reenroll-revokes@example.com")
    other_device_token, _ = auth_service.create_session(db, user, ip="9.9.9.9", user_agent="other-device")
    calling_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)

    raw_secret, _ = auth_service.start_mfa_reenrollment(db, user, password)
    _, new_token = auth_service.confirm_mfa_reenrollment(db, user, pyotp.TOTP(raw_secret).now(), ip=None, user_agent=None)

    assert new_token != calling_token
    assert auth_service.resolve_session(db, other_device_token) is None
    assert auth_service.resolve_session(db, calling_token) is None
    resolved = auth_service.resolve_session(db, new_token)
    assert resolved is not None and resolved.id == user.id


# --- GitHub issue #23: auth state transitions under GENUINE concurrency ----
# (real threads, each its own DB session/transaction against the same
# Postgres, released via a barrier so they actually overlap - not a
# sequential simulation, which cannot reproduce a lost-update race at all.)

def _concurrent(engine, n, call):
    import threading

    from sqlalchemy.orm import sessionmaker

    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)
    barrier = threading.Barrier(n)
    results: list[tuple[bool, object]] = [None] * n  # type: ignore[list-item]

    def worker(index: int) -> None:
        session = SessionLocal()
        try:
            barrier.wait(timeout=10)
            try:
                results[index] = (True, call(session))
            except Exception as exc:  # noqa: BLE001 - captured, asserted below
                results[index] = (False, exc)
        finally:
            session.rollback()
            session.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return results


def test_concurrent_wrong_password_attempts_produce_exactly_n_increments(db, engine, admin_user):
    """GitHub issue #23: the old plain read-modify-write could lose
    increments under concurrency - N simultaneous wrong-password attempts
    must produce exactly N increments and a deterministic lockout, not
    fewer (which would silently weaken brute-force protection)."""
    user, _ = _invite(db, admin_user, email="concurrent-lockout@example.com")
    email = user.email
    n = 6  # < LOCKOUT_THRESHOLD, so every attempt is a plain failed count, not a lockout short-circuit

    def attempt(session):
        with pytest.raises(auth_service.AuthError):
            auth_service.authenticate_password(session, email, "wrong", ip=None, user_agent=None)
        return True

    results = _concurrent(engine, n, attempt)
    assert all(ok for ok, _ in results), results

    db.refresh(user)
    assert user.failed_password_count == n, f"expected exactly {n} increments, got {user.failed_password_count}"


def test_concurrent_same_backup_code_yields_exactly_one_session_and_rejections(db, admin_user, engine):
    user, password = _enrolled_user(db, admin_user, email="concurrent-backup@example.com")
    raw_codes = passwords.generate_backup_codes(1)
    db.query(UserBackupCode).filter(UserBackupCode.user_id == user.id).delete()
    db.add(UserBackupCode(user_id=user.id, code_hash=passwords.hash_secret(raw_codes[0])))
    db.commit()

    user_id, code = user.id, raw_codes[0]
    n = 4

    def attempt(session):
        from app.models.user import User as UserModel
        u = session.get(UserModel, user_id)
        challenge = auth_service.create_login_challenge(session, u, "mfa_verify")
        _, raw_token = auth_service.verify_mfa_login(session, challenge.id, code, ip=None, user_agent=None)
        return raw_token

    results = _concurrent(engine, n, attempt)
    successes = [r for ok, r in results if ok]
    failures = [r for ok, r in results if not ok]
    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(failures) == n - 1
    assert all(isinstance(exc, auth_service.AuthError) for exc in failures)

    assert auth_service.resolve_session(db, successes[0]) is not None
    remaining_unused = db.query(UserBackupCode).filter(
        UserBackupCode.user_id == user_id, UserBackupCode.used_at.is_(None),
    ).count()
    assert remaining_unused == 0


def test_concurrent_same_totp_code_yields_exactly_one_session_and_rejections(db, admin_user, engine):
    user, password = _enrolled_user(db, admin_user, email="concurrent-totp@example.com")
    db.refresh(user)
    from app import mfa
    secret = mfa.decrypt_secret(user.totp_secret_encrypted)
    # Land on a step this user has not consumed yet (enrollment already
    # consumed the current one) so every thread races the SAME fresh step.
    code = pyotp.TOTP(secret).at(int(time.time()) + 30)
    user_id = user.id
    n = 4

    def attempt(session):
        from app.models.user import User as UserModel
        u = session.get(UserModel, user_id)
        challenge = auth_service.create_login_challenge(session, u, "mfa_verify")
        _, raw_token = auth_service.verify_mfa_login(session, challenge.id, code, ip=None, user_agent=None)
        return raw_token

    results = _concurrent(engine, n, attempt)
    successes = [r for ok, r in results if ok]
    failures = [r for ok, r in results if not ok]
    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(failures) == n - 1
    assert all(isinstance(exc, auth_service.AuthError) for exc in failures)
    assert auth_service.resolve_session(db, successes[0]) is not None
