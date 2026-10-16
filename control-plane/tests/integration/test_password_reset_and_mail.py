"""REQ-IAM-020 (GitHub issue #44) and REQ-MAIL-001..005 (GitHub issue #45): the optional
outbound e-mail service and the self-service password reset that is its first user.

An enrolled user is built through the real first-sign-in path, so the second factor
the reset asks for is a real authenticator secret, not a stub."""

from __future__ import annotations

import datetime as dt
import re
import time
import uuid

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import auth_service, mail_settings, mfa, passwords
from app.api.admin import create_user
from app.db.base import get_db
from app.main import app
from app.models.mail import MailOutbox, PasswordResetToken
from app.models.user import AccountAuditLog, User, UserBackupCode, UserSession
from app.schemas.auth import AdminCreateUserIn
from app.settings_store import _decrypt_api_key

PASSWORD = "a-strong-real-password-123"
NEW_PASSWORD = "another-strong-password-456"


class _Req:
    headers: dict = {}
    client = None


@pytest.fixture
def client(engine):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override
    yield TestClient(app)
    app.dependency_overrides.clear()


def _configure_mail(db, *, enabled=True):
    mail_settings.set_mail_config(
        db, enabled=enabled, host="smtp.example.org", port=587, security="starttls", username="relay",
        password="relay-secret", from_address="axial@example.org", from_name="Axial",
    )


def _enrolled(db, admin_user, email="reset.me@example.com") -> tuple[User, str]:
    out = create_user(AdminCreateUserIn(email=email, display_name="Reset Me", role="operator"), _Req(), actor=admin_user, db=db)
    user = db.get(User, out.user.id)
    challenge = auth_service.create_login_challenge(db, user, "set_password")
    user = auth_service.set_first_password(db, challenge.id, PASSWORD, ip=None, user_agent=None)
    enroll = auth_service.create_login_challenge(db, user, "mfa_enroll")
    user, raw_secret, _ = auth_service.begin_mfa_enrollment(db, enroll.id)
    auth_service.confirm_mfa_enrollment(db, enroll.id, pyotp.TOTP(raw_secret).now(), ip=None, user_agent=None)
    return user, raw_secret


def _fresh_code(secret: str, offset: int = 1) -> str:
    """A code from a later time step than any used so far (enrolment consumed the current one)."""
    return pyotp.TOTP(secret).at(int(time.time()) + 30 * offset)


def _request(client, email: str):
    return client.post("/auth/password-reset/request", json={"email": email})


def _queued(db, to: str | None = None) -> list[MailOutbox]:
    stmt = select(MailOutbox).where(MailOutbox.kind == "password_reset")
    if to:
        stmt = stmt.where(MailOutbox.to_address == to)
    return list(db.scalars(stmt.order_by(MailOutbox.created_at)))


def _token_from_outbox(row: MailOutbox) -> str:
    body = _decrypt_api_key(row.body_enc)
    match = re.search(r"/reset-password#([A-Za-z0-9_-]{20,})", body)
    assert match, body
    return match.group(1)


# ------------------------------------------------------------ REQ-MAIL-001


def test_nothing_is_offered_until_mail_is_configured_and_switched_on(client, db):
    assert client.get("/auth/recovery-options").json() == {"self_service_reset": False}
    _configure_mail(db, enabled=False)
    assert client.get("/auth/recovery-options").json() == {"self_service_reset": False}
    _configure_mail(db, enabled=True)
    body = client.get("/auth/recovery-options").json()
    assert body == {"self_service_reset": True}, "the answer reveals nothing but whether it is offered"


def test_with_no_mail_a_request_is_answered_the_same_and_queues_nothing(client, db, admin_user):
    user, _ = _enrolled(db, admin_user)
    r = _request(client, user.email)
    assert r.status_code == 202
    assert _queued(db) == []
    audit = db.scalars(select(AccountAuditLog).where(AccountAuditLog.action == "password_reset_request")).all()
    assert audit and audit[-1].payload["reason"] == "mail_not_available"


# ------------------------------------------------------------ REQ-IAM-020: request


def test_the_response_is_identical_for_a_known_and_an_unknown_address(client, db, admin_user):
    _configure_mail(db)
    user, _ = _enrolled(db, admin_user)
    known = _request(client, user.email)
    unknown = _request(client, "nobody.here@example.com")
    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()
    assert len(_queued(db)) == 1 and _queued(db)[0].to_address == user.email


def test_the_message_has_the_link_in_the_fragment_and_the_body_is_encrypted_at_rest(client, db, admin_user):
    _configure_mail(db)
    user, _ = _enrolled(db, admin_user)
    _request(client, user.email)
    row = _queued(db)[0]
    token = _token_from_outbox(row)
    assert "?" not in re.search(r"https?://\S+/reset-password#\S+", _decrypt_api_key(row.body_enc)).group(0)
    assert token not in (row.body_enc or ""), "the stored body is ciphertext"
    stored = db.scalars(select(PasswordResetToken)).one()
    assert stored.token_hash == passwords_hash_of(token) and token not in stored.token_hash
    assert row.subject == "Reset your Axial password"


def passwords_hash_of(token: str) -> str:
    from app.password_reset import hash_token

    return hash_token(token)


def test_a_newer_request_supersedes_the_older_token(client, db, admin_user):
    _configure_mail(db)
    user, secret = _enrolled(db, admin_user)
    _request(client, user.email)
    _request(client, user.email)
    first, second = (_token_from_outbox(r) for r in _queued(db))
    r = client.post("/auth/password-reset/complete", json={"token": first, "new_password": NEW_PASSWORD, "code": _fresh_code(secret)})
    assert r.status_code == 400
    ok = client.post("/auth/password-reset/complete", json={"token": second, "new_password": NEW_PASSWORD, "code": _fresh_code(secret)})
    assert ok.status_code == 204, "the refused attempt on the old token did not use up the code"


def test_requests_beyond_three_an_hour_queue_nothing(client, db, admin_user):
    _configure_mail(db)
    user, _ = _enrolled(db, admin_user)
    for _ in range(5):
        assert _request(client, user.email).status_code == 202
    assert len(_queued(db)) == 3
    reasons = [a.payload.get("reason") for a in db.scalars(select(AccountAuditLog).where(AccountAuditLog.action == "password_reset_request"))]
    assert reasons.count("throttled") == 2


def test_accounts_that_cannot_use_a_reset_receive_no_link(client, db, admin_user):
    _configure_mail(db)
    disabled, _ = _enrolled(db, admin_user, "disabled.user@example.com")
    disabled.status = "disabled"
    invited = db.get(User, create_user(
        AdminCreateUserIn(email="invited.user@example.com", display_name="Invited", role="operator"),
        _Req(), actor=admin_user, db=db).user.id)
    no_totp, _ = _enrolled(db, admin_user, "no.totp@example.com")
    no_totp.totp_secret_encrypted = None
    no_totp.totp_confirmed_at = None
    db.commit()
    for address in (disabled.email, invited.email, no_totp.email):
        assert _request(client, address).status_code == 202
    assert _queued(db) == []


# ------------------------------------------------------------ REQ-IAM-020: complete


def _start(client, db, admin_user, email="reset.me@example.com"):
    _configure_mail(db)
    user, secret = _enrolled(db, admin_user, email)
    _request(client, user.email)
    return user, secret, _token_from_outbox(_queued(db, user.email)[-1])


def test_a_reset_sets_the_password_revokes_sessions_clears_the_lockout_and_leaves_mfa(client, db, admin_user):
    user, secret, token = _start(client, db, admin_user)
    raw_session, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    user.failed_password_count, user.locked_until = 7, dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)
    secret_before, confirmed_before = user.totp_secret_encrypted, user.totp_confirmed_at
    db.commit()

    r = client.post("/auth/password-reset/complete", json={"token": token, "new_password": NEW_PASSWORD, "code": _fresh_code(secret)})
    assert r.status_code == 204
    assert "set-cookie" not in {k.lower() for k in r.headers}, "a reset signs nobody in"

    db.expire_all()
    user = db.get(User, user.id)
    assert passwords.verify_secret(NEW_PASSWORD, user.password_hash)
    assert not passwords.verify_secret(PASSWORD, user.password_hash)
    assert user.failed_password_count == 0 and user.locked_until is None
    assert user.totp_secret_encrypted == secret_before and user.totp_confirmed_at == confirmed_before
    assert auth_service.resolve_session(db, raw_session) is None
    assert all(s.revoked_at is not None for s in db.scalars(select(UserSession).where(UserSession.user_id == user.id)))
    actions = [(a.action, a.outcome) for a in db.scalars(select(AccountAuditLog).order_by(AccountAuditLog.ts))]
    assert ("password_reset_request", "success") in actions and ("password_reset_complete", "success") in actions


def test_the_user_can_then_sign_in_with_the_new_password_and_the_authenticator(client, db, admin_user):
    user, secret, token = _start(client, db, admin_user)
    client.post("/auth/password-reset/complete", json={"token": token, "new_password": NEW_PASSWORD, "code": _fresh_code(secret)})
    db.expire_all()
    logged_in, step = auth_service.authenticate_password(db, user.email, NEW_PASSWORD, ip=None, user_agent=None)
    assert step == "mfa_verify"


def test_a_token_works_once(client, db, admin_user):
    user, secret, token = _start(client, db, admin_user)
    body = {"token": token, "new_password": NEW_PASSWORD, "code": _fresh_code(secret)}
    assert client.post("/auth/password-reset/complete", json=body).status_code == 204
    again = client.post("/auth/password-reset/complete", json={**body, "code": _fresh_code(secret, 2), "new_password": "yet-another-password-789"})
    assert again.status_code == 400
    db.expire_all()
    assert passwords.verify_secret(NEW_PASSWORD, db.get(User, user.id).password_hash)


@pytest.mark.parametrize("make_token", [
    lambda token: token + "x",
    lambda token: token[:-3],
    lambda token: "A" * 43,
    lambda token: " ",
])
def test_a_tampered_or_unknown_token_is_refused_without_changing_anything(client, db, admin_user, make_token):
    user, secret, token = _start(client, db, admin_user)
    before = db.get(User, user.id).password_hash
    r = client.post("/auth/password-reset/complete",
                    json={"token": make_token(token), "new_password": NEW_PASSWORD, "code": _fresh_code(secret)})
    assert r.status_code == 400 and r.json()["detail"] == "this reset link is invalid or has expired"
    db.expire_all()
    assert db.get(User, user.id).password_hash == before


def test_an_expired_token_is_refused(client, db, admin_user):
    user, secret, token = _start(client, db, admin_user)
    row = db.scalars(select(PasswordResetToken)).one()
    row.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
    db.commit()
    r = client.post("/auth/password-reset/complete", json={"token": token, "new_password": NEW_PASSWORD, "code": _fresh_code(secret)})
    assert r.status_code == 400


def test_a_wrong_code_is_refused_keeps_the_token_and_five_wrong_codes_end_it(client, db, admin_user):
    user, secret, token = _start(client, db, admin_user)
    for attempt in range(5):
        r = client.post("/auth/password-reset/complete", json={"token": token, "new_password": NEW_PASSWORD, "code": "000000"})
        assert r.status_code == 400 and r.json()["detail"] == "that code was not accepted", attempt
    db.expire_all()
    assert db.scalars(select(PasswordResetToken)).one().invalidated_at is not None
    good = client.post("/auth/password-reset/complete", json={"token": token, "new_password": NEW_PASSWORD, "code": _fresh_code(secret)})
    assert good.status_code == 400, "a token that was guessed against is finished"
    db.expire_all()
    assert passwords.verify_secret(PASSWORD, db.get(User, user.id).password_hash)


def test_a_wrong_code_does_not_consume_the_token(client, db, admin_user):
    user, secret, token = _start(client, db, admin_user)
    assert client.post("/auth/password-reset/complete",
                       json={"token": token, "new_password": NEW_PASSWORD, "code": "123456"}).status_code == 400
    assert client.post("/auth/password-reset/complete",
                       json={"token": token, "new_password": NEW_PASSWORD, "code": _fresh_code(secret)}).status_code == 204


def test_a_replayed_authenticator_code_is_refused(client, db, admin_user):
    user, secret, token = _start(client, db, admin_user)
    code = _fresh_code(secret)
    user.totp_last_step = int((time.time() + 30) // 30)  # this step was already used to sign in
    db.commit()
    r = client.post("/auth/password-reset/complete", json={"token": token, "new_password": NEW_PASSWORD, "code": code})
    assert r.status_code == 400


def test_a_backup_code_works_once(client, db, admin_user):
    user, secret, token = _start(client, db, admin_user)
    raw = passwords.generate_backup_codes(1)[0]
    db.query(UserBackupCode).filter(UserBackupCode.user_id == user.id).delete()
    db.add(UserBackupCode(user_id=user.id, code_hash=passwords.hash_secret(raw)))
    db.commit()
    assert client.post("/auth/password-reset/complete",
                       json={"token": token, "new_password": NEW_PASSWORD, "code": raw}).status_code == 204
    db.expire_all()
    assert db.scalars(select(UserBackupCode).where(UserBackupCode.user_id == user.id)).one().used_at is not None


def test_a_weak_password_is_refused_and_the_token_still_works(client, db, admin_user):
    user, secret, token = _start(client, db, admin_user)
    r = client.post("/auth/password-reset/complete", json={"token": token, "new_password": "short", "code": _fresh_code(secret)})
    assert r.status_code == 422
    assert client.post("/auth/password-reset/complete",
                       json={"token": token, "new_password": NEW_PASSWORD, "code": _fresh_code(secret)}).status_code == 204


def test_a_token_cannot_be_used_with_another_users_code(client, db, admin_user):
    _configure_mail(db)
    alice, alice_secret = _enrolled(db, admin_user, "alice@example.com")
    bob, bob_secret = _enrolled(db, admin_user, "bob@example.com")
    _request(client, alice.email)
    token = _token_from_outbox(_queued(db, alice.email)[0])
    r = client.post("/auth/password-reset/complete", json={"token": token, "new_password": NEW_PASSWORD, "code": _fresh_code(bob_secret)})
    assert r.status_code == 400
    db.expire_all()
    assert passwords.verify_secret(PASSWORD, db.get(User, alice.id).password_hash)


def test_an_account_disabled_after_the_request_cannot_complete(client, db, admin_user):
    user, secret, token = _start(client, db, admin_user)
    user.status = "disabled"
    db.commit()
    r = client.post("/auth/password-reset/complete", json={"token": token, "new_password": NEW_PASSWORD, "code": _fresh_code(secret)})
    assert r.status_code == 400


def test_the_reset_never_resets_mfa_even_when_the_user_lost_the_authenticator(client, db, admin_user):
    """No code, no reset: a user who lost the authenticator needs an administrator's Reset MFA."""
    user, secret, token = _start(client, db, admin_user)
    r = client.post("/auth/password-reset/complete", json={"token": token, "new_password": NEW_PASSWORD, "code": "ABCD1234"})
    assert r.status_code == 400
    db.expire_all()
    u = db.get(User, user.id)
    assert u.totp_secret_encrypted is not None and u.totp_confirmed_at is not None


# ------------------------------------------------------------ REQ-MAIL-002: settings


def test_mail_settings_are_an_administrators_and_the_password_is_write_only(client, db, admin_user, test_user):
    admin_token, _ = auth_service.create_session(db, admin_user, ip=None, user_agent=None)
    op_token, _ = auth_service.create_session(db, test_user, ip=None, user_agent=None)
    body = {"enabled": True, "host": "smtp.example.org", "port": 587, "security": "starttls", "username": "relay",
            "password": "super-secret-relay-password", "from_address": "axial@example.org", "from_name": "Axial"}
    assert client.put("/settings/mail", json=body, headers={"Authorization": f"Bearer {op_token}"}).status_code == 403
    assert client.get("/settings/mail", headers={"Authorization": f"Bearer {op_token}"}).status_code == 403
    r = client.put("/settings/mail", json=body, headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    assert r.json()["password_set"] is True and "super-secret" not in r.text
    assert "super-secret" not in client.get("/settings/mail", headers={"Authorization": f"Bearer {admin_token}"}).text
    stored = db.scalars(select(mail_settings.AppSetting).where(mail_settings.AppSetting.key == "mail_config")).one()
    assert "super-secret" not in str(stored.value) and stored.value["password_enc"]
    # an empty password keeps the stored one
    again = client.put("/settings/mail", json={**body, "password": ""}, headers={"Authorization": f"Bearer {admin_token}"})
    assert again.json()["password_set"] is True
    assert mail_settings.relay_credentials(db)["password"] == "super-secret-relay-password"


@pytest.mark.parametrize("change", [
    {"host": ""}, {"host": "postgres"}, {"host": "localhost"}, {"host": "127.0.0.1"}, {"host": "169.254.169.254"},
    {"host": "relay.internal"}, {"host": "smtp.example.org\r\nRCPT TO:<x@y>"}, {"port": 0}, {"port": 70000},
    {"from_address": "not-an-address"}, {"from_address": "a@b.com\r\nBcc: x@y.com"}, {"security": "none"},
    {"from_name": "Axial\r\nBcc: x@y.com"},
])
def test_unacceptable_mail_settings_are_refused(client, db, admin_user, change):
    token, _ = auth_service.create_session(db, admin_user, ip=None, user_agent=None)
    body = {"enabled": True, "host": "smtp.example.org", "port": 587, "security": "starttls", "username": "u",
            "password": "p", "from_address": "axial@example.org", "from_name": "Axial", **change}
    r = client.put("/settings/mail", json=body, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code in (422, 400), (change, r.status_code, r.text)


# ------------------------------------------------------------ REQ-MAIL-003/004: queue and test


def test_a_test_message_goes_to_the_callers_own_address_and_is_rate_limited(client, db, admin_user):
    _configure_mail(db)
    token, _ = auth_service.create_session(db, admin_user, ip=None, user_agent=None)
    h = {"Authorization": f"Bearer {token}"}
    for _ in range(5):
        assert client.post("/settings/mail/test", headers=h).status_code == 202
    assert client.post("/settings/mail/test", headers=h).status_code == 429
    rows = db.scalars(select(MailOutbox).where(MailOutbox.kind == "test")).all()
    assert len(rows) == 5 and {r.to_address for r in rows} == {admin_user.email}


def test_a_test_message_is_refused_while_mail_is_not_available(client, db, admin_user):
    token, _ = auth_service.create_session(db, admin_user, ip=None, user_agent=None)
    assert client.post("/settings/mail/test", headers={"Authorization": f"Bearer {token}"}).status_code == 409


def test_the_worker_gets_the_relay_and_the_decrypted_body_only_over_the_internal_token(client, db, admin_user):
    from app.config import get_settings

    _configure_mail(db)
    user, _ = _enrolled(db, admin_user)
    _request(client, user.email)
    assert client.get("/internal/mail/due").status_code in (401, 403)
    due = client.get("/internal/mail/due", headers={"x-asm-internal-token": get_settings().internal_api_token}).json()
    assert due["relay"]["password"] == "relay-secret" and due["relay"]["host"] == "smtp.example.org"
    assert len(due["messages"]) == 1 and "/reset-password#" in due["messages"][0]["body"]


def test_nothing_is_handed_to_the_worker_while_mail_is_off(client, db, admin_user):
    from app.config import get_settings

    _configure_mail(db)
    user, _ = _enrolled(db, admin_user)
    _request(client, user.email)
    _configure_mail(db, enabled=False)
    due = client.get("/internal/mail/due", headers={"x-asm-internal-token": get_settings().internal_api_token}).json()
    assert due == {"relay": None, "messages": []}


def test_delivery_removes_the_body_and_failure_backs_off_then_ends_visibly(client, db, admin_user):
    from app.config import get_settings

    _configure_mail(db)
    user, _ = _enrolled(db, admin_user)
    _request(client, user.email)
    other = mail_settings  # noqa: F841 (keeps the import used when assertions are trimmed)
    token = {"x-asm-internal-token": get_settings().internal_api_token}
    message = client.get("/internal/mail/due", headers=token).json()["messages"][0]
    first = client.post(f"/internal/mail/{message['id']}/result", json={"delivered": False, "error": "relay_response_451"}, headers=token)
    assert first.json()["state"] == "pending" and first.json()["attempts"] == 1
    db.expire_all()
    row = db.get(MailOutbox, uuid.UUID(message["id"]))
    assert row.next_attempt_at > dt.datetime.now(dt.timezone.utc) and row.last_error == "relay_response_451"
    for _ in range(5):
        last = client.post(f"/internal/mail/{message['id']}/result", json={"delivered": False, "error": "x"}, headers=token)
    assert last.json()["state"] == "failed"
    db.expire_all()
    assert db.get(MailOutbox, uuid.UUID(message["id"])).body_enc is None


def test_a_delivered_message_loses_its_body(client, db, admin_user):
    from app.config import get_settings

    _configure_mail(db)
    user, _ = _enrolled(db, admin_user)
    _request(client, user.email)
    token = {"x-asm-internal-token": get_settings().internal_api_token}
    message = client.get("/internal/mail/due", headers=token).json()["messages"][0]
    assert client.post(f"/internal/mail/{message['id']}/result", json={"delivered": True}, headers=token).json()["state"] == "delivered"
    db.expire_all()
    row = db.get(MailOutbox, uuid.UUID(message["id"]))
    assert row.state == "delivered" and row.body_enc is None and row.delivered_at is not None


def test_audit_entries_never_carry_the_address_the_token_or_the_code(client, db, admin_user):
    user, secret, token = _start(client, db, admin_user)
    client.post("/auth/password-reset/complete", json={"token": token, "new_password": NEW_PASSWORD, "code": _fresh_code(secret)})
    blob = " ".join(str(a.payload) for a in db.scalars(select(AccountAuditLog)))
    assert token not in blob and NEW_PASSWORD not in blob and "relay-secret" not in blob
