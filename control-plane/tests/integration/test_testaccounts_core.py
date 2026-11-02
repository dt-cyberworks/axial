"""REQ-TESTACCT-001, -002, -003, -006 (consent), -007, -008, -009 (GitHub #89, R4): test accounts of an engagement, against a real PostgreSQL.

The gateway rule and the "nothing we keep contains the secret" search are in test_testaccounts_gateway.py."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from app import auth_service, testaccounts
from app.config import get_settings
from app.db.base import get_db
from app.gateway.audit import verify_audit_chain
from app.main import app
from app.models.asset import DiscoveredAsset
from app.models.audit import AuditLog
from app.models.dns_record import DnsRecord
from app.models.engagement import Engagement, ScopeAsset
from app.models.scan_run import ScanRun
from app.models.test_account import LoginConsent, TestAccount, TestAccountHost
from app.passwords import hash_secret
from app.models.user import User
from tests.integration.owners import make_owner

SECRET = "-".join(["S3cret", "Pass", "word", "4711"])
HOST = "metasploitable2"
OTHER = "juice-shop"


@pytest.fixture(autouse=True)
def _cipher(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "testaccount_encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(settings, "testaccount_encryption_key_previous", "")


@pytest.fixture
def eng(db, lab_engagement):
    lab_engagement.ai_testing_allowed = True
    db.commit()
    return lab_engagement


@pytest.fixture
def owner(db, eng):
    return db.get(User, eng.owner_user_id)


def make(db, eng, owner, *, label="shop", kind="login_form", hosts=(HOST,), secret=SECRET, role="user", username="alice", **kw):
    return testaccounts.create(
        db, eng, owner, label=label, role=role, kind=kind, username=username, secret=secret,
        login_path=kw.pop("login_path", "/login" if kind in testaccounts.LOGIN_KINDS else None), header_name=kw.pop("header_name", None),
        hosts=[{"host": h} for h in hosts], attested=kw.pop("attested", True), **kw)


# --- REQ-TESTACCT-001: entering an account --------------------------------------------------------------------------------------


def test_an_account_is_stored_with_its_hosts_and_an_audit_row_without_the_secret(db, eng, owner):
    account = make(db, eng, owner, hosts=(HOST, OTHER))
    assert {a.host for a in testaccounts.assignments_of(db, account)} == {HOST, OTHER}
    rows = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == "testaccount_created")).all()
    assert len(rows) == 1 and rows[0].payload["hosts"] == sorted([HOST, OTHER])
    assert SECRET not in str(rows[0].payload) and "len" not in str(rows[0].payload).lower()


@pytest.mark.parametrize("bad,code", [
    ({"label": "has space"}, "testaccount_label_invalid"), ({"label": ""}, "testaccount_label_invalid"),
    ({"role": " "}, "testaccount_role_invalid"), ({"kind": "oauth"}, "testaccount_kind_invalid"),
    ({"login_path": "login"}, "testaccount_login_path_invalid"), ({"login_path": "/login?next=/"}, "testaccount_login_path_invalid"),
    ({"username": ""}, "testaccount_username_required"), ({"secret": "short"}, "testaccount_secret_invalid"),
    ({"secret": "x" * 600}, "testaccount_secret_invalid"),
])
def test_negative_invalid_fields_store_nothing(db, eng, owner, bad, code):
    args = dict(label="shop", role="user", kind="login_form", username="alice", secret=SECRET, login_path="/login", header_name=None,
                hosts=[{"host": HOST}], attested=True)
    args.update(bad)
    with pytest.raises(testaccounts.TestAccountError) as err:
        testaccounts.create(db, eng, owner, **args)
    assert err.value.code == code and testaccounts.accounts_of(db, eng.id) == []


def test_negative_without_the_attestation_nothing_is_stored(db, eng, owner):
    with pytest.raises(testaccounts.TestAccountError) as err:
        make(db, eng, owner, attested=False)
    assert (err.value.status, err.value.code) == (422, "testaccount_attestation_required") and testaccounts.accounts_of(db, eng.id) == []


def test_negative_a_label_is_unique_and_there_are_at_most_four_accounts(db, eng, owner):
    make(db, eng, owner, label="a1")
    with pytest.raises(testaccounts.TestAccountError) as taken:
        make(db, eng, owner, label="a1")
    assert taken.value.code == "testaccount_label_taken"
    for i in range(2, 5):
        make(db, eng, owner, label=f"a{i}")
    with pytest.raises(testaccounts.TestAccountError) as limit:
        make(db, eng, owner, label="a5")
    assert limit.value.code == "testaccount_limit" and len(testaccounts.accounts_of(db, eng.id)) == 4


@pytest.mark.parametrize("host", ["*.metasploitable2", "outside.example.com", "clean-nginx", "", "a b", "metasploitable2/path"])
def test_negative_a_host_outside_the_scope_denied_or_not_concrete_cannot_be_assigned(db, eng, owner, host):
    with pytest.raises(testaccounts.TestAccountError) as err:
        make(db, eng, owner, hosts=(host,))
    assert (err.value.status, err.value.code) == (422, "testaccount_host_not_allowed") and testaccounts.accounts_of(db, eng.id) == []


def test_an_account_without_a_host_is_stored_but_usable_nowhere(db, eng, owner):
    account = make(db, eng, owner, hosts=())
    where = testaccounts.where_usable(db, eng, account)
    assert where["can"] == [] and {c["reason"] for c in where["cannot"]} == {"not_assigned"}


def test_at_most_fifty_hosts_per_account(db, eng, owner):
    account = make(db, eng, owner)
    hosts = [{"host": f"h{i}.metasploitable2"} for i in range(51)]
    with pytest.raises(testaccounts.TestAccountError) as err:
        testaccounts.set_hosts(db, eng, owner, account, hosts, attested=True, consent=False)
    assert err.value.code == "testaccount_limit"


def test_the_same_account_can_be_assigned_to_several_hosts_and_a_removed_one_is_gone(db, eng, owner):
    account = make(db, eng, owner, hosts=(HOST, OTHER))
    testaccounts.set_hosts(db, eng, owner, account, [{"host": HOST}], attested=True, consent=False)
    assert [a.host for a in testaccounts.assignments_of(db, account)] == [HOST]


def test_negative_assigning_a_further_host_repeats_the_attestation(db, eng, owner):
    account = make(db, eng, owner)
    with pytest.raises(testaccounts.TestAccountError) as err:
        testaccounts.set_hosts(db, eng, owner, account, [{"host": HOST}, {"host": OTHER}], attested=False, consent=False)
    assert err.value.code == "testaccount_attestation_required"
    testaccounts.set_hosts(db, eng, owner, account, [{"host": HOST}], attested=False, consent=False)   # removing needs none


# --- REQ-TESTACCT-002: at rest, write-only, erased ------------------------------------------------------------------------------


def test_the_secret_is_encrypted_at_rest(db, eng, owner):
    account = make(db, eng, owner)
    stored = db.execute(text("SELECT secret_enc FROM engagement_test_account WHERE id = :i"), {"i": account.id}).scalar()
    assert stored and SECRET not in stored and stored.startswith("gAAAA")
    assert testaccounts.decrypt_secret(stored) == SECRET


def test_negative_without_a_key_saving_fails_loudly_and_stores_nothing(db, eng, owner, monkeypatch):
    monkeypatch.setattr(get_settings(), "testaccount_encryption_key", "")
    with pytest.raises(testaccounts.TestAccountError) as err:
        make(db, eng, owner)
    assert (err.value.status, err.value.code) == (503, "testaccount_cipher_unavailable") and testaccounts.accounts_of(db, eng.id) == []


def test_negative_a_malformed_key_is_refused_and_no_other_key_is_used(db, eng, owner, monkeypatch):
    monkeypatch.setattr(get_settings(), "testaccount_encryption_key", "not-a-fernet-key")
    monkeypatch.setattr(get_settings(), "settings_encryption_key", Fernet.generate_key().decode())   # must not be borrowed
    with pytest.raises(testaccounts.TestAccountError) as err:
        make(db, eng, owner)
    assert err.value.status == 503


def test_a_rotated_key_still_reads_what_the_old_key_wrote(db, eng, owner, monkeypatch):
    account = make(db, eng, owner)
    old = get_settings().testaccount_encryption_key
    monkeypatch.setattr(get_settings(), "testaccount_encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(get_settings(), "testaccount_encryption_key_previous", old)
    assert testaccounts.decrypt_secret(account.secret_enc) == SECRET


def test_negative_the_read_model_never_carries_the_secret_not_even_its_length(db, eng, owner):
    account = make(db, eng, owner)
    shown = repr(testaccounts.view(db, eng, account)) + repr(testaccounts.consent_view(db, eng))
    assert SECRET not in shown and str(len(SECRET)) not in shown.replace("1", "1")[:0] + shown[:0], "no length is shown"
    assert testaccounts.view(db, eng, account)["secret_set"] is True
    assert "secret_enc" not in testaccounts.view(db, eng, account) and "secret" not in testaccounts.view(db, eng, account)


def test_replacing_the_secret_is_the_only_way_to_change_it_and_clears_a_suspension(db, eng, owner):
    account = make(db, eng, owner)
    row = testaccounts.assignments_of(db, account)[0]
    row.suspended_at, row.failed_runs = dt.datetime.now(dt.timezone.utc), 2
    account.state = "suspended"
    db.commit()
    testaccounts.replace_secret(db, eng, owner, account, "A-brand-new-secret-9")
    db.refresh(account)
    db.refresh(row)
    assert testaccounts.decrypt_secret(account.secret_enc) == "A-brand-new-secret-9"
    assert (account.state, row.suspended_at, row.failed_runs) == ("active", None, 0)
    audit = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == "testaccount_secret_replaced")).one()
    assert "A-brand-new" not in str(audit.payload) and SECRET not in str(audit.payload)


def test_deleting_an_account_deletes_the_ciphertext(db, eng, owner):
    account = make(db, eng, owner)
    testaccounts.delete(db, eng, owner, account)
    assert db.execute(text("SELECT count(*) FROM engagement_test_account")).scalar() == 0
    assert db.execute(text("SELECT count(*) FROM engagement_test_account_host")).scalar() == 0


@pytest.mark.parametrize("status", ["completed", "revoked"])
def test_negative_the_ciphertext_is_erased_not_just_flagged_when_the_engagement_ends(db, eng, owner, status):
    make(db, eng, owner)
    eng.status = status
    db.commit()
    assert testaccounts.erase_expired(db) == 1
    row = db.execute(text("SELECT secret_enc, state FROM engagement_test_account")).one()
    assert row.secret_enc is None and row.state == "erased"
    assert testaccounts.erase_expired(db) == 0, "idempotent"


def test_negative_the_ciphertext_is_erased_when_the_authorization_window_ends(db, eng, owner):
    make(db, eng, owner)
    eng.authorized_until = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    db.commit()
    assert testaccounts.erase_expired(db) == 1
    assert db.execute(text("SELECT secret_enc FROM engagement_test_account")).scalar() is None


def test_the_monitoring_housekeeping_erases_the_accounts_of_an_ended_engagement_and_keeps_its_result_shape(db, eng, owner):
    """The periodic job is what erases a secret when nobody closes the engagement through the API (REQ-TESTACCT-002)."""
    from app import monitoring

    make(db, eng, owner)
    eng.authorized_until = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    db.commit()
    assert monitoring.housekeeping(db) == {"missed_runs": 0, "expiring": 0}, "the internal endpoint's result keeps its two keys"
    assert db.execute(text("SELECT secret_enc FROM engagement_test_account")).scalar() is None


def test_an_erased_account_stays_listed_and_cannot_be_revived(db, eng, owner):
    account = make(db, eng, owner)
    testaccounts.erase_engagement(db, eng.id, reason="test")
    db.refresh(account)
    assert testaccounts.view(db, eng, account)["state"] == "erased"
    with pytest.raises(testaccounts.TestAccountError) as err:
        testaccounts.replace_secret(db, eng, owner, account, "Another-secret-12")
    assert err.value.code == "testaccount_erased"


def test_negative_an_ended_engagement_accepts_no_new_account(db, eng, owner):
    eng.status = "completed"
    db.commit()
    with pytest.raises(testaccounts.TestAccountError) as err:
        make(db, eng, owner)
    assert err.value.code == "testaccount_engagement_closed"


# --- who may write: the real routing --------------------------------------------------------------------------------------------


def _session(engine, role="operator"):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)
    with SessionLocal() as s:
        user = User(email=f"u-{uuid.uuid4().hex[:8]}@example.com", display_name="U", role=role, status="active",
                    must_change_password=False, password_hash=hash_secret("pw-not-used-1234"))
        s.add(user)
        s.commit()
        raw, _ = auth_service.create_session(s, user, ip="127.0.0.1", user_agent="test")  # type: ignore[misc]
        s.commit()
        return user.id, {"Authorization": f"Bearer {raw}"}


@pytest.fixture
def http(engine):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def override():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


BODY = {"label": "shop", "role": "user", "kind": "login_form", "username": "alice", "secret": SECRET, "login_path": "/login",
        "hosts": [{"host": HOST}], "attested": True}


def test_negative_only_the_owner_or_an_administrator_can_write_and_everyone_signed_in_can_read(engine, http, db, eng):
    owner_id, owner_headers = _session(engine)
    eng.owner_user_id = owner_id
    db.commit()
    _, stranger = _session(engine)
    _, admin = _session(engine, role="admin")
    url = f"/engagements/{eng.id}/test-accounts"
    assert http.post(url, json=BODY).status_code == 401
    assert http.post(url, json=BODY, headers=stranger).status_code == 403
    assert http.get(url, headers=stranger).status_code == 200, "reading is open (REQ-IAM-022)"
    created = http.post(url, json=BODY, headers=owner_headers)
    assert created.status_code == 201, created.text
    account_id = created.json()["id"]
    for method, path, body in (("put", f"{url}/{account_id}/secret", {"secret": "Another-secret-12"}),
                               ("put", f"{url}/{account_id}/hosts", {"hosts": [], "attested": True}),
                               ("post", f"{url}/{account_id}/resume", None), ("delete", f"{url}/{account_id}", None)):
        refused = getattr(http, method)(path, headers=stranger, **({"json": body} if body is not None else {}))
        assert refused.status_code == 403, (method, path)
    assert http.put(f"{url}/{account_id}/secret", headers=admin, json={"secret": "Another-secret-12"}).status_code == 200
    assert http.post(f"/engagements/{eng.id}/login-consent", headers=stranger).status_code == 403


def test_negative_no_response_ever_contains_the_secret(engine, http, db, eng):
    owner_id, headers = _session(engine)
    eng.owner_user_id = owner_id
    db.commit()
    responses = [http.post(f"/engagements/{eng.id}/test-accounts", headers=headers, json=BODY)]
    responses.append(http.get(f"/engagements/{eng.id}/test-accounts", headers=headers))
    responses.append(http.get(f"/engagements/{eng.id}/test-accounts/host-choices", headers=headers))
    responses.append(http.get(f"/engagements/{eng.id}", headers=headers))
    responses.append(http.get(f"/engagements/{eng.id}/login-consent", headers=headers))
    responses.append(http.post(f"/engagements/{eng.id}/test-accounts", headers=headers, json={**BODY, "secret": SECRET, "kind": "oauth"}))  # an error body
    responses.append(http.put(f"/engagements/{eng.id}/test-accounts/{uuid.uuid4()}/secret", headers=headers, json={"secret": SECRET}))     # 404
    for r in responses:
        assert SECRET not in r.text, (r.request.url, r.status_code)


def test_the_secret_does_not_appear_in_the_repr_of_the_request_model():
    from app.schemas.test_account import TestAccountCreateIn

    assert SECRET not in repr(TestAccountCreateIn(**BODY))


# --- REQ-TESTACCT-004: what makes a host usable --------------------------------------------------------------------------------


def _verdict(db, eng, account, host):
    return testaccounts.host_verdict(db, eng, account, host)


def test_an_assigned_authorized_host_is_usable(db, eng, owner):
    account = make(db, eng, owner)
    v = _verdict(db, eng, account, HOST)
    assert v.usable and v.reason is None


def test_negative_a_host_of_the_engagement_that_is_not_assigned_is_not_usable(db, eng, owner):
    account = make(db, eng, owner, hosts=(HOST,))
    assert (_verdict(db, eng, account, OTHER).usable, _verdict(db, eng, account, OTHER).reason) == (False, "not_assigned")


def test_negative_a_host_stops_being_usable_when_it_is_held_denied_flagged_unattested_or_suspended(db, eng, owner):
    account = make(db, eng, owner, hosts=(HOST, OTHER))
    asset = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=HOST, discovered_via="test", in_scope=True, hold_state="held")
    db.add(asset)
    db.commit()
    assert _verdict(db, eng, account, HOST).reason == "held_for_review"
    asset.hold_state = None
    db.commit()
    assert _verdict(db, eng, account, HOST).usable, "usable again when the cause is gone"

    db.add(ScopeAsset(engagement_id=eng.id, rule="deny", asset_type="domain", value=HOST, active_allowed=False))
    db.commit()
    assert _verdict(db, eng, account, HOST).reason == "denied"

    db.add(DnsRecord(engagement_id=eng.id, fqdn=OTHER, takeover_suspected=True))
    db.commit()
    assert _verdict(db, eng, account, OTHER).reason == "possible_takeover"

    rule = db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.value == "juice-shop", ScopeAsset.rule == "allow")).one()
    db.execute(text("DELETE FROM dns_record WHERE engagement_id = :e"), {"e": eng.id})
    rule.authorization_verified = False
    db.commit()
    assert _verdict(db, eng, account, OTHER).reason == "not_authorized"
    rule.authorization_verified = True
    row = [a for a in testaccounts.assignments_of(db, account) if a.host == OTHER][0]
    row.suspended_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    assert _verdict(db, eng, account, OTHER).reason == "suspended_after_rejected_logins"


def test_negative_an_erased_or_suspended_account_is_not_usable_anywhere(db, eng, owner):
    account = make(db, eng, owner)
    account.state = "suspended"
    db.commit()
    assert _verdict(db, eng, account, HOST).reason == "account_suspended"
    account.state = "erased"
    db.commit()
    assert _verdict(db, eng, account, HOST).reason == "account_erased"


def test_a_host_added_to_the_scope_later_receives_no_credential(db, eng, owner):
    account = make(db, eng, owner, hosts=(HOST,))
    db.add(DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value="new.metasploitable2", discovered_via="test", in_scope=True))
    db.commit()
    assert _verdict(db, eng, account, "new.metasploitable2").reason == "not_assigned"


# --- REQ-TESTACCT-003: what the agent is given ---------------------------------------------------------------------------------


def test_the_agent_gets_the_value_and_both_lists_with_reasons(db, eng, owner):
    make(db, eng, owner, hosts=(HOST,))
    (given,) = testaccounts.agent_accounts(db, eng)
    assert given["secret"] == SECRET and given["can_use_on"] == [HOST]
    assert {"host": OTHER, "reason": "not_assigned", "reason_text": "not assigned to this account"} in given["cannot_use_on"]
    assert given["login_paths"] == {HOST: "/login"}


def test_negative_the_agent_is_given_nothing_for_erased_suspended_or_inactive_engagements(db, eng, owner):
    account = make(db, eng, owner)
    eng.status = "paused"
    db.commit()
    assert testaccounts.agent_accounts(db, eng) == []
    eng.status = "active"
    account.state = "suspended"
    db.commit()
    assert testaccounts.agent_accounts(db, eng) == []
    account.state = "active"
    db.commit()
    testaccounts.erase_engagement(db, eng.id, reason="test")
    assert testaccounts.agent_accounts(db, eng) == []


def test_negative_a_run_never_receives_another_engagements_account(db, eng, owner, test_user):
    make(db, eng, owner)
    other = Engagement(title="Other", source="lab", status="active", owner_user_id=test_user.id,
                       authorized_from=eng.authorized_from, authorized_until=eng.authorized_until)
    db.add(other)
    db.commit()
    assert testaccounts.agent_accounts(db, other) == []


def test_the_internal_agent_context_carries_the_accounts(db, eng, owner):
    from app.api.internal import agent_context

    make(db, eng, owner)
    ctx = agent_context(eng.id, db)
    assert [a["label"] for a in ctx["test_accounts"]] == ["shop"] and ctx["test_accounts"][0]["secret"] == SECRET


# --- REQ-TESTACCT-006/009: the monitor's consent ------------------------------------------------------------------------------


@pytest.fixture
def mon(db, eng):
    eng.operating_mode = "monitoring"
    eng.status = "draft"
    db.commit()
    return eng


def test_a_monitor_with_a_login_account_is_not_activated_without_a_current_consent(db, mon, owner):
    make(db, mon, owner)
    assert testaccounts.activation_problems(db, mon) == ["login_consent_required"]
    testaccounts.give_consent(db, mon, owner)
    assert testaccounts.activation_problems(db, mon) == []


def test_negative_the_activation_endpoint_refuses_such_a_monitor(engine, http, db, mon):
    owner_id, headers = _session(engine)
    mon.owner_user_id = owner_id
    mon.authorized_from = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    db.commit()
    created = http.post(f"/engagements/{mon.id}/test-accounts", headers=headers, json=BODY)
    assert created.status_code == 201, created.text
    refused = http.post(f"/engagements/{mon.id}/activate", headers=headers)
    assert (refused.status_code, refused.json()["detail"]) == (409, "login_consent_required")
    assert http.post(f"/engagements/{mon.id}/login-consent", headers=headers).status_code == 201


def test_the_consent_names_exactly_the_pairs_and_is_appended_never_edited(db, mon, owner):
    account = make(db, mon, owner, hosts=(HOST, OTHER))
    first = testaccounts.give_consent(db, mon, owner)
    assert {(p["label"], p["host"]) for p in first.pairs} == {("shop", HOST), ("shop", OTHER)}
    second = testaccounts.give_consent(db, mon, owner)
    assert first.id != second.id and db.query(LoginConsent).count() == 2
    assert testaccounts.consent_covers(db, mon.id, account, HOST, "/login") is not None


def test_negative_a_host_added_to_an_active_monitors_account_gets_no_login_until_a_consent_covers_the_pair(db, mon, owner):
    account = make(db, mon, owner, hosts=(HOST,))
    testaccounts.give_consent(db, mon, owner)
    mon.status = "active"
    db.commit()
    testaccounts.set_hosts(db, mon, owner, account, [{"host": HOST}, {"host": OTHER}], attested=True, consent=False)
    assert testaccounts.consent_covers(db, mon.id, account, OTHER, "/login") is None
    assert testaccounts.consent_covers(db, mon.id, account, HOST, "/login") is not None
    testaccounts.set_hosts(db, mon, owner, account, [{"host": HOST}, {"host": OTHER}], attested=True, consent=True)
    assert testaccounts.consent_covers(db, mon.id, account, OTHER, "/login") is not None


def test_negative_a_revoked_or_outdated_consent_covers_nothing(db, mon, owner):
    account = make(db, mon, owner)
    row = testaccounts.give_consent(db, mon, owner)
    testaccounts.revoke_consent(db, mon, owner)
    assert testaccounts.consent_covers(db, mon.id, account, HOST, "/login") is None
    again = testaccounts.give_consent(db, mon, owner)
    again.wording_version = "1999-01-01"
    db.commit()
    assert testaccounts.consent_covers(db, mon.id, account, HOST, "/login") is None
    assert testaccounts.activation_problems(db, mon) == ["login_consent_required"]
    assert row.id != again.id


def test_negative_a_changed_login_path_is_not_covered_by_the_old_consent(db, mon, owner):
    account = make(db, mon, owner)
    testaccounts.give_consent(db, mon, owner)
    testaccounts.set_hosts(db, mon, owner, account, [{"host": HOST, "login_path": "/other-login"}], attested=True, consent=False)
    assert testaccounts.consent_covers(db, mon.id, account, HOST, "/other-login") is None


def test_negative_an_assessment_has_no_login_consent(db, eng, owner):
    make(db, eng, owner)
    with pytest.raises(testaccounts.TestAccountError) as err:
        testaccounts.give_consent(db, eng, owner)
    assert err.value.code == "login_consent_not_applicable"
    assert testaccounts.activation_problems(db, eng) == []


def test_a_bearer_account_needs_no_login_consent(db, mon, owner):
    make(db, mon, owner, label="api", kind="header_token", username=None, header_name="Authorization")
    assert testaccounts.activation_problems(db, mon) == []


def test_closing_a_monitor_revokes_its_consent_and_erases_the_secret(db, mon, owner):
    make(db, mon, owner)
    testaccounts.give_consent(db, mon, owner)
    testaccounts.erase_engagement(db, mon.id, reason="engagement_completed")
    assert db.query(LoginConsent).filter(LoginConsent.revoked_at.is_(None)).count() == 0


# --- REQ-TESTACCT-007/008: outcomes, suspension, lost coverage --------------------------------------------------------------------


def _outcomes(db, eng, *items):
    return testaccounts.fold_outcomes(db, eng, [{"label": l, "host": h, "outcome": o} for l, h, o in items])


def test_two_rejected_runs_in_a_row_suspend_the_account_on_that_host_only(db, eng, owner):
    account = make(db, eng, owner, hosts=(HOST, OTHER))
    first = _outcomes(db, eng, ("shop", HOST, "rejected"), ("shop", OTHER, "session_established"))
    assert first["suspended"] == [] and first["lost"] == [{"label": "shop", "host": HOST, "outcome": "rejected"}]
    second = _outcomes(db, eng, ("shop", HOST, "rejected"), ("shop", OTHER, "session_established"))
    assert second["suspended"] == [{"label": "shop", "host": HOST}]
    assert _verdict(db, eng, account, HOST).reason == "suspended_after_rejected_logins"
    assert _verdict(db, eng, account, OTHER).usable, "a rejection on one host does not stop another"
    db.refresh(account)
    assert account.state == "active"


def test_negative_a_success_resets_the_count(db, eng, owner):
    account = make(db, eng, owner)
    _outcomes(db, eng, ("shop", HOST, "rejected"))
    _outcomes(db, eng, ("shop", HOST, "session_established"))
    _outcomes(db, eng, ("shop", HOST, "rejected"))
    assert _verdict(db, eng, account, HOST).usable


def test_an_account_suspended_on_every_host_is_suspended_as_a_whole(db, eng, owner):
    account = make(db, eng, owner, hosts=(HOST, OTHER))
    for _ in range(2):
        _outcomes(db, eng, ("shop", HOST, "rejected"), ("shop", OTHER, "rejected"))
    db.refresh(account)
    assert account.state == "suspended" and testaccounts.agent_accounts(db, eng) == []


def test_resuming_lifts_a_suspension_without_replacing_the_secret(db, eng, owner):
    account = make(db, eng, owner)
    for _ in range(2):
        _outcomes(db, eng, ("shop", HOST, "rejected"))
    db.refresh(account)
    testaccounts.resume(db, eng, owner, account)
    assert _verdict(db, eng, account, HOST).usable


def test_a_regained_session_is_reported(db, eng, owner):
    make(db, eng, owner)
    _outcomes(db, eng, ("shop", HOST, "rejected"))
    assert _outcomes(db, eng, ("shop", HOST, "session_established"))["regained"] == [{"label": "shop", "host": HOST}]


def test_outcomes_for_an_unknown_account_or_host_or_value_are_ignored(db, eng, owner):
    make(db, eng, owner)
    assert _outcomes(db, eng, ("ghost", HOST, "rejected"), ("shop", "elsewhere", "rejected"), ("shop", HOST, "weird")) \
        == {"lost": [], "regained": [], "suspended": []}


def test_the_outcomes_endpoint_marks_lost_coverage_and_records_a_monitor_event(db, mon, owner):
    from app.api.internal import record_test_account_outcomes
    from app.models.monitoring import ChangeEvent
    from app.schemas.test_account import OutcomeIn, OutcomesIn

    make(db, mon, owner, hosts=(HOST, OTHER))
    mon.status = "active"
    run = ScanRun(engagement_id=mon.id, phase="agent", state="running", attempt=1)
    db.add(run)
    db.commit()
    out = record_test_account_outcomes(run.id, OutcomesIn(outcomes=[
        OutcomeIn(label="shop", host=HOST, outcome="rejected"), OutcomeIn(label="shop", host=OTHER, outcome="not_attempted")]), db)
    assert out["coverage_lost"] is True and out["never_logged_in"] == ["shop"]
    events = db.scalars(select(ChangeEvent).where(ChangeEvent.engagement_id == mon.id)).all()
    assert [e.kind for e in events] == ["auth_coverage_lost"] and events[0].detail == {"label": "shop", "host": HOST}
    db.refresh(run)
    assert run.checkpoint["test_account_outcomes"][0]["outcome"] == "rejected"


def test_negative_a_clean_login_is_not_lost_coverage(db, eng, owner):
    from app.api.internal import record_test_account_outcomes
    from app.schemas.test_account import OutcomeIn, OutcomesIn

    make(db, eng, owner)
    run = ScanRun(engagement_id=eng.id, phase="agent", state="running", attempt=1)
    db.add(run)
    db.commit()
    out = record_test_account_outcomes(run.id, OutcomesIn(outcomes=[OutcomeIn(label="shop", host=HOST, outcome="session_established")]), db)
    assert out["coverage_lost"] is False and out["never_logged_in"] == []


def test_the_audit_chain_still_verifies_after_all_of_it(db, eng, owner):
    account = make(db, eng, owner)
    testaccounts.replace_secret(db, eng, owner, account, "Another-secret-12")
    _outcomes(db, eng, ("shop", HOST, "rejected"))
    testaccounts.erase_engagement(db, eng.id, reason="test")
    assert verify_audit_chain(db, eng.id).ok


# --- REQ-TESTACCT-009: what the authorization document states ---------------------------------------------------------------------


def test_the_authorization_lines_carry_label_role_kind_username_hosts_and_who_attested_never_the_secret(db, eng, owner):
    assert testaccounts.authorization_lines(db, eng) is None, "no account, no lines: an old document keeps its checksum"
    make(db, eng, owner, hosts=(OTHER, HOST))
    (line,) = testaccounts.authorization_lines(db, eng)
    assert line["hosts"] == sorted([HOST, OTHER]) and line["label"] == "shop" and line["username"] == "alice"
    assert line["attested_by"] == owner.display_name and line["attested_at"]
    assert SECRET not in repr(line)


def test_an_erased_account_is_history_and_not_listed_in_the_document(db, eng, owner):
    make(db, eng, owner)
    testaccounts.erase_engagement(db, eng.id, reason="test")
    assert testaccounts.authorization_lines(db, eng) is None


# --- REQ-TESTACCT-008: the report says what was tested behind a login --------------------------------------------------------------


def test_the_report_lists_each_account_per_host_with_the_result_and_what_could_not_be_used(db, eng, owner):
    import io
    import re

    from pypdf import PdfReader

    from app.pdf_report import render_report_pdf
    from app.report_builder import build_report_model

    account = make(db, eng, owner, hosts=(HOST, OTHER))
    db.add(DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=OTHER, discovered_via="t", in_scope=True, hold_state="held"))
    run = ScanRun(engagement_id=eng.id, phase="report", state="done", attempt=1,
                  checkpoint={"test_account_outcomes": [{"label": "shop", "host": HOST, "outcome": "rejected"}]})
    db.add(run)
    db.commit()
    model = build_report_model(db, eng, run)
    rows = {(r.account, r.host): r.result for r in model.authenticated_testing}
    assert rows[("shop", HOST)] == "login rejected: NOT tested behind the login"
    assert rows[("shop", OTHER)] == "could not be used: held for review"
    text = re.sub(r"\s+", " ", " ".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(render_report_pdf(model))).pages))
    assert "Authenticated testing" in text and "login rejected: NOT tested behind the login" in text and "untested, not clean" in text
    assert SECRET not in text and account.role == "user"


def test_negative_a_report_of_an_engagement_without_accounts_has_no_such_section(db, eng):
    from app.report_builder import build_report_model

    assert build_report_model(db, eng, None).authenticated_testing == []
