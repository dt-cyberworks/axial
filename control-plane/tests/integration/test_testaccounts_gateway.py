"""REQ-TESTACCT-004, -005, -006, -007 (GitHub #89, R4): the Scope Gateway's rule for test-account credentials, and the proof that nothing the
platform keeps contains the secret.

The model sees the real value (D1), so these are the controls that do not need the model: a credential goes only into an http_request to a
host assigned to its account and still usable, a password only into its declared login, at most two attempts a host and run, one narrow
allowance for a consented monitor - and a search of every table for the value and its encodings finds nothing."""

from __future__ import annotations

import base64
import datetime as dt
import json
from urllib.parse import quote, quote_plus

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, text

from app import testaccounts
from app.api.internal import add_finding, internal_agent_event, internal_record_agent_step, internal_tool_execution
from app.config import get_settings
from app.gateway.authorize import ToolCall, authorize
from app.models.approval import ApprovalRequest
from app.models.asset import DiscoveredAsset
from app.models.audit import AuditLog
from app.models.engagement import ScopeAsset
from app.models.scan_run import ScanRun
from app.models.test_account import TestAccountLoginAttempt
from app.models.user import User
from app.schemas.internal import AgentEventIn, AgentStepIn, FindingIn, ToolExecutionEventIn

SECRET = "-".join(["S3cret", "Pass", "word", "4711"])
HOST = "metasploitable2"
OTHER = "juice-shop"
LOGIN_BODY = "username=alice&password={{testaccount:shop}}"
RISK = {"level": "low", "description": "log in with the dedicated test account"}


@pytest.fixture(autouse=True)
def _cipher(monkeypatch):
    monkeypatch.setattr(get_settings(), "testaccount_encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(get_settings(), "testaccount_encryption_key_previous", "")


@pytest.fixture
def eng(db, lab_engagement):
    lab_engagement.ai_testing_allowed = True
    db.commit()
    return lab_engagement


@pytest.fixture
def owner(db, eng):
    return db.get(User, eng.owner_user_id)


@pytest.fixture
def run(db, eng):
    r = ScanRun(engagement_id=eng.id, phase="agent", state="running", attempt=1, budget_tool_calls_max=200)
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def account(db, eng, owner, *, label="shop", kind="login_form", hosts=(HOST,), secret=SECRET, username="alice", **kw):
    return testaccounts.create(
        db, eng, owner, label=label, role="user", kind=kind, username=username if kind != "header_token" else None, secret=secret,
        login_path=("/login" if kind in testaccounts.LOGIN_KINDS else None), header_name=kw.pop("header_name", None),
        hosts=[{"host": h} for h in hosts], attested=True)


def call(eng, run, *, tool="http_request", target=HOST, method="POST", path="/login", body=LOGIN_BODY, headers=None, risk=RISK, **kw):
    args = {"method": method, "path": path}
    if body is not None:
        args["body"] = body
    if headers is not None:
        args["headers"] = headers
    return ToolCall(engagement_id=eng.id, tool=tool, category="vuln", mode="active", target=target, args=args, is_automated=True,
                    phase="agent", scan_run_id=run.id, risk=risk, **kw)


def audit_rows(db, eng, action="tool_call"):
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == action).order_by(AuditLog.ts)).all()


def decide(db, c, **kw):
    return authorize(db, c, **kw)


# --- R-A: only http_request ------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["nikto", "nuclei", "ffuf", "testssl", "nmap", "httpx", "wafw00f", "activemq-openwire-probe"])
def test_negative_the_credential_in_any_other_tool_is_denied_even_on_the_right_host(db, eng, owner, run, tool):
    account(db, eng, owner)
    d = decide(db, call(eng, run, tool=tool, body=None, path="/", method="GET", headers={"X-Token": "{{testaccount:shop}}"}))
    assert d.allowed is False and d.reason == "credential_tool_not_allowed", (tool, d.reason)
    assert "shop" in (d.detail or "") and SECRET not in (d.detail or "")


# --- R-B: only the assigned, usable hosts ------------------------------------------------------------------------------------


def test_negative_a_host_of_the_engagement_that_is_not_assigned_is_denied_the_central_case_of_d8(db, eng, owner, run):
    account(db, eng, owner, hosts=(HOST,))
    d = decide(db, call(eng, run, target=OTHER))
    assert (d.allowed, d.reason) == (False, "credential_host_not_usable")
    assert "not assigned to this account" in d.detail and OTHER in d.detail


def test_negative_a_host_outside_the_scope_is_denied_by_the_existing_scope_rule_first(db, eng, owner, run):
    account(db, eng, owner)
    assert decide(db, call(eng, run, target="outside.example.com")).reason == "target_out_of_scope"


def test_negative_another_account_assigned_there_does_not_help(db, eng, owner, run):
    account(db, eng, owner, label="shop", hosts=(HOST,))
    account(db, eng, owner, label="blog", hosts=(OTHER,))
    d = decide(db, call(eng, run, target=OTHER))   # carries shop's placeholder, aimed at the host blog is assigned to
    assert d.reason == "credential_host_not_usable"


@pytest.mark.parametrize("cause,reason", [("held", "held for review"), ("deny", "blocked by a deny rule"), ("takeover", "possible subdomain takeover"),
                                           ("unattested", "no attested allow rule"), ("suspended", "login was rejected on two runs in a row")])
def test_negative_an_assigned_host_that_stops_being_usable_is_refused_with_its_reason(db, eng, owner, run, cause, reason):
    acct = account(db, eng, owner, hosts=(HOST,))
    if cause == "held":
        db.add(DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=HOST, discovered_via="t", in_scope=True, hold_state="held"))
    elif cause == "deny":
        db.add(ScopeAsset(engagement_id=eng.id, rule="deny", asset_type="domain", value=HOST, active_allowed=False))
    elif cause == "takeover":
        from app.models.dns_record import DnsRecord
        db.add(DnsRecord(engagement_id=eng.id, fqdn=HOST, takeover_suspected=True))
    elif cause == "unattested":
        for rule in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.value == HOST, ScopeAsset.rule == "allow")):
            rule.authorization_verified = False
    else:
        testaccounts.assignments_of(db, acct)[0].suspended_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    d = decide(db, call(eng, run))
    assert d.allowed is False
    # the existing gates may answer first (held host, deny rule, unattested); when the credential rule answers it names the reason
    if d.reason == "credential_host_not_usable":
        assert reason in d.detail
    else:
        assert d.reason in {"asset_held_for_review", "explicit_out_of_scope", "active_not_allowed", "target_out_of_scope"}


def test_negative_the_usable_host_verdict_and_the_gateway_agree_for_every_reason(db, eng, owner, run):
    """The agent's list and the gateway's decision come from one function; a host the list calls unusable is refused."""
    acct = account(db, eng, owner, hosts=(HOST,))
    where = testaccounts.where_usable(db, eng, acct)
    assert where["can"] == [HOST]
    assert decide(db, call(eng, run, target=HOST)).reason != "credential_host_not_usable"
    for cannot in where["cannot"]:
        assert decide(db, call(eng, run, target=cannot["host"])).reason in {"credential_host_not_usable", "target_out_of_scope"}


@pytest.mark.parametrize("form", ["plain", "percent", "plus", "json", "b64-secret", "b64-basic"])
def test_negative_every_recognized_form_of_the_value_is_caught_not_only_the_placeholder(db, eng, owner, run, form):
    account(db, eng, owner, hosts=(HOST,))
    value = {"plain": SECRET, "percent": quote(SECRET, safe=""), "plus": quote_plus(SECRET), "json": json.dumps(SECRET)[1:-1],
             "b64-secret": base64.b64encode(SECRET.encode()).decode(), "b64-basic": base64.b64encode(f"alice:{SECRET}".encode()).decode()}[form]
    d = decide(db, call(eng, run, target=OTHER, body=f"password={value}"))
    assert d.reason == "credential_host_not_usable", (form, d.reason)
    d2 = decide(db, call(eng, run, target=OTHER, body=None, method="GET", path="/", headers={"Authorization": f"Basic {value}"}))
    assert d2.reason == "credential_host_not_usable", (form, d2.reason)


@pytest.mark.parametrize("suffix", ["|url", "|plus", "|json", "|b64", "|basic", "|b64u", "|basicu"])
def test_negative_a_placeholder_that_remembers_its_encoding_is_the_same_account(db, eng, owner, run, suffix):
    """The worker writes {{testaccount:shop|url}} when it found the value percent-encoded."""
    account(db, eng, owner, hosts=(HOST,))
    d = decide(db, call(eng, run, target=OTHER, body="password={{testaccount:shop%s}}" % suffix))
    assert d.reason == "credential_host_not_usable", (suffix, d.reason)


def test_negative_a_value_that_is_not_the_secret_is_not_taken_for_it(db, eng, owner, run):
    account(db, eng, owner)
    assert decide(db, call(eng, run, target=OTHER, body="password=something-else-entirely")).reason != "credential_host_not_usable"


def test_negative_an_unknown_placeholder_is_refused(db, eng, owner, run):
    account(db, eng, owner)
    d = decide(db, call(eng, run, body="password={{testaccount:ghost}}"))
    assert (d.allowed, d.reason) == (False, "credential_wrong_use") and "ghost" in d.detail


def test_negative_the_rule_holds_with_every_other_permission_on(db, eng, owner, run):
    """Approved, consented, in scope, active: a credential still never reaches a host that is not its own."""
    acct = account(db, eng, owner, hosts=(HOST,))
    eng.operating_mode = "monitoring"
    db.commit()
    testaccounts.give_consent(db, eng, owner)
    bad = call(eng, run, target=OTHER)
    approval = ApprovalRequest(engagement_id=eng.id, tool_call=bad.as_jsonable(), state="approved",
                               expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1))
    db.add(approval)
    db.commit()
    assert decide(db, bad, approved_request_id=approval.id).reason == "credential_host_not_usable"
    assert decide(db, call(eng, run, target=HOST)).allowed is True, "the right host, consented, is the allowance"
    assert acct is not None


# --- R-D: a password only in its login ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("method,path", [("POST", "/other"), ("GET", "/login"), ("PUT", "/login"), ("POST", "/login/extra"), ("POST", "/login?next=/admin")])
def test_negative_a_login_accounts_password_is_only_for_its_declared_login_request(db, eng, owner, run, method, path):
    account(db, eng, owner)
    d = decide(db, call(eng, run, method=method, path=path))
    assert (d.allowed, d.reason) == (False, "credential_wrong_use"), (method, path, d.reason)
    assert "POST /login" in d.detail


def test_a_bearer_account_may_be_used_on_any_path_of_an_assigned_host(db, eng, owner, run):
    account(db, eng, owner, label="api", kind="header_token", header_name="Authorization")
    d = decide(db, call(eng, run, method="GET", path="/api/anything", body=None, headers={"Authorization": "Bearer {{testaccount:api}}"}))
    assert d.reason not in {"credential_wrong_use", "credential_host_not_usable", "credential_tool_not_allowed"}


def test_negative_a_bearer_account_still_obeys_the_host_rule(db, eng, owner, run):
    account(db, eng, owner, label="api", kind="header_token", hosts=(HOST,))
    d = decide(db, call(eng, run, target=OTHER, method="GET", path="/", body=None, headers={"Authorization": "Bearer {{testaccount:api}}"}))
    assert d.reason == "credential_host_not_usable"


def test_negative_one_request_cannot_carry_two_accounts_logins(db, eng, owner, run):
    account(db, eng, owner, label="shop")
    account(db, eng, owner, label="admin")
    d = decide(db, call(eng, run, body="u=a&p={{testaccount:shop}}&q={{testaccount:admin}}"))
    assert d.reason == "credential_wrong_use"


def test_a_request_that_names_no_account_is_untouched_by_the_rule(db, eng, owner, run):
    account(db, eng, owner)
    d = decide(db, call(eng, run, body="q=hello", path="/search"))
    assert d.is_pending is True, "an ordinary state-changing request still waits for approval"


# --- assessment: the login stays a per-command approval (D5) ----------------------------------------------------------------


def test_in_an_assessment_the_login_waits_for_approval_and_the_approval_holds_the_placeholder_not_the_value(db, eng, owner, run):
    account(db, eng, owner)
    d = decide(db, call(eng, run))
    assert d.is_pending is True and d.approval_request_id is not None
    approval = db.get(ApprovalRequest, d.approval_request_id)
    stored = json.dumps(approval.tool_call)
    assert "{{testaccount:shop}}" in stored and SECRET not in stored


def test_an_approved_login_is_claimed_and_counts_as_one_attempt(db, eng, owner, run):
    acct = account(db, eng, owner)
    pending = decide(db, call(eng, run))
    approval = db.get(ApprovalRequest, pending.approval_request_id)
    approval.state = "approved"
    db.commit()
    d = decide(db, call(eng, run), approved_request_id=approval.id)
    assert (d.allowed, d.reason) == (True, "all_checks_passed")
    assert testaccounts.login_attempts(db, acct, HOST, run.id) == (1, 1)


def test_a_call_that_carried_the_raw_value_is_stored_scrubbed_and_can_still_be_claimed(db, eng, owner, run):
    """A worker bug that forgot to substitute must not put the value in the approval, and must not break the claim either."""
    account(db, eng, owner)
    raw = call(eng, run, body=f"username=alice&password={SECRET}")
    pending = decide(db, raw)
    approval = db.get(ApprovalRequest, pending.approval_request_id)
    assert SECRET not in json.dumps(approval.tool_call) and "{{testaccount:shop}}" in json.dumps(approval.tool_call)
    approval.state = "approved"
    db.commit()
    assert decide(db, raw, approved_request_id=approval.id).allowed is True


# --- R-E: attempts --------------------------------------------------------------------------------------------------------


def _allow_login(db, eng, run, target=HOST):
    c = call(eng, run, target=target)
    pending = decide(db, c)
    approval = db.get(ApprovalRequest, pending.approval_request_id)
    approval.state = "approved"
    db.commit()
    return decide(db, c, approved_request_id=approval.id)


def test_negative_the_third_login_on_one_host_in_one_run_is_denied(db, eng, owner, run):
    account(db, eng, owner)
    assert _allow_login(db, eng, run).allowed and _allow_login(db, eng, run).allowed
    d = decide(db, call(eng, run))
    assert (d.allowed, d.reason) == (False, "login_attempt_limit") and "no further attempt" in d.detail


def test_negative_a_rejection_on_one_host_does_not_use_up_another_hosts_attempts(db, eng, owner, run):
    account(db, eng, owner, hosts=(HOST, OTHER))
    assert _allow_login(db, eng, run, HOST).allowed and _allow_login(db, eng, run, HOST).allowed
    assert decide(db, call(eng, run, target=HOST)).reason == "login_attempt_limit"
    assert decide(db, call(eng, run, target=OTHER)).is_pending is True, "the other host still has both attempts"


def test_negative_twenty_logins_over_all_hosts_is_the_limit(db, eng, owner, run):
    acct = account(db, eng, owner, hosts=(HOST, OTHER))
    for i in range(20):
        testaccounts.record_login_attempt(db, acct, f"h{i % 10}.example", run.id)
    db.commit()
    assert decide(db, call(eng, run, target=HOST)).reason == "login_attempt_limit"


def test_a_new_run_starts_with_fresh_attempts(db, eng, owner, run):
    account(db, eng, owner)
    assert _allow_login(db, eng, run).allowed and _allow_login(db, eng, run).allowed
    run.state = "done"
    second = ScanRun(engagement_id=eng.id, phase="agent", state="running", attempt=1, budget_tool_calls_max=200)
    db.add(second)
    db.commit()
    assert decide(db, call(eng, second)).is_pending is True


# --- R-F: the one allowance, for a consented monitor ------------------------------------------------------------------------


@pytest.fixture
def mon(db, eng, owner):
    eng.operating_mode = "monitoring"
    db.commit()
    return eng


def test_a_consented_monitors_declared_login_is_allowed_without_an_approval_and_the_audit_row_names_the_consent(db, mon, owner, run):
    account(db, mon, owner)
    consent = testaccounts.give_consent(db, mon, owner)
    d = decide(db, call(mon, run))
    assert (d.allowed, d.reason, d.is_pending) == (True, "testaccount_login", False)
    row = audit_rows(db, mon)[-1]
    assert row.reason == "testaccount_login" and row.payload["consent_id"] == str(consent.id)
    assert SECRET not in json.dumps(row.payload)
    assert testaccounts.login_attempts(db, db.scalars(select(testaccounts.TestAccount)).one(), HOST, run.id) == (1, 1)


def test_negative_without_a_consent_the_monitors_login_waits_for_an_approval_which_nobody_gives_unattended(db, mon, owner, run):
    account(db, mon, owner)
    assert decide(db, call(mon, run)).is_pending is True


@pytest.mark.parametrize("variant", [
    {"path": "/other"}, {"method": "PUT"}, {"method": "DELETE"}, {"body": "username=mallory&password={{testaccount:shop}}"},
])
def test_negative_nothing_but_the_declared_login_is_allowed_by_the_consent(db, mon, owner, run, variant):
    account(db, mon, owner)
    testaccounts.give_consent(db, mon, owner)
    d = decide(db, call(mon, run, **variant))
    assert d.reason != "testaccount_login" and d.allowed is False


def test_negative_another_state_changing_request_of_a_consented_monitor_still_waits(db, mon, owner, run):
    account(db, mon, owner)
    testaccounts.give_consent(db, mon, owner)
    d = decide(db, call(mon, run, path="/profile", body="name=x"))
    assert d.is_pending is True and d.reason == "pending_approval"


def test_negative_the_consent_covers_only_its_pairs(db, mon, owner, run):
    acct = account(db, mon, owner, hosts=(HOST,))
    testaccounts.give_consent(db, mon, owner)
    testaccounts.set_hosts(db, mon, owner, acct, [{"host": HOST}, {"host": OTHER}], attested=True, consent=False)
    assert decide(db, call(mon, run, target=HOST)).reason == "testaccount_login"
    assert decide(db, call(mon, run, target=OTHER)).is_pending is True, "the new host has no consent yet"


@pytest.mark.parametrize("cause", ["revoked", "outdated", "paused", "outside-window", "denied-host"])
def test_negative_the_consent_does_not_survive_the_things_that_end_it(db, mon, owner, run, cause):
    account(db, mon, owner)
    consent = testaccounts.give_consent(db, mon, owner)
    if cause == "revoked":
        testaccounts.revoke_consent(db, mon, owner)
    elif cause == "outdated":
        consent.wording_version = "1999-01-01"
    elif cause == "paused":
        mon.status = "paused"
    elif cause == "outside-window":
        mon.authorized_until = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    else:
        db.add(ScopeAsset(engagement_id=mon.id, rule="deny", asset_type="domain", value=HOST, active_allowed=False))
    db.commit()
    d = decide(db, call(mon, run))
    assert d.reason != "testaccount_login" and d.allowed is False


def test_negative_a_monitor_in_a_run_over_its_login_attempts_is_denied_even_with_a_consent(db, mon, owner, run):
    account(db, mon, owner)
    testaccounts.give_consent(db, mon, owner)
    assert decide(db, call(mon, run)).allowed and decide(db, call(mon, run)).allowed
    assert decide(db, call(mon, run)).reason == "login_attempt_limit"


def test_an_assessment_is_not_widened_by_a_consent_that_cannot_exist_there(db, eng, owner, run):
    account(db, eng, owner)
    assert decide(db, call(eng, run)).is_pending is True


# --- REQ-TESTACCT-005: nothing the platform keeps contains the secret -----------------------------------------------------------


FORMS = [SECRET, quote(SECRET, safe=""), quote_plus(SECRET), base64.b64encode(SECRET.encode()).decode(),
         base64.b64encode(f"alice:{SECRET}".encode()).decode()]


def _everything_the_database_holds(db) -> dict[str, str]:
    db.expire_all()
    out = {}
    tables = db.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'")).scalars().all()
    for table in tables:
        out[table] = "\n".join(db.execute(text(f'SELECT t::text FROM "{table}" t')).scalars().all())
    return out


def test_negative_a_search_of_every_table_for_the_value_and_its_encodings_finds_nothing(db, eng, owner, run):
    """The model writes the value everywhere it can: the request, its reason, the finding, the evidence, the transcript, an event."""
    acct = account(db, eng, owner, hosts=(HOST,))
    echoed = f"Welcome alice, your password {SECRET} was accepted; Basic {FORMS[4]}; url {FORMS[1]}"
    c = call(eng, run, body=f"username=alice&password={SECRET}", rationale=f"log in as alice with {SECRET}")
    pending = decide(db, c)
    decide(db, call(eng, run, target=OTHER, body=f"password={SECRET}"))                  # refused, and audited
    approval = db.get(ApprovalRequest, pending.approval_request_id)
    approval.state = "approved"
    db.commit()
    decide(db, c, approved_request_id=approval.id)
    add_finding(eng.id, FindingIn(category="exposure", title=f"Password {SECRET} reflected", confidence="validated",
                                  evidence={"echo": echoed, "nested": [{"v": FORMS[2]}]}, raw_ref=f"https://x/?p={FORMS[1]}"), db)
    internal_record_agent_step(eng.id, AgentStepIn(scan_run_id=run.id, iteration=1,
                                                   request_messages=[{"role": "user", "content": f"account shop password {SECRET}"}],
                                                   response_text=f"I will log in with {SECRET}",
                                                   response_tool_calls=[{"function": {"arguments": json.dumps({"body": f"p={SECRET}"})}}]), db)
    internal_agent_event(eng.id, AgentEventIn(event="observation", decision="ALLOW", reason=f"saw {SECRET}",
                                              payload={"observation": echoed}), db)
    internal_tool_execution(eng.id, ToolExecutionEventIn(
        scan_run_id=run.id, tool="http_request", phase="agent", authorized_target=HOST, success=True,
        command=f"curl -d 'password={SECRET}'", response=echoed, stderr_summary=f"echo {SECRET}"), db)
    dumped = _everything_the_database_holds(db)
    leaks = {table: [f for f in FORMS if f in text_] for table, text_ in dumped.items() if any(f in text_ for f in FORMS)}
    assert not leaks, f"the secret or an encoding of it is stored in: {leaks}"
    assert "{{testaccount:shop}}" in dumped["audit_log"], "the placeholder stands where it was"
    assert acct is not None


def test_a_finding_keeps_its_meaning_with_the_placeholder_and_a_second_observation_still_dedupes(db, eng, owner):
    account(db, eng, owner)
    body = FindingIn(category="exposure", title=f"Password {SECRET} reflected", confidence="validated", evidence={"echo": SECRET})
    first = add_finding(eng.id, body, db)
    again = add_finding(eng.id, body, db)
    assert again["id"] == first["id"] and again["diff"] == "persist"


def test_the_scrub_replaces_in_place_and_leaves_other_engagements_alone(db, eng, owner, test_user):
    from app.models.engagement import Engagement

    account(db, eng, owner)
    other = Engagement(title="Other", source="lab", status="active", owner_user_id=test_user.id,
                       authorized_from=eng.authorized_from, authorized_until=eng.authorized_until)
    db.add(other)
    db.commit()
    assert testaccounts.scrub_text(db, other.id, f"x {SECRET} y") == f"x {SECRET} y"
    assert testaccounts.scrub_text(db, eng.id, f"x {SECRET} y") == "x {{testaccount:shop}} y"


def test_a_secret_is_never_too_short_to_search_for(db, eng, owner):
    with pytest.raises(testaccounts.TestAccountError):
        account(db, eng, owner, secret="abc")
    assert testaccounts.scrub_text(db, eng.id, "abc abc abc") == "abc abc abc"


def test_a_database_without_the_key_cannot_search_for_values_but_still_denies_placeholders(db, eng, owner, run, monkeypatch):
    account(db, eng, owner, hosts=(HOST,))
    db.info.clear()
    monkeypatch.setattr(get_settings(), "testaccount_encryption_key", "")
    d = decide(db, call(eng, run, target=OTHER))
    assert d.reason == "credential_host_not_usable", "the placeholder is found without decrypting anything"


def test_the_login_attempt_table_holds_no_value(db, eng, owner, run):
    account(db, eng, owner)
    _allow_login(db, eng, run)
    rows = db.scalars(select(TestAccountLoginAttempt)).all()
    assert len(rows) == 1 and SECRET not in str(vars(rows[0]))
