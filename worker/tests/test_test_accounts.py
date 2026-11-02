"""REQ-TESTACCT-003/005/007/008 (GitHub #89, R4) on the worker: the model's tool call is rewritten before it leaves the process, the value is
put back in exactly one place, a missing account never produces a request with a placeholder, and a login is classified conservatively."""

from __future__ import annotations

import base64
import json
from urllib.parse import quote, quote_plus

import pytest

from app import test_accounts as ta

SECRET = "-".join(["S3cret", "Pass", "word", "4711"])
RUN = "run-1"
ACCOUNT = {"label": "shop", "role": "user", "kind": "login_form", "username": "alice", "secret": SECRET, "login_path": "/login",
           "login_paths": {"shop.example.test": "/login", "blog.example.test": "/wp-login.php"},
           "can_use_on": ["shop.example.test", "blog.example.test"],
           "cannot_use_on": [{"host": "old.example.test", "reason": "held_for_review", "reason_text": "held for review"}]}


@pytest.fixture(autouse=True)
def _clean():
    yield
    ta.unregister(RUN)
    ta.unregister("run-2")


@pytest.fixture
def registered():
    return ta.register(RUN, [ACCOUNT])


# --- rewriting what leaves the process -------------------------------------------------------------------------------------------


def test_the_value_becomes_a_placeholder_in_headers_body_path_and_nested_structures(registered):
    out = ta.to_placeholders({"path": f"/x?p={SECRET}", "headers": {"X-A": f"Bearer {SECRET}"}, "body": f"a=1&password={SECRET}",
                              "list": [SECRET, {"deep": (SECRET,)}]})
    assert SECRET not in json.dumps(out)
    assert out["body"] == "a=1&password={{testaccount:shop}}" and out["headers"]["X-A"] == "Bearer {{testaccount:shop}}"
    assert out["list"][1]["deep"] == ("{{testaccount:shop}}",)


@pytest.mark.parametrize("form,render", [
    ("url", lambda s, u: quote(s, safe="")), ("plus", lambda s, u: quote_plus(s)), ("json", lambda s, u: json.dumps(s)[1:-1]),
    ("b64", lambda s, u: base64.b64encode(s.encode()).decode()), ("basic", lambda s, u: base64.b64encode(f"{u}:{s}".encode()).decode()),
])
def test_every_recognized_encoding_is_replaced_and_remembers_its_form(form, render):
    secret = 'p@ss "w0rd"/+ü!'
    ta.register(RUN, [{**ACCOUNT, "secret": secret}])
    text = f"x={render(secret, 'alice')}&y=1"
    out = ta.to_placeholders(text)
    assert render(secret, "alice") not in out
    assert "{{testaccount:shop" in out
    assert ta.resolve(out) == text, "putting the value back yields exactly the bytes the model wrote"


def test_the_round_trip_is_exact_for_a_json_body_with_special_characters():
    secret = 'pa"ss\\word-1234'
    ta.register(RUN, [{**ACCOUNT, "secret": secret}])
    body = json.dumps({"user": "alice", "password": secret})
    assert json.loads(ta.resolve(ta.to_placeholders(body)))["password"] == secret


def test_nothing_is_rewritten_when_no_account_is_registered():
    payload = {"a": SECRET}
    assert ta.to_placeholders(payload) is payload and not ta.active()


def test_a_value_that_is_not_the_secret_is_left_alone(registered):
    assert ta.to_placeholders("password=something-else-entirely") == "password=something-else-entirely"


def test_a_secret_below_the_minimum_length_is_not_registered_at_all():
    assert ta.register(RUN, [{**ACCOUNT, "secret": "short"}]) == {} and ta.to_placeholders("short") == "short"


def test_accounts_of_two_runs_are_both_rewritten_but_only_the_own_run_resolves_its_own(registered):
    ta.register("run-2", [{**ACCOUNT, "label": "other", "secret": "Another-Secret-9876"}])
    assert ta.to_placeholders("a=Another-Secret-9876 b=" + SECRET) == "a={{testaccount:other}} b={{testaccount:shop}}"
    assert ta.resolve("{{testaccount:other}}", run_key="run-2") == "Another-Secret-9876"
    with pytest.raises(ta.UnresolvedPlaceholder):
        ta.resolve("{{testaccount:other}}", run_key=RUN)


# --- the last mile -------------------------------------------------------------------------------------------------------------


def test_the_value_is_put_back_for_the_one_request(registered):
    args = {"method": "POST", "path": "/login", "headers": {}, "body": "u=alice&p={{testaccount:shop}}"}
    sent = ta.resolve(args, run_key=RUN)
    assert sent["body"] == f"u=alice&p={SECRET}" and args["body"].endswith("{{testaccount:shop}}"), "the stored form is untouched"


def test_negative_a_placeholder_without_an_account_is_never_sent_as_the_value(registered):
    with pytest.raises(ta.UnresolvedPlaceholder) as err:
        ta.resolve({"body": "p={{testaccount:ghost}}"}, run_key=RUN)
    assert err.value.args == ("ghost",)


def test_negative_after_the_run_ends_the_value_cannot_be_put_back():
    ta.register(RUN, [ACCOUNT])
    ta.unregister(RUN)
    with pytest.raises(ta.UnresolvedPlaceholder):
        ta.resolve("{{testaccount:shop}}", run_key=RUN)
    assert not ta.active() and ta.to_placeholders(SECRET) == SECRET


# --- sessions and logins -------------------------------------------------------------------------------------------------------


def test_identity_is_primary_secondary_or_an_accounts_label(registered):
    assert [ta.identity_for(x, RUN) for x in ("primary", "SECONDARY", "shop", "SHOP", "bogus", "")] == \
        ["primary", "secondary", "shop", "shop", "primary", "primary"]


def test_a_login_is_recognized_by_its_method_path_host_and_placeholder(registered):
    body = "u=alice&p={{testaccount:shop}}"
    assert ta.login_account_for(RUN, "shop.example.test", "POST", "/login", body).label == "shop"
    assert ta.login_account_for(RUN, "blog.example.test", "POST", "/wp-login.php", body).label == "shop", "a login path of its own for that host"


@pytest.mark.parametrize("host,method,path,body", [
    ("shop.example.test", "GET", "/login", "{{testaccount:shop}}"), ("shop.example.test", "POST", "/other", "{{testaccount:shop}}"),
    ("shop.example.test", "POST", "/wp-login.php", "{{testaccount:shop}}"), ("shop.example.test", "POST", "/login", "no placeholder"),
    ("shop.example.test", "POST", "/login", "{{testaccount:ghost}}"),
])
def test_negative_anything_else_is_not_a_login(registered, host, method, path, body):
    assert ta.login_account_for(RUN, host, method, path, body) is None


OK_COOKIE = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; Path=/\r\n\r\nwelcome"


@pytest.mark.parametrize("response,cookies,expected", [
    (OK_COOKIE, {"sid"}, "session_established"),
    ('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"access_token": "x"}', set(), "session_established"),
    ("HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: sid=abc\r\n\r\n", {"sid"}, "session_established"),
    # conservative: when in doubt, rejected
    ("HTTP/1.1 401 Unauthorized\r\n\r\nbad", set(), "rejected"),
    ("HTTP/1.1 403 Forbidden\r\nSet-Cookie: sid=a\r\n\r\n", {"sid"}, "rejected"),
    ("HTTP/1.1 302 Found\r\nLocation: /login.php\r\nSet-Cookie: PHPSESSID=a\r\n\r\n", {"PHPSESSID"}, "rejected"),
    ("HTTP/1.1 200 OK\r\n\r\nInvalid credentials", set(), "rejected"),
    ("", set(), "rejected"),
    ("curl: (7) Failed to connect", set(), "rejected"),
])
def test_a_login_is_classified_conservatively(response, cookies, expected):
    assert ta.classify_login(response, cookies) == expected


# Found live against DVWA (2026-11-01): the target issued its session id BEFORE the login and keeps it, so an accepted login answers
# `302 -> index.php` with no new cookie, and a wrong one (or a stale CSRF token) answers `302 -> login.php`.
DVWA_OK = "HTTP/1.1 302 Found\r\nLocation: index.php\r\nContent-Length: 0\r\n\r\n"


@pytest.mark.parametrize("response,had_session,expected", [
    (DVWA_OK, True, "session_established"),
    ("HTTP/1.1 303 See Other\r\nLocation: /account/home\r\n\r\n", True, "session_established"),
    # without a session held before, a bare redirect proves nothing
    (DVWA_OK, False, "rejected"),
    # the redirects of a wrong password stay rejected whatever the jar held
    ("HTTP/1.1 302 Found\r\nLocation: login.php\r\n\r\n", True, "rejected"),
    ("HTTP/1.1 302 Found\r\nLocation: /signin?next=/home\r\n\r\n", True, "rejected"),
    ("HTTP/1.1 302 Found\r\nLocation: /home?error=1\r\n\r\n", True, "rejected"),
    ("HTTP/1.1 302 Found\r\nLocation: /denied\r\n\r\n", True, "rejected"),
    # a form shown again is not an acceptance, redirect or not
    ("HTTP/1.1 200 OK\r\n\r\n<form>Invalid credentials</form>", True, "rejected"),
    ("HTTP/1.1 302 Found\r\n\r\n", True, "rejected"),
    ("HTTP/1.1 401 Unauthorized\r\nLocation: /home\r\n\r\n", True, "rejected"),
])
def test_a_login_that_keeps_the_sessions_it_already_had_is_recognized_by_where_it_sends_you(response, had_session, expected):
    assert ta.classify_login(response, set(), had_session=had_session) == expected


# --- what the agent is told ---------------------------------------------------------------------------------------------------


def test_the_agent_block_has_the_value_and_both_lists_with_reasons():
    block = ta.render_for_agent([ACCOUNT])
    assert SECRET in block and "username alice" in block
    assert "Can be used on: shop.example.test, blog.example.test" in block
    assert "Cannot be used on: old.example.test (held for review)" in block
    assert "POST /login" in block and "blog.example.test → /wp-login.php" in block
    for rule in ("only into http_request", "At most two login attempts", "identity=<label>", "UNTESTED", "Do not write the password"):
        assert rule in block


def test_an_account_with_no_host_says_it_can_be_used_nowhere():
    assert "this account cannot be used anywhere yet" in ta.render_for_agent([{**ACCOUNT, "can_use_on": []}])


def test_a_bearer_account_is_described_without_a_login_path():
    block = ta.render_for_agent([{**ACCOUNT, "kind": "header_token", "username": None, "header_name": "Authorization", "login_path": None}])
    assert "token " + SECRET in block and "send it in the header Authorization" in block and "Log in with POST" not in block


def test_no_accounts_no_block():
    assert ta.render_for_agent([]) == ""
