"""REQ-TESTACCT-013 (GitHub #89, R4): the worker tells the tool runner which secrets a request carries, so that the runner's own log does
not keep them. The declaration travels in a header and is never part of the command, the payload or the audit rendering."""

from __future__ import annotations

import base64
import json
from urllib.parse import quote

import pytest

from app import test_accounts as ta
from app import tool_runner_client as trc
from app.tasks import dispatch

RUN = "22222222-2222-2222-2222-222222222222"
ENG = "11111111-1111-1111-1111-111111111111"
SHOP = "Sh0p pw/ab12cd34ef&x+y"
BLOG = "Bl0g-secret-7788"
ACCOUNTS = [
    {"label": "shop", "role": "user", "kind": "login_form", "username": "alice", "secret": SHOP, "login_path": "/login",
     "can_use_on": ["shop.example.test"], "cannot_use_on": []},
    {"label": "blog", "role": "user", "kind": "login_form", "username": "bob", "secret": BLOG, "login_path": "/login",
     "can_use_on": ["blog.example.test"], "cannot_use_on": []},
]


@pytest.fixture(autouse=True)
def _accounts():
    ta.register(RUN, ACCOUNTS)
    yield
    ta.unregister(RUN)


def decode(header_value: str) -> list[str]:
    return json.loads(base64.b64decode(header_value))


# --- which strings ---------------------------------------------------------------------------------------------------------


def test_the_forms_of_only_the_accounts_the_request_names():
    forms = ta.mask_forms({"body": "username=alice&password={{testaccount:shop|url}}"}, run_key=RUN)
    assert SHOP in forms and quote(SHOP, safe="") in forms and base64.b64encode(SHOP.encode()).decode() in forms
    assert base64.b64encode(f"alice:{SHOP}".encode()).decode() in forms, "the Basic form is covered too"
    assert not any(BLOG in f for f in forms), "another account's secret is not declared"


def test_nothing_is_declared_for_a_request_without_a_placeholder_or_with_an_unknown_one():
    assert ta.mask_forms({"body": "plain"}, run_key=RUN) == []
    assert ta.mask_forms({"body": "{{testaccount:ghost}}"}, run_key=RUN) == []
    assert ta.mask_forms({"body": "{{testaccount:shop}}"}, run_key="some-other-run") == []


# --- dispatch -------------------------------------------------------------------------------------------------------------


@pytest.fixture
def runner(monkeypatch):
    seen = {"calls": []}

    def run(tool, target, args, **kw):
        seen["calls"].append({"args": args, **kw})
        return {"success": True, "stdout": "HTTP/1.0 200 OK\r\n\r\nok", "stderr": "", "exit_code": 0}

    monkeypatch.setattr(dispatch.tool_runner, "run", run)
    monkeypatch.setattr(dispatch.tool_execution, "record", lambda *a, **kw: None)
    return seen


def test_dispatch_declares_the_secret_for_the_one_request_that_puts_it_back(runner):
    dispatch._run(ENG, "http_request", "https://shop.example.test", {"method": "POST", "path": "/login", "body": "password={{testaccount:shop}}"}, RUN)
    call = runner["calls"][0]
    assert call["args"]["body"] == f"password={SHOP}", "the request itself carries the real value"
    assert SHOP in call["log_mask"] and BLOG not in json.dumps(call["log_mask"])


def test_dispatch_passes_no_declaration_when_there_is_nothing_to_declare(runner):
    dispatch._run(ENG, "http_request", "https://shop.example.test", {"method": "GET", "path": "/"}, RUN)
    assert "log_mask" not in runner["calls"][0], "a runner or a test double that does not know the argument is not given it"


def test_negative_an_unresolvable_placeholder_sends_nothing_and_declares_nothing(runner):
    ta.unregister(RUN)
    result = dispatch._run(ENG, "http_request", "https://shop.example.test", {"method": "POST", "path": "/login", "body": "{{testaccount:shop}}"}, RUN)
    assert runner["calls"] == [] and result["error_reason"] == "credential_unresolvable"


# --- the runner client --------------------------------------------------------------------------------------------------------


@pytest.fixture
def posted(monkeypatch):
    seen = {}

    def fake(self, path, payload, scan_run_id, budget_s=None, log_mask=None):
        seen.update(path=path, payload=payload, log_mask=log_mask, header=trc._log_mask_header(log_mask))
        return {"stdout": "HTTP/1.0 200 OK\r\n\r\nok", "stderr": "", "return_code": 0, "success": True}

    class _Response:
        def __init__(self, body):
            self._body = body

        def raise_for_status(self):
            pass

        def json(self):
            return self._body

    monkeypatch.setattr(trc.ToolRunnerClient, "_post_cancellable", lambda self, *a, **kw: _Response(fake(self, *a, **kw)))
    monkeypatch.setattr(trc, "EGRESS_PROXY_URL", "")
    monkeypatch.setattr(trc.ToolRunnerClient, "egress_proxy_unreachable", lambda self: False)
    return seen


def test_the_declaration_is_a_header_and_never_part_of_the_command_the_payload_or_the_audit_rendering(posted):
    runner = trc.ToolRunnerClient()
    result = runner.run("http_request", "https://shop.example.test", {"method": "POST", "path": "/login", "body": f"password={SHOP}"},
                        log_mask=[SHOP, quote(SHOP, safe="")])
    assert decode(posted["header"]) == sorted([SHOP, quote(SHOP, safe="")], key=len)
    assert "log_mask" not in json.dumps(posted["payload"]), "not in the command payload"
    assert "asm_log_mask" not in json.dumps(posted["payload"])
    assert SHOP not in result["command"] and quote(SHOP, safe="") not in result["command"], "the audit rendering still drops the body"


def test_no_header_without_a_declaration(posted):
    trc.ToolRunnerClient().run("http_request", "https://shop.example.test", {"method": "GET", "path": "/"})
    assert posted["header"] is None


def test_the_header_is_bounded_and_short_strings_are_left_out():
    assert trc._log_mask_header(["short", "1234567"]) is None
    many = [f"{index:04d}" + "x" * 400 for index in range(200)]
    header = trc._log_mask_header(many)
    assert header is not None and len(header) <= trc.LOG_MASK_MAX_CHARS and decode(header)


def test_the_header_reaches_the_wire_with_the_run_id(monkeypatch):
    sent = {}

    class _Client:
        def post(self, path, json=None, headers=None, **kw):
            sent.update(path=path, headers=headers)

            class _R:
                def raise_for_status(self):
                    pass

                def json(self_inner):
                    return {"stdout": "", "stderr": "", "return_code": 0, "success": True}
            return _R()

    runner = trc.ToolRunnerClient()
    monkeypatch.setattr(runner, "_client", _Client())
    runner._post_cancellable("/api/command", {"command": "true"}, None, 60, log_mask=[SHOP])
    assert decode(sent["headers"][trc.LOG_MASK_HEADER]) == [SHOP]
