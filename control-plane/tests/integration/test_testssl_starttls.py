"""TC-PIPE-009 (gateway): testssl on a non-web TLS service may name only a fixed
STARTTLS protocol; nothing else can be passed to it."""

from __future__ import annotations

import pytest

from app.gateway.authorize import ToolCall, authorize
from app.gateway import args_safety
from app.tools import registry


def _call(eng, args):
    return ToolCall(engagement_id=eng.id, tool="testssl", category="fingerprint", mode="active",
                    target="metasploitable2", args=args, phase="scan")


@pytest.mark.parametrize("args", [{}, {"starttls": "smtp"}, {"starttls": "imap"}, {"starttls": "pop3"}, {"starttls": "ftp"},
                                  {"starttls": "ldap"}, {"starttls": "xmpp"}, {"starttls": "nntp"}, {"starttls": "postgres"},
                                  {"starttls": "mysql"}])
def test_req_pipe_009_the_known_starttls_protocols_and_no_arguments_are_allowed(db, lab_engagement, args):
    d = authorize(db, _call(lab_engagement, args))
    assert d.allowed, d.reason


@pytest.mark.parametrize("args", [
    {"starttls": "telnet"}, {"starttls": "SMTP"}, {"starttls": "smtp; id"}, {"starttls": ""}, {"starttls": None},
    {"starttls": ["smtp"]}, {"starttls": "$(id)"}, {"starttls": "smtp", "ip": "1.2.3.4"}, {"ip": "1.2.3.4"},
    {"file": "/etc/passwd"}, {"additional_args": "--openssl /bin/sh"}, {"url": "http://x"}, {"proxy": "evil:8080"},
])
def test_negative_req_pipe_009_anything_but_a_known_starttls_protocol_is_unsafe(db, lab_engagement, args):
    d = authorize(db, _call(lab_engagement, args))
    assert not d.allowed and d.reason == "unsafe_arguments"


def test_req_pipe_009_the_registry_validates_testssl_with_the_same_rule():
    spec = registry.get("testssl")
    assert spec.arg_validator is args_safety._testssl_args_safe
    assert registry.validate_args("testssl", {"starttls": "smtp"}) is True
    assert registry.validate_args("testssl", {"starttls": "gopher"}) is False
    assert spec.max_runtime_seconds == 600


def test_req_pipe_009_the_worker_and_gateway_protocol_sets_agree():
    import importlib.util
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[3] / "worker" / "app" / "tool_runner_client.py"
    text = path.read_text()
    start = text.index("TESTSSL_STARTTLS = (") + len("TESTSSL_STARTTLS = (")
    worker_set = {p.strip().strip('"') for p in text[start:text.index(")", start)].replace("\n", "").split(",") if p.strip()}
    assert worker_set == args_safety.TESTSSL_STARTTLS


# --- REQ-PIPE-009: testssl follows the engagement's own tool list --------------------------------------
# johannes 2026-09-30: testssl is one of the tools an engagement can select; selected means it
# runs (web and non-web services alike) with no further approval; switched off means it never runs.

import datetime as dt  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import auth_service  # noqa: E402
from app.db.base import get_db  # noqa: E402
from app.main import app  # noqa: E402


def _api(engine):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override
    return TestClient(app)


@pytest.fixture
def api(engine, db):
    client = _api(engine)
    yield client
    app.dependency_overrides.clear()


def _owner_headers(db, eng):
    from app.models.user import User

    user = db.get(User, eng.owner_user_id)
    raw, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    return {"Authorization": f"Bearer {raw}"}


def _set_testssl(api, db, eng, **entry):
    r = api.put(f"/engagements/{eng.id}/config", headers=_owner_headers(db, eng),
                json={"tools": [{"tool": "testssl", **entry}]})
    assert r.status_code == 200, r.text


def test_req_pipe_009_testssl_is_one_of_the_tools_the_engagement_can_select(api, db, lab_engagement):
    tools = api.get(f"/engagements/{lab_engagement.id}/config", headers=_owner_headers(db, lab_engagement)).json()["tools"]
    row = next(t for t in tools if t["tool"] == "testssl")
    assert row["enabled"] is True and row["category"] == "fingerprint" and row["installed"] is True
    assert row["requires_approval"] is False, "selected means no further approval by default"


@pytest.mark.parametrize("args", [{}, {"starttls": "smtp"}, {"starttls": "imap"}])
def test_req_pipe_009_selected_in_the_tool_list_it_runs_without_any_approval(api, db, lab_engagement, args):
    _set_testssl(api, db, lab_engagement, enabled=True, requires_approval=False)
    d = authorize(db, _call(lab_engagement, args))
    assert d.allowed and not d.is_pending and d.approval_request_id is None


@pytest.mark.parametrize("args", [{}, {"starttls": "smtp"}, {"starttls": "ldap"}])
def test_req_pipe_009_switched_off_in_the_tool_list_it_never_runs_web_or_non_web(api, db, lab_engagement, args):
    _set_testssl(api, db, lab_engagement, enabled=False)
    d = authorize(db, _call(lab_engagement, args))
    assert not d.allowed and d.reason == "tool_disabled"


def test_negative_req_pipe_009_switching_testssl_off_does_not_switch_other_tools_off(api, db, lab_engagement):
    _set_testssl(api, db, lab_engagement, enabled=False)
    other = ToolCall(engagement_id=lab_engagement.id, tool="wafw00f", category="fingerprint", mode="active",
                     target="metasploitable2", args={}, phase="scan")
    assert authorize(db, other).allowed


def test_req_pipe_009_the_scan_settings_tell_the_worker_which_tools_are_off(api, db, lab_engagement):
    from app.config import get_settings

    internal = {"X-ASM-Internal-Token": get_settings().internal_api_token}
    url = f"/internal/engagements/{lab_engagement.id}/scan-settings"
    assert "testssl" not in api.get(url, headers=internal).json()["disabled_tools"]
    _set_testssl(api, db, lab_engagement, enabled=False)
    assert "testssl" in api.get(url, headers=internal).json()["disabled_tools"]
    _set_testssl(api, db, lab_engagement, enabled=None)  # inherit the global policy again
    assert "testssl" not in api.get(url, headers=internal).json()["disabled_tools"]


def test_negative_req_pipe_009_a_selected_tool_can_still_be_forced_to_ask_for_approval_by_the_operator(api, db, lab_engagement):
    """The operator's own choice: a per-tool approval requirement is honoured, the pipeline adds none."""
    _set_testssl(api, db, lab_engagement, enabled=True, requires_approval=True)
    d = authorize(db, _call(lab_engagement, {"starttls": "smtp"}))
    assert not d.allowed and d.is_pending
