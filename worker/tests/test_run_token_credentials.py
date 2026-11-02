"""REQ-EGRESS-008 (GitHub #81): the runner presents the run's signed identity to the egress proxy as proxy credentials,
where the tool can carry them, and keeps it out of everything that is stored.

The set of tools is not a guess: scripts/probe_runner_proxy_credentials.py ran each tool of the runner image against a
recording stand-in proxy. curl, httpx, nuclei, ffuf, katana, wafw00f and nikto sent the credentials; the screenshot
browser refuses a proxy URL with credentials (ERR_NO_SUPPORTED_PROXIES) and testssl takes host:port only."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app import tool_runner_client as trc

RUN = "22222222-2222-4222-8222-222222222222"
ENG = "11111111-1111-4111-8111-111111111111"
TOKEN = ".".join(["v1", "eyJlIjoiMSJ9", "c2lnbmF0dXJl"])
PROXY = "http://egress-proxy:3128"
TARGET = "https://a.example.com"

# tool -> (args, whether the probe showed it carries proxy credentials)
CALLS = {
    "http_request": ({"method": "GET", "path": "/"}, True),
    "httpx": ({}, True),
    "nuclei": ({"mode": "tech"}, True),
    "nuclei:select": ({"mode": "select", "group": "generic", "shard": "1/5"}, True),
    "ffuf": ({"wordlist": "common"}, True),
    "katana": ({}, True),
    "wafw00f": ({}, True),
    "nikto": ({}, True),
    "screenshot": ({}, False),   # via the loopback forwarder (REQ-EGRESS-010), see test_egress_forwarder_wrapper.py
    "testssl": ({}, False),
}


@pytest.fixture(autouse=True)
def _proxy(monkeypatch):
    monkeypatch.setattr(trc, "EGRESS_PROXY_URL", PROXY)
    monkeypatch.setattr(trc, "EGRESS_RUN_TOKENS", True)


def _runner(monkeypatch, captured, *, token=TOKEN, fetch=None):
    runner = trc.ToolRunnerClient()
    runner._egress_tokens = trc._EgressTokens(fetch or (lambda run: {"token": token, "expires_in": 600}))

    def post(path, payload, scan_run_id, budget_s=None):
        captured.update(path=path, payload=payload)
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"stdout": f"proxy is {PROXY.replace('http://', f'http://asm:{token}@')}", "stderr": f"saw {token}",
                          "return_code": 0, "success": True},
        )

    monkeypatch.setattr(runner, "_post_cancellable", post)
    return runner


def _run(runner, key, **kwargs):
    args, _ = CALLS[key]
    tool = key.split(":")[0]
    return runner.run(tool, TARGET, dict(args), scan_run_id=kwargs.pop("scan_run_id", RUN), **kwargs)


def _sent(captured) -> str:
    return json.dumps(captured["payload"])


# --- the URL ---------------------------------------------------------------------------------------------------------

def test_the_proxy_url_is_plain_unless_a_credential_is_in_force():
    assert trc._proxy_url() == PROXY


def test_a_credential_in_force_goes_into_the_userinfo_of_the_proxy_url():
    scope = trc._PROXY_CREDENTIAL.set(TOKEN)
    try:
        assert trc._proxy_url() == f"http://asm:{TOKEN}@egress-proxy:3128"
        assert trc._proxy_hostport() == "egress-proxy:3128", "testssl's host:port never carries credentials"
    finally:
        trc._PROXY_CREDENTIAL.reset(scope)
    assert trc._proxy_url() == PROXY


@pytest.mark.parametrize("hostile", ["a b", "a;touch /tmp/x", "$(id)", "a@b", "a/b", "a'b", 'a"b', "a\nb", "", "x" * 1025, "a:b", "é"])
def test_negative_a_credential_that_could_change_the_shape_of_the_command_is_refused(hostile):
    """A control plane that answered with something hostile must not reach a shell."""
    scope = trc._PROXY_CREDENTIAL.set(hostile)
    try:
        if hostile == "":
            assert trc._proxy_url() == PROXY   # no credential at all
        else:
            with pytest.raises(ValueError, match="unsafe proxy credential"):
                trc._proxy_url()
    finally:
        trc._PROXY_CREDENTIAL.reset(scope)


# --- which tools carry it --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("key", [k for k, (_, carries) in CALLS.items() if carries])
def test_the_tools_that_carry_proxy_credentials_send_the_run_token(monkeypatch, key):
    captured: dict = {}
    result = _run(_runner(monkeypatch, captured), key)
    assert f"asm:{TOKEN}@egress-proxy:3128" in _sent(captured)
    assert PROXY.replace("http://", "") in _sent(captured)
    assert result["success"] is True


@pytest.mark.parametrize("key", [k for k, (_, carries) in CALLS.items() if not carries])
def test_negative_the_tools_that_cannot_carry_credentials_never_get_them_in_a_proxy_url(monkeypatch, key):
    """They get the token through the forwarder's environment instead (REQ-EGRESS-010)."""
    captured: dict = {}
    _run(_runner(monkeypatch, captured), key)
    sent = _sent(captured)
    assert f"asm:{TOKEN}@" not in sent and "@egress-proxy" not in sent
    assert "127.0.0.1:${ASM_FWD_PORT}" in sent.replace("\\", "")


@pytest.mark.parametrize("key", list(CALLS))
def test_negative_with_the_switch_off_no_tool_gets_a_token_or_asks_for_one(monkeypatch, key):
    monkeypatch.setattr(trc, "EGRESS_RUN_TOKENS", False)
    asked: list = []
    captured: dict = {}
    _run(_runner(monkeypatch, captured, fetch=lambda run: asked.append(run) or {"token": TOKEN, "expires_in": 600}), key)
    assert asked == [] and "asm:" not in _sent(captured) and TOKEN not in _sent(captured)


def test_negative_a_call_without_a_run_gets_no_token(monkeypatch):
    asked: list = []
    captured: dict = {}
    runner = _runner(monkeypatch, captured, fetch=lambda run: asked.append(run) or {"token": TOKEN, "expires_in": 600})
    runner.run("httpx", TARGET, {}, scan_run_id=None)
    assert asked == [] and TOKEN not in _sent(captured)


def test_negative_without_a_configured_proxy_nothing_is_built_around_credentials(monkeypatch):
    monkeypatch.setattr(trc, "EGRESS_PROXY_URL", "")
    captured: dict = {}
    _run(_runner(monkeypatch, captured), "httpx")
    assert TOKEN not in _sent(captured) and "-proxy" not in _sent(captured)


def test_the_credential_of_one_call_never_stays_in_force_for_the_next(monkeypatch):
    captured: dict = {}
    runner = _runner(monkeypatch, captured)
    _run(runner, "httpx")
    assert trc._PROXY_CREDENTIAL.get() is None and trc._proxy_url() == PROXY
    _run(runner, "screenshot")
    assert trc._PROXY_CREDENTIAL.get() is None and trc._PROXY_VIA_FORWARDER.get() is False
    assert trc._proxy_url() == PROXY and trc._proxy_hostport() == "egress-proxy:3128"


# --- what is stored --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("key", [k for k, (_, carries) in CALLS.items() if carries])
def test_negative_the_stored_command_never_holds_the_token(monkeypatch, key):
    captured: dict = {}
    result = _run(_runner(monkeypatch, captured), key)
    assert TOKEN not in (result.get("command") or "")
    assert f"asm:{trc.REDACTED_PROXY_CREDENTIAL}@egress-proxy:3128" in (result.get("command") or "")


@pytest.mark.parametrize("key", ["httpx", "nikto"])
def test_negative_a_tool_that_echoes_its_proxy_setting_does_not_put_the_token_into_the_result(monkeypatch, key):
    captured: dict = {}
    result = _run(_runner(monkeypatch, captured), key)
    assert TOKEN not in result["stdout"] and TOKEN not in result["stderr"]
    assert trc.REDACTED_PROXY_CREDENTIAL in result["stdout"]


def test_the_identity_headers_are_the_platforms_never_a_callers(monkeypatch):
    captured: dict = {}
    runner = _runner(monkeypatch, captured)
    runner.run("http_request", TARGET, {"method": "GET", "path": "/", "headers": {
        "Proxy-Authorization": "Basic Zm9yZ2Vk", "x-asm-engagement-id": ENG, "X-Test": "kept"}}, scan_run_id=RUN)
    command = captured["payload"]["command"]
    assert "X-Test: kept" in command
    assert "Zm9yZ2Vk" not in command and ENG not in command and "x-asm-engagement-id" not in command.lower()
    assert command.lower().count("proxy-authorization") == 0


# --- the token cache -------------------------------------------------------------------------------------------------

class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_a_token_is_fetched_once_and_refreshed_a_minute_before_it_expires():
    clock, fetched = _Clock(), []
    cache = trc._EgressTokens(lambda run: fetched.append(run) or {"token": f"t{len(fetched)}", "expires_in": 600}, clock)
    assert cache.get(RUN) == "t1" and cache.get(RUN) == "t1" and fetched == [RUN]
    clock.now += 539
    assert cache.get(RUN) == "t1"
    clock.now += 2
    assert cache.get(RUN) == "t2" and len(fetched) == 2


def test_each_run_has_its_own_token():
    cache = trc._EgressTokens(lambda run: {"token": f"token-{run[-1]}", "expires_in": 600})
    assert cache.get("aaa1") == "token-1" and cache.get("bbb2") == "token-2"


def test_negative_a_refusal_means_no_token_and_is_not_asked_again_at_once(caplog):
    clock, calls = _Clock(), []

    def refuse(run):
        calls.append(run)
        raise RuntimeError("409 scan_run_not_active")

    cache = trc._EgressTokens(refuse, clock)
    assert cache.get(RUN) is None and cache.get(RUN) is None and len(calls) == 1
    clock.now += trc._EgressTokens.RETRY_AFTER_FAILURE_S + 1
    assert cache.get(RUN) is None and len(calls) == 2


def test_negative_a_failed_refresh_drops_the_old_token_instead_of_using_an_expired_one():
    clock, state = _Clock(), {"fail": False}

    def fetch(run):
        if state["fail"]:
            raise RuntimeError("control plane down")
        return {"token": "first", "expires_in": 100}

    cache = trc._EgressTokens(fetch, clock)
    assert cache.get(RUN) == "first"
    state["fail"] = True
    clock.now += 200
    assert cache.get(RUN) is None


@pytest.mark.parametrize("answer", [{}, {"token": None}, {"expires_in": 5}, "nope", None])
def test_negative_an_answer_without_a_token_is_no_token(answer):
    cache = trc._EgressTokens(lambda run: answer)
    assert cache.get(RUN) is None


def test_a_missing_token_never_stops_the_tool(monkeypatch):
    def refuse(run):
        raise RuntimeError("down")

    captured: dict = {}
    result = _run(_runner(monkeypatch, captured, fetch=refuse), "httpx")
    assert result["success"] is True and "asm:" not in _sent(captured)


def test_the_control_plane_client_asks_the_token_endpoint_of_the_run(monkeypatch):
    from app.control_plane_client import client

    seen: dict = {}

    def post(url, **kwargs):
        seen["url"] = url
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"token": TOKEN, "expires_in": 600})

    monkeypatch.setattr(client._client, "post", post)
    assert client.egress_token(RUN)["token"] == TOKEN
    assert seen["url"] == f"/internal/scan-runs/{RUN}/egress-token"


@pytest.mark.parametrize("reason", ["invalid_run_token", "run_token_required", "run_not_active", "run_check_unavailable",
                                    "engagement_share_exhausted", "destination_busy"])
def test_the_proxy_refusals_of_the_identity_are_a_blocked_egress_not_an_empty_result(monkeypatch, reason):
    """A tool that only prints the proxy's refusal (no HTTP code in its message) must not read as "nothing found"."""
    runner = trc.ToolRunnerClient()

    def post(path, payload, scan_run_id, budget_s=None):
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {
            "stdout": "", "stderr": f"proxy said: {reason}", "return_code": 56, "success": False})

    monkeypatch.setattr(runner, "_post_cancellable", post)
    assert runner.run("http_request", TARGET, {"method": "GET", "path": "/"}, scan_run_id=RUN)["error_reason"] == "egress_proxy_blocked"
