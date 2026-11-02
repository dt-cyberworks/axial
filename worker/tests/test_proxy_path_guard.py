"""REQ-RAWLEASE-006: a web tool does not run - and so cannot read as "nothing found" - while the tool runner cannot reach
the egress proxy.

Seen on int after the proxy was recreated: the runner's firewall still allowed the proxy's old address, httpx printed
nothing and exited 0 ("not a web service"), testssl said "no TLS", and the run ended `complete`. The gateway sits in the
runner's network namespace and probes the proxy from there; the worker asks it before starting a proxied tool."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app import raw_egress_client
from app import tool_runner_client as trc

RUN = "22222222-2222-4222-8222-222222222222"
TARGET = "https://a.example.com"


class _Http:
    def __init__(self, body=None, error=None):
        self.body, self.error, self.gets = body, error, 0

    def get(self, path):
        self.gets += 1
        if self.error:
            raise self.error
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: self.body)


def _client(body=None, error=None):
    client = raw_egress_client.RawEgressGatewayClient("http://gateway")
    client._client = _Http(body, error)
    return client


# --- the gateway client ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("reachable", [True, False])
def test_the_client_reports_what_the_gateway_says(reachable):
    assert _client({"status": "ok", "egress": {"proxy": {"reachable": reachable}}}).proxy_reachable() is reachable


@pytest.mark.parametrize("body", [
    {"status": "ok"},                                            # a gateway that predates the field
    {"status": "ok", "egress": {"proxy": {"reachable": None}}},  # not probed yet
    {"status": "ok", "egress": {"proxy": {"reachable": "no"}}},  # not a boolean: never read as False
    {"egress": None},
])
def test_an_unknown_answer_is_none_never_false(body):
    assert _client(body).proxy_reachable() is None


def test_a_gateway_that_does_not_answer_is_unknown_not_down():
    assert _client(error=RuntimeError("connection refused")).proxy_reachable() is None


def test_one_answer_is_reused_for_a_moment_then_asked_again(monkeypatch):
    clock = {"now": 100.0}
    monkeypatch.setattr(raw_egress_client.time, "monotonic", lambda: clock["now"])
    client = _client({"egress": {"proxy": {"reachable": False}}})
    assert client.proxy_reachable() is False
    assert client.proxy_reachable() is False
    assert client._client.gets == 1
    clock["now"] += raw_egress_client.PROXY_STATE_TTL_SECONDS + 0.1
    client._client.body = {"egress": {"proxy": {"reachable": True}}}
    assert client.proxy_reachable() is True
    assert client._client.gets == 2


# --- the runner client ----------------------------------------------------------------------------------------------

@pytest.fixture
def runner(monkeypatch):
    monkeypatch.setattr(trc, "EGRESS_PROXY_URL", "http://egress-proxy:3128")
    monkeypatch.setattr(trc, "EGRESS_RUN_TOKENS", False)
    monkeypatch.setattr(trc, "RAW_NETWORK_MODE", "lease-gateway")
    sent = []

    def post(path, payload, scan_run_id, budget_s=None):
        sent.append(path)
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {
            "stdout": "ok", "stderr": "", "return_code": 0, "success": True})

    r = trc.ToolRunnerClient()
    monkeypatch.setattr(r, "_post_cancellable", post)
    r.sent = sent
    return r


def _proxy_is(monkeypatch, value):
    monkeypatch.setattr(raw_egress_client.raw_egress_gateway, "proxy_reachable", lambda: value)
    monkeypatch.setattr(raw_egress_client.raw_egress_gateway, "available", lambda: True)


@pytest.mark.parametrize("tool", sorted(trc._HTTP_PROXIED_TOOLS))
def test_a_proxied_tool_does_not_run_while_the_proxy_is_unreachable(runner, monkeypatch, tool):
    _proxy_is(monkeypatch, False)
    result = runner.run(tool, TARGET, {"method": "GET", "path": "/"} if tool == "http_request" else {}, scan_run_id=RUN)
    assert result["success"] is False
    assert result["error_reason"] == "egress_proxy_unreachable"
    assert runner.sent == []  # nothing was handed to the runner, so nothing was sent anywhere


def test_the_refusal_reads_as_a_failed_check_not_a_skipped_or_clean_one():
    from app import tool_execution

    result = {"success": False, "error_reason": "egress_proxy_unreachable"}
    assert tool_execution.outcome_of(result) == "failed"
    assert "egress_proxy_unreachable" not in tool_execution.SKIP_REASONS


@pytest.mark.parametrize("state", [True, None])
def test_a_reachable_or_unknown_proxy_does_not_stop_a_tool(runner, monkeypatch, state):
    """Negative for the guard itself: only an explicit "no" blocks; a gateway that is silent must not disable scanning."""
    _proxy_is(monkeypatch, state)
    assert runner.run("httpx", TARGET, {}, scan_run_id=RUN)["success"] is True
    assert runner.sent


def test_a_tool_that_does_not_use_the_proxy_is_not_held_back(runner, monkeypatch):
    """The raw protocol probes reach their target through a gateway lease, not through the proxy."""
    _proxy_is(monkeypatch, False)
    asked = []
    monkeypatch.setattr(raw_egress_client.raw_egress_gateway, "proxy_reachable", lambda: asked.append(1) or False)
    result = runner.run("redis-probe", "203.0.113.5", {"port": 6379}, scan_run_id=RUN)
    assert result["error_reason"] != "egress_proxy_unreachable"
    assert asked == []
    assert runner.sent


def test_without_a_configured_proxy_nothing_is_asked(runner, monkeypatch):
    monkeypatch.setattr(trc, "EGRESS_PROXY_URL", "")

    def boom():
        raise AssertionError("the gateway must not be asked when no proxy is configured")

    monkeypatch.setattr(raw_egress_client.raw_egress_gateway, "proxy_reachable", boom)
    assert runner.run("httpx", TARGET, {}, scan_run_id=RUN)["success"] is True


def test_without_a_gateway_in_this_deployment_nothing_is_asked(runner, monkeypatch):
    monkeypatch.setattr(trc, "RAW_NETWORK_MODE", "disabled")

    def boom():
        raise AssertionError("the gateway must not be asked when raw network mode is off")

    monkeypatch.setattr(raw_egress_client.raw_egress_gateway, "proxy_reachable", boom)
    assert runner.run("httpx", TARGET, {}, scan_run_id=RUN)["success"] is True
