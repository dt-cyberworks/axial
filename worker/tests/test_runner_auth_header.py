"""REQ-HARDEN-001 (worker side): the tool-runner client presents the runner
shared secret on every request to the execution boundary, so the runner can
reject any peer that does not hold it."""

from __future__ import annotations

import importlib

from app import tool_runner_client as trc


def test_client_sends_runner_token_header_when_configured(monkeypatch):
    monkeypatch.setenv("RUNNER_API_TOKEN", "unit-test-runner-secret")
    reloaded = importlib.reload(trc)
    try:
        client = reloaded.ToolRunnerClient()
        assert client._client.headers.get("X-ASM-Runner-Token") == "unit-test-runner-secret"
    finally:
        monkeypatch.delenv("RUNNER_API_TOKEN", raising=False)
        importlib.reload(trc)


def test_no_token_header_when_unconfigured(monkeypatch):
    monkeypatch.delenv("RUNNER_API_TOKEN", raising=False)
    reloaded = importlib.reload(trc)
    client = reloaded.ToolRunnerClient()
    # httpx never invents a header we did not set.
    assert "X-ASM-Runner-Token" not in client._client.headers
