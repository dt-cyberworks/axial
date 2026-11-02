"""REQ-EGRESS-006 (GitHub #81): the proxy refuses to start in production with the development key or none."""

from __future__ import annotations

import importlib
import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@localhost:5432/x")

from app import run_token  # noqa: E402


@pytest.fixture(autouse=True)
def _restore_module():
    yield
    importlib.reload(run_token)


@pytest.mark.parametrize("secret", ["", "egress-run-token-change-me-in-dev"])
def test_negative_production_with_a_dev_default_or_empty_key_does_not_start(monkeypatch, secret):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("EGRESS_RUN_TOKEN_SECRET", secret)
    with pytest.raises(RuntimeError, match="egress_run_token_secret"):
        importlib.reload(run_token)


def test_production_with_its_own_key_starts_and_uses_it(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("EGRESS_RUN_TOKEN_SECRET", "a-real-secret")
    assert importlib.reload(run_token).SECRET == "a-real-secret"


def test_development_may_use_the_default(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("EGRESS_RUN_TOKEN_SECRET", raising=False)
    assert importlib.reload(run_token).SECRET == "egress-run-token-change-me-in-dev"
