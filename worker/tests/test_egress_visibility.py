"""Egress-Block-Sichtbarkeit (REQ-EGRESS-002): ein Proxy-Block wird als Fehler
erkannt, ein sauberes (leeres) Ergebnis NICHT faelschlich als Block."""

from __future__ import annotations

import pytest

from app.tasks import dispatch


def test_detects_proxy_denial_token():
    result = {"stdout": "HTTP/1.1 407 Blocked\nContent-Length: 28\n\nmissing_engagement_id_header",
              "stderr": "", "success": True}
    assert dispatch._egress_block_reason(result) == "missing_engagement_id_header"


def test_detects_host_unresolved():
    result = {"stdout": "", "stderr": "curl: (56) Received HTTP code 409 from proxy after CONNECT",
              "success": False}
    assert dispatch._egress_block_reason(result) == "received http code 409 from proxy"


def test_clean_empty_result_is_not_flagged():
    # Tool lief sauber, Ziel erreichbar, nichts gefunden -> KEIN Block.
    assert dispatch._egress_block_reason({"stdout": "", "stderr": "", "success": True}) is None


def test_target_own_407_is_not_a_proxy_block():
    # Ein 407 vom ZIEL (nach erfolgreichem CONNECT), ohne unsere Proxy-Tokens,
    # ist eine echte Beobachtung, kein Egress-Block.
    result = {"stdout": "HTTP/1.1 407 Proxy Authentication Required\nWWW-Authenticate: Basic",
              "stderr": "", "success": True}
    assert dispatch._egress_block_reason(result) is None


def test_run_raises_egress_blocked(monkeypatch):
    monkeypatch.setattr(dispatch.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(dispatch.tool_runner, "run",
                        lambda *a, **k: {"stdout": "no_engagement_for_host", "stderr": "", "success": True})
    with pytest.raises(dispatch._EgressBlocked):
        dispatch._run("019649b8-0000-7000-8000-000000000001", "httpx", "x", {})


def test_dispatch_reports_block_not_clean(monkeypatch):
    monkeypatch.setattr(dispatch.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(dispatch.tool_runner, "run",
                        lambda *a, **k: {"stdout": "missing_engagement_id_header", "stderr": "", "success": True})
    obs = dispatch.dispatch("019649b8-0000-7000-8000-000000000001", "aid", "nikto", "example.org")
    assert "EGRESS BLOCKED" in obs.as_text()
    # Not disguised as a clean result (these are the tools' "nothing found" summaries).
    text = obs.as_text().lower()
    for clean in ("no missing security headers reported", "no template matches", "no hits", "no waf detected"):
        assert clean not in text
