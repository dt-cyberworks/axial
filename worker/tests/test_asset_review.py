"""TC-ASSETREVIEW-001/002/006: worker-seitiges Gate.

Verifiziert asset_review.gate(): No-Op wenn nicht opt-in, filtert die
discovered-Liste bei einer positiven Entscheidung, und faellt bei
Ablauf/Cancel/Erstellungsfehler fail-closed auf None (der Aufrufer MUSS dann
abbrechen - siehe pipeline.py)."""

from __future__ import annotations

from app.tasks import asset_review


def _discovered():
    return [
        {"asset_id": "a1", "value": "good.example.com"},
        {"asset_id": "a2", "value": "bad.example.com"},
    ]


def test_gate_is_noop_when_not_required(monkeypatch):
    monkeypatch.setattr(asset_review.client, "asset_review_required", lambda eid: False)
    called = []
    monkeypatch.setattr(asset_review.client, "create_asset_review", lambda *a, **k: called.append(1) or {})
    out = asset_review.gate("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", _discovered())
    assert out == _discovered()
    assert called == []


def test_gate_is_noop_when_nothing_discovered(monkeypatch):
    monkeypatch.setattr(asset_review.client, "asset_review_required", lambda eid: True)
    called = []
    monkeypatch.setattr(asset_review.client, "create_asset_review", lambda *a, **k: called.append(1) or {})
    out = asset_review.gate("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", [])
    assert out == []
    assert called == []  # keine Kandidaten -> keine Pause noetig


def test_gate_filters_discovered_list_on_submitted_decision(monkeypatch):
    monkeypatch.setattr(asset_review.client, "asset_review_required", lambda eid: True)
    monkeypatch.setattr(asset_review.client, "create_asset_review", lambda *a, **k: {"id": "rev-1"})
    monkeypatch.setattr(asset_review.client, "is_cancel_requested", lambda rid: False)
    monkeypatch.setattr(asset_review.client, "get_asset_review",
                        lambda rid: {"state": "submitted", "excluded_values": ["bad.example.com"]})

    out = asset_review.gate("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", _discovered())

    assert out == [{"asset_id": "a1", "value": "good.example.com"}]


def test_gate_fails_closed_on_expired(monkeypatch):
    monkeypatch.setattr(asset_review.client, "asset_review_required", lambda eid: True)
    monkeypatch.setattr(asset_review.client, "create_asset_review", lambda *a, **k: {"id": "rev-1"})
    monkeypatch.setattr(asset_review.client, "is_cancel_requested", lambda rid: False)
    monkeypatch.setattr(asset_review.client, "get_asset_review", lambda rid: {"state": "expired"})

    out = asset_review.gate("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", _discovered())

    assert out is None


def test_gate_fails_closed_on_cancel(monkeypatch):
    monkeypatch.setattr(asset_review.client, "asset_review_required", lambda eid: True)
    monkeypatch.setattr(asset_review.client, "create_asset_review", lambda *a, **k: {"id": "rev-1"})
    monkeypatch.setattr(asset_review.client, "is_cancel_requested", lambda rid: True)

    out = asset_review.gate("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", _discovered())

    assert out is None


def test_gate_candidates_carry_the_real_asset_type(monkeypatch):
    """REQ-CIDRDISC-003: an ip-typed discovered asset must produce an
    asset_type="ip" candidate, not a hardcoded "domain" - control-plane's
    decide_asset_review creates the excluded-candidate deny row with exactly
    this type, so a wrong value here would create a wrongly-typed deny rule
    for an IP (domain-shaped matching against an IP value)."""
    monkeypatch.setattr(asset_review.client, "asset_review_required", lambda eid: True)
    captured = {}

    def create_asset_review(engagement_id, scan_run_id, candidate_assets):
        captured["candidates"] = candidate_assets
        return {"id": "rev-1"}

    monkeypatch.setattr(asset_review.client, "create_asset_review", create_asset_review)
    monkeypatch.setattr(asset_review.client, "is_cancel_requested", lambda rid: False)
    monkeypatch.setattr(asset_review.client, "get_asset_review", lambda rid: {"state": "submitted", "excluded_values": []})

    discovered = [
        {"asset_id": "a1", "value": "good.example.com", "asset_type": "domain"},
        {"asset_id": "a2", "value": "203.0.113.5", "asset_type": "ip"},
        # a legacy caller that omits asset_type entirely must still default
        # to "domain" (mirrors control-plane's own candidate.get(...) fallback).
        {"asset_id": "a3", "value": "legacy.example.com"},
    ]

    asset_review.gate("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", discovered)

    by_value = {c["value"]: c["asset_type"] for c in captured["candidates"]}
    assert by_value["good.example.com"] == "domain"
    assert by_value["203.0.113.5"] == "ip"
    assert by_value["legacy.example.com"] == "domain"


def test_gate_fails_closed_when_creation_fails(monkeypatch):
    monkeypatch.setattr(asset_review.client, "asset_review_required", lambda eid: True)

    def boom(*a, **k):
        raise RuntimeError("control-plane unreachable")
    monkeypatch.setattr(asset_review.client, "create_asset_review", boom)

    out = asset_review.gate("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", _discovered())

    assert out is None
