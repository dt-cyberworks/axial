import datetime as dt

from tests.integration.owners import make_owner
from app.api import findings as findings_api
from app.models.asset import DiscoveredAsset, Service
from app.models.audit import AuditLog
from app.models.engagement import Engagement
from app.models.finding import Finding


# REQ-LENS-005: "complete" now means all four sections, so a stop with fewer is flagged (the backstop for providers that do
# not say why they stopped). The text that used to stand here, "complete answer", has no sections.
COMPLETE = (
    "## What it is\nA missing header.\n\n## Where it was found\napp.example.com:443.\n\n"
    "## Why it matters\nBrowsers apply fewer protections.\n\n## What to do\n- Set the header."
)


def _seed_finding(db):
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        owner_user_id=make_owner(db).id,
        title="Lens test",
        source="own_domain",
        status="active",
        authorized_from=now - dt.timedelta(hours=1),
        authorized_until=now + dt.timedelta(hours=1),
    )
    db.add(eng)
    db.flush()
    asset = DiscoveredAsset(
        engagement_id=eng.id,
        asset_type="domain",
        value="app.example.com",
        in_scope=True,
        discovered_via="test",
    )
    db.add(asset)
    db.flush()
    service = Service(
        asset_id=asset.id,
        port=443,
        protocol="https",
        transport="tcp",
        product="nginx",
        version="1.24",
    )
    db.add(service)
    db.flush()
    finding = Finding(
        engagement_id=eng.id,
        asset_id=asset.id,
        service_id=service.id,
        category="misconfig",
        title="Missing Security Headers",
        cve_ids=[],
        confidence="validated",
        status="open",
        severity="low",
        risk_score=37.5,
        evidence={"tool": "nikto", "missing_headers": ["content-security-policy"]},
        fingerprint="lens-test-finding",
    )
    db.add(finding)
    db.commit()
    return eng, finding


def test_lens_agent_generates_and_caches_explanation(db, monkeypatch):
    eng, finding = _seed_finding(db)
    calls = []

    def fake_lens_agent(db_session, context):
        calls.append(context)
        assert context["title"] == "Missing Security Headers"
        assert context["target"]["asset_value"] == "app.example.com"
        assert context["evidence"]["missing_headers"] == ["content-security-policy"]
        explanation = (
            "## What it is\n"
            "A missing browser security header.\n\n"
            "## What to do\n"
            "Set the header on the affected endpoint."
        )
        return explanation, "test-model", False

    monkeypatch.setattr(findings_api, "_call_lens_agent", fake_lens_agent)

    first = findings_api.explain_finding_with_lens(eng.id, finding.id, db)
    assert first.source == "llm"
    assert "What it is" in first.explanation
    assert first.truncated is False
    assert calls and len(calls) == 1

    db.refresh(finding)
    assert finding.evidence["lens_agent"]["model"] == "test-model"
    assert finding.evidence["lens_agent"]["truncated"] is False
    assert "Set the header" in finding.evidence["lens_agent"]["explanation"]

    monkeypatch.setattr(findings_api, "_call_lens_agent", lambda *_: (_ for _ in ()).throw(AssertionError("should use cache")))
    second = findings_api.explain_finding_with_lens(eng.id, finding.id, db)
    assert second.source == "cached"
    assert second.explanation == first.explanation
    assert second.truncated is False

    audit = db.query(AuditLog).filter(AuditLog.engagement_id == eng.id, AuditLog.actor == "lens_agent").all()
    assert len(audit) == 1
    assert audit[0].decision == "ALLOW"
    assert audit[0].reason == "finding_explained"


def test_lens_agent_flags_a_truncated_response_and_caches_the_flag(db, monkeypatch):
    """GitHub issue #14: a real BREACH/testssl finding was observed cut off
    mid-sentence with "What to do" never appearing, and no indication to the
    operator that anything was missing - finish_reason == "length" must be
    surfaced, not silently treated as a complete explanation."""
    eng, finding = _seed_finding(db)

    def fake_truncated(db_session, context):
        return "## What it is\nA missing header, cut off mid-sent", "test-model", True

    monkeypatch.setattr(findings_api, "_call_lens_agent", fake_truncated)

    first = findings_api.explain_finding_with_lens(eng.id, finding.id, db)
    assert first.truncated is True

    db.refresh(finding)
    assert finding.evidence["lens_agent"]["truncated"] is True

    # GitHub #88 / REQ-LENS-005 replaces what used to follow here. A cut-off analysis was served from the cache for good
    # ("should use cache"), so the operator could never get a complete one. It is kept for display, flagged, and is
    # NOT final: the next request asks the provider again (tests/integration/test_lens_analysis_completeness.py).
    asked_again = []
    monkeypatch.setattr(findings_api, "_call_lens_agent", lambda *_: asked_again.append(1) or fake_truncated(*_))
    second = findings_api.explain_finding_with_lens(eng.id, finding.id, db)
    assert asked_again == [1], "a cut-off analysis must not be served from the cache"
    assert second.source == "llm"
    assert second.truncated is True


def test_lens_agent_call_extracts_finish_reason_from_the_provider_response(db, monkeypatch):
    """Unlike the two tests above (which monkeypatch _call_lens_agent itself),
    this exercises the real function's finish_reason parsing against a
    provider-shaped response, proving the extraction logic itself is correct."""
    import httpx

    monkeypatch.setattr(
        findings_api, "get_llm_config",
        lambda db_session: type("Cfg", (), {
            "is_usable": True, "base_url": "https://llm.example.test/v1",
            "model": "test-model", "api_key": "key",
        })(),
    )

    class FakeResponse:
        status_code = 200
        def raise_for_status(self):
            pass
        def json(self):
            return {"choices": [{"message": {"content": "partial answer, cut off"}, "finish_reason": "length"}]}

    class FakeClient:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, *a, **k): return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)

    result = findings_api._call_lens_agent(db, {"title": "x"})

    assert result.explanation == "partial answer, cut off"
    assert result.truncated is True


def test_lens_agent_call_finish_reason_stop_is_not_truncated(db, monkeypatch):
    import httpx

    monkeypatch.setattr(
        findings_api, "get_llm_config",
        lambda db_session: type("Cfg", (), {
            "is_usable": True, "base_url": "https://llm.example.test/v1",
            "model": "test-model", "api_key": "key",
        })(),
    )

    class FakeResponse:
        status_code = 200
        def raise_for_status(self):
            pass
        def json(self):
            return {"choices": [{"message": {"content": COMPLETE}, "finish_reason": "stop"}]}

    class FakeClient:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, *a, **k): return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)

    result = findings_api._call_lens_agent(db, {"title": "x"})

    assert result.explanation == COMPLETE
    assert result.truncated is False
