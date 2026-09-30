"""REQ-COVER-001/003/004/006/007: per-engagement switches, per-URL validation,
pipeline-only tools, stored endpoints/screenshots and their access control."""

from __future__ import annotations

import base64
import datetime as dt
import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.api import engagements as engagements_api
from app.api import internal as internal_api
from app.api.settings import SubfinderKeysIn, read_subfinder_keys, update_subfinder_keys
from app.db.base import get_db
from app.gateway.authorize import ToolCall, authorize
from app.main import app
from app.models.discovery_artifacts import DiscoveredEndpoint, WebScreenshot
from app.models.engagement import BountyProgram, Engagement
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
from app.schemas.engagement import EngagementUpdate
from app.schemas.internal import DiscoveredEndpointIn, DiscoveredEndpointsIn, WebScreenshotIn
from app.settings_store import get_subfinder_keys

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
PNG_B64 = base64.b64encode(PNG).decode()


def _call(eng, tool, category, mode="active", target="metasploitable2", args=None, phase="scan"):
    return ToolCall(
        engagement_id=eng.id, tool=tool, category=category, mode=mode, target=target,
        args=args or {}, phase=phase,
    )


def _enable(db, eng, **flags):
    for name, value in flags.items():
        setattr(eng, name, value)
    db.commit()


# --- REQ-COVER-007: switches are enforced by the gateway -------------------

def test_defaults_only_subfinder_is_on(db, lab_engagement):
    assert lab_engagement.subfinder_enabled is True
    assert lab_engagement.crawling_enabled is False
    assert lab_engagement.oob_enabled is False
    assert lab_engagement.screenshots_enabled is False


@pytest.mark.parametrize("tool,category,mode,args,reason", [
    ("katana", "fingerprint", "active", {}, "crawling_not_enabled"),
    ("nuclei", "vuln", "active", {"mode": "endpoints", "urls": ["http://metasploitable2/a?x=1"]}, "crawling_not_enabled"),
    ("nuclei", "vuln", "active", {"mode": "oob"}, "oob_not_enabled"),
    ("screenshot", "fingerprint", "active", {}, "screenshots_not_enabled"),
])
def test_negative_switch_off_denies(db, lab_engagement, tool, category, mode, args, reason):
    d = authorize(db, _call(lab_engagement, tool, category, mode, args=args))
    assert not d.allowed and d.reason == reason


@pytest.mark.parametrize("tool,category,args,flag", [
    ("katana", "fingerprint", {}, "crawling_enabled"),
    ("screenshot", "fingerprint", {}, "screenshots_enabled"),
    ("nuclei", "vuln", {"mode": "oob"}, "oob_enabled"),
    ("nuclei", "vuln", {"mode": "endpoints", "urls": ["http://metasploitable2/a?x=1"]}, "crawling_enabled"),
])
def test_switch_on_allows(db, lab_engagement, tool, category, args, flag):
    _enable(db, lab_engagement, **{flag: True})
    d = authorize(db, _call(lab_engagement, tool, category, args=args))
    assert d.allowed, d.reason


def test_negative_subfinder_switch_off_denies(db, lab_engagement):
    _enable(db, lab_engagement, subfinder_enabled=False)
    d = authorize(db, _call(lab_engagement, "subfinder", "recon", "passive"))
    assert not d.allowed and d.reason == "subfinder_not_enabled"


def test_subfinder_allowed_by_default_passive_grant(db, lab_engagement):
    d = authorize(db, _call(lab_engagement, "subfinder", "recon", "passive"))
    assert d.allowed, d.reason


def test_negative_switch_never_overrides_scope(db, lab_engagement):
    _enable(db, lab_engagement, crawling_enabled=True, screenshots_enabled=True, oob_enabled=True)
    for tool, category in (("katana", "fingerprint"), ("screenshot", "fingerprint")):
        d = authorize(db, _call(lab_engagement, tool, category, target="clean-nginx"))
        assert d.reason == "explicit_out_of_scope"
        d = authorize(db, _call(lab_engagement, tool, category, target="evil.example.com"))
        assert d.reason == "target_out_of_scope"


def test_negative_pipeline_only_tools_are_not_agent_callable(db, lab_engagement):
    _enable(db, lab_engagement, crawling_enabled=True, screenshots_enabled=True, ai_testing_allowed=True)
    run = ScanRun(engagement_id=lab_engagement.id, phase="agent", state="running")
    db.add(run)
    db.commit()
    for tool, category, mode in (("katana", "fingerprint", "active"), ("screenshot", "fingerprint", "active"),
                                 ("subfinder", "recon", "passive")):
        call = _call(lab_engagement, tool, category, mode, phase="agent")
        call.scan_run_id = run.id
        d = authorize(db, call)
        assert not d.allowed and d.reason == "tool_not_agent_callable"


def test_negative_switch_off_denied_even_with_grants_and_approval_off(db, lab_engagement):
    # The grants of the lab engagement would allow the category; only the switch stops it.
    d = authorize(db, _call(lab_engagement, "katana", "fingerprint"))
    assert d.reason == "crawling_not_enabled"


# --- REQ-COVER-003: per-URL validation of the endpoints pass ---------------

def _endpoints_call(eng, urls):
    return _call(eng, "nuclei", "vuln", args={"mode": "endpoints", "urls": urls})


@pytest.mark.parametrize("url", [
    "http://clean-nginx/admin?a=1",              # denied host
    "http://evil.example.com/x",                 # not in scope
    "http://user:pw@metasploitable2/x",          # userinfo
])
def test_negative_endpoint_outside_scope_denies_whole_call(db, lab_engagement, url):
    _enable(db, lab_engagement, crawling_enabled=True)
    d = authorize(db, _endpoints_call(lab_engagement, ["http://metasploitable2/ok?a=1", url]))
    assert not d.allowed
    assert d.reason in ("endpoint_out_of_scope", "unsafe_arguments")


@pytest.mark.parametrize("urls", [
    [], "http://metasploitable2/", ["ftp://metasploitable2/x"], ["http://metasploitable2/" + "a" * 3000],
    ["http://metasploitable2/x"] * 51, [42],
])
def test_negative_malformed_endpoint_lists_are_unsafe(db, lab_engagement, urls):
    _enable(db, lab_engagement, crawling_enabled=True)
    d = authorize(db, _endpoints_call(lab_engagement, urls))
    assert not d.allowed and d.reason == "unsafe_arguments"


@pytest.mark.parametrize("args", [
    {"mode": "bogus"}, {"mode": "oob", "urls": ["http://metasploitable2/x"]}, {"mode": "oob", "tags": ["cve"]},
    {"mode": "main", "urls": ["http://metasploitable2/x"]}, {"mode": "endpoints", "urls": ["http://metasploitable2/x"], "tags": ["cve"]},
    {"mode": "oob", "iserver": "attacker.example"}, {"mode": "oob", "itoken": "x"},
    {"mode": "oob", "part": "../../etc"}, {"mode": "oob", "part": "all"}, {"mode": "oob", "part": "generic"}, {"mode": "headless", "part": "generic_a"},
    {"part": "../../etc"}, {"part": "generic_a"}, {"part": "misconfig"}, {"part": "all"}, {"mode": "takeover", "part": "other"},
    # REQ-PIPE-004: network/ and javascript/ templates never run against a web surface.
    {"part": "network_javascript"}, {"part": "network"}, {"part": "javascript"},
])
def test_negative_nuclei_extended_args_rejected(db, lab_engagement, args):
    _enable(db, lab_engagement, crawling_enabled=True, oob_enabled=True)
    d = authorize(db, _call(lab_engagement, "nuclei", "vuln", args=args))
    assert not d.allowed and d.reason == "unsafe_arguments"


@pytest.mark.parametrize("args", [
    {}, {"mode": "tech"}, {"mode": "headless"}, {"mode": "takeover"},
    {"mode": "select", "group": "generic"}, {"mode": "select", "group": "generic", "shard": "1/6"},
    {"mode": "select", "group": "all", "shard": "12/12"},
    {"mode": "select", "group": "products", "products": ["nextcloud", "nginx", "php"]},
    {"mode": "select", "group": "products", "shard": "1/2", "products": ["nextcloud_server", "apache", "asp.net"]},
])
def test_req_pipe_004_index_based_nuclei_selections_are_allowed(db, lab_engagement, args):
    # Mirrors worker/tests/test_scan_pipeline_v2.py (the worker only ever sends these shapes).
    d = authorize(db, _call(lab_engagement, "nuclei", "vuln", args=args))
    assert d.allowed, d.reason


@pytest.mark.parametrize("args", [
    # No path, tag or template can be named by a caller: only a group, a shard and product keys.
    {"mode": "select"}, {"mode": "select", "group": "everything"}, {"mode": "select", "group": "../../etc"},
    {"mode": "select", "group": "generic", "shard": "0/3"}, {"mode": "select", "group": "generic", "shard": "4/3"},
    {"mode": "select", "group": "generic", "shard": "1/65"}, {"mode": "select", "group": "generic", "shard": "a/b"},
    {"mode": "select", "group": "generic", "shard": "1/3; id"},
    {"mode": "select", "group": "products"}, {"mode": "select", "group": "products", "products": []},
    {"mode": "select", "group": "products", "products": "nginx"},
    {"mode": "select", "group": "products", "products": ["ng inx"]},
    {"mode": "select", "group": "products", "products": ["../etc/passwd"]},
    {"mode": "select", "group": "products", "products": ["a; rm -rf /"]},
    {"mode": "select", "group": "products", "products": ["$(id)"]},
    {"mode": "select", "group": "products", "products": ["Nginx"]},
    {"mode": "select", "group": "products", "products": ["a" * 41]},
    {"mode": "select", "group": "products", "products": [f"p{i}" for i in range(25)]},
    {"mode": "select", "group": "generic", "products": ["nginx"]},
    {"mode": "select", "group": "all", "products": ["nginx"]},
    {"mode": "select", "group": "generic", "tags": ["cve"]},
    {"mode": "select", "group": "generic", "urls": ["http://metasploitable2/x"]},
    {"mode": "select", "group": "generic", "part": "other"},
    {"mode": "select", "group": "generic", "template": "/etc/passwd"},
    # Values of the wrong type are refused, never a crash.
    {"mode": ["select"]}, {"mode": {"a": 1}}, {"mode": "select", "group": ["generic"]}, {"mode": "select", "group": {"x": 1}},
    {"mode": "select", "group": "generic", "shard": ["1/2"]}, {"mode": "select", "group": "generic", "shard": 1},
    # The selection keys mean nothing on any other mode.
    {"group": "generic"}, {"shard": "1/2"}, {"products": ["nginx"]},
    {"mode": "tech", "group": "generic"}, {"mode": "headless", "shard": "1/2"},
    {"mode": "takeover", "products": ["nginx"]}, {"mode": "oob", "group": "generic"},
    {"mode": "endpoints", "urls": ["http://metasploitable2/x"], "group": "generic"},
    # The former directory parts are gone (REQ-PIPE-004).
    {"part": "other"}, {"part": "http_misconfiguration"}, {"part": "cves_2020_2021"}, {"part": "network_javascript"},
])
def test_negative_req_pipe_004_nuclei_selection_arguments_are_rejected(db, lab_engagement, args):
    _enable(db, lab_engagement, crawling_enabled=True, oob_enabled=True)
    d = authorize(db, _call(lab_engagement, "nuclei", "vuln", args=args))
    assert not d.allowed and d.reason == "unsafe_arguments"


def test_negative_katana_and_screenshot_take_no_arguments(db, lab_engagement):
    _enable(db, lab_engagement, crawling_enabled=True, screenshots_enabled=True)
    for tool in ("katana", "screenshot"):
        d = authorize(db, _call(lab_engagement, tool, "fingerprint", args={"depth": 99}))
        assert not d.allowed and d.reason == "unsafe_arguments"


# --- REQ-COVER-006: screenshots and bug-bounty identification --------------

def test_negative_screenshot_denied_when_bounty_program_requires_identification(db):
    from app.models.engagement import ScopeAsset, ToolGrant
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="bounty", source="bug_bounty", status="active", screenshots_enabled=True,
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(hours=1),
    )
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="bounty.example",
                      active_allowed=True, authorization_verified=True))
    db.add(ToolGrant(engagement_id=eng.id, tool_category="fingerprint", mode="active", requires_manual_approval=False))
    db.add(BountyProgram(engagement_id=eng.id, platform="h1", program_ref="p", automation_allowed=True,
                         ai_testing_allowed=False, ident_header_value="researcher-42"))
    db.commit()
    d = authorize(db, _call(eng, "screenshot", "fingerprint", target="bounty.example"))
    assert not d.allowed and d.reason == "screenshots_not_permitted_for_bounty"


# --- API: switches ---------------------------------------------------------

def test_switches_editable_while_active_and_audited(db, lab_engagement, test_user):
    out = engagements_api.update_engagement(
        lab_engagement.id, EngagementUpdate(crawling_enabled=True, subfinder_enabled=False), db, test_user,
    )
    assert out.crawling_enabled is True and out.subfinder_enabled is False


def test_null_switch_value_is_ignored(db, lab_engagement, test_user):
    engagements_api.update_engagement(
        lab_engagement.id, EngagementUpdate.model_validate({"oob_enabled": None, "title": "t2"}), db, test_user,
    )
    db.refresh(lab_engagement)
    assert lab_engagement.oob_enabled is False


# --- internal: discovery options, endpoints, screenshots -------------------

def test_discovery_options_reflect_switches(db, lab_engagement):
    assert internal_api.discovery_options(lab_engagement.id, db) == {
        "subfinder": True, "crawling": False, "oob": False, "screenshots": False,
    }
    _enable(db, lab_engagement, crawling_enabled=True)
    assert internal_api.discovery_options(lab_engagement.id, db)["crawling"] is True


def _endpoints(*urls, source="katana"):
    return DiscoveredEndpointsIn(endpoints=[DiscoveredEndpointIn(url=u, source=source, param_names=["a"]) for u in urls])


def test_store_endpoints_drops_out_of_scope_and_denied(db, lab_engagement):
    _enable(db, lab_engagement, crawling_enabled=True)
    out = internal_api.store_discovered_endpoints(lab_engagement.id, _endpoints(
        "http://metasploitable2/a?x=1", "http://clean-nginx/b", "http://evil.example.com/c",
        "http://u:p@metasploitable2/d", "ftp://metasploitable2/e",
    ), db)
    assert out == {"stored": 1, "dropped": 4}
    rows = db.scalars(select(DiscoveredEndpoint).where(DiscoveredEndpoint.engagement_id == lab_engagement.id)).all()
    assert [r.host for r in rows] == ["metasploitable2"]


def test_store_endpoints_is_idempotent_and_merges_params(db, lab_engagement):
    _enable(db, lab_engagement, crawling_enabled=True)
    internal_api.store_discovered_endpoints(lab_engagement.id, _endpoints("http://metasploitable2/a?x=1"), db)
    body = DiscoveredEndpointsIn(endpoints=[DiscoveredEndpointIn(url="http://metasploitable2/a?x=1", source="katana", param_names=["b"])])
    out = internal_api.store_discovered_endpoints(lab_engagement.id, body, db)
    assert out["stored"] == 0
    row = db.scalar(select(DiscoveredEndpoint).where(DiscoveredEndpoint.engagement_id == lab_engagement.id))
    assert row.param_names == ["a", "b"]


def test_negative_store_endpoints_requires_switch(db, lab_engagement):
    with pytest.raises(HTTPException) as exc:
        internal_api.store_discovered_endpoints(lab_engagement.id, _endpoints("http://metasploitable2/a"), db)
    assert exc.value.status_code == 409


def test_agent_context_lists_endpoints(db, lab_engagement):
    from app.models.asset import DiscoveredAsset
    _enable(db, lab_engagement, crawling_enabled=True)
    db.add(DiscoveredAsset(engagement_id=lab_engagement.id, asset_type="domain", value="metasploitable2", in_scope=True,
                          discovered_via="test"))
    db.commit()
    internal_api.store_discovered_endpoints(lab_engagement.id, _endpoints("http://metasploitable2/a?x=1"), db)
    ctx = internal_api.agent_context(lab_engagement.id, db)
    assert ctx["hosts"][0]["endpoints"] == [{"method": "GET", "url": "http://metasploitable2/a?x=1", "params": ["a"]}]


def test_store_screenshot_roundtrip_and_replace(db, lab_engagement):
    _enable(db, lab_engagement, screenshots_enabled=True)
    body = WebScreenshotIn(url="http://metasploitable2/", png_base64=PNG_B64)
    internal_api.store_web_screenshot(lab_engagement.id, body, db)
    internal_api.store_web_screenshot(lab_engagement.id, body, db)
    rows = db.scalars(select(WebScreenshot).where(WebScreenshot.engagement_id == lab_engagement.id)).all()
    assert len(rows) == 1 and bytes(rows[0].content) == PNG and rows[0].byte_size == len(PNG)


@pytest.mark.parametrize("url,b64,status", [
    ("http://metasploitable2/", base64.b64encode(b"<html>not a png</html>").decode(), 422),
    ("http://metasploitable2/", "!!!not-base64!!!", 422),
    ("http://clean-nginx/", PNG_B64, 422),
    ("http://evil.example.com/", PNG_B64, 422),
    ("http://metasploitable2/", base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * 2_100_000).decode(), 413),
])
def test_negative_store_screenshot_rejects(db, lab_engagement, url, b64, status):
    _enable(db, lab_engagement, screenshots_enabled=True)
    with pytest.raises(HTTPException) as exc:
        internal_api.store_web_screenshot(lab_engagement.id, WebScreenshotIn(url=url, png_base64=b64), db)
    assert exc.value.status_code == status


def test_negative_store_screenshot_requires_switch(db, lab_engagement):
    with pytest.raises(HTTPException) as exc:
        internal_api.store_web_screenshot(
            lab_engagement.id, WebScreenshotIn(url="http://metasploitable2/", png_base64=PNG_B64), db)
    assert exc.value.status_code == 409


def test_delete_engagement_removes_artifacts(db, lab_engagement):
    _enable(db, lab_engagement, crawling_enabled=True, screenshots_enabled=True)
    internal_api.store_discovered_endpoints(lab_engagement.id, _endpoints("http://metasploitable2/a"), db)
    internal_api.store_web_screenshot(
        lab_engagement.id, WebScreenshotIn(url="http://metasploitable2/", png_base64=PNG_B64), db)
    engagements_api._delete_engagement_dependents(db, lab_engagement.id)
    db.flush()
    assert db.scalars(select(DiscoveredEndpoint).where(DiscoveredEndpoint.engagement_id == lab_engagement.id)).all() == []
    assert db.scalars(select(WebScreenshot).where(WebScreenshot.engagement_id == lab_engagement.id)).all() == []


# --- public API: ownership on endpoints/screenshots ------------------------

def _client(engine) -> TestClient:
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override_get_db
    return TestClient(app)


def _user(db, email) -> User:
    u = User(email=email, display_name="t", role="operator", status="active", must_change_password=False,
             password_hash=hash_secret("irrelevant-not-used"))
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def test_screenshot_image_ownership_and_headers(engine, db, lab_engagement, test_user):
    _enable(db, lab_engagement, screenshots_enabled=True, crawling_enabled=True)
    internal_api.store_discovered_endpoints(lab_engagement.id, _endpoints("http://metasploitable2/a"), db)
    internal_api.store_web_screenshot(
        lab_engagement.id, WebScreenshotIn(url="http://metasploitable2/", png_base64=PNG_B64), db)
    shot = db.scalar(select(WebScreenshot).where(WebScreenshot.engagement_id == lab_engagement.id))
    stranger = _user(db, f"stranger-{uuid.uuid4().hex[:8]}@example.com")
    owner_tok, _ = auth_service.create_session(db, test_user, ip=None, user_agent=None)
    other_tok, _ = auth_service.create_session(db, stranger, ip=None, user_agent=None)
    client = _client(engine)
    try:
        ok = client.get(f"/engagements/{lab_engagement.id}/screenshots/{shot.id}/image",
                        headers={"Authorization": f"Bearer {owner_tok}"})
        assert ok.status_code == 200 and ok.content == PNG
        assert ok.headers["content-type"] == "image/png"
        assert ok.headers["x-content-type-options"] == "nosniff"
        assert "no-store" in ok.headers["cache-control"]
        assert len(client.get(f"/engagements/{lab_engagement.id}/endpoints",
                              headers={"Authorization": f"Bearer {owner_tok}"}).json()) == 1
        # Negative: another user's engagement is a 404 on every route; no credentials is 401.
        for path in ("endpoints", "screenshots", f"screenshots/{shot.id}/image"):
            assert client.get(f"/engagements/{lab_engagement.id}/{path}",
                              headers={"Authorization": f"Bearer {other_tok}"}).status_code == 404
            assert client.get(f"/engagements/{lab_engagement.id}/{path}").status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_negative_screenshot_id_of_another_engagement_is_404(engine, db, lab_engagement, test_user):
    now = dt.datetime.now(dt.timezone.utc)
    mine = Engagement(title="mine", source="own_domain", status="active", owner_user_id=test_user.id,
                      authorized_from=now, authorized_until=now + dt.timedelta(days=1))
    db.add(mine)
    _enable(db, lab_engagement, screenshots_enabled=True)
    internal_api.store_web_screenshot(
        lab_engagement.id, WebScreenshotIn(url="http://metasploitable2/", png_base64=PNG_B64), db)
    shot = db.scalar(select(WebScreenshot).where(WebScreenshot.engagement_id == lab_engagement.id))
    tok, _ = auth_service.create_session(db, test_user, ip=None, user_agent=None)
    client = _client(engine)
    try:
        r = client.get(f"/engagements/{mine.id}/screenshots/{shot.id}/image", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 404
    finally:
        app.dependency_overrides.clear()


# --- REQ-COVER-001: subfinder provider keys --------------------------------

def test_subfinder_keys_encrypted_never_returned(db):
    out = update_subfinder_keys(SubfinderKeysIn(keys={"virustotal": "vt-secret-123"}), db)
    assert {"name": "virustotal", "key_set": True} in out.providers
    assert "vt-secret-123" not in str(read_subfinder_keys(db).model_dump())
    assert get_subfinder_keys(db) == {"virustotal": "vt-secret-123"}
    from app.models.app_setting import AppSetting
    raw = str(db.get(AppSetting, "subfinder_config").value)
    assert "vt-secret-123" not in raw
    # omitted = unchanged, "" = removed
    update_subfinder_keys(SubfinderKeysIn(keys={"shodan": "sh-1"}), db)
    assert set(get_subfinder_keys(db)) == {"virustotal", "shodan"}
    update_subfinder_keys(SubfinderKeysIn(keys={"virustotal": ""}), db)
    assert set(get_subfinder_keys(db)) == {"shodan"}


@pytest.mark.parametrize("keys", [
    {"not-a-provider": "x"}, {"virustotal": "a: b\nevil: [x]"}, {"virustotal": "has space"}, {"virustotal": "x" * 300},
])
def test_negative_subfinder_keys_rejected(db, keys):
    with pytest.raises(HTTPException) as exc:
        update_subfinder_keys(SubfinderKeysIn(keys=keys), db)
    assert exc.value.status_code == 422
