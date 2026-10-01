"""TC-PIPE-003/005/006/008/010/015 (control plane): the persisted scan plan, its
fencing, the scan-depth setting and the public read-out.

Runs through the real HTTP routing (internal token / operator session), because
ownership and the internal token are router-level dependencies."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from app import auth_service, scan_plan
from app.config import get_settings
from app.db.base import get_db
from app.main import app
from app.models.engagement import BountyProgram, Engagement
from app.models.scan_plan import ScanCheck, ScanSurface
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
from app.scan_lifecycle import start_scan_run


def _client(engine) -> TestClient:
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    return TestClient(app)


@pytest.fixture
def api(engine, db):
    client = _client(engine)
    yield client
    app.dependency_overrides.clear()


def _internal():
    return {"X-ASM-Internal-Token": get_settings().internal_api_token}


def _user(db, email):
    user = User(email=email, display_name="U", role="operator", status="active",
                must_change_password=False, password_hash=hash_secret("irrelevant-not-used"))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _bearer(db, user):
    raw, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    return {"Authorization": f"Bearer {raw}"}


def _engagement(db, owner, **over):
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(title="E", source="own_domain", status="active", owner_user_id=owner.id,
                     authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1), **over)
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _run(db, eng, attempt=1):
    run = start_scan_run(db, eng.id)
    run.attempt = attempt
    db.commit()
    return run


def _plan_body(host="a.example", checks=None, **surface):
    return {"surfaces": [{
        "host": host, "ip": "192.0.2.1", "port": 443, "scheme": "https", "service_class": "web",
        "profile": ["nginx"], "fingerprint": {"url": f"https://{host}", "status_code": 200, "tech": ["Nginx"],
                                                "headers": {"server": "nginx", "Set-Cookie": "sid=secret", "cookie": "x", "authorization": "y"}},
        "checks": checks if checks is not None else [
            {"check_id": "wafw00f", "tool": "wafw00f", "state": "planned", "reason": "web", "budget_s": 90},
            {"check_id": "screenshot", "tool": "screenshot", "state": "skipped", "reason": "switch_off"},
            {"check_id": "nuclei:endpoints", "tool": "nuclei", "state": "planned", "reason": "crawled_endpoints",
             "args": {"mode": "endpoints"}, "depends_on": "katana"},
        ],
        **surface,
    }]}


def _post(api, run, body, attempt=1):
    return api.post(f"/internal/scan-runs/{run.id}/plan", json=body, params={"attempt": attempt}, headers=_internal())


# --- storing the plan (REQ-PIPE-003) --------------------------------------------------------------

def test_req_pipe_003_a_stored_plan_keeps_every_check_with_its_reason_and_order(api, db, test_user):
    eng = _engagement(db, test_user)
    run = _run(db, eng)
    r = _post(api, run, _plan_body())
    assert r.status_code == 201 and r.json() == {"surfaces_created": 1, "checks_created": 3}
    plan = api.get(f"/internal/scan-runs/{run.id}/plan", headers=_internal()).json()
    (surface,) = plan["surfaces"]
    checks = surface["checks"]
    assert [c["check_id"] for c in checks] == ["wafw00f", "screenshot", "nuclei:endpoints"]
    assert [c["seq"] for c in checks] == sorted(c["seq"] for c in checks) and len({c["seq"] for c in checks}) == 3
    assert (checks[1]["state"], checks[1]["reason"]) == ("skipped", "switch_off") and checks[1]["finished_at"]
    assert checks[2]["depends_on"] == "katana" and checks[2]["args"] == {"mode": "endpoints"}
    assert plan["summary"] == {"checks": 3, "by_state": {"planned": 2, "skipped": 1}, "surfaces": 1}


def test_req_pipe_008_storing_the_same_plan_again_never_resets_progress(api, db, test_user):
    eng = _engagement(db, test_user)
    run = _run(db, eng)
    _post(api, run, _plan_body())
    check = db.scalars(select(ScanCheck).where(ScanCheck.check_id == "wafw00f")).one()
    api.patch(f"/internal/scan-checks/{check.id}", json={"state": "complete", "attempt": 1}, headers=_internal())
    again = _post(api, run, _plan_body())
    assert again.json() == {"surfaces_created": 0, "checks_created": 0}
    db.expire_all()
    assert db.get(ScanCheck, check.id).state == "complete"


def test_req_pipe_003_a_later_plan_adds_only_what_is_new(api, db, test_user):
    eng = _engagement(db, test_user)
    run = _run(db, eng)
    _post(api, run, _plan_body(checks=[{"check_id": "a", "tool": "wafw00f", "state": "planned", "reason": "r"}]))
    r = _post(api, run, _plan_body(checks=[{"check_id": "a", "tool": "wafw00f", "state": "planned", "reason": "r"},
                                          {"check_id": "b", "tool": "ffuf", "state": "planned", "reason": "r"}]))
    assert r.json()["checks_created"] == 1
    seqs = [c.seq for c in db.scalars(select(ScanCheck).order_by(ScanCheck.seq))]
    assert seqs == [1, 2]


def test_negative_req_pipe_002_session_bearing_headers_are_never_stored_or_shown(api, db, test_user):
    eng = _engagement(db, test_user)
    run = _run(db, eng)
    _post(api, run, _plan_body())
    surface = db.scalars(select(ScanSurface)).one()
    assert set(surface.fingerprint["headers"]) == {"server"}
    stored = str(surface.fingerprint).lower()
    assert "secret" not in stored and "set-cookie" not in stored
    public = api.get(f"/engagements/{eng.id}/scan-runs/{run.id}/plan", headers=_bearer(db, test_user)).json()
    assert "headers" not in public["surfaces"][0]["fingerprint"], "response headers are not part of the public shape"


def test_scrub_fingerprint_bounds_and_cleans_headers():
    cleaned = scan_plan.scrub_fingerprint({"headers": {f"h{i}": "v" * 900 for i in range(100)} | {"Proxy-Authorization": "z"}})
    assert len(cleaned["headers"]) == 60 and all(len(v) <= 300 for v in cleaned["headers"].values())
    assert "proxy-authorization" not in cleaned["headers"]
    assert scan_plan.scrub_fingerprint({}) == {} and scan_plan.scrub_fingerprint(None) == {}


# --- fencing (REQ-RESUME-002 for the plan) -------------------------------------------------------------

def test_negative_a_replaced_worker_can_neither_store_nor_update_the_plan(api, db, test_user):
    eng = _engagement(db, test_user)
    run = _run(db, eng, attempt=2)
    stale = _post(api, run, _plan_body(), attempt=1)
    assert stale.status_code == 409 and "superseded" in stale.text
    assert _post(api, run, _plan_body(), attempt=2).status_code == 201
    check = db.scalars(select(ScanCheck)).first()
    refused = api.patch(f"/internal/scan-checks/{check.id}", json={"state": "running", "attempt": 1}, headers=_internal())
    assert refused.status_code == 409
    surface = db.scalars(select(ScanSurface)).one()
    assert api.patch(f"/internal/scan-surfaces/{surface.id}", json={"profile": ["x"], "attempt": 1}, headers=_internal()).status_code == 409


def test_negative_the_plan_cannot_be_written_to_a_finished_run(api, db, test_user):
    eng = _engagement(db, test_user)
    run = _run(db, eng)
    _post(api, run, _plan_body())
    check = db.scalars(select(ScanCheck)).first()
    run.state = "done"
    db.commit()
    assert _post(api, run, _plan_body(host="b.example")).status_code == 409
    assert api.patch(f"/internal/scan-checks/{check.id}", json={"state": "complete", "attempt": 1}, headers=_internal()).status_code == 409


def test_negative_the_internal_plan_endpoints_need_the_internal_token(api, db, test_user):
    eng = _engagement(db, test_user)
    run = _run(db, eng)
    assert api.post(f"/internal/scan-runs/{run.id}/plan", json=_plan_body()).status_code == 403
    assert api.get(f"/internal/scan-runs/{run.id}/plan").status_code == 403
    assert api.patch(f"/internal/scan-checks/{uuid.uuid4()}", json={"state": "running"}).status_code == 403
    assert api.get(f"/internal/engagements/{eng.id}/scan-settings").status_code == 403


# --- check updates (REQ-PIPE-006) ---------------------------------------------------------------------------

def test_req_pipe_006_a_check_moves_through_its_states_and_records_the_outcome(api, db, test_user):
    eng = _engagement(db, test_user)
    run = _run(db, eng)
    _post(api, run, _plan_body())
    check = db.scalars(select(ScanCheck).where(ScanCheck.check_id == "wafw00f")).one()
    running = api.patch(f"/internal/scan-checks/{check.id}", json={"state": "running", "attempt": 1}, headers=_internal()).json()
    assert running["state"] == "running" and running["attempt"] == 1 and running["started_at"] and not running["finished_at"]
    done = api.patch(f"/internal/scan-checks/{check.id}", headers=_internal(), json={
        "state": "partial", "attempt": 1, "findings": 2, "duration_s": 12.5,
        "outcome_summary": {"detail": "budget_reached", "templates": 400}, "budget_s": 300, "args": {"mode": "select"},
    }).json()
    assert (done["state"], done["findings"], done["duration_s"], done["budget_s"]) == ("partial", 2, 12.5, 300)
    assert done["finished_at"] and done["outcome_summary"] == {"detail": "budget_reached", "templates": 400}
    again = api.patch(f"/internal/scan-checks/{check.id}", json={"state": "running", "attempt": 1}, headers=_internal()).json()
    assert again["attempt"] == 2 and again["finished_at"] is None, "a check that runs again counts the attempt"


@pytest.mark.parametrize("state", ["planned", "bogus", "Complete", ""])
def test_negative_req_pipe_006_only_the_known_outcome_states_are_accepted(api, db, test_user, state):
    eng = _engagement(db, test_user)
    run = _run(db, eng)
    _post(api, run, _plan_body())
    check = db.scalars(select(ScanCheck)).first()
    assert api.patch(f"/internal/scan-checks/{check.id}", json={"state": state, "attempt": 1}, headers=_internal()).status_code == 422


def test_negative_a_plan_can_only_be_created_planned_or_skipped(api, db, test_user):
    eng = _engagement(db, test_user)
    run = _run(db, eng)
    bad = _plan_body(checks=[{"check_id": "a", "tool": "t", "state": "complete", "reason": "r"}])
    assert _post(api, run, bad).status_code == 422
    no_reason = _plan_body(checks=[{"check_id": "a", "tool": "t", "state": "planned", "reason": ""}])
    assert _post(api, run, no_reason).status_code == 422, "every check names its reason"
    bad_class = _plan_body(service_class="mystery")
    assert _post(api, run, bad_class).status_code == 422
    assert _post(api, run, _plan_body(checks=[{"check_id": "a", "tool": "t", "state": "planned", "reason": "r", "budget_s": 99999}])).status_code == 422


def test_req_pipe_002_a_surface_profile_can_be_refined_by_the_technology_check(api, db, test_user):
    eng = _engagement(db, test_user)
    run = _run(db, eng)
    _post(api, run, _plan_body())
    surface = db.scalars(select(ScanSurface)).one()
    r = api.patch(f"/internal/scan-surfaces/{surface.id}", headers=_internal(),
                  json={"profile": ["nginx", "nextcloud", "nginx"], "attempt": 1})
    assert r.json()["profile"] == ["nginx", "nextcloud"]


# --- the public plan (REQ-PIPE-010) ----------------------------------------------------------------------------

def test_req_pipe_010_the_owner_reads_the_plan_of_a_run(api, db, test_user):
    eng = _engagement(db, test_user, scan_profile="thorough")
    run = _run(db, eng)
    _post(api, run, _plan_body())
    body = api.get(f"/engagements/{eng.id}/scan-runs/{run.id}/plan", headers=_bearer(db, test_user)).json()
    assert body["scan_profile"] == "thorough" and body["state"] == "running"
    (surface,) = body["surfaces"]
    assert surface["host"] == "a.example" and surface["service_class"] == "web" and surface["profile"] == ["nginx"]
    assert [c["check_id"] for c in surface["checks"]] == ["wafw00f", "screenshot", "nuclei:endpoints"]
    assert {"reason", "state", "duration_s", "findings"} <= set(surface["checks"][0])


def test_negative_req_pipe_010_a_mismatched_run_or_unknown_run_is_404_and_any_user_may_read_the_plan(api, db, test_user):
    eng = _engagement(db, test_user)
    other_eng = _engagement(db, test_user)
    run = _run(db, eng)
    _post(api, run, _plan_body())
    stranger = _user(db, "stranger@example.com")
    # REQ-IAM-022: every signed-in user reads every engagement's plan.
    assert api.get(f"/engagements/{eng.id}/scan-runs/{run.id}/plan", headers=_bearer(db, stranger)).status_code == 200
    assert api.get(f"/engagements/{other_eng.id}/scan-runs/{run.id}/plan", headers=_bearer(db, test_user)).status_code == 404
    assert api.get(f"/engagements/{eng.id}/scan-runs/{uuid.uuid4()}/plan", headers=_bearer(db, test_user)).status_code == 404
    assert api.get(f"/engagements/{eng.id}/scan-runs/{run.id}/plan").status_code == 401


def test_req_pipe_010_an_engagement_delete_takes_its_plan_with_it(api, db, engine, test_user):
    eng = _engagement(db, test_user)
    run = _run(db, eng)
    _post(api, run, _plan_body())
    run.state = "done"
    db.commit()
    r = api.delete(f"/engagements/{eng.id}", headers=_bearer(db, test_user))
    assert r.status_code in (200, 204)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM scan_check")).scalar() == 0
        assert conn.execute(text("SELECT count(*) FROM scan_surface")).scalar() == 0


# --- scan depth (REQ-PIPE-005) -------------------------------------------------------------------------------------

def test_req_pipe_005_the_default_depth_is_standard(api, db, test_user):
    eng = _engagement(db, test_user)
    assert eng.scan_profile == "standard"
    assert api.get(f"/engagements/{eng.id}", headers=_bearer(db, test_user)).json()["scan_profile"] == "standard"


def test_req_pipe_005_the_depth_is_set_at_creation_and_changed_at_any_status_and_audited(api, db, test_user):
    headers = _bearer(db, test_user)
    now = dt.datetime.now(dt.timezone.utc)
    created = api.post("/engagements", headers=headers, json={
        "title": "T", "authorized_from": now.isoformat(), "authorized_until": (now + dt.timedelta(days=1)).isoformat(),
        "scan_profile": "thorough"}).json()
    assert created["scan_profile"] == "thorough"
    eng = _engagement(db, test_user)
    assert eng.status == "active"
    r = api.patch(f"/engagements/{eng.id}", headers=headers, json={"scan_profile": "thorough"})
    assert r.status_code == 200 and r.json()["scan_profile"] == "thorough"
    audit = db.execute(text("SELECT payload FROM audit_log WHERE engagement_id = :e AND action = 'engagement_updated'"), {"e": eng.id}).all()
    assert any((row[0] or {}).get("scan_profile") == "thorough" for row in audit)
    back = api.patch(f"/engagements/{eng.id}", headers=headers, json={"scan_profile": "standard"})
    assert back.json()["scan_profile"] == "standard"


@pytest.mark.parametrize("value", ["deep", "THOROUGH", "", "full", 1])
def test_negative_req_pipe_005_only_standard_and_thorough_exist(api, db, test_user, value):
    eng = _engagement(db, test_user)
    assert api.patch(f"/engagements/{eng.id}", headers=_bearer(db, test_user), json={"scan_profile": value}).status_code == 422


def test_negative_req_pipe_005_a_null_depth_changes_nothing(api, db, test_user):
    eng = _engagement(db, test_user, scan_profile="thorough")
    r = api.patch(f"/engagements/{eng.id}", headers=_bearer(db, test_user), json={"scan_profile": None, "title": "New"})
    assert r.json()["scan_profile"] == "thorough" and r.json()["title"] == "New"


def test_req_pipe_005_a_run_records_the_depth_it_started_with(db, test_user):
    eng = _engagement(db, test_user, scan_profile="thorough")
    run = start_scan_run(db, eng.id)
    assert run.scan_profile == "thorough"
    run.state = "done"
    db.commit()
    eng.scan_profile = "standard"
    db.commit()
    assert db.get(ScanRun, run.id).scan_profile == "thorough", "a later change does not rewrite history"
    assert start_scan_run(db, eng.id).scan_profile == "standard"


def test_negative_req_pipe_005_the_depth_never_changes_scope_grants_or_switches(api, db, test_user):
    eng = _engagement(db, test_user, crawling_enabled=False, oob_enabled=False, screenshots_enabled=False)
    api.patch(f"/engagements/{eng.id}", headers=_bearer(db, test_user), json={"scan_profile": "thorough"})
    db.expire_all()
    fresh = db.get(Engagement, eng.id)
    assert (fresh.crawling_enabled, fresh.oob_enabled, fresh.screenshots_enabled) == (False, False, False)
    assert fresh.status == "active" and fresh.authorized_until == eng.authorized_until


# --- settings for the worker (REQ-PIPE-005/015) -------------------------------------------------------------------------

def test_req_pipe_015_the_worker_gets_the_depth_and_at_most_two_parallel_checks(api, db, test_user):
    eng = _engagement(db, test_user, scan_profile="thorough")
    r = api.get(f"/internal/engagements/{eng.id}/scan-settings", headers=_internal())
    body = r.json()
    assert (body["scan_profile"], body["max_parallel_checks"]) == ("thorough", 2)
    # Tools that are not installed or off by default are listed; the scan's own tools are not.
    assert not {"testssl", "nuclei", "ffuf", "katana", "httpx", "wafw00f"} & set(body["disabled_tools"])


def test_req_pipe_015_a_bounty_programs_own_concurrency_cap_can_only_lower_it(api, db, test_user):
    eng = _engagement(db, test_user)
    db.add(BountyProgram(engagement_id=eng.id, platform="h1", program_ref="p", automation_allowed=True,
                         ai_testing_allowed=False, max_concurrency=1))
    db.commit()
    assert api.get(f"/internal/engagements/{eng.id}/scan-settings", headers=_internal()).json()["max_parallel_checks"] == 1
    prog = db.scalars(select(BountyProgram)).one()
    prog.max_concurrency = 50
    db.commit()
    assert api.get(f"/internal/engagements/{eng.id}/scan-settings", headers=_internal()).json()["max_parallel_checks"] == 2


def test_negative_req_pipe_015_settings_of_an_unknown_engagement_are_404(api):
    assert api.get(f"/internal/engagements/{uuid.uuid4()}/scan-settings", headers=_internal()).status_code == 404


# --- REQ-PIPE-018: what the agent is told about the run's checks ------------------------------------

def _in_scope_asset(db, eng, value):
    from app.models.asset import DiscoveredAsset
    asset = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=value, in_scope=True, discovered_via="passive-osint")
    db.add(asset)
    db.commit()
    return asset


def _agent_checks(db, eng, host="a.example"):
    from app.api.internal import agent_context
    return next(h for h in agent_context(eng.id, db)["hosts"] if h["host"] == host)["checks"]


def _mark(api, db, check_id, state):
    row = db.scalars(select(ScanCheck).where(ScanCheck.check_id == check_id)).one()
    api.patch(f"/internal/scan-checks/{row.id}", json={"state": state, "attempt": 1}, headers=_internal())


def test_req_pipe_018_the_agent_context_lists_finished_and_skipped_checks_with_the_ffuf_wordlist(api, db, test_user):
    eng = _engagement(db, test_user)
    _in_scope_asset(db, eng, "a.example")
    run = _run(db, eng)
    _post(api, run, _plan_body(checks=[
        {"check_id": "wafw00f", "tool": "wafw00f", "state": "planned", "reason": "web"},
        {"check_id": "ffuf", "tool": "ffuf", "state": "planned", "reason": "web", "args": {"wordlist": "quickhits"}},
        {"check_id": "ffuf:deep", "tool": "ffuf", "state": "planned", "reason": "thorough", "args": {"wordlist": "raft-medium-dirs"}},
        {"check_id": "katana", "tool": "katana", "state": "planned", "reason": "switch_on"},
        {"check_id": "screenshot", "tool": "screenshot", "state": "skipped", "reason": "switch_off"},
    ]))
    _mark(api, db, "wafw00f", "complete")
    _mark(api, db, "ffuf", "complete")
    _mark(api, db, "ffuf:deep", "partial")
    assert _agent_checks(db, eng) == [
        {"port": 443, "check_id": "wafw00f", "tool": "wafw00f", "state": "complete"},
        {"port": 443, "check_id": "ffuf", "tool": "ffuf", "state": "complete", "wordlist": "quickhits"},
        {"port": 443, "check_id": "ffuf:deep", "tool": "ffuf", "state": "partial", "wordlist": "raft-medium-dirs"},
        {"port": 443, "check_id": "screenshot", "tool": "screenshot", "state": "skipped", "reason": "switch_off"},
    ], "katana is still planned: to come, not done"


def test_req_pipe_018_a_host_without_a_plan_or_without_a_running_run_gets_an_empty_list(api, db, test_user):
    eng = _engagement(db, test_user)
    _in_scope_asset(db, eng, "a.example")
    assert _agent_checks(db, eng) == [], "no run"
    run = _run(db, eng)
    _post(api, run, _plan_body(checks=[{"check_id": "wafw00f", "tool": "wafw00f", "state": "planned", "reason": "web"}]))
    _mark(api, db, "wafw00f", "complete")
    assert len(_agent_checks(db, eng)) == 1
    db.get(ScanRun, run.id).state = "done"
    db.commit()
    assert _agent_checks(db, eng) == [], "a finished run is not the current run"


def test_negative_req_pipe_018_nothing_the_target_returned_reaches_the_agent_context(api, db, test_user):
    import json
    from app.api.internal import agent_context
    eng = _engagement(db, test_user)
    _in_scope_asset(db, eng, "a.example")
    run = _run(db, eng)
    _post(api, run, _plan_body(checks=[
        {"check_id": "ffuf", "tool": "ffuf", "state": "planned", "reason": "web", "args": {"wordlist": "quickhits", "path": "/FUZZ"}},
    ]))
    _mark(api, db, "ffuf", "complete")
    body = json.dumps(agent_context(eng.id, db), default=str)
    assert "sid=secret" not in body and "authorization" not in body.lower().replace("authorization_", "")
    (item,) = _agent_checks(db, eng)
    assert set(item) <= {"port", "check_id", "tool", "state", "wordlist", "reason"}
    assert "path" not in item and "args" not in item


def test_negative_req_pipe_018_a_non_string_wordlist_is_left_out_and_never_crashes(api, db, test_user):
    eng = _engagement(db, test_user)
    _in_scope_asset(db, eng, "a.example")
    run = _run(db, eng)
    _post(api, run, _plan_body(checks=[
        {"check_id": "ffuf", "tool": "ffuf", "state": "planned", "reason": "web", "args": {"wordlist": ["x"]}},
        {"check_id": "nuclei:tech", "tool": "nuclei", "state": "planned", "reason": "t", "args": {"mode": "tech", "wordlist": "quickhits"}},
    ]))
    _mark(api, db, "ffuf", "complete")
    _mark(api, db, "nuclei:tech", "complete")
    items = {i["check_id"]: i for i in _agent_checks(db, eng)}
    assert "wordlist" not in items["ffuf"] and "wordlist" not in items["nuclei:tech"], "only an ffuf check carries a wordlist key"


def test_req_pipe_018_the_list_per_host_is_capped(api, db, test_user):
    eng = _engagement(db, test_user)
    _in_scope_asset(db, eng, "a.example")
    run = _run(db, eng)
    skipped = [{"check_id": f"c{i}", "tool": "wafw00f", "state": "skipped", "reason": "x" * 300} for i in range(40)]
    body = _plan_body(checks=skipped)
    body["surfaces"].append({**body["surfaces"][0], "port": 8443})
    assert _post(api, run, body).status_code == 201
    items = _agent_checks(db, eng)
    assert len(items) == scan_plan.AGENT_CHECKS_PER_HOST < 80
    assert all(len(i["reason"]) <= 80 for i in items)
