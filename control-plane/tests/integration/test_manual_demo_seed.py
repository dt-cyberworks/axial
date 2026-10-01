"""TC-MANUAL-004: the demo data behind the manual's screenshots (REQ-MANUAL-004).

The seed goes in through the real models and the real audit writer. These tests prove
it holds demo data only, that what it builds is internally consistent (the audit chain
verifies, the plan and the diff have something to show), and that it can run on an
empty database.
"""

import importlib.util
import json
import pathlib
import re
import secrets

import pytest
from sqlalchemy import func, select, text

from app.gateway.audit import verify_audit_chain
from app.models.approval import ApprovalRequest
from app.models.asset import DiscoveredAsset
from app.models.audit import AuditLog
from app.models.engagement import Engagement
from app.models.finding import Finding, FindingObservation
from app.models.scan_plan import ScanCheck, ScanSurface
from app.models.scan_run import ScanRun
from app.models.user import User

_SEED = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "manual_demo_seed.py"
_CHECKER = pathlib.Path(__file__).resolve().parents[3] / "scripts" / "check_manual.py"
LOGIN_PHRASE = secrets.token_urlsafe(18)  # a fresh one per run; nothing is ever signed in with it


def _load(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def seeded(db):
    seed = _load(_SEED, "manual_demo_seed")
    return seed.seed(db, password=LOGIN_PHRASE)


def _dump_everything(db) -> str:
    """Every text column of every table the seed fills, as one string."""
    chunks = []
    for table in ("app_user", "engagement", "scope_asset", "discovered_asset", "service", "dns_record", "finding",
                  "scan_run", "scan_surface", "scan_check", "audit_log", "agent_step", "approval_request",
                  "report", "discovered_endpoint", "tool_approval_policy"):
        for row in db.execute(text(f"SELECT t::text FROM {table} t")):
            chunks.append(row[0])
    return "\n".join(chunks)


def test_seed_holds_demo_data_only(db, seeded):
    checker = _load(_CHECKER, "check_manual")
    blob = _dump_everything(db).lower()
    for marker in checker.load_private_markers(_CHECKER.parents[1]):
        assert marker not in blob, f"private marker {marker!r} in the demo data"
    # Every address is in a documentation range, every email on a reserved domain.
    for address in re.findall(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\w|\.\d)", blob):
        assert address.startswith(("203.0.113.", "198.51.100.", "192.0.2.")) or address in {"0.0.0.0", "127.0.0.1"}, address
    for email in re.findall(r"[\w.+-]+@([\w.-]+\.[a-z]{2,})", blob):
        assert email in {"example.com", "example.org", "example.net"}, email


def test_seed_creates_users_of_every_state(db, seeded):
    states = {(u.role, u.status) for u in db.scalars(select(User))}
    assert ("admin", "active") in states
    assert ("operator", "active") in states
    assert ("operator", "disabled") in states
    assert ("operator", "invited") in states
    invited = db.scalar(select(User).where(User.status == "invited"))
    assert invited.totp_secret_encrypted is None
    assert [a["email"] for a in seeded["accounts"] if a["totp_secret"]], "an account with a TOTP secret is needed to sign in"


def test_seed_audit_chains_verify(db, seeded):
    assert db.scalar(select(func.count()).select_from(AuditLog)) > 20
    for engagement in db.scalars(select(Engagement)):
        assert verify_audit_chain(db, engagement.id).ok, engagement.title


def test_seed_gives_the_run_comparison_something_to_show(db, seeded):
    first, latest = seeded["runs"]["main_first"], seeded["runs"]["main_latest"]

    def fingerprints(run_id):
        return set(db.scalars(select(FindingObservation.fingerprint).where(FindingObservation.scan_run_id == run_id)))

    before, after = fingerprints(first), fingerprints(latest)
    assert after - before, "no new finding between the two runs"
    assert before - after, "no resolved finding between the two runs"
    assert before & after, "no persisting finding between the two runs"


def test_seed_covers_every_finding_state_and_a_lens_explanation(db, seeded):
    main = seeded["engagements"]["main"]
    findings = list(db.scalars(select(Finding).where(Finding.engagement_id == main)))
    assert {f.status for f in findings} >= {"open", "resolved", "accepted_risk", "false_positive"}
    assert {f.severity for f in findings} == {"critical", "high", "medium", "low", "info"}
    assert any((f.evidence or {}).get("lens_agent") for f in findings)
    assert any(f.is_kev for f in findings)


def test_seed_plan_shows_ran_skipped_and_partial_checks(db, seeded):
    run = seeded["runs"]["main_latest"]
    states = {c.state for c in db.scalars(select(ScanCheck).where(ScanCheck.scan_run_id == run))}
    assert {"complete", "partial", "skipped"} <= states
    classes = {s.service_class for s in db.scalars(select(ScanSurface).where(ScanSurface.scan_run_id == run))}
    assert {"web", "web_alias"} <= classes


def test_seed_gives_every_engagement_an_owner_and_shows_two_different_owners(db, seeded):
    owners = {e.owner_user_id for e in db.scalars(select(Engagement))}
    assert None not in owners and len(owners) == 2  # the console can show a read-only view of someone else's


def test_seed_has_a_running_run_and_a_draft_but_no_pending_approval(db, seeded):
    running = db.get(ScanRun, seeded["runs"]["retail_running"])
    assert running.state == "running" and running.current_tool
    assert db.get(Engagement, seeded["engagements"]["draft"]).status == "draft"
    # The console shows the approval popup on every page, so the seed must not leave one behind.
    assert db.scalars(select(ApprovalRequest)).all() == []


def test_a_pending_approval_can_be_added_on_its_own(db, seeded):
    seed = _load(_SEED, "manual_demo_seed")
    approval_id = seed.add_pending_approval(
        db, engagement_id=seeded["engagements"]["retail"], scan_run_id=seeded["runs"]["retail_running"])
    request = db.get(ApprovalRequest, approval_id)
    assert request.state == "requested" and request.tool_call["tool"] == "http_request"
    assert request.tool_call["scan_run_id"] == seeded["runs"]["retail_running"]
    assert not _load(_CHECKER, "check_manual").private_content(json.dumps(request.tool_call))


def test_seed_audit_shows_allowed_and_denied_calls(db, seeded):
    main = seeded["engagements"]["main"]
    rows = list(db.scalars(select(AuditLog).where(AuditLog.engagement_id == main)))
    assert {r.decision for r in rows if r.action in ("tool_call", "tool_execution")} >= {"ALLOW", "DENY"}
    assert any(r.actor == "agent" for r in rows)
    json.dumps([r.payload for r in rows])  # every payload is plain JSON


def test_seed_scope_has_allow_deny_and_a_range(db, seeded):
    main = seeded["engagements"]["main"]
    rows = db.execute(text("SELECT rule, asset_type FROM scope_asset WHERE engagement_id = :e"), {"e": main}).all()
    assert {r[0] for r in rows} == {"allow", "deny"}
    assert "cidr" in {r[1] for r in rows}


def test_seed_assets_include_a_takeover_candidate(db, seeded):
    values = set(db.scalars(select(DiscoveredAsset.value)))
    assert "old-blog.example.com" in values
    flagged = db.execute(text("SELECT count(*) FROM dns_record WHERE takeover_suspected")).scalar()
    assert flagged == 1
