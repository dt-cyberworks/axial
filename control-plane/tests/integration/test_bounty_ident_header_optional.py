"""GitHub issue #32: REQ-AUTH-006's 2026-08-12 amendment made a bug-bounty
program's identification header optional (e.g. Port of Antwerp-Bruges on
Intigriti identifies researchers out-of-band, no header at all) -
worker/app/tool_runner_client.py's injection call sites were updated for
this, but scan_readiness.evaluate() and the Scope Gateway's authorize()
still hard-required a header, making the shipped feature unusable end-to-
end for exactly the program it was built for."""

from __future__ import annotations

import datetime as dt

from tests.integration.owners import make_owner
from app.gateway.authorize import ToolCall, authorize
from app.models.engagement import BountyProgram, Engagement, ScopeAsset, ToolGrant
from app.scan_readiness import evaluate


def _bounty_engagement(db, *, with_program: bool, ident_header_value: str | None = None) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        owner_user_id=make_owner(db).id,
        title="Bounty ident-optional test", source="bug_bounty", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
    )
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(
        engagement_id=eng.id, rule="allow", asset_type="domain",
        value="target.example.test", active_allowed=True, authorization_verified=True,
    ))
    db.add(ToolGrant(engagement_id=eng.id, tool_category="fingerprint", mode="active", requires_manual_approval=False))
    if with_program:
        db.add(BountyProgram(
            engagement_id=eng.id, platform="intigriti", program_ref="portofantwerp",
            automation_allowed=True, ai_testing_allowed=False, max_rps=2.0, max_concurrency=2,
            ident_header_name="X-Bug-Bounty", ident_header_value=ident_header_value,
        ))
    db.commit()
    db.refresh(eng)
    return eng


def _call(eng: Engagement) -> ToolCall:
    return ToolCall(
        engagement_id=eng.id, tool="httpx", category="fingerprint",
        mode="active", target="target.example.test", args={"method": "GET"},
    )


# --- scan_readiness.evaluate() -------------------------------------------

def test_readiness_is_ready_with_a_header_less_program(db):
    eng = _bounty_engagement(db, with_program=True, ident_header_value=None)
    r = evaluate(db, eng.id)
    assert r.ready is True
    assert not any(b.code in ("bounty_ident_missing", "bounty_program_missing") for b in r.blockers)


def test_readiness_still_blocks_when_no_program_row_exists_at_all(db):
    eng = _bounty_engagement(db, with_program=False)
    r = evaluate(db, eng.id)
    assert r.ready is False
    assert any(b.code == "bounty_program_missing" for b in r.blockers)


def test_readiness_is_ready_with_a_configured_header_unchanged(db):
    eng = _bounty_engagement(db, with_program=True, ident_header_value="researcher-handle")
    r = evaluate(db, eng.id)
    assert r.ready is True


# --- Scope Gateway authorize() --------------------------------------------

def test_gateway_allows_an_otherwise_valid_call_with_a_header_less_program(db):
    eng = _bounty_engagement(db, with_program=True, ident_header_value=None)
    decision = authorize(db, _call(eng))
    assert decision.allowed is True


def test_gateway_still_denies_when_no_program_row_exists_at_all(db):
    """Regression guard (issue #32's own acceptance criteria): prog is None
    must remain a hard failure - only the 'row exists, header unset' case
    is relaxed. (Caught by the PRE-EXISTING step-3 bounty_program_missing
    check, not the now-removed dead step-7 code that used to duplicate it.)"""
    eng = _bounty_engagement(db, with_program=False)
    decision = authorize(db, _call(eng))
    assert decision.allowed is False
    assert decision.reason == "bounty_program_missing"


def test_gateway_allows_a_call_with_a_configured_header_unchanged(db):
    eng = _bounty_engagement(db, with_program=True, ident_header_value="researcher-handle")
    decision = authorize(db, _call(eng))
    assert decision.allowed is True
