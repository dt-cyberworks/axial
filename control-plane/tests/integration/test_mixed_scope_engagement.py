"""GitHub issue #38: no single test previously drove ONE engagement
containing a domain, a direct ip, and a cidr TOGETHER through the
control-plane half of the pipeline (asset review's decide flow -> the
Scope Gateway). Mocks only genuinely external boundaries (there are none on
this side - discovery's passive-source HTTP calls are the worker's own
concern, covered by worker/tests/test_mixed_scope_discovery.py); everything
here runs against a real Postgres, mirroring the existing lab_engagement
fixture pattern from test_raw_egress_lease.py."""

from __future__ import annotations

import datetime as dt
import uuid

from tests.integration.owners import make_owner
from app.api.engagements import decide_asset_review
from app.api.internal import create_asset_review
from app.gateway.authorize import ToolCall, authorize
from app.models.engagement import BountyProgram, Engagement, ScopeAsset, ToolGrant
from app.models.scan_run import ScanRun
from app.schemas.asset_review import AssetReviewDecisionIn
from app.schemas.internal import AssetReviewCreateIn


def _mixed_engagement(db, *, source="own_domain") -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        owner_user_id=make_owner(db).id,
        title="Mixed scope test", source=source, status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
    )
    db.add(eng)
    db.flush()
    db.add_all([
        ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain",
                   value="example.test", active_allowed=True, authorization_verified=True),
        ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="ip",
                   value="198.51.100.9", active_allowed=True, authorization_verified=True),
        ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="cidr",
                   value="203.0.113.0/28", active_allowed=True, authorization_verified=True),
        # An unrelated host must never match this engagement's scope.
    ])
    for cat in ("recon", "fingerprint", "vuln"):
        db.add(ToolGrant(engagement_id=eng.id, tool_category=cat, mode="active", requires_manual_approval=False))
    db.commit()
    db.refresh(eng)
    return eng


def _scan_run(db, engagement_id) -> ScanRun:
    run = ScanRun(engagement_id=engagement_id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def test_gateway_allows_all_three_scope_types_on_the_same_mixed_engagement(db):
    eng = _mixed_engagement(db)

    for target, category in (("example.test", "fingerprint"), ("198.51.100.9", "fingerprint")):
        decision = authorize(db, ToolCall(
            engagement_id=eng.id, tool="httpx", category=category, mode="active",
            target=target, args={"method": "GET"},
        ))
        assert decision.allowed is True, f"{target} should be allowed: {decision.reason}"

    # A host inside the allowed CIDR is authorized too.
    decision = authorize(db, ToolCall(
        engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active",
        target="203.0.113.1", args={"method": "GET"},
    ))
    assert decision.allowed is True


def test_gateway_denies_an_unrelated_target_on_the_same_mixed_engagement(db):
    eng = _mixed_engagement(db)

    for target in ("evil.example.com", "198.51.100.200", "203.0.114.1"):  # different domain, IP, and CIDR
        decision = authorize(db, ToolCall(
            engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active",
            target=target, args={"method": "GET"},
        ))
        assert decision.allowed is False, f"{target} should be denied but was allowed"


def test_asset_review_decide_creates_correctly_typed_deny_rows_for_a_mixed_candidate_batch(db, test_user):
    """A single review batch spanning domain- and ip-typed candidates -
    deselecting one of each must create a deny row with THAT candidate's own
    asset_type, not a one-size-fits-all guess."""
    eng = _mixed_engagement(db)
    run = _scan_run(db, eng.id)
    candidates = [
        {"asset_id": str(uuid.uuid4()), "value": "sub.example.test", "asset_type": "domain"},
        {"asset_id": str(uuid.uuid4()), "value": "203.0.113.1", "asset_type": "ip"},
        {"asset_id": str(uuid.uuid4()), "value": "203.0.113.2", "asset_type": "ip"},
    ]
    review = create_asset_review(eng.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)

    decide_asset_review(
        eng.id, review["id"],
        AssetReviewDecisionIn(excluded_values=["sub.example.test", "203.0.113.1"]),
        db, user=test_user,
    )

    denies = {(a.asset_type, a.value) for a in db.query(ScopeAsset).filter(
        ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "deny",
    ).all()}
    assert ("domain", "sub.example.test") in denies
    assert ("ip", "203.0.113.1") in denies
    assert ("ip", "203.0.113.2") not in denies  # not excluded - must not be denied


def test_gateway_denies_exactly_the_assets_excluded_from_a_mixed_review_batch(db, test_user):
    """The end-to-end point of #38: the SAME engagement, after a mixed-type
    asset-review exclusion, is checked against the Scope Gateway directly -
    the excluded host is denied, an unexcluded sibling candidate of the SAME
    type is unaffected, and the engagement's other, untouched scope (the
    domain apex, the direct ip) still works normally."""
    eng = _mixed_engagement(db)
    run = _scan_run(db, eng.id)
    candidates = [
        {"asset_id": str(uuid.uuid4()), "value": "203.0.113.1", "asset_type": "ip"},
        {"asset_id": str(uuid.uuid4()), "value": "203.0.113.2", "asset_type": "ip"},
    ]
    review = create_asset_review(eng.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)
    decide_asset_review(eng.id, review["id"], AssetReviewDecisionIn(excluded_values=["203.0.113.1"]), db, user=test_user)

    denied_decision = authorize(db, ToolCall(
        engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active",
        target="203.0.113.1", args={"method": "GET"},
    ))
    assert denied_decision.allowed is False
    assert denied_decision.reason == "explicit_out_of_scope"

    still_allowed = authorize(db, ToolCall(
        engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active",
        target="203.0.113.2", args={"method": "GET"},
    ))
    assert still_allowed.allowed is True

    domain_still_allowed = authorize(db, ToolCall(
        engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active",
        target="example.test", args={"method": "GET"},
    ))
    assert domain_still_allowed.allowed is True


def test_bug_bounty_host_discovery_only_policy_holds_on_a_mixed_scope_engagement(db):
    """REQ-CIDRDISC-005's bug_bounty raw-nmap carve-out, re-proven together
    with the domain/ip/cidr mix rather than an ip/cidr-only engagement -
    a full/configured TCP request is still denied even though the SAME
    engagement's domain/ip targets pass the general gateway checks fine."""
    from app.gateway.raw_egress_lease import issue_raw_egress_lease

    eng = _mixed_engagement(db, source="bug_bounty")
    db.add(BountyProgram(
        engagement_id=eng.id, platform="intigriti", program_ref="mixed-scope-test",
        automation_allowed=True, ai_testing_allowed=False, max_rps=2.0, max_concurrency=2,
    ))
    db.commit()
    run = _scan_run(db, eng.id)

    host_discovery = issue_raw_egress_lease(
        db, engagement_id=eng.id, scan_run_id=run.id,
        authorized_target="203.0.113.0/28", resolved_target="203.0.113.0/28",
        phase="fingerprint", port_profile="host_discovery",
    )
    assert host_discovery.decision.allowed is True

    full_tcp = issue_raw_egress_lease(
        db, engagement_id=eng.id, scan_run_id=run.id,
        authorized_target="198.51.100.9", resolved_target="198.51.100.9",
        phase="fingerprint", port_profile="full_tcp",
    )
    assert full_tcp.decision.allowed is False
    assert full_tcp.decision.reason == "raw_nmap_not_permitted_for_bug_bounty"

    # The engagement's domain target is completely unaffected by the
    # bug_bounty raw-nmap carve-out - it never goes through this path at all.
    domain_decision = authorize(db, ToolCall(
        engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active",
        target="example.test", args={"method": "GET"},
    ))
    assert domain_decision.allowed is True
