"""TC-ASSETREVIEW-001..005: Post-Discovery Asset Review Gate.

Deckt die control-plane-seitige Haelfte ab: Opt-in-Default, Review-Erstellung
pausiert den Lauf, Abwahl erzeugt eine ECHTE, vom Gateway durchgesetzte
deny-Regel, die Pruefung kann Scope nur einschraenken (nie erweitern), und
Scope-Regeln bleiben nach Erstellung sichtbar/entfernbar.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi import HTTPException

from app.api.engagements import (
    _delete_engagement_dependents,
    decide_asset_review,
    delete_scope_asset,
    list_asset_reviews,
    list_scope_assets,
)
from app.api.internal import asset_review_required, create_asset_review, internal_get_asset_review
from app.gateway.authorize import ToolCall, authorize
from app.models.asset import DiscoveredAsset
from app.models.asset_review import AssetReviewRequest
from app.models.engagement import ScopeAsset
from app.models.scan_run import ScanRun
from app.schemas.asset_review import AssetReviewDecisionIn
from app.schemas.internal import AssetReviewCreateIn


def _scan_run(db, engagement_id) -> ScanRun:
    run = ScanRun(engagement_id=engagement_id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


# --- TC-ASSETREVIEW-001: opt-in default ------------------------------------

def test_review_not_required_by_default(db, lab_engagement):
    assert asset_review_required(lab_engagement.id, db)["required"] is False


def test_review_required_when_enabled(db, lab_engagement):
    lab_engagement.asset_review_enabled = True
    db.commit()
    assert asset_review_required(lab_engagement.id, db)["required"] is True


# --- TC-ASSETREVIEW-002: creation pauses the run; candidates match ---------

def test_create_review_pauses_run_and_stores_candidates(db, lab_engagement):
    run = _scan_run(db, lab_engagement.id)
    candidates = [{"asset_id": str(uuid.uuid4()), "value": "metasploitable2", "asset_type": "domain"}]

    resp = create_asset_review(lab_engagement.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)

    db.refresh(run)
    assert run.state == "waiting_approval"
    assert run.state_reason == "asset_review_pending"

    review = db.get(AssetReviewRequest, resp["id"])
    assert review.state == "pending"
    assert review.candidate_assets == candidates


def test_create_review_is_idempotent_per_run(db, lab_engagement):
    run = _scan_run(db, lab_engagement.id)
    candidates = [{"asset_id": str(uuid.uuid4()), "value": "juice-shop", "asset_type": "domain"}]
    first = create_asset_review(lab_engagement.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)
    second = create_asset_review(lab_engagement.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)
    assert first["id"] == second["id"]


def test_decide_resumes_run(db, lab_engagement, test_user):
    run = _scan_run(db, lab_engagement.id)
    candidates = [{"asset_id": str(uuid.uuid4()), "value": "metasploitable2", "asset_type": "domain"}]
    resp = create_asset_review(lab_engagement.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)

    decide_asset_review(lab_engagement.id, resp["id"], AssetReviewDecisionIn(excluded_values=[]), db, user=test_user)

    db.refresh(run)
    assert run.state == "running"
    assert run.state_reason is None


# --- TC-ASSETREVIEW-003: deselection creates a real, enforced deny rule ---

def _call(eng, tool="httpx", target="orphan-subdomain.example", category="fingerprint"):
    return ToolCall(engagement_id=eng.id, tool=tool, category=category, mode="active", target=target, args={})


def test_deselection_creates_deny_and_gateway_enforces_it(db, lab_engagement, test_user):
    asset = DiscoveredAsset(
        engagement_id=lab_engagement.id, asset_type="domain", value="orphan-subdomain.example",
        in_scope=True, discovered_via="crt.sh",
    )
    db.add(asset)
    # An allow rule that structurally matches (poor DNS management scenario).
    db.add(ScopeAsset(engagement_id=lab_engagement.id, rule="allow", asset_type="wildcard",
                       value="*.example", active_allowed=True))
    db.commit()

    run = _scan_run(db, lab_engagement.id)
    candidates = [{"asset_id": str(asset.id), "value": "orphan-subdomain.example", "asset_type": "domain"}]
    resp = create_asset_review(lab_engagement.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)

    # Sanity: before the decision, the host would be allowed (matches the wildcard).
    assert authorize(db, _call(lab_engagement)).allowed is True

    decide_asset_review(
        lab_engagement.id, resp["id"],
        AssetReviewDecisionIn(excluded_values=["orphan-subdomain.example"]), db, user=test_user,
    )

    db.refresh(asset)
    assert asset.in_scope is False

    deny_row = db.query(ScopeAsset).filter(
        ScopeAsset.engagement_id == lab_engagement.id, ScopeAsset.rule == "deny",
        ScopeAsset.value == "orphan-subdomain.example",
    ).first()
    assert deny_row is not None

    # The REAL proof: the Scope Gateway now denies it - not just a pipeline skip.
    decision = authorize(db, _call(lab_engagement))
    assert decision.allowed is False


def test_two_reviews_excluding_the_same_value_create_only_one_deny_row(db, lab_engagement, test_user):
    value = "dup-host.example"
    for _ in range(2):
        run = _scan_run(db, lab_engagement.id)
        candidates = [{"asset_id": str(uuid.uuid4()), "value": value, "asset_type": "domain"}]
        resp = create_asset_review(lab_engagement.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)
        decide_asset_review(
            lab_engagement.id, resp["id"], AssetReviewDecisionIn(excluded_values=[value]), db, user=test_user,
        )
        # GitHub issue #18: only one running/waiting_approval scan_run per
        # engagement is now a real database invariant - a real second scan
        # only ever starts after the first reaches a terminal state, so
        # simulate that here before the loop's next iteration creates one.
        run.state = "done"
        db.add(run)
        db.commit()
    rows = db.query(ScopeAsset).filter(
        ScopeAsset.engagement_id == lab_engagement.id, ScopeAsset.rule == "deny", ScopeAsset.value == value,
    ).all()
    assert len(rows) == 1


def test_resubmitting_a_decided_review_is_rejected(db, lab_engagement, test_user):
    run = _scan_run(db, lab_engagement.id)
    candidates = [{"asset_id": str(uuid.uuid4()), "value": "metasploitable2", "asset_type": "domain"}]
    resp = create_asset_review(lab_engagement.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)
    decide_asset_review(lab_engagement.id, resp["id"], AssetReviewDecisionIn(excluded_values=[]), db, user=test_user)

    with pytest.raises(HTTPException) as exc:
        decide_asset_review(lab_engagement.id, resp["id"], AssetReviewDecisionIn(excluded_values=[]), db, user=test_user)
    assert exc.value.status_code == 409


# --- TC-ASSETREVIEW-004: the gate can only narrow scope, never widen it ---

def test_excluding_a_value_outside_the_candidate_set_is_ignored(db, lab_engagement, test_user):
    run = _scan_run(db, lab_engagement.id)
    candidates = [{"asset_id": str(uuid.uuid4()), "value": "metasploitable2", "asset_type": "domain"}]
    resp = create_asset_review(lab_engagement.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)

    review = decide_asset_review(
        lab_engagement.id, resp["id"],
        AssetReviewDecisionIn(excluded_values=["not-a-real-candidate.example"]), db, user=test_user,
    )

    assert review.excluded_values == []
    leaked = db.query(ScopeAsset).filter(ScopeAsset.value == "not-a-real-candidate.example").first()
    assert leaked is None


def test_keeping_a_candidate_creates_no_new_scope_asset_row(db, lab_engagement, test_user):
    before = db.query(ScopeAsset).filter(ScopeAsset.engagement_id == lab_engagement.id).count()
    run = _scan_run(db, lab_engagement.id)
    candidates = [{"asset_id": str(uuid.uuid4()), "value": "metasploitable2", "asset_type": "domain"}]
    resp = create_asset_review(lab_engagement.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)
    decide_asset_review(lab_engagement.id, resp["id"], AssetReviewDecisionIn(excluded_values=[]), db, user=test_user)
    after = db.query(ScopeAsset).filter(ScopeAsset.engagement_id == lab_engagement.id).count()
    assert after == before


# --- TC-ASSETREVIEW-006: internal poll lazily expires ----------------------

def test_internal_get_review_lazily_expires(db, lab_engagement):
    run = _scan_run(db, lab_engagement.id)
    review = AssetReviewRequest(
        engagement_id=lab_engagement.id, scan_run_id=run.id,
        candidate_assets=[{"asset_id": str(uuid.uuid4()), "value": "x", "asset_type": "domain"}],
        state="pending", expires_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1),
    )
    db.add(review)
    db.commit()

    out = internal_get_asset_review(review.id, db)
    assert out["state"] == "expired"


# --- TC-ASSETREVIEW-005: scope assets listable/removable post-creation ----

def test_scope_asset_delete_reverts_a_deny_and_gateway_allows_again(db, lab_engagement, test_user):
    deny = ScopeAsset(engagement_id=lab_engagement.id, rule="deny", asset_type="domain", value="metasploitable2")
    db.add(deny)
    db.commit()
    assert authorize(db, _call(lab_engagement, target="metasploitable2")).allowed is False

    delete_scope_asset(lab_engagement.id, deny.id, db, user=test_user)

    assert db.get(ScopeAsset, deny.id) is None
    assert authorize(db, _call(lab_engagement, target="metasploitable2")).allowed is True


def test_list_scope_assets_includes_new_rows(db, lab_engagement):
    before = len(list_scope_assets(lab_engagement.id, db))
    db.add(ScopeAsset(engagement_id=lab_engagement.id, rule="deny", asset_type="domain", value="another.example"))
    db.commit()
    after = list_scope_assets(lab_engagement.id, db)
    assert len(after) == before + 1


def test_engagement_delete_cleans_up_pending_asset_review(db, lab_engagement):
    """Regression: ein pending asset_review_request (FK auf scan_run) darf das
    Loeschen des Engagements nicht mit einer FK-Verletzung blockieren."""
    run = _scan_run(db, lab_engagement.id)
    candidates = [{"asset_id": str(uuid.uuid4()), "value": "metasploitable2", "asset_type": "domain"}]
    create_asset_review(lab_engagement.id, run.id, AssetReviewCreateIn(candidate_assets=candidates), db)

    # Darf nicht werfen (vorher: FK-Verletzung ueber asset_review_request.scan_run_id).
    _delete_engagement_dependents(db, lab_engagement.id)
    db.commit()

    assert db.query(AssetReviewRequest).filter(AssetReviewRequest.engagement_id == lab_engagement.id).count() == 0
