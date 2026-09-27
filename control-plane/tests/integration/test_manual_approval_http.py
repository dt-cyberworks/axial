"""Manuelle Freigabe fuer zustandsaendernde http_request (REQ-APPROVAL-001/002/003).

Deckt die Gateway-Entscheidung, die internen Worker-Endpunkte (Status pollen +
Einmal-Konsum) und die Negativpfade ab (R4: Positiv- UND Negativtests)."""

from __future__ import annotations

import datetime as dt

from app.api.internal import (internal_claim_approval, internal_complete_approval, internal_get_approval)
from app.gateway.authorize import ToolCall, authorize
from app.models.approval import ApprovalRequest
from app.schemas.internal import ApprovalExecutionResult
from fastapi import HTTPException
import pytest


def _write_call(eng, with_risk=True, target="metasploitable2", method="POST", path="/login"):
    return ToolCall(
        engagement_id=eng.id, tool="http_request", category="vuln", mode="active",
        target=target, args={"method": method, "path": path, "body": "next=/"},
        rationale="confirm redirect",
        risk={"level": "medium", "description": "submits a login form; no stored data changes"} if with_risk else None,
    )


# --- Gateway-Entscheidung ---------------------------------------------------

def test_write_with_risk_creates_pending_approval(db, lab_engagement):
    d = authorize(db, _write_call(lab_engagement))
    assert not d.allowed and d.is_pending and d.approval_request_id is not None


def test_write_without_risk_is_denied(db, lab_engagement):
    d = authorize(db, _write_call(lab_engagement, with_risk=False))
    assert not d.allowed and not d.is_pending and d.reason == "risk_statement_required"


def test_out_of_scope_write_denied_not_pending(db, lab_engagement):
    """NEGATIV: ein zustandsaendernder Request auf ein deny-Ziel wird HART geblockt,
    nie zur Freigabe angeboten."""
    d = authorize(db, _write_call(lab_engagement, target="clean-nginx"))
    assert not d.allowed and not d.is_pending and d.reason == "explicit_out_of_scope"


# --- Interne Worker-Endpunkte (Status + Einmal-Konsum) ----------------------

def test_claim_reauthorizes_and_is_single_use(db, lab_engagement):
    d = authorize(db, _write_call(lab_engagement))
    aid = d.approval_request_id

    assert internal_get_approval(aid, db)["state"] == "requested"
    denied = internal_claim_approval(aid, db)
    assert not denied.allowed

    ap = db.get(ApprovalRequest, aid)
    ap.state = "approved"
    db.commit()

    claim = internal_claim_approval(aid, db)
    assert claim.allowed
    assert claim.tool_call == ap.tool_call
    assert db.get(ApprovalRequest, aid).state == "executing"

    second = internal_claim_approval(aid, db)
    assert not second.allowed
    assert "approval_not_claimable:executing" in second.reason

    done = internal_complete_approval(aid, ApprovalExecutionResult(success=True), db)
    assert done["state"] == "consumed"
    with pytest.raises(HTTPException) as exc:
        internal_complete_approval(aid, ApprovalExecutionResult(success=True), db)
    assert exc.value.status_code == 409


def test_claim_rechecks_current_scope(db, lab_engagement):
    from app.models.engagement import ScopeAsset

    d = authorize(db, _write_call(lab_engagement))
    ap = db.get(ApprovalRequest, d.approval_request_id)
    ap.state = "approved"
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id, rule="deny", asset_type="domain",
        value="metasploitable2", active_allowed=False,
    ))
    db.commit()

    claim = internal_claim_approval(ap.id, db)
    assert not claim.allowed
    assert claim.reason == "explicit_out_of_scope"
    assert db.get(ApprovalRequest, ap.id).state == "execution_failed"


def test_expired_approval_reported_as_expired(db, lab_engagement):
    d = authorize(db, _write_call(lab_engagement))
    ap = db.get(ApprovalRequest, d.approval_request_id)
    ap.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    db.commit()
    assert internal_get_approval(d.approval_request_id, db)["state"] == "expired"


# --- REQ-APPROVAL-005: configurable timeout -------------------------------

def test_created_approval_uses_the_resolved_campaign_timeout(db, lab_engagement):
    """_create_approval_request must use the resolved (campaign-override ->
    global -> 900s built-in) timeout, not the old hardcoded 15 minutes."""
    lab_engagement.approval_timeout_seconds_override = 300
    db.commit()

    before = dt.datetime.now(dt.timezone.utc)
    d = authorize(db, _write_call(lab_engagement))
    ap = db.get(ApprovalRequest, d.approval_request_id)

    delta = (ap.expires_at - before).total_seconds()
    assert 295 <= delta <= 305, f"expected ~300s expiry, got {delta}s"


def test_short_timeout_override_genuinely_expires_and_cannot_be_claimed(db, lab_engagement):
    """Negative test (required for R3): a short-timeout override cannot be
    exploited into a permanently-pending, still-claimable approval - once
    expired, claiming it is denied exactly like the normal expiry path."""
    lab_engagement.approval_timeout_seconds_override = 60  # the configured floor
    db.commit()

    d = authorize(db, _write_call(lab_engagement))
    ap = db.get(ApprovalRequest, d.approval_request_id)

    # Simulate the configured window having elapsed.
    ap.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
    db.commit()

    assert internal_get_approval(d.approval_request_id, db)["state"] == "expired"
    denied = internal_claim_approval(d.approval_request_id, db)
    assert not denied.allowed
    assert db.get(ApprovalRequest, d.approval_request_id).state == "expired"
