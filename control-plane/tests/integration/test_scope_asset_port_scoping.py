"""REQ-PORTSCOPE-001/004: per-target port ranges - write-time subset
validation on scope-asset creation, and the internal scan-envelope
endpoint's per-target resolution."""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from app.api.engagements import add_scope_asset
from app.api.internal import get_scan_envelope
from app.schemas.engagement import ScopeAssetCreate


def test_scope_asset_port_range_wider_than_ceiling_is_rejected(db, lab_engagement, test_user):
    lab_engagement.tcp_port_from, lab_engagement.tcp_port_to = 1, 1024
    db.commit()

    with pytest.raises(HTTPException) as exc:
        add_scope_asset(
            lab_engagement.id,
            ScopeAssetCreate(rule="allow", asset_type="domain", value="wide.example", port_from=1, port_to=65535),
            db, user=test_user,
        )
    assert exc.value.status_code == 422


def test_scope_asset_port_range_within_the_ceiling_is_accepted(db, lab_engagement, test_user):
    lab_engagement.tcp_port_from, lab_engagement.tcp_port_to = 1, 1024
    db.commit()

    asset = add_scope_asset(
        lab_engagement.id,
        ScopeAssetCreate(rule="allow", asset_type="domain", value="narrow.example", port_from=443, port_to=443),
        db, user=test_user,
    )
    assert (asset.port_from, asset.port_to) == (443, 443)


def test_scope_asset_with_no_port_override_is_always_accepted(db, lab_engagement, test_user):
    lab_engagement.tcp_port_from, lab_engagement.tcp_port_to = 8000, 8100
    db.commit()

    asset = add_scope_asset(
        lab_engagement.id,
        ScopeAssetCreate(rule="allow", asset_type="domain", value="inherits.example"),
        db, user=test_user,
    )
    assert (asset.port_from, asset.port_to) == (None, None)


def test_scan_envelope_endpoint_resolves_the_matched_targets_own_range(db, lab_engagement, test_user):
    add_scope_asset(
        lab_engagement.id,
        ScopeAssetCreate(rule="allow", asset_type="domain", value="narrow.example", port_from=8080, port_to=8080),
        db, user=test_user,
    )
    db.commit()

    resolved = get_scan_envelope(lab_engagement.id, host="narrow.example", db=db)
    assert resolved == {"tcp_port_from": 8080, "tcp_port_to": 8080}


def test_scan_envelope_endpoint_falls_back_to_the_ceiling_for_an_unmatched_host(db, lab_engagement, test_user):
    add_scope_asset(
        lab_engagement.id,
        ScopeAssetCreate(rule="allow", asset_type="domain", value="narrow.example", port_from=8080, port_to=8080),
        db, user=test_user,
    )
    db.commit()

    resolved = get_scan_envelope(lab_engagement.id, host="somewhere-else.example", db=db)
    assert resolved == {"tcp_port_from": lab_engagement.tcp_port_from, "tcp_port_to": lab_engagement.tcp_port_to}


def test_scan_envelope_endpoint_without_host_returns_the_flat_ceiling_unchanged(db, lab_engagement):
    resolved = get_scan_envelope(lab_engagement.id, host=None, db=db)
    assert resolved == {"tcp_port_from": lab_engagement.tcp_port_from, "tcp_port_to": lab_engagement.tcp_port_to}


def test_scan_envelope_endpoint_404s_for_an_unknown_engagement(db):
    with pytest.raises(HTTPException) as exc:
        get_scan_envelope(uuid.uuid4(), host=None, db=db)
    assert exc.value.status_code == 404
