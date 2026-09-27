"""GitHub issue #35: no maximum host-discovery range existed anywhere - a
CIDR of any size (including 0.0.0.0/0) could be registered as active_allowed
with no operator-visible warning. Enforced in add_scope_asset (not the
schema) since it needs Settings.max_host_discovery_addresses."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app import config
from app.api.engagements import add_scope_asset
from app.schemas.engagement import ScopeAssetCreate


@pytest.fixture(autouse=True)
def _small_max(monkeypatch):
    """A small limit makes the test fast and the boundary easy to reason
    about, rather than actually constructing a near-65536-address network."""
    monkeypatch.setenv("MAX_HOST_DISCOVERY_ADDRESSES", "16")
    config.get_settings.cache_clear()
    yield
    config.get_settings.cache_clear()


def test_negative_a_cidr_larger_than_the_configured_maximum_is_rejected(db, lab_engagement, test_user):
    with pytest.raises(HTTPException) as exc:
        add_scope_asset(
            lab_engagement.id,
            ScopeAssetCreate(rule="allow", asset_type="cidr", value="203.0.113.0/27"),  # 32 addresses > 16
            db, user=test_user,
        )
    assert exc.value.status_code == 422


def test_a_cidr_at_or_under_the_configured_maximum_is_accepted(db, lab_engagement, test_user):
    asset = add_scope_asset(
        lab_engagement.id,
        ScopeAssetCreate(rule="allow", asset_type="cidr", value="203.0.113.0/28"),  # exactly 16 addresses
        db, user=test_user,
    )
    assert asset.value == "203.0.113.0/28"


def test_negative_the_default_production_limit_rejects_a_slash_8(db, lab_engagement, test_user, monkeypatch):
    """Regression guard for the real default (65536, a /16) - a /8
    (16,777,216 addresses) must still be rejected without an explicit
    override, proving the limit isn't accidentally a no-op."""
    monkeypatch.delenv("MAX_HOST_DISCOVERY_ADDRESSES", raising=False)
    config.get_settings.cache_clear()

    with pytest.raises(HTTPException) as exc:
        add_scope_asset(
            lab_engagement.id,
            ScopeAssetCreate(rule="allow", asset_type="cidr", value="10.0.0.0/8"),
            db, user=test_user,
        )
    assert exc.value.status_code == 422
    config.get_settings.cache_clear()


def test_max_size_check_does_not_apply_to_domain_or_ip_asset_types(db, lab_engagement, test_user):
    """The check is CIDR-specific - a plain domain/ip value has no "size" to
    bound and must be unaffected."""
    asset = add_scope_asset(
        lab_engagement.id,
        ScopeAssetCreate(rule="allow", asset_type="domain", value="unbounded-is-fine.example"),
        db, user=test_user,
    )
    assert asset.value == "unbounded-is-fine.example"
