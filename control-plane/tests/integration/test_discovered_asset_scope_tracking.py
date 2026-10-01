"""REQ-ASSETREVIEW-009 / GitHub issue #33: discovered_asset.in_scope follows the
current scope in both directions.

Discovery re-classifies every value against the current scope on every run.
Before the fix the upsert could only promote a row, so a value that fell out
of scope stayed in the agent's in-scope pool (list_discovered_assets with
in_scope=true) forever.
"""

from __future__ import annotations

import datetime as dt

from tests.integration.owners import make_owner
from app.api.internal import add_discovered_asset, list_discovered_assets
from app.models.asset import DiscoveredAsset
from app.models.engagement import Engagement
from app.schemas.internal import DiscoveredAssetIn


def _engagement(db) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(owner_user_id=make_owner(db).id, title="Scope tracking", source="own_domain", status="active",
                     authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1))
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _upsert(db, eng, value: str, in_scope: bool, via: str = "passive-osint") -> str:
    return str(add_discovered_asset(eng.id, DiscoveredAssetIn(
        asset_type="domain", value=value, discovered_via=via, in_scope=in_scope), db)["id"])


def _agent_pool(db, eng) -> set[str]:
    return {a["value"] for a in list_discovered_assets(eng.id, in_scope=True, db=db)}


def test_negative_a_value_that_falls_out_of_scope_is_demoted_and_leaves_the_agent_pool(db):
    eng = _engagement(db)
    first = _upsert(db, eng, "old.example.com", True)
    assert "old.example.com" in _agent_pool(db, eng)
    second = _upsert(db, eng, "old.example.com", False)
    assert second == first  # same row, no duplicate
    assert "old.example.com" not in _agent_pool(db, eng)
    assert db.get(DiscoveredAsset, first).in_scope is False


def test_a_value_that_comes_back_into_scope_is_promoted_again(db):
    eng = _engagement(db)
    asset_id = _upsert(db, eng, "app.example.com", True)
    _upsert(db, eng, "app.example.com", False)
    _upsert(db, eng, "app.example.com", True)
    assert "app.example.com" in _agent_pool(db, eng)
    assert db.get(DiscoveredAsset, asset_id).in_scope is True


def test_demoted_values_stay_in_the_inventory(db):
    eng = _engagement(db)
    _upsert(db, eng, "legacy.example.com", True)
    _upsert(db, eng, "legacy.example.com", False)
    everything = {a["value"]: a["in_scope"] for a in list_discovered_assets(eng.id, in_scope=None, db=db)}
    assert everything == {"legacy.example.com": False}


def test_an_upsert_keeps_the_original_discovery_source(db):
    eng = _engagement(db)
    asset_id = _upsert(db, eng, "www.example.com", True, via="scope-direct")
    _upsert(db, eng, "www.example.com", False, via="known")
    assert db.get(DiscoveredAsset, asset_id).discovered_via == "scope-direct"
