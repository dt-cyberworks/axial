"""REQ-FPEFF-006: one service row per (asset, port, protocol).

Found live on int (run 019feaae-...): nmap and httpx each reported port 443
from their own angle and each inserted a row, leaving example.org with three
:443 entries and cloud.example.org with 9 service rows containing duplicates
on both 80 and 443 - inflating the customer report's asset inventory and the
attack-surface graph.
"""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi import HTTPException

from tests.integration.owners import make_owner
from app.api.internal import add_service
from app.models.asset import DiscoveredAsset, Service
from app.models.engagement import Engagement
from app.schemas.internal import ServiceIn


@pytest.fixture
def asset(db):
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        owner_user_id=make_owner(db).id,
        title="Service dedup", source="own_domain", status="active",
        authorized_from=now - dt.timedelta(days=1), authorized_until=now + dt.timedelta(days=1),
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)
    a = DiscoveredAsset(
        engagement_id=eng.id, asset_type="domain", value="target.example",
        in_scope=True, discovered_via="seed",
    )
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _count(db, asset_id, port=None) -> int:
    q = db.query(Service).filter(Service.asset_id == asset_id)
    if port is not None:
        q = q.filter(Service.port == port)
    return q.count()


def test_the_same_port_from_two_tools_yields_one_row(db, asset):
    """nmap first (transport/product), then httpx (status/title/tech)."""
    first = add_service(asset.engagement_id, ServiceIn(
        asset_id=asset.id, port=443, protocol="tcp", transport="tcp", product="nginx", version="1.24.0",
    ), db)
    second = add_service(asset.engagement_id, ServiceIn(
        asset_id=asset.id, port=443, protocol="tcp", product="nginx",
        tech_stack={"tech": ["nginx"], "title": "404 Not Found", "status": 404},
    ), db)

    assert first["id"] == second["id"]
    assert _count(db, asset.id, 443) == 1


def test_the_second_record_enriches_rather_than_blanks(db, asset):
    add_service(asset.engagement_id, ServiceIn(
        asset_id=asset.id, port=443, protocol="tcp", transport="tcp", product="nginx", version="1.24.0",
    ), db)
    add_service(asset.engagement_id, ServiceIn(
        asset_id=asset.id, port=443, protocol="tcp", product="nginx",
        tech_stack={"tech": ["nginx"], "title": "404 Not Found", "status": 404},
    ), db)

    row = db.query(Service).filter(Service.asset_id == asset.id, Service.port == 443).one()
    # The later, richer call adds its fields...
    assert row.tech_stack["status"] == 404
    # ...without discarding what the earlier one established.
    assert row.version == "1.24.0"
    assert row.transport == "tcp"


def test_negative_different_ports_stay_distinct(db, asset):
    add_service(asset.engagement_id, ServiceIn(asset_id=asset.id, port=80, protocol="tcp", product="nginx"), db)
    add_service(asset.engagement_id, ServiceIn(asset_id=asset.id, port=443, protocol="tcp", product="nginx"), db)
    assert _count(db, asset.id) == 2


def test_negative_different_protocols_on_one_port_stay_distinct(db, asset):
    """A UDP service on 443 is not the TCP one."""
    add_service(asset.engagement_id, ServiceIn(asset_id=asset.id, port=443, protocol="tcp", product="nginx"), db)
    add_service(asset.engagement_id, ServiceIn(asset_id=asset.id, port=443, protocol="udp", product="dns"), db)
    assert _count(db, asset.id, 443) == 2


def test_negative_the_same_port_on_a_different_asset_stays_distinct(db, asset):
    other = DiscoveredAsset(
        engagement_id=asset.engagement_id, asset_type="domain", value="other.example",
        in_scope=True, discovered_via="seed",
    )
    db.add(other)
    db.commit()
    db.refresh(other)

    add_service(asset.engagement_id, ServiceIn(asset_id=asset.id, port=443, protocol="tcp", product="nginx"), db)
    add_service(asset.engagement_id, ServiceIn(asset_id=other.id, port=443, protocol="tcp", product="nginx"), db)

    assert _count(db, asset.id, 443) == 1
    assert _count(db, other.id, 443) == 1


def test_repeated_identical_records_never_accumulate(db, asset):
    """A re-run must not grow the inventory."""
    for _ in range(5):
        add_service(asset.engagement_id, ServiceIn(
            asset_id=asset.id, port=443, protocol="tcp", transport="tcp", product="nginx",
        ), db)
    assert _count(db, asset.id, 443) == 1


def test_an_asset_from_another_engagement_is_rejected(db, asset):
    import uuid
    with pytest.raises(HTTPException) as exc:
        add_service(uuid.uuid4(), ServiceIn(asset_id=asset.id, port=443, protocol="tcp", product="nginx"), db)
    assert exc.value.status_code == 404
