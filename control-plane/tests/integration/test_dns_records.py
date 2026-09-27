"""TC-DNS-001: DNS-Inventar-Endpunkte + Scope-Invariante auf DB-Ebene.

Verifiziert, dass ein dns_record ein reines Metadatum ist: idempotenter Upsert,
Auflistung (Dangling zuerst) - und der NEGATIV-Kern: das gespeicherte CNAME-Ziel
wird nie zu einem discovered_asset und nie nach resolved_host materialisiert.
"""

from __future__ import annotations

from app.api.engagements import _delete_engagement_dependents
from app.api.findings import list_dns_records
from app.api.internal import upsert_dns_record
from app.gateway.dns_materialization import materialize
from app.models.asset import DiscoveredAsset
from app.models.dns_record import DnsRecord
from app.models.resolved_host import ResolvedHost
from app.schemas.internal import DnsRecordIn


def _record(fqdn, **over):
    base = dict(
        fqdn=fqdn,
        cname_chain=[fqdn, "x.elb.amazonaws.com"],
        terminal_target="x.elb.amazonaws.com",
        terminal_ips=["1.2.3.4"],
        hosting_provider="aws-elb",
        is_shared_infra=True,
        dns_status="resolved",
        takeover_suspected=False,
    )
    base.update(over)
    return DnsRecordIn(**base)


def test_upsert_is_idempotent_on_fqdn(db, lab_engagement):
    r1 = upsert_dns_record(lab_engagement.id, _record("app.example.com"), db)
    r2 = upsert_dns_record(
        lab_engagement.id,
        _record("app.example.com", hosting_provider="aws-cloudfront", is_cdn=True, is_shared_infra=False),
        db,
    )
    assert r1["id"] == r2["id"]  # kein Duplikat, gleiche Zeile aufgefrischt

    rows = list_dns_records(lab_engagement.id, db)
    assert len(rows) == 1
    assert rows[0].hosting_provider == "aws-cloudfront"


def test_list_orders_dangling_first(db, lab_engagement):
    upsert_dns_record(lab_engagement.id, _record("healthy.example.com"), db)
    upsert_dns_record(
        lab_engagement.id,
        _record("orphan.example.com", terminal_ips=[], dns_status="dangling", takeover_suspected=True),
        db,
    )
    rows = list_dns_records(lab_engagement.id, db)
    assert rows[0].fqdn == "orphan.example.com"
    assert rows[0].takeover_suspected is True


def test_cname_target_never_becomes_asset_or_materialized(db, lab_engagement):
    """NEGATIV-KERN (REQ-DNS-001): ein dns_record ist eine Sackgasse. Das
    CNAME-Ziel taucht nirgends als scanbares Asset oder materialisierte IP auf."""
    upsert_dns_record(lab_engagement.id, _record("app.example.com"), db)

    # 1. Kein discovered_asset traegt den Ziel-Namen.
    leaked_asset = (
        db.query(DiscoveredAsset)
        .filter(DiscoveredAsset.value == "x.elb.amazonaws.com")
        .first()
    )
    assert leaked_asset is None

    # 2. Materialisierung (raw egress) zieht ihre Namen NUR aus scope_asset /
    #    in-scope discovered_asset - nie aus dns_record. Das Ziel darf nach einer
    #    Materialisierung nicht in resolved_host stehen.
    materialize(db, lab_engagement.id)
    leaked_ip_host = (
        db.query(ResolvedHost)
        .filter(ResolvedHost.hostname == "x.elb.amazonaws.com")
        .first()
    )
    assert leaked_ip_host is None


def test_engagement_delete_cleans_up_dns_records(db, lab_engagement):
    """Regression: das Loeschen eines Engagements muss dns_record-Zeilen mit
    entfernen - sonst blockiert der FK (dns_record -> discovered_asset/engagement)
    das Loeschen (500)."""
    asset = DiscoveredAsset(
        engagement_id=lab_engagement.id, asset_type="domain", value="app.example.com",
        in_scope=True, discovered_via="test",
    )
    db.add(asset)
    db.flush()
    upsert_dns_record(lab_engagement.id, _record("app.example.com", asset_id=asset.id), db)

    # Darf nicht werfen (vorher: FK-Verletzung).
    _delete_engagement_dependents(db, lab_engagement.id)
    db.commit()

    assert db.query(DnsRecord).filter(DnsRecord.engagement_id == lab_engagement.id).count() == 0
    assert db.query(DiscoveredAsset).filter(DiscoveredAsset.engagement_id == lab_engagement.id).count() == 0
