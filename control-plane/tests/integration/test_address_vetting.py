"""REQ-SCAN-016 (GitHub #77): an address that can never be a scan target never reaches raw egress.

The egress proxy always refused a name that resolves to loopback, link-local or the metadata address. The raw path (nmap)
did not look at an address's class: the materialization accepted whatever a scoped name resolved to and the lease only
compared the address with it. These tests cover the IPv4 and IPv6 literal forms at both places: the materialization
(a name that resolves to one is not materialized at all) and the lease (no lease, no traffic, even for a forged
materialization row)."""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select

from app.api.internal import internal_raw_egress_lease
from app.gateway import address_vetting, dns_materialization
from app.models.audit import AuditLog
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.resolved_host import ResolvedHost
from app.models.scan_run import ScanRun
from app.schemas.internal import RawEgressLeaseIn
from tests.integration.owners import make_owner

BLOCKED = [
    ("127.0.0.1", "blocked_loopback_address"),
    ("169.254.169.254", "blocked_link_local_address"),
    ("0.0.0.0", "blocked_unspecified_address"),
    ("224.0.0.1", "blocked_multicast_address"),
    ("::1", "blocked_loopback_address"),
    ("fe80::1", "blocked_link_local_address"),
    ("fe80::1%eth0", "blocked_link_local_address"),
    ("::", "blocked_unspecified_address"),
    ("ff02::1", "blocked_multicast_address"),
    ("::ffff:127.0.0.1", "blocked_loopback_address"),
    ("::ffff:169.254.169.254", "blocked_link_local_address"),
    ("64:ff9b::7f00:1", "blocked_loopback_address"),
    ("2002:a9fe:a9fe::1", "blocked_link_local_address"),
]
ALLOWED = ["203.0.113.9", "10.1.2.3", "172.20.0.5", "192.168.1.4", "2606:4700::1111", "fc00::5", "2001:db8::7", "::ffff:203.0.113.9"]


@pytest.mark.parametrize("address, reason", BLOCKED)
def test_the_shared_rule_names_every_never_legitimate_form(address, reason):
    assert address_vetting.never_legitimate_reason(address) == reason


@pytest.mark.parametrize("address", ALLOWED)
def test_private_ranges_and_public_addresses_of_both_families_stay_allowed(address):
    assert address_vetting.never_legitimate_reason(address) is None


def test_an_address_that_cannot_be_parsed_is_refused_not_trusted():
    for text in ("", "not-an-ip", "300.1.1.1", "1.2.3", "gggg::1"):
        assert address_vetting.never_legitimate_reason(text) == "blocked_unparseable_address", text


# ------------------------------------------------------------- the materialization


def _engagement(db) -> Engagement:
    owner = make_owner(db)
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(title="E", source="own_domain", status="active", authorized_from=now - dt.timedelta(hours=1),
                     authorized_until=now + dt.timedelta(days=30), owner_user_id=owner.id)
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="example.test",
                      active_allowed=True, authorization_verified=True))
    db.commit()
    db.refresh(eng)
    return eng


def _materialize(db, eng, monkeypatch, answers: dict[str, set[str]]):
    monkeypatch.setattr(dns_materialization, "_resolve", lambda name: set(answers.get(name, set())))
    for name in answers:
        if name != "example.test":
            db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value=name,
                              active_allowed=True, authorization_verified=True))
    db.commit()
    result = dns_materialization.materialize(db, eng.id)
    rows = {(r.hostname, r.ip_address) for r in db.scalars(select(ResolvedHost).where(ResolvedHost.engagement_id == eng.id))}
    return result, rows


@pytest.mark.parametrize("address, reason", BLOCKED)
def test_negative_a_name_that_resolves_to_a_never_legitimate_address_is_not_materialized(db, monkeypatch, address, reason):
    eng = _engagement(db)
    result, rows = _materialize(db, eng, monkeypatch, {"evil.example.test": {address}})
    assert rows == set()
    assert [(d["hostname"], d["reason"]) for d in result.denied_ips] == [("evil.example.test", reason)]
    audit = db.scalar(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == "dns_materialization"))
    assert audit.payload["denied_ips"][0]["reason"] == reason


def test_negative_one_bad_answer_poisons_the_whole_name_like_in_the_egress_proxy(db, monkeypatch):
    eng = _engagement(db)
    result, rows = _materialize(db, eng, monkeypatch, {
        "mixed.example.test": {"203.0.113.9", "2606:4700::1111", "169.254.169.254"},
        "good.example.test": {"203.0.113.10", "2001:db8::7"},
    })
    assert rows == {("good.example.test", "203.0.113.10"), ("good.example.test", "2001:db8::7")}  # both families kept
    assert {d["ip_address"] for d in result.denied_ips} == {"203.0.113.9", "2606:4700::1111", "169.254.169.254"}


def test_a_private_ipv4_and_a_unique_local_ipv6_are_materialized_for_lab_and_internal_targets(db, monkeypatch):
    eng = _engagement(db)
    _, rows = _materialize(db, eng, monkeypatch, {"lab.example.test": {"10.1.2.3", "fc00::5"}})
    assert rows == {("lab.example.test", "10.1.2.3"), ("lab.example.test", "fc00::5")}


# ------------------------------------------------------------- the lease


def _run_with_row(db, eng, ip, hostname="lab.example.test"):
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.flush()
    db.add(ResolvedHost(engagement_id=eng.id, hostname=hostname, ip_address=ip, resolved_at=dt.datetime.now(dt.timezone.utc)))
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value=hostname,
                      active_allowed=True, authorization_verified=True))
    for category in ("recon", "fingerprint", "vuln"):
        db.add(ToolGrant(engagement_id=eng.id, tool_category=category, mode="active", requires_manual_approval=False))
    db.commit()
    return run


def _lease(db, eng, run, resolved, *, authorized="lab.example.test"):
    return internal_raw_egress_lease(
        eng.id, RawEgressLeaseIn(scan_run_id=run.id, authorized_target=authorized, resolved_target=resolved,
                                 phase="fingerprint", port_profile="full_tcp"), db)


@pytest.mark.parametrize("address, reason", BLOCKED)
def test_negative_no_lease_is_issued_for_a_never_legitimate_address_even_with_a_forged_materialization(db, address, reason):
    """The row says the name resolves to it (a stale or forged snapshot); the lease still refuses, so nmap never runs."""
    eng = _engagement(db)
    run = _run_with_row(db, eng, address.split("%")[0])
    result = _lease(db, eng, run, address)
    assert result.allowed is False and result.reason == "resolved_target_blocked_address" and result.lease_token is None
    denial = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == "raw_egress_lease")).all()
    assert denial and denial[-1].reason == "resolved_target_blocked_address"


def test_negative_a_literal_ip_scope_asset_of_a_blocked_class_gets_no_lease_either(db):
    eng = _engagement(db)
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="ip", value="127.0.0.1", active_allowed=True,
                      authorization_verified=True))
    db.commit()
    assert _lease(db, eng, run, "127.0.0.1", authorized="127.0.0.1").reason == "resolved_target_blocked_address"


@pytest.mark.parametrize("address", ["203.0.113.9", "2001:db8::7", "2606:4700::1111"])
def test_a_lease_is_issued_for_an_ipv4_and_an_ipv6_address_that_the_materialization_holds(db, address):
    eng = _engagement(db)
    run = _run_with_row(db, eng, address)
    result = _lease(db, eng, run, address)
    assert result.allowed is True and result.lease_token, result.reason


def test_negative_an_ipv6_address_the_name_does_not_resolve_to_gets_no_lease(db):
    """A host's AAAA record must not steer a scan at an address the engagement did not authorize."""
    eng = _engagement(db)
    run = _run_with_row(db, eng, "203.0.113.9")
    assert _lease(db, eng, run, "2001:db8::99").reason == "materialized_target_mismatch"
