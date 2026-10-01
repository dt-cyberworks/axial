import base64
import datetime as dt
import json

from sqlalchemy import select

from tests.integration.owners import make_owner
from app.api.internal import internal_raw_egress_lease
from app.models.audit import AuditLog
from app.models.engagement import BountyProgram, Engagement, ScopeAsset, ToolGrant
from app.models.resolved_host import ResolvedHost
from app.models.scan_run import ScanRun
from app.schemas.internal import RawEgressLeaseIn


def _run_and_resolution(db, engagement_id, *, hostname="metasploitable2", ip="192.0.2.10"):
    run = ScanRun(engagement_id=engagement_id, phase="fingerprint", state="running")
    db.add(run)
    db.flush()
    db.add(ResolvedHost(
        engagement_id=engagement_id,
        hostname=hostname,
        ip_address=ip,
        resolved_at=dt.datetime.now(dt.timezone.utc),
    ))
    db.commit()
    return run


def _payload(token: str) -> dict:
    body = token.split(".", 1)[0]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def test_lease_is_scope_gateway_authorized_and_bound_to_materialized_ip(db, lab_engagement):
    run = _run_and_resolution(db, lab_engagement.id)
    body = RawEgressLeaseIn(
        scan_run_id=run.id,
        authorized_target="metasploitable2",
        resolved_target="192.0.2.10",
        phase="fingerprint",
        port_profile="full_tcp",
    )

    result = internal_raw_egress_lease(lab_engagement.id, body, db)

    assert result.allowed is True
    assert result.lease_token
    payload = _payload(result.lease_token)
    assert payload["engagement_id"] == str(lab_engagement.id)
    assert payload["scan_run_id"] == str(run.id)
    assert payload["authorized_target"] == "metasploitable2"
    assert payload["resolved_target"] == "192.0.2.10"
    assert payload["ports"] == [[1, 65535]]
    assert payload["max_rate"] <= 1000
    actions = db.scalars(
        select(AuditLog.action).where(AuditLog.engagement_id == lab_engagement.id)
    ).all()
    assert "tool_call" in actions
    assert "raw_egress_lease" in actions


def test_lease_denies_unmaterialized_ip(db, lab_engagement):
    run = _run_and_resolution(db, lab_engagement.id)

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id,
            authorized_target="metasploitable2",
            resolved_target="198.51.100.99",
        ),
        db,
    )

    assert result.allowed is False
    assert result.reason == "materialized_target_mismatch"
    assert result.lease_token is None


def test_lease_rechecks_current_ip_deny_precedence(db, lab_engagement):
    run = _run_and_resolution(db, lab_engagement.id)
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id,
        rule="deny",
        asset_type="ip",
        value="192.0.2.10",
        active_allowed=False,
    ))
    db.commit()

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id,
            authorized_target="metasploitable2",
            resolved_target="192.0.2.10",
        ),
        db,
    )

    assert result.allowed is False
    assert result.reason == "resolved_target_not_in_current_raw_policy"


def test_lease_requires_running_scan_owned_by_engagement(db, lab_engagement):
    run = _run_and_resolution(db, lab_engagement.id)
    run.state = "done"
    db.commit()

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id,
            authorized_target="metasploitable2",
            resolved_target="192.0.2.10",
        ),
        db,
    )

    assert result.allowed is False
    assert result.reason == "scan_run_not_active"


def test_configured_tcp_lease_uses_persisted_engagement_range(db, lab_engagement):
    lab_engagement.tcp_port_from = 443
    lab_engagement.tcp_port_to = 8443
    db.commit()
    run = _run_and_resolution(db, lab_engagement.id)

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2",
            resolved_target="192.0.2.10", port_profile="configured_tcp",
        ),
        db,
    )

    assert result.allowed is True
    assert result.port_range == "443-8443"
    payload = _payload(result.lease_token)
    assert payload["protocol"] == "tcp"
    assert payload["ports"] == [[443, 8443]]
    assert payload["port_profile"] == "configured_tcp"

def test_legacy_full_tcp_profile_cannot_widen_restricted_engagement(db, lab_engagement):
    lab_engagement.tcp_port_from = 443
    lab_engagement.tcp_port_to = 443
    db.commit()
    run = _run_and_resolution(db, lab_engagement.id)

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2",
            resolved_target="192.0.2.10", port_profile="full_tcp",
        ),
        db,
    )
    assert result.allowed is False
    assert result.reason == "full_tcp_not_configured"

# REQ-PORTSCOPE-003: per-target port ranges (ScopeAsset.port_from/to),
# intersected with the engagement's tcp_port_from/to ceiling.

def test_target_specific_port_range_narrows_the_ceiling(db, lab_engagement):
    asset = db.scalars(select(ScopeAsset).where(ScopeAsset.value == "metasploitable2")).one()
    asset.port_from, asset.port_to = 22, 22
    db.commit()
    run = _run_and_resolution(db, lab_engagement.id)

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2",
            resolved_target="192.0.2.10", port_profile="configured_tcp",
        ),
        db,
    )

    assert result.allowed is True
    assert result.port_range == "22"
    payload = _payload(result.lease_token)
    assert payload["ports"] == [[22, 22]]


def test_negative_target_range_cannot_widen_beyond_the_ceiling_even_if_the_row_is_bad(db, lab_engagement):
    """The stored per-target range is never trusted alone - it's always
    re-intersected with the current ceiling. Bypasses the API's own
    write-time validation (direct ORM write) to prove the enforcement path
    itself, not just the write-time check, is what actually protects this."""
    lab_engagement.tcp_port_from = 1
    lab_engagement.tcp_port_to = 1024
    asset = db.scalars(select(ScopeAsset).where(ScopeAsset.value == "metasploitable2")).one()
    asset.port_from, asset.port_to = 1, 65535  # wider than the ceiling - should never survive intact
    db.commit()
    run = _run_and_resolution(db, lab_engagement.id)

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2",
            resolved_target="192.0.2.10", port_profile="configured_tcp",
        ),
        db,
    )

    assert result.allowed is True
    assert result.port_range == "1-1024"
    payload = _payload(result.lease_token)
    assert payload["ports"] == [[1, 1024]]


def test_negative_full_tcp_denied_for_a_target_narrowed_below_the_ceiling(db, lab_engagement):
    """The engagement ceiling alone (1-65535) is not enough for full_tcp if
    THIS target's own range narrows it - full_tcp must mean genuinely
    unrestricted for the specific target being scanned, not just a wide
    engagement-level default that happens to apply to other targets."""
    asset = db.scalars(select(ScopeAsset).where(ScopeAsset.value == "metasploitable2")).one()
    asset.port_from, asset.port_to = 1, 8000
    db.commit()
    run = _run_and_resolution(db, lab_engagement.id)

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2",
            resolved_target="192.0.2.10", port_profile="full_tcp",
        ),
        db,
    )

    assert result.allowed is False
    assert result.reason == "full_tcp_not_configured"


def test_multiple_matched_assets_produce_one_nmap_port_segment_each(db, lab_engagement):
    """Two allow-scope rows both match 'metasploitable2' (the exact domain
    entry already in lab_engagement, plus a covering wildcard added here)
    with different port overrides - the nmap port-list must carry both
    segments, not a collapsed min/max envelope that would over-authorize
    the gap between them."""
    exact = db.scalars(select(ScopeAsset).where(ScopeAsset.value == "metasploitable2")).one()
    exact.port_from, exact.port_to = 22, 22
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id, rule="allow", asset_type="wildcard",
        value="metasploit*", active_allowed=True, authorization_verified=True,
        port_from=8080, port_to=8080,
    ))
    db.commit()
    run = _run_and_resolution(db, lab_engagement.id)

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2",
            resolved_target="192.0.2.10", port_profile="configured_tcp",
        ),
        db,
    )

    assert result.allowed is True
    assert result.port_range == "22,8080"
    payload = _payload(result.lease_token)
    assert sorted(payload["ports"]) == [[22, 22], [8080, 8080]]


def test_udp_lease_is_opt_in_and_binds_only_fixed_profile(db, lab_engagement):
    run = _run_and_resolution(db, lab_engagement.id)
    denied = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2",
            resolved_target="192.0.2.10", port_profile="targeted_udp",
        ),
        db,
    )
    assert denied.allowed is False
    assert denied.reason == "udp_discovery_not_enabled"

    lab_engagement.udp_discovery_enabled = True
    db.commit()
    allowed = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2",
            resolved_target="192.0.2.10", port_profile="targeted_udp",
        ),
        db,
    )
    assert allowed.allowed is True
    assert allowed.protocol == "udp"
    assert allowed.port_range == "53,123,161,443,500,1900,4500,5060,5353"
    payload = _payload(allowed.lease_token)
    assert payload["ports"] == [[port, port] for port in (53, 123, 161, 443, 500, 1900, 4500, 5060, 5353)]
    assert payload["max_rate"] <= 100


# --- REQ-AGENT-025: raw_tcp_probe (redis-probe/activemq-banner) -----------

def test_raw_tcp_probe_lease_scopes_to_exactly_one_port(db, lab_engagement):
    lab_engagement.tcp_port_from = 6379
    lab_engagement.tcp_port_to = 6379
    db.commit()
    run = _run_and_resolution(db, lab_engagement.id)

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2", resolved_target="192.0.2.10",
            port_profile="raw_tcp_probe", port=6379, tool="redis-probe",
        ),
        db,
    )

    assert result.allowed is True
    assert result.port_range == "6379"
    payload = _payload(result.lease_token)
    assert payload["ports"] == [[6379, 6379]]
    assert payload["port_profile"] == "raw_tcp_probe"
    assert payload["protocol"] == "tcp"


def test_raw_tcp_probe_lease_denies_port_outside_configured_range(db, lab_engagement):
    """The single most important negative test for REQ-AGENT-025: an
    engagement restricted to port 443 must not be able to reach port 6379
    via this new tool just because the tool itself defaults there."""
    lab_engagement.tcp_port_from = 443
    lab_engagement.tcp_port_to = 443
    db.commit()
    run = _run_and_resolution(db, lab_engagement.id)

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2", resolved_target="192.0.2.10",
            port_profile="raw_tcp_probe", port=6379, tool="redis-probe",
        ),
        db,
    )

    assert result.allowed is False
    assert result.reason == "port_not_in_configured_range"


def test_raw_tcp_probe_lease_requires_a_valid_port(db, lab_engagement):
    lab_engagement.tcp_port_from = 1
    lab_engagement.tcp_port_to = 65535
    db.commit()
    run = _run_and_resolution(db, lab_engagement.id)

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2", resolved_target="192.0.2.10",
            port_profile="raw_tcp_probe", tool="activemq-banner",  # no port supplied
        ),
        db,
    )

    assert result.allowed is False
    assert result.reason == "raw_tcp_probe_port_invalid"


def test_raw_tcp_probe_lease_authorizes_against_the_real_tool_not_nmap(db, lab_engagement):
    """The Scope Gateway must check redis-probe's own grant/policy, never
    nmap's - a lease request for one tool must never be silently authorized
    against a different tool's allowlist."""
    lab_engagement.tcp_port_from = 1
    lab_engagement.tcp_port_to = 65535
    db.commit()
    run = _run_and_resolution(db, lab_engagement.id)

    result = internal_raw_egress_lease(
        lab_engagement.id,
        RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="metasploitable2", resolved_target="192.0.2.10",
            port_profile="raw_tcp_probe", port=61616, tool="activemq-banner",
        ),
        db,
    )
    assert result.allowed is True
    actions = db.scalars(
        select(AuditLog.action).where(AuditLog.engagement_id == lab_engagement.id)
    ).all()
    assert "tool_call" in actions


# --- REQ-FPEFF-001: the freshness window must survive the efficiency fix ----

def _lease(db, engagement_id, run):
    return internal_raw_egress_lease(engagement_id, RawEgressLeaseIn(
        scan_run_id=run.id,
        authorized_target="metasploitable2",
        resolved_target="192.0.2.10",
        phase="fingerprint",
        port_profile="full_tcp",
    ), db)


def test_negative_a_stale_materialization_is_still_denied(db, lab_engagement):
    """REQ-FPEFF-001 fixed the PRODUCER of the DNS snapshot (it was taken once
    per run and aged out mid-run), never this check that consumes it.

    Widening or bypassing the window would defeat the anti-DNS-rebinding
    control it exists for, so this asserts the check still bites - a snapshot
    older than the window is refused no matter how it was produced.
    """
    from app.config import get_settings

    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run)
    db.flush()
    max_age = max(60, min(get_settings().raw_egress_materialization_max_age_seconds, 3600))
    db.add(ResolvedHost(
        engagement_id=lab_engagement.id,
        hostname="metasploitable2",
        ip_address="192.0.2.10",
        # Comfortably past the window, whatever it is configured to.
        resolved_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=max_age + 120),
    ))
    db.commit()

    result = _lease(db, lab_engagement.id, run)

    assert result.allowed is False
    assert result.reason == "materialized_target_stale"


def test_a_fresh_materialization_is_allowed(db, lab_engagement):
    """The positive counterpart: the same request with a fresh snapshot passes,
    so the test above is detecting staleness and not some unrelated denial."""
    run = _run_and_resolution(db, lab_engagement.id)
    assert _lease(db, lab_engagement.id, run).allowed is True


def test_the_freshness_window_default_is_unchanged():
    """Pins the window itself: the efficiency work must not have quietly
    relaxed it to make the staleness symptom disappear."""
    from app.config import Settings

    assert Settings().raw_egress_materialization_max_age_seconds == 900


# --------------------------------------------------------------------------
# REQ-CIDRDISC-001/002/005: host_discovery profile (liveness-only CIDR sweep)
# --------------------------------------------------------------------------

def _host_discovery(db, engagement_id, run, cidr: str = "203.0.113.0/28"):
    return internal_raw_egress_lease(engagement_id, RawEgressLeaseIn(
        scan_run_id=run.id, authorized_target=cidr, resolved_target=cidr,
        phase="fingerprint", port_profile="host_discovery",
    ), db)


def test_host_discovery_lease_authorizes_a_whole_cidr_scope_asset(db, lab_engagement):
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id, rule="allow", asset_type="cidr",
        value="203.0.113.0/28", active_allowed=True, authorization_verified=True,
    ))
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = _host_discovery(db, lab_engagement.id, run)

    assert result.allowed is True
    assert result.lease_token
    payload = _payload(result.lease_token)
    assert payload["resolved_target"] == "203.0.113.0/28"
    assert payload["port_profile"] == "host_discovery"
    assert payload["ports"] == [[80, 80], [443, 443]]
    assert payload["protocol"] == "tcp"


# --- GitHub issue #34: a deny exception inside the CIDR must not block ----
# sweeping the rest of the range - proven at the control-plane authorization
# layer here; worker/tests/test_discovery_ip_cidr.py proves the worker
# actually requests the reduced sub-ranges instead of the original CIDR.

def test_negative_host_discovery_still_denies_the_original_cidr_when_a_deny_exception_overlaps_it(db, lab_engagement):
    """This denial is intentional and must NOT be weakened by the #34 fix -
    the fix works around it by having the WORKER request smaller sub-ranges
    that individually avoid the exception (see worker/app/tasks/discovery.py's
    _sweepable_sub_ranges), not by loosening this check to let a sweep reach
    a denied address."""
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id, rule="allow", asset_type="cidr",
        value="203.0.113.0/28", active_allowed=True, authorization_verified=True,
    ))
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id, rule="deny", asset_type="ip",
        value="203.0.113.5", active_allowed=False,
    ))
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = _host_discovery(db, lab_engagement.id, run)

    assert result.allowed is False
    assert result.reason == "resolved_target_not_in_current_raw_policy"


def test_host_discovery_authorizes_a_sub_range_that_avoids_the_deny_exception(db, lab_engagement):
    """The other half of the fix: a NARROWER sub-network of the allowed CIDR
    that doesn't overlap the deny exception is authorized normally - this is
    what the worker now requests instead of the original, denied full range."""
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id, rule="allow", asset_type="cidr",
        value="203.0.113.0/28", active_allowed=True, authorization_verified=True,
    ))
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id, rule="deny", asset_type="ip",
        value="203.0.113.5", active_allowed=False,
    ))
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    # 203.0.113.0/30 covers .0-.3, entirely clear of the denied .5.
    result = _host_discovery(db, lab_engagement.id, run, cidr="203.0.113.0/30")

    assert result.allowed is True
    assert result.lease_token
    payload = _payload(result.lease_token)
    assert payload["resolved_target"] == "203.0.113.0/30"


def test_negative_host_discovery_denies_a_range_wider_than_the_scope_asset(db, lab_engagement):
    """REQ-CIDRDISC-001: the sweep is authorized as a subnet-of/equal check -
    a /27 request against a /28 scope asset must not widen the sweep."""
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id, rule="allow", asset_type="cidr",
        value="203.0.113.0/28", active_allowed=True, authorization_verified=True,
    ))
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = _host_discovery(db, lab_engagement.id, run, cidr="203.0.113.0/27")

    assert result.allowed is False
    assert result.lease_token is None


def test_negative_host_discovery_denies_authorized_resolved_mismatch(db, lab_engagement):
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id, rule="allow", asset_type="cidr",
        value="203.0.113.0/28", active_allowed=True, authorization_verified=True,
    ))
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = internal_raw_egress_lease(lab_engagement.id, RawEgressLeaseIn(
        scan_run_id=run.id, authorized_target="203.0.113.0/28", resolved_target="203.0.113.16/28",
        phase="fingerprint", port_profile="host_discovery",
    ), db)

    assert result.allowed is False
    assert result.reason == "materialized_target_mismatch"


def test_negative_host_discovery_denied_when_80_443_outside_engagement_ceiling(db, lab_engagement):
    lab_engagement.tcp_port_from = 1000
    lab_engagement.tcp_port_to = 2000
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id, rule="allow", asset_type="cidr",
        value="203.0.113.0/28", active_allowed=True, authorization_verified=True,
    ))
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = _host_discovery(db, lab_engagement.id, run)

    assert result.allowed is False
    assert result.reason == "host_discovery_ports_out_of_range"


def test_negative_host_discovery_range_still_needs_active_allowed(db, lab_engagement):
    """A cidr scope asset with active_allowed=False is a passive-only grant -
    the sweep is itself an active operation and must still be refused. Denied
    by the raw-policy check (mirrors the pre-existing single-host behavior in
    _ip_is_allowed_by_current_policy, which also filters on active_allowed
    before authorize() itself ever runs) rather than authorize()'s own
    active_not_allowed reason - same outcome, earlier chokepoint."""
    db.add(ScopeAsset(
        engagement_id=lab_engagement.id, rule="allow", asset_type="cidr",
        value="203.0.113.0/28", active_allowed=False,
    ))
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = _host_discovery(db, lab_engagement.id, run)

    assert result.allowed is False
    assert result.reason == "resolved_target_not_in_current_raw_policy"


def _bug_bounty_engagement(
    db, *, automation_allowed: bool, max_rps: float = 3.0, with_program: bool = True,
    tcp_syn_scan_profile: str = "none", raw_max_packets_per_second: float | None = None,
    network_scan_authorization_evidence: str | None = None,
) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        owner_user_id=make_owner(db).id,
        title="Bounty raw discovery", source="bug_bounty", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
        # REQ-PORTSCOPE-001 ceiling: wide enough that configured_tcp/full_tcp
        # GitHub issue #37 tests below are never accidentally narrowed by it.
        tcp_port_from=1, tcp_port_to=65535,
    )
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(
        engagement_id=eng.id, rule="allow", asset_type="cidr",
        value="203.0.113.0/28", active_allowed=True, authorization_verified=True,
    ))
    for cat in ("recon", "fingerprint", "vuln"):
        db.add(ToolGrant(engagement_id=eng.id, tool_category=cat, mode="active", requires_manual_approval=False))
    if with_program:
        db.add(BountyProgram(
            engagement_id=eng.id, platform="intigriti", program_ref="portofantwerp",
            automation_allowed=automation_allowed, ai_testing_allowed=False,
            max_rps=max_rps, ident_header_name="X-Bug-Bounty",
            # GitHub issue #32: a header is no longer required by
            # authorize()'s bug_bounty gate (only the program row itself
            # is) - set here anyway to match a realistic program policy,
            # not because this test depends on it.
            ident_header_value="researcher-handle",
            # GitHub issue #37: explicit per-program network-scan capability tier.
            tcp_syn_scan_profile=tcp_syn_scan_profile,
            raw_max_packets_per_second=raw_max_packets_per_second,
            network_scan_authorization_evidence=network_scan_authorization_evidence,
        ))
    db.commit()
    db.refresh(eng)
    return eng


def test_host_discovery_exempted_from_bug_bounty_raw_nmap_block_when_automation_allowed(db):
    """REQ-CIDRDISC-005: the ONE narrow exception to raw_nmap_not_permitted_for_bug_bounty."""
    eng = _bug_bounty_engagement(db, automation_allowed=True, max_rps=3.0)
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = _host_discovery(db, eng.id, run)

    assert result.allowed is True
    assert result.max_rate == 3  # tightened to the program's own cap
    payload = _payload(result.lease_token)
    assert payload["max_rate"] == 3


def test_negative_bug_bounty_host_discovery_denied_without_automation_allowed(db):
    eng = _bug_bounty_engagement(db, automation_allowed=False)
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = _host_discovery(db, eng.id, run)

    assert result.allowed is False
    assert result.reason == "raw_nmap_not_permitted_for_bug_bounty"


def test_negative_bug_bounty_host_discovery_denied_without_a_bounty_program_row(db):
    eng = _bug_bounty_engagement(db, automation_allowed=True, with_program=False)
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = _host_discovery(db, eng.id, run)

    assert result.allowed is False
    assert result.reason == "raw_nmap_not_permitted_for_bug_bounty"


def test_negative_bug_bounty_other_profiles_are_still_denied_not_widened(db):
    """The exemption must never generalize to full_tcp/configured_tcp/
    targeted_udp/raw_tcp_probe - only host_discovery."""
    eng = _bug_bounty_engagement(db, automation_allowed=True)
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = internal_raw_egress_lease(eng.id, RawEgressLeaseIn(
        scan_run_id=run.id, authorized_target="203.0.113.1", resolved_target="203.0.113.1",
        phase="fingerprint", port_profile="configured_tcp",
    ), db)

    assert result.allowed is False
    assert result.reason == "raw_nmap_not_permitted_for_bug_bounty"


def test_common_profile_unlocks_configured_tcp_but_not_full_tcp(db):
    """GitHub issue #37: tcp_syn_scan_profile='common' is the ONE new tier
    that additionally permits configured_tcp (the engagement's own already-
    configured scope-asset port ranges) - full_tcp must still be denied,
    since 'common' never implies the broader 'full' tier."""
    eng = _bug_bounty_engagement(db, automation_allowed=True, tcp_syn_scan_profile="common")
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    allowed = internal_raw_egress_lease(eng.id, RawEgressLeaseIn(
        scan_run_id=run.id, authorized_target="203.0.113.1", resolved_target="203.0.113.1",
        phase="fingerprint", port_profile="configured_tcp",
    ), db)
    assert allowed.allowed is True
    assert allowed.port_profile == "configured_tcp"
    payload = _payload(allowed.lease_token)
    assert payload["port_profile"] == "configured_tcp"

    denied = internal_raw_egress_lease(eng.id, RawEgressLeaseIn(
        scan_run_id=run.id, authorized_target="203.0.113.1", resolved_target="203.0.113.1",
        phase="fingerprint", port_profile="full_tcp",
    ), db)
    assert denied.allowed is False
    assert denied.reason == "raw_nmap_not_permitted_for_bug_bounty"


def test_full_profile_with_evidence_unlocks_full_tcp(db):
    """GitHub issue #37: tcp_syn_scan_profile='full' additionally permits
    full_tcp, but only alongside a recorded network_scan_authorization_
    evidence reason - never on automation_allowed/max_rps alone."""
    eng = _bug_bounty_engagement(
        db, automation_allowed=True, tcp_syn_scan_profile="full",
        network_scan_authorization_evidence="Program scope doc explicitly lists full-port TCP scanning as in scope (see program brief section 4).",
    )
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = internal_raw_egress_lease(eng.id, RawEgressLeaseIn(
        scan_run_id=run.id, authorized_target="203.0.113.1", resolved_target="203.0.113.1",
        phase="fingerprint", port_profile="full_tcp",
    ), db)

    assert result.allowed is True
    assert result.port_profile == "full_tcp"
    payload = _payload(result.lease_token)
    assert payload["port_profile"] == "full_tcp"
    assert payload["ports"] == [[1, 65535]]


def test_negative_full_profile_without_evidence_denies_full_tcp(db):
    """GitHub issue #37's own explicit acceptance criterion: 'full' without
    a recorded authorization reason must be denied, distinctly, rather than
    silently treated like 'common' or like 'none'."""
    eng = _bug_bounty_engagement(db, automation_allowed=True, tcp_syn_scan_profile="full")
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = internal_raw_egress_lease(eng.id, RawEgressLeaseIn(
        scan_run_id=run.id, authorized_target="203.0.113.1", resolved_target="203.0.113.1",
        phase="fingerprint", port_profile="full_tcp",
    ), db)

    assert result.allowed is False
    assert result.reason == "full_tcp_requires_authorization_evidence"


def test_negative_default_none_profile_still_denies_configured_tcp_and_full_tcp(db):
    """Explicit regression guard: a program row that never opts into a
    broader tier (the pre-existing, pre-issue-#37 default) must behave
    identically to before this change - the ONE exemption is host_discovery."""
    eng = _bug_bounty_engagement(db, automation_allowed=True, tcp_syn_scan_profile="none")
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    for profile in ("configured_tcp", "full_tcp"):
        result = internal_raw_egress_lease(eng.id, RawEgressLeaseIn(
            scan_run_id=run.id, authorized_target="203.0.113.1", resolved_target="203.0.113.1",
            phase="fingerprint", port_profile=profile,
        ), db)
        assert result.allowed is False
        assert result.reason == "raw_nmap_not_permitted_for_bug_bounty"


def test_raw_max_packets_per_second_overrides_max_rps_for_the_raw_rate(db):
    """GitHub issue #37: raw_max_packets_per_second and max_rps (an HTTP
    request-rate concept) must never be conflated. When the program sets the
    new, distinct field, it - not max_rps - governs the raw nmap rate."""
    eng = _bug_bounty_engagement(
        db, automation_allowed=True, max_rps=2.0, raw_max_packets_per_second=800.0,
    )
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = _host_discovery(db, eng.id, run)

    assert result.allowed is True
    # 800 raw pps, NOT 2 (max_rps) - and capped by settings.nmap_max_rate/1000
    # ceiling like every other raw lease, same as the pre-existing behavior.
    assert result.max_rate != 2
    payload = _payload(result.lease_token)
    assert payload["max_rate"] == result.max_rate


def test_raw_max_packets_per_second_falls_back_to_max_rps_when_unset(db):
    """Backward compatibility: a program that never sets the new field keeps
    exactly the pre-#37 behavior (max_rps tightens the raw rate)."""
    eng = _bug_bounty_engagement(db, automation_allowed=True, max_rps=4.0, raw_max_packets_per_second=None)
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()

    result = _host_discovery(db, eng.id, run)

    assert result.allowed is True
    assert result.max_rate == 4
