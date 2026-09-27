import uuid

from app.gateway.raw_egress_policy import build_raw_egress_policy
from app.models.engagement import ScopeAsset


def _asset(rule, asset_type, value, *, active_allowed=True):
    return ScopeAsset(
        id=uuid.uuid4(),
        engagement_id=uuid.uuid4(),
        rule=rule,
        asset_type=asset_type,
        value=value,
        active_allowed=active_allowed,
    )


def test_raw_egress_policy_uses_ip_blocks_and_deny_exceptions():
    engagement_id = uuid.uuid4()
    rendered = build_raw_egress_policy(
        engagement_id,
        [
            _asset("allow", "cidr", "203.0.113.0/24"),
            _asset("deny", "ip", "203.0.113.10"),
        ],
    )

    assert rendered.ip_blocks == [{"cidr": "203.0.113.0/24", "except": ["203.0.113.10/32"]}]
    assert rendered.policy["spec"]["egress"] == [
        {"to": [{"ipBlock": {"cidr": "203.0.113.0/24", "except": ["203.0.113.10/32"]}}]}
    ]


def test_raw_egress_policy_omits_names_until_ips_are_materialized():
    engagement_id = uuid.uuid4()
    rendered = build_raw_egress_policy(engagement_id, [_asset("allow", "domain", "example.com")])

    assert rendered.ip_blocks == []
    assert rendered.policy["spec"]["egress"] == []
    assert rendered.omitted_assets[0]["reason"] == "raw_egress_requires_ip_or_cidr"
    assert "no active IP/CIDR allow assets; rendered policy denies raw egress" in rendered.warnings


def test_materialized_ips_become_allow_blocks():
    engagement_id = uuid.uuid4()
    rendered = build_raw_egress_policy(
        engagement_id,
        [_asset("allow", "domain", "example.org")],
        materialized_ips=[{"hostname": "example.org", "ip_address": "93.254.65.195"}],
    )
    # Der Name ist jetzt via /32-Block erlaubt, nicht mehr fail-closed.
    assert {"cidr": "93.254.65.195/32"} in rendered.ip_blocks
    assert rendered.policy["spec"]["egress"] == [
        {"to": [{"ipBlock": {"cidr": "93.254.65.195/32"}}]}
    ]


def test_materialized_ip_under_deny_is_suppressed():
    engagement_id = uuid.uuid4()
    rendered = build_raw_egress_policy(
        engagement_id,
        [_asset("allow", "domain", "example.org"), _asset("deny", "ip", "93.254.65.195")],
        materialized_ips=[{"hostname": "example.org", "ip_address": "93.254.65.195"}],
    )
    # deny-Vorrang: die materialisierte IP == deny-IP -> Block komplett unterdrueckt.
    assert rendered.ip_blocks == []
    assert any("fully suppressed by deny rule" in w for w in rendered.warnings)
