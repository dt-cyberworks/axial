"""GitHub issue #35: scope-asset creation previously accepted arbitrary
strings for rule/asset_type/value with no format validation anywhere in the
stack - malformed input failed, if at all, deep in downstream code
(ipaddress.ip_network raising ValueError, silently swallowed by fail-closed
except branches) rather than being rejected clearly at creation time."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.engagement import ScopeAssetCreate


def _make(**overrides):
    defaults = dict(rule="allow", asset_type="domain", value="example.com")
    defaults.update(overrides)
    return ScopeAssetCreate(**defaults)


# --- rule / asset_type enums -----------------------------------------------

def test_negative_invalid_rule_is_rejected():
    with pytest.raises(ValidationError):
        _make(rule="maybe")


def test_negative_invalid_asset_type_is_rejected():
    with pytest.raises(ValidationError):
        _make(asset_type="subdomain")


# --- domain ------------------------------------------------------------

def test_domain_accepts_a_normal_hostname():
    assert _make(asset_type="domain", value="example.com").value == "example.com"


def test_domain_accepts_a_bare_dotless_hostname():
    """This codebase's own lab fixtures use bare internal Docker hostnames
    ("metasploitable2") as legitimate domain-type scope values - a
    dot-required validator would break that real, tested use case."""
    assert _make(asset_type="domain", value="metasploitable2").value == "metasploitable2"


def test_domain_lowercases_and_strips_trailing_dot():
    assert _make(asset_type="domain", value="Example.COM.").value == "example.com"


@pytest.mark.parametrize("bad", [
    "http://example.com", "example .com", "exa mple.com", "example.com/path",
    "user@example.com", "", "   ", "exam\tple.com",
])
def test_negative_domain_rejects_malformed_values(bad):
    with pytest.raises(ValidationError):
        _make(asset_type="domain", value=bad)


# --- wildcard ------------------------------------------------------------

def test_wildcard_accepts_a_leading_star_dot_pattern():
    assert _make(asset_type="wildcard", value="*.example.com").value == "*.example.com"


def test_wildcard_accepts_a_trailing_star_pattern_with_no_dot():
    """Real existing scope asset ("metasploit*") - see
    test_raw_egress_lease.py's own fixture."""
    assert _make(asset_type="wildcard", value="metasploit*").value == "metasploit*"


@pytest.mark.parametrize("bad", ["http://*.example.com", "*.example.com/path", "* example.com", ""])
def test_negative_wildcard_rejects_malformed_values(bad):
    with pytest.raises(ValidationError):
        _make(asset_type="wildcard", value=bad)


# --- ip --------------------------------------------------------------------

def test_ip_accepts_a_valid_ipv4_address():
    assert _make(asset_type="ip", value="203.0.113.5").value == "203.0.113.5"


def test_negative_ip_rejects_ambiguous_leading_zero_octets():
    """ipaddress.ip_address() deliberately rejects leading-zero octets
    (Python's own fix for the octal-injection ambiguity class of bug,
    CVE-2021-29921) - inherited here for free by using it as the parser."""
    with pytest.raises(ValidationError):
        _make(asset_type="ip", value="203.000.113.005")


@pytest.mark.parametrize("bad", ["999.1.1.1", "not-an-ip", "203.0.113.5/24", ""])
def test_negative_ip_rejects_malformed_values(bad):
    with pytest.raises(ValidationError):
        _make(asset_type="ip", value=bad)


def test_negative_ip_rejects_ipv6():
    """GitHub issue #35's documented decision: IPv6 is rejected at input
    time (no test proves it works end-to-end through the raw-egress chain)
    rather than silently accepted and failing somewhere later."""
    with pytest.raises(ValidationError, match="IPv6"):
        _make(asset_type="ip", value="2001:db8::1")


# --- cidr --------------------------------------------------------------------

def test_cidr_accepts_a_clean_network():
    assert _make(asset_type="cidr", value="203.0.113.0/28").value == "203.0.113.0/28"


def test_cidr_canonicalizes_host_bits_set():
    """'10.0.0.5/24' and '10.0.0.0/24' denote the same network - normalized
    to the same canonical stored value rather than two distinct-looking
    rows for equivalent input."""
    assert _make(asset_type="cidr", value="10.0.0.5/24").value == "10.0.0.0/24"


@pytest.mark.parametrize("bad", ["203.0.113.0/33", "not-a-cidr", ""])
def test_negative_cidr_rejects_malformed_values(bad):
    with pytest.raises(ValidationError):
        _make(asset_type="cidr", value=bad)


def test_cidr_accepts_a_bare_address_as_a_degenerate_slash_32():
    """A bare address is a legitimate (if unusual) CIDR value - ipaddress
    itself treats it as a /32, a valid single-host network. Documented here
    rather than silently left untested; asset_type=ip remains the natural
    choice for a single host."""
    assert _make(asset_type="cidr", value="203.0.113.0").value == "203.0.113.0/32"


def test_negative_cidr_rejects_ipv6():
    with pytest.raises(ValidationError, match="IPv6"):
        _make(asset_type="cidr", value="2001:db8::/32")


# --- cloud_account -----------------------------------------------------

def test_cloud_account_accepts_an_arbitrary_non_empty_value():
    """No canonical format is known/enforced anywhere in this codebase for
    cloud_account (unused beyond exact-string matching in authorize.py) -
    only the generic empty-string check applies."""
    assert _make(asset_type="cloud_account", value="arn:aws:iam::123456789012:root").value == \
        "arn:aws:iam::123456789012:root"


def test_negative_cloud_account_rejects_empty_value():
    with pytest.raises(ValidationError):
        _make(asset_type="cloud_account", value="")
