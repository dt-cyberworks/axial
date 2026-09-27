from app.gateway.authorize import _matches_asset_value, _matches_path
from app.models.engagement import ScopeAsset


def _asset(asset_type: str, value: str, path_pattern: str | None = None) -> ScopeAsset:
    return ScopeAsset(asset_type=asset_type, value=value, path_pattern=path_pattern)


def test_domain_matches_apex_and_subdomains():
    a = _asset("domain", "api.kunde.de")
    assert _matches_asset_value("api.kunde.de", a)
    assert _matches_asset_value("sub.api.kunde.de", a)
    assert not _matches_asset_value("otherkunde.de", a)


def test_wildcard_matches_subdomains():
    a = _asset("wildcard", "*.kunde.de")
    assert _matches_asset_value("sub.kunde.de", a)
    assert not _matches_asset_value("kunde.de", a)  # fnmatch: '*' erfordert mind. ein Zeichen davor


def test_cidr_matches_contained_ip():
    a = _asset("cidr", "10.0.0.0/24")
    assert _matches_asset_value("10.0.0.5", a)
    assert not _matches_asset_value("10.0.1.5", a)


def test_cidr_range_target_matches_subnet_or_equal_scope_asset():
    """REQ-CIDRDISC-001: target_is_range checks network containment, not
    point containment - a host-discovery sweep is authorized against a whole
    range in one call."""
    a = _asset("cidr", "10.0.0.0/24")
    assert _matches_asset_value("10.0.0.0/24", a, target_is_range=True)  # exact match
    assert _matches_asset_value("10.0.0.0/25", a, target_is_range=True)  # proper subnet
    assert not _matches_asset_value("10.0.0.0/23", a, target_is_range=True)  # broader than allowed
    assert not _matches_asset_value("10.0.1.0/24", a, target_is_range=True)  # disjoint
    # a single ip-type asset is itself a /32 network - equal, not broader
    single = _asset("ip", "10.0.0.5")
    assert _matches_asset_value("10.0.0.5/32", single, target_is_range=True)
    assert not _matches_asset_value("10.0.0.4/31", single, target_is_range=True)  # broader than the single host


def test_range_target_without_the_flag_uses_point_semantics_unchanged():
    """A caller that forgets target_is_range=True (i.e. every pre-existing
    call site) must see the OLD behavior: a CIDR-shaped target fails to parse
    as ipaddress.ip_address and is denied, never silently reinterpreted."""
    a = _asset("cidr", "10.0.0.0/24")
    assert not _matches_asset_value("10.0.0.0/25", a)


def test_path_pattern_glob():
    assert _matches_path("/admin/users", "/admin/*")
    assert not _matches_path("/public/index", "/admin/*")
    assert _matches_path("/anything", None)  # kein Pfad-Filter = alles matcht
