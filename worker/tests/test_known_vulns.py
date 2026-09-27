"""REQ-CORR-006: known_vulns.lookup() must not match a version_prefix-bearing
entry when no version was supplied - previously `version` being falsy
short-circuited the version_prefix check entirely, so ANY vsftpd version
(not just the vulnerable 2.3.4) matched CVE-2011-2523."""

from app.known_vulns import lookup


def test_lookup_without_version_does_not_match_version_gated_entry():
    assert lookup("vsftpd 3.0.5", None) is None


def test_lookup_with_matching_version_still_matches():
    vuln = lookup("vsftpd 2.3.4", "2.3.4")
    assert vuln is not None
    assert vuln.cve_ids == ["CVE-2011-2523"]


def test_lookup_with_non_matching_version_does_not_match():
    assert lookup("vsftpd 3.0.5", "3.0.5") is None


def test_lookup_without_product_returns_none():
    assert lookup(None, "2.3.4") is None


def test_lookup_entry_without_version_prefix_matches_on_product_alone():
    # distccd carries no version_prefix - a product-name match is sufficient
    # regardless of version, unaffected by this fix.
    vuln = lookup("distccd", None)
    assert vuln is not None
    assert vuln.cve_ids == ["CVE-2004-2687"]
