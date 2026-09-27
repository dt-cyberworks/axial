"""REQ-CORR-001 regression: real NVD API response shapes found live against
pentest-ground.com (2026-07-29) exposed two bugs in candidate extraction:

1. NVD's `configurations` mix the actual application CPE match
   (`cpe:2.3:a:...`) with unrelated OS/hardware platform CPE matches
   (`cpe:2.3:o:...`), both marked `vulnerable=true`. Including the
   platform entries as unconstrained "matches any version" candidates
   caused CVE-2009-2629 (real nginx range 0.1.0-0.8.15) to also match a
   detected nginx 1.31.3 - completely outside every real range - via its
   six paired Debian/Fedora platform CPE matches, which carry no version
   info of their own.
2. Many older CVEs carry no version range at all; the single affected
   version is embedded directly in the CPE string
   (`cpe:2.3:a:php:php:1.0:*:*:*:*:*:*:*`). Treating "no range" as "no
   constraint" (matches every version) rather than extracting that exact
   version caused ancient PHP CVEs (1999-2001) to match a detected PHP
   8.5.8.

Fixtures below are trimmed, real captured shapes from
`services.nvd.nist.gov/rest/json/cves/2.0` for these exact two CVEs.
"""

from __future__ import annotations

import httpx

from app import nvd_client


def _nvd_response(vulnerabilities: list[dict]) -> httpx.Response:
    request = httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    return httpx.Response(200, json={"vulnerabilities": vulnerabilities}, request=request)


def _cve_2009_2629_response() -> dict:
    """Real shape: 4 real nginx (application) ranges + 6 unrelated Debian/
    Fedora platform matches with no version info of their own."""
    def app_match(start: str, end: str) -> dict:
        return {
            "vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
            "versionStartIncluding": start, "versionEndExcluding": end,
        }

    def os_match(criteria: str) -> dict:
        return {"vulnerable": True, "criteria": criteria}

    return {
        "cve": {
            "id": "CVE-2009-2629",
            "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                app_match("0.1.0", "0.5.38"),
                app_match("0.6.0", "0.6.39"),
                app_match("0.7.0", "0.7.62"),
                app_match("0.8.0", "0.8.15"),
                os_match("cpe:2.3:o:debian:debian_linux:4.0:*:*:*:*:*:*:*"),
                os_match("cpe:2.3:o:debian:debian_linux:5.0:*:*:*:*:*:*:*"),
                os_match("cpe:2.3:o:fedoraproject:fedora:10:*:*:*:*:*:*:*"),
            ]}]}],
        }
    }


def _cve_1999_0058_response() -> dict:
    """Real shape: two exact-version application CPEs, no range fields at all."""
    return {
        "cve": {
            "id": "CVE-1999-0058",
            "metrics": {},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:php:php:1.0:*:*:*:*:*:*:*"},
                {"vulnerable": True, "criteria": "cpe:2.3:a:php:php:2.0b10:*:*:*:*:*:*:*"},
            ]}]}],
        }
    }


def test_os_platform_cpe_matches_are_excluded_from_candidates(monkeypatch):
    monkeypatch.setattr(
        nvd_client.httpx, "get",
        lambda *a, **k: _nvd_response([_cve_2009_2629_response()]),
    )
    candidates = nvd_client.fetch_nvd_candidates("nginx")

    assert candidates is not None
    assert len(candidates) == 4  # only the 4 real application-CPE ranges
    for c in candidates:
        assert c["cve_id"] == "CVE-2009-2629"
        assert c.get("exact_versions") is None
        assert c["version_start_including"] is not None


def test_exact_cpe_version_is_extracted_when_no_range_present(monkeypatch):
    monkeypatch.setattr(
        nvd_client.httpx, "get",
        lambda *a, **k: _nvd_response([_cve_1999_0058_response()]),
    )
    candidates = nvd_client.fetch_nvd_candidates("php")

    assert candidates is not None
    assert len(candidates) == 2
    exact_versions = sorted(c["exact_versions"][0] for c in candidates)
    assert exact_versions == ["1.0", "2.0b10"]
    for c in candidates:
        assert c["version_start_including"] is None


def test_end_to_end_a_far_newer_version_does_not_match_either_cve(monkeypatch):
    """The actual regression: detected versions from the live scan
    (nginx 1.31.3, PHP 8.5.8) must not match either fixture CVE post-fix."""
    from app.version_compare import version_in_range

    monkeypatch.setattr(
        nvd_client.httpx, "get",
        lambda *a, **k: _nvd_response([_cve_2009_2629_response()]),
    )
    nginx_candidates = nvd_client.fetch_nvd_candidates("nginx")
    assert not any(
        version_in_range(
            "1.31.3",
            start_including=c["version_start_including"], start_excluding=c["version_start_excluding"],
            end_including=c["version_end_including"], end_excluding=c["version_end_excluding"],
            exact_versions=c.get("exact_versions"),
        )
        for c in nginx_candidates
    )

    monkeypatch.setattr(
        nvd_client.httpx, "get",
        lambda *a, **k: _nvd_response([_cve_1999_0058_response()]),
    )
    php_candidates = nvd_client.fetch_nvd_candidates("php")
    assert not any(
        version_in_range(
            "8.5.8",
            start_including=c["version_start_including"], start_excluding=c["version_start_excluding"],
            end_including=c["version_end_including"], end_excluding=c["version_end_excluding"],
            exact_versions=c.get("exact_versions"),
        )
        for c in php_candidates
    )


def test_cpe_part_product_version_parsing():
    assert nvd_client._cpe_part_product_version("cpe:2.3:a:php:php:1.0:*:*:*:*:*:*:*") == ("a", "php", "1.0")
    assert nvd_client._cpe_part_product_version("cpe:2.3:o:debian:debian_linux:4.0:*:*:*:*:*:*:*") == ("o", "debian_linux", "4.0")
    assert nvd_client._cpe_part_product_version("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*") == ("a", "nginx", None)


def _cve_2008_3687_response() -> dict:
    """Real shape (fetched live, 2026-08-03): Xen's FLASK/XSM security
    module, "Heap-based buffer overflow in the flask_security_label
    function in Xen 3.3... compiled with the XSM:FLASK module" - nothing to
    do with the Python Flask framework, but its CPE product is
    `xen_flask_module` and its version field is a wildcard with no range
    fields at all, so pre-fix this matched a detected Flask at any version."""
    return {
        "cve": {
            "id": "CVE-2008-3687",
            "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 6.8}}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:xen:xen:3.3:*:*:*:*:*:*:*"},
                {"vulnerable": True, "criteria": "cpe:2.3:a:xen:xen_flask_module:*:*:*:*:*:*:*:*"},
            ]}]}],
        }
    }


def _cve_2002_0131_response() -> dict:
    """Real shape (fetched live, 2026-08-03): ActiveState's ActivePython
    ActiveX control - a browser scripting engine, nothing to do with the
    Python interpreter. CPE product is `activepython` with no delimiter at
    all before "python", so pre-fix a plain substring check matched it
    against every detected Python version."""
    return {
        "cve": {
            "id": "CVE-2002-0131",
            "metrics": {},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:activestate:activepython:*:*:*:*:*:*:*:*"},
                {"vulnerable": True, "criteria": "cpe:2.3:a:activestate:activepython:2.1:*:*:*:*:*:*:*"},
            ]}]}],
        }
    }


def test_flask_python_framework_does_not_match_unrelated_xen_module(monkeypatch):
    """REQ-CORR-001 regression, found live during the VAmPI benchmark pilot
    (2026-08-03): a detected Flask install must not match Xen's unrelated
    FLASK security module, at any version - the old substring check matched
    "flask" inside "xen_flask_module" and, since that CPE match carries no
    version range, fired on every scan that detected any Flask version."""
    monkeypatch.setattr(
        nvd_client.httpx, "get",
        lambda *a, **k: _nvd_response([_cve_2008_3687_response()]),
    )
    candidates = nvd_client.fetch_nvd_candidates("flask")
    assert candidates == []


def test_python_interpreter_does_not_match_unrelated_activepython(monkeypatch):
    """Same class of regression as above for "python" vs. ActiveState's
    unrelated `activepython` ActiveX control CPE - no word boundary exists
    between "active" and "python" at all, so a raw substring check matched
    unconditionally regardless of the interpreter version detected."""
    monkeypatch.setattr(
        nvd_client.httpx, "get",
        lambda *a, **k: _nvd_response([_cve_2002_0131_response()]),
    )
    candidates = nvd_client.fetch_nvd_candidates("python")
    assert candidates == []


def test_product_matches_still_allows_documented_first_token_residual_cases():
    """The previously-documented, explicitly-accepted lower-severity residual
    cases (docs/requirements/live-vulnerability-correlation.md, "Implementation
    status") must keep matching: "nginx" anchors the first word of
    `nginx_proxy_manager`, "php" anchors the first word of `php_fi`. An
    exact-match-only filter was already rejected for false-negative reasons
    (Apache's own CPE product is `http_server`, not `apache`)."""
    assert nvd_client._product_matches("nginx", "nginx_proxy_manager") is True
    assert nvd_client._product_matches("php", "php_fi") is True


def test_product_matches_rejects_middle_token_and_delimiter_free_substring():
    assert nvd_client._product_matches("flask", "xen_flask_module") is False
    assert nvd_client._product_matches("python", "activepython") is False
    assert nvd_client._product_matches("nginx", "xcode") is False
    assert nvd_client._product_matches("nginx", "software_collections") is False


def test_unrelated_bundled_product_is_excluded_even_when_application_part(monkeypatch):
    """REQ-CORR-001 regression: CVE-2016-0742 lists nginx (real match, real
    range) alongside unrelated apple:xcode and redhat:software_collections
    application CPEs on the same CVE record - only the nginx entries must
    survive the product-name filter."""
    def response(*a, **k):
        request = httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        return httpx.Response(200, request=request, json={"vulnerabilities": [{"cve": {
            "id": "CVE-2016-0742",
            "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "0.6.18", "versionEndExcluding": "1.8.1"},
                {"vulnerable": True, "criteria": "cpe:2.3:a:apple:xcode:*:*:*:*:*:*:*:*",
                 "versionEndExcluding": "13.0"},
                {"vulnerable": True, "criteria": "cpe:2.3:a:redhat:software_collections:1.0:*:*:*:*:*:*:*"},
            ]}]}],
        }}]})

    monkeypatch.setattr(nvd_client.httpx, "get", response)
    candidates = nvd_client.fetch_nvd_candidates("nginx")

    assert candidates is not None
    assert len(candidates) == 1
    assert candidates[0]["version_end_excluding"] == "1.8.1"
