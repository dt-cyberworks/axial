"""HTTP clients for the live vulnerability data sources used by the
correlate phase (REQ-CORR-001/002/003): NVD (candidate CVEs per product +
their affected-version ranges), EPSS (exploitation-probability score), and
the CISA KEV catalog.

Pure network functions - no DB access. Like discovery.py's passive OSINT
sources, these are third-party data lookups, never target contact; results
are persisted by the caller (correlate.py) through the control-plane
internal API cache endpoints, never written directly here.

Each function returns `None` on total failure (REQ-CORR-005: the caller
distinguishes "source unreachable this run" from "reachable, found
nothing" - an empty list/dict on success is a meaningfully different result
than None).
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT = 20.0
EPSS_BATCH_SIZE = 100


def _extract_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            score = (entries[0].get("cvssData") or {}).get("baseScore")
            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    return None
    return None


def _iter_vulnerable_cpe_matches(configurations: list):
    for config in configurations or []:
        for node in (config.get("nodes") or []) if isinstance(config, dict) else []:
            for match in (node.get("cpeMatch") or []) if isinstance(node, dict) else []:
                if match.get("vulnerable", True):
                    yield match


def _cpe_part_product_version(criteria: str) -> tuple[str | None, str | None, str | None]:
    """Parse a CPE 2.3 URI (`cpe:2.3:part:vendor:product:version:...`).
    Returns (part, product, version) - version is None for a wildcard
    (`*`/`-`)."""
    fields = criteria.split(":")
    if len(fields) < 6:
        return None, None, None
    version = fields[5]
    return fields[2] or None, fields[4] or None, (None if version in ("*", "-", "") else version)


def _product_matches(product_key: str, cpe_product: str | None) -> bool:
    """A CVE's `configurations` can legitimately list several unrelated
    affected application CPEs on one CVE (e.g. CVE-2016-0742 affects nginx,
    but also lists `apple:xcode` and `redhat:software_collections` as
    separate bundling products) - keywordSearch has no way to scope to just
    the one we asked about, so this filters candidates back down to the
    product we actually detected.

    Found live (2026-08-03, VAmPI/DVWA benchmark pilot): raw substring
    containment (the previous approach here, matching `known_vulns.py`'s)
    is unsafe against two of the most common real-world signals, "flask"
    and "python". `"flask" in "xen flask module"` is True - CVE-2008-3687
    is a Xen hypervisor security-module (FLASK/XSM) overflow, unrelated to
    the Python Flask framework, but "flask" sits as a complete word inside
    Xen's compound CPE product `xen_flask_module`. `"python" in
    "activepython"` is True with no delimiter at all - CVE-2002-0131 is an
    ActiveState ActiveX control, unrelated to the Python interpreter. Both
    would (and did) fire on every single Flask/Python detection regardless
    of version, since these CPE matches also carry no version range and
    fall back to "matches every version" (see `version_in_range`).

    A single shared token only counts as product identity when it anchors
    one of the two names - its first or last word - not when merely
    embedded in the *middle* of an unrelated multi-word compound (`flask`
    is the middle word of `xen_flask_module`) and not as a bare substring
    with no word boundary at all (`python` inside `activepython`). This
    still intentionally allows the previously-documented, lower-severity
    residual cases through unchanged (`jc21:nginx_proxy_manager` - "nginx"
    anchors the first word; `php:php_fi` - "php" anchors the first word):
    an exact-match-only filter was already rejected for those on
    false-negative grounds (Apache's own CPE product is `http_server`, not
    `apache`/`apache httpd`) - see docs/requirements/
    live-vulnerability-correlation.md. This narrows recall further without
    reintroducing that regression."""
    if not cpe_product:
        return False
    normalized = cpe_product.replace("_", " ").lower()
    if product_key == normalized:
        return True
    key_tokens = product_key.split()
    cpe_tokens = normalized.split()
    if not key_tokens or not cpe_tokens:
        return False
    if len(key_tokens) == 1:
        return key_tokens[0] in (cpe_tokens[0], cpe_tokens[-1])
    if len(cpe_tokens) == 1:
        return cpe_tokens[0] in (key_tokens[0], key_tokens[-1])
    return False


def fetch_nvd_candidates(product_key: str, api_key: str | None = None) -> list[dict] | None:
    """Query NVD for CVEs whose CPE matches `product_key`. One candidate row
    per (CVE, CPE-match-node) - a CVE with no CPE-match data at all (only a
    text-description keyword hit) is not included: that is materially weaker
    evidence than an NVD-asserted product association and would be a poor
    basis for a specific CVE finding.

    Two corrections found live against real NVD data (2026-07-29, real scan
    against pentest-ground.com): (1) NVD's `configurations` frequently mix the
    actual application CPE match (`cpe:2.3:a:...`) with unrelated operating-
    system/hardware platform CPE matches (`cpe:2.3:o:...`/`cpe:2.3:h:...`,
    e.g. "this CVE also affects Debian/Fedora") in the same match list, all
    marked `vulnerable=true` - only the `a` (application) entries describe
    the product's own affected versions, so non-`a` entries are dropped
    entirely rather than treated as an unconstrained match. (2) many older
    CVEs carry no version RANGE at all - the single affected version is
    embedded directly in the CPE string itself (e.g.
    `cpe:2.3:a:php:php:1.0:*:*:*:*:*:*:*`) - extracted here as an exact
    version rather than defaulting to "no constraint = matches every
    version", which without this fix matched CVEs from 1999-2019 against an
    unrelated, far newer detected version. (3) a CVE's `configurations` can
    legitimately list several unrelated application CPEs on one CVE record
    (nginx itself, plus e.g. `apple:xcode` and `redhat:software_collections`
    bundling it) - a CPE match whose own product component does not
    resemble `product_key` is dropped too (`_product_matches`)."""
    headers = {"apiKey": api_key} if api_key else {}
    try:
        resp = httpx.get(
            NVD_URL, params={"keywordSearch": product_key, "resultsPerPage": 50},
            headers=headers, timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("NVD lookup for %s failed: %s", product_key, exc)
        return None

    candidates: list[dict] = []
    for item in data.get("vulnerabilities", []) if isinstance(data, dict) else []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        cvss_base = _extract_cvss(cve.get("metrics") or {})
        for match in _iter_vulnerable_cpe_matches(cve.get("configurations") or []):
            part, cpe_product, exact_version = _cpe_part_product_version(match.get("criteria") or "")
            if part != "a" or not _product_matches(product_key, cpe_product):
                continue  # not an application CPE match for this product (platform entry or an unrelated bundled product)
            has_range = any(match.get(k) for k in (
                "versionStartIncluding", "versionStartExcluding",
                "versionEndIncluding", "versionEndExcluding",
            ))
            candidates.append({
                "cve_id": cve_id,
                "cvss_base": cvss_base,
                "exact_versions": [exact_version] if not has_range and exact_version else None,
                "version_start_including": match.get("versionStartIncluding"),
                "version_start_excluding": match.get("versionStartExcluding"),
                "version_end_including": match.get("versionEndIncluding"),
                "version_end_excluding": match.get("versionEndExcluding"),
            })
    return candidates


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float] | None:
    """Batched (REQ-CORR-002). Returns None only if every batch failed;
    a CVE missing from the result just has no EPSS score (normal for very
    new/reserved CVEs), not a failure."""
    if not cve_ids:
        return {}
    scores: dict[str, float] = {}
    chunks = [cve_ids[i:i + EPSS_BATCH_SIZE] for i in range(0, len(cve_ids), EPSS_BATCH_SIZE)]
    failures = 0
    for chunk in chunks:
        try:
            resp = httpx.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("EPSS query for %d CVEs failed: %s", len(chunk), exc)
            failures += 1
            continue
        for row in data.get("data", []) if isinstance(data, dict) else []:
            cid = row.get("cve")
            try:
                score = float(row.get("epss"))
            except (TypeError, ValueError):
                continue
            if cid:
                scores[cid] = score
    if failures == len(chunks):
        return None
    return scores


def fetch_kev_catalog() -> tuple[list[str], str | None] | None:
    """Returns (cve_ids, catalog_version) or None on failure."""
    try:
        resp = httpx.get(KEV_URL, timeout=REQUEST_TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("CISA KEV catalog not retrievable: %s", exc)
        return None
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    cve_ids = [v.get("cveID") for v in vulns if isinstance(v, dict) and v.get("cveID")]
    catalog_version = data.get("catalogVersion") if isinstance(data, dict) else None
    return cve_ids, catalog_version
