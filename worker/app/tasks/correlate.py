"""Phase 3 - Vulnerability Correlation (REQ-CORR-001..008).

Live NVD/EPSS/CISA-KEV correlation for real (non-lab) engagements. Computed
against third-party data sources - no contact with the target, so no gateway
call is needed (the same class as discovery.py's passive OSINT sources).

Lab engagements stay unchanged: `known_vulns.py` is still wired directly into
fingerprint.py's `_nmap_scan` (REQ-CORR-006) so that the lab test loop stays
deterministic and works without internet access - this phase explicitly skips
lab targets instead of also checking them against NVD.

`services`: the list aggregated by fingerprint.run() - a mix of nmap entries
(`product`/`product_name`/`version`) and httpx entries (`tech`: list of
strings), see REQ-CORR-007.
"""

from __future__ import annotations

import datetime as dt
import logging

from app.control_plane_client import client
from app.lab_hosts import is_lab_host
from app.nvd_client import fetch_epss_scores, fetch_kev_catalog, fetch_nvd_candidates
from app.product_signature import normalize_product_key, split_tech_entry
from app.version_compare import version_in_range

logger = logging.getLogger(__name__)

NVD_CACHE_TTL_SECONDS = 24 * 3600
EPSS_CACHE_TTL_SECONDS = 24 * 3600
KEV_CACHE_TTL_SECONDS = 6 * 3600


_BOUND_KEYS = (
    "version_start_including", "version_start_excluding", "version_end_including", "version_end_excluding",
)
# REQ-CORR-009: a CVE whose only NVD rows carry no version limit is weaker evidence than one with a
# documented affected range, so it carries less weight in the risk score.
UNBOUNDED_EXPOSURE_FACTOR = 0.5
UNBOUNDED_NOTE = (
    "NVD lists no affected-version limit for this CVE, so every version of the product matches. "
    "Old NVD records are often too sparse to say where the problem ended: check the CVE text against "
    "the version actually in use before acting on it."
)


def _is_bounded(candidate: dict) -> bool:
    """True if this NVD row says WHICH versions are affected (an exact version or any range bound)."""
    return bool(candidate.get("exact_versions")) or any(candidate.get(k) for k in _BOUND_KEYS)


def _matches_version(version: str, candidate: dict) -> bool:
    return version_in_range(
        version,
        start_including=candidate.get("version_start_including"),
        start_excluding=candidate.get("version_start_excluding"),
        end_including=candidate.get("version_end_including"),
        end_excluding=candidate.get("version_end_excluding"),
        exact_versions=candidate.get("exact_versions"),
    )


def match_cves(version: str, candidates: list[dict]) -> list[dict]:
    """The CVEs a detected version is affected by, one entry per CVE (REQ-CORR-001/009).

    NVD gives one row per CPE-match node of a CVE. Old records often hold a row with no version limit
    next to correctly bounded rows, or on its own. The rows of one CVE are judged together:

    * if any row of the CVE is bounded, only the bounded rows decide, and a lone unbounded row can no
      longer make a version affected that every bounded row excludes (GitHub #69: CVE-2007-2768 against
      OpenSSH 9.6p1);
    * if no row is bounded, the CVE matches every version, as NVD says, but it is marked `unbounded`
      so it is reported with less weight and a plain explanation.
    """
    by_cve: dict[str, list[dict]] = {}
    for cand in candidates:
        if cand.get("cve_id"):
            by_cve.setdefault(cand["cve_id"], []).append(cand)
    out: list[dict] = []
    for cve_id, rows in by_cve.items():
        bounded = [r for r in rows if _is_bounded(r)]
        if bounded:
            hit = next((r for r in bounded if _matches_version(version, r)), None)
            if hit is not None:
                out.append({"cve_id": cve_id, "cvss_base": hit.get("cvss_base"), "bounded": True})
        elif any(_matches_version(version, r) for r in rows):
            out.append({"cve_id": cve_id, "cvss_base": rows[0].get("cvss_base"), "bounded": False})
    return out


def _is_stale(fetched_at, ttl_seconds: int) -> bool:
    if not fetched_at:
        return True
    try:
        ts = dt.datetime.fromisoformat(str(fetched_at).replace("Z", "+00:00"))
    except ValueError:
        return True
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - ts).total_seconds() > ttl_seconds


def _resolve_signatures(entry: dict) -> list[tuple[str, str, str]]:
    """(name, version, source_label) triples this service entry yields for
    correlation. A signal with no usable version is never included
    (REQ-CORR-001/007) - there is no way to confirm an affected-version
    range without one."""
    out: list[tuple[str, str, str]] = []
    if "tech" in entry:
        for tech in entry.get("tech") or []:
            if not isinstance(tech, str) or not tech.strip():
                continue
            name, version = split_tech_entry(tech)
            if name and version:
                out.append((name, version, "httpx_tech_stack"))
    else:
        name = entry.get("product_name") or entry.get("product")
        version = entry.get("version")
        if name and version:
            out.append((name, version, "nmap_banner"))
    return out


def run(engagement_id: str, services: list[dict]) -> list[dict]:
    real_services = [s for s in services if not is_lab_host(str(s.get("target", "")))]
    signatures = [
        (name, version, source_label, entry)
        for entry in real_services
        for name, version, source_label in _resolve_signatures(entry)
    ]
    if not signatures:
        logger.info("correlate: no product/version signals to correlate for engagement %s", engagement_id)
        return []

    try:
        nvd_config = client.get_nvd_config()
        api_key = nvd_config.get("api_key") or None
    except Exception as exc:  # noqa: BLE001 - config lookup failure -> just no key
        logger.warning("NVD config not retrievable, continuing without an API key: %s", exc)
        api_key = None

    nvd_ok = epss_ok = kev_ok = True

    # 1. NVD candidates per distinct product key, cache-first (REQ-CORR-001/004).
    candidates_by_key: dict[str, list[dict]] = {}
    for name, _version, _source, _entry in signatures:
        key = normalize_product_key(name)
        if key in candidates_by_key:
            continue
        try:
            cached = client.get_cve_lookup_cache(key)
        except Exception as exc:  # noqa: BLE001 - cache read failure is not an NVD failure
            logger.warning("cve_lookup_cache not readable for %s: %s", key, exc)
            cached = None
        if cached is not None and not _is_stale(cached.get("fetched_at"), NVD_CACHE_TTL_SECONDS):
            candidates_by_key[key] = cached["candidates"]
            continue
        fetched = fetch_nvd_candidates(key, api_key=api_key)
        if fetched is None:
            nvd_ok = False
            candidates_by_key[key] = cached["candidates"] if cached is not None else []
            continue
        candidates_by_key[key] = fetched
        try:
            client.put_cve_lookup_cache(key, fetched)
        except Exception as exc:  # noqa: BLE001 - a cache-write failure must not drop the data we already have
            logger.warning("cve_lookup_cache not writable for %s: %s", key, exc)

    # 2. Local version-range filter -> per-service CVE matches (REQ-CORR-001/009).
    matches: list[dict] = []
    for name, version, source_label, entry in signatures:
        key = normalize_product_key(name)
        for hit in match_cves(version, candidates_by_key.get(key, [])):
            matches.append({
                "entry": entry, "cve_id": hit["cve_id"], "cvss_base": hit["cvss_base"], "bounded": hit["bounded"],
                "source_label": source_label, "name": name, "version": version,
            })

    if not matches:
        if not nvd_ok:
            logger.warning("correlate: NVD not reachable for engagement %s, no matches this run", engagement_id)
        return []

    all_cve_ids = sorted({m["cve_id"] for m in matches})

    # 3. EPSS enrichment, cache-first + batched (REQ-CORR-002/004).
    try:
        epss_cached = client.get_epss_cache(all_cve_ids)
        epss_scores: dict[str, float] = dict(epss_cached.get("scores") or {})
    except Exception as exc:  # noqa: BLE001
        logger.warning("epss_cache not readable: %s", exc)
        epss_scores = {}
    missing_epss = [c for c in all_cve_ids if c not in epss_scores]
    if missing_epss:
        fetched_epss = fetch_epss_scores(missing_epss)
        if fetched_epss is None:
            epss_ok = False
        else:
            epss_scores.update(fetched_epss)
            if fetched_epss:
                try:
                    client.put_epss_cache(fetched_epss)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("epss_cache not writable: %s", exc)

    # 4. KEV membership, cache-first, once per run (REQ-CORR-003/004).
    kev_ids: set[str] = set()
    try:
        kev_cached = client.get_kev_catalog_cache()
    except Exception as exc:  # noqa: BLE001
        logger.warning("kev_catalog_cache not readable: %s", exc)
        kev_cached = {}
    kev_ids = set(kev_cached.get("cve_ids") or [])
    if _is_stale(kev_cached.get("fetched_at"), KEV_CACHE_TTL_SECONDS):
        fetched_kev = fetch_kev_catalog()
        if fetched_kev is None:
            kev_ok = False
        else:
            ids, catalog_version = fetched_kev
            kev_ids = set(ids)
            try:
                client.put_kev_catalog_cache(ids, catalog_version)
            except Exception as exc:  # noqa: BLE001
                logger.warning("kev_catalog_cache not writable: %s", exc)

    # 5. Persist findings (REQ-CORR-005: partial source failure never
    # discards matches already obtained from the sources that did succeed).
    written: list[dict] = []
    for m in matches:
        entry = m["entry"]
        cve_id = m["cve_id"]
        evidence = {
            # REQ-CORR-009: attributed to the correlation itself, not "unknown tool" in the console.
            "tool": "nvd_correlation", "source": m["source_label"], "product": m["name"], "version": m["version"],
            "cve_id": cve_id, "affected_versions": "documented range" if m["bounded"] else "unbounded",
        }
        if not m["bounded"]:
            evidence["note"] = UNBOUNDED_NOTE
        finding = client.add_finding(
            engagement_id, asset_id=entry.get("asset_id"), service_id=entry.get("service_id"),
            category="cve", title=f"{m['name']} {m['version']} - {cve_id}",
            cve_ids=[cve_id], cvss_base=m["cvss_base"], epss=epss_scores.get(cve_id),
            is_kev=cve_id in kev_ids, confidence="inferred", evidence=evidence,
            exposure_factor=1.0 if m["bounded"] else UNBOUNDED_EXPOSURE_FACTOR, business_factor=0.5,
        )
        written.append(finding)

    if not (nvd_ok and epss_ok and kev_ok):
        logger.warning(
            "correlate: degraded outcome for engagement %s (nvd_ok=%s epss_ok=%s kev_ok=%s) - "
            "%d findings persisted anyway",
            engagement_id, nvd_ok, epss_ok, kev_ok, len(written),
        )
    return written
