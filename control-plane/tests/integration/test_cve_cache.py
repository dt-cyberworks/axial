"""REQ-CORR-004: the live NVD/EPSS/KEV correlation cache endpoints
(worker-facing, internal API). Plain read-through key/value storage -
staleness/TTL is the worker's decision, these tests only cover storage
correctness (miss, roundtrip, upsert, batch-miss-omission)."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.internal import (
    internal_get_cve_lookup_cache,
    internal_get_epss_cache,
    internal_get_kev_catalog_cache,
    internal_nvd_config,
    internal_put_cve_lookup_cache,
    internal_put_epss_cache,
    internal_put_kev_catalog_cache,
)
from app.schemas.internal import (
    CveLookupCacheIn,
    EpssCacheBatchIn,
    EpssCacheEntryIn,
    KevCatalogCacheIn,
)


def test_cve_lookup_cache_miss_raises_404(db):
    with pytest.raises(HTTPException) as exc_info:
        internal_get_cve_lookup_cache("neverseen", db)
    assert exc_info.value.status_code == 404


def test_cve_lookup_cache_put_then_get_roundtrip(db):
    candidates = [{"cve_id": "CVE-2024-0001", "cvss_base": 9.8,
                   "version_start_including": "1.0", "version_end_excluding": "2.0"}]
    internal_put_cve_lookup_cache(CveLookupCacheIn(product_key="openssh", candidates=candidates), db)

    out = internal_get_cve_lookup_cache("openssh", db)
    assert out.product_key == "openssh"
    assert out.candidates == candidates
    assert out.source == "nvd"


def test_cve_lookup_cache_put_upserts_same_product_key(db):
    first = [{"cve_id": "CVE-2024-0001", "cvss_base": 9.8}]
    second = [{"cve_id": "CVE-2024-0002", "cvss_base": 5.0}]
    internal_put_cve_lookup_cache(CveLookupCacheIn(product_key="nginx", candidates=first), db)
    internal_put_cve_lookup_cache(CveLookupCacheIn(product_key="nginx", candidates=second), db)

    out = internal_get_cve_lookup_cache("nginx", db)
    assert out.candidates == second


def test_epss_cache_omits_misses_and_batch_upserts(db):
    internal_put_epss_cache(
        EpssCacheBatchIn(entries=[
            EpssCacheEntryIn(cve_id="CVE-2024-0001", epss=0.42),
            EpssCacheEntryIn(cve_id="CVE-2024-0002", epss=0.01),
        ]),
        db,
    )

    out = internal_get_epss_cache("CVE-2024-0001,CVE-2024-0002,CVE-2024-9999", db)
    assert out.scores == {"CVE-2024-0001": 0.42, "CVE-2024-0002": 0.01}
    assert "CVE-2024-9999" not in out.scores


def test_epss_cache_upsert_overwrites_existing_score(db):
    internal_put_epss_cache(EpssCacheBatchIn(entries=[EpssCacheEntryIn(cve_id="CVE-2024-0003", epss=0.1)]), db)
    internal_put_epss_cache(EpssCacheBatchIn(entries=[EpssCacheEntryIn(cve_id="CVE-2024-0003", epss=0.9)]), db)

    out = internal_get_epss_cache("CVE-2024-0003", db)
    assert out.scores["CVE-2024-0003"] == 0.9


def test_kev_catalog_cache_empty_before_first_fetch(db):
    out = internal_get_kev_catalog_cache(db)
    assert out.cve_ids == []
    assert out.fetched_at is None


def test_kev_catalog_cache_put_then_get_roundtrip(db):
    internal_put_kev_catalog_cache(
        KevCatalogCacheIn(cve_ids=["CVE-2021-2523", "CVE-2010-2075"], catalog_version="2026.07.01"), db
    )

    out = internal_get_kev_catalog_cache(db)
    assert set(out.cve_ids) == {"CVE-2021-2523", "CVE-2010-2075"}
    assert out.catalog_version == "2026.07.01"
    assert out.fetched_at is not None


def test_kev_catalog_cache_put_replaces_snapshot(db):
    internal_put_kev_catalog_cache(KevCatalogCacheIn(cve_ids=["CVE-A"], catalog_version="v1"), db)
    internal_put_kev_catalog_cache(KevCatalogCacheIn(cve_ids=["CVE-B"], catalog_version="v2"), db)

    out = internal_get_kev_catalog_cache(db)
    assert out.cve_ids == ["CVE-B"]
    assert out.catalog_version == "v2"


def test_nvd_config_unset_by_default(db):
    cfg = internal_nvd_config(db)
    assert cfg.source in {"unset", "env"}  # env-based CI config is legitimate, just never "db" here
    if cfg.source == "unset":
        assert cfg.api_key is None
