-- Live NVD/EPSS/KEV correlation cache (REQ-CORR-001..008).
--
-- Read-through cache so the worker's correlate phase does not re-query NVD/
-- EPSS/CISA-KEV for every scan run. Cached at product-name granularity for
-- NVD (a new version of an already-seen product needs no new NVD request,
-- only a local version-range check), per-CVE for EPSS, and as one catalog
-- snapshot for KEV. Staleness (TTL) is a worker-side decision based on
-- fetched_at; these tables are plain key/value storage.

CREATE TABLE IF NOT EXISTS cve_lookup_cache (
    id           UUID PRIMARY KEY DEFAULT uuidv7(),
    product_key  TEXT NOT NULL UNIQUE,
    candidates   JSONB NOT NULL,
    fetched_at   TIMESTAMPTZ NOT NULL,
    source       TEXT NOT NULL DEFAULT 'nvd'
);

CREATE TABLE IF NOT EXISTS epss_score_cache (
    cve_id      TEXT PRIMARY KEY,
    epss        NUMERIC(5, 4) NOT NULL,
    fetched_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS kev_catalog_cache (
    id               SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    cve_ids          JSONB NOT NULL,
    catalog_version  TEXT,
    fetched_at       TIMESTAMPTZ NOT NULL
);
