-- Extended discovery and detection (REQ-COVER-001/003/004/006/007, R4,
-- authorized by johannes 2026-09-29). Per-engagement switches for the four
-- capabilities, plus storage for crawled endpoints and screenshots.
-- Idempotent.
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS subfinder_enabled BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS crawling_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS oob_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS screenshots_enabled BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS discovered_endpoint (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id  UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    scan_run_id    UUID REFERENCES scan_run(id) ON DELETE SET NULL,
    url            TEXT NOT NULL,
    host           TEXT NOT NULL,
    port           INTEGER NOT NULL,
    method         TEXT NOT NULL DEFAULT 'GET',
    source         TEXT NOT NULL,
    param_names    JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_discovered_endpoint UNIQUE (engagement_id, method, url)
);
CREATE INDEX IF NOT EXISTS ix_discovered_endpoint_engagement ON discovered_endpoint (engagement_id);

CREATE TABLE IF NOT EXISTS web_screenshot (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id  UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    scan_run_id    UUID REFERENCES scan_run(id) ON DELETE SET NULL,
    url            TEXT NOT NULL,
    host           TEXT NOT NULL,
    port           INTEGER NOT NULL,
    byte_size      INTEGER NOT NULL DEFAULT 0,
    sha256         VARCHAR(64),
    content        BYTEA,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_web_screenshot_engagement ON web_screenshot (engagement_id);
