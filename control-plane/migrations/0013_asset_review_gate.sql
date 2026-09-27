-- Post-discovery asset review gate (REQ-ASSETREVIEW-001..007).
--
-- Optional, per-engagement pause between discovery and fingerprint: the
-- operator reviews the in-scope discovered assets and may exclude specific
-- hosts/IPs before the rest of the pipeline touches them. An exclusion becomes
-- a real, gateway-enforced deny scope_asset row (see decide endpoint) - this
-- table only tracks the review lifecycle itself.

ALTER TABLE engagement
  ADD COLUMN IF NOT EXISTS asset_review_enabled BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS asset_review_request (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id      UUID NOT NULL REFERENCES engagement(id),
    scan_run_id        UUID NOT NULL UNIQUE REFERENCES scan_run(id),
    candidate_assets   JSONB NOT NULL,
    state              TEXT NOT NULL DEFAULT 'pending',
    excluded_values    JSONB,
    expires_at         TIMESTAMPTZ NOT NULL,
    decided_at         TIMESTAMPTZ,
    decided_by         TEXT
);

CREATE INDEX IF NOT EXISTS idx_asset_review_request_engagement_state
  ON asset_review_request(engagement_id, state);
