-- Incremental migration for existing M1 databases that were created before
-- Agent settings, ai_testing opt-in, and DNS materialization existed.

ALTER TABLE engagement
  ADD COLUMN IF NOT EXISTS ai_testing_allowed BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS resolved_host (
  id             UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id  UUID NOT NULL REFERENCES engagement(id),
  scope_asset_id UUID REFERENCES scope_asset(id),
  hostname       TEXT NOT NULL,
  ip_address     TEXT NOT NULL,
  resolved_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (engagement_id, hostname, ip_address)
);

CREATE TABLE IF NOT EXISTS app_setting (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_resolved_host_engagement ON resolved_host(engagement_id);
