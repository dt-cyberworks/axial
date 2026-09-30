-- GitHub issue #40 (REQ-RATE-001): one row per call or network request that
-- was allowed to go ahead, reserved BEFORE it goes ahead. The rate limit counts
-- these rows under a per-(engagement, path) advisory lock, so concurrent
-- callers can no longer all read the same count and all proceed. The audit
-- log stays the record of what happened; it is no longer the counter.
-- Rows older than an hour are pruned by the reservation code. Idempotent.
CREATE TABLE IF NOT EXISTS rate_reservation (
  id            BIGSERIAL PRIMARY KEY,
  engagement_id UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
  path          TEXT NOT NULL CHECK (path IN ('gateway', 'proxy')),
  ts            TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS rate_reservation_window
  ON rate_reservation (engagement_id, path, ts);
