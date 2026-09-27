-- Scan-run liveness heartbeat for self-healing raw-egress lease lifecycle.
--
-- A run that stops making progress (worker crashed or hung) must not block new
-- scans for its engagement forever. The worker refreshes heartbeat_at while the
-- run progresses; the control plane reaps runs whose heartbeat is stale before
-- creating a new run. See docs/requirements/raw-egress-lease-stability.md
-- (REQ-RAWLEASE-001).

ALTER TABLE scan_run
  ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Reaper reads active runs by (engagement, state, heartbeat_at).
CREATE INDEX IF NOT EXISTS idx_scan_run_active_heartbeat
  ON scan_run(engagement_id, state, heartbeat_at);
