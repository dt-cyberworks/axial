-- Monitoring target baseline (REQ-BASE-001..006): discover, let the owner select, then scan.
--
-- Additive and idempotent. The previous release ignores these columns, so rolling the application
-- back is safe. The decision itself is kept as ordinary `deny` rows of scope_asset and as audit rows.

ALTER TABLE engagement ADD COLUMN IF NOT EXISTS target_review_state TEXT;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS target_review_run_id UUID;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS targets_confirmed_at TIMESTAMPTZ;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS targets_confirmed_by TEXT;

ALTER TABLE engagement DROP CONSTRAINT IF EXISTS ck_engagement_target_review_state;
ALTER TABLE engagement ADD CONSTRAINT ck_engagement_target_review_state
    CHECK (target_review_state IS NULL
           OR target_review_state IN ('discovering', 'awaiting_selection', 'confirmed', 'discovery_failed'));

-- A monitor that already exists was never asked: it keeps running as it is and can review its
-- targets from the engagement page at any time.
UPDATE engagement
   SET target_review_state = 'confirmed', targets_confirmed_at = now(), targets_confirmed_by = 'legacy'
 WHERE operating_mode = 'monitoring'
   AND status IN ('active', 'paused', 'completed')
   AND target_review_state IS NULL;

-- The discovery run that opens the baseline has its own trigger.
ALTER TABLE scan_run DROP CONSTRAINT IF EXISTS ck_scan_run_trigger;
ALTER TABLE scan_run ADD CONSTRAINT ck_scan_run_trigger CHECK (trigger IN ('manual', 'scheduled', 'baseline'));
