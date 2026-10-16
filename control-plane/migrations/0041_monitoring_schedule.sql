-- Run a monitoring engagement every N days (REQ-MON-001, REQ-MON-003).
--
-- One interval per engagement, stored on the engagement itself. Additive and idempotent: the code of
-- the previous release ignores these columns, so a rollback of the application is safe. The table
-- engagement_schedule from 0039 stays in place, unused.

ALTER TABLE engagement ADD COLUMN IF NOT EXISTS schedule_every_days SMALLINT;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS schedule_set_at TIMESTAMPTZ;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS schedule_anchor_at TIMESTAMPTZ;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS schedule_skip_reason TEXT;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS schedule_skip_since TIMESTAMPTZ;

ALTER TABLE engagement DROP CONSTRAINT IF EXISTS ck_engagement_schedule_every_days;
ALTER TABLE engagement ADD CONSTRAINT ck_engagement_schedule_every_days
    CHECK (schedule_every_days IS NULL OR schedule_every_days BETWEEN 1 AND 90);

-- Only a monitoring engagement can have one.
ALTER TABLE engagement DROP CONSTRAINT IF EXISTS ck_engagement_schedule_monitoring_only;
ALTER TABLE engagement ADD CONSTRAINT ck_engagement_schedule_monitoring_only
    CHECK (schedule_every_days IS NULL OR operating_mode = 'monitoring');

-- The scheduler's tick looks only at engagements that have an interval.
CREATE INDEX IF NOT EXISTS idx_engagement_schedule_due
    ON engagement (schedule_anchor_at) WHERE schedule_every_days IS NOT NULL;
