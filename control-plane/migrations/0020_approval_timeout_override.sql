-- Per-engagement override for the manual-approval expiry duration
-- (REQ-APPROVAL-005). NULL inherits the global app_setting default (900s).

ALTER TABLE engagement
  ADD COLUMN IF NOT EXISTS approval_timeout_seconds_override INTEGER;
