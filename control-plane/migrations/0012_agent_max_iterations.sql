-- Per-engagement override for the Vector Agent iteration budget
-- (REQ-AGENT-008). NULL inherits the global app_setting default (50).

ALTER TABLE engagement
  ADD COLUMN IF NOT EXISTS agent_max_iterations_override INTEGER;
