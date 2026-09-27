-- REQ-AGENT-026: per-engagement override for the Vector Agent's completion
-- token cap, mirroring agent_max_iterations_override /
-- approval_timeout_seconds_override. NULL (the default, and what every
-- existing row gets) means "inherit the global default"
-- (app_setting['agent_max_tokens'], else the built-in 8192), so a plain ADD
-- COLUMN is a zero-behavior-change backfill.
--
-- Bounds match settings_store's MIN/MAX_AGENT_MAX_TOKENS and the worker's own
-- re-clamp, so no layer can produce a cap outside 1024-32768.

ALTER TABLE engagement
  ADD COLUMN IF NOT EXISTS agent_max_tokens_override INTEGER;

-- Postgres has no ADD CONSTRAINT IF NOT EXISTS, and the runner's
-- schema_migration table already guarantees one execution - this guard just
-- keeps the file independently re-runnable, as required for migrations here.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'engagement_agent_max_tokens_override_bounds_chk'
  ) THEN
    ALTER TABLE engagement
      ADD CONSTRAINT engagement_agent_max_tokens_override_bounds_chk
        CHECK (agent_max_tokens_override IS NULL
               OR agent_max_tokens_override BETWEEN 1024 AND 32768);
  END IF;
END $$;
