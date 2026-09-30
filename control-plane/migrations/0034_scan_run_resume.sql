-- GitHub issue #42 (REQ-RESUME-001..005): a scan run can be taken over after
-- its worker died and continue from the last completed phase.
--   attempt        how many times a worker has claimed the run (0 = never);
--                  every write a worker makes is fenced by it, so a worker
--                  that was replaced can no longer touch the run
--   owner_task_id  Celery task id of the attempt that currently owns the run
--   checkpoint     what the next phase needs from the completed ones (the
--                  discovered assets, the fingerprinted services, warnings)
--                  plus the task parameters, so a resume needs nothing else
-- Idempotent.
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS attempt INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS owner_task_id TEXT;
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS checkpoint JSONB;
