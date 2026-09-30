-- Evidence-driven scan pipeline (REQ-PIPE-014). The `validate` phase performed
-- no validation and was removed; a run stored at it continues at `score`. The
-- enum value itself stays (PostgreSQL cannot drop enum values), it is simply
-- never written again. Idempotent.
UPDATE scan_run SET phase = 'score' WHERE phase = 'validate';
