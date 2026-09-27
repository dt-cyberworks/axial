-- GitHub issue #18: "one active scan_run per engagement" previously existed
-- only as two racing application-level reads (start_scan, create_scan_run) -
-- concurrent requests could both pass the check and both insert a running
-- row, doubling real traffic sent at a real target and doubling the
-- per-engagement rate limit (authorize.py's rate check serializes via a
-- per-scan_run row lock, so two runs on one engagement are throttled
-- independently). This index makes the rule a real database invariant,
-- enforced regardless of how many processes race, in addition to (not
-- instead of) the application-level check that still returns a clean 409.
--
-- Idempotent: if a pre-existing deployment somehow already has duplicate
-- active rows, this CREATE UNIQUE INDEX fails loudly (migration aborts)
-- rather than silently reaping data - a duplicate active run is exactly the
-- kind of state an operator should be told about, not have quietly cleaned
-- up during a migration.
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_run_one_active_per_engagement
  ON scan_run (engagement_id)
  WHERE state IN ('running', 'waiting_approval');
