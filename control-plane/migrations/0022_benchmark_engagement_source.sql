-- REQ-BENCH-007: a new engagement_source value, 'benchmark', is the control
-- point that keeps any benchmark-only capability (e.g. default-credential
-- testing) unreachable from a real engagement. Idempotent: ADD VALUE IF NOT
-- EXISTS is safe to re-run (Postgres 12+).
ALTER TYPE engagement_source ADD VALUE IF NOT EXISTS 'benchmark';
