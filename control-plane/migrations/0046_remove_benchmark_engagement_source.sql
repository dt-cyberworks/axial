-- REQ-BENCHSEP-001/006 (GitHub #90): there is no engagement source called 'benchmark'.
-- A benchmark run is an ordinary engagement, and nothing in the product may behave differently because something is
-- being measured. Existing benchmark-source engagements become 'lab' (nothing is deleted); the audit log is not touched,
-- so rows whose actor is 'internal:benchmark-harness' or whose payload says "source": "benchmark" stay as they were
-- and the hash chain still verifies. Postgres cannot drop an enum value, so the type is recreated without it.
-- Idempotent: it does nothing once the value is gone. Migration 0022, which added the value, is history and is not edited.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid
    WHERE t.typname = 'engagement_source' AND e.enumlabel = 'benchmark'
  ) THEN
    UPDATE engagement SET source = 'lab' WHERE source = 'benchmark';
    ALTER TYPE engagement_source RENAME TO engagement_source_with_benchmark;
    CREATE TYPE engagement_source AS ENUM ('lab', 'own_domain', 'bug_bounty', 'customer');
    ALTER TABLE engagement ALTER COLUMN source TYPE engagement_source USING source::text::engagement_source;
    DROP TYPE engagement_source_with_benchmark;
  END IF;
END
$$;
