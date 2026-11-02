-- REQ-HANDOVER-001/007 (GitHub #84): an assessment started from a monitor ("Test deeper") remembers which monitor it
-- follows. Nothing is copied from the monitor; the link is read-only context (what monitoring found, shown to the assessment's
-- agent) and a navigation aid. Deleting the monitor leaves the assessment standing with an empty link.
-- Idempotent: safe to re-run.
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS handover_from_id uuid REFERENCES engagement(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS ix_engagement_handover_from ON engagement (handover_from_id) WHERE handover_from_id IS NOT NULL;
