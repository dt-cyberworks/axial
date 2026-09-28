-- REQ-TRIAGE-001: who changed a finding's status, when, and why. The status
-- column itself already allows open/accepted_risk/resolved/false_positive
-- (0001); until now nothing could set it. The justification is kept on the
-- finding (not only in the audit log) because the console and the report
-- show it next to the finding. Idempotent.
ALTER TABLE finding ADD COLUMN IF NOT EXISTS status_note TEXT;
ALTER TABLE finding ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ;
ALTER TABLE finding ADD COLUMN IF NOT EXISTS status_changed_by TEXT;
