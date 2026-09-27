-- REQ-REPORT-001: generated customer reports (Architektur Kap. 6.1).
--
-- The PDF bytes live here rather than in MinIO on purpose: these documents
-- are plain wrapped text (typically well under 100 KB), and the configured
-- S3 path is not used by any code today - adding a client plus credentials
-- for a few kilobytes would be new failure surface for no benefit.
--
-- A report is retained after generation because it is the deliverable: the
-- customer received exactly this document, and a later scan run must not
-- retroactively change it.

CREATE TABLE IF NOT EXISTS report (
  id             UUID PRIMARY KEY,
  engagement_id  UUID NOT NULL REFERENCES engagement(id),
  scan_run_id    UUID REFERENCES scan_run(id),
  status         TEXT NOT NULL DEFAULT 'queued',
  error          TEXT,
  requested_by   TEXT NOT NULL,
  filename       TEXT NOT NULL,
  byte_size      INTEGER NOT NULL DEFAULT 0,
  sha256         VARCHAR(64),
  content        BYTEA,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The list view is always "this engagement's reports, newest first".
CREATE INDEX IF NOT EXISTS report_engagement_created_idx
  ON report (engagement_id, created_at DESC);
