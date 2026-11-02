-- Retest and run only what is still open (REQ-RETEST-001..009, GitHub #75).
--
-- Additive and idempotent. The previous release ignores the new column and table, so rolling the
-- application back is safe.

-- A run restricted to a list of checks (NULL = a full run). Each item names a host, optionally a
-- port, and one of an exact check id, a check family or a tool.
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS retest_items JSONB;

-- A request an unattended run could not get a decision for, kept whole so that a person can look at
-- it later and decide to send it, one request at a time.
CREATE TABLE IF NOT EXISTS open_request (
    id                 UUID PRIMARY KEY DEFAULT uuidv7(),
    engagement_id      UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    source_run_id      UUID REFERENCES scan_run(id) ON DELETE SET NULL,
    source_approval_id UUID,
    tool               TEXT NOT NULL,
    target             TEXT NOT NULL,
    method             TEXT,
    path               TEXT,
    call               JSONB NOT NULL,
    rationale          TEXT NOT NULL DEFAULT '',
    risk               JSONB,
    state_changing     BOOLEAN NOT NULL DEFAULT TRUE,
    reason             TEXT NOT NULL,
    dedupe_key         TEXT NOT NULL,
    state              TEXT NOT NULL DEFAULT 'open',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at         TIMESTAMPTZ,
    decided_by         TEXT,
    sent_run_id        UUID REFERENCES scan_run(id) ON DELETE SET NULL,
    sent_approval_id   UUID
);

ALTER TABLE open_request DROP CONSTRAINT IF EXISTS ck_open_request_state;
ALTER TABLE open_request ADD CONSTRAINT ck_open_request_state
    CHECK (state IN ('open', 'sent', 'rejected', 'expired', 'superseded'));

-- One open item per distinct request.
CREATE UNIQUE INDEX IF NOT EXISTS uq_open_request_one_open
    ON open_request (engagement_id, dedupe_key) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS ix_open_request_engagement ON open_request (engagement_id, state);
