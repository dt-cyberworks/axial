-- Evidence-driven scan pipeline (REQ-PIPE-003/005/008/010, R3, approved by
-- johannes 2026-09-29): the persisted scan plan. A `scan_surface` is one open
-- port of an approved asset with its service class and technology profile; a
-- `scan_check` is one planned (or deliberately skipped) check against a
-- surface. The check row is the checkpoint: a resumed run continues with the
-- next unfinished check. Idempotent.

ALTER TABLE engagement ADD COLUMN IF NOT EXISTS scan_profile VARCHAR(16) NOT NULL DEFAULT 'standard';
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS scan_profile VARCHAR(16);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_engagement_scan_profile') THEN
        ALTER TABLE engagement ADD CONSTRAINT ck_engagement_scan_profile
            CHECK (scan_profile IN ('standard', 'thorough'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS scan_surface (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id    UUID NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    engagement_id  UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    asset_id       UUID REFERENCES discovered_asset(id) ON DELETE SET NULL,
    host           TEXT NOT NULL,
    ip             TEXT,
    port           INTEGER NOT NULL,
    scheme         TEXT,
    service_class  VARCHAR(16) NOT NULL,
    alias_of       TEXT,
    profile        JSONB NOT NULL DEFAULT '[]'::jsonb,
    fingerprint    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_scan_surface UNIQUE (scan_run_id, host, port),
    CONSTRAINT ck_scan_surface_class CHECK (service_class IN ('web', 'web_alias', 'tls_service', 'service', 'unknown'))
);
CREATE INDEX IF NOT EXISTS ix_scan_surface_run ON scan_surface (scan_run_id);
CREATE INDEX IF NOT EXISTS ix_scan_surface_engagement ON scan_surface (engagement_id);

CREATE TABLE IF NOT EXISTS scan_check (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id    UUID NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    engagement_id  UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    surface_id     UUID NOT NULL REFERENCES scan_surface(id) ON DELETE CASCADE,
    seq            INTEGER NOT NULL,
    check_id       TEXT NOT NULL,
    tool           TEXT NOT NULL,
    args           JSONB NOT NULL DEFAULT '{}'::jsonb,
    depends_on     TEXT,
    state          VARCHAR(16) NOT NULL DEFAULT 'planned',
    reason         TEXT NOT NULL,
    budget_s       INTEGER,
    attempt        INTEGER NOT NULL DEFAULT 0,
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    duration_s     NUMERIC(10, 2),
    findings       INTEGER NOT NULL DEFAULT 0,
    outcome_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT uq_scan_check UNIQUE (scan_run_id, surface_id, check_id),
    CONSTRAINT ck_scan_check_state CHECK (state IN ('planned', 'running', 'complete', 'partial', 'failed', 'skipped'))
);
CREATE INDEX IF NOT EXISTS ix_scan_check_run ON scan_check (scan_run_id, seq);
CREATE INDEX IF NOT EXISTS ix_scan_check_engagement ON scan_check (engagement_id);
