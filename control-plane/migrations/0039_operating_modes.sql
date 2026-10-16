-- Operating modes: unattended monitoring and attended testing
-- (REQ-MODE-001..019, REQ-MON-001/002).
--
--   engagement.operating_mode          monitoring | assessment (existing rows: assessment)
--   engagement.new_asset_policy        auto | hold            (monitoring)
--   engagement.state_changing_requests capability, off until a consent exists
--   engagement.fragility_breaker       stop on a target that fails after state changes
--   engagement.review_at               standing-authorization review date
--   scan_run.trigger/initiated_by/supervision/health/schedule_id/scope_hosts/retest_finding_id
--   discovered_asset.hold_state        held | released (hold policy)
--   engagement_consent, engagement_schedule, run_inventory_snapshot, change_event,
--   inbox_item, notification_target, alert_event
--
-- scan_profile gains `passive` and `light` (REQ-MODE-011). Idempotent.

-- ---------------------------------------------------------------- engagement
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS operating_mode TEXT NOT NULL DEFAULT 'assessment';
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS new_asset_policy TEXT NOT NULL DEFAULT 'auto';
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS state_changing_requests BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS fragility_breaker BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE engagement ADD COLUMN IF NOT EXISTS review_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_engagement_operating_mode') THEN
        ALTER TABLE engagement ADD CONSTRAINT ck_engagement_operating_mode
            CHECK (operating_mode IN ('monitoring', 'assessment'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_engagement_new_asset_policy') THEN
        ALTER TABLE engagement ADD CONSTRAINT ck_engagement_new_asset_policy
            CHECK (new_asset_policy IN ('auto', 'hold'));
    END IF;
END $$;

-- scan depth: the two new tiers (REQ-MODE-011)
ALTER TABLE engagement DROP CONSTRAINT IF EXISTS ck_engagement_scan_profile;
ALTER TABLE engagement ADD CONSTRAINT ck_engagement_scan_profile
    CHECK (scan_profile IN ('passive', 'light', 'standard', 'thorough'));

-- --------------------------------------------------------------------- scan_run
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS trigger TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS initiated_by TEXT;
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS supervision TEXT;
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS health TEXT;
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS schedule_id UUID;
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS scope_hosts JSONB;
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS retest_finding_id UUID;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_scan_run_trigger') THEN
        ALTER TABLE scan_run ADD CONSTRAINT ck_scan_run_trigger CHECK (trigger IN ('manual', 'scheduled'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_scan_run_supervision') THEN
        ALTER TABLE scan_run ADD CONSTRAINT ck_scan_run_supervision
            CHECK (supervision IS NULL OR supervision IN ('attended', 'semi_attended', 'unattended'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_scan_run_health') THEN
        ALTER TABLE scan_run ADD CONSTRAINT ck_scan_run_health
            CHECK (health IS NULL OR health IN ('ok', 'degraded', 'failed'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_scan_run_engagement_health
    ON scan_run (engagement_id, finished_at DESC) WHERE health IS NOT NULL;

-- ----------------------------------------------------------- discovered_asset
ALTER TABLE discovered_asset ADD COLUMN IF NOT EXISTS hold_state TEXT;
ALTER TABLE discovered_asset ADD COLUMN IF NOT EXISTS held_at TIMESTAMPTZ;
ALTER TABLE discovered_asset ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ;
ALTER TABLE discovered_asset ADD COLUMN IF NOT EXISTS released_by TEXT;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_discovered_asset_hold_state') THEN
        ALTER TABLE discovered_asset ADD CONSTRAINT ck_discovered_asset_hold_state
            CHECK (hold_state IS NULL OR hold_state IN ('held', 'released'));
    END IF;
END $$;

-- ---------------------------------------------------------- engagement_consent
-- Appended, never edited. Current = the latest row of a kind; valid when its action
-- is `given` and its wording version is the one the code currently ships.
CREATE TABLE IF NOT EXISTS engagement_consent (
    id              UUID PRIMARY KEY DEFAULT uuidv7(),
    engagement_id   UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('state_change')),
    action          TEXT NOT NULL CHECK (action IN ('given', 'revoked')),
    wording_version INTEGER NOT NULL,
    wording_sha256  TEXT NOT NULL,
    given_by        TEXT NOT NULL,
    given_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_engagement_consent_lookup
    ON engagement_consent (engagement_id, kind, given_at DESC);

-- --------------------------------------------------------- engagement_schedule
CREATE TABLE IF NOT EXISTS engagement_schedule (
    id               UUID PRIMARY KEY DEFAULT uuidv7(),
    engagement_id    UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    tier             TEXT NOT NULL CHECK (tier IN ('passive', 'light', 'standard', 'thorough')),
    cadence          TEXT NOT NULL CHECK (cadence IN ('daily', 'weekly')),
    time_of_day      TEXT NOT NULL DEFAULT '02:00',
    timezone         TEXT NOT NULL DEFAULT 'UTC',
    weekday          INTEGER CHECK (weekday IS NULL OR weekday BETWEEN 0 AND 6),
    window_start     TEXT,
    window_end       TEXT,
    window_days      INTEGER[],
    jitter_minutes   INTEGER NOT NULL DEFAULT 0 CHECK (jitter_minutes BETWEEN 0 AND 240),
    enabled          BOOLEAN NOT NULL DEFAULT true,
    disabled_reason  TEXT,
    next_run_at      TIMESTAMPTZ,
    last_run_at      TIMESTAMPTZ,
    last_skip_reason TEXT,
    skip_count       INTEGER NOT NULL DEFAULT 0,
    created_by       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (engagement_id, tier)
);
CREATE INDEX IF NOT EXISTS idx_engagement_schedule_due
    ON engagement_schedule (next_run_at) WHERE enabled;

-- ------------------------------------------------------ run_inventory_snapshot
-- What one run saw: assets and services. The change feed is a set difference of
-- two snapshots, independent of how the live tables are updated.
CREATE TABLE IF NOT EXISTS run_inventory_snapshot (
    scan_run_id   UUID NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    engagement_id UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('asset', 'service')),
    key           TEXT NOT NULL,
    data          JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (scan_run_id, kind, key)
);
CREATE INDEX IF NOT EXISTS idx_run_inventory_snapshot_engagement
    ON run_inventory_snapshot (engagement_id);

-- --------------------------------------------------------------- change_event
CREATE TABLE IF NOT EXISTS change_event (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    engagement_id UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    scan_run_id   UUID REFERENCES scan_run(id) ON DELETE SET NULL,
    kind          TEXT NOT NULL,
    subject       TEXT NOT NULL,
    severity      TEXT,
    detail        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_change_event_engagement
    ON change_event (engagement_id, created_at DESC);

-- ----------------------------------------------------------------- inbox_item
CREATE TABLE IF NOT EXISTS inbox_item (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    engagement_id UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    dedupe_key    TEXT NOT NULL,
    summary       TEXT NOT NULL,
    detail        JSONB NOT NULL DEFAULT '{}'::jsonb,
    state         TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'resolved')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at   TIMESTAMPTZ,
    resolved_by   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_inbox_item_open
    ON inbox_item (engagement_id, dedupe_key) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS idx_inbox_item_state ON inbox_item (state, created_at DESC);

-- ---------------------------------------------------------- notification_target
CREATE TABLE IF NOT EXISTS notification_target (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    engagement_id UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('webhook')),
    url           TEXT NOT NULL,
    secret_enc    TEXT,
    min_severity  TEXT NOT NULL DEFAULT 'high'
                  CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notification_target_engagement ON notification_target (engagement_id);

-- ----------------------------------------------------------------- alert_event
CREATE TABLE IF NOT EXISTS alert_event (
    id              UUID PRIMARY KEY DEFAULT uuidv7(),
    engagement_id   UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    target_id       UUID NOT NULL REFERENCES notification_target(id) ON DELETE CASCADE,
    event_kind      TEXT NOT NULL,
    immediate       BOOLEAN NOT NULL DEFAULT false,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    deliver_after   TIMESTAMPTZ NOT NULL DEFAULT now(),
    next_attempt_at TIMESTAMPTZ,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_alert_event_due
    ON alert_event (deliver_after) WHERE state = 'pending';
