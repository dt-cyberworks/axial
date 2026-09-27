-- Individual accounts + mandatory TOTP MFA + per-user engagement ownership
-- (REQ-IAM-002..011). Extends REQ-IAM-001 (minimum-safe-operation.md), which
-- explicitly scoped itself to a single shared operator credential and flagged
-- RBAC as required before expanding the operating model.

CREATE TABLE IF NOT EXISTS app_user (
    id                     UUID PRIMARY KEY DEFAULT uuidv7(),
    email                  TEXT NOT NULL UNIQUE,
    display_name           TEXT NOT NULL,
    password_hash          TEXT NOT NULL,
    role                   TEXT NOT NULL DEFAULT 'operator' CHECK (role IN ('admin', 'operator')),
    status                 TEXT NOT NULL DEFAULT 'invited' CHECK (status IN ('invited', 'active', 'disabled')),
    must_change_password   BOOLEAN NOT NULL DEFAULT true,
    totp_secret_encrypted  BYTEA,
    totp_confirmed_at      TIMESTAMPTZ,
    totp_last_step         BIGINT,
    failed_password_count  INT NOT NULL DEFAULT 0,
    locked_until           TIMESTAMPTZ,
    created_by_user_id     UUID REFERENCES app_user(id),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at          TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_backup_code (
    id          UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id     UUID NOT NULL REFERENCES app_user(id),
    code_hash   TEXT NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_user_backup_code_user ON user_backup_code(user_id);

CREATE TABLE IF NOT EXISTS login_challenge (
    id           UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id      UUID NOT NULL REFERENCES app_user(id),
    purpose      TEXT NOT NULL CHECK (purpose IN ('set_password', 'mfa_verify', 'mfa_enroll')),
    attempts     INT NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_login_challenge_user ON login_challenge(user_id);

CREATE TABLE IF NOT EXISTS user_session (
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id        UUID NOT NULL REFERENCES app_user(id),
    token_hash     TEXT NOT NULL UNIQUE,
    ip_address     TEXT,
    user_agent     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_user_session_user ON user_session(user_id);

-- Separate, globally hash-chained trail (REQ-IAM-009) - deliberately NOT the
-- same table/chain as audit_log (app/gateway/audit.py), which is chained
-- PER ENGAGEMENT and carries per-engagement legal-evidence semantics that
-- account/security events (no engagement) don't fit and must not dilute.
CREATE TABLE IF NOT EXISTS account_audit_log (
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user_id  UUID REFERENCES app_user(id),
    action         TEXT NOT NULL,
    outcome        TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    ip_address     TEXT,
    user_agent     TEXT,
    payload        JSONB NOT NULL DEFAULT '{}',
    prev_hash      TEXT,
    row_hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_audit_log_ts ON account_audit_log(ts);

ALTER TABLE engagement ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES app_user(id);
