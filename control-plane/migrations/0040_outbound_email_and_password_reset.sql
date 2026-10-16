-- Optional outbound e-mail (GitHub issue #45, REQ-MAIL-001..005) and the self-service
-- password reset that uses it (GitHub issue #44, REQ-IAM-020). Idempotent.
--
--   mail_outbox            queued messages; the body is encrypted and removed after delivery
--   password_reset_token   single-use reset tokens, stored only as a hash
--
-- The mail relay settings live in app_setting (key `mail_config`), like the LLM provider.

CREATE TABLE IF NOT EXISTS mail_outbox (
    id              UUID PRIMARY KEY DEFAULT uuidv7(),
    kind            TEXT NOT NULL,
    to_address      TEXT NOT NULL,
    subject         TEXT NOT NULL,
    body_enc        TEXT,
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    requested_by    UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_mail_outbox_due ON mail_outbox (next_attempt_at) WHERE state = 'pending';

CREATE TABLE IF NOT EXISTS password_reset_token (
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id        UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    token_hash     TEXT NOT NULL UNIQUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ,
    invalidated_at TIMESTAMPTZ,
    attempts       INTEGER NOT NULL DEFAULT 0,
    request_ip     TEXT
);
CREATE INDEX IF NOT EXISTS idx_password_reset_token_user ON password_reset_token (user_id, created_at DESC);
