-- REQ-TESTACCT-001/002/006/007 (GitHub #89): dedicated test accounts that an engagement's owner enters so the agent can test
-- behind a login. Idempotent.
--
-- engagement_test_account       one account of one engagement; the secret is Fernet-encrypted and NULL once erased
-- engagement_test_account_host  the hosts the owner assigned it to (D8): an account is bound to those hosts only
-- engagement_login_consent      a monitor's consent to log in, appended and never edited; it covers (account, host) pairs
-- engagement_test_account_login_attempt   one row per login request the gateway allowed, for the attempt limits
-- Rollback: nothing else reads these tables; dropping them is safe and the previous version ignores them.

CREATE TABLE IF NOT EXISTS engagement_test_account (
  id                  UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id       UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
  label               TEXT NOT NULL,
  role                TEXT NOT NULL,
  kind                TEXT NOT NULL CHECK (kind IN ('login_form', 'login_json', 'basic', 'header_token')),
  login_path          TEXT,
  header_name         TEXT,
  username            TEXT,
  secret_enc          TEXT,
  secret_set_at       TIMESTAMPTZ,
  state               TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended', 'erased')),
  suspended_reason    TEXT,
  attested_by         UUID REFERENCES app_user(id),
  attested_at         TIMESTAMPTZ,
  attestation_version TEXT NOT NULL,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (engagement_id, label)
);

CREATE TABLE IF NOT EXISTS engagement_test_account_host (
  id                  UUID PRIMARY KEY DEFAULT uuidv7(),
  account_id          UUID NOT NULL REFERENCES engagement_test_account(id) ON DELETE CASCADE,
  host                TEXT NOT NULL,
  login_path          TEXT,
  assigned_by         UUID NOT NULL REFERENCES app_user(id),
  assigned_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  attestation_version TEXT NOT NULL,
  failed_runs         INTEGER NOT NULL DEFAULT 0,
  suspended_at        TIMESTAMPTZ,
  suspended_reason    TEXT,
  last_outcome        TEXT,
  last_outcome_at     TIMESTAMPTZ,
  UNIQUE (account_id, host)
);

CREATE TABLE IF NOT EXISTS engagement_login_consent (
  id              UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id   UUID NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
  given_by        UUID NOT NULL REFERENCES app_user(id),
  given_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  wording_version TEXT NOT NULL,
  pairs           JSONB NOT NULL,
  revoked_at      TIMESTAMPTZ,
  revoked_by      UUID REFERENCES app_user(id)
);
CREATE INDEX IF NOT EXISTS ix_login_consent_engagement ON engagement_login_consent (engagement_id);

CREATE TABLE IF NOT EXISTS engagement_test_account_login_attempt (
  id           UUID PRIMARY KEY DEFAULT uuidv7(),
  account_id   UUID NOT NULL REFERENCES engagement_test_account(id) ON DELETE CASCADE,
  scan_run_id  UUID,
  host         TEXT NOT NULL,
  at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_login_attempt_account_run ON engagement_test_account_login_attempt (account_id, scan_run_id);
