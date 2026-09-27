-- Minimum safe-operation baseline.
--
-- Approval execution has an explicit claim and terminal result. The existing
-- state column is TEXT, so no enum migration is required.

ALTER TABLE approval_request
  ADD COLUMN IF NOT EXISTS execution_started_at TIMESTAMPTZ;
ALTER TABLE approval_request
  ADD COLUMN IF NOT EXISTS execution_finished_at TIMESTAMPTZ;
ALTER TABLE approval_request
  ADD COLUMN IF NOT EXISTS execution_error TEXT;

CREATE INDEX IF NOT EXISTS idx_approval_request_state_expiry
  ON approval_request(state, expires_at);


-- Dedicated read-only proxy role for the local Compose baseline. Production
-- must rotate this development password through its database provisioning.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'asm_proxy_ro') THEN
    CREATE ROLE asm_proxy_ro LOGIN PASSWORD 'asm-proxy-dev';
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO asm_proxy_ro;
GRANT SELECT ON engagement, scope_asset, resolved_host, bounty_program, audit_log TO asm_proxy_ro;
