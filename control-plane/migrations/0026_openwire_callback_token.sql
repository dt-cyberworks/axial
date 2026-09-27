-- REQ-AGENT-027: single-use callback tokens for the OpenWire deserialization
-- probe. Proving CVE-2023-46604-class RCE requires observing that the
-- target itself fetched a URL we host (see docs/requirements/
-- raw-protocol-testing.md for why - the exploit mechanism has no in-band
-- response to read, unlike e.g. Struts2's OGNL-in-header trick). This table
-- is the entire state this minimal, purpose-built callback receiver needs:
-- "was this exact token fetched, and when" - nothing about the calling
-- target (headers, source IP, body) is stored, by design (REQ-AUDIT-004/007
-- discipline: untrusted input from a by-definition-untrusted, possibly-now-
-- compromised caller is never logged).

CREATE TABLE IF NOT EXISTS openwire_callback_token (
  token          VARCHAR(64) PRIMARY KEY,
  engagement_id  UUID NOT NULL REFERENCES engagement(id),
  scan_run_id    UUID REFERENCES scan_run(id),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at     TIMESTAMPTZ NOT NULL,
  triggered_at   TIMESTAMPTZ
);

-- The worker polls "has my token been triggered yet" repeatedly within its
-- bounded wait window - this is the hot lookup path, already covered by the
-- primary key. This index supports the housekeeping query (expired,
-- never-triggered tokens) without a sequential scan as the table grows.
CREATE INDEX IF NOT EXISTS openwire_callback_token_expires_idx
  ON openwire_callback_token (expires_at);
