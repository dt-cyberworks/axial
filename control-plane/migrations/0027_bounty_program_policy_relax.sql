-- REQ-AUTH-006 (amended 2026-08-12): live-testing against real Intigriti
-- programs showed policy_sha256 has no well-defined input - programs expose
-- their rules as dynamic, company-editable prose with no downloadable
-- artifact to hash, and the column was never read anywhere downstream
-- (gateway/egress-proxy/worker all ignore it). Drop it entirely rather than
-- just relaxing it - keeping an unused column around invites someone to
-- start trusting it as an integrity check it never was.
--
-- Not every program requires a custom identification header either (e.g.
-- Port of Antwerp-Bruges identifies via an out-of-band @intigriti.me email
-- alias, not a header) - ident_header_value becomes optional. The worker's
-- injection logic (worker/app/tool_runner_client.py) already treats a
-- missing name/value as "inject nothing", so no worker code change is
-- needed for this to be safe.

ALTER TABLE bounty_program DROP COLUMN IF EXISTS policy_sha256;
ALTER TABLE bounty_program ALTER COLUMN ident_header_value DROP NOT NULL;
