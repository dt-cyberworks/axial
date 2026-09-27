-- GitHub issue #37: bug-bounty engagements were previously permitted only
-- the liveness-only host_discovery raw-nmap profile - a blanket policy,
-- confirmed deliberate (REQ-CIDRDISC-005) but with no way for a program
-- whose actual rules of engagement permit more (e.g. a real Intigriti
-- program with an unqualified "automated tooling: N req/s" clause and no
-- port-scan prohibition) to be granted anything broader. Adds an explicit,
-- narrow per-program network-scanning capability model - default 'none'
-- preserves today's behavior exactly for every existing row.
--
-- tcp_syn_scan_profile: 'none' (today's default - host_discovery only),
-- 'common' (also permits configured_tcp - the engagement's own already-
-- configured scope-asset port ranges, reusing existing machinery, not a
-- new top-N port list), 'full' (also permits full_tcp - all 65535 ports -
-- and requires network_scan_authorization_evidence to be non-empty).
--
-- raw_max_packets_per_second: deliberately DISTINCT from max_rps (an HTTP
-- request-rate concept) - conflating the two was itself part of the gap
-- this issue reports. Nullable: existing programs that never set it keep
-- their current behavior (max_rps used as the raw-rate fallback, exactly
-- as issue_raw_egress_lease already did for host_discovery before this
-- migration) rather than losing their rate cap outright.
--
-- network_scan_authorization_evidence: a free-text record of why a
-- profile beyond 'common' is believed authorized (a quote from the
-- program's published rules, a ticket reference, etc.) - explicitly NOT a
-- hash of "the document" (REQ-AUTH-006's 2026-08-12 amendment already
-- established that no such single artifact exists for a real program).

ALTER TABLE bounty_program
  ADD COLUMN IF NOT EXISTS tcp_syn_scan_profile text NOT NULL DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS raw_max_packets_per_second numeric(6,2),
  ADD COLUMN IF NOT EXISTS network_scan_authorization_evidence text;

ALTER TABLE bounty_program
  DROP CONSTRAINT IF EXISTS bounty_program_tcp_syn_scan_profile_check;
ALTER TABLE bounty_program
  ADD CONSTRAINT bounty_program_tcp_syn_scan_profile_check
  CHECK (tcp_syn_scan_profile IN ('none', 'common', 'full'));
