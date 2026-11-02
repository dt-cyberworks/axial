-- REQ-EGRESS-007 (GitHub #81): the egress proxy checks that the run named by a signed run token is still live
-- (state running / waiting_approval, no cancellation requested, run of that engagement). It is read-only on the
-- database by design, so it gets column-level SELECT on exactly the columns that question needs - not the table.
-- Idempotent: GRANT is a no-op when the privilege is already there. A production role that was created by hand needs
-- the same statement (docs/deployment.md).
GRANT SELECT (id, engagement_id, state, cancel_requested) ON scan_run TO asm_proxy_ro;
