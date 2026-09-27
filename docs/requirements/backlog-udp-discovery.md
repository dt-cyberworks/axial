---
title: Bounded UDP service discovery backlog
status: implemented
risk: R4
owner: security-engineering
---

# Bounded UDP service discovery backlog

## REQ-SCAN-011: UDP discovery is targeted, scope-bound, and explicitly enabled

The scanner shall support bounded UDP service discovery for infrastructure
where UDP exposure is relevant. The profile remains explicitly opt-in and is
separate from TCP discovery.

Acceptance criteria:

- UDP discovery is disabled by default and is never silently added to the
  existing TCP profile.
- The approved UDP profile is exactly `53,123,161,443,500,1900,4500,5060,5353`
  for DNS, NTP, SNMP, QUIC/HTTP3, IKE/IPsec, SSDP, SIP, and mDNS.
- The operator may enable UDP for authorized lab, own-domain, or customer
  engagements. Bug-bounty engagements remain denied until program-specific
  UDP permission is represented in deterministic control-plane state.
- Every UDP invocation uses the audited materialized IP and a signed lease
  binding the exact UDP port envelope, rate, retry bound, timeout, scan run,
  engagement, nonce, and expiry.
- Results distinguish `open`, `closed`, `filtered`, and `open|filtered`;
  ambiguous or empty UDP output is never reported as a clean result.
- Follow-up service detection is limited to ports identified by the bounded
  discovery stage, and execution evidence records the tested UDP ports and
  discovered-service count.
- A full `1-65535` UDP scan is not a default profile and requires a separately
  approved design, explicit operator approval, and dedicated performance and
  safety tests.

Security invariants:

- Scope Gateway authorization, deny precedence, audited IP materialization,
  fail-closed raw egress, and truthful result persistence remain mandatory.
- Explicitly authorized by the repository owner on 2026-07-26; normal R4
  legal, security-review, isolated-validation, and release gates remain.



Backlog decision log:

- 2026-07-26 — the repository owner explicitly promoted this existing backlog
  item and requested implementation together with the Nmap queue and TCP-range
  items.
