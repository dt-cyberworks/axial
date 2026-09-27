---
title: CNAME/DNS inventory and takeover detection verification
status: ready
risk: R3
owner: security-engineering
---

# CNAME / DNS Inventory & Takeover Detection Verification

Verifies [`../requirements/dns-cname-inventory-and-takeover.md`](../requirements/dns-cname-inventory-and-takeover.md).
R3: a negative scope-safety test is required.

## TC-DNS-001: CNAME resolution builds metadata, never a scannable asset

Requirements:

- REQ-DNS-001
- REQ-DNS-002

Automated tests:

- `worker/tests/test_dns_intel.py`

Objective:

Verify that resolving a FQDN with a CNAME chain yields the ordered chain,
terminal addresses, and provider classification, and — the key negative — that
the CNAME target is returned as metadata only and never surfaces as a
discovered/owned/scannable asset.

Expected results:

- `app.example.com → x.elb.amazonaws.com → 1.2.3.4` yields the full chain,
  terminal IPs, `hosting_provider = aws-elb`, `is_shared_infra = true`.
- Chain-depth cap and CNAME-loop detection terminate without error.
- The CNAME target is present only in the `dns_record`/chain, never as a
  `discovered_asset` and never passed to DNS materialization.

## TC-DNS-003: Dangling CNAME raises a passive takeover finding; healthy does not

Requirements:

- REQ-DNS-003

Automated tests:

- `worker/tests/test_dns_intel.py`
- `worker/tests/test_discovery_dns.py`

Objective:

Verify DNS-only dangling detection: a CNAME to an NXDOMAIN target is flagged
`dangling` / `takeover_suspected` and produces exactly one inferred takeover
finding, no HTTP request is made to the third-party target, and a healthy chain
produces none.

Expected results:

- `orphan.example.com → deleted.s3.amazonaws.com` (NXDOMAIN) →
  `dns_status = dangling`, `takeover_suspected = true`, provider `aws-s3`.
- The discovery phase posts one `misconfig`/`inferred` finding with the chain in
  evidence; no HTTP fetch of the third-party target occurs.
- A resolving chain yields `dns_status = resolved` and no takeover finding.
