---
title: CNAME/DNS inventory and dangling-DNS takeover detection
status: implemented
risk: R3
owner: security-engineering
---

# CNAME / DNS Inventory & Dangling-DNS (Subdomain-Takeover) Detection

This document is the requirement source for enriching passive discovery with the
DNS resolution graph (CNAME chains, hosting-provider classification) and for
detecting dangling-DNS / subdomain-takeover conditions.

The scanner is deliberately **explicit-allow-list scoped** (scope comes from the
engagement / bug-bounty program, not from ownership inference). This feature adds
*inventory metadata and a passive finding* — it must not widen what is actively
scanned. Discovery/attribution may only *propose*; the Scope Gateway remains the
sole gate for active scanning.

**Risk class: R3** (touches scope-adjacent discovery; carries a scope-safety
invariant that requires a negative test). No new active/offensive capability is
introduced: DNS lookups are passive public reads, and the only new active-ish
artifact is an *inferred* finding requiring human verification.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-DNS-001: CNAME chains are resolved and stored as metadata only

Passive discovery must resolve the full CNAME chain of each in-scope FQDN and
persist it as inventory metadata, without ever promoting a CNAME target to a
scannable asset.

Acceptance criteria:
- For each in-scope discovered FQDN, the ordered CNAME chain (`fqdn → cname₁ →
  … → terminal`) and the terminal A/AAAA addresses are resolved and stored in a
  `dns_record` row linked to the originating `discovered_asset`.
- The **FQDN is the asset**; the CNAME target (e.g. `x.elb.amazonaws.com`,
  `company.okta.com`) is stored as metadata **only**. A CNAME target must never
  be written as a `discovered_asset`, must never be marked `in_scope`, and must
  never be materialized into `resolved_host` for raw egress.
- Resolution is bounded: chain depth is capped and CNAME loops are detected and
  terminated without error.
- A DNS failure for one name does not abort discovery; the name is recorded with
  status `unresolved`.

Security invariants:
- Scope Gateway remains the sole authority for active scanning; DNS metadata
  never authorizes a target. A CNAME target is never active-scannable.

## REQ-DNS-002: Hosting-provider and dependency classification

The resolved chain must be classified so the operator can see what a name is
hosted on and which names are third-party dependencies rather than owned infra.

Acceptance criteria:
- The terminal target (and, failing that, any chain hop) is matched against a
  maintained provider suffix map (AWS ELB/S3/CloudFront, Azure/Front Door, GCP,
  Cloudflare, Fastly, Okta, GitHub Pages, Heroku, Netlify, Shopify, Zendesk, …).
- Each `dns_record` records a `hosting_provider` label and boolean
  classification flags: `is_cdn`, `is_saas`, `is_idp`, `is_shared_infra`.
- Classification is metadata; it never changes scope or the set of scannable
  assets. Names that resolve directly to A/AAAA with no known provider are
  recorded with `hosting_provider = null` and no flags.

## REQ-DNS-003: Dangling-DNS / subdomain-takeover detection (passive)

A CNAME that points to a de-provisioned target must be surfaced as a potential
subdomain takeover, detected purely at the DNS level.

Acceptance criteria:
- A FQDN whose CNAME chain terminates in a name that does not resolve
  (NXDOMAIN / no A/AAAA) is recorded with `dns_status = dangling` and
  `takeover_suspected = true`.
- A dangling target that matches a known claimable provider suffix raises the
  finding's confidence context (provider named in the evidence); an unknown
  provider is still flagged as suspected but noted as lower confidence.
- Detection is **DNS-only**: the scanner must not issue any HTTP request to the
  third-party target to confirm the takeover (that would test out-of-scope
  infrastructure). Confirmation is left to the human operator.
- Each dangling result creates a `misconfig`, `confidence = inferred` finding
  ("Potential subdomain takeover (dangling DNS)") against the originating asset,
  with the CNAME chain, terminal target, and provider in its evidence. It is
  de-duplicated by the existing finding fingerprint like any other finding.
- A healthy chain (terminal resolves to at least one address) is `resolved` and
  never produces a takeover finding.
