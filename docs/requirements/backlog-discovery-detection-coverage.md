---
title: Discovery and detection coverage
status: backlog
risk: R4
owner: security-engineering
---

# Discovery and Detection Coverage

From the 2026-09-27 review (findings A1, A2, A4). The detection core is
sound; these items close the coverage gaps an ASM or bug-bounty user will
notice first. Each item is separately promotable; their risk differs.

## REQ-COVER-001: Passive subdomain discovery through subfinder

Acceptance criteria:

- Discovery aggregates subfinder's passive sources in addition to crt.sh,
  CertSpotter, and HackerTarget, with the same scope filtering and
  deny-precedence as today.
- A source failure never fails discovery (unchanged behavior).
- Optional API keys for subfinder's sources are admin settings.

## REQ-COVER-002: Subdomain-takeover checks

Acceptance criteria:

- nuclei's `takeover` templates run in the web suite, complementing the
  existing DNS-level dangling-CNAME detection with service fingerprints.
- Verified against a benchmark target with a real dangling record before
  release (Definition of Done: real benchmark run).

## REQ-COVER-003: Endpoint discovery by crawling and URL history ⚖

Acceptance criteria:

- A crawler (katana) and URL-history sources (for example Wayback/CommonCrawl
  via gau) feed discovered URLs to the web suite and the Vector Agent.
- The crawler runs through the egress proxy under the scan rate policy;
  URL-history lookups are passive and never touch the target.

## REQ-COVER-004: Out-of-band interaction server ⚖

Acceptance criteria:

- A self-hosted interaction server (for example interactsh) on the
  platform's public domain lets nuclei's ~680 out-of-band templates
  (blind SSRF, blind injection, Log4Shell class) confirm findings.
- The runner reaches only that server in addition to the egress proxy;
  interactions are tied to the engagement and audited.

## REQ-COVER-005: Retire tools that are enabled but never used

Acceptance criteria:

- Tools that are whitelisted but not wired into any phase (`whatweb`,
  `sslscan`, `default-cred-check`) are either wired with tests or removed
  from the runtime whitelist; `subfinder`/`amass` stop being "mapped but
  never dispatched".

Value and context:

- Missing takeover checks and blind vulnerability classes are the most
  visible detection gaps for bug-bounty users; broader passive discovery
  and endpoint discovery are table stakes for ASM.

Open questions and dependencies:

- REQ-COVER-003/004 are R4 (new active capability / widened egress): need
  johannes's explicit authorization and a legal check (crawling depth,
  third-party archives).
- Where the interaction server runs, and its data retention.
- Runner image size and build time (the tool-runner build currently fails
  in CI; fix that first).

Implementation authorization:

- None until each requirement is promoted out of `backlog` through SDLC
  review; R4 items need explicit human authorization.

Backlog decision log:

- 2026-09-27 — proposed by the review agent; REQ-COVER-002 and -005 look
  like the cheapest wins, REQ-COVER-004 the biggest detection gain.

Security invariants:

- Every new tool call passes the Scope Gateway; nothing reaches a target
  except through the egress proxy or a signed raw-egress lease.
- Deny precedence, windows, budgets, and approvals are unchanged.
