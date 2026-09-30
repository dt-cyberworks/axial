---
title: Extended discovery and detection (subfinder, crawling, OOB, screenshots)
status: implemented
risk: R4
owner: security-engineering
---

# Extended Discovery and Detection

From the 2026-09-27 review (findings A1, A2, A3, A4), follow-ups 08 parts C, D, E
and follow-up 10. Four capabilities, each behind its own per-engagement switch
in the console:

| Switch (engagement flag) | Capability | Default | Reaches the target? |
|---|---|---|---|
| `subfinder_enabled` | REQ-COVER-001: passive subdomain sources via subfinder | on | no (third-party sources only) |
| `crawling_enabled` | REQ-COVER-003: crawler (katana), URL history, endpoint tests | off | yes, through the egress proxy |
| `oob_enabled` | REQ-COVER-004: out-of-band interaction templates (self-hosted server) | off | yes, nuclei payloads; callbacks reach the platform's own server |
| `screenshots_enabled` | REQ-COVER-006: one screenshot per live web service | off | yes, one page load per service through the egress proxy |

**Risk class: R4.** REQ-COVER-003, -004 and -006 add active capabilities against
targets and widen what the runner can reach (an interaction server, a browser
rendering untrusted pages). REQ-COVER-001 adds outgoing requests from the
worker to third-party data sources. Every item needs negative tests. An
automated agent cannot approve its own R4 exception.

**Authorization:** johannes (project/security owner) authorized the whole set on
2026-09-29 ("I approve all changes. Subfinder in worker image. 8 approved with
gui switch in the engagement configuration to allow or not allow usage and 10
approved."). The conditions he set:

- subfinder runs in the **worker image** (an explicit, narrow exception to
  "the worker runs no tool binaries", see REQ-COVER-001);
- every one of the new capabilities is switched on or off **per engagement in
  the console**;
- follow-up 10 (screenshots) is approved and gets the same switch (decided
  with the authorization: an active capability without an operator switch
  would be inconsistent with the rest).

Human security review of the finished implementation and its live
verification is still owed before this document moves to `verified`.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-COVER-007: Each capability is a per-engagement switch that the gateway enforces

Acceptance criteria:

- The engagement has four boolean flags `subfinder_enabled` (default true),
  `crawling_enabled`, `oob_enabled` and `screenshots_enabled` (default
  false). Existing engagements get the defaults; the migration is idempotent.
- The create wizard and the engagement edit page show all four as switches with
  a one-sentence plain-language description, and the engagement summary lists
  which are on. The owner can change them at any time (they are not part of
  the draft-only authorization envelope); the change takes effect on the next
  tool call, not only on the next run.
- [Negative test] The Scope Gateway denies a `katana` call, a `screenshot`
  call and a `nuclei` call with `mode` `endpoints` when `crawling_enabled` /
  `screenshots_enabled` is false, and a `nuclei` call with `mode` `oob` when
  `oob_enabled` is false, each with a distinct machine-readable reason, and
  writes the audit row. The denial happens even when the tool is enabled in the
  registry and in the campaign's tool policy: a per-engagement switch narrows,
  it never widens.
- [Negative test] Turning a switch on does not lift any other gateway check:
  scope (deny first), authorization window, port window, bug-bounty rules, rate
  policy, budget and approvals apply exactly as for every other tool call.
- [Negative test] The Vector Agent cannot propose these tools: they are not
  offered to it, and the gateway denies them for `phase` `agent`.
- [Negative test] With a switch off the worker makes no call for the capability
  at all (verified per capability), and records the skip.
- The switches reach the worker through the internal API only.

## REQ-COVER-001: Passive subdomain discovery through subfinder

Acceptance criteria:

- Discovery aggregates subfinder's passive sources in addition to crt.sh,
  CertSpotter and HackerTarget, with the same scope filtering and deny
  precedence as today. subfinder is started without `-active`; it never
  resolves or connects to a name the sources did not already list.
- subfinder is a pinned, checksum-verified binary in the **worker image**
  (version and SHA-256 per architecture in the Dockerfile). This is the one tool
  binary the worker holds. It only talks to third-party data sources over the
  worker's OSINT egress, never to the target, and it has no access to the
  runner, the database or the audit log.
- The call passes the Scope Gateway (`subfinder`, category `recon`, mode
  `passive`), so a campaign that disables the tool, or a denied domain, stops it,
  and each run is audited.
- [Negative test] A name outside the allowed scope, a name a deny rule covers,
  and a name that only shares a suffix (`badexample.com`) are dropped even if
  subfinder returns them.
- A failing, missing or slow subfinder never fails discovery or drops the other
  sources; it is bounded by a hard timeout.
- Optional API keys for subfinder's sources are an admin setting, stored
  encrypted like the NVD/LLM keys, never returned by the API (only which
  providers are set), and validated (provider names from an allowlist, key
  characters restricted). The worker writes them to a private temporary file for
  the one call and deletes it afterwards; they never appear in the command line,
  logs or audit rows.
- With `subfinder_enabled` false, subfinder is not started and discovery is
  identical to today.

## REQ-COVER-003: Endpoint discovery by crawling and URL history

Acceptance criteria:

- With `crawling_enabled`, the fingerprint phase runs katana once per live web
  service, through the egress proxy under the scan rate policy (and the bug-
  bounty rate cap and identification header where they apply), with a hard cap
  on depth, on pages and on run time. The crawler stays on the one host it was
  authorized for and does no headless (browser) crawling.
- URL history (Wayback Machine, CommonCrawl) is looked up by the worker as a
  passive source; the target is never contacted for it. Only URLs whose host is
  an in-scope, active-allowed target and whose path no deny rule excludes are
  kept.
- Discovered endpoints are stored per engagement (URL, host, port, method,
  source, parameter names, first seen), bounded per run, and shown to the Vector
  Agent as context so it can choose them as targets. The agent still proposes
  and the gateway still decides.
- Endpoints with query parameters feed one extra nuclei pass (`mode`
  `endpoints`, DAST templates) per host with a bounded URL list. The gateway
  validates **every** URL in that list against the current scope, deny rules,
  port window and path rules, not only the call's target host.
- [Negative test] A URL whose host is out of scope, denied, on another port
  than authorized, or that carries userinfo or a non-http(s) scheme is refused
  by the gateway when it appears in an `endpoints` call, and is dropped before
  it is stored or handed to a tool.
- [Negative test] The crawler and the endpoint pass are not run when
  `crawling_enabled` is false; a proxy-bypass attempt (a URL on an address not
  in scope) is refused by the egress proxy like for every other tool.
- Crawl results never create new scope: a discovered host outside the
  allowed scope is never a target.

## REQ-COVER-004: Self-hosted out-of-band interaction server

Acceptance criteria:

- The stack contains an optional `oob` profile with a self-hosted interaction
  server (interactsh, image pinned by digest) on the platform's own domain
  (`OOB_DOMAIN`, delegated to the host by an NS record the operator sets up).
  It runs with an authentication token, without the wildcard/LDAP/SMB/FTP/
  responder modes, read-only rootfs, dropped capabilities and bounded in-memory
  retention (default 7 days). The first version answers DNS callbacks from the
  internet; HTTP/HTTPS/SMTP callbacks are not published (the edge owns 80/443).
- The runner reaches that server on a dedicated internal network in addition
  to the egress proxy, and nothing else: the network is `internal: true`, the
  server has no route out, and the runner still has no direct internet access.
  The interaction token reaches the runner only through its environment, never
  in a command line, audit row or log.
- With `oob_enabled`, one extra nuclei pass (`mode` `oob`) runs the
  interaction-based templates against each live web service, through the
  egress proxy and the rate policy. nuclei creates its own interaction
  session per call, so an interaction is tied to that call, engagement and
  run; the call and its result are audited like any other.
- If the server is not configured or not reachable, the pass is skipped and the
  run records `oob_unavailable`; it never falls back to a public interaction
  server. `-no-interactsh` stays on for every non-OOB pass.
- [Negative test] No nuclei call may name an interaction server or token;
  arguments other than the fixed `mode` are refused for `oob`; a call with
  `mode` `oob` when `oob_enabled` is false, or a gateway-denied target, does
  not run.
- [Live verification] Registering with and polling the server from the runner
  works on the dev stack. A real callback needs the public domain and NS
  delegation; that live check is recorded at deploy time, or marked as not
  possible if the domain is not delegated yet.

## REQ-COVER-006: Screenshots of live web services

Acceptance criteria:

- With `screenshots_enabled`, one page load per live web service and run
  produces one screenshot, using the Chromium already in the runner image,
  through the egress proxy, under the rate policy, with a per-page timeout, no
  clicks, no form input and no navigation beyond redirects. Capped per run.
- The gateway authorizes each URL (`screenshot`, category `fingerprint`) like any
  other call. For a bug-bounty engagement that requires an identification
  header, screenshots are denied (the browser cannot add the mandatory header
  to every request), and the skip is recorded.
- Screenshots are stored in the database per engagement and run (PNG, size
  capped), listed and served only to users who can see the engagement, and
  deleted with it. They are not part of the PDF report (open question 2 of
  follow-up 10: answered "no" for now, because a screenshot can contain
  third-party or personal data; a later requirement can add them).
- The image response carries `Content-Type: image/png`, `nosniff` and
  `Cache-Control: private, no-store`.
- [Negative test] No screenshot is taken of an out-of-scope, denied or wrongly
  ported URL, and no request bypasses the egress proxy (the browser is
  started with the proxy and without any direct route).
- [Negative test] Another user cannot list or fetch the screenshots of an
  engagement they do not own (404, same as other engagement resources).
- Chromium renders untrusted pages inside the runner container (non-root,
  read-only rootfs, dropped capabilities, isolated network, throwaway profile
  directory, hard timeout). The residual risk (a browser exploit, and
  `--no-sandbox` inside the container) is documented in the design and accepted
  by the authorization above.
- [Live verification] A real dev run against a benchmark target produces
  screenshots and the extra run time is recorded.

---

Security invariants:

- Every tool call passes the Scope Gateway; nothing reaches a target except
  through the egress proxy or a signed raw-egress lease. Deny precedence,
  windows, budgets and approvals are unchanged.
- A per-engagement switch can only remove capability. It is checked by the
  gateway on every call, not only by the worker.
- The worker holds one tool binary (subfinder) that speaks only to third-party
  data sources.

Verification log:

- 2026-09-29 - authorized by johannes (see above). Implemented the same day; automated tests TC-COVER-003..009 green. Live verification on dev (katana flags, nuclei `-dast` template loading, interaction-server registration, screenshot size, run-time cost) and human security review still owed.
