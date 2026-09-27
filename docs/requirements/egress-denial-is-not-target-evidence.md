---
title: Content discovery must report distinct responses, and a proxy denial is never target evidence
status: implemented
risk: R3
owner: security-engineering
---

# Content Discovery Integrity

Context: found live 2026-08-10 while auditing every DENY and tool failure in
scan run `019fec2a-a66c-762b-a68d-571a854c4b44`.

`ffuf` is invoked with `-mc 200,204,301,302,307,401,403,405,500` — it accepts
a wordlist entry as a discovered path based on **status code alone**, with no
auto-calibration (`-ac`) and no response-size filter. Any endpoint that
answers uniformly therefore yields one "discovery" per wordlist entry.
Measured across three hosts in one run:

| Host | Resolves | Reported "paths" | Distinct responses |
|---|---|---|---|
| `scan-int.example.org` | yes, real server | 1677 | **1** (200, 396 bytes — 100%) |
| `scan.example.org` | yes, real server | 1677 | **1** (200, 396 bytes — 99.9%) |
| `synapp-int.example.org` | **NXDOMAIN** | 1800 | **1** (403, 21 bytes — 100%) |

The 396-byte body is the operator console's React SPA shell: Caddy's
`try_files {path} /index.html` returns `index.html` for every path, so every
probe "succeeds". The 21-byte body is our own egress proxy's denial string
`dns_resolution_failed`, which the tool cannot distinguish from a target
response.

**This is not an edge case confined to broken hosts.** Two of the three
affected hosts resolve, serve real content, and are the platform's own
consoles — one of them public. A customer report would assert ~1,677
discovered paths on a host that has none, and the finding looks entirely
plausible precisely because the host is real. That is worse than a missed
finding: a report that invents evidence discredits every genuine finding
beside it.

A secondary defect compounds it on the NXDOMAIN host: because the egress
proxy's `403 Blocked` is indistinguishable from a target response, `httpx`
recorded a **phantom `Service` row and `http_live=True` for a host that does
not exist**, which then satisfied the web suite's liveness gate and let
`nikto`, `ffuf` and `nuclei` run their full template sets — ~33,000 denied
requests, all written to the hash-chained audit log.

**The denials themselves are correct.** The SSRF guard (REQ-HARDEN-002) did
exactly its job and nothing unauthorized left the platform. Every defect here
is in how tools and parsers *interpret* responses.

**Risk class: R3.** Finding integrity on the customer-facing artifact, with
`confidence: validated` asserted on fabricated results, plus tens of
thousands of junk rows in the evidentiary audit trail. No Scope Gateway,
egress, or authorization behaviour changes — this makes the platform believe
*less*, never reach further.

## REQ-DISCO-001: A content-discovery hit must be a distinct response

Acceptance criteria:

- `ffuf` runs with auto-calibration enabled (`-ac`), its own purpose-built
  mechanism for exactly this: it probes known-nonexistent paths first, learns
  the catch-all signature, and filters responses matching it.
- Independently of the tool's own filtering, a result set is rejected as
  content discovery when its hits are not meaningfully distinct — concretely,
  when effectively all hits share one `(status, length)` pair. One response
  repeated N times is one observation, not N findings.
- The rejection is recorded as a tool outcome with a reason, not silently
  dropped: an operator must be able to see that discovery ran and why it
  produced nothing (REQ-SCAN-014's coverage signal depends on honest
  per-tool outcomes).
- [Negative test] the three observed cases each yield **zero** content-
  discovery findings: 1677×(200,396), 1676/1677×(200,396), 1800×(403,21).
- [Negative test] a genuinely varied result set — several distinct
  status/length combinations — is still reported in full. The fix must not
  suppress real content discovery, which is the tool's entire purpose.
- [Negative test] a small result set that happens to be uniform (e.g. 2 hits)
  is not discarded on that basis alone; the guard targets catch-all
  behaviour, not coincidence.

## REQ-DISCO-002: A proxy denial is distinguishable from a target response

Acceptance criteria:

- Every response the egress proxy generates itself (rather than relaying)
  carries an unambiguous marker header naming it a platform denial and its
  reason.
- The marker is on **all** self-generated responses, not just the DNS path:
  `out_of_scope_deny`, `out_of_scope_port`, `not_in_scope`, `rate_limited`,
  `audit_unavailable`, `proxy_capacity_exhausted`, blocked-address denials
  and malformed-request rejections are equally not-the-target.
- It cannot be forged by a target: it is added to responses the proxy
  synthesises and never copied from upstream.
- [Negative test] a genuine `403` from a real in-scope target does **not**
  carry the marker and is still recorded normally — hosts that legitimately
  answer 403 must keep producing findings.

## REQ-DISCO-003: Tool output derived from a denial is never target evidence

Acceptance criteria:

- A parsed result whose response carries the denial marker produces no
  `Service` row, no `Finding`, and no `http_live=True`.
- The tool execution is still recorded with the denial reason, so the run
  does not look like the tool was never attempted.
- [Negative test] the observed case is reproduced: a `403` whose body is
  exactly a denial reason yields zero findings and zero service rows.

## REQ-DISCO-004: The web suite is gated on the same materialization nmap uses

Acceptance criteria:

- When DNS materialization produced no IP for a host, the web tools are
  skipped for that host with a recorded reason, exactly as `nmap` already
  does (`materialized_ip_missing`) — instead of being attempted and
  generating ~33,000 denied requests.
- The skip is recorded per tool so the audit trail shows why each did not run.
- [Negative test] a host that *does* materialize runs the full suite,
  unaffected.
- This is an efficiency and audit-hygiene control, **not** a security
  boundary: the egress proxy remains the enforcement point and would refuse
  these connections regardless. It must never be relied on as the reason a
  connection does not happen.
