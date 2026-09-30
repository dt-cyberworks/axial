---
title: Discovery and detection coverage (implemented parts)
status: implemented
risk: R3
owner: security-engineering
---

# Discovery and Detection Coverage (Implemented Parts)

From the 2026-09-27 review (findings A1, A4), follow-up 08 parts A and B. The
remaining coverage items (REQ-COVER-001, -003, -004, -006, -007) are in
[`extended-discovery.md`](extended-discovery.md).

**Risk class: R3.** REQ-COVER-005 changes the runtime tool whitelist (it gets
smaller); REQ-COVER-002 adds one template tag to an existing tool that already
runs through the egress proxy under the scan rate policy.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-COVER-002: Subdomain-takeover checks

Acceptance criteria:

- The scan runs the `takeover` tag in a nuclei pass of its own (the main pass
  plus this tag exceeded HexStrike's hard 300s command limit in a live run on
  2026-09-29), complementing the DNS-level dangling-CNAME detection with
  service fingerprints.
- The existing exclusions (`intrusive`, `dos`, `fuzz`, `csp-bypass`) stay in
  place: adding the tag never re-admits an excluded template.
- The main nuclei pass is no longer one call: it runs as bounded selections from the
  template index baked into the runner image (REQ-PIPE-004, superseding the earlier
  fixed directory parts), each with its own declared time budget (REQ-PIPE-007; a live
  run on 2026-09-29 showed the ~6000-template single pass being killed at the former
  fixed 300s limit). Matches printed by a pass that ran into its budget or exited
  non-zero are kept as findings, while the pass is still recorded as partial or failed
  (coverage reduced), never as clean.
- The Scope Gateway accepts only the typed selection shape (group, shard, product keys)
  for the main pass; a template path, a tag list, a `part`, or any wrongly typed value is
  `unsafe_arguments`.
- The tool call stays behind the Scope Gateway, the egress proxy and the scan
  rate policy exactly like the other nuclei passes.
- [Live verification] A real dev run against a target with a dangling record
  shows a takeover finding, and the extra run time is measured. Recorded at
  deploy/test time, not by a unit test.

## REQ-COVER-005: Retire tools that are enabled but never used

Acceptance criteria:

- `amass`, `whatweb`, `sslscan` and `default-cred-check` are not enabled by
  default and therefore are not on the runtime whitelist; each registry note
  says why and which tool covers the job.
- [Negative test] The gateway denies a call to each retired tool.
- Every default-enabled tool either has a caller in the worker or is listed as
  a known exception with a reason. `subfinder` is the one exception until
  REQ-COVER-001 decides how it runs.
- The in-app documentation and the tool catalog match the registry.
