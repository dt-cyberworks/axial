---
title: English runtime text and code comments
status: implemented
risk: R2
owner: engineering
---

# English Runtime Text

Context: the 2026-09-27 review (finding C4) found German comments in about
half of the backend modules, and German text that people read at runtime:
the API description, tool notes in the console, the Vector Agent's tool
descriptions and observations (shown in the run's agent tab), finding titles
in the report, and log lines. The console, docs, and public repository are
English. johannes asked for this to be implemented on 2026-09-29.

**Risk class: R2** — mostly text, but finding titles are part of the
de-duplication fingerprint, so translating them touches persisted data.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-TEXT-001: Text that people read at runtime is English

Acceptance criteria:

- API errors, OpenAPI texts, tool notes, the Vector Agent's tool
  descriptions and observations, finding titles, and log lines of
  control-plane, worker, egress-proxy, and raw-egress-gateway are English.
- A test scans the runtime string literals of those services and fails on
  German text. Constants assigned to a name starting with `_LEGACY` are
  historical data and exempt.
- [Negative test] The scan reports a German message planted in a sample.
- Finding titles that used to be German keep their identity: a finding
  recorded under the German title is the same finding (same row, same
  triage decision) when a later scan reports the English title. The
  fingerprint keeps hashing the original wording.
- Migration 0032 renames the stored German titles to English without
  changing fingerprints; running it twice changes nothing. The hash-chained
  audit log is not touched.
- `AGENTS.md` says new comments are English and that German comments in
  touched code are translated in a separate commit.

Security invariants:

- None changed. Agent tool descriptions are prompts; the Scope Gateway
  decides every action regardless of their wording.
