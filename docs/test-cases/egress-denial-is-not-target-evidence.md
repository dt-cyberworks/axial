---
title: Content discovery integrity verification
status: ready
risk: R3
owner: security-engineering
---

# Content Discovery Integrity Verification

Verifies [`../requirements/egress-denial-is-not-target-evidence.md`](../requirements/egress-denial-is-not-target-evidence.md).

Every requirement here makes the platform record **less**, so the tests that
prove it still records real findings are the load-bearing ones. The three
observed failures are used directly as fixtures rather than invented data.

## TC-DISCO-001: A content-discovery hit is a distinct response

Requirements:

- REQ-DISCO-001

Automated tests:

- `worker/tests/test_content_discovery_integrity.py`

Objective:

Prove a catch-all responder yields no findings, that genuine discovery is
untouched, and that ffuf's own calibration is enabled.

Expected results:

- **Negative:** each observed case yields zero findings — 1677×(200,396),
  1676/1677×(200,396) with one outlier, 1800×(403,21).
- **Negative:** a genuinely varied result set (several distinct
  status/length pairs) is kept in full — the fix must not suppress real
  discovery.
- **Negative:** a small uniform set (2-3 hits) is not discarded; the guard
  targets wildcard behaviour, not coincidence.
- A rejected set is recorded as a tool outcome with reason
  `content_discovery_catch_all`, not silently dropped.
- `ffuf` is invoked with `-ac`.
- The guard is applied on the agent's dispatch path as well, so the agent is
  never told a catch-all is a discovery.

## TC-DISCO-002: A denial is distinguishable from a target response

Requirements:

- REQ-DISCO-002

Automated tests:

- `egress-proxy/tests/test_audit_payload_port.py`

Objective:

Confirm the proxy labels every response it synthesises, that the label cannot
be malformed or injected into, and that it cannot originate from a target.

Expected results:

- Every self-generated response carries the marker header — asserted across
  all ten denial reasons the proxy emits, not just the DNS path.
- The marker value stays one well-formed, bounded header line even when the
  reason carries an exception string with embedded CRLF.
- **Negative:** the marker is emitted only from `_deny` — the relay and
  plain-HTTP forwarding paths never add it, so a target cannot forge it.

## TC-DISCO-003: Denial-derived output is never target evidence

Requirements:

- REQ-DISCO-003

Automated tests:

- `worker/tests/test_content_discovery_integrity.py`

Objective:

Prove the platform's own refusal never becomes a service, a finding, or a
liveness signal — while a target's genuine 403 still does.

Expected results:

- **Negative:** the observed case — a `403` carrying the denial marker —
  parses to zero rows, so no `Service`, no `Finding`, no `http_live=True`.
- The marker is matched case-insensitively and also detected inside a raw
  response blob.
- **Negative:** a genuine `403` from a real target (no marker) is still
  parsed and recorded normally, preserving findings on hosts that
  legitimately answer 403.
- `httpx` is invoked with `-include-response-header`, without which the
  marker never reaches the parser.

## TC-DISCO-004: No web tooling against an unresolvable host

Requirements:

- REQ-DISCO-004

Automated tests:

- `worker/tests/test_content_discovery_integrity.py`

Objective:

Verify the web suite honours the same DNS materialization result nmap already
does, instead of generating tens of thousands of denied requests.

Expected results:

- **Negative:** a host with no materialized IP runs no web tool at all, and
  each skipped tool is recorded with `materialized_ip_missing` so the audit
  trail explains the absence.
- A host that does materialize runs the full suite in the documented order,
  unaffected.
