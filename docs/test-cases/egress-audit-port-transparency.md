---
title: Egress-proxy audit port transparency verification
status: ready
risk: R3
owner: security-engineering
---

# Egress-Proxy Audit Port Transparency Verification

Verifies [`../requirements/egress-audit-port-transparency.md`](../requirements/egress-audit-port-transparency.md).

## TC-AUDIT-005: The plain-HTTP audit payload records the enforced port

Requirements:

- REQ-AUDIT-005

Automated tests:

- `egress-proxy/tests/test_audit_payload_port.py`

Objective:

Prove the port `evaluate()` actually checked for a plain-HTTP request is the
same value that reaches the audit trail, so the audit record is
self-sufficient evidence of what was enforced rather than something an
operator has to trust the source code for.

Expected results:

- **Negative test (the required one):** a plain-HTTP `ALLOW` decision's
  audit payload contains `port` equal to the exact port `evaluate()` was
  called with — written to fail against the pre-fix code (confirmed: raises
  `KeyError: 'port'`) and pass after the fix, so it is a genuine regression
  test rather than one that would pass either way.
- `host`, `path`, and `method` are still present and unchanged (no fields
  dropped or renamed).
- The CONNECT path's payload, which already carried `port`, is unaffected.

## Manual/live verification (2026-08-09)

Cross-checked directly against int's database for the live engagement that
surfaced this (`pentest ground`, ceiling narrowed to port 4280 only,
`019fe768-acdf-77d8-bb63-3ce9e9cb4c23`):

- Every CONNECT-path audit row for this engagement already showed
  `"port": "4280"` explicitly.
- Every plain-HTTP-path `ALLOW`/`allow` row for the same engagement, in the
  same time window, could only exist if `evaluate()`'s port check had
  passed — `evaluate()` returns `False, "out_of_scope_port"` otherwise, and
  no such `DENY`/`out_of_scope_port` rows appeared alongside these `ALLOW`
  rows for the same requests. This confirms enforcement was correct even
  before the fix; only the audit record was incomplete.
