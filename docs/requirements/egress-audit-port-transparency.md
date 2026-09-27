---
title: Egress-proxy audit trail records the enforced port for plain-HTTP decisions
status: verified
risk: R3
owner: security-engineering
---

**Security review:** approved by johannes (project/security owner) on
2026-08-09. **Deployed to int 2026-08-09**: `egress-proxy` rebuilt and
recreated (no other services touched — no network churn this time), and
live-verified with a real plain-HTTP request through the running proxy for
the `pentest ground` engagement (`ceiling 4280-4280`) — the resulting audit
row shows `{"host": "www.pentest-ground.com", "path":
"/live-verify-audit-port-fix", "port": "4280", "method": "GET"}`, proving
the fix in production conditions, not only mocked.

# Egress-Proxy Audit Port Transparency

Context: found live 2026-08-09 — johannes inspected an `ALLOW` audit entry
for a plain-HTTP request during a real scan of `pentest ground` (whose
engagement ceiling is narrowed to a single port, 4280) and could not see
which port the Scope Gateway (`egress-proxy`) had actually checked. The
recorded payload was `{"method", "host", "path"}` only.

Root cause: `egress-proxy/app/proxy.py`'s `_forward_plain_http()` — the
plain-HTTP (non-CONNECT) forwarding path — calls `evaluate(engagement_id,
host, path, port)` with the real port and correctly enforces it (confirmed
by direct DB inspection: every `ALLOW`/`allow` row for this engagement's
plain-HTTP traffic can only exist because `evaluate()`'s
`out_of_scope_port` branch was not hit), but then builds the audit payload
without including `port`. The CONNECT path (`{"method", "host", "port"}`,
used for TLS/tunneled traffic) already included it — this was an
inconsistency between the two forwarding paths, not a missing feature
everywhere.

**This was never an enforcement gap** — `evaluate()` is the sole network
enforcement point for both paths and was never bypassed. It was a
transparency gap: the audit trail's purpose (an independent, inspectable
record of what the gateway decided) could not be verified from the record
itself for plain-HTTP traffic, only inferred from reading the source code.

**Risk class: R3.** Touches the Scope Gateway's audit payload — the
durable, hash-chained record this platform relies on to prove what was
actually authorized and enforced (same audit surface as REQ-AUDIT-003/004).
No enforcement logic, authorization decision, or egress path changes; this
adds one already-computed value (`port`, already a parameter to the
enclosing function) to data already being written.

## REQ-AUDIT-005: Every egress-proxy audit decision records the port that was actually checked

Acceptance criteria:

- The plain-HTTP forwarding path's audit payload includes `port` (the same
  integer passed to `evaluate()`), for both `ALLOW` and `DENY` decisions.
- [Negative test] a test that asserts the payload submitted to the audit
  trail for an allowed plain-HTTP request contains the exact port enforced
  — written to fail against the pre-fix code (confirmed: it raised
  `KeyError: 'port'` before the fix) and pass after.
- The CONNECT path's existing behavior (port already present) is unchanged.

Not fixed as part of this: `redis-probe`/`activemq-banner` raw-protocol
audit entries are recorded via a different path
(`raw_egress_lease.py`/`tool_execution.record`), out of scope here — this
requirement covers the `egress-proxy`'s own live per-connection audit
entries specifically.

Tests must verify this requirement directly. Do not weaken tests to match
implementation; update implementation when it violates this document.
