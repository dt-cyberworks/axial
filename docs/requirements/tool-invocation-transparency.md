---
title: Tool invocation transparency (exact command line in the audit trail)
status: implemented
risk: R3
owner: security-engineering
---

# Tool Invocation Transparency

Context: the audit trail records that a tool ran, against which target, with
what outcome (`tool_execution`), and separately that the gateway authorized it
(`tool_call`) — but never **how** it was invoked. The worker builds the literal
command for six tools (`httpx`, `testssl`, `http_request`, `ffuf`,
`redis-probe`, `activemq-banner`) in `worker/app/tool_runner_client.py` and
POSTs it to the runner's generic `/api/command`; the remaining six (`nmap`,
`nuclei`, `nikto`, `subfinder`, `amass`, `wafw00f`) send a structured body to
a tool-specific HexStrike endpoint. In both cases `ToolRunnerClient.run()`
returns only `stdout`/`stderr`/`exit_code`/`success`, so the invocation is
discarded the moment it returns.

That is a real transparency gap for the artifact this platform exists to
produce: an operator, a customer, or an insurer can see *that* `nikto` ran
against a host, but not with which tuning flags, wordlist, timeouts or headers
— so "prove exactly what you did to my systems" cannot be answered from the
audit log alone.

**Risk class: R3.** It writes new data into the durable, hash-chained audit
trail (`audit` is explicitly an R3 surface in
[`sdlc.md`](../engineering/sdlc.md) §2), and the data being written is exactly
where credentials would appear if this were done naively — the agent may set
`Authorization`/`X-Api-Key` headers, a session cookie is merged into
`http_request` headers automatically (`worker/app/session_state.py`), and a
login body can carry a password. REQ-AUDIT-004 is therefore not a nicety but
the security-critical half of this change, and needs negative tests plus human
security review. No new capability, egress path, or authorization decision is
introduced — the gateway, proxy and lease boundaries are untouched.

**Security review:** REQ-AUDIT-003/004 approved by johannes (project/security
owner) on 2026-08-07, after review of `worker/tests/test_command_redaction.py`
— in particular the negative test that asserts a bearer token, session
cookie, API key and login password are each absent as substrings from what
reaches the audit payload — and live verification from the deployed worker
that both dispatch paths record a real invocation while a tool that never ran
records `command = NULL` rather than a fabricated one.

**REQ-AUDIT-006/007 (added 2026-08-10, pending review — do not deploy without
johannes's sign-off):** REQ-AUDIT-003/004 solved the request/outbound half of
"prove exactly what you did to my systems." It left the response/inbound half
open — `http_request`'s whole purpose is that its raw response (status +
headers + body) is what the LLM classifies from, but that response was never
part of the audited `tool_execution` record at all, and the ONE place it was
recorded (the agent's own `observation` event) stored it **unredacted** and
truncated to an arbitrary 2000 characters. Found live on int on 2026-08-10, in
the course of answering johannes's question about showing more response
detail in the audit log: real, unredacted session cookie values from a
Nextcloud login (`ocqycf4p1g88=...`) and a DVWA login (`PHPSESSID=...`) were
present in the hash-chained `audit_log` table. Same risk class and same fix
shape as REQ-AUDIT-004 (redact by structured value, not by string-scanning a
built blob), applied to the one path REQ-AUDIT-004 did not cover.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-AUDIT-003: The exact tool invocation is recorded in the audit trail

Every completed tool execution records the invocation that was actually used,
alongside the outcome data it already records.

Acceptance criteria:

- The `tool_execution` audit entry carries a `command` field describing the
  invocation for **both** dispatch paths: the literal shell command for
  `/api/command` tools, and a deterministic rendering of the structured request
  body for the HexStrike per-tool endpoints.
- The recorded invocation reflects what was actually sent — it is produced by
  the same command/body builder used for execution, never re-derived or
  approximated by a separate code path that could drift from it.
- The field is bounded before it reaches durable storage, so an unusually large
  argument set cannot bloat the audit table.
- A tool whose invocation cannot be determined records no `command` rather
  than a fabricated or partial one; absence is never rendered as a guess.
- Recording is best-effort telemetry: a failure to capture or record the
  invocation never changes the tool's own outcome (the existing
  `tool_execution.record` contract is preserved).

## REQ-AUDIT-004: Credentials are never written to the audit trail

The recorded invocation is redacted so that secrets present in a real
invocation do not enter durable audit storage.

This mirrors the rule already established for session capture
(`worker/app/tasks/agent.py::_capture_session`, REQ-AGENT-022): audit the fact
and the *names*, never the secret values — "a session id is exactly as
sensitive as the credential that produced it".

Acceptance criteria:

- The value of a sensitive request header is replaced with a redaction marker
  while the header **name** is preserved, so the operator can still see that
  (for example) an `Authorization` header was sent, and to where, without the
  credential being stored. At minimum: `authorization`, `proxy-authorization`,
  `cookie`, `set-cookie`, `x-api-key`, `api-key`, `x-auth-token`,
  `x-access-token`, `x-session-token`, matched case-insensitively.
- Credential-bearing fields in a request body (e.g. `password`, `passwd`,
  `pwd`, `token`, `secret`, `api_key`, `apikey`, `auth`) have their values
  replaced, in both form-encoded and JSON bodies, while non-credential fields
  stay readable (an XSS test marker in a body must remain visible — redacting
  everything would defeat the purpose of this feature).
- Redaction is applied to the **structured arguments** before the logged
  invocation is rendered, not by pattern-matching over an already-built command
  string, so a quoting or escaping edge case cannot cause a secret to survive.
- The redacted invocation is otherwise byte-identical in structure to the
  executed one: same tool, same flags, same order, same target — only secret
  values differ.
- A negative test proves that a command containing a real-looking bearer token,
  session cookie, and login password reaches the audit payload with none of
  those values present anywhere in it.

## REQ-AUDIT-006: The full target response is recorded for `http_request`

Every successful `http_request` dispatch (used directly by the Vector Agent
and by `register_test_identity`, which dispatches through the same
`http_request` path) records the full response it received — not only the
fact that a call happened — as part of the same `tool_execution` audit entry
that already carries the request (`command`, REQ-AUDIT-003).

Acceptance criteria:

- The `tool_execution` audit entry carries a `response` field with the
  response status line, headers, and body for a successful `http_request`
  call — the same evidence already returned to the LLM for classification,
  not a re-summarized or re-derived version of it.
- Every other tool's `tool_execution` entry leaves `response` absent — their
  raw output is already parsed into services/findings/`outcome_summary`;
  duplicating it here would bloat the audit table without adding
  operator-visible value that isn't already recorded elsewhere.
- A failed or blocked `http_request` call (egress-denied, timeout, no
  response) records no `response`, never a partial or fabricated one.
- The field is bounded before it reaches durable storage, matching the
  runner's own already-justified 16 KB response cap
  (`worker/app/tool_runner_client.py::_http_request_command`) — this field
  never legitimately needs to exceed what the runner itself produced.
- The same recorded response is what the operator can see in the run's
  activity view, not only in the raw audit payload — an operator should not
  need to already know the field's internal name to find "what did the target
  actually send back."

## REQ-AUDIT-007: The recorded response is redacted the same way requests are

The recorded response is redacted so that secrets present in a real target
response — most concretely, a session cookie set via `Set-Cookie` — do not
enter durable audit storage or the model's own context, mirroring
REQ-AUDIT-004's rule for the request side: keep the name, drop the value.

Acceptance criteria:

- A sensitive response header's value (at minimum, everything in
  REQ-AUDIT-004's `SENSITIVE_HEADERS` set — `set-cookie` foremost, since a
  session identifier is exactly as sensitive as the credential that produced
  it, REQ-AGENT-022) is replaced with the redaction marker while the header
  **name** and line position are preserved, including when a response sends
  more than one `Set-Cookie` header.
- Header redaction is applied per line across the ENTIRE captured text
  unconditionally, not only after a header/body boundary is located — the
  runner's 16 KB cap can truncate mid-header or before the blank line that
  separates headers from body, and a response cut at that point must still
  have every header line it does contain redacted rather than shipped
  unredacted because no boundary was found.
- A JSON response body's credential-named fields (the same field-name rule as
  REQ-AUDIT-004: `password`, `token`, `secret`, `api_key`, etc.) are redacted
  the same way a JSON request body already is; the rest of the body — the
  actual evidence a vulnerability classification depends on — stays fully
  readable.
- Redaction happens exactly once, at the point the response is first turned
  into text, and the SAME redacted text is what reaches the LLM's own
  context, the `tool_execution.response` field, and the agent's `observation`
  audit event — no second, independent copy that could drift out of sync or
  reintroduce the gap this closes.
- The `observation` audit event's response text is no longer separately
  truncated to an arbitrary smaller bound than the (already-redacted,
  already-16KB-bounded) canonical text — a second truncation on top of an
  already-safe value only throws away evidence for no security benefit.
- **Negative test (the required R3 one):** given a raw response containing a
  real-shaped `Set-Cookie` session value and a JSON body with a `password`
  field, the text that reaches the audit payload contains neither value as a
  substring anywhere in it, including when the captured text is truncated
  mid-header (simulating the runner's 16 KB cut landing before the body).
- A non-sensitive response header (e.g. `Content-Type`, `Server`) and the
  rest of a response body's content (e.g. HTML markup, a reflected XSS test
  marker) are never redacted.
