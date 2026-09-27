---
title: Tool invocation transparency verification
status: ready
risk: R3
owner: security-engineering
---

# Tool Invocation Transparency Verification

Verifies [`../requirements/tool-invocation-transparency.md`](../requirements/tool-invocation-transparency.md).
R3: the change writes new data into the durable hash-chained audit trail, and
that data is precisely where credentials would leak if redaction were wrong —
so the negative tests in TC-AUDIT-004 and TC-AUDIT-007 are the load-bearing
ones, not the happy-path capture tests.

## TC-AUDIT-003: The exact invocation is captured for both dispatch paths

Requirements:

- REQ-AUDIT-003

Automated tests:

- `worker/tests/test_tool_invocation_audit.py`
- `control-plane/tests/integration/test_tool_execution_audit.py`

Objective:

Verify the invocation actually used is captured and reaches the audit payload,
for both the literal-command tools and the structured-body HexStrike tools,
without changing tool outcomes.

Expected results:

- A `/api/command` tool (e.g. `ffuf`, `httpx`) records a `command` string
  containing the real binary and flags that were sent to the runner.
- A HexStrike-endpoint tool (e.g. `nmap`, `nuclei`) records a deterministic
  rendering of the structured body that was sent, not an empty or fabricated
  command.
- The captured invocation is produced by the same builder used for execution
  (asserted by comparing against the builder's own output), so the two cannot
  drift.
- The value is truncated to the documented bound before storage.
- `ToolExecutionEventIn` accepts the new field, and the internal
  `tool-executions` endpoint writes it into the `tool_execution` audit payload.
- A tool with no determinable invocation records `command` absent/None, and the
  execution's own success/exit code is unchanged either way.

## TC-AUDIT-004: Credentials never reach the audit payload

Requirements:

- REQ-AUDIT-004

Automated tests:

- `worker/tests/test_command_redaction.py`

Objective:

Prove that secrets which genuinely occur in real invocations — a bearer token,
an auto-merged session cookie, an API key header, and a login password body —
are absent from the recorded invocation, while everything non-secret stays
readable.

Expected results:

- Sensitive header values are replaced with the redaction marker and the header
  **name** survives, for every name in the documented set, matched
  case-insensitively (`Authorization`, `authorization`, `AUTHORIZATION` all
  redact).
- Credential-named body fields are redacted in both form-encoded
  (`user=x&password=y`) and JSON (`{"password": "y"}`) bodies; a
  non-credential field in the same body (including an XSS test marker) remains
  fully readable.
- **Negative test (the required R3 one):** given an `http_request` invocation
  carrying a real-shaped bearer token, a `Cookie: session=...` header, and a
  login body with a password, the string that reaches the audit payload
  contains none of those secret values as substrings — asserted against the
  secret values directly, not against an expected-output template that could
  be updated to match a regression.
- Redaction operates on structured args before rendering, so a value
  containing quotes, spaces, or shell metacharacters is still fully redacted
  (no quoting edge case leaks it).
- A non-sensitive header (e.g. `Accept`, `User-Agent`) is never redacted.

## TC-AUDIT-006: The full `http_request` response is captured

Requirements:

- REQ-AUDIT-006

Automated tests:

- `worker/tests/test_dispatch_response_capture.py`
- `control-plane/tests/integration/test_tool_execution_audit.py`

Objective:

Verify a successful `http_request` dispatch records its full response as a
`response` field on the same `tool_execution` audit entry that already
carries the request, that every other tool leaves it absent, and that a
failed/blocked call never records a partial or fabricated one.

Expected results:

- A successful `http_request` call's `tool_execution` entry has a `response`
  field containing the status line, headers, and body the runner returned.
- A non-`http_request` tool's `tool_execution` entry has `response` absent.
- A failed `http_request` call (runner error, egress block, no response) has
  `response` absent, not an empty string or partial capture.
- `ToolExecutionEventIn` accepts the new field bounded to the runner's own
  16 KB response cap, and the internal `tool-executions` endpoint writes it
  into the `tool_execution` audit payload.

## TC-AUDIT-007: The recorded response is redacted, including under truncation

Requirements:

- REQ-AUDIT-007

Automated tests:

- `worker/tests/test_command_redaction.py`
- `worker/tests/test_dispatch_response_capture.py`

Objective:

Prove that a real session cookie set via `Set-Cookie` and a credential-named
JSON body field are absent from the recorded response and the agent's own
observation text — including when the captured text is cut mid-header, the
shape the runner's 16 KB cap actually produces — while the rest of the
response (headers, body, non-credential fields) stays fully readable and
identical everywhere it is used.

Expected results:

- **Negative test (the required R3 one):** a raw response carrying a
  real-shaped `Set-Cookie` session value and a JSON body `password` field
  reaches the audit payload with neither value present anywhere in it,
  asserted against the secret values directly.
- The same negative assertion holds when the raw text is truncated partway
  through the `Set-Cookie` header line (simulating the runner's cap landing
  mid-header) — the truncated fragment is still redacted, not shipped as-is
  because no header/body boundary was found.
- Multiple `Set-Cookie` headers in one response are each redacted
  independently; none collapses into or overwrites another.
- A non-sensitive header (`Content-Type`, `Server`) and non-credential body
  content (HTML markup, a reflected XSS test marker) are byte-identical to
  the input — redaction never touches evidence that is not itself a secret.
- The redacted text reaching `tool_execution.response`, the agent's LLM-facing
  observation, and the `agent_event` "observation" audit entry are the SAME
  string for one call — proving there is exactly one redaction site, not two
  independently-truncated copies that could drift.
- The `agent_event` observation text is no longer cut to 2000 characters
  below the canonical (already-redacted, already-16KB-bounded) response.
