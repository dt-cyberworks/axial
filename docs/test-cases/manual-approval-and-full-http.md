---
title: Manual approval & full HTTP capability verification
status: ready
risk: R4
owner: security-engineering
---

# Manual Approval & Full HTTP (curl) Capability Verification

Verifies [`../requirements/manual-approval-and-full-http.md`](../requirements/manual-approval-and-full-http.md).
R4: positive and negative paths are both required.

## TC-HTTP-002: Full HTTP tool — structural validity and state-change classification

Requirements:

- REQ-HTTP-002

Automated tests:

- `control-plane/tests/test_args_safety.py`

Objective:

Verify that read and write methods plus an optional body are structurally valid
and shell-injection-safe, that malformed input is rejected, and that the
read-vs-write classification is correct.

Expected results:

- `GET/HEAD/OPTIONS/POST/PUT/DELETE/PATCH` with clean headers/path/body validate.
- An unknown method, CRLF injection, or oversized body is rejected.
- `http_request_is_state_changing` is true for write methods and for any body.

## TC-APPROVAL-001: State-changing requests require per-command approval

Requirements:

- REQ-APPROVAL-001
- REQ-APPROVAL-002

Automated tests:

- `control-plane/tests/integration/test_manual_approval_http.py`
- `control-plane/tests/integration/test_gateway_agent_budget.py`

Objective:

Verify the Scope Gateway routes a valid state-changing `http_request` to a
pending approval, denies it outright when out of scope or lacking a risk
statement, and that the approval is a single-use token.

Expected results:

- In-scope write with a risk statement → `pending_approval` with an approval that
  carries the request, rationale, and risk.
- Write without a risk statement → `risk_statement_required` (fail-closed).
- Out-of-scope write → hard deny (`explicit_out_of_scope`), never pending.
- Consuming an approval twice is rejected; an expired approval reports `expired`.

## TC-APPROVAL-003: The agent waits live and executes only after approval

Requirements:

- REQ-APPROVAL-003

Automated tests:

- `worker/tests/test_agent.py`

Objective:

Verify the agent pauses on a pending write, executes and consumes on approval,
skips on rejection, and aborts the wait on run cancellation — no execution
without approval.

Expected results:

- Approved → the write is dispatched and the approval is consumed once.
- Rejected → the write is not dispatched.
- Run cancelled while waiting → the write is not dispatched.

## TC-APPROVAL-005: The approval timeout is configurable and cannot be exploited into a permanent pending state

Requirements:

- REQ-APPROVAL-005

Automated tests:

- `control-plane/tests/integration/test_approval_timeout_api.py`
- `control-plane/tests/integration/test_config_layers.py`
- `control-plane/tests/integration/test_manual_approval_http.py`
- `worker/tests/test_agent.py`

Objective:

Verify the global default + per-engagement override resolve correctly, the
created approval's `expires_at` reflects the resolved value (not the old
hardcoded 15 minutes), the worker's poll ceiling matches it, and a short
timeout cannot be used to keep an approval claimable past its expiry.

Expected results:

- `GET`/`PUT /settings/approval-timeout-seconds` roundtrips within [60, 86400];
  out-of-range values are rejected.
- Engagement `/config` reports the effective value and an override flag that
  correctly reflects campaign-override → global → built-in resolution,
  including explicit-null-clears-override and omitted-field-leaves-untouched.
- `authorize()` creates an approval whose `expires_at` matches the resolved
  timeout (verified with a 300s campaign override).
- A 60s (floor) override genuinely expires and a subsequent claim attempt is
  denied — never a permanently-pending, still-claimable approval.
- `_await_approval` gives up around the passed-in `approval_timeout_seconds`
  (verified with a short 2s value), not a hardcoded 900s constant, and its
  auto-rejection message names the configured timeout explicitly.

## TC-APPROVAL-006: Manual approval executes for every gated tool, not only http_request

Requirements:

- REQ-APPROVAL-006

Automated tests:

- `worker/tests/test_agent.py`
- `frontend/tests/global_approval_surfacing.test.mjs`

Objective:

Prove the real, live-found bug is fixed: a `run_check`-routed tool
(testssl/nikto/nuclei/wafw00f/redis-probe/activemq-banner) that requires
manual approval actually waits for and executes on the operator's decision,
carries the agent's rationale into the popup, and the popup itself renders
honestly for a tool with no HTTP method/path/risk concept.

Expected results:

- `test_run_check_pending_approval_waits_instead_of_skipping` - a `run_check`
  proposal requiring approval dispatches the real tool call once approved
  (previously: returned "PENDING: ... skipped" immediately and never
  dispatched regardless of the eventual decision).
- `test_run_check_pending_approval_includes_the_agents_rationale` -
  `decision_payload["rationale"]` carries what the agent actually provided
  (previously: silently absent).
- `test_await_approval_dispatches_the_exact_approved_tool_not_a_hardcoded_default` -
  approving a `testssl` proposal dispatches `testssl`, not a hardcoded
  `http_request` (previously: always dispatched `http_request` regardless of
  what was approved - latent, since no non-`http_request` caller existed
  yet).
- `global_approval_surfacing.test.mjs`'s new assertions - `ApprovalModal.tsx`
  branches on whether the approval is HTTP-shaped (`isHttpShaped`) and only
  claims a risk assessment exists when one is actually present
  (`hasRiskAssessment`), rather than rendering `"? →"` and "(no risk
  description)" for a tool class that has neither concept.

## TC-HTTP-003: An agent HTTP request never fans out

Requirements:

- REQ-HTTP-003

Automated tests:

- `worker/tests/test_http_request_single_request.py`

Objective:

Prove a path containing curl glob syntax produces exactly one request, so
one authorization or approval can never be multiplied.

Expected results:

- `test_http_request_command_disables_url_globbing` - `curl --globoff` first, URL unchanged.
- `test_negative_a_globbing_path_sends_exactly_one_request` - with a real curl and a local counting server, `/item/[1-5]` and `/{a,b,c}` arrive once, as sent, for GET, POST, and DELETE. Against the code before the fix, `/item/[1-5]` arrived five times.
