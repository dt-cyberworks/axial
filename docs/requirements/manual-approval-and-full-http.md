---
title: Manual approval for state-changing requests and full HTTP capability
status: implemented
risk: R4
owner: security-engineering
---

# Manual Approval & Full HTTP (curl) Capability Requirements

This document is the requirement source for giving the Vector Agent a full HTTP
("curl") capability — including **state-changing** methods — while keeping the
project's security invariants intact through **mandatory, per-command human
approval with an LLM-assessed risk statement**.

**Risk class: R4** (new active/offensive capability with destructive potential).
Per [`../engineering/sdlc.md`](../engineering/sdlc.md) §2/§5/§7 this change
requires explicit human authorization, positive and negative tests, `make
lab-test`, and a security-owner review. An automated agent may implement it but
**may not self-approve** the R4 decision.

## Invariant exception (AGENTS.md / sdlc.md §4)

`sdlc.md` §4 lists "no destructive … behavior is added" as a release gate. This
change deliberately adds *the potential* for state-changing requests, so it
requires a documented exception:

- **Scope:** the Vector Agent may *propose* state-changing HTTP requests
  (POST/PUT/DELETE/PATCH) against in-scope hosts only.
- **Compensating control:** such a request never executes autonomously. It stops
  at the Scope Gateway, creates an approval, and runs only after a human operator
  approves *that exact request*. Reads (GET/HEAD/OPTIONS) remain autonomous.
- **Boundaries preserved:** target scope, time window, deny-precedence, egress
  isolation, audit integrity, and "workers do not scan targets directly" are all
  unchanged — the write still goes through the gateway and egress-proxy.
- **Owner / expiry / approval:** security-engineering; reviewed per release;
  approval recorded at the R4 gate before enablement.

Tests must verify these requirements directly. Do not weaken tests or the
envelope to satisfy implementation.

---

## REQ-HTTP-002: The Vector Agent has a full HTTP (curl) tool

The agent's HTTP tool must support the full request surface a curl-based HTTP
client provides, so the agent can craft real validation/exploitation requests
(e.g. submit a login form to prove an open redirect), not only reads.

Acceptance criteria:
- The `http_request` tool accepts any of `GET, HEAD, OPTIONS, POST, PUT, DELETE,
  PATCH`, an optional request `body`, and arbitrary request headers, executed via
  curl through the egress-proxy.
- Read methods (`GET/HEAD/OPTIONS`) run under the existing non-destructive
  envelope and remain **autonomous** (no approval).
- Write methods and any request carrying a body are treated as state-changing and
  are governed by REQ-APPROVAL-001 (never autonomous).
- Header/path/body inputs remain size-bounded and shell-injection-safe
  (shlex-quoted); malformed input is denied, not approved.

## REQ-HTTP-003: One http_request is exactly one HTTP request

Found in the 2026-09-27 review: curl expands `[a-b]` ranges and `{x,y}`
lists in a URL into one request per combination, and the path validator
allows those characters (PHP array parameters such as `ids[]=1` are
legitimate test input). A path like `/item/[1-500]` therefore turned one
gateway decision - or one human approval of a DELETE - into 500 requests.

Acceptance criteria:
- The command built for `http_request` disables URL globbing
  (`curl --globoff`), so brackets and braces in the path are sent
  literally.
- [Negative test] Running the built command against a local server with a
  range or list pattern in the path, for `GET`, `POST`, and `DELETE`,
  delivers exactly one request, with the path unchanged.
- The in-app documentation's description of the command matches what runs.

## REQ-APPROVAL-001: State-changing requests require per-command human approval

A state-changing agent request that is otherwise valid must not be hard-denied
and must not run autonomously; it must require explicit, per-command human
approval.

Acceptance criteria:
- A state-changing `http_request` that is in scope, within window, and
  well-formed produces a **pending approval** (one per request), not an
  `unsafe_arguments` denial and not an autonomous execution.
- A state-changing request that is out of scope, out of window, or malformed is
  still denied outright (approval is never offered for an otherwise-invalid call).
- The approval carries the exact request (method, path, headers, body), the
  agent's rationale, and the risk statement (REQ-APPROVAL-002).
- The write executes **only** after an operator approves that specific approval;
  on reject or expiry it is skipped. No bypass; execution is audited.

## REQ-APPROVAL-002: The approval shows what, why, and an LLM-assessed risk

The operator's approval prompt must let a human decide with full context.

Acceptance criteria:
- The approval presents, per request: **What** (method, path, headers, body),
  **Why** (the agent's rationale), and **Risk** — a risk level and a plain-language
  description **produced by the LLM** (the proposing agent), not a static string.
- The risk statement describes what the request does and what could go wrong
  (e.g. state change, data modification, effect on a real user/session).
- If the agent supplies no risk statement for a state-changing request, the
  request is not offered for approval (fail-closed).

## REQ-APPROVAL-003: Live approval; the run waits and shows a popup

Approval is a live, per-command interaction, not a silent background queue.

Acceptance criteria:
- While a write is pending, the scan run enters `waiting_approval` and the agent
  waits for the decision up to the approval's expiry.
- The Run detail view shows a **popup** for each pending approval with What/Why/
  Risk and Approve / Reject actions.
- On approve, the request executes and its result is fed back to the agent, which
  continues; on reject or expiry, the agent records it and continues without it.
- Multiple pending writes are presented individually (one popup per command).

## REQ-APPROVAL-005: The approval timeout is configurable (global default + per-engagement override)

Context: the approval expiry (`ApprovalRequest.expires_at`) already existed
and was already enforced (lazily, on read), but its 15-minute duration was a
hardcoded literal with no setting anywhere, and the worker's independent poll
ceiling (`_APPROVAL_MAX_WAIT_SECONDS`) duplicated that same 15 minutes as a
second, unrelated hardcoded constant that could silently desync from it.
This closes both gaps and makes the operator-facing behavior explicit: an
engagement is never stuck waiting on an approval indefinitely just because
the operator stepped away past the configured window.

**Risk class: R3** — this changes the manual-approval gate's expiry
behavior directly (`gateway/authorize.py`'s `_create_approval_request`,
explicitly named in the R3 category). It does not introduce a new active
capability or change whether/how a decision can bypass the gateway — only
*how long* a pending decision is allowed to wait, and how that duration is
configured.

Acceptance criteria:
- A global default timeout (seconds) is configurable via
  `GET`/`PUT /settings/approval-timeout-seconds`, bounded to [60, 86400],
  defaulting to 900 (the previous hardcoded value) so an unconfigured
  deployment behaves exactly as before.
- Each engagement may override the effective timeout via
  `approval_timeout_seconds_override` on its `/config` GET/PUT, following the
  same campaign-override-else-global-else-built-in resolution order and
  field-presence (not just null-vs-value) semantics already used for the
  agent iteration budget.
- `_create_approval_request` uses the resolved timeout (campaign → global →
  900s) instead of a hardcoded literal.
- The worker's poll ceiling for `_await_approval` is the same resolved value
  passed down from the control plane at scan-start time — it can never
  silently desync from the value that actually governs `expires_at`.
- Once the timeout elapses without a decision, the pending approval
  auto-rejects (existing `state="expired"` value, unchanged) and the
  agent-facing message explicitly reads as an automatic rejection due to no
  response in time, not a generic/ambiguous "expired".
- An out-of-range override (below 60s or above 86400s) is rejected by schema
  validation before it can reach the database.

Security invariants:
- No change to the claim/expire atomicity already enforced in
  `_claim_matching_approval`, to what counts as a valid decision, or to any
  ALLOW/DENY path in the Scope Gateway — only the expiry *duration* and its
  configurability change.
- A short timeout cannot be used to create a permanently-pending, still-
  claimable approval: once expired, claiming it is denied exactly like the
  pre-existing expiry path (proven by a negative test).

## REQ-APPROVAL-006: Manual approval works identically for every gated tool, not only http_request

Context: found live 2026-08-09 - a real engagement's agent proposed
`testssl`, which the operator had configured to require manual approval.
The popup appeared (empty: no rationale, "?" for what it would do, "no risk
description"), and clicking Approve had **no effect** - the tool never ran.
Root cause: `worker/app/tasks/agent.py::_handle_run_check` (the handler for
every `run_check`-routed tool - testssl/nikto/nuclei/wafw00f/redis-probe/
activemq-banner) created the `ApprovalRequest` row but, on `is_pending`,
returned `"PENDING: ... skipped"` to the agent immediately instead of
waiting for the decision like `_handle_http_request`/
`_handle_register_test_identity` already did via `_await_approval`. The
agent had already moved on by the time an operator's decision existed, so
approving or rejecting were identically inert. Separately,
`decision_payload` for `run_check` never carried the `rationale` field at
all (silently dropped, not merely optional/absent), and `_await_approval`
itself was hardcoded to always dispatch `"http_request"` regardless of what
was actually approved - harmless while it had exactly two callers that both
happened to be `http_request`-shaped, wrong once a third, differently-shaped
caller existed.

**Risk class: R4** (same class as REQ-APPROVAL-001/002/003: this is the
approval/execution mechanism itself). Reuses the existing, already-reviewed
claim/re-authorize/dispatch path in `_await_approval` (gateway
re-authorization via `client.claim_approval` on the exact stored call, not a
new execution path) - extended to cover more tools, not redesigned.

Acceptance criteria:

- Any `run_check`-routed tool that requires manual approval waits for the
  operator's decision exactly like `http_request` does (`_await_approval`),
  and executes the exact, gateway-re-authorized approved call on approval -
  approving must have an observable effect, not silently no-op.
- `_await_approval` dispatches the tool actually present in the approved,
  stored `tool_call` (`exact.get("tool")`), never a hardcoded default -
  proven by a test that approves a non-`http_request` tool and asserts that
  exact tool is what gets dispatched.
- `run_check`'s `decision_payload` carries the agent's `rationale` (already
  collected by its own tool schema, previously collected and discarded) so
  the approval popup has real content for scanner tools too.
- The operator UI (`ApprovalModal.tsx`) renders a non-HTTP-shaped approval
  (no `method`/`path`) as `{tool} → {target}`, not `"? →"`, and omits the
  Risk section entirely when no risk assessment exists (these tools are
  read-only recon, not state-changing writes - the absence is a genuine
  property of the tool class, not a missing/broken field to apologize for).
- [Negative test] rejecting a `run_check` approval still results in no
  dispatch, exactly as before - only the *pending* (previously silently
  inert) path changes behavior.

Not yet closed: `_handle_run_check`'s `run_check` tool schema still has no
`risk`/`risk_level` fields for the agent to fill in (unlike `http_request`,
where they're required for state-changing calls) - left absent deliberately,
since these tools are inherently read-only reconnaissance, not because the
gap wasn't noticed. If an operator-configured manual-approval policy ever
extends to a genuinely state-changing `run_check`-routed tool in the future,
this should be revisited.
