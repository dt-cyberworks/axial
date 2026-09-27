---
title: Minimum safe operation for a single-operator deployment
status: approved
risk: R4
owner: security-engineering
---

# Minimum safe operation

This baseline targets a single trusted operator running ASM behind localhost or
a private VPN. It does not claim multi-tenant readiness. RBAC, workload
identity, and runner-bound dispatch artifacts remain required before expanding
the operating model.

## REQ-CONFIG-001: Production configuration fails closed

When production mode is enabled, the control plane and supporting workloads
shall refuse to start with development credentials or missing required secrets.

Acceptance criteria:

- Production mode rejects `change-me-in-dev` internal and signing secrets.
- Production mode rejects default database and object-store credentials.
- Secrets are supplied through deployment secret inputs and are never logged.
- Development mode remains usable with explicit development defaults.

## REQ-IAM-001: Public operator API requires one authenticated operator

Every public control-plane endpoint except health shall require a configured
single-operator credential. Internal workload credentials are not accepted as
operator credentials.

Acceptance criteria:

- Missing or invalid operator credentials receive `401`.
- `/health` remains unauthenticated.
- Internal endpoints continue to require their separate internal credential.
- Approval actor identity is derived by the server, not accepted from the UI.
- Authentication failures are sanitized and audited where an engagement can be
  identified.

## REQ-AUDIT-001: Proxy audit events use a control-plane-owned writer

The egress proxy shall not write application audit rows directly. It shall
submit structured events to an authenticated internal control-plane endpoint.

Acceptance criteria:

- The proxy database credential is read-only.
- The control plane validates and appends proxy events.
- An event contains engagement, decision, reason, and bounded sanitized payload.
- Required audit submission failure causes the corresponding request to fail
  closed.

## REQ-AUDIT-002: Audit-chain append is serialized per engagement

Audit rows shall be appended to one concurrency-safe chain per engagement.

Acceptance criteria:

- Concurrent appends cannot select the same predecessor.
- Accepted rows have one predecessor except the genesis row.
- Chain verification detects modification, removal, insertion, and reordering.
- Concurrency integration tests prove serialization.

## REQ-APPROVAL-004: Approved calls are atomically claimed and reauthorized

A manually approved call shall be atomically claimed before dispatch and shall
pass current gateway checks again using the exact stored call.

Acceptance criteria:

- Only one worker can transition `approved` to `executing`.
- Claiming reloads the exact stored call; callers cannot replace target or args.
- Current engagement state, window, scope, deny rules, grants, tool policy,
  argument safety, rate limit, and budget are rechecked.
- Reauthorization does not create a second approval.
- Dispatch occurs only after a successful claim.
- Completion transitions `executing` to `consumed` or `execution_failed`.
- Claim, denial, consumption, and failure are audited.
- Expired, altered, reused, rejected, or already executing approvals never
  dispatch.

