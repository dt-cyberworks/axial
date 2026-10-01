---
title: Installation-wide read access to engagements, owner-only changes
status: implemented
risk: R3
owner: security-engineering
---

# Installation-wide Read Access to Engagements, Owner-only Changes

GitHub issue #47. An operator can be blocked by an engagement they cannot see and cannot
resolve. Seen on dev on 2026-09-30: activating an engagement failed with `409 allow-scope
overlaps another currently active engagement's allow-scope` because of a legacy engagement
that no operator could see, so there was nothing to resolve and nobody to ask. Two rules
disagreed. REQ-IAM-007 let operators see only engagements they own; REQ-CONCUR-003 compared
an activation against every active engagement of any owner and deliberately did not name it.

**Decisions (johannes, 2026-10-01, on the six open questions of the issue):**

1. **Access level: read-only.** Every user can look at every engagement; changing it,
   scanning, activating, deleting and deciding tool-call approvals stay with the owner and
   admins.
2. **What a reader sees: everything of the engagement.** Findings and evidence, runs, agent
   steps, the live stream, reports and PDFs, the audit log and the tool-invocation data,
   scope, grants and per-engagement configuration. Global settings, API keys and user
   management are not part of an engagement and stay admin-only.
3. **No engagement without an owner.** The ownerless legacy engagements get one, and none
   can be created again.
4. **The overlap error names the engagement** (its title and its owner), because the reader
   can now see it.
5. **Existence semantics (left to the author):** a signed-in user can see every engagement,
   so a refused change is `403`, not `404`; `404` remains for an id that does not exist.
6. **No tenant preparation** now. "Installation" is the only boundary; nothing here adds a
   tenant concept.

This changes the access rule of REQ-IAM-007 and REQ-IAM-014, the scoping of REQ-PORTFOLIO-001
and the "does not name it" sentence of REQ-CONCUR-003. Each of them carries a pointer to this
document. It does **not** change the Scope Gateway, the internal worker API, admin behavior,
sign-in, MFA, sessions or the audit chain.

**Risk class: R3.** It relaxes a documented confidentiality boundary between operators.
**Security review:** approved by johannes (project and security owner) on 2026-10-01, with
the decision that it ships in the patch release v0.3.1 (it carries migration 0038, which
runs automatically on upgrade and is described in the upgrade notes of `INSTALL.md`). The
approval is his, not the implementing agent's: an automated agent cannot approve an R3 change,
and it is not approved by being implemented. Roll-out to int and prod stays dev, then int,
then prod, as for every change; the approval does not skip that order.

Tests must verify these requirements directly. Do not weaken tests to match implementation;
update implementation when it violates this document.

---

## REQ-IAM-021: Every engagement has an owner

Acceptance criteria:

- `engagement.owner_user_id` is `NOT NULL`. The original REQ-IAM-007 already said "not null
  after migration"; this makes it true.
- The migration gives every ownerless engagement to the oldest active administrator. It stops
  with a clear error, changing nothing, when there are ownerless engagements and no
  administrator. It is idempotent.
- Every path that creates an engagement sets an owner: the operator endpoint (the caller,
  never client-supplied) and the benchmark seeding endpoint (the oldest active
  administrator; it answers `409` when there is none).
- Reassigning an owner needs an existing user and can never clear it.
- [Negative test] Inserting an engagement without an owner is refused by the database.
- [Negative test] The migration on a database with ownerless engagements assigns the oldest
  active administrator, and aborts without changes when no administrator exists.

Security invariants: ownership still decides who may change an engagement (REQ-IAM-023); the
Scope Gateway is untouched.

## REQ-IAM-022: Every signed-in user can read every engagement

Acceptance criteria:

- The engagement list returns every engagement to every signed-in user, each with its owner
  (display name and email) and a `can_manage` flag that says whether the caller may change it.
- Every read of an engagement (`GET` on a route under `/engagements/{id}`) is allowed for every
  signed-in user: detail, scope, grants, configuration, readiness, findings, DNS, summary,
  graph, runs and their plan, diff and agent steps, the audit log and its facets, the live
  stream, reports and the authorization PDF, discovery artifacts, asset reviews.
- The findings overview (`GET /findings`) covers every engagement and offers an
  "only my engagements" filter (`mine=true`); it shows each finding's engagement owner.
- Global settings, API keys, user management and the account audit stay admin-only
  (REQ-IAM-013 is unchanged). The list of pending approvals (the popup queue) stays limited to
  the caller's own engagements, and to all of them for an administrator: it is the owner's
  action queue.
- A disabled or locked account, and a request without credentials, still reads nothing.
- [Negative test] A non-owner can read each of the routes above and receives the same data the
  owner receives.
- [Negative test] An unauthenticated request is `401`; an id that does not exist is `404` for
  everyone.

Security invariants: reading never changes state; the internal worker API is not reachable
with a user session.

## REQ-IAM-023: Only the owner or an administrator can change an engagement

Acceptance criteria:

- Every request that is not a read (`POST`, `PUT`, `PATCH`, `DELETE`) on a route under
  `/engagements/{id}` is refused with `403` for a user who is neither the owner nor an
  administrator, before the request body is read and before anything is written. This covers
  edit, configuration, scope, grants, overrides, bounty program, authorization attestation,
  activation, starting a scan, cancelling a run, asset-review decisions, triage, requesting a
  Lens explanation, requesting a report, and deletion.
- Deciding an approval (`approve`, `reject`) is `403` for a non-owner; the approval keeps its
  state, nothing is executed, and its state is not revealed before the check.
- Reassigning an owner stays admin-only (`403` for everyone else, including the owner).
- Admins keep full rights; the owner keeps full rights.
- The check is one rule in one place (`app/security.py`) applied by the router for every
  present and future route, not a per-endpoint decision.
- [Negative test] For every mutating route under `/engagements/{id}` a non-owner operator gets
  `403` and the engagement, its scope, grants, runs, findings and audit log are unchanged.
- [Negative test] A non-owner cannot approve or reject an approval of another user's engagement.
- [Negative test] A new mutating route under `/engagements/{id}` without the rule fails the
  route-sweep test, so the rule cannot be forgotten.

Security invariants: the Scope Gateway still authorizes every tool call independently of who
asked; this requirement answers only "may this human change this engagement".

## REQ-IAM-024: The activation overlap error names the engagement

Acceptance criteria:

- When activating an engagement, or adding an allow-scope row to an active one, is refused
  because of an overlapping active engagement, the `409` message names that engagement's title
  and its owner (display name and email). When several overlap, it names up to three.
- The refusal itself is unchanged (REQ-CONCUR-003): same conditions, nothing is written.
- [Negative test] An activation that does not overlap is not refused and names nothing.

Security invariants: the check compares against every active engagement of any owner, as before.

## REQ-IAM-025: The console shows who owns what and what the reader may do

Acceptance criteria:

- The overview lists every engagement with an **Owner** column and an **Only mine** filter; the
  metrics follow the filter.
- An engagement the user cannot change shows a read-only notice that names its owner, and
  carries none of the controls that change it: edit, delete, activate, attest, start run, stop
  scan, tool grants, configuration, triage, Lens explanation, report generation and the
  asset-review decision. Reading controls (tabs, filters, downloads, audit) stay.
- The findings overview has an **Only my engagements** filter and shows the engagement's owner.
- The server is the authority: a hidden control is a convenience, and a request sent anyway gets
  `403` (REQ-IAM-023).
- [Negative test] The frontend requirement test asserts that every change control is guarded by
  the `can_manage` flag the API returns.

Security invariants: none beyond REQ-IAM-023; hiding is not a control.

---

## Verification log

2026-10-01, dev (not yet int; the human security review is pending):

- Migration 0038 applied by the compose `migrate` service; `engagement.owner_user_id` is `NOT NULL`. Dev had no
  ownerless engagement, so the backfill itself is proven by the integration test, not live.
- Live, real HTTP and a real browser, three throwaway accounts (owner, reader, admin; removed afterwards, no
  scan started): the reader sees the owner's engagement in the list with its owner and `can_manage=false`, reads
  every part of it (12 read routes 200), gets `403` on 9 kinds of change (edit, scope, grants, activate, scan,
  report, configuration, owner reassignment, delete) with the documented message and nothing written (engagement
  row and audit-log count unchanged), cannot see or decide the owner's pending approval (`403`, state unchanged),
  while the owner and an administrator can change it and only an administrator can reassign. The reader's
  activation of an overlapping engagement is `409` and names the engagement and its owner. In the console the
  reader's overview shows the Owner column, **Only mine** works, the owner's row has no Edit or Delete, the
  engagement page shows the read-only notice without Edit, Start run, Activate or Generate report, the edit page
  shows the notice instead of the form, and the owner sees the controls.
- The benchmark seeding endpoint created its engagement under the oldest active administrator.
- UAT golden path green on dev.


2026-10-01, int (after johannes's approval of this requirement; deployed from the v0.3.1 release commit):

- Pre-checks on the live database: no scan run in flight, 3 engagements of which none ownerless, 2 active
  administrators. A database dump was taken first and the previous control-plane image kept for rollback.
- Migration 0038 applied by the `migrate` service (exit 0): `engagement.owner_user_id` is `NOT NULL`; engagements,
  users and findings are unchanged (3, 4, 75). With no ownerless engagement it only tightened the column, so the
  backfill and its fail-closed refusal are still proven by the integration test, not live.
- Live, real HTTPS through the shared edge, with the operator UAT account (not an administrator): the list shows
  all 3 engagements, the 2 it does not own with `can_manage=false` and their owners named; it reads all five
  read routes of one of them (200); a no-op `PATCH` and an empty-body scope `POST` on it are `403` (an empty body
  would have been `422` if the rule had not fired first); an unknown id is `404`; the findings page covers every
  engagement.
- UAT golden path and scan journey green on int (the journey scanned only its approved target).
