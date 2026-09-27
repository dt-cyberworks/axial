# Software Development Lifecycle

This document is the authoritative engineering lifecycle for this repository.
It applies to human contributors and coding agents.

## 1. Change lifecycle

Every non-trivial change follows this sequence:

1. **Define** — create or update an approved requirement in
   `docs/requirements/`. Requirements describe observable behavior, not an
   implementation.
2. **Classify** — assign a change risk from `R0` through `R4`.
3. **Design** — document architecture, data, API, UI, security-boundary, rollout,
   and rollback effects when the risk or complexity requires it.
4. **Plan verification** — create or update test cases in `docs/test-cases/`.
   Every acceptance criterion needs verification.
5. **Implement** — keep migrations, models, schemas, APIs, workers, UI, and
   documentation aligned.
6. **Verify** — run the gates required for the risk class. Security-sensitive
   changes require a negative test.
7. **Review** — obtain the required human review. Automated agents cannot
   self-approve an SDLC exception or an `R3`/`R4` security decision.
8. **Release** — use immutable artifacts, record known risks, verify the
   deployment, and retain a rollback path.

## 2. Risk classification

| Risk | Typical change | Minimum verification |
|---|---|---|
| `R0` | Comments, copy, non-functional formatting | Relevant static check |
| `R1` | Normal UI or isolated application behavior | Unit tests and build |
| `R2` | API, persistence, worker orchestration | Unit and integration tests; migration/rollback assessment |
| `R3` | Scope Gateway, auth, audit, runner, proxy, secrets | Threat-model assessment, positive and negative tests, integration and lab gates, security-owner review |
| `R4` | New active capability, widened egress, destructive potential | Explicit human authorization, legal/security review, isolated validation, staged release |

A change may be classified upward at any time. Downgrading an `R3` or `R4`
change requires a documented human decision.

## 3. Requirements and test cases

- Requirement IDs use `REQ-<DOMAIN>-NNN`.
- Test-case IDs use `TC-<DOMAIN>-NNN`.
- Approved requirements contain explicit acceptance criteria.
- Test cases reference the requirements they verify and the executable tests
  that implement them.
- `make requirements-check` validates the records.
- `make traceability` regenerates `docs/traceability/requirements-to-tests.md`.
- Generated traceability must be current in every pull request.

### 3.1 Backlog items

The backlog is kept as requirements-as-code in `docs/requirements/`; no Jira
or Confluence is required.

- A human or coding agent may propose and create
  `docs/requirements/backlog-<topic>.md`. Creating an item records a product
  idea; it does not authorize implementation.
- Before creating an item, the human and agent may discuss value, scope,
  alternatives, risk, and whether the item belongs in the backlog. If the
  value is clear and recording it is useful, an agent may create it directly
  and report that it did so.
- A backlog item has `status: backlog`, a preliminary risk and owner,
  observable acceptance criteria, security invariants, open
  questions/dependencies, and an implementation authorization of `None`.
- Backlog items do not require executable tests. They are excluded from the
  definition of done until selected for implementation.
- An authorized human promotes an item by explicitly selecting it for
  implementation. The same document records the dated decision and any scope
  clarification, changes status through the normal lifecycle, and receives
  linked `TC-*` cases before implementation.
- An explicit request that both creates and implements an item may promote it
  in the same change. The decision log must still preserve that it originated
  in the backlog and identify the human authorization.
- Promotion does not waive `R3`/`R4` legal, security-review, negative-test, or
  release gates. Coding agents cannot approve those exceptions themselves.

## 4. Required security behavior

The invariants in `AGENTS.md` are release gates. In particular:

- active operations always pass the Scope Gateway;
- explicit deny wins;
- authorization fails closed;
- workers do not write directly to the database or scan targets directly;
- runner and proxy isolation remains intact;
- audit integrity is preserved;
- no destructive, credential, mass-scan, or out-of-scope behavior is added.

Tests may not be weakened to accommodate behavior that violates a requirement
or invariant. An exception must identify its owner, scope, expiry, compensating
control, and approval.

## 5. Definition of done

A change is complete only when:

- its requirement and acceptance criteria are approved or the change qualifies
  as `R0`;
- affected test cases and executable tests are present;
- required positive and negative paths pass;
- migrations and API compatibility have been assessed;
- relevant architecture, security, API, data, testing, deployment, legal, and
  roadmap documentation is updated;
- no secret or sensitive evidence is exposed;
- rollout and rollback are understood;
- required human reviewers have approved it;
- `make verify` passes, plus `make lab-test` for applicable `R3`/`R4` changes;
- a change to scan, detection, or agent-dispatch behavior additionally runs
  in the dev environment against the relevant deployed benchmark target(s)
  (`benchmark/cli.py`, scoped with `--only` to the changed capability rather
  than the full sweep) - real infrastructure and real ground truth, not only
  mocked tests.

## 6. Release evidence

CI results are the normal test evidence and should not be committed per run.
For a formal release, add `docs/releases/<version>/release-manifest.md` with:

- source commit and artifact/image digests;
- included requirement IDs;
- CI run reference;
- migrations and deployment verification;
- known risks and approved exceptions;
- rollback instructions.

