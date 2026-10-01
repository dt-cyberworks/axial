# Architecture & GUI Design: Engagement Visibility and Owner-only Changes

Design spec for [`../requirements/engagement-visibility.md`](../requirements/engagement-visibility.md)
(GitHub issue #47, R3). SDLC phases 2 (architecture) and 3 (GUI design). One row per requirement
in section 5.

## 1. Data model

| Change | Table | Purpose | Requirement |
|---|---|---|---|
| `owner_user_id` becomes `NOT NULL` | `engagement` | no ownerless engagement | REQ-IAM-021 |

Migration `0038_engagement_owner_required.sql` (idempotent): in one `DO` block it counts ownerless
engagements; if there are any it gives them to the oldest active administrator
(`ORDER BY created_at, id`) and notes how many; with ownerless rows and no active administrator it
**raises and changes nothing** (fail closed, never a guessed owner). Then
`ALTER COLUMN ... SET NOT NULL`. No audit rows are written from SQL (the audit chain is hash-linked
by the application); the notice in the migration output is the record, and an administrator can
reassign through the existing endpoint, which audits.

## 2. The rule (backend)

One function, `enforce_engagement_access` in `app/security.py`, replaces `enforce_engagement_ownership`
as the router-wide dependency on the public router:

```text
no engagement_id in the path / malformed id -> pass (handler validation decides)
admin                                       -> pass
engagement does not exist                   -> 404
method GET / HEAD / OPTIONS                 -> pass            (REQ-IAM-022)
caller is the owner                         -> pass
otherwise                                   -> 403 "only the owner of this engagement or an administrator can change it"
```

It runs during dependency resolution, before the request body is validated, so a refused change
neither writes nor even parses. `can_manage_engagement(user, eng)` is the same predicate for the
places that need the answer as data. Everything else follows:

| Place | Change |
|---|---|
| `GET /engagements` | every engagement joined with its owner; each carries `owner_name`, `owner_email`, `can_manage` |
| `GET/PATCH/POST activate, reassign` | the same three fields on the response (set per request, not stored) |
| `app/api/approvals.py` | decision refuses a non-owner with 403 before revealing state; the pending list stays the owner's (admin: all) |
| `app/api/portfolio.py` (`GET /findings`) | no owner scope; `mine=true` adds one; each item carries `engagement_owner` |
| `_check_no_active_scope_overlap` | names up to three conflicting engagements (title, owner name and email) |
| `POST /internal/benchmark/engagements` | owner = oldest active administrator; 409 without one |
| `Engagement.owner_user_id` | non-nullable in the model |

Not changed: the Scope Gateway, the internal worker API, admin routes, settings, sign-in, sessions,
the audit chain, and the live stream's own logic (it is read-only and only differs by being long-lived).

## 3. GUI design

- **Overview:** an **Owner** column (name, email below), an **Only mine** checkbox in the queue header
  that also drives the metric strip; **Edit** and **Delete** appear only when `can_manage`.
- **Engagement page:** a read-only notice (`ReadOnlyNotice`, names the owner) when `!can_manage`; Edit,
  activation, attestation, tool grants, Start run, Generate report and the tool-grants link are hidden;
  findings get `canManage` (triage and the Lens request are hidden, an existing explanation stays readable).
- **Edit page:** the notice and a link back instead of the form.
- **Run page:** Stop scan and the asset-review decision hidden; the notice, and for a paused review a line
  saying it waits for the owner.
- **Audit:** readable; the one-click override only when `can_manage`.
- **All findings:** an **Only my engagements** filter in the URL (`?mine=1`) and the owner under each engagement.

The flag defaults to "no" wherever it is unknown, and the server refuses a change whatever the console shows.

## 4. Risks and how they are handled

| Risk | Handling |
|---|---|
| A route is added without the rule | the rule is on the router, not the endpoint; a wiring test fails for a route that lacks it; a sweep test sends every changing route as a non-owner |
| A write hides behind a GET | the sweep and the rule treat only GET/HEAD/OPTIONS as reads; the review list of the frontend test names every file that sends a change |
| More data is exposed than intended | the decision is "everything of the engagement" (johannes, 2026-10-01); global settings, API keys and users are not part of an engagement and stay admin-only; user emails of owners become visible to every user, which the decision accepts |
| The migration guesses an owner | it never does: it uses the oldest active administrator or stops without changing anything |
| A role downgrade keeps a right | the rule reads the caller's role per request |

## 5. Requirement coverage

| Requirement | Where it is designed | Verified by |
|---|---|---|
| REQ-IAM-021 | section 1; benchmark and create rows of section 2 | [TC-IAM-021](../test-cases/engagement-visibility.md) |
| REQ-IAM-022 | the rule, list/portfolio rows of section 2 | [TC-IAM-022](../test-cases/engagement-visibility.md) |
| REQ-IAM-023 | the rule, approvals row of section 2 | [TC-IAM-023](../test-cases/engagement-visibility.md) |
| REQ-IAM-024 | overlap row of section 2 | [TC-IAM-024](../test-cases/engagement-visibility.md) |
| REQ-IAM-025 | section 3 | [TC-IAM-025](../test-cases/engagement-visibility.md) |

## 6. Rollout and rollback

Rollout (after the human security review): dev, then int, then prod (prod stays as it is until asked);
the migration runs with the control plane. On a database with legacy ownerless engagements the
oldest active administrator becomes their owner; reassign them if someone else should own them.
Rollback: revert the code; `ALTER TABLE engagement ALTER COLUMN owner_user_id DROP NOT NULL` if rows
must be ownerless again (old code treats them as admin-only). Adopted owners are not undone.
