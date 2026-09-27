---
title: The session check survives a transient network failure
status: implemented
risk: R2
owner: security-engineering
---

**Deployed to int 2026-08-10** (frontend-only change, static bundle rsynced
to `edge-shared/frontend-int`, no backend/container touched). Live-verified
on scan-int.example.org with Playwright: intercepted `/auth/me` and
aborted it 3× to reproduce the exact original failure mode (a request that
never gets a response) - the console now shows the "Can't reach the server"
error screen instead of a blank page, and clicking Retry with the network
healthy again recovers to the normal login screen. `tsc` and
`test:requirements` (18/18) both clean; `requirements-check` validates
186 requirements / 156 test cases.

# Auth Check Network Resilience

## REQ-IAM-012: A failed session check retries, then shows a recoverable error, instead of a permanently blank console

Context: found live 2026-08-10 on scan-int.example.org - an operator
loaded the console in Firefox and saw a fully blank page (just the `<html>`
shell, nothing rendered). The server side was healthy the whole time
(confirmed: `/`, the JS bundle, and the CSS all returned 200 with correct
content; a clean headless-Chrome load of the same URL rendered the login
screen normally). Reloading only the failed request in DevTools' Network
tab made the page load immediately, without changing anything server-side -
proving the failure was a one-off transient blip (extension interference,
a cold/failed connection, a brief network hiccup) on the initial
`GET /auth/me` call the console makes to resolve the signed-in user.

Root cause: `AuthenticatedShell` (`frontend/src/App.tsx`) only handled two
states - loading, and "no session" (which `api/client.ts`'s `request()`
already redirects to `/login` for, but *only* when the fetch actually
completes with an HTTP 401 response). A request that never reaches the
server - blocked by a browser extension, a failed connection, a network
blip - throws a `TypeError` before any response exists, so that redirect
branch never runs. `isLoading` becomes `false`, `me` stays `undefined`, and
the component's `if (!me) return null;` fallback (written assuming the
redirect was already in flight) renders nothing, forever, with no error
message and no way to recover short of a manual page reload.

**Risk class: R2** (a frontend resiliency/UX fix - no change to what a
session check authorizes or how a 401 is handled; only changes behavior for
requests that never reach the server at all).

Acceptance criteria:

- The `/auth/me` session check automatically retries a bounded number of
  times (2) with backoff when the failure is a network-level error
  (`TypeError`, i.e. the request never got a response), so most transient
  blips self-heal without operator action.
- The console never retries this way for a confirmed HTTP response
  (including a real 401, which is already redirecting to `/login` via the
  existing global handler) - only for the network-failure case, to avoid
  redundant work on a failure that a retry cannot fix differently.
- If the check is still failing after retries are exhausted, the console
  shows a visible error state (not a blank page) with the failure reason
  and a manual "Retry" button, using the same visual shell as the login
  screen (`AuthLayout`).
- [Regression test] a structural check on the retry predicate and the
  error-state rendering, matching this codebase's existing convention of
  source-level requirement tests for the operator console
  (`frontend/tests/*.test.mjs`).

Not fixed as part of this: the underlying cause of any *specific* transient
failure (e.g. a particular browser extension's interference) is outside the
application's control and isn't diagnosed or worked around here - this
makes the console resilient to that class of failure in general, rather
than chasing one browser's specific behavior.
