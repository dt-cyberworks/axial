---
title: Browser hardening headers verification
status: ready
risk: R3
owner: security-engineering
---

# Browser Hardening Headers Verification

Verifies [`../requirements/web-security-headers.md`](../requirements/web-security-headers.md).

## TC-WEBSEC-001: Headers on every response, from the real edge

Requirements:

- REQ-WEBSEC-001

Automated tests:

- `scripts/tests/test_edge_caddy_routing.py`

Objective:

Run the real Caddyfiles in Docker against a stub backend and prove every
header is present with the exact value, on static and proxied responses,
and that the backend's `Server` banner is stripped.

Expected results:

- `test_edge_caddyfile_sends_security_headers_on_spa_and_api` - single-environment edge.
- `test_edge_shared_caddyfile_sends_security_headers_for_both_environments` - both sites of the shared edge.
- Against the configuration before the change, both fail (no HSTS).
- A real-browser session under the policy logs no CSP violation (recorded in the change's QA notes).

## TC-WEBSEC-002: No third-party requests

Requirements:

- REQ-WEBSEC-002

Automated tests:

- `frontend/tests/web_security_requirements.test.mjs`

Objective:

Prove the console bundles its fonts and references no external origin.

Expected results:

- `index.html` has no Google Fonts link and declares `lang="en"`; `main.tsx` imports the bundled fonts.

## TC-WEBSEC-003: No cache collision between console and API

Requirements:

- REQ-WEBSEC-003

Automated tests:

- `scripts/tests/test_edge_caddy_routing.py`

Objective:

Prove each path class gets exactly the intended cache policy from the real
edge, so a cached console page can never answer an API request.

Expected results:

- `test_edge_caddyfile_cache_policy_keeps_console_and_api_apart` - `no-store` and `Vary: Accept` on a shared path for both Accept variants, `no-cache` on the shell, `immutable` on `/assets/`.
- Real-browser check: three direct loads of an engagement URL in a row all show the engagement (failed before the change).

