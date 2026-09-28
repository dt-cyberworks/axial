---
title: Browser hardening headers and no third-party requests from the console
status: implemented
risk: R3
owner: security-engineering
---

# Browser Hardening Headers and No Third-Party Requests

Context: the 2026-09-27 review found that the edge (Caddy) set no browser
security headers at all, while the console keeps its session token in
`sessionStorage`, where a successful XSS could read it. A Content Security
Policy is the main control limiting what an XSS could do. The same review
found the console loading its fonts from Google on every page load, which
sends each user's IP address to a third party (a German court held this
unlawful under the GDPR in 2022, LG München I, 3 O 17493/20) and would
have forced foreign origins into the CSP.

**Risk class: R3** (edge configuration of the public entrypoint). Needs
human security review and a live check after deployment.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-WEBSEC-001: Every response carries browser hardening headers

Acceptance criteria:

- Both edge configurations (`edge/Caddyfile`, and each site in
  `edge-shared/Caddyfile`) send on every response — the console's static
  files and the proxied API alike:
  - `Strict-Transport-Security: max-age=31536000`
  - `Content-Security-Policy` allowing only the console's own origin for
    scripts, styles, images (plus `data:` and `blob:`), fonts, and
    connections; no plugins; `base-uri`, `form-action` self;
    `frame-ancestors 'none'`
  - `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
    `Referrer-Policy: no-referrer`, and a `Permissions-Policy` that turns
    off camera, microphone, geolocation, payment, and USB
- [Negative test] The upstream's `Server` banner is removed, and the
  edge's values win over anything the upstream sends.
- The console works unchanged under this policy in a real browser (no CSP
  violations while logging in, browsing an engagement, triaging, and
  downloading a report).

## REQ-WEBSEC-002: The console makes no third-party requests

Acceptance criteria:

- The console's fonts (Inter, Space Grotesk; SIL Open Font License) are
  bundled into the build instead of loaded from Google Fonts.
- [Negative test] The built `index.html` and assets reference no external
  origin, and contain no inline script.
- The document declares its actual language (`lang="en"`).

## REQ-WEBSEC-003: Console pages and API data never share a cache entry

Found while verifying REQ-WEBSEC-001 in a real browser: console routes and
API routes share URLs (`/engagements/<id>`) and the edge tells them apart
only by the `Accept` header, but no response said so. After opening an
engagement by URL, the browser answered the console's own API request for
the same URL from the cached HTML page, and the engagement never loaded.
This affected production before the change.

Acceptance criteria:

- Responses on the shared prefixes (`/auth`, `/engagements`, `/approvals`,
  `/settings`, `/tools`, `/admin`, `/callback`), HTML and API alike, carry
  `Cache-Control: no-store` and `Vary: Accept` — API data such as findings
  is never stored in the browser cache.
- The console shell on all other paths carries `Cache-Control: no-cache`
  (always revalidated); content-hashed build assets under `/assets/` are
  cacheable for a year (`immutable`).
- [Negative test] Opening an engagement's URL directly, repeatedly, loads
  the engagement every time.

Security invariants:

- The CSP needs no `unsafe-inline` for scripts and no foreign origin; a
  future change that needs either must update this record first.
