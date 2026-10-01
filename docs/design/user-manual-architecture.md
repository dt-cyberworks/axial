# Architecture & GUI Design: User Manual in the Repository

Design spec for the requirements in
[`../requirements/user-manual.md`](../requirements/user-manual.md) (GitHub issue #50).
SDLC phases 2 (architecture) and 3 (GUI design). One row per requirement in section 8.

## 1. What changes, and what does not

| Area | Change |
|---|---|
| Data model, migrations, API, worker, Scope Gateway | **None.** Nothing here touches authorization or any stored data. |
| Console (`frontend/`) | The `Documentation` page, its `/docs` route, its navigation link and the styles only it used are removed. An optional **Manual** link appears only in a console built with `VITE_MANUAL_URL`. |
| Control plane (`control-plane/`) | A setting `CORS_ALLOWED_ORIGINS` (default `http://localhost:5173`, the previous hard-coded value) so the screenshot stack can serve the console from another port; plus a demo seed script (`control-plane/scripts/manual_demo_seed.py`) that is never run by the product. |
| Documentation | `docs/manual/` with its screenshots in `docs/manual/img/`, its checker and its tests. |
| Process | `AGENTS.md`, the Definition of Done, `CLAUDE.md`, the `Makefile` and the SDLC workflow name the manual. |

## 2. Layout of the manual

```text
docs/manual/
  README.md                 what Axial does and is not; where to start; conventions
  quickstart.md             install, first admin, sign in, first engagement, scan, report
  concepts.md               engagement, run, Scope Gateway, agents, findings, scoring, roles
  guides/                   one page per job (define, authorize, tools, run, tune, approve,
                            triage, compare, reports, users and MFA, LLM)
  reference/                one page per screen: overview, wizard, engagement, run detail,
                            audit, settings, account and admin; README has the address table
  tools.md                  every tool in plain language; command lines live in the catalog
  operations.md             what an operator of the installation does; links to INSTALL.md
  safety-legal-limits.md    what Axial will and will not do; legal duties; known limits
  troubleshooting.md        every readiness blocker, denial, run and check reason
  glossary.md
  img/                      generated screenshots (demo data only)
```

Conventions every page follows (and the checker enforces): a level-1 title, then **Who this is for** and
**After this page you can**; names on screen in bold exactly as the console shows them, listed per page in
`<!-- ui-labels: ... -->`; links only to files the public export keeps; no command lines for tools (link the
[tool catalog](../security/tool-catalog.md) instead); no restating of `INSTALL.md`.

## 3. Console changes (GUI design)

- `App.tsx`: remove the `Documentation` import, the `<NavLink to="/docs">` and `<Route path="/docs">`. `/docs`
  then matches the existing `*` route and shows **Page not found** (REQ-CONSOLE-009).
- `App.tsx`: `const MANUAL_URL` is read from `import.meta.env.VITE_MANUAL_URL` at build time and accepted only
  if it starts with `http://` or `https://`. When set, one `<a href target="_blank" rel="noopener noreferrer">Manual</a>`
  follows the **Admin** entry in the navigation. Without the variable nothing renders.
- `styles.css`: remove `.docs-layout`, `.docs-index`, `.docs-body`, `.docs-section`, `.docs-fields`.
- `uat/golden_path.py`: the former documentation step opens `/docs` and expects **Page not found**.
- Unrelated: the API's own interactive documentation (`/docs` on the API port, outside production) is untouched.

Inline help (field hints, tooltips, empty states, the explanations next to switches) stays in the console;
it is part of the UI, not documentation.

## 4. Checks (`scripts/check_manual.py`, standard library only)

| Check | What it catches |
|---|---|
| structure | a required page missing; a page without title, audience line or outcome line; a README that does not link the manual |
| links | a dead relative link or anchor (GitHub's slug rule); a manual link to a file the public export drops |
| routes | a console route (`App.tsx`) the screen reference does not mention |
| labels | a quoted UI label the console's source does not contain |
| codes | a readiness blocker, gateway denial, run reason or check reason not explained in troubleshooting |
| tools | an installed tool of the registry not described in `tools.md` |
| images | an image that is missing, unused, or larger than 1 MB |
| privacy | a private marker (`scripts/manual-private-markers.txt`, kept out of the public export), an address outside the documentation ranges, an email outside `example.com`/`.org`/`.net` |

`make manual-check` runs it; `make verify` and the SDLC workflow include it.

## 5. Screenshots (`scripts/manual_screenshots.py`, `make manual-screenshots`)

1. Build the control-plane image from the working tree under a unique name; create a new network, a PostgreSQL
   and a Redis container, all named `asm-manual-<id>`.
2. Apply every migration; run `control-plane/scripts/manual_demo_seed.py` in a container. It goes through the real
   models and the real audit writer, so screens render real data shapes and the audit chain verifies. Demo data:
   Example Corp on `example.com`, addresses in `203.0.113.0/24`, accounts on `example.com`; three engagements,
   two finished runs with a Plan, a Diff and agent steps, one running run, findings in every status, a Lens
   explanation, a DNS takeover candidate. The one pending approval is added only for its own screenshot because
   the console shows that popup on every page.
3. Start the control plane on `127.0.0.1:<free port>` with secrets generated for this run; build the console
   with `VITE_API_BASE_URL` for it (no `VITE_MANUAL_URL`) and serve it on another free port. CORS allows exactly
   that origin (`CORS_ALLOWED_ORIGINS`).
4. Sign in as the demo accounts in a real browser (system Chrome, TOTP), photograph each screen, and write
   `docs/manual/img/<name>.png`. The demo browser reports the client address `203.0.113.7` through
   `X-Forwarded-For` (which the control plane trusts from private peers, as behind the real edge), so the Account
   page lists a documentation address and no real one.
5. **Leak guard:** before each image, the text, titles, labels and input values of the page are checked with the
   same rule set as the pages (`private_content`). A hit aborts the run and writes no image.
6. Tear everything down (containers, network, image, temp directory), also on failure. `--keep` leaves the stack
   for inspection; `--only <name>...` regenerates single images.

The developer's own `asm_business-*` stack, its volumes and its ports are never used.

## 6. Risks and how they are handled

| Risk | Handling |
|---|---|
| The manual drifts from the product | `check_manual.py` fails on the drifts a machine can see (routes, labels, codes, tools, links); the Definition of Done makes the manual part of every user-visible change |
| Private data in a public manual or screenshot | one rule set, a leak guard before every image, a manual-wide scan, a marker file the public export omits |
| A screenshot stack touches real data | unique names, own network, own database, 127.0.0.1 only, generated secrets, teardown on every exit |
| A false statement in the safety chapter | R2 plus a named human review of `safety-legal-limits.md` and the safety parts of `concepts.md` before the next public export (pending, recorded in the requirement) |

## 7. Rollout and rollback

Rollout: merge; the next console build no longer contains the page. Nothing to migrate. Environments that bookmarked
`/docs` land on **Page not found**. Rollback: revert the commit; the page returns with its route and styles.

## 8. Requirement coverage

| Requirement | Where it is designed | Verified by |
|---|---|---|
| REQ-MANUAL-001 | sections 2 and 9; the entry-point links in `README.md` and `docs/README.md` | [TC-MANUAL-001](../test-cases/user-manual.md) |
| REQ-MANUAL-002 | sections 2 and 4 (routes, codes, tools); the guide list | [TC-MANUAL-002](../test-cases/user-manual.md) |
| REQ-MANUAL-003 | section 4 | [TC-MANUAL-003](../test-cases/user-manual.md) |
| REQ-MANUAL-004 | section 5 | [TC-MANUAL-004](../test-cases/user-manual.md) |
| REQ-MANUAL-005 | section 3 | [TC-MANUAL-005](../test-cases/user-manual.md) |
| REQ-MANUAL-006 | section 1 (process row) | [TC-MANUAL-006](../test-cases/user-manual.md) |

## 9. Migration of the former in-app page

The former page had ten sections and 84 topics. Each is covered in the manual; the table records where. The
mapping was verified once, when the page was removed, by searching the page named here for each topic's key
terms; the manual checks then keep the route, label, code and tool coverage current.

| Former section | Topics | Now in |
|---|---|---|
| Core concepts & safety model | Engagement; Scan run; Scope Gateway; Vector Agent; Lens Agent; Findings (fingerprint de-dup); Risk score & severity; Authenticated scanning; Confidence validated vs inferred | [concepts.md](../manual/concepts.md) |
| Tools the scanner uses | Passive discovery (crt.sh etc.); subfinder; katana; URL history; nuclei crawled + OOB; screenshot; nmap; httpx; wafw00f; testssl; nuclei; Security headers; ffuf; http_request; redis-probe; activemq-banner; activemq-openwire-probe | [tools.md](../manual/tools.md) |
| Overview (main page) | Metric strip; Status lifecycle; Authorized window; Row actions | [reference/overview.md](../manual/reference/overview.md) |
|  | Phone navigation | [reference/README.md](../manual/reference/README.md) |
| All findings | What it shows / paging; Status tabs; Filters in the address; Open a finding; Who sees what | [reference/overview.md](../manual/reference/overview.md) |
| Engagement detail | Authorization attest; Tabs; Start run readiness; Severity filter; Attack-surface graph; DNS & hosting / takeover; Discovery extras; Crawled endpoints / screenshots; Risk signal | [reference/engagement.md](../manual/reference/engagement.md) |
|  | Runs table + reasons; cancellation_status_unavailable; pipeline_error | [troubleshooting.md](../manual/troubleshooting.md) |
|  | Scan depth | [guides/tune-a-scan.md](../manual/guides/tune-a-scan.md) |
|  | Subdomain source keys | [reference/settings.md](../manual/reference/settings.md) |
|  | Triage; Triage regression reopen | [guides/triage-findings.md](../manual/guides/triage-findings.md) |
|  | Tool grants; Campaign tool overrides | [guides/control-which-tools-run.md](../manual/guides/control-which-tools-run.md) |
|  | Scope assets | [guides/define-an-engagement.md](../manual/guides/define-an-engagement.md) |
|  | Asset review pause | [reference/run-detail.md](../manual/reference/run-detail.md) |
| Run detail | Stop scan; Progress tab; Plan tab; Vector Agent tab; Activity tab; Asset review popup | [reference/run-detail.md](../manual/reference/run-detail.md) |
|  | Diff tab | [guides/compare-runs.md](../manual/guides/compare-runs.md) |
|  | Approval popup | [guides/approve-or-deny-a-tool-call.md](../manual/guides/approve-or-deny-a-tool-call.md) |
| New engagement wizard | Window step; Scope step; Tools step; Review / Authorize PDF; ?draft= resume | [reference/wizard.md](../manual/reference/wizard.md) |
| Agent settings | Provider | [guides/configure-the-llm.md](../manual/guides/configure-the-llm.md) |
|  | Scan rate policy; Tool policy; Vector Agent instructions; Iteration budget | [reference/settings.md](../manual/reference/settings.md) |
| Audit | One log; Search; Filters; Details & overrides | [reference/audit.md](../manual/reference/audit.md) |
| Accounts, login & MFA | Signing in; Account page; Engagement ownership; Admin: Account audit | [reference/account-and-admin.md](../manual/reference/account-and-admin.md) |
|  | First login; Admin: Users | [guides/users-and-mfa.md](../manual/guides/users-and-mfa.md) |

**Deliberately dropped, with the reason:**

| Dropped | Reason |
|---|---|
| The `REQ-...` identifiers cited inside field descriptions | Identifiers belong to the records; a reader of the manual needs the behavior, and the records stay one search away. |
| The exact command line and flags of each tool in the former tools section | The [tool catalog](../security/tool-catalog.md) is the single source for them; the manual links to the matching catalog entry so the two cannot drift. |
| The names of the three passive discovery sources in the former discovery text | They are listed in the tool catalog; the manual describes what they do. |
| The "Help" eyebrow, the section index and anchors of the former page | The manual's table of contents and Markdown headings do this job on GitHub. |
