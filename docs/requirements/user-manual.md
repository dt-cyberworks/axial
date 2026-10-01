---
title: User manual in the repository
status: implemented
risk: R2
owner: engineering
---

# User Manual in the Repository

GitHub issue #50. The only user documentation was a console page,
`frontend/src/pages/Documentation.tsx` (route `/docs`): ten sections as long string
literals inside a TypeScript file. It could only be read in a running, configured
console; a text change was a code change, a frontend build and a deploy; it had no
search across pages, no screenshots or diagrams and no versioning per release; its tool
descriptions restated what `docs/security/tool-catalog.md` already records, so the two
drifted; and it was a per-screen field reference with no first ten minutes, no "how do
I" and no troubleshooting.

It is replaced by a manual in `docs/manual/`, in Markdown, reviewed like code and
shipped with the public export. The running software keeps no documentation pages of
its own.

**Decisions (johannes, 2026-10-01, on issue #50 and the proposed defaults):** the
in-app documentation page is replaced, not kept; inline help (field hints, tooltips,
empty states) stays, it is part of the UI; the console may link to the manual but
carries no content of it; the manual is Markdown on GitHub first, a searchable site is
a later and separately authorised step; and the in-app page is removed only after the
manual covers everything it covered, in the same change that proves it. REQ-DOC-001 is
**superseded** by this document.

**Risk class: R2.** Documentation, plus the removal of one read-only static route. No
change to authorization, the Scope Gateway, the data model or any API. One care point:
the safety, legal and limits chapter makes statements that operators and reviewers rely
on. **Review:** a human reads `docs/manual/safety-legal-limits.md` and the safety
passages of `docs/manual/concepts.md` before the next public export; that review is
pending and is not given by the author. On 2026-10-01 johannes
instructed the public release that contains this manual while the review was still open; the
review itself remains open and is not recorded as given.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-MANUAL-001: The user documentation is a manual in `docs/manual/`

Acceptance criteria:

- `docs/manual/` holds the manual in Markdown with these parts: a start page with a
  ten-minute quickstart; concepts; guides (one page per job); a screen reference (every
  screen, tab and field); tools in plain language; operations; safety, legal and
  limits; troubleshooting; and a glossary. The set of required pages is listed in
  `scripts/check_manual.py`.
- The manual is reachable from `README.md` and from `docs/README.md`.
- Every page begins with a level-1 heading and states who it is for and what the reader
  will be able to do afterwards.
- Every topic of the former in-app page is covered in the manual or deliberately
  dropped with a one-line reason; the mapping is recorded in
  `docs/design/user-manual-architecture.md`.
- Operations does not restate `INSTALL.md`: it links to it. The tools page does not
  restate command lines: it links to `docs/security/tool-catalog.md`, the single source
  for them.
- REQ-DOC-001 is marked superseded by this requirement, and every record that pointed
  at the in-app page points at the manual (or at the tool catalog) instead.

Security invariants: None. The manual describes behavior; it does not change it.

## REQ-MANUAL-002: The manual covers every screen, every operator-visible code and every tool

Acceptance criteria:

- Every route of the console (`frontend/src/App.tsx`) is mentioned in the screen
  reference, so adding a route without a manual entry fails the check.
- [Negative test] Every readiness blocker, every Scope Gateway denial reason, every run
  reason, and every check reason the console can show is explained in
  `docs/manual/troubleshooting.md`, with its meaning and what to do. A code added to
  the source and not explained fails the check.
- Every tool the scan can use is described in `docs/manual/tools.md`: what it does, why
  it is there, who starts it, and whether it needs approval.
- The guides cover, at least: defining an engagement and its scope (domain, IP, CIDR,
  port scoping, bug-bounty settings), authorizing and activating, controlling which
  tools run (grants, switches and approval, GitHub issue #48), starting and watching a
  run, tuning a scan, approving a tool call, triaging findings, comparing runs,
  reports, users and two-factor authentication, and configuring the AI provider.

Security invariants: None.

## REQ-MANUAL-003: The manual is checked for accuracy on every verification

Acceptance criteria:

- `make manual-check` (`scripts/check_manual.py`, standard library only) runs in
  `make verify` and in the SDLC workflow.
- [Negative test] Every relative link in `docs/`, `README.md` and `INSTALL.md` resolves
  to an existing file, and every anchor in a manual link resolves to a heading, using
  GitHub's rule for anchors. A dead link or a missing anchor fails the check.
- [Negative test] A link from the manual may only point at a file the public export
  keeps (`scripts/oss-public-paths.txt` minus `scripts/oss-public-paths.deny.txt`). In
  the exported tree, where those rules are absent, this part is skipped.
- [Negative test] A UI label quoted in the manual, listed on its page in
  `<!-- ui-labels: A | B -->`, must exist in the console's source; the screen reference,
  the guides and the quickstart must list theirs. A label the console does not have
  fails the check.
- [Negative test] The manual contains no private hostname, account or contact of the
  maintainers, no address outside the documentation ranges, and no email address outside
  `example.com`, `example.org` and `example.net`.
- [Negative test] An image a page references must exist, an image no page uses fails
  the check, and no image is larger than 1 MB.
- The checks have executable tests that also prove they fail on the mistake they exist
  to catch.
- A dry-run of `scripts/publish_oss.py` includes `docs/manual/` and passes its own link
  check.

Security invariants: None.

## REQ-MANUAL-004: Screenshots are generated, and show demo data only

Acceptance criteria:

- The screenshots in `docs/manual/img/` are produced by one documented command
  (`make manual-screenshots`, `scripts/manual_screenshots.py`) against a stack that the
  command builds itself from a throwaway database, a throwaway control plane and the
  console built from the working tree. It never touches the developer's own stack or
  data, and it tears everything down.
- The stack is seeded with demo data only: example hostnames (`example.com` and its
  subdomains), documentation address ranges, and demo accounts.
- [Negative test] Before each screenshot the page text is checked against a list of
  forbidden strings (the maintainers' hostnames, accounts and tooling); a match aborts
  the run without writing the image.
- The command is idempotent: running it again rewrites the same set of files, and
  `make manual-check` fails if a screenshot is missing, unused or too large.

Security invariants: the demo stack is local, uses generated secrets and is never
reachable from outside the host.

## REQ-MANUAL-005: The console carries no documentation pages

Acceptance criteria:

- `frontend/src/pages/Documentation.tsx`, its import, its route (`/docs`) and its
  navigation link are removed, together with the styles only it used. In the console,
  `/docs` shows the normal **Page not found** page. (The API's own interactive
  documentation at `/docs`, available outside production, is unrelated and unchanged.)
- The console shows a **Manual** link in its navigation only when it was built with
  `VITE_MANUAL_URL`; the link opens that address in a new tab. Without the variable
  there is no link.
- [Negative test] A frontend requirement test asserts that none of the removed pieces
  exists again and that the optional link is conditional.
- The UAT golden path no longer opens `/docs` for documentation; it checks that the
  address shows **Page not found**.

Security invariants: None. The link carries no credential and uses `rel="noopener noreferrer"`.

## REQ-MANUAL-006: The process names the manual

Acceptance criteria:

- `CLAUDE.md` (SDLC step 6), `AGENTS.md` (documentation touchpoints) and the Definition
  of Done say that a change to user-visible behavior updates the matching page of
  `docs/manual/` and that `make manual-check` passes. None of them names the in-app
  documentation page.
- [Negative test] A test asserts this for the public files (`AGENTS.md`, the Definition
  of Done, the `Makefile` and the SDLC workflow).

Security invariants: None.
