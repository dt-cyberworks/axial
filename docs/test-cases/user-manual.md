---
title: User manual verification
status: ready
risk: R2
owner: engineering
---

# User Manual Verification

Verifies [`../requirements/user-manual.md`](../requirements/user-manual.md).

## TC-MANUAL-001: The manual exists, is complete and reachable

Requirements:

- REQ-MANUAL-001

Automated tests:

- `scripts/tests/test_check_manual.py`

Objective:

Prove every required page exists with a title and audience lines, that `README.md` and `docs/README.md` link the
manual, and that each check also fails on the mistake it guards against.

Expected results:

- The real tree passes the structure check.
- A missing required page, a page without the audience lines and a README without the manual link are reported.
- The former in-app topics are mapped in `docs/design/user-manual-architecture.md`.

## TC-MANUAL-002: Every screen, code and tool is covered

Requirements:

- REQ-MANUAL-002

Automated tests:

- `scripts/tests/test_check_manual.py`

Objective:

Prove that adding a route, a readiness blocker, a gateway denial, a run or check reason, or an installed tool
without documenting it fails the check.

Expected results:

- A route in `App.tsx` that the screen reference does not mention is reported.
- A code that troubleshooting does not explain is reported.
- An installed tool missing from `tools.md` is reported; a tool that is not installed is not required.

## TC-MANUAL-003: The manual is checked for accuracy

Requirements:

- REQ-MANUAL-003

Automated tests:

- `scripts/tests/test_check_manual.py`

Objective:

Prove the links, anchors, public-export visibility, UI labels, privacy rules and image rules work and fail on
the mistake they exist for, and that the public export carries the manual.

Expected results:

- A dead link, a missing anchor, a link to a file the export drops, an unknown UI label, a private marker, an
  address outside the documentation ranges, a foreign email domain, a missing, unused or oversized image: each is
  reported.
- The marker file itself is on the export's deny list.
- A dry run of `scripts/publish_oss.py` includes `docs/manual/` and passes its own link check (run on the
  committed tree; recorded in the verification log of the change).

## TC-MANUAL-004: Screenshots are generated and show demo data only

Requirements:

- REQ-MANUAL-004

Automated tests:

- `control-plane/tests/integration/test_manual_demo_seed.py`
- `scripts/tests/test_check_manual.py`

Objective:

Prove the seeded data is demo-only and realistic (audit chain verifies, runs differ, every finding status), and
that the manual check rejects a missing, unused or oversized image.

Expected results:

- No private marker, no address outside the documentation ranges and no email outside the example domains in any
  seeded table.
- Every audit chain verifies; the two finished runs give new, resolved and persisting findings.
- The pending approval is not part of the seed.
- Live: `make manual-screenshots` builds and removes its own stack, writes every image and aborts on a leak
  (verified when an Account page showed a real session address, which the run refused to photograph).

## TC-MANUAL-005: The console carries no documentation pages

Requirements:

- REQ-MANUAL-005

Automated tests:

- `frontend/tests/user_manual_requirements.test.mjs`

Objective:

Prove the page, route, navigation link and styles are gone and the optional link is conditional, and that the
test fails when the page or an unconditional link comes back.

Expected results:

- `Documentation.tsx` does not exist; `/docs` is not a route; `/docs` shows **Page not found**.
- The **Manual** link is rendered only when `VITE_MANUAL_URL` is an http(s) address.
- The UAT golden path expects **Page not found** at `/docs`.

## TC-MANUAL-006: The process names the manual

Requirements:

- REQ-MANUAL-006

Automated tests:

- `scripts/tests/test_manual_process.py`

Objective:

Prove `AGENTS.md`, the Definition of Done, `CLAUDE.md`, the `Makefile` and the SDLC workflow send user-visible
changes to the manual and run the check, and that none names the removed page.

Expected results:

- Each file names `docs/manual/` and `make manual-check` where the process is described.
- `make verify` and the workflow run the check.
- No file names `Documentation.tsx` or the in-app documentation page.
