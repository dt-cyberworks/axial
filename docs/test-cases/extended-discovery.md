---
title: Extended discovery verification
status: ready
risk: R4
owner: security-engineering
---

# Extended Discovery Verification

Verifies [`../requirements/extended-discovery.md`](../requirements/extended-discovery.md).

## TC-COVER-003: Switches are enforced by the gateway (control plane)

Requirements:

- REQ-COVER-007

Automated tests:

- `control-plane/tests/integration/test_extended_discovery.py`

Objective:

Prove the four switches have the documented defaults, that a switch that is off
denies its tool with a distinct reason even when grants and approvals allow it,
that a switch on never lifts scope, that the pipeline-only tools are denied to
the agent, and that the switches can be edited at any status with an audit row.

Expected results:

- The default, switch-off, switch-never-overrides-scope, not-agent-callable and
  editable-while-active tests pass.

## TC-COVER-004: subfinder is passive, scoped and keeps its keys private (worker, control plane)

Requirements:

- REQ-COVER-001

Automated tests:

- `worker/tests/test_extended_discovery.py`
- `control-plane/tests/integration/test_extended_discovery.py`

Objective:

Prove subfinder names go through the scope filter with deny precedence and
suffix-only names dropped, that a switch off or a gateway denial runs nothing,
that keys go to a private temporary file and never to a command line, that a
timeout or missing binary never fails discovery, and that keys are stored
encrypted and never returned.

Expected results:

- The subfinder tests in both files pass, including the negative ones.

## TC-COVER-005: Crawling, URL history and the endpoint pass stay in scope (worker, control plane)

Requirements:

- REQ-COVER-003

Automated tests:

- `worker/tests/test_extended_discovery.py`
- `control-plane/tests/integration/test_extended_discovery.py`

Objective:

Prove the crawl and endpoint commands are bounded and proxied, every URL is
quoted, out-of-scope, denied, credentialed and non-http URLs are dropped before
storage and refused by the gateway, nothing runs with crawling off, a failed
store never fails a scan, and endpoints reach the agent as context.

Expected results:

- The katana, endpoints-pass, URL-history and store-endpoint tests pass.

Manual/live verification:

- Dev run against the UAT domain only: katana flags accepted by the installed
  version, nuclei `-dast` loads templates, endpoints stored.

## TC-COVER-006: The out-of-band pass uses only the platform's own server (worker, gateway, compose)

Requirements:

- REQ-COVER-004

Automated tests:

- `worker/tests/test_extended_discovery.py`
- `worker/tests/test_tool_runner_client.py`
- `raw-egress-gateway/tests/test_gateway.py`
- `scripts/tests/test_production_exposure.py`

Objective:

Prove the OOB command reads the token from the runner environment, refuses a
missing or malformed server, that the main and headless passes still disable
interactsh, that the gateway policy gains exactly one accept rule (or none when
unconfigured), and that the server is digest-pinned, read-only, isolated, only
DNS is published and only on loopback by default.

Expected results:

- The oob tests in those files pass.

Manual/live verification:

- Register and poll from the runner on the dev stack. A real callback needs a
  delegated domain and is recorded at deploy time or marked not possible.

## TC-COVER-007: Screenshots are stored and served safely (worker, control plane)

Requirements:

- REQ-COVER-006

Automated tests:

- `worker/tests/test_extended_discovery.py`
- `control-plane/tests/integration/test_extended_discovery.py`

Objective:

Prove the screenshot command is proxied and size checked, an empty result is an
honest failure, only PNGs within the size cap are stored, bug-bounty engagements
that need an identification header are denied, another engagement's or user's
screenshot is a 404, and the image response carries the safe headers.

Expected results:

- The screenshot tests pass.

## TC-COVER-008: The console shows and edits the switches (frontend)

Requirements:

- REQ-COVER-007
- REQ-COVER-003
- REQ-COVER-006

Automated tests:

- `frontend/tests/extended_discovery_requirements.test.mjs`

Objective:

Prove the wizard, the edit page and the engagement header expose all four
switches with descriptions and defaults, the edit page is not limited to draft,
and endpoints and screenshots are shown from same-origin URLs.

Expected results:

- All tests in the file pass and `tsc --noEmit` is clean.

Manual/live verification:

- Playwright smoke: create an engagement, toggle each switch, reload, check it
  persisted; view the Assets tab after a run.

## TC-COVER-009: Subfinder keys page never shows a key (frontend)

Requirements:

- REQ-COVER-001

Automated tests:

- `frontend/tests/extended_discovery_requirements.test.mjs`

Objective:

Prove the keys form uses password inputs, never renders a stored key and only
sends typed values.

Expected results:

- The subfinder keys test passes.
