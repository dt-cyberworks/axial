---
title: Scan coverage against a documented vulnerability set verification
status: ready
risk: R2
owner: product-engineering
---

# Scan Coverage Against A Documented Vulnerability Set Verification

Verifies [`../requirements/scan-coverage-against-documented-vulnerabilities.md`](../requirements/scan-coverage-against-documented-vulnerabilities.md).

## TC-AGENT-016: nuclei includes the generic dast template tag

Requirements:

- REQ-AGENT-016

Automated tests:

- `worker/tests/test_nuclei_tags.py`

Objective:

Verify the nuclei invocation's `-tags` construction includes the generic
`dast` template set, without weakening the existing `intrusive`/`dos`/`fuzz`
safety exclusion.

Expected results:

- `_nuclei_body`'s `additional_args` includes `dast` on the `-tags`
  (inclusion) side.
- `intrusive`, `dos`, and `fuzz` are still present on the `-etags` side.

## TC-AGENT-018: nuclei runs as two sub-300s passes (fast main + tiny headless domxss)

Requirements:

- REQ-AGENT-018

Automated tests:

- `worker/tests/test_nuclei_tags.py`

Objective:

Verify nuclei is split into a fast non-headless main pass and a separate tiny
headless `domxss` pass (so neither exceeds the runner's hard 300s per-command
cap), that the headless pass is correctly sandboxed and resource-capped for
this container's isolation model, and that the deterministic fingerprint phase
dispatches both.

Expected results:

- The main pass (`args={}`) includes `dast` in `-tags`, is NOT headless
  (no `-headless`, no `domxss`), and still excludes `intrusive`, `dos`,
  `fuzz`, and `csp-bypass` via `-etags`.
- The headless pass (`args={"mode":"headless"}`) uses the precise `domxss`
  tag - not the broad `headless` tag or a bare `xss` tag - and includes
  `-headless`, `-system-chrome`, `--no-sandbox`, and caps `-hbs`/`-headc` to
  `2` (not the nuclei default of `10`).
- `fingerprint._nuclei_scan` dispatches nuclei twice, main then headless
  (`test_fingerprint_nuclei_scan_runs_main_then_headless`).
- Live confirmation: a real scan's audit log shows BOTH nuclei tool_execution
  rows succeeding (`success=true`, no `nonzero_exit`), unlike the pre-split
  combined call that got killed at 300s.

## TC-AGENT-019: The default agent prompt covers stored injection, weak session IDs, and exposed challenge secrets

Requirements:

- REQ-AGENT-019

Automated tests:

- `control-plane/tests/test_default_prompts.py`

Objective:

Confirm the default agent prompt's text covers all three categories via
non-destructive, generic (not target-specific) structural signals.

Expected results:

- The prompt instructs an inert-marker, approval-gated check for stored
  injection - never a live payload.
- The prompt instructs a multi-sample, read-only entropy/rotation check for
  session identifiers - never guessing, reusing, or hijacking a real one.
- The prompt instructs a read-only check for a challenge-response control's
  secret being exposed client-side, worded generically (not tied to any
  specific CAPTCHA product).

## TC-AGENT-017: The default agent prompt covers CSRF via a non-destructive structural check

Requirements:

- REQ-AGENT-017

Automated tests:

- `control-plane/tests/test_default_prompts.py`

Objective:

Confirm the default agent prompt's text explicitly covers CSRF detection via
a read-only structural signal (missing anti-CSRF token) and explicitly
forbids submitting the form to prove impact.

Expected results:

- `DEFAULT_AGENT_PROMPT` mentions CSRF, names the anti-CSRF token check, and
  contains an explicit instruction not to submit the form.

## TC-AGENT-020: The default agent prompt makes the agent test all three XSS classes via http_request

Requirements:

- REQ-AGENT-020

Automated tests:

- `control-plane/tests/test_default_prompts.py`

Objective:

Confirm the default agent prompt makes the agent own XSS detection via
`http_request` (curl, no browser), covering reflected, DOM-based, and stored
XSS non-destructively, and that it no longer defers structured injection
detection to `nuclei`.

Expected results:

- The prompt no longer contains "let `nuclei`'s injection-tagged templates do
  the structured detection", and does contain "YOU test this yourself".
- Reflected XSS: the prompt names a read-only marker-reflection check for
  unescaped special characters ("UNESCAPED", "no browser needed").
- DOM-based XSS: the prompt instructs reading the client-side JS for a
  source→sink flow (mentions `document.write`) and states the agent never
  needs a real browser.
- Stored XSS: the prompt keeps the approval-gated inert-marker guidance
  ("not a live script payload", "requires operator approval").
