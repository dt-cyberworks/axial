---
title: Scan coverage against a documented, self-labeled vulnerability set
status: implemented
risk: R2
owner: product-engineering
---

# Scan Coverage Against a Documented, Self-Labeled Vulnerability Set

Context: the user asked to compare a real scan's findings against a real,
publicly documented training target's own self-labeled vulnerability list -
`pentest-ground.com:4280`, which runs DVWA (Damn Vulnerable Web Application).
DVWA documents its own vulnerability categories directly in its UI: each of
its 15 modules has a page whose title names its vulnerability class (e.g.
"Vulnerability: Reflected Cross Site Scripting (XSS)") plus a "More
Information" section linking to the relevant OWASP reference. This is
read-only, published information - not something this project discovers by
testing, so comparing against it does not require actively exploiting the
target.

Of DVWA's 15 self-documented modules, the existing scan/agent pipeline
correctly found and reported 3 (Command Injection, File Inclusion, File
Upload) plus several bonus findings beyond DVWA's own module list (auth
disabled, config/DB-credential exposure, DB setup page exposed, source-code
disclosure, phpinfo exposure). Reflected XSS - independently confirmed live
and reachable on the target via read-only inspection, not by injecting a
payload from this project's own tooling - was not detected at all, despite
being one of DVWA's best-known modules.

**Root cause, and why it splits across several fixes (plus REQ-AGENT-015 in
`agent-budget-and-tool-call-tolerance.md`, found in the same investigation):**
nuclei is this project's deterministic, templated detector for exactly this
class of generic (non-CVE-specific) web vulnerability - it already runs on
every scan, but its baked-in `-tags` allowlist never included the generic
`dast` (xss/sqli/redirect/lfi/rfi/cmdi/ssrf/ssti/xxe/crlf) templates, so it
could never have caught this regardless of budget or agent behavior
(REQ-AGENT-016). A further subset of `dast` templates (DOM-XSS, CSP-Bypass)
additionally require a real browser (nuclei's `-headless` mode) and were
skipped entirely regardless of `-tags` until REQ-AGENT-018 added one. The
Vector Agent's own read-only structural reasoning is the right mechanism for
categories no generic template can express at all (CSRF token absence, stored
injection, weak session-ID entropy, an exposed CAPTCHA secret - each depends
on understanding a specific form/flow's purpose, not a generic signature) -
REQ-AGENT-017 and REQ-AGENT-019 extend its guidance for exactly those,
narrowly, rather than asking the agent to compensate for a templating gap by
manually replicating what a deterministic tool should catch instead.

**Explicit non-goal, not an oversight:** Brute Force and JavaScript-puzzle
challenges. Brute Force needs repeated failed-auth attempts, which this
project's non-destructive philosophy already excludes outright (stated
explicitly in the default agent prompt). JavaScript challenges are bespoke
client-side logic that varies per application - there is no generalizable,
non-target-specific signature or heuristic worth writing for it. Every other
gap found in this investigation (SQLi/blind SQLi, XSS in all three forms,
CSRF, Weak Session IDs, Insecure CAPTCHA, Open Redirect, CSP Bypass) is now
addressed by REQ-AGENT-016/017/018/019 below, deliberately designed to be
generic - none of it is tuned to DVWA or `pentest-ground.com` specifically;
every fix is a capability that fires on any target with the matching shape
(a form without a CSRF token, a session cookie that never rotates, a
templated injection class nuclei already knows generically, and so on).

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-AGENT-016: nuclei's deterministic templates cover generic injection classes

nuclei must run its baked-in `dast/vulnerabilities/*` generic templates
(reflected/DOM XSS, SQLi including blind/time-based, open redirect, LFI/RFI,
command injection, SSRF, SSTI, XXE, CRLF) - the modern, product-agnostic
detection suite designed for exactly this class of vulnerability, as opposed
to the CVE- or product-specific templates already covered by the existing
`cve` tag.

Acceptance criteria:
- nuclei's `-tags` allowlist includes `dast` in addition to the existing
  `cve,misconfig,exposure,exposures,default-login,waf`.
- `dast`-tagged templates are not tagged `fuzz`/`intrusive`/`dos` (verified,
  not assumed) - the existing safety exclusion is unaffected and does not
  need to change to accommodate this.
- The existing conservative invocation (rate-limit, timeout, retries, egress
  proxy, non-intrusive-only) is otherwise unchanged.

## REQ-AGENT-018: nuclei runs a headless DOM-XSS pass, split from the main pass to fit the executor's hard timeout

DOM-based XSS has no plain-HTTP generic template - proving it requires
executing the page's own JavaScript, which needs a real browser. Without
nuclei's `-headless` flag, any headless-flow template is silently never
executed at all, regardless of which `-tags` are set - this is a second,
independent reason this category was never findable, separate from the
`-tags` gap REQ-AGENT-016 closed.

**Why it must be a SEPARATE nuclei pass (found live, not by reasoning):**
the tool runner (HexStrike) hard-kills every single command at 300s
(`COMMAND_TIMEOUT`, not overridable per call via the API the worker uses -
verified in its source). A first attempt combined the full tag set and
`-headless` into one nuclei invocation; against the real, egress-proxied
training target it exceeded 300s and was killed (`nonzero_exit`, only the
early fast templates' findings captured), whereas the identical non-headless
command had completed cleanly 5/5 on that same target before. Crucially, that
run's DOM-XSS finding came from the Vector Agent's own reasoning, not the
headless template - so the combined call had negative net value: it broke the
deterministic nuclei pass and added nothing. The fix is to split nuclei into
two invocations, each safely under the 300s cap: a fast non-headless **main
pass** (the full tag set, REQ-AGENT-016) and a tiny separate **headless pass**
(`-headless -tags domxss`, one generic template). Measured in isolation: the
headless pass ~10s, the main pass well under the cap as before. Raising a
`max_runtime_seconds` in the control-plane registry was also proven useless -
it is a secondary limit above HexStrike's own 300s, which fires first.

**Scope of the headless pass, and why it is narrow (measured, not assumed):**
DOM-XSS templates do not carry the `dast` tag - only `headless`/`xss`/
`domxss`. The `domxss` tag matches exactly one generic, product-agnostic
DOM-XSS template (`headless/window-name-domxss.yaml`) plus one specific HTTP
CVE template - two total, ~10s. The broader `headless` tag was rejected: it
would include, among other things, a DVWA-specific template nuclei itself
ships, which this document's own non-goal is to avoid depending on. The
`csp-bypass` bucket (~192 templates, also headless-only) stays excluded on
measured cost grounds: nuclei's entire dedicated `headless/` directory (24
templates) took ~530s against one fast target with headless-concurrency 2
(Chrome waits out most of its `-page-timeout` on a non-match) - wildly
disproportionate for a generic ASM baseline.

Acceptance criteria:
- The tool-runner image includes a real browser (Chromium) - an explicit,
  deliberate, narrow exception to this image's own stated "only the
  allowlisted tools" minimalism, approved by the security owner given the
  real, generic capability gain (DOM-XSS becomes detectable on any target).
- nuclei runs as two separate invocations (main non-headless + headless
  `domxss`), each a distinct sub-300s command; the deterministic fingerprint
  phase dispatches both, an agent-proposed nuclei call gets the fast main pass.
- The headless pass uses the precise `domxss` tag - not the broad `headless`
  or `xss` tags, which would each pull in far more than intended.
- `csp-bypass` remains excluded via the main pass's `-etags`, on measured
  cost grounds.
- The headless pass runs with `-headless -system-chrome` (uses the image's own
  installed browser; never attempts a runtime download - the isolated
  runtime image has no internet access) and `-headless-options "--no-sandbox"`
  (Chrome's own internal sandbox needs capabilities the container deliberately
  does not grant - `cap_drop: ALL` - so the container's own isolation
  (non-root, read-only rootfs, capability drop, egress-proxy-only network)
  substitutes for it instead; this trade-off is recorded here, not hidden).
- Headless concurrency (`-headless-bulk-size`, `-headless-concurrency`) is
  capped well below nuclei's own default (10/10) to fit the actual deployed
  host's resources (a small 2 vCPU/1.8GB VPS cannot run many concurrent
  Chrome processes) - not a security control, an operational one.
- Both passes reliably complete within the tool runner's hard 300s per-command
  timeout (verified by a real scan showing both nuclei executions succeed,
  no `nonzero_exit`), rather than relying on a control-plane budget that the
  runner's own cap overrides anyway.

## REQ-AGENT-019: The agent covers stored injection, weak session IDs, and exposed challenge secrets - generically

These three categories have no generic nuclei template (each depends on
understanding a specific form/flow's purpose or requires multiple samples
over time) but are non-destructively provable by an agent that reasons about
the observed page/flow shape - the same way REQ-AGENT-017 already does for
CSRF. None of this is worded in terms of any specific target or application;
it must read as generic guidance that fires whenever ANY in-scope host has
the matching shape.

Acceptance criteria:
- Stored injection: the prompt instructs proposing at most one
  state-changing request (already gated by existing operator-approval
  machinery) using an inert, unique marker string - never a live script
  payload - when a form's data appears to persist and be redisplayed
  elsewhere, then verifying via a read-only follow-up whether the marker
  survives unescaped.
- Weak session IDs: the prompt instructs requesting the same page multiple
  times without authenticating and comparing the issued session-identifier
  values for non-rotation, low entropy, or an obvious sequential pattern -
  explicitly never guessing, reusing, or hijacking a real session.
- Exposed challenge secrets (e.g. CAPTCHA): the prompt instructs a read-only
  check for whether a challenge's expected answer or validation token is
  visible in the page source, a hidden field, or client-side JS - regardless
  of which specific challenge product is in use.

## REQ-AGENT-017: The agent checks for CSRF via a non-destructive structural signal

CSRF cannot be expressed as a generic nuclei template (it depends on
understanding which form performs a state-changing action), but proving it
non-destructively does not require performing that action - the absence of an
anti-CSRF token on a state-changing form, observed via a single read-only
page fetch, is sufficient evidence.

Acceptance criteria:
- The default agent prompt explicitly instructs: fetch a state-changing form
  page with a read-only `http_request` (GET), and if the returned HTML has no
  hidden anti-CSRF token field (`csrf`, `_token`, `authenticity_token`, nonce,
  or similar) for an action that would otherwise execute via a simple
  cross-site request, report it.
- The prompt explicitly forbids submitting the form to "prove" impact -
  reading the page is sufficient and keeps the check non-destructive.

**Live-verified (2026-07-29):** a real scan against `pentest-ground.com`
(DVWA, security level low) after deploying both fixes recorded, among
others: "Reflected XSS Without Authentication — Unencoded Input in HTML
Output" (medium, validated) and "CSRF — Password Change via GET Without
Anti-CSRF Token" (medium, validated) - neither had ever been found in three
prior scans against the same target before these fixes. A bonus find from
the same run, "Verbose PHP Error Messages — Internal Paths and SQL Query
Disclosure" (low, validated), independently covers the SQL Injection
module's currently-broken state (its backing database table is not
initialized on this instance) without this project's own tooling ever
submitting an injection payload. Pending johannes's review.

## REQ-AGENT-020: The agent tests all three XSS classes itself via http_request, no browser needed

Found by reviewing every tool call of a real scan (2026-07-29): XSS detection
was non-deterministic (one run found reflected + DOM XSS, the next found
neither) because the agent prompt deferred "structured injection detection" to
`nuclei` - but `nuclei` structurally cannot find it here: its injection
templates fire against a URL already handed to them WITH the vulnerable
parameter, and our invocation runs it against the bare base URL with no
parameter/endpoint discovery. The agent, by contrast, discovers endpoints
(via `content_discovery` and by reading pages), knows which parameters and
forms exist, and can craft targeted `http_request` (curl) probes against the
actual input surfaces. XSS detection therefore belongs to the agent, done
non-destructively via curl - no browser, no headless nuclei required for the
detection to work (the separately-kept headless `domxss` template from
REQ-AGENT-018 is a narrow `window.name`-sink complement, not the primary
mechanism).

Acceptance criteria:
- The default agent prompt no longer tells the agent to let `nuclei` do the
  structured injection detection; it explicitly makes the agent own XSS
  testing itself via `http_request`.
- Reflected XSS: the prompt instructs sending a read-only GET with an inert,
  unique marker containing XSS-significant characters (`<`, `>`, `"`, `'`) into
  a reflected parameter, then checking whether those characters return
  UNESCAPED in the HTML body - unescaped reflection is the proof, no browser
  or script execution.
- DOM-based XSS: the prompt instructs fetching the page and READING its
  client-side JavaScript for a source→sink flow with no encoding (e.g.
  `location`/`document.URL`/`window.name` into `document.write`/`.innerHTML`/
  `eval`), and states the structural pattern in the served JS is sufficient
  evidence - the agent never needs a real browser to fire an alert.
- Stored XSS: unchanged from REQ-AGENT-019's stored-injection guidance
  (approval-gated inert-marker persist-and-redisplay, never a live payload).
- All of it is worded generically - no reference to any specific target,
  parameter name, or application; it fires wherever an in-scope host has a
  reflected parameter, client-side JS, or a persist-and-redisplay surface.

Security invariants:
- Every reflected/DOM check is read-only (`http_request` GET); the only
  state-changing step (stored XSS marker submission) stays behind the existing
  operator-approval gate. No live/weaponized script payloads are ever sent -
  only inert markers whose only purpose is to observe escaping behavior.
