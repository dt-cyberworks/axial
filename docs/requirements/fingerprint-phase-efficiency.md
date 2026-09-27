---
title: Fingerprint phase efficiency (DNS freshness, per-IP nmap, evidence-driven tool sequencing)
status: implemented
risk: R2
owner: security-engineering
---

# Fingerprint Phase Efficiency

Context: a real int scan (`019feaae-768d-7489-858a-0503c127b676`, engagement
`019feaac-73c7-7f97-aea4-462719075d89`, 7 hosts, 2026-08-10 07:58-09:00+)
exposed three independent problems in the fingerprint phase. All three are
visible in that run's own audit trail; none is hypothetical.

1. **nmap failed for 5 of 7 hosts** with `materialized_target_stale`, and the
   failure is deterministic, not flaky (REQ-FPEFF-001).
2. **The same IP was scanned repeatedly.** The 7 hostnames resolve to only 2
   distinct IPs; `example.org` and `cloud.example.org` (both
   `93.254.158.41`) each ran a full 1-65535 TCP scan and each reported the
   identical 5 services (REQ-FPEFF-002).
3. **Expensive tools ran against surfaces that could not repay them.** The
   web suite (nikto + testssl + nuclei + ffuf, ~7.5 min per host/port, of
   which nuclei alone is ~4m37s) ran in full against bare nginx catch-all
   vhosts answering `404`/`403`, and ran against port 443 even where nmap had
   already established the port set (REQ-FPEFF-003/004).

Roughly half of that ~62-minute run was spent on work that could not produce
a new finding.

**Risk class: R2.** This changes worker orchestration and what gets scanned,
so it carries a coverage risk and needs the negative tests below. It does not
touch the Scope Gateway, the egress boundary, authorization, or the audit
chain: every tool call still goes through `_propose()` → `authorize()` exactly
as before, and every skip is *fewer* calls, never a call that would previously
have been denied. Nothing here can widen scope.

**Coverage is the binding constraint, not speed.** Where a shortcut would
trade a possible finding for runtime, this document chooses coverage — see
REQ-FPEFF-004's explicit non-goal. Confirmed with the repository owner
(2026-08-10) rather than assumed, since it is a security-relevant judgment.

**Deployment note (learned the hard way, 2026-08-10):** deploying this change
by rsyncing only the services' `app/` trees took int's control-plane down.
The image is rebuilt from the *server's* `requirements.txt`, so syncing
application code that gained a new third-party dependency without syncing the
dependency file produces an image whose code imports a module the image does
not contain — a clean build followed by an `ImportError` crashloop. Sync
`requirements.txt` alongside `app/` whenever either might have changed.

## REQ-FPEFF-001: A host's DNS materialization is fresh when its own raw scan is authorized

Context: `fingerprint.run()` called `materialize_dns()` exactly once, before
the per-host loop. The raw-egress lease that authorizes nmap re-checks that
materialization's age per host at dispatch time against
`raw_egress_materialization_max_age_seconds` (900s) — a deliberate
anti-DNS-rebinding control that must stay. Because each host's tool suite
takes ~7.5 minutes, every host from roughly the third onward was dispatched
more than 900s after the single snapshot and was denied.

Observed in the run above: hosts at +2m41s and +10m09s succeeded; hosts at
+25m23s, +32m48s, +39m44s, +47m07s and +54m27s were all denied.

Acceptance criteria:

- A host's resolution is re-materialized immediately before that host's raw
  scan is authorized, so its age at authorization time is bounded by the work
  of a single host, not of the whole engagement.
- The freshness window itself is **unchanged**. This requirement fixes the
  producer of the snapshot, never the check that consumes it: raising or
  bypassing the window would weaken the rebinding control the check exists
  for.
- Re-materialization is the existing audited control-plane operation
  (`materialize_dns`); the worker never resolves DNS itself for this purpose.
- [Negative test] with a materialization older than the window, a raw lease is
  still denied — proving the freshness check remains enforced and this change
  did not defeat it.
- [Negative test] a re-materialization failure does not silently scan against
  a stale IP: the host's raw scan is skipped with a recorded reason.
- An engagement whose hosts complete quickly behaves exactly as before.

## REQ-FPEFF-002: One nmap scan per distinct network target per run

Context: nmap `-sS`/`-sU` operates on the resolved IP; the hostname used to
reach it does not change which ports are open. Scanning one IP once per
hostname multiplies the most expensive, most serialized operation in the
pipeline (raw egress is a single global FIFO lease, REQ-CONCUR-002) with no
new information.

Acceptance criteria:

- Within one scan run, a port scan is executed at most once per distinct
  `(resolved IP, effective port range, protocol)` key. Subsequent hostnames
  resolving to an already-scanned key reuse that result.
- The key includes the **effective port range**, not just the IP: per-target
  port scoping (REQ-PORTSCOPE-001) allows two hostnames on one IP to carry
  different authorized ranges, and a narrower earlier scan must never be
  reused to satisfy a wider later one.
- A reused result is recorded in the audit trail against the *reusing* host
  (so per-host evidence stays complete) and identifies the host whose scan
  produced it. Reuse is visible, never silent.
- Discovered services are attributed to every hostname that resolves to that
  IP, so no asset loses service inventory by virtue of being scanned second.
- [Negative test] two hostnames on the same IP with *different* effective port
  ranges each get their own scan.
- [Negative test] deduplication never crosses a scan-run boundary — a later
  run re-scans, since ports change over time.
- Web/L7 tools are explicitly **out of scope** for this deduplication; see
  REQ-FPEFF-004.

## REQ-FPEFF-003: Web ports come from scan evidence when it exists

Context: `_web_candidate_ports()` returned `[443] + <nmap web ports>`
unconditionally, so 443 was probed even when nmap had positively established
the open-port set and 443 was not in it.

Acceptance criteria:

- When a port scan succeeded for the target, the web-probe candidate list is
  derived from its open ports; a port that scan proved closed is not probed.
- When no scan result exists (denied, unavailable, or degraded), the previous
  behaviour is retained: probe 443 (plus any configured single port). Absence
  of evidence must not be read as evidence of absence — this is the
  fail-toward-coverage direction, and the run is already marked degraded by
  REQ-SCAN-014.
- An explicitly configured single port (REQ-FIDELITY-003/REQ-PORTSCOPE-004)
  continues to override both paths.
- The existing cap on additional web ports is retained.

## REQ-FPEFF-004: Deep tools run once per distinct web surface, never once per name

Context: virtual hosting means one IP serves different content per `Host:`
header — in the run above, `93.254.158.41` returned `404`, `403`, `302` and
`303` for four different names. Deduplicating web tools by IP would therefore
silently discard real, distinct attack surface. But the converse also
occurred: `example.org` and `mail.example.org` both returned an identical
bare nginx `404`, and each independently absorbed a full ~7.5-minute deep
suite for the same catch-all vhost.

Acceptance criteria:

- The expensive tools (`nikto`, `ffuf`, `nuclei`) run at most once per
  distinct web-surface fingerprint within a run, where the fingerprint is
  `(resolved IP, port, HTTP status, webserver, title, content length)`.
- Any difference in that fingerprint means both hosts are scanned in full.
  The comparison errs toward scanning: unknown or missing fields never
  collapse two surfaces together.
- A skipped host records the skip against itself, naming the host whose scan
  covered it, so the audit trail shows why a tool did not run.
- `httpx` (liveness/fingerprinting) and `testssl` (per-name certificate
  validity) always run per hostname and are never deduplicated — the
  certificate presented for one name says nothing about another, and the
  fingerprint itself is httpx's output.
- **Explicit non-goal:** a vhost is never skipped merely because its root
  returns `404`/`403`. Content discovery exists precisely to find paths that
  respond where the root does not, so "the root 404s" is not evidence that
  the surface is empty. Only *provably duplicated* work is skipped.
- [Negative test] two same-IP hosts whose responses differ in any single
  fingerprint field are both deep-scanned.
- [Negative test] a 404-root vhost with no duplicate is still deep-scanned in
  full, including ffuf.

## REQ-FPEFF-005: The web suite runs cheapest-and-most-informative first

Acceptance criteria:

- Within a live web port the order is: `httpx` (liveness, scheme, status,
  fingerprint) → `wafw00f` (~1s, and WAF presence is context for reading every
  later result) → `testssl` (only when TLS was confirmed) → `nikto` → `ffuf` →
  `nuclei` (by far the most expensive, ~4m37s observed, therefore last).
- Every existing gate is preserved: a port httpx did not confirm live still
  skips the whole suite, and `testssl` still skips a confirmed non-TLS port.
- Ordering changes execution sequence only. No tool is added or removed by
  this requirement, and a completed suite performs the same set of calls as
  before.

## REQ-FPEFF-006: A service is recorded once per (asset, port, protocol)

Context: nmap and httpx both call `add_service()` for the same port, so the
run above left `example.org` with three `:443` rows and
`cloud.example.org` with 9 service rows containing duplicates on both 80 and
443. This inflates the asset inventory in the customer report and the
attack-surface graph.

Acceptance criteria:

- Recording a service for an `(asset, port, protocol)` that already exists
  updates that row instead of inserting a second one.
- Later, richer information (httpx's status/title/tech) enriches the existing
  row rather than replacing it with a sparser one or duplicating it.
- [Negative test] recording the same port twice from two different tools
  yields exactly one row.

## REQ-FPEFF-007: A generic template must not duplicate a purpose-built tool

Context: found live 2026-08-10 while auditing what the fingerprint phase's
tool time actually bought. Two nuclei templates re-derive, less accurately,
what a dedicated tool in the same per-host suite has already established
seconds earlier:

* **`waf-detect`** — the template's matchers default to OR (it declares no
  `matchers-condition`), and one of its 96 matchers is `nginxgeneric`, whose
  regex is simply `(?i)nginx` against `part: response`. Any server emitting
  the string "nginx" — i.e. every stock nginx `Server:` header — therefore
  matches. Observed exactly that: all five nginx-backed hosts on
  `93.254.158.41` produced a "WAF Detection" finding while `wafw00f`, the
  purpose-built detector running against the same host in the same suite,
  correctly reported no WAF; neither Caddy-backed host matched. These are
  false positives reaching a customer-facing report.
* **`http-missing-security-headers`** — records `info`-severity
  "HTTP Missing Security Headers" for a host where `nikto` has already
  recorded the same fact at `low` severity *and named the specific missing
  headers*. The two carry different fingerprints, so the platform's own
  finding deduplication never collapses them: every affected host carried
  two rows for one fact (observed on all 8 hosts).

Note the asymmetry that decides which side to keep: in both cases the
purpose-built tool is both **more accurate** and **cheaper** (nikto ~24s vs
nuclei ~5min per host).

Acceptance criteria:

- Both templates are excluded from every nuclei invocation by template id
  (`-eid`), not by dropping a tag: `waf-detect` also carries `tech`, `misc`
  and `discovery`, and `http-missing-security-headers` carries `misconfig`,
  `headers`, `generic` and `vuln` — excluding by tag would remove large,
  unrelated parts of the template set.
- Exclusion is verified to remove exactly those two templates and nothing
  else (measured: 5974 -> 5972 selected).
- The capability itself is **not** lost: `wafw00f` continues to run per host
  for WAF detection, and `nikto` continues to report missing security
  headers with their specific names. This requirement removes a redundant,
  less accurate second opinion - never the only source of a signal.
- [Negative test] the exclusion names both ids explicitly, so adding a tag
  later cannot silently reintroduce either template.
- [Negative test] no other template id is excluded, so this cannot become a
  general-purpose "quieten nuclei" list without a further deliberate change.

Not in scope: this is a defect in an upstream community template, not in the
platform. It is handled by exclusion rather than by patching the vendored
template, so a template refresh (which is a full re-bake, see the deployment
note above) cannot silently restore it.

## REQ-FPEFF-008: nuclei never waits on out-of-band callbacks it cannot receive

Context: found live 2026-08-11 investigating why nuclei never flags
`CVE-2023-46604` (Apache ActiveMQ OpenWire RCE) against the benchmark VM's
deliberately-vulnerable container, despite a genuine, well-formed template
(`javascript/cves/2023/CVE-2023-46604.yaml`) existing for it. The template
requires an Interactsh out-of-band callback to confirm exploitation — it
registers a unique callback subdomain with a public `oast.*` server, embeds
it in the exploit payload, and waits to see whether the target calls back.
The tool-runner has **no internet egress by design** (isolated image, all
traffic forced through the egress proxy) — confirmed by the exact same
failure mode on nuclei's own routine version-check call to `api.pdtm.sh`.
Every Interactsh-dependent template (680 of the baked set, grepped directly)
therefore fails, deterministically, on every single run — but not quickly:
measured live, `CVE-2023-46604` alone spent 60-90s retrying registration
against all 6 public `oast.*` servers before giving up with "no results
found" — the same terminal outcome achievable in ~2ms.

Acceptance criteria:

- Every nuclei invocation passes `-no-interactsh`, in both the main and the
  headless pass.
- A template that depends on Interactsh completes near-instantly (millisecond
  order) instead of spending 60-90s per template retrying against unreachable
  OOB servers, with the same "no results" outcome either way.
- A template that mixes an OOB matcher with ordinary HTTP request/response
  matchers still executes its non-OOB requests normally — `-no-interactsh`
  degrades only the OOB-specific portion, verified live against a real
  mixed-matcher template (`CVE-2019-17558`): its full non-OOB HTTP request
  chain executed and reached a normal (correctly negative) conclusion in
  ~8s, not zero and not a hang.
- This is an efficiency fix, not a coverage change: templates that could
  never produce a usable result in this environment (no OOB receiver exists
  to confirm them) still cannot produce one — the fix removes wasted scan
  time, not any signal that was previously reachable.

Not in scope: actually confirming OOB-dependent CVEs (like `CVE-2023-46604`)
requires either a self-hosted callback receiver reachable from the target
or an in-band confirmation technique specific to that vulnerability class —
tracked separately as new agent-tool capability work, not a nuclei
configuration change.
