---
title: Fingerprint phase efficiency verification
status: ready
risk: R2
owner: security-engineering
---

# Fingerprint Phase Efficiency Verification

Verifies [`../requirements/fingerprint-phase-efficiency.md`](../requirements/fingerprint-phase-efficiency.md).
The load-bearing tests here are the negative ones: every requirement in that
document makes the scanner do *less*, so each needs a test proving it does not
do less than it should.

## TC-FPEFF-001: A host's DNS materialization is fresh at its own authorization

Requirements:

- REQ-FPEFF-001

Automated tests:

- `worker/tests/test_fingerprint_efficiency.py`
- `control-plane/tests/integration/test_raw_egress_lease.py`

Objective:

Prove the snapshot is produced per host rather than once per run, and that the
freshness check which the original defect exposed is still enforced.

Expected results:

- Each host triggers its own re-materialization before its raw scan is
  authorized, so N hosts produce N materializations rather than one.
- **Negative:** a materialization older than the configured window still
  produces a denied lease (`materialized_target_stale`) — the fix must not
  have widened or bypassed the window.
- **Negative:** when re-materialization fails, the host's raw scan is skipped
  with a recorded reason rather than proceeding against a stale IP.
- The configured window value is unchanged from before the fix.

## TC-FPEFF-002: One port scan per distinct network target per run

Requirements:

- REQ-FPEFF-002

Automated tests:

- `worker/tests/test_fingerprint_efficiency.py`

Objective:

Verify the deduplication key is correct in both directions — that it collapses
genuinely identical work and refuses to collapse anything else.

Expected results:

- Five hostnames resolving to one IP with one shared port range produce
  exactly one executed port scan.
- Every one of those hostnames still receives the discovered services, so no
  asset loses inventory by being scanned second.
- The reuse is recorded per reusing host and names the host whose scan
  produced the result.
- **Negative:** two hostnames on the same IP with *different* effective port
  ranges produce two scans.
- **Negative:** two hostnames on *different* IPs produce two scans.
- **Negative:** the cache is per run — a second run re-scans the same IP.

## TC-FPEFF-003: Web ports follow scan evidence, and its absence

Requirements:

- REQ-FPEFF-003

Automated tests:

- `worker/tests/test_fingerprint_efficiency.py`

Objective:

Confirm the candidate list follows real scan evidence when it exists, and
falls back to probing 443 when it does not - so the change never converts a
missing scan into a silently unprobed host.

Expected results:

- With a successful scan whose open ports exclude 443, 443 is not probed.
- With a successful scan whose open ports include 443 plus a web port, both
  are probed, subject to the existing cap.
- **Negative:** with no scan result at all (denied/unavailable), 443 is still
  probed — absence of evidence must not be treated as evidence of absence.
- A configured single port still overrides both paths.

## TC-FPEFF-004: Deep tools deduplicate by web surface, not by host or IP

Requirements:

- REQ-FPEFF-004

Automated tests:

- `worker/tests/test_fingerprint_efficiency.py`

Objective:

This is the requirement with real coverage risk, so the negative cases matter
more than the positive one.

Expected results:

- Two hosts on one IP returning an identical fingerprint run the deep tools
  once; the second records a skip naming the first.
- **Negative:** hosts differing in *any single* fingerprint field (status,
  webserver, title, content length) are both deep-scanned — asserted field by
  field, not just in aggregate.
- **Negative:** a `404`-root vhost with no duplicate is deep-scanned in full,
  including `ffuf`. A 404 root is never itself a reason to skip.
- **Negative:** a missing/unknown fingerprint field never collapses two hosts
  together.
- `httpx` and `testssl` run for every hostname regardless of duplication.

## TC-FPEFF-005: Web suite ordering

Requirements:

- REQ-FPEFF-005

Automated tests:

- `worker/tests/test_fingerprint_efficiency.py`

Objective:

Verify the reorder changes sequence only - the same tools still run, and every
pre-existing gate still fires.

Expected results:

- Observed call order for a live port is httpx → wafw00f → testssl → nikto →
  ffuf → nuclei.
- A port httpx did not confirm live still runs no further tools.
- A confirmed non-TLS port still skips testssl.
- The set of tools called for a fully live TLS port is unchanged from before
  the reordering.

## TC-FPEFF-006: Services are not duplicated

Requirements:

- REQ-FPEFF-006

Automated tests:

- `control-plane/tests/integration/test_service_dedup.py`

Objective:

Verify the upsert collapses exactly the duplicates observed live (nmap and
httpx reporting one port) without merging genuinely distinct services.

Expected results:

- Recording the same `(asset, port, protocol)` twice yields one row.
- The second record enriches the first (status/title/tech present) rather than
  blanking fields or inserting a duplicate.
- Different ports, or different protocols on one port, remain distinct rows.

## TC-FPEFF-007: Redundant templates are excluded, and only those

Requirements:

- REQ-FPEFF-007

Automated tests:

- `worker/tests/test_nuclei_tags.py`

Objective:

Verify the two templates that duplicate a purpose-built tool are excluded
from every nuclei invocation, that the exclusion is by id rather than by tag,
and that the mechanism cannot quietly grow into a general coverage reduction.

Expected results:

- Both `waf-detect` and `http-missing-security-headers` are excluded by
  `-eid` in the main pass **and** the headless pass.
- **Negative:** the exclusion list contains exactly those two ids — a new
  entry requires a deliberate change, since each must be justified by a tool
  in the same per-host suite that owns the signal.
- **Negative:** the `waf` and `misconfig` tags are still requested, proving
  the exclusion did not remove the tags those templates happen to share and
  so did not drop unrelated templates.
- Measured against the real template set: the selection drops from 5974 to
  5972, i.e. exactly two templates and no collateral.

## TC-FPEFF-008: nuclei does not wait on unreachable OOB callbacks

Requirements:

- REQ-FPEFF-008

Automated tests:

- `worker/tests/test_nuclei_tags.py`

Objective:

Verify every nuclei invocation disables Interactsh, and that doing so only
degrades the OOB-specific portion of a template rather than breaking its
ordinary HTTP request/response matchers.

Expected results:

- `-no-interactsh` is present in both the main pass and the headless pass.
- Live-verified (not just flag presence): `javascript/cves/2023/CVE-2023-46604.yaml`
  against a real target went from 60-90s (retrying registration against 6
  public `oast.*` servers) to ~2ms with the flag set, both ending in the same
  "no results found" outcome.
- Live-verified: a mixed-matcher template (`CVE-2019-17558`, one OOB matcher
  + two ordinary ones) still executed its full non-OOB HTTP request chain
  and reached a normal conclusion in ~8s (bounded by the request timeout,
  not a hang) — `-no-interactsh` does not silently kill matchers that don't
  need it.
- No new `network_request` audit entries are generated by a template whose
  OOB precondition fails before any connection is attempted — confirms this
  failure mode carries no scope-bypass risk (nothing is sent to the target
  at all in that case).
