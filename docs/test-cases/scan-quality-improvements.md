---
title: Scan quality improvements verification
status: ready
risk: R3
owner: security-engineering
---

# Scan Quality Improvements Verification

Verifies [`../requirements/scan-quality-improvements.md`](../requirements/scan-quality-improvements.md).
R3: the changes broaden active scanning; tests pin the exact invocations and
that intrusive categories stay excluded.

## TC-SCANQUAL-001: Discovery aggregates multiple fault-isolated OSINT sources

Requirements:

- REQ-SCANQUAL-001

Automated tests:

- `worker/tests/test_scan_quality.py`

Objective:

Verify discovery merges subdomains from crt.sh plus additional passive sources,
that one source failing never loses the others or breaks discovery, and that
each source parses and scopes correctly.

Expected results:

- `_passive_subdomains` returns the de-duplicated union of all sources.
- A source raising is caught; the remaining sources' results survive.
- The certspotter (JSON) and hackertarget (CSV) sources parse their responses,
  strip wildcards, and keep only names within the queried root; an HTTP error
  or a rate-limit message yields an empty set (best-effort).

## TC-SCANQUAL-002: nikto runs the broad non-intrusive tuning

Requirements:

- REQ-SCANQUAL-002

Automated tests:

- `worker/tests/test_scan_quality.py`

Objective:

Verify the nikto invocation requests tuning categories 1,2,3,b and never the
intrusive/destructive categories.

Expected results:

- The nikto `additional_args` contain `-Tuning 123b`.
- No intrusive category (4,5,6,7,8,9,0,a,c) is requested.

## TC-SCANQUAL-003: Web tools cover nmap-discovered ports

Requirements:

- REQ-SCANQUAL-003

Automated tests:

- `worker/tests/test_scan_quality.py`

Objective:

Verify web candidate-port selection and the run() wiring: a broad window
web-enumerates 443 plus nmap-identified web ports (bounded, 443 never dropped);
a configured single port pins every web tool to exactly that port.

Expected results:

- `_web_candidate_ports` returns 443 plus nmap web ports, capped, with 443
  always kept even when more than the cap of web ports are found.
- With a broad window and nmap finding a web service on 8080, `_web_suite` runs
  for 443 (None) and 8080.
- With a configured single port (4280), `_web_suite` runs only for 4280.

## TC-SCANQUAL-004: testssl runs vulnerability checks

Requirements:

- REQ-SCANQUAL-004

Automated tests:

- `worker/tests/test_scan_quality.py`

Objective:

Verify the testssl command runs its vulnerability section in addition to the
protocol/server-default hygiene checks and the severity filter.

Expected results:

- The command includes `--vulnerable` alongside `--protocols`,
  `--server-defaults`, and `--severity LOW`.

## TC-SCANQUAL-005: ffuf content discovery runs automatically in the fingerprint baseline

Requirements:

- REQ-SCANQUAL-005

Automated tests:

- `worker/tests/test_scan_quality.py`

Objective:

Verify ffuf now runs unconditionally once a live HTTP service is confirmed
(no agent decision required), is skipped on a dead host, aggregates its hits
into one Finding, and stays fail-open on a tool error.

Expected results:

- `_web_suite` calls ffuf with `{"wordlist": "quickhits"}` once `_http_probe`
  confirms a live service.
- No ffuf call is made when the host is not live.
- One or more parsed hits become exactly one `add_finding` call with
  `category="exposure"`, `confidence="inferred"`, and the hits listed in
  `evidence`.
- Zero hits produces no Finding.
- `tool_runner.run` raising for ffuf is logged and does not abort the rest of
  `_web_suite` (the other web tools still run).
