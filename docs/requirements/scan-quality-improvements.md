---
title: Scan quality improvements (discovery breadth, tool coverage)
status: verified
risk: R3
owner: security-engineering
---

# Scan Quality Improvements

A review of how the deterministic discovery and fingerprint phases invoke their
tools (`worker/app/tasks/discovery.py`, `fingerprint.py`,
`tool_runner_client.py`) surfaced four coverage gaps. The tool invocations are
deliberately centralized in the worker body-builders (the "closed args
round-trip" - neither the caller nor the LLM can inject flags), which is the
right pattern and is preserved. Within that pattern, four invocations leave
value on the table.

**Risk class: R3** (changes to the active scanning behavior and, for discovery,
the OSINT sources the worker contacts). All changes stay within the platform's
non-destructive posture: no injection/DoS/command-execution/SQLi tests are
added; only read-only checks and passive OSINT. Per the SDLC this cannot be
self-approved and needs human security review.

**Security review:** approved by johannes (project/security owner) on
2026-07-28, after review of `worker/tests/test_scan_quality.py` (pinned
invocations, intrusive categories excluded) and live verification of the passive
OSINT sources and the nikto tuning behavior from the deployed worker.

**Security review (REQ-SCANQUAL-005):** approved by johannes on 2026-08-07,
after live verification from the deployed worker that ffuf now runs
automatically once a live HTTP service is confirmed, is skipped on a dead
host, and reports its hits as a single `inferred`-confidence finding. Same
non-destructive posture: no new tool, registry, gateway or `args_safety`
change - only the caller (fingerprint baseline instead of agent-optional).

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-SCANQUAL-001: Discovery uses multiple passive OSINT sources

Context: discovery enumerates subdomains only from crt.sh, which the code itself
calls "notoriously unreliable". subfinder/amass are installed in the runner
image but are unreachable for OSINT there (the runner egress is scope-locked to
in-scope targets, so third-party OSINT sources are blocked) and are never
dispatched - dead code. Passive OSINT belongs in the worker's egress path (like
crt.sh), in Python, keeping the "worker runs no offensive tool binaries"
boundary intact.

Acceptance criteria:

- Discovery aggregates subdomains from crt.sh **plus** at least two additional
  free, key-less passive OSINT sources (no target contact), merged and
  de-duplicated.
- Every source is best-effort and independently fault-isolated: any one source
  failing (timeout, error, malformed response) never fails discovery or drops
  the other sources' results.
- Only names within an in-scope root are kept, and deny precedence still
  applies, exactly as today - the extra sources broaden input, never scope.
- No offensive tool binary is added to the worker image; the additions are
  plain Python HTTP queries on the existing OSINT egress path.

## REQ-SCANQUAL-002: nikto covers non-intrusive misconfiguration and info-disclosure

> **Superseded by REQ-PIPE-013 (johannes, 2026-09-29, decision D2).** The
> automatic scan pipeline no longer runs nikto: it always stopped at its 40 s
> budget and its useful checks overlap nuclei's generic templates. Missing
> security headers now come from the response headers httpx records. nikto
> stays available on demand to the agent. The criteria below describe the
> retired behaviour and are kept for history; their test was replaced by
> `worker/tests/test_scan_pipeline_v2.py` (TC-PIPE-013).

Context: nikto ran with `-Tuning b` (software identification only). The missing
-security-header findings the parser consumes DO still surface under `b` (they
come from nikto's baseline header analysis - verified empirically), so this is
not a correctness bug; but `b` omits the non-intrusive Misconfiguration (2) and
Information Disclosure (3) categories that are exactly the ASM-relevant checks
(exposed default/backup files, info leaks).

Acceptance criteria:

- nikto is invoked with the non-intrusive tuning categories relevant to ASM:
  interesting files (1), misconfiguration (2), information disclosure (3), and
  software identification (b) - i.e. `-Tuning 123b`.
- The intrusive/destructive categories remain excluded: injection (4), denial
  of service (6), remote file retrieval (5,7), command execution (8), SQL
  injection (9), file upload (0), authentication bypass (a), remote source
  inclusion (c).
- Runtime stays bounded (`-maxtime`), and all traffic still goes through the
  scope-enforcing egress proxy.

## REQ-SCANQUAL-003: Web tools cover nmap-discovered HTTP ports, not only 443

Context: when the engagement authorizes a single non-standard port, all web
tools correctly target that port (REQ-FIDELITY-003). But for a broad port
window, the web tools (httpx/nikto/wafw00f/testssl/nuclei) only ever hit port
443, so a host serving HTTP on a port nmap discovered (e.g. 8080, 8443) is never
web-enumerated.

Acceptance criteria:

- When the engagement authorizes a single non-default port, behavior is
  unchanged: every web tool targets that one port (REQ-FIDELITY-003 preserved).
- When the port window is broad and nmap discovers HTTP/TLS services on
  additional ports, the web tools are also run against those ports (plus the
  standard 443), bounded to a small cap to keep runtime and cost sane, and only
  on ports the engagement authorizes (the egress proxy still enforces the port
  window).
- A host with no live HTTP service is still skipped (the dead-host optimization
  is preserved per candidate port).

## REQ-SCANQUAL-004: testssl runs the non-destructive vulnerability checks

Context: testssl ran `--protocols --server-defaults` only - protocol and
certificate hygiene - so its (non-destructive) vulnerability probes (Heartbleed,
ROBOT, CCS, BEAST, etc.) never ran, missing well-known, high-value TLS findings.

Acceptance criteria:

- The testssl invocation additionally runs its vulnerability test section
  (`--vulnerable`), keeping the existing protocol/server-default checks and the
  `--severity LOW` output filter.
- These checks are diagnostic and non-destructive (crafted handshakes, read
  responses; no exploitation), consistent with the platform posture.
- The existing testssl JSON parser consumes the additional findings unchanged
  (they carry the same id/severity shape).

## REQ-SCANQUAL-005: ffuf content discovery runs in the automatic fingerprint baseline

Context: `ffuf` (`control-plane/app/tools/registry.py`) is a fully-built,
already-approved, non-destructive content-discovery tool with a working
parser (`worker/app/ffuf_parse.py`), but unlike httpx/nikto/wafw00f/testssl/
nuclei it only ever runs if the agent decides to call it mid-loop - it is
never part of the deterministic Phase 2 fingerprint baseline. On a real
target this means hidden-but-unlinked paths (backups, exposed `.git`,
default admin panels) are found only if the LLM happens to think to look,
not as a matter of course the way nikto's header check or nuclei's baseline
templates already are.

Acceptance criteria:

- Once httpx confirms a live HTTP(S) service for a host/port (the same gate
  `_web_enum`/`_waf_detect`/`_tls_scan`/`_nuclei_scan` already use), ffuf runs
  automatically with the `quickhits` wordlist - no agent decision required.
- A dead (not-live) host never gets an automatic ffuf call, same as the
  other four web tools.
- Runtime stays bounded by the tool's existing `max_runtime_seconds` cap and
  `-maxtime`; no new registry, gateway, or `args_safety` change - this reuses
  the existing tool call shape unchanged, only the caller (fingerprint phase
  instead of agent-optional) is new.
- Traffic still goes through the scope-enforcing egress proxy; an
  out-of-scope host cannot receive an automatic ffuf call.
- Discovered paths are aggregated into a single Finding per host
  (`confidence="inferred"`, `category="exposure"`) so the agent sees them
  in its starting evidence the same way it already sees nikto/testssl
  findings - judging whether a hit matters remains the agent's job, not the
  worker's (this tool never asserts a confirmed vulnerability itself).
- Zero hits produces no Finding (mirrors nikto's empty-result behavior).
