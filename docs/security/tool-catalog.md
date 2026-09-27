---
title: Tool catalog and static invocation reference
status: implemented
risk: R1
owner: security-engineering
---

# Tool Catalog and Static Invocation Reference

This document is written for a security researcher who needs to know exactly
**which tools this platform executes, with which command-line arguments, and
why** — not just that "a Scope Gateway authorizes tool calls" (that
architectural story is in [`security-model.md`](../security-model.md)). It is
a companion to the capability registry
[`control-plane/app/tools/registry.py`](../../control-plane/app/tools/registry.py),
which is the single source of truth this document describes in prose. If the
two ever disagree, the code is authoritative — this file should be updated to
match.

Every command line shown below is taken verbatim (flags, order, defaults)
from the worker source that constructs it. Nothing here is a paraphrase of
intent; each flag has a one-line "why".

## 1. Two invocation paths

Every tool call on this platform is authorized once by the Scope Gateway
(`control-plane/app/gateway/authorize.py`) before it reaches the isolated
`tool-runner` container. But **who chooses the arguments** differs by tool:

| Path | Who picks the target | Who picks the arguments | Tools |
|---|---|---|---|
| **Deterministic pipeline** | The pipeline (every in-scope asset, every run) | The worker — fixed, hardcoded per call site, never influenced by the LLM | `nmap`, `httpx`, `nikto`, `wafw00f`, `testssl`, `nuclei` (both passes) |
| **Vector Agent proposal** | The LLM, constrained to the in-scope host list | The LLM, but only through a narrow, gateway-validated envelope (never raw flags) | `http_request` (curl), `ffuf` (content discovery), `redis-probe`/`activemq-banner`/`activemq-openwire-probe` (curated raw-protocol probes — the agent picks the tool and target only, never the bytes sent, §3.4), plus a same-envelope re-run of the pipeline's `run_check` tools (`httpx`, `nikto`, `wafw00f`, `testssl`, `nuclei` — **not** `nmap`) |

The Vector Agent never writes a shell command or a tool flag. It calls one of
five typed functions (`run_check`, `http_request`, `content_discovery`,
`report_finding`, `finish` — defined in
[`worker/app/tasks/agent.py:133-260`](../../worker/app/tasks/agent.py#L133-L260)).
For `run_check` the actual invocation is byte-for-byte the same hardcoded
command the deterministic pipeline uses (see §2) — the agent only chooses
*which* tool and *which* in-scope host, never the flags. For `http_request`
and `content_discovery` the agent supplies structured fields (method, path,
headers, body / wordlist, path, extensions, candidates) that are independently
re-validated for shape by `control-plane/app/gateway/args_safety.py` before the
worker turns them into a concrete command (§3).

`nmap` is explicitly excluded from agent proposals
(`worker/app/tasks/agent.py:341-345`, `ALLOWED_TOOLS` at
`worker/app/tasks/agent.py:63`): the TCP/UDP port sweep is engagement-configured
pipeline work the agent can read the results of but never repeat or widen.

## 2. Deterministic pipeline tools — exact static invocations

These run once per in-scope asset in the `fingerprint` phase
(`worker/app/tasks/fingerprint.py`), in this order: `nmap` first (so
discovered web ports can steer the web tools), then for each candidate web
port: `httpx` (liveness gate) → `nikto` → `wafw00f` → `testssl` → `nuclei`
(main pass) → `nuclei` (headless pass). If `httpx` finds no live HTTP service
on a port, the remaining web tools are skipped for that port
(`worker/app/tasks/fingerprint.py:422-436`).

### 2.1 nmap — port/service discovery

Source: `worker/app/tool_runner_client.py:69-124` (`_nmap_body`),
executed via a **signed raw-egress lease** (§6), not through the shared HTTP
egress proxy — raw SYN/UDP sockets cannot go through an HTTP proxy.

nmap runs in up to four bounded stages per engagement, chosen by `stage` in
the request body. Each stage's flags are validated exactly (not just
allow-listed) in `_nmap_body` — a stage/flag/port mismatch raises before
anything is sent to the runner.

**Stage `discovery`** — find which configured TCP ports are open:
```
-sS <ports> --privileged -T3 -Pn -n --max-rate <rate> --max-retries 2 --host-timeout 600s -oX -
```
| Flag | Why |
|---|---|
| `-sS` | SYN scan (half-open) — the standard, lowest-footprint TCP port-state probe; never completes a full handshake. |
| `<ports>` | The **engagement-configured** TCP range (`Engagement.tcp_port_from/to`, default full `1-65535`, narrowable by the operator to a `configured_tcp` window) — never an arbitrary or agent-chosen range. |
| `--privileged` | Raw-socket SYN scanning needs `CAP_NET_RAW`; granted narrowly to the ephemeral tool-runner container, not to the worker. |
| `-T3` | Nmap's default/"normal" timing template — deliberately not aggressive (`-T4`/`-T5`). |
| `-Pn` | Skip ICMP host-discovery ping. Many externally-facing targets (and bug-bounty scopes) block ICMP; without `-Pn` a live-but-ping-filtered host would be silently skipped. |
| `-n` | No reverse-DNS lookups — avoids noisy, unnecessary resolver traffic; the isolated runner network also has no general DNS. |
| `--max-rate <rate>` | Hard packet-rate ceiling, **1–1000 pps**, validated by `args_safety._nmap_args_safe` (`control-plane/app/gateway/args_safety.py:51-88`). Rate-limits the scan so it cannot look like — or act like — a denial-of-service flood against a possibly small target. |
| `--max-retries 2` | Bounded retransmissions — reliability without unbounded noise. |
| `--host-timeout 600s` | Generous ceiling so a full 1–65535 sweep of a heavily filtered host (~200s at 1000pps) completes instead of nmap discarding the host mid-scan and reporting zero open ports (this happened live at a tighter 280s timeout; comment at `tool_runner_client.py:86-89`). Stays safely under the raw-egress lease TTL (900s). |
| `-oX -` | XML to stdout — deterministic, machine-parseable output for `worker/app/nmap_parse.py`, instead of nmap's human-oriented default text. |

**Stage `service`** — version-fingerprint exactly the ports `discovery` found
open, in batches of 128 (capped at 1024 ports total to bound runtime):
```
-sV <open-ports> --version-light -T3 -Pn -n --max-rate <rate> --max-retries 2 --host-timeout 180s -oX -
```
Same rationale as above for the shared flags. `-sV` is service/version
detection — the actual purpose of the fingerprint phase (feeds
`worker/app/known_vulns.py` product→CVE lookups). `--version-light` trades
some detection depth for speed/reliability versus `--version-all`. The
timeout drops to 180s because this stage only probes a bounded, already-known
set of open ports rather than sweeping the full range.

**Stage `udp_discovery` / `udp_service`** — only run if the operator opted the
engagement into UDP discovery (`Engagement.udp_discovery_enabled`); otherwise
nmap never touches UDP at all. When enabled, the port set is a **fixed,
hardcoded list of nine well-known UDP services**, never a sweep:
```
-sU 53,123,161,443,500,1900,4500,5060,5353 --privileged -T3 -Pn -n --max-rate <rate ≤100> --max-retries 1 --host-timeout 180s -oX -
```
53/DNS, 123/NTP, 161/SNMP, 443/QUIC, 500/IKE, 1900/SSDP, 4500/IPsec NAT-T,
5060/SIP, 5353/mDNS — chosen because UDP scanning is inherently slow and
prone to false "open|filtered" results; a full UDP range scan is prohibitively
expensive and noisy for the value it adds, so only commonly-exposed,
commonly-misconfigured services are probed. `--max-rate` is capped lower
(≤100 vs ≤1000 for TCP) because UDP probing is more sensitive to rate-related
false positives. `udp_service` re-probes only the ports `udp_discovery`
actually confirmed `open` (ambiguous `open|filtered` results are treated as
inconclusive, not open — `worker/app/raw_nmap.py:200-214`).

Argument hardening independent of the above (`args_safety._nmap_args_safe`,
`control-plane/app/gateway/args_safety.py:51-88`): the only accepted keys are
`{flags, ports, max_rate, port_profile}`; any flag containing
`--script=exploit` is rejected outright; `-sU` is never permitted in the
narrow "service re-check" envelope theoretically available to other callers.
In practice nmap is never dispatched with agent-supplied args at all — it is
excluded from Vector Agent proposals entirely (§1).

Concurrency and safety mechanics around nmap (not scan content, but relevant
to a researcher auditing "can this ever run wider than advertised"): a signed,
short-TTL lease (`raw_egress_gateway`) is acquired per stage, heartbeated
every 3s, and revoked immediately after; `use_cache: false` on every call
disables HexStrike's own result cache, which is keyed only by the raw command
string with no engagement scoping (`tool_runner_client.py:117-122`) — without
this, a re-scan or a different engagement hitting the same target+flags could
silently receive another run's stale result.

### 2.2 httpx — HTTP liveness and tech-stack fingerprint

Source: `worker/app/tool_runner_client.py:262-269` (`_httpx_command`),
dispatched through the generic `/api/command` runner endpoint (HexStrike's
own dedicated `httpx` endpoint passes the target via `-l`, which it treats as
a *file of hosts* rather than a single hostname — verified broken for
single-host calls, hence the workaround).
```
httpx -u <url> -json -silent -disable-update-check -tech-detect -status-code -title -web-server -timeout 10 -no-color [-proxy <egress-proxy-url>]
```
| Flag | Why |
|---|---|
| `-u <url>` | A single, explicit target URL (`https://` forced if the target has no scheme) — no crawling, no host-list expansion. |
| `-json` | Structured, reliably parseable output (`worker/app/httpx_parse.py`). |
| `-silent` | Suppresses banner/progress noise that would otherwise pollute stdout. |
| `-disable-update-check` | The runner image is isolated (no general internet egress); httpx must never try to phone home for updates. |
| `-tech-detect` | Fingerprint the technology stack (Wappalyzer-style signatures) — the actual purpose of this call; feeds `service.tech_stack`. |
| `-status-code -title -web-server` | Minimal liveness/metadata signals used to decide whether the host is "live" (gates whether nikto/wafw00f/testssl/nuclei even run) and to populate service metadata. |
| `-timeout 10` | Bounded per-request timeout so one slow/hanging host cannot stall the whole fingerprint phase. |
| `-no-color` | Clean, ANSI-escape-free text for downstream parsing. |
| `-proxy <url>` (if configured) | httpx does **not** honor `HTTP_PROXY`/`HTTPS_PROXY` environment variables, so the egress proxy must be passed explicitly — this is what forces httpx traffic through the second, independent scope re-check (§6), instead of reaching the target directly from the runner's network path. |

This deterministic call always passes an empty argument dict; the only method
`args_safety._httpx_args_safe` (`args_safety.py:102-104`) would ever permit for
a hypothetical future non-empty call is `GET`/`HEAD`/`OPTIONS`.

### 2.3 nikto — web misconfiguration / missing-header scan

Source: `worker/app/tasks/fingerprint.py:208-234` (`_web_enum`), dispatched to
HexStrike's `/api/tools/nikto` endpoint with the egress proxy injected by
`worker/app/tool_runner_client.py:215-223` (`_nikto_body`).
```
-Tuning 123b -maxtime 40s -useproxy <egress-proxy-url>
```
| Flag | Why |
|---|---|
| `-Tuning 123b` | Restricts nikto to four non-destructive test categories: `1` interesting files, `2` misconfiguration, `3` information disclosure, `b` software/version identification. **Deliberately excludes**: `4` injection, `5`/`7` remote file retrieval, `6` denial of service, `8` command execution, `9` SQL injection, `0` file upload, `a` authentication bypass, `c` remote source inclusion — this keeps the scan strictly diagnostic, matching the platform's non-destructive posture (`REQ-SCANQUAL-002`). Missing-security-header findings (the actual reason nikto is run — see below) surface from nikto's baseline analysis regardless of tuning. |
| `-maxtime 40s` | Hard wall-clock ceiling per host — nikto is well known to run long on large/slow sites; this bounds the fingerprint phase's total runtime. |
| `-useproxy <url>` | Nikto ignores `HTTP_PROXY` env vars; the proxy must be passed as an explicit flag to force all of nikto's requests through the egress proxy's scope re-check and rate limiting. |

Why nikto specifically: `httpx`'s HexStrike endpoint does not expose raw
response headers, so nikto's plaintext output (parsed by
`worker/app/nikto_parse.py`) is the mechanism used to reliably detect missing
security headers (`X-Frame-Options`, `Strict-Transport-Security`, etc.) —
documented at `worker/app/tasks/fingerprint.py:9-15`.

### 2.4 wafw00f — WAF fingerprint (informational only)

Source: `worker/app/tasks/fingerprint.py:248-273` (`_waf_detect`), proxy
injected by `worker/app/tool_runner_client.py:236-243` (`_wafw00f_body`).
```
-p <egress-proxy-url>
```
`wafw00f` is Python-`requests`-based and honors `-p`/`--proxy` directly
(verified). This is purely reconnaissance context for the operator (what, if
anything, protects this asset) — a detected WAF produces only an
`info`-level finding (`exposure_factor=0.2, business_factor=0.2`,
`fingerprint.py:267-273`); the platform never attempts to bypass or evade a
detected WAF.

### 2.5 testssl — TLS/certificate hygiene

Source: `worker/app/tool_runner_client.py:272-292` (`_testssl_command`),
dispatched through the generic `/api/command` endpoint (no dedicated
HexStrike endpoint exists for testssl).
```
testssl --quiet --protocols --server-defaults --vulnerable --severity LOW [--ip <resolved-ip>] [--proxy <proxy-host:port>] --jsonfile <tmp>.json <url> >/dev/null 2>&1; cat <tmp>.json; rm -f <tmp>.json
```
| Flag | Why |
|---|---|
| `--quiet` | Suppresses banner noise. |
| `--protocols` | Enumerates supported TLS/SSL protocol versions — surfaces weak/deprecated protocols (SSLv2/3, TLS1.0/1.1). |
| `--server-defaults` | Certificate and default cipher/negotiation hygiene checks (expiry, key size, chain issues, default cipher order). |
| `--vulnerable` | Runs testssl's built-in **non-destructive** vulnerability probes (Heartbleed, ROBOT, CCS injection, BEAST, …, `REQ-SCANQUAL-004`). These are crafted-handshake, read-only diagnostic probes — they detect a vulnerable server response, they do not exploit it (e.g. no actual Heartbleed memory exfiltration beyond the tool's own bounded detection check). |
| `--severity LOW` | Only surfaces findings at `LOW` severity or above — filters pure-informational noise before it reaches the findings pipeline. |
| `--ip <resolved-ip>` | testssl resolves DNS **locally** (unlike nikto/nuclei, which go through the proxy), but the isolated runner container has no DNS resolver. The worker passes the already-audited, materialized IP obtained from the control-plane's own scope-checked DNS materialization step (`client.materialize_dns`) — this is a routing detail, not a security-relevant tool argument, so it is deliberately **not** passed through the Scope Gateway's argument validator (`fingerprint.py:325-327`); the hostname/URL, which *is* security-relevant, still is. |
| `--proxy <host:port>` (if configured) | Same rationale as nikto/wafw00f — forces testssl's connections through the egress proxy's second scope check. |
| `--jsonfile <tmp>.json` + `cat`+`rm` | testssl does not emit clean JSON to stdout on its own (it mixes in banner text); output goes to a uniquely-named temp file (testssl refuses to overwrite an existing file, and unique names avoid collisions between concurrent scans), which is then `cat`'d for pure JSON and deleted immediately. |

Only findings with `severity >= LOW` become platform findings, using
testssl's own severity for each check (`fingerprint.py:311-349`).

### 2.6 nuclei — template-based vulnerability/exposure scan (two passes)

Source: `worker/app/tool_runner_client.py:153-212` (`_nuclei_body`),
dispatched to HexStrike's `/api/tools/nuclei` endpoint. Templates are **baked
into the runner image at build time** (`/opt/nuclei-templates`) — never
fetched at scan time, since the isolated runner has no general internet
access; this also makes the template set an auditable, pinned artifact rather
than something that silently changes between scans.

Flags common to both passes:
```
-t /opt/nuclei-templates -disable-update-check -j -silent -no-color
```
`-t` pins the template source; `-disable-update-check` matches the
build-time-only template policy; `-j` gives JSONL for
`worker/app/nuclei_parse.py`; `-silent -no-color` keep stdout clean.

**Why two separate passes at all**: HexStrike's command executor hard-kills
*every* call at 300s, non-configurably. A single combined run (full
non-headless template set + headless browser mode) against a real, proxied
target exceeded 300s in live testing and returned only partial results
(`REQ-AGENT-018`, `tool_runner_client.py:158-168`). Splitting into two
independently-bounded passes fixed this; each pass alone measured
comfortably under 300s.

**Main pass** (non-headless):
```
-tags cve,misconfig,exposure,exposures,default-login,waf,dast -severity info,low,medium,high,critical -etags intrusive,dos,fuzz,csp-bypass -rate-limit 50 -timeout 8 -retries 1 [-p <egress-proxy-url>]
```
| Flag | Why |
|---|---|
| `-tags cve,misconfig,exposure,exposures,default-login,waf,dast` | Only run templates in these categories. `dast` (`REQ-AGENT-016`) is nuclei's bucket of generic vulnerability-class templates — XSS, SQLi (including blind/time-based), open redirect, LFI, RFI, command injection, SSRF, SSTI, XXE, CRLF injection — each capped at `max-request:1` and *not* tagged `fuzz`, so it is not excluded by `-etags` below. |
| `-severity info,low,medium,high,critical` | All severities included; filtering happens by tag/exclude-tag, not by severity, at this stage. |
| `-etags intrusive,dos,fuzz,csp-bypass` | Explicitly excludes nuclei's own intrusive, denial-of-service, and fuzzing template categories. `csp-bypass` is excluded separately because it requires headless mode and pulls in ~192 vendor-specific templates — measured at ~530s for that directory alone against one target, disproportionate for a generic ASM baseline. |
| `-rate-limit 50` | Caps requests/sec so the scan cannot overwhelm the target or resemble a DoS. |
| `-timeout 8 -retries 1` | Bounded per-request timeout and a single retry — keeps the whole pass under HexStrike's hard 300s executor limit. |
| `-p <url>` (if configured) | Forces nuclei traffic through the egress proxy (second scope check), same rationale as the other HTTP tools. |

**Headless pass** (deliberately minimal — one template only):
```
-tags domxss -severity info,low,medium,high,critical -rate-limit 50 -timeout 8 -retries 1 [-p <egress-proxy-url>] -headless -system-chrome -ho "--no-sandbox" -hbs 2 -headc 2 -page-timeout 20
```
| Flag | Why |
|---|---|
| `-tags domxss` | Narrowed to exactly **one** generic DOM-XSS template (`headless/window-name-domxss.yaml`). Deliberately *not* the broad `headless` tag (pulls in a DVWA-specific template) or `xss` (1411 templates, overwhelmingly product-specific) — `domxss` precisely targets the one generic template; a second DOM-XSS template match is already CVE-tagged and covered by the main pass. |
| `-headless` | Enables nuclei's browser-based template engine — required for DOM-XSS detection, which needs actual JavaScript execution, not just a static HTTP response. |
| `-system-chrome` | Uses the Chromium already installed in the runner image at build time — no runtime download (the image has no general internet access). |
| `-ho "--no-sandbox"` | Passed through to Chrome. Chrome's own sandbox needs Linux capabilities the container deliberately does not have (`cap_drop: ALL`); isolation instead comes from the container boundary itself (non-root, read-only rootfs, `cap_drop: ALL`, network only via the egress proxy). |
| `-hbs 2 -headc 2` | Caps concurrent headless browser sessions/instances at 2 — the small production host cannot sustain many parallel Chrome processes. |
| `-page-timeout 20` | Bounded per-page load timeout. |

Argument hardening independent of the above
(`args_safety._nuclei_args_safe`, `args_safety.py:91-99`): any caller-supplied
`tags` containing `intrusive`, `dos`, or `fuzz` is rejected — defense in
depth in case a future caller ever adds tags to a nuclei call; today's
deterministic calls pass no such tags.

Every nmap/nuclei call also sets `use_cache: false` (and nmap sets
`use_recovery: false`) for the same reason described in §2.1: HexStrike's
built-in result cache is not engagement-scoped.

## 3. Vector-Agent-proposable tools — bounded envelopes

The Vector Agent (`worker/app/tasks/agent.py`) reasons over evidence already
collected by the deterministic pipeline and may propose a small, additional
set of checks. Every proposal still passes through the identical Scope
Gateway used by the pipeline; the difference from §2 is only that the
*arguments* the agent supplies are themselves validated, rather than being
absent/fixed.

### 3.1 `run_check` — re-run a pipeline tool against a specific host

The agent picks a `tool` (any of `httpx`, `nikto`, `wafw00f`, `testssl`,
`nuclei` — never `nmap`) and a `target` from the in-scope host list
(`worker/app/tasks/agent.py:136-153`). If authorized, the exact same
hardcoded command from §2 runs against that host — the agent cannot alter a
single flag. This exists so the agent can, for example, ask for a fresh
`nuclei` pass against one specific host it has a hypothesis about, without
being able to change what `nuclei` actually does.

### 3.2 `http_request` — agent-crafted raw HTTP read/write

Source: `worker/app/tool_runner_client.py:295-325` (`_http_request_command`).
This is the agent's primary manual investigation tool — enumerating
authorization headers, probing endpoints, testing access-control bypasses,
judging exposed data — with the **full** response returned for the LLM to
classify.
```
curl -sS -i -X <METHOD> --max-time 20 [-x <egress-proxy-url>] [-H "<name>: <value>" ...] [--data-raw <body>] <url> | head -c 16384
```
| Flag | Why |
|---|---|
| `-sS` | Silent progress meter, but errors still shown. |
| `-i` | Include response headers — the agent specifically needs these (e.g. to judge security headers, cache-control, auth challenges). |
| `-X <METHOD>` | Agent-chosen from `GET,HEAD,OPTIONS,POST,PUT,DELETE,PATCH`. **Read methods (`GET/HEAD/OPTIONS`) run autonomously.** Any write method (`POST/PUT/DELETE/PATCH`), or any request carrying a body regardless of method, is never executed autonomously — the gateway routes it to a human operator approval queue instead of denying it outright (`REQ-APPROVAL-001/002`, `args_safety.http_request_is_state_changing`, `args_safety.py:28-32`). A state-changing proposal must also include the agent's own risk assessment (`risk_level`, `risk`) or it is rejected with `risk_statement_required` before ever reaching a human. |
| `--max-time 20` | Bounded per-request wall-clock timeout. |
| `-x <proxy-url>` (if configured) | Forces the request through the egress proxy for the second scope check. |
| `-H "<name>: <value>"` | Agent-specified headers — each name is validated as an RFC-7230 token (`args_safety._HEADER_NAME_RE`, `args_safety.py:14`), each value is size-bounded (≤1024 chars) and rejected if it contains `\r`/`\n` (blocks header/request-splitting injection), at most 30 headers. |
| `--data-raw <body>` | Chosen over `--data`/`-d` specifically because those reinterpret a leading `@` or `%` in the body — surprising and unsafe for arbitrary agent-authored content; `--data-raw` sends the string byte-for-byte. Body is size-bounded to 16 KB (`args_safety._MAX_BODY_LEN`, `args_safety.py:25`). |
| `<url>` | `target` (from the in-scope host list) + agent-chosen `path`. Path is structurally validated: must start with `/`, ≤2048 chars, no whitespace/CR/LF (`args_safety._http_request_args_safe`, `args_safety.py:113-145`). |
| `\| head -c 16384` | Caps the **response** read at 16 KB (status + headers + start of body) — enough for classification while protecting the LLM's context budget. |

Every argument is additionally `shlex.quote()`-escaped by the worker before
shell execution (`tool_runner_client.py:322`) — defense in depth on top of
the gateway's structural validation, in case a future gateway path is ever
loosened.

State-changing requests that reach the approval queue are re-authorized at
claim time from the **exact stored call** the operator approved
(`worker/app/tasks/agent.py:480-497`) — an in-memory copy of the agent's
proposal is never trusted for execution, only the control-plane's persisted
record of what was actually approved.

### 3.3 `content_discovery` (ffuf) — curated directory/endpoint brute force

Source: `worker/app/tool_runner_client.py:340-377` (`_ffuf_command`). The
agent curates (picks a wordlist matching the target's tech stack, optionally
adds a few reasoned candidate paths); ffuf does the volume, rate-limited and
non-destructive, through the egress proxy.
```
ffuf -w <wordlist-path>:FUZZ -u <url> -mc 200,204,301,302,307,401,403,405,500 -rate 20 -t 10 -maxtime 90 -s -of json -o <tmp>.json [-e <ext1,ext2,...>] [-x <egress-proxy-url>]
```
| Flag | Why |
|---|---|
| `-w <path>:FUZZ` | The agent selects a wordlist by a **fixed key** (`common`, `raft-medium-dirs`, `raft-medium-files`, `quickhits`, `directory-list-medium`), mapped server-side to a real SecLists path baked into the runner image (`FFUF_WORDLISTS`, `tool_runner_client.py:331-337`) — the agent can never supply a raw filesystem path (which would otherwise allow something like `-w /etc/passwd`). |
| agent `extra_candidates` | Optional small list of the agent's own reasoned path/filename guesses (e.g. `.git/config`); written via `printf` (each candidate individually `shlex.quote()`-escaped) to a throwaway temp wordlist used **instead of** the base wordlist, rather than being passed as raw ffuf flags. Each candidate is validated against a strict path-token pattern (`args_safety._CANDIDATE_RE`, `args_safety.py:48`), max 200 entries. |
| `-u <url>` | Target host + agent-chosen `path`, which **must contain the literal `FUZZ` placeholder** (validated by `args_safety._FUZZ_PATH_RE`, `args_safety.py:43`) and only safe path characters — no whitespace, CRLF, or shell metacharacters. |
| `-mc 200,204,301,302,307,401,403,405,500` | Only match response codes indicating a real resource or access-control-relevant behavior (found, redirect, auth-required, forbidden, method-not-allowed, server-error) — filters ffuf's default noise. |
| `-rate 20` | Requests/sec cap — gentler than nuclei's 50 because content discovery issues far more requests per target than a template scan. |
| `-t 10` | 10 concurrent worker threads. |
| `-maxtime 90` | Hard 90s wall-clock cap per run. |
| `-s -of json -o <tmp>` | Silent + structured JSON to a unique temp file (parsed by `worker/app/ffuf_parse.py`, then deleted). |
| `-e <ext>` | Optional agent-chosen extensions, each validated against `\.?[A-Za-z0-9]{1,8}` (`args_safety._EXT_RE`, `args_safety.py:44`), max 10. |
| `-x <proxy-url>` (if configured) | Forces every ffuf request through the egress proxy's per-request scope re-check. |

Argument hardening (`args_safety._ffuf_args_safe`, `args_safety.py:148-175`):
only the keys `{wordlist, path, extensions, extra_candidates}` are accepted;
each is validated as above; anything else is rejected outright.

### 3.4 `redis-probe` / `activemq-banner` / `activemq-openwire-probe` — curated raw-protocol probes (`REQ-AGENT-025`, `REQ-AGENT-027`)

For non-HTTP services the tools above cannot touch at all: Redis and
ActiveMQ's OpenWire transport speak their own binary wire protocols, not
HTTP, so nothing in §2/§3.1–3.3 can reach them. Source:
`worker/app/tool_runner_client.py:475-552` (`_raw_tcp_probe_command` + three
one-line wrappers), `worker/app/openwire_payload.py`,
`worker/app/tasks/dispatch.py`. The agent proposes only the **tool** and the
**target** (typically a host `nmap` already flagged as `redis`/`activemq`);
`args_safety._raw_tcp_probe_args_safe` rejects any other argument outright —
the bytes sent, if any, are never agent-composed.

All three run the same bounded, generated Python one-liner:
```
timeout 8 python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
s.connect((<host>, <port>))
<s.sendall(<fixed bytes>) — omitted entirely for activemq-banner>
data = s.recv(4096)
# status/byte-count header + up to 2000 printable bytes to stdout
"
```
| Element | Why |
|---|---|
| outer `timeout 8` | Defense-in-depth ceiling beyond the socket-level timeouts, for edge cases they don't cover (e.g. DNS resolution hanging before `connect()` even starts its own clock). |
| `settimeout(3)` | 3s connect timeout and 3s read timeout, independently enforced. |
| `s.recv(4096)` | Bounded read — enough to capture a protocol greeting, never a bulk transfer. |
| printable-byte filter, 2000-byte cap | Only ASCII-printable bytes (plus tab/CR/LF) reach the LLM/UI, capped at 2000 bytes — binary protocol noise is stripped before storage or display. |

**`redis-probe`**: sends exactly the fixed bytes `PING\r\n` (RESP protocol)
and nothing else. Confirms reachability and whether the port answers
`+PONG` with no authentication required — a real, common Redis
misconfiguration. Never sends any other Redis command.

**`activemq-banner`**: sends nothing at all. ActiveMQ's OpenWire transport
self-announces a `WireFormatInfo` greeting to any client that connects —
purely passive, read-only.

**`activemq-openwire-probe`** (R4 — the one tool in this document that
actively exercises a vulnerability rather than only observing): targets
`CVE-2023-46604` (OpenWire deserialization RCE, CVSS 10.0), the same class
of flaw as the older `CVE-2015-5254`. This is the specific gap nuclei's own
template for this CVE cannot close in this deployment: that template needs
a public Interactsh out-of-band callback server, and the isolated runner
has no general internet egress by design (§4/§6; also
`docs/requirements/fingerprint-phase-efficiency.md` `REQ-FPEFF-008`).

The packet is a single curated entry
(`worker/app/openwire_payload.py`'s `GADGETS` table) — its header is
byte-matched against nuclei's own public reference template for this CVE,
with the trailing resource-URL length encoded as a proper 2-byte
big-endian prefix (`struct.pack(">H", len)`); the reference template's own
unpadded-hex length encoding is silently byte-misaligned for the common
case of 16–255-character URLs, which this fixes. The embedded URL is a
single-use callback link to a new, deliberately minimal, genuinely
**unauthenticated** control-plane endpoint
(`GET /callback/openwire/{token}`, `control-plane/app/api/openwire_callback.py`
— unauthenticated because the caller is the probed target itself, which
cannot present any platform credential). If the target is vulnerable, its
own deserialization/exploitation of the crafted packet makes it fetch that
exact URL — the fetch itself is the proof, since OpenWire RCE has no
in-band response to read (unlike, e.g., Struts2 S2-045's OGNL-in-header
technique). The receiver serves back only static, inert Spring bean XML —
no `ProcessBuilder`/subprocess payload, deliberately less than the public
reference PoC — and each token is single-use: an unknown, expired, or
already-triggered token gets an identical generic 404, leaking no
information about token validity.

`dispatch.py` polls the callback-status endpoint for up to **8 seconds**
after the packet is sent. If no callback arrives in that window, **nothing
is reported as a finding** — a sent-but-unconfirmed probe is deliberately
treated the same as no evidence at all (patched, egress-filtered, and
simply slow are indistinguishable from this side). A connect failure never
even polls for a callback.

Because this genuinely attempts remote code execution rather than merely
observing, it is the one raw-protocol probe that is **not** autonomous:
`authorize.py`'s `state_changing` check includes it unconditionally — the
same hardcoded treatment as `http_request`'s write methods (§3.2), **not**
the configurable `tool_grant.requires_manual_approval` field. Every
invocation requires a fresh, explicit human approval with the agent's own
risk assessment attached, and this cannot be bypassed by an operator (or a
bug) setting that grant field to `False` — verified by a dedicated negative
test (`control-plane/tests/integration/test_openwire_probe_approval.py::
test_negative_a_grants_own_requires_manual_approval_false_does_not_bypass_the_mandatory_gate`).

All three probes share the same **signed, single-port raw-egress lease**
mechanism `nmap` uses (§6), via a `raw_tcp_probe` port profile scoped to
exactly the one port being probed at a time — never nmap's full configured
range.

## 4. Passive OSINT discovery — not gateway tool calls at all

Source: `worker/app/tasks/discovery.py`. Before any of the above runs, the
`discovery` phase enumerates candidate subdomains for every in-scope root
domain using **only public, third-party data aggregators** — it never
queries the target directly, so these calls do not go through
`client.authorize()`/the Scope Gateway at all (there is no "active call
against a customer system" to authorize):

| Source | Query | Notes |
|---|---|---|
| **crt.sh** | `GET https://crt.sh/?q=%.<domain>&output=json` | Certificate Transparency log search. Notoriously flaky (intermittent 404/502); retried up to 3 times with backoff (`discovery.py:59-84`). |
| **Cert Spotter** | `GET https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names` | Free, key-less CT issuance API (`REQ-SCANQUAL-001`). |
| **HackerTarget** | `GET https://api.hackertarget.com/hostsearch/?q=<domain>` | Free, key-less hostname search, CSV response. Rate-limited; treated as best-effort. |

All three sources are independently fault-isolated (`discovery.py:133-147`)
— one failing source never blocks discovery or drops the others' results.
Results are only ever used to *propose* new discovered assets, which are then
subjected to the same in-scope/deny-rule check as everything else
(`discovery.py:206-217`) before any active tool ever touches them.

## 5. Rate limiting — two independent layers

A researcher auditing "how fast can this scan a target" should be aware
there are **two separate, independently-enforced rate mechanisms** that both
apply simultaneously:

1. **Gateway admission rate** (`REQ-RATE-001..003`,
   `docs/requirements/scan-rate-policy.md`) — an operator-configurable cap on
   gateway-*approved* tool calls per second, enforced in
   `control-plane/app/gateway/authorize.py` independent of which tool is
   being called. When exceeded, the gateway either hard-denies
   (`rate_limited`) or, if auto-slow-down is enabled, returns a `THROTTLE`
   with a retry delay that the worker/agent must wait out before
   re-authorizing (never a bypass — see `_authorize_throttled`,
   `worker/app/tasks/agent.py:305-318`).
2. **Tool-embedded pacing** — the fixed rate flags baked into each static
   invocation in §2/§3 (`nmap --max-rate`, `nuclei -rate-limit 50`,
   `ffuf -rate 20`), which bound how fast a *single already-authorized* tool
   call paces its own internal requests/packets, independent of the gateway's
   call-level admission control.

## 6. Where scope is actually enforced on the wire

Every tool above reaches its target through exactly one of two enforcement
paths — this is what makes the flag choices above matter, not just declare
intent:

- **`raw_network`** (nmap, and `redis-probe`/`activemq-banner`/
  `activemq-openwire-probe`, §3.4): a signed, short-TTL lease
  (`control-plane/app/gateway/raw_egress_lease.py`) authorizes a specific
  IP/port/rate for a bounded time window; `nftables` (Compose) or a generated
  Kubernetes `NetworkPolicy` (cluster deployments) deny everything else at
  the network layer. nmap's lease covers the engagement-configured port
  range; the three raw-protocol probes instead use a `raw_tcp_probe` port
  profile scoped to exactly the one port being probed. If raw-network egress
  is not enabled for a deployment, these tools are refused outright
  (`raw_egress_unavailable`, `tool_runner_client.py:517-521`) rather than
  silently degrading.
- **`http_proxy`** (httpx, nikto, wafw00f, testssl, nuclei, http_request,
  ffuf): every one of these tools is passed an explicit proxy flag (see the
  tables above) because none of them honor `HTTP_PROXY` environment
  variables. The egress proxy performs an independent, second scope
  re-check and attaches the required identification header per request —
  documented in [`security-model.md`](../security-model.md#defense-in-depth-zwei-unabhängige-scope-prüfungen).
- **`passive`** (crt.sh, Cert Spotter, HackerTarget, and the registry-declared
  but not-yet-orchestrated `subfinder`/`amass`): queries a third-party data
  source, never the target; not authorized by the gateway because there is
  no active call to authorize.

## 7. Full capability matrix

Generated from `registry.capability_matrix()` — run `python -c "from app.tools import registry; import json; print(json.dumps(registry.capability_matrix(), indent=2))"` inside the control-plane container for the live, current values. As of this writing:

| Tool | Category | Execution class | Installed | Enabled | Dispatched | Notes |
|---|---|---|---|---|---|---|
| `nmap` | fingerprint | raw_network | yes | yes | **yes** | Deterministic pipeline only (§2.1); never agent-proposable. |
| `httpx` | fingerprint | http_proxy | yes | yes | **yes** | Via generic `/api/command` (§2.2); also agent-proposable via `run_check`. |
| `nikto` | vuln | http_proxy | yes | yes | **yes** | §2.3; also agent-proposable via `run_check`. |
| `wafw00f` | fingerprint | http_proxy | yes | yes | **yes** | §2.4; also agent-proposable via `run_check`. |
| `sslscan` | fingerprint | raw_network | yes | yes | no | Installed and whitelisted, but not wired into the worker client — not currently executed by any phase. |
| `testssl` | fingerprint | http_proxy | yes | yes | **yes** | §2.5; also agent-proposable via `run_check`. |
| `nuclei` | vuln | http_proxy | yes | yes | **yes** | §2.6, two passes; also agent-proposable via `run_check` (single pass). |
| `http_request` | vuln | http_proxy | yes | yes | **yes** | Agent-only (§3.2); not part of the deterministic pipeline. |
| `ffuf` | vuln | http_proxy | yes | yes | **yes** | Agent-only (§3.3); not part of the deterministic pipeline. |
| `redis-probe` | fingerprint | raw_network | yes | yes | **yes** | §3.4; agent-only, passive (sends one fixed `PING\r\n`). |
| `activemq-banner` | fingerprint | raw_network | yes | yes | **yes** | §3.4; agent-only, purely passive (sends nothing). |
| `activemq-openwire-probe` | vuln | raw_network | yes | yes | **yes** | §3.4; agent-only, R4 — the one tool that actively exercises a vulnerability (CVE-2023-46604); mandatory per-call human approval. |
| `default-cred-check` | cred | http_proxy | yes | yes | no | Argument policy exists (max 3 attempts, default wordlist only) but no tool binary is wired up yet — pure placeholder. |
| `subfinder` | recon | passive | yes | yes | no | Worker-mapped to a HexStrike endpoint, but no scan phase currently calls it — passive subdomain discovery today goes through the direct OSINT sources in §4 instead. |
| `amass` | recon | passive | yes | yes | no | Same status as `subfinder`. |
| `whatweb` | fingerprint | http_proxy | yes | yes | no | Installed and whitelisted, not wired into the worker client. |
| `dnsx` | recon | passive | **no** | no | no | Whitelisted in policy but **not actually present** in the runner image (the Dockerfile installs `dnsutils`, not ProjectDiscovery's `dnsx`). |
| `tlsx` | recon | passive | **no** | no | no | Same status as `dnsx`. |
| *(exploit category)* | exploit | — | — | — | — | Intentionally empty — no exploitation tooling is offered in the current capability set. |

This table is intentionally honest about gaps rather than aspirational: a
tool being whitelisted in policy does not mean it can currently run (see
`registry.enabled_but_not_installed()`, which flags exactly the
`dnsx`/`tlsx` inconsistency above), and being installed does not mean any
scan phase actually calls it. This "capability funnel" discipline is
described in `docs/kali-tools-capability-analysis-handoff.md`.

## 8. Verifying this document against the running system

Every claim above is traceable to a specific line of source:

- Capability policy: `control-plane/app/tools/registry.py`
- Argument hardening (structural validation of agent-supplied args):
  `control-plane/app/gateway/args_safety.py`
- Scope Gateway decision chain: `control-plane/app/gateway/authorize.py`
- Static command construction (the actual flags): `worker/app/tool_runner_client.py`
- Deterministic pipeline orchestration: `worker/app/tasks/fingerprint.py`
- Raw-network (nmap) execution and lease lifecycle: `worker/app/raw_nmap.py`,
  `control-plane/app/gateway/raw_egress_lease.py`
- Raw-protocol probe packet construction and dispatch:
  `worker/app/raw_tcp_probe.py`, `worker/app/openwire_payload.py`,
  `worker/app/tasks/dispatch.py`, `control-plane/app/api/openwire_callback.py`
- Vector Agent tool definitions and dispatch: `worker/app/tasks/agent.py`
- Passive OSINT discovery: `worker/app/tasks/discovery.py`

If a security review needs to confirm that no flag has silently drifted from
what is documented here, diff the command-construction functions cited above
against the tables in §2/§3 — every flag in this document is a direct
transcription, not a summary.
