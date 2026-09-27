---
title: Raw-protocol testing for non-HTTP services (Redis, ActiveMQ OpenWire)
status: implemented
risk: R4
owner: security-engineering
---

# Raw-Protocol Testing

Derived from the 2026-08-04 full benchmark sweep
(`docs/benchmarking/benchmark-design.md`, sec 21+): the Vector Agent's
toolkit is entirely HTTP-centric. `vulhub-redis-lua-sandbox` (Redis, port
6379) and part of `vulhub-activemq-cve-2023-46604-vuln` (ActiveMQ OpenWire,
port 61616) scored zero findings for a structural reason, not a detection
-quality one - `httpx`/`nikto`/`nuclei`/`http_request`/`ffuf` are all
HTTP-only, and `nmap` only reports that a port is open, never what a
service actually says back.

**Scope, per johannes's explicit choice**: raw-protocol testing only -
curated, worker-built, non-agent-composed probes. Multi-step exploit-chain
construction (Struts2 S2-045 OGNL, Confluence OGNL, Log4Shell JNDI) is
explicitly deferred, named here so it is not lost, not designed further.

**Risk class: R3.** Not R4: this extends the EXISTING, already-reviewed
raw-egress lease/nftables safety boundary `nmap` already goes through
(`control-plane/app/gateway/raw_egress_lease.py`/`raw_egress_policy.py`,
`raw-egress-gateway/app/gateway.py`) to two new, narrow, read-only,
non-destructive checks - it does not introduce a new safety mechanism, and
introduces zero agent-composed network payloads. Approved by johannes
2026-08-04 (Plan Mode).

Tests must verify this requirement directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-AGENT-025: The agent can prove reachability/exposure of non-HTTP services via two curated, non-destructive probes

Context: see above. `redis-probe` sends the single, official, read-only
Redis `PING` command and reads the reply - `+PONG` proves the instance
answered a command before any authentication (a real, reportable exposure);
an auth-required error proves the opposite, correctly protected, not a
finding. `activemq-banner` sends **nothing** - ActiveMQ's OpenWire protocol
self-announces a `WireFormatInfo` packet (broker version embedded as
readable ASCII) purely passively on connect; any readable greeting confirms
an unauthenticated, network-reachable message broker.

Acceptance criteria:

- Both are exposed to the agent through the EXISTING `run_check(tool,
  target)` schema - no new agent-facing tool, no structured argument the
  agent can influence. The exact bytes sent (or none) are a fixed,
  server-side registry entry per tool
  (`worker/app/tool_runner_client.py::_RAW_TCP_PROTOCOLS`), never
  agent-supplied; `args_safety._raw_tcp_probe_args_safe` fails closed on any
  non-empty argument.
- Both go through the SAME signed raw-egress lease / nftables enforcement
  `nmap` already uses (`port_profile="raw_tcp_probe"`), not the HTTP
  egress-proxy (a raw TCP connect cannot traverse it). The Scope Gateway
  authorizes against the REAL tool name (`redis-probe`/`activemq-banner`),
  never silently checked against `nmap`'s own grant/policy instead.
- The lease is scoped to **exactly one port** (not a range) - re-validated
  independently at two layers: the control-plane checks the requested port
  against the engagement's own configured TCP range before ever signing a
  lease, and the raw-egress-gateway's `verify_lease` independently rejects
  any `raw_tcp_probe`-profile lease whose port is not a single first==last
  pair, regardless of what the control-plane signed.
- The port probed is `single_port` (REQ-FIDELITY-007, when the engagement
  restricts to one non-standard port - the case for every benchmark VM
  target, where NAT remaps the port) or, failing that, the protocol's
  conventional default (6379 / 61616).
- Connect and read are hard-timeout-bounded (~3s each) and the read is
  capped (4096 bytes raw, 2000 bytes of the printable extract surfaced to
  the LLM) - a target that never responds or streams unbounded data cannot
  hang the pipeline or blow the LLM's context budget.
- `redis-probe`'s `+PONG` and `activemq-banner`'s non-empty readable
  greeting are recorded as WORKER-authored findings (`confidence:
  validated`, an explicit `severity_override`) - the same authorship model
  as nikto's missing-header or wafw00f's WAF-detected findings, not routed
  through the LLM agent's own `evidence_basis` mechanism, since no LLM
  judgment is involved in producing them.
- No response, a connect failure, or an auth-required reply is explicitly
  NOT a finding - only ever surfaced as an observation for the agent to
  read, mirroring `report_finding`'s existing "do not record non-findings"
  discipline.

## REQ-AGENT-027: A curated, non-agent-composed probe can prove OpenWire deserialization RCE, with operator approval per attempt

Context: `docs/benchmarking/benchmark-design.md` already flagged this exact
gap ("the ActiveMQ CVE-2023-46604 deserialization PoC... require[s] an OOB
callback to an attacker-controlled host the harness must provide"). Confirmed
2026-08-11 investigating why nuclei's own template for this CVE
(`javascript/cves/2023/CVE-2023-46604.yaml`) never fires here: it depends on
a public Interactsh OOB server, and the tool-runner has no internet egress by
design (REQ-FPEFF-008) — so this vulnerability class is untestable by any
existing tool, not merely under-covered. Every OTHER cataloged ActiveMQ CVE
(Jolokia RCE/unauthorized-access variants, the REST fileserver arbitrary-write
bug, default-login checks) is HTTP-based and already covered by baked nuclei
templates — this requirement is scoped narrowly to the OpenWire
deserialization class specifically (`CVE-2023-46604` today; the same
underlying flaw as the older `CVE-2015-5254`), not a general ActiveMQ probe.

**Risk class: R4** (this document's frontmatter risk moves from R3 to R4 to
reflect this addition — REQ-AGENT-025 above is unaffected and remains
correctly R3, since it is read-only and sends zero bytes/one fixed
non-exploitive command). Unlike REQ-AGENT-025's passive probes, this sends a
crafted packet that deliberately triggers the SAME code path a real
deserialization RCE uses, on a real, possibly-production service. Requires
explicit human authorization per `docs/engineering/sdlc.md`, cannot be
self-approved, and needs the negative tests + security review CLAUDE.md
requires for R3/R4 work.

**Security review:** approved by johannes (project/security owner) on
2026-08-11, based on the design summary above (curated single-gadget table,
no-agent-input `args_safety` rejection, hardcoded non-bypassable approval
gate, minimal single-use callback token, confidence-tiering discipline) and
the full negative-test set in
`control-plane/tests/integration/test_openwire_probe_approval.py` and
`worker/tests/test_dispatch_openwire_probe.py`. The wire-format packet
construction itself (`worker/app/openwire_payload.py`) is reasoned from
nuclei's own reference template rather than empirically confirmed at review
time — see the live-fire verification note in the test-case doc.

**Why this needs a callback at all, and why self-hosted rather than
Interactsh:** the exploit mechanism is that the BROKER (not the scanner)
fetches a Spring bean XML config from an attacker-supplied URL and executes
what it defines — proof of RCE requires observing that fetch, there is no
in-band response to read (unlike, for example, Struts2 S2-045's
`%{math}` OGNL header trick, whose result comes back in the SAME HTTP
response). A third-party OOB provider is unusable here (no internet egress,
by design) and would mean handing an unvalidated fetch event on our own
infrastructure to a service we do not run. A minimal, self-hosted receiver
answers only "was this exact, single-use, short-lived token fetched" — no
third party, no standing listener, no general-purpose callback capability.

Acceptance criteria:

- The exact packet bytes are built server-side from a small, curated,
  version-controlled table of known-good gadget constructions
  (`worker/app/openwire_payload.py`), keyed by name (e.g.
  `spring-classpathxml-cve-2023-46604`) — never agent-composed, never
  agent-influenced in any way. `args_safety` rejects any non-empty argument
  for this tool, identically to `redis-probe`/`activemq-banner`
  (REQ-AGENT-025's existing `_raw_tcp_probe_args_safe`, extended to cover
  this tool by name). A future, similarly-verified gadget (a "future
  weakness" in the same OpenWire-deserialization class) is added as a new
  table entry, not a new tool, a new transport, or a new approval path.
- Only ONE gadget ships in this change: the exact construction nuclei's own
  (non-functional-here) template and the well-known public PoC
  (`X1r0z/ActiveMQ-RCE`) both use — reusing a known-good, community-vetted
  byte sequence rather than deriving OpenWire/Java-serialization framing from
  scratch.
- Transport reuses the EXISTING raw-egress-lease boundary
  (`worker/app/raw_tcp_probe.py::execute_probe`, `port_profile="raw_tcp_probe"`)
  unchanged — the same signed lease, the same nftables enforcement, the same
  single-port (never a range) re-validation at both the control-plane and the
  raw-egress-gateway that `nmap`/`redis-probe`/`activemq-banner` already go
  through. No new safety mechanism is introduced at the network layer.
- **Every single invocation requires a fresh, per-call, human approval before
  it is sent** — added to the SAME hardcoded `state_changing` check
  `control-plane/app/gateway/authorize.py` already applies to `http_request`
  (not merely a configurable `requires_manual_approval` grant, which an
  operator could disable): this tool is exploitation-adjacent by nature, and
  approval must not be optional-by-configuration the way it is for ordinary
  active tools.
- The LLM-assessed risk statement shown to the operator states plainly that
  this attempts to trigger the target's deserialization code path and
  requires it to fetch a URL we host — not phrased as a passive check.
- The callback receiver is minimal and purpose-built, not a general-purpose
  listener:
  - A fresh callback token is unguessable (kept consistent with this
    codebase's existing token-generation standard), bound to exactly one
    `(engagement_id, scan_run_id)` pair, and expires shortly after the probe's
    own bounded wait window — a stale or foreign token is rejected exactly
    like an unknown one.
  - The public endpoint records ONLY "this token was fetched, at this time" -
    no request header, source IP, or body from the (by definition untrusted,
    potentially-now-compromised) calling target is logged or stored,
    mirroring this codebase's existing redact-or-omit discipline for
    untrusted input entering durable storage (REQ-AUDIT-004/007).
  - A fetch against an unknown, expired, or already-consumed token returns a
    generic response indistinguishable from any other 404 - it must not leak
    which tokens are valid, in flight, or which engagement they belong to.
  - The served resource is static, inert content (a syntactically valid but
    functionally empty Spring bean definition) - it does not itself carry a
    second-stage payload of any kind.
- Confidence is tiered honestly, mirroring REQ-AGENT-025's "absence is not a
  finding" discipline:
  - Callback observed within the bounded wait -> `confidence: validated`,
    `evidence_basis: direct_technical_proof` - the strongest tier this
    platform has, because it is: an outbound fetch from the target,
    authenticated by an unguessable single-use token, is unambiguous proof
    the deserialization gadget executed.
  - Packet sent, connection accepted, no callback observed within the wait ->
    explicitly NOT a finding - a bounded-confidence observation only (the
    target may be patched, egress-filtered outbound, or simply slower than
    the wait window), never silently reported as "clean."
  - Connection refused/lease denied/target unreachable -> the existing
    non-finding observation path REQ-AGENT-025 already established.
- Bounded like every other agent-dispatched call: hard connect/send timeout
  matching the existing raw-tcp-probe budget, and a hard-capped wait for the
  callback (seconds, not minutes) so one probe cannot stall the agent phase's
  own iteration budget.

## Explicitly out of scope for this requirement

- **Multi-step exploit-chain construction for other product-specific
  vulnerability classes** (Struts2 S2-045 OGNL injection, Confluence OGNL,
  Log4Shell JNDI callback payloads) remains deferred, not designed here.
  REQ-AGENT-027 above takes up exactly one such chain (OpenWire
  deserialization) because it was the specific gap this session's benchmark
  run surfaced and nuclei structurally cannot cover in this environment - it
  is not a general "build exploit chains now" decision. Struts2 in
  particular already has a working, non-destructive, in-band confirmation
  technique (the OGNL math-expression header trick, no callback needed) and
  does not share this requirement's callback-infrastructure justification.
- A dynamic per-host service-lookup for the probed port. `single_port` (when
  the engagement is restricted to one port) or the protocol's own
  conventional default is sufficient for every real deployment shape this
  session identified; a service-discovery-driven port lookup is a natural,
  incremental follow-up if a real engagement ever needs it, not built now.
- A third raw protocol. The I/O primitive
  (`tool_runner_client._raw_tcp_probe_command`) and the lease profile are
  already generic; adding one is a registry entry in
  `_RAW_TCP_PROTOCOLS`/`raw_tcp_probe.DEFAULT_PORTS` plus a
  `ToolSpec`/`TOOL_CATEGORY`/`args_safety` entry, not new plumbing.
