---
title: Raw-protocol testing verification
status: ready
risk: R3
owner: security-engineering
---

# Raw-Protocol Testing Verification

Verifies [`../requirements/raw-protocol-testing.md`](../requirements/raw-protocol-testing.md).

## TC-AGENT-025: redis-probe / activemq-banner are curated, lease-scoped, and honestly reported

Requirements:

- REQ-AGENT-025

Automated tests:

- `control-plane/tests/test_args_safety.py`
- `control-plane/tests/test_tool_registry.py`
- `control-plane/tests/integration/test_raw_egress_lease.py`
- `control-plane/tests/integration/test_enabled_tools_dispatchable.py`
- `raw-egress-gateway/tests/test_gateway.py`
- `worker/tests/test_tool_runner_client.py`
- `worker/tests/test_raw_tcp_probe.py`
- `worker/tests/test_dispatch_raw_tcp_probe.py`

Objective:

Verify the two curated raw-protocol probes take no agent-composed input,
are authorized and network-scoped through the same lease/nftables mechanism
`nmap` already uses (scoped to exactly one port, checked independently at
both the control-plane and the raw-egress-gateway), execute real,
non-destructive socket I/O correctly, and only ever report a finding when
the evidence actually supports one.

Expected results:

- `args_safety` rejects any non-empty argument for either tool.
- The registry's derived whitelist/dispatchable-set includes both tools;
  the worker's own dispatch table matches exactly (no drift).
- A `raw_tcp_probe` lease is granted only when the requested port falls
  within the engagement's configured TCP range - denied otherwise
  (`port_not_in_configured_range`), and denied when no valid port is
  supplied at all (`raw_tcp_probe_port_invalid`).
- The Scope Gateway authorizes a `raw_tcp_probe` lease against the REAL
  tool name (`redis-probe`/`activemq-banner`), never against `nmap`.
- NEGATIVE (raw-egress-gateway): a `raw_tcp_probe`-profile lease whose
  `ports` is a range (not a single port) is rejected at signature
  -verification time, independent of what the control-plane signed.
- The `raw_tcp_probe` profile is recognized as valid for `protocol="tcp"`
  leases (previously only `full_tcp`/`configured_tcp` were accepted) and
  correctly activates/deactivates the nftables rule for that one port.
- The generated probe command, run for real against a live local TCP
  socket (not just inspected as a string): `redis-probe` actually
  transmits `PING\r\n` and captures a `+PONG` reply; `activemq-banner`
  sends nothing and captures a passively-offered greeting, with non
  -printable bytes stripped from what reaches the LLM; a refused connection
  is reported cleanly, not as a hang or a crash.
- `resolve_port` prefers `single_port` (REQ-FIDELITY-007) over the
  protocol's own conventional default when both are available.
- The lease lifecycle (reserve → acquire → activate → run → deactivate →
  release) always releases the reservation, including when the lease is
  denied or when activation itself raises.
- `redis-probe`'s `+PONG` and `activemq-banner`'s non-empty greeting are
  recorded as `confidence=validated` findings with an explicit severity;
  an auth-required reply, a connect failure, or a denied lease are NEVER
  recorded as findings.

## TC-AGENT-027: the OpenWire probe is curated, callback-verified, and mandatorily approved

Requirements:

- REQ-AGENT-027

Automated tests:

- `worker/tests/test_openwire_payload.py`
- `worker/tests/test_dispatch_openwire_probe.py`
- `control-plane/tests/test_args_safety.py`
- `control-plane/tests/test_tool_registry.py`
- `control-plane/tests/integration/test_enabled_tools_dispatchable.py`
- `control-plane/tests/integration/test_openwire_callback.py`
- `control-plane/tests/integration/test_openwire_probe_approval.py`

Objective:

R4: verify the packet is built correctly from the ONE curated gadget and
never from agent-supplied data, that the callback receiver correctly proves
or fails to prove exploitation without ever leaking token validity to an
untrusted caller, and that every invocation requires a fresh, non-bypassable
human approval.

Expected results:

- The packet header byte-matches nuclei's own verified `CVE-2023-46604`
  template exactly; the length field is a proper 2-byte big-endian prefix
  (not the reference template's own unpadded, sometimes-misaligned hex
  concatenation), correct across a range of callback URL lengths spanning
  the case where that reference approach breaks (16-255 chars).
- `build_probe_packet` takes no argument beyond the callback URL and an
  optional gadget name defaulting to the one curated entry; an unknown
  gadget or a non-URL callback is rejected.
- `args_safety` rejects any non-empty argument for `activemq-openwire-probe`,
  identically to REQ-AGENT-025's two tools.
- A fetch to `/callback/openwire/{token}` with a valid, unexpired,
  not-yet-triggered token marks it triggered and serves static inert XML
  content (no bean definition, no `ProcessBuilder`, no second-stage
  payload); an unknown, expired, or already-triggered token returns an
  identical generic 404 either way. The route requires no authentication of
  any kind (neither `require_user` nor the internal token) - the caller is
  a probed target, which cannot present platform credentials.
- The dispatch handler: skips cleanly with no materialized IP; never polls
  for a callback when the connection itself failed; reports a
  `confidence=validated`, `severity_override=critical`,
  `evidence_basis=direct_technical_proof` finding tagged `CVE-2023-46604`
  ONLY when a callback is actually observed within the bounded wait;
  explicitly records NO finding when the packet was sent but no callback
  arrived in time (patched/filtered/slow are indistinguishable from here);
  a callback-status polling error degrades to no finding rather than
  crashing the scan.
- NEGATIVE (gateway): `activemq-openwire-probe` is unconditionally
  state-changing - a call without a risk statement is DENIED, not pending;
  an out-of-scope target is hard-denied, not pending; and critically, an
  operator (or a bug) setting the tool's own `ToolGrant.requires_manual_
  approval` to `False` does NOT bypass the mandatory approval gate, because
  the requirement comes from the hardcoded `state_changing` check, not that
  configurable field.

**Live-fire verification status:** the above is unit/integration coverage
of the tool's own logic (packet bytes, approval gate, callback plumbing).
The end-to-end claim - that the packet actually triggers the target
broker's deserialization and produces a real callback - is verified
separately, by running an actual scan against the benchmark
CVE-2023-46604 target through the real product flow (agent proposes,
operator approves, dispatch sends the real packet) rather than by a
standalone script. Record the outcome and date here once performed.
