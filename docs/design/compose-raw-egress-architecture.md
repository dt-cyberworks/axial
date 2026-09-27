# Compose raw-egress architecture

Design for [REQ-SCAN-009/010](../requirements/scan-integrity.md),
[REQ-SCAN-011](../requirements/backlog-udp-discovery.md),
[REQ-SCAN-012](../requirements/backlog-nmap-gateway-queue.md), and
[REQ-SCAN-013](../requirements/backlog-engagement-port-range.md).

## Security boundary

Nmap cannot use the HTTP proxy as a transparent packet-level enforcement
layer. Compose therefore runs HexStrike in the network namespace owned by a
minimal `raw-egress-gateway`.

- The gateway owns `NET_ADMIN` and an `nftables` OUTPUT chain with default
  `drop`; the runner owns only `NET_RAW`.
- The fixed HTTP-proxy IP on port 3128 is the only baseline exception.
- Target egress needs both a FIFO queue-head reservation and a valid signed
  lease whose `scan_run_id` matches that opaque reservation.
- The kernel receives only the audited target IP and either the persisted TCP
  interval or fixed targeted UDP ports. TCP and UDP use separate nft sets.
- Neither service has the Docker socket or a DB/control-plane data route.

## Reservation and lease sequence

```mermaid
sequenceDiagram
    participant CP as Control plane / Scope Gateway
    participant WK as Worker
    participant RG as Raw-egress gateway
    participant TR as Tool runner / Nmap
    participant T as Materialized target IP

    WK->>RG: reserve(scan_run_id)
    alt another run owns the gateway
        RG-->>WK: queued(position, opaque token)
        WK->>RG: poll same reservation
    end
    RG-->>WK: granted(opaque token)
    WK->>CP: request configured_tcp lease(run, hostname, audited IP)
    CP->>CP: scope + persisted engagement range + args + rate + budget
    CP-->>WK: signed TCP lease(IP, exact range, nonce, expiry)
    WK->>RG: activate(lease, reservation token)
    RG->>RG: verify run match; install 12s kernel target timeout
    loop while Nmap invocation is alive
        WK->>RG: heartbeat(lease, reservation token)
        RG->>RG: refresh exact target timeout
    end
    WK->>TR: TCP discovery for exact configured range
    TR->>T: only admitted TCP packets
    WK->>TR: -sV only for confirmed-open TCP ports
    WK->>RG: deactivate TCP lease in finally
    opt engagement UDP opt-in
        WK->>CP: request targeted_udp lease
        CP-->>WK: signed exact nine-port UDP lease
        WK->>RG: activate + heartbeat
        WK->>TR: bounded UDP discovery
        TR->>T: only admitted UDP packets
        WK->>TR: -sU -sV only for confirmed-open UDP ports
        WK->>RG: deactivate UDP lease in finally
    end
    WK->>RG: release reservation
    RG->>RG: promote next live FIFO waiter
```

A reservation is scheduling metadata, not authorization, and installs no
firewall target. Signed capabilities can therefore be issued only after the run
reaches the queue head instead of expiring while it waits.

## Lifetime and crash behavior

The active kernel target element has a 12-second timeout, refreshed every three
seconds while the worker is inside the Nmap invocation. Normal completion
flushes target plus TCP/UDP port sets immediately. If the worker dies, the
heartbeat stops and both the timer and kernel timeout close target egress. If
the gateway process dies while its shared namespace survives, the kernel target
still expires independently. The longer signed-token expiry is only an upper
bound; it is not the active network lifetime.

Queue entries must poll to stay live. Stale queued entries and inactive granted
heads expire, capacity is bounded, cancellations release their entry, and only
the queue head can activate. The gateway never replaces an active target.

## Nmap profiles

`configured_tcp` is derived from `engagement.tcp_port_from/to` (default
`1-65535`; equal bounds mean one port):

1. discovery: `-sS -Pn -n -p <exact-range>`, `-T3`, bounded rate/retries and
   timeout, XML output;
2. service detection: `-sV --version-light` only for sorted confirmed-open
   ports in bounded batches.

`targeted_udp` is disabled by default and fixed to
`53,123,161,443,500,1900,4500,5060,5353`:

1. discovery: `-sU -Pn -n`, lower rate/retry bounds, XML output;
2. persist counts for `open`, `closed`, `filtered`, and `open|filtered`;
3. run `-sU -sV` only on confirmed `open` ports.

Arbitrary/disjoint ranges, full UDP, LLM-controlled flags, and bug-bounty raw
Nmap without deterministic program permission remain denied.

## Kubernetes

Kubernetes continues toward one labeled runner Job and generated NetworkPolicy
per engagement. The Compose FIFO is a shared-namespace scheduling control, not
a reason to multiplex mutable target policy inside a Kubernetes Job.
