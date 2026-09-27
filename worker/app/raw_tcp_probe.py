"""Lease-bound curated raw-protocol probes (REQ-AGENT-025).

Mirrors raw_nmap.py's acquire-lease -> activate -> execute -> deactivate
shape (same signed-lease/nftables safety boundary nmap already goes
through), deliberately WITHOUT a heartbeat thread: a probe is a single
sub-second connect/read/close, not a multi-second scan, so it comfortably
finishes within the lease's own minimum TTL (>=60s) without needing to keep
extending it.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.raw_egress_client import raw_egress_gateway
from app.tool_runner_client import tool_runner

# Protocol name (matches the tool name and worker/app/tool_runner_client.py's
# own registry) -> conventional default port, used only when the engagement
# is not restricted to a single non-standard port (REQ-FIDELITY-007's
# single_port takes precedence when set - see dispatch.py).
DEFAULT_PORTS = {
    "redis-probe": 6379,
    "activemq-banner": 61616,
    "activemq-openwire-probe": 61616,
}


def _failed(reason: str, detail: str = "") -> dict:
    return {
        "stdout": "", "stderr": (detail or reason)[:1000],
        "exit_code": -1, "success": False, "error_reason": reason,
    }


@dataclass(frozen=True)
class RawProbeOutcome:
    result: dict
    port: int


def resolve_port(tool: str, single_port: int | None) -> int:
    """REQ-FIDELITY-007: an engagement restricted to one non-standard port
    (as every benchmark VM target this session is) means the probe's real
    port IS that configured port, not the protocol's conventional default -
    the benchmark VM's own NAT/hostfwd remaps ports, so "6379" would be
    wrong there even though it is the right default for a normal, un-NAT'd
    deployment. single_port always wins when set."""
    return single_port if single_port is not None else DEFAULT_PORTS[tool]


def execute_probe(
    engagement_id: str, scan_run_id: str, tool: str, authorized_target: str, ip: str,
    *, single_port: int | None = None, extra_args: dict | None = None,
) -> RawProbeOutcome:
    from app.control_plane_client import client
    import uuid as _uuid

    port = resolve_port(tool, single_port)
    reservation_token: str | None = None
    try:
        reservation = raw_egress_gateway.acquire_reservation(
            scan_run_id, cancel_requested=lambda: client.is_cancel_requested(_uuid.UUID(scan_run_id)),
        )
        reservation_token = str(reservation["reservation_token"])

        lease: dict = {}
        for _ in range(8):
            lease = client.acquire_raw_egress_lease(
                _uuid.UUID(engagement_id), scan_run_id=scan_run_id,
                authorized_target=authorized_target, resolved_target=ip, phase="agent",
                port_profile="raw_tcp_probe", port=port, tool=tool,
            )
            if lease.get("allowed") or not lease.get("is_throttled"):
                break
            import time
            time.sleep(min(max(float(lease.get("retry_after_seconds") or 1.0), 0.1), 5.0))

        if not lease.get("allowed") or not lease.get("lease_token"):
            reason = str(lease.get("reason") or "raw_egress_lease_denied")
            return RawProbeOutcome(result=_failed(reason), port=port)

        lease_token = str(lease["lease_token"])
        activated = False
        try:
            raw_egress_gateway.activate(lease_token, reservation_token)
            activated = True
            result = tool_runner.run(tool, ip, {"port": port, **(extra_args or {})}, scan_run_id=scan_run_id)
        except Exception as exc:  # noqa: BLE001
            result = _failed("raw_egress_activation_or_dispatch_failed", str(exc))
        finally:
            if activated:
                try:
                    raw_egress_gateway.deactivate(lease_token, reservation_token)
                except Exception as exc:  # noqa: BLE001
                    result = dict(result)
                    result["stderr"] = (f"{result.get('stderr') or ''}\nraw_egress_revoke_failed:{exc}").strip()[:1000]
        return RawProbeOutcome(result=result, port=port)
    except Exception as exc:  # noqa: BLE001
        return RawProbeOutcome(result=_failed("raw_egress_reservation_failed", str(exc)), port=port)
    finally:
        if reservation_token is not None:
            try:
                raw_egress_gateway.release_reservation(scan_run_id, reservation_token)
            except Exception:  # noqa: BLE001
                pass
