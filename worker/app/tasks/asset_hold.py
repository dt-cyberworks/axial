"""New-asset policy of a monitoring engagement (REQ-MODE-008).

After discovery, a host that is new to the engagement and not itself a declared
scope value is held: it is inventoried, shows up in the inbox, and receives no
active check until a person acknowledges it. This is the unattended form of the
asset review: it never waits, it simply leaves the host out of this run.

Scoped runs (REQ-MODE-017) use the same place to leave out what was not asked for.
The control plane decides which hosts are held; the worker only applies it and
fails closed (tests nothing) when it cannot ask.
"""

from __future__ import annotations

import logging

from app.control_plane_client import client

logger = logging.getLogger(__name__)


def apply(scan_run_id: str, discovered: list[dict]) -> list[dict]:
    info = client.run_info(scan_run_id)
    if info.get("operating_mode") != "monitoring" or not discovered:
        return discovered
    try:
        result = client.evaluate_hold(scan_run_id, [
            {"asset_id": a["asset_id"], "value": a.get("value")} for a in discovered if a.get("asset_id")
        ])
    except Exception as exc:  # noqa: BLE001
        logger.warning("hold policy could not be evaluated, testing no discovered host: %s", exc)
        return []
    held = {str(i) for i in result.get("held", [])}
    kept = [a for a in discovered if str(a.get("asset_id")) not in held]
    if held:
        logger.info("scan_run %s: %d new host(s) held until acknowledged", scan_run_id, len(held))
    return kept


def limit_to_hosts(discovered: list[dict], scope_hosts: list[str] | None) -> list[dict]:
    """REQ-MODE-017: a run limited to some hosts tests those and nothing else."""
    if not scope_hosts:
        return discovered
    wanted = {h.lower().rstrip(".") for h in scope_hosts}
    return [a for a in discovered if str(a.get("value", "")).lower().rstrip(".") in wanted]
