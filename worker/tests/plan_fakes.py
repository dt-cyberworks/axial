"""An in-memory stand-in for the control plane's scan-plan endpoints, so a test
can drive discovery -> plan -> execution end to end without a network. It keeps
the same rules the real store keeps: rows are created idempotently, ordered by
`seq`, and a check's state only moves through the executor's updates."""

from __future__ import annotations

import copy
import itertools


class FakePlanStore:
    def __init__(self) -> None:
        self.surfaces: dict[str, dict] = {}
        self.checks: dict[str, dict] = {}
        self._ids = itertools.count(1)
        self._seq = itertools.count(1)
        self.check_updates: list[tuple[str, dict]] = []
        self.checkpoint: dict = {}

    # -- control-plane client surface -------------------------------------------------
    def store_scan_plan(self, scan_run_id, surfaces):
        created = 0
        for row in surfaces:
            key = next((sid for sid, s in self.surfaces.items() if (s["host"], s["port"]) == (row["host"], row["port"])), None)
            if key is None:
                key = f"s{next(self._ids)}"
                self.surfaces[key] = {k: copy.deepcopy(v) for k, v in row.items() if k != "checks"} | {"id": key, "checks": []}
            existing = {c["check_id"] for c in self.checks.values() if c["surface_id"] == key}
            for check in row.get("checks", []):
                if check["check_id"] in existing:
                    continue
                cid = f"c{next(self._ids)}"
                self.checks[cid] = {
                    "id": cid, "surface_id": key, "seq": next(self._seq), "attempt": 0, "findings": 0,
                    "outcome_summary": {}, "duration_s": None, "started_at": None, "finished_at": None,
                    **copy.deepcopy(check),
                }
                created += 1
        return {"surfaces_created": len(self.surfaces), "checks_created": created}

    def get_scan_plan(self, scan_run_id):
        surfaces = []
        for sid, surface in self.surfaces.items():
            checks = sorted((copy.deepcopy(c) for c in self.checks.values() if c["surface_id"] == sid), key=lambda c: c["seq"])
            surfaces.append({**copy.deepcopy(surface), "checks": checks})
        return {"scan_run_id": str(scan_run_id), "surfaces": surfaces}

    def update_scan_check(self, scan_run_id, check_id, **fields):
        self.check_updates.append((check_id, dict(fields)))
        row = self.checks[check_id]
        state = fields.get("state")
        if state == "running":
            row["attempt"] += 1
        for key in ("state", "reason", "args", "budget_s", "findings", "duration_s", "outcome_summary"):
            if key in fields and fields[key] is not None:
                row[key] = copy.deepcopy(fields[key])
        return copy.deepcopy(row)

    def update_scan_surface(self, scan_run_id, surface_id, **fields):
        if fields.get("profile") is not None:
            self.surfaces[surface_id]["profile"] = list(fields["profile"])
        return {"id": surface_id}

    def update_scan_run(self, scan_run_id, **fields):
        self.checkpoint.update(fields.get("checkpoint") or {})
        return {}

    # -- helpers for assertions -------------------------------------------------------
    def check(self, host: str, check_id: str, port: int | None = None) -> dict:
        for sid, surface in self.surfaces.items():
            if surface["host"] == host and (port is None or surface["port"] == port):
                for c in self.checks.values():
                    if c["surface_id"] == sid and c["check_id"] == check_id:
                        return c
        raise KeyError((host, check_id))

    def states(self, host: str, port: int | None = None) -> dict[str, str]:
        out = {}
        for sid, surface in self.surfaces.items():
            if surface["host"] == host and (port is None or surface["port"] == port):
                out.update({c["check_id"]: c["state"] for c in self.checks.values() if c["surface_id"] == sid})
        return out


def install(monkeypatch, client) -> FakePlanStore:
    """Route the worker's plan calls to a fresh in-memory store."""
    store = FakePlanStore()
    for name in ("store_scan_plan", "get_scan_plan", "update_scan_check", "update_scan_surface", "update_scan_run"):
        monkeypatch.setattr(client, name, getattr(store, name), raising=False)
    return store
