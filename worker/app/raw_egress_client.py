"""Client for the FIFO, lease-enforcing Compose raw-egress gateway."""

from __future__ import annotations

import os
import time
from collections.abc import Callable

import httpx

RAW_EGRESS_GATEWAY_URL = os.environ.get("RAW_EGRESS_GATEWAY_URL", "http://raw-egress-gateway:8765")
RAW_EGRESS_QUEUE_WAIT_SECONDS = max(30.0, min(float(os.environ.get("RAW_EGRESS_QUEUE_WAIT_SECONDS", "1800")), 7200.0))
RAW_EGRESS_QUEUE_POLL_SECONDS = max(0.2, min(float(os.environ.get("RAW_EGRESS_QUEUE_POLL_SECONDS", "1")), 5.0))
# GitHub issue #22: shared secret authenticating the worker to the raw-egress
# gateway's reservation/lease API - mirrors RUNNER_API_TOKEN's own header
# pattern below (worker/app/tool_runner_client.py).
RAW_EGRESS_API_TOKEN = os.environ.get("RAW_EGRESS_API_TOKEN", "raw-egress-api-change-me-in-dev")

class RawEgressGatewayClient:
    def __init__(self, base_url: str = RAW_EGRESS_GATEWAY_URL, timeout: float = 5.0):
        default_headers = {"X-ASM-RawEgress-Token": RAW_EGRESS_API_TOKEN} if RAW_EGRESS_API_TOKEN else None
        self._client = httpx.Client(base_url=base_url, timeout=timeout, headers=default_headers)

    def available(self) -> bool:
        try:
            response = self._client.get("/health")
            response.raise_for_status()
            body = response.json()
            return body.get("status") == "ok" and body.get("policy_enforced") is True
        except Exception:  # noqa: BLE001
            return False

    def acquire_reservation(
        self, scan_run_id: str, *, cancel_requested: Callable[[], bool] | None = None,
        wait_seconds: float = RAW_EGRESS_QUEUE_WAIT_SECONDS,
    ) -> dict:
        deadline = time.monotonic() + max(0.1, wait_seconds)
        last: dict = {}
        reservation_token: str | None = None
        try:
            while time.monotonic() < deadline:
                if cancel_requested is not None and cancel_requested():
                    raise RuntimeError("raw_egress_queue_cancelled")
                response = self._client.post(
                    "/v1/reservations/acquire", json={"scan_run_id": scan_run_id}
                )
                response.raise_for_status()
                last = response.json()
                reservation_token = str(last.get("reservation_token") or "")
                if not reservation_token or last.get("policy_enforced") is not True:
                    raise RuntimeError("raw_egress_reservation_invalid")
                if last.get("status") == "granted":
                    return last
                if last.get("status") != "queued":
                    raise RuntimeError("raw_egress_reservation_invalid")
                time.sleep(RAW_EGRESS_QUEUE_POLL_SECONDS)
            raise TimeoutError("raw_egress_queue_timeout")
        except Exception:
            if reservation_token:
                try:
                    self.release_reservation(scan_run_id, reservation_token)
                except Exception:  # noqa: BLE001
                    pass
            raise

    def release_reservation(self, scan_run_id: str, reservation_token: str) -> dict:
        response = self._client.post("/v1/reservations/release", json={
            "scan_run_id": scan_run_id, "reservation_token": reservation_token,
        })
        response.raise_for_status()
        body = response.json()
        if body.get("status") != "released" or body.get("policy_enforced") is not True:
            raise RuntimeError("raw_egress_reservation_not_released")
        return body

    @staticmethod
    def _lease_body(lease_token: str, reservation_token: str) -> dict:
        return {"lease_token": lease_token, "reservation_token": reservation_token}

    def activate(self, lease_token: str, reservation_token: str) -> dict:
        response = self._client.post(
            "/v1/leases/activate", json=self._lease_body(lease_token, reservation_token)
        )
        response.raise_for_status()
        body = response.json()
        if body.get("status") != "active" or body.get("policy_enforced") is not True:
            raise RuntimeError("raw_egress_policy_not_enforced")
        return body

    def heartbeat(self, lease_token: str, reservation_token: str) -> dict:
        response = self._client.post(
            "/v1/leases/heartbeat", json=self._lease_body(lease_token, reservation_token)
        )
        response.raise_for_status()
        body = response.json()
        if body.get("status") != "active" or body.get("policy_enforced") is not True:
            raise RuntimeError("raw_egress_heartbeat_failed")
        return body

    def deactivate(self, lease_token: str, reservation_token: str) -> dict:
        response = self._client.post(
            "/v1/leases/deactivate", json=self._lease_body(lease_token, reservation_token)
        )
        response.raise_for_status()
        body = response.json()
        if body.get("status") != "inactive" or body.get("policy_enforced") is not True:
            raise RuntimeError("raw_egress_policy_not_revoked")
        return body

raw_egress_gateway = RawEgressGatewayClient()
