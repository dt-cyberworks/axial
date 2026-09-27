import pytest

from app import raw_egress_client

class _Response:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")
    def json(self):
        return self._payload

class _Http:
    def __init__(self, acquire):
        self.acquire = list(acquire)
        self.calls = []
    def post(self, path, json):
        self.calls.append((path, json))
        if path.endswith("/acquire"):
            return _Response(self.acquire.pop(0))
        return _Response({"status": "released", "policy_enforced": True})

def test_client_polls_fifo_queue_until_granted(monkeypatch):
    client = raw_egress_client.RawEgressGatewayClient("http://gateway")
    client._client = _Http([
        {"status": "queued", "reservation_token": "slot", "position": 2, "policy_enforced": True},
        {"status": "granted", "reservation_token": "slot", "position": 0, "policy_enforced": True},
    ])
    monkeypatch.setattr(raw_egress_client.time, "sleep", lambda _: None)
    result = client.acquire_reservation("22222222-2222-2222-2222-222222222222", wait_seconds=1)
    assert result["status"] == "granted"
    assert [call[0] for call in client._client.calls] == [
        "/v1/reservations/acquire", "/v1/reservations/acquire",
    ]

def test_client_cancellation_removes_queued_reservation(monkeypatch):
    client = raw_egress_client.RawEgressGatewayClient("http://gateway")
    client._client = _Http([
        {"status": "queued", "reservation_token": "slot", "position": 1, "policy_enforced": True},
    ])
    monkeypatch.setattr(raw_egress_client.time, "sleep", lambda _: None)
    checks = iter([False, True])
    with pytest.raises(RuntimeError, match="raw_egress_queue_cancelled"):
        client.acquire_reservation(
            "22222222-2222-2222-2222-222222222222",
            cancel_requested=lambda: next(checks), wait_seconds=1,
        )
    assert client._client.calls[-1][0] == "/v1/reservations/release"
