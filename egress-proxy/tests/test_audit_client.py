import io

from app import audit_client


class _Response:
    status = 201

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_proxy_submits_authenticated_structured_audit(monkeypatch):
    seen = {}

    def fake_open(request, timeout):
        seen["request"] = request
        seen["timeout"] = timeout
        return _Response()

    monkeypatch.setattr(audit_client.urllib.request, "urlopen", fake_open)
    audit_client.submit_audit("00000000-0000-0000-0000-000000000001", "DENY", "not_in_scope", {"host": "x"})
    assert seen["request"].get_header("X-asm-internal-token")
    assert b'"reason": "not_in_scope"' in seen["request"].data



def test_proxy_request_fails_closed_when_audit_is_unavailable(monkeypatch):
    import asyncio
    from app import proxy

    class Writer:
        def __init__(self):
            self.data = b""
            self.closed = False
        def write(self, data):
            self.data += data
        async def drain(self):
            return None
        def close(self):
            self.closed = True
        async def wait_closed(self):
            return None

    def unavailable(*args, **kwargs):
        raise OSError("control plane unavailable")

    monkeypatch.setattr(proxy, "submit_audit_batch", unavailable)
    writer = Writer()
    result = asyncio.run(proxy._submit_audit_or_deny(writer, "engagement", "ALLOW", "ok", {}))
    assert result is False
    assert b"HTTP/1.1 503" in writer.data
    assert b"audit_unavailable" in writer.data
