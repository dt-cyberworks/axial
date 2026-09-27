import asyncio

from app import proxy


class _Writer:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data):
        self.data += data

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    def get_extra_info(self, _name):
        return None


def test_excess_clients_fail_closed_and_capacity_recovers(monkeypatch):
    entered = asyncio.Event()
    release = asyncio.Event()
    handled = []

    async def fake_inner(_reader, writer):
        handled.append(writer)
        entered.set()
        await release.wait()

    async def scenario():
        monkeypatch.setattr(proxy, "_CLIENT_SLOTS", asyncio.Semaphore(1))
        monkeypatch.setattr(proxy, "_handle_client", fake_inner)
        first = _Writer()
        excess = _Writer()
        recovered = _Writer()

        first_task = asyncio.create_task(proxy.handle_client(object(), first))
        await entered.wait()
        await proxy.handle_client(object(), excess)
        assert b"HTTP/1.1 503" in excess.data
        assert b"proxy_capacity_exhausted" in excess.data
        assert excess.closed

        release.set()
        await first_task
        release.clear()
        entered.clear()
        recovered_task = asyncio.create_task(proxy.handle_client(object(), recovered))
        await entered.wait()
        release.set()
        await recovered_task
        assert handled == [first, recovered]

    asyncio.run(scenario())
