"""REQ-EGRESS-010 (GitHub #81): the loopback forwarder that carries the run token for the tools that cannot.

The real forwarder runs, in-process and as a subprocess, against a stand-in upstream proxy that records exactly what it
received. The question each test asks is what reaches the egress proxy and what does not."""

from __future__ import annotations

import asyncio
import base64
import os
import pathlib
import socket
import subprocess
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import egress_forwarder as fw  # noqa: E402

SCRIPT = pathlib.Path(fw.__file__)
TOKEN = ".".join(["v1", "eyJlIjoiMSJ9", "c2lnbmF0dXJl"])
BASIC = "Basic " + base64.b64encode(f"asm:{TOKEN}".encode()).decode()


class Upstream:
    """Stand-in egress proxy: records every head it receives and answers like the real one would."""

    def __init__(self):
        self.heads: list[bytes] = []
        self.bodies: list[bytes] = []
        self.tunnel_echo = True
        self.server = None
        self.port = 0

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = await reader.read(4096)
            if not chunk:
                writer.close()
                return
            buffer += chunk
        head, _, rest = buffer.partition(b"\r\n\r\n")
        self.heads.append(head)
        if head.startswith(b"CONNECT"):
            writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: stand-in\r\n\r\n")
            await writer.drain()
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                self.bodies.append(data)
                if self.tunnel_echo:
                    writer.write(b"echo:" + data)
                    await writer.drain()
        else:
            self.bodies.append(rest)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
        writer.close()

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()


async def _start(upstream: Upstream, port_file, **kwargs):
    task = asyncio.ensure_future(fw.serve(("127.0.0.1", upstream.port), fw.authorization_value("asm", TOKEN), str(port_file), kwargs.get("max_lifetime")))
    for _ in range(100):
        if port_file.exists() and port_file.read_text().strip():
            return task, int(port_file.read_text())
        await asyncio.sleep(0.05)
    raise AssertionError("the forwarder never wrote its port")


async def _exchange(port: int, payload: bytes, *, read: int = 4096, wait: float = 0.3) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    await asyncio.sleep(wait)
    data = b""
    try:
        data = await asyncio.wait_for(reader.read(read), timeout=3)
    except asyncio.TimeoutError:
        pass
    writer.close()
    return data


def _run(coro):
    return asyncio.run(coro)


# --- what reaches the proxy ------------------------------------------------------------------------------------------

def test_the_credentials_are_added_to_a_connect_and_the_tunnel_stays_opaque(tmp_path):
    async def scenario():
        up = Upstream()
        await up.start()
        task, port = await _start(up, tmp_path / "port")
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"CONNECT host.example:443 HTTP/1.1\r\nHost: host.example:443\r\n\r\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3)
        writer.write(b"\x16\x03\x01 raw tls bytes")
        await writer.drain()
        echoed = await asyncio.wait_for(reader.read(100), timeout=3)
        writer.close()
        await asyncio.sleep(0.1)
        task.cancel()
        await up.stop()
        return up, reply, echoed

    up, reply, echoed = _run(scenario())
    assert reply.startswith(b"HTTP/1.1 200 Connection Established")
    assert echoed == b"echo:\x16\x03\x01 raw tls bytes" and up.bodies == [b"\x16\x03\x01 raw tls bytes"]
    head = up.heads[0].decode()
    assert head.splitlines()[0] == "CONNECT host.example:443 HTTP/1.1"
    assert f"Proxy-Authorization: {BASIC}" in head and "Host: host.example:443" in head


def test_the_credentials_are_added_to_a_plain_http_request_and_its_body_is_forwarded(tmp_path):
    async def scenario():
        up = Upstream()
        await up.start()
        task, port = await _start(up, tmp_path / "port")
        got = await _exchange(port, b"POST http://host.example/x HTTP/1.1\r\nHost: host.example\r\nContent-Length: 5\r\n\r\nhello")
        task.cancel()
        await up.stop()
        return up, got

    up, got = _run(scenario())
    assert got.endswith(b"ok") and up.bodies == [b"hello"]
    assert up.heads[0].decode().count("Proxy-Authorization:") == 1 and BASIC in up.heads[0].decode()


@pytest.mark.parametrize("supplied", ["Proxy-Authorization: Basic Zm9yZ2VkOnRva2Vu", "proxy-authorization: Basic Zm9yZ2Vk", "PROXY-AUTHORIZATION: x"])
def test_negative_a_client_cannot_supply_or_override_the_identity(tmp_path, supplied):
    async def scenario():
        up = Upstream()
        await up.start()
        task, port = await _start(up, tmp_path / "port")
        await _exchange(port, f"GET http://host.example/ HTTP/1.1\r\nHost: host.example\r\n{supplied}\r\nX-Other: kept\r\n\r\n".encode())
        task.cancel()
        await up.stop()
        return up

    head = _run(scenario()).heads[0].decode()
    assert head.lower().count("proxy-authorization:") == 1 and BASIC in head
    assert "Zm9yZ2Vk" not in head and "X-Other: kept" in head


def test_negative_it_is_not_an_open_proxy_every_connection_goes_to_the_one_upstream(tmp_path):
    """Whatever the client asks for, the bytes go to the configured upstream - which is where scope is decided."""
    async def scenario():
        up = Upstream()
        await up.start()
        task, port = await _start(up, tmp_path / "port")
        await _exchange(port, b"CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n", wait=0.2)
        await _exchange(port, b"GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        task.cancel()
        await up.stop()
        return up

    up = _run(scenario())
    assert [h.split(b"\r\n")[0] for h in up.heads] == [b"CONNECT 169.254.169.254:80 HTTP/1.1", b"GET http://127.0.0.1:1/ HTTP/1.1"]


def test_it_writes_the_port_once_listening_and_leaves_no_temporary_file(tmp_path):
    async def scenario():
        up = Upstream()
        await up.start()
        task, port = await _start(up, tmp_path / "port")
        task.cancel()
        await up.stop()
        return port

    port = _run(scenario())
    assert 1024 <= port <= 65535
    assert not list(tmp_path.glob("port.tmp")), "the temporary file is renamed away"


def test_the_bind_address_is_the_loopback_interface_not_all_interfaces():
    source = SCRIPT.read_text()
    assert 'host="127.0.0.1"' in source and '"0.0.0.0"' not in source


# --- failure behavior ------------------------------------------------------------------------------------------------

def test_negative_an_unreachable_upstream_is_a_visible_502_never_a_direct_connection(tmp_path):
    async def scenario():
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()
        up = Upstream()
        up.port = dead_port
        task, port = await _start(up, tmp_path / "port")
        got = await _exchange(port, b"CONNECT host.example:443 HTTP/1.1\r\n\r\n")
        task.cancel()
        return got

    got = _run(scenario())
    assert got.startswith(b"HTTP/1.1 502") and b"forwarder_upstream_unavailable" in got


def test_negative_a_head_that_is_too_large_or_never_finishes_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, "HEAD_READ_TIMEOUT_S", 0.5)

    async def scenario():
        up = Upstream()
        await up.start()
        task, port = await _start(up, tmp_path / "port")
        slow = await _exchange(port, b"GET http://x/ HTTP/1.1\r\nHost: x\r\n", wait=1.0)      # never ends the head
        big = await _exchange(port, b"GET http://x/ HTTP/1.1\r\n" + b"X: " + b"a" * 80000 + b"\r\n\r\n")
        task.cancel()
        await up.stop()
        return up, slow, big

    up, slow, big = _run(scenario())
    assert slow.startswith(b"HTTP/1.1 408")
    assert big.startswith(b"HTTP/1.1 408") or big == b""
    assert up.heads == [], "nothing incomplete or oversized reached the proxy"


# --- starting, the credential and cleanup ----------------------------------------------------------------------------

@pytest.mark.parametrize("env", [{}, {fw.CREDENTIAL_ENV: ""}, {fw.CREDENTIAL_ENV: "a b"}, {fw.CREDENTIAL_ENV: "a;b"}, {fw.CREDENTIAL_ENV: "$(id)"},
                                  {fw.CREDENTIAL_ENV: "x" * 1025}, {fw.CREDENTIAL_ENV: "é"}])
def test_negative_it_refuses_to_start_without_a_safe_credential(tmp_path, env, capsys, monkeypatch):
    monkeypatch.setattr(fw.asyncio, "run", lambda coro: (coro.close(), pytest.fail("the forwarder started"))[1])
    code = fw.main(["--upstream", "egress-proxy:3128", "--port-file", str(tmp_path / "p")], environ=env)
    assert code == 2 and not (tmp_path / "p").exists()
    assert "credential" in capsys.readouterr().err


@pytest.mark.parametrize("upstream", ["", "egress-proxy", "egress-proxy:0", "egress-proxy:99999", "a b:3128", "http://egress-proxy:3128", ";x:1", "-bad:1"])
def test_negative_it_refuses_an_upstream_that_is_not_host_and_port(tmp_path, upstream, monkeypatch):
    monkeypatch.setattr(fw.asyncio, "run", lambda coro: (coro.close(), pytest.fail("the forwarder started"))[1])
    assert fw.main([f"--upstream={upstream}", "--port-file", str(tmp_path / "p")], environ={fw.CREDENTIAL_ENV: TOKEN}) == 2


def test_negative_it_refuses_an_unsafe_user_name(tmp_path, monkeypatch):
    monkeypatch.setattr(fw.asyncio, "run", lambda coro: (coro.close(), pytest.fail("the forwarder started"))[1])
    assert fw.main(["--upstream", "a:1", "--user", "a:b", "--port-file", str(tmp_path / "p")], environ={fw.CREDENTIAL_ENV: TOKEN}) == 2


def _spawn(tmp_path, upstream_port, *, lifetime="30", parent=None):
    env = {**os.environ, fw.CREDENTIAL_ENV: TOKEN}
    cmd = [sys.executable, str(SCRIPT), "--upstream", f"127.0.0.1:{upstream_port}", "--port-file", str(tmp_path / "port"), "--max-lifetime", lifetime]
    return subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _wait_for_port(tmp_path):
    for _ in range(100):
        if (tmp_path / "port").exists() and (tmp_path / "port").read_text().strip():
            return int((tmp_path / "port").read_text())
        time.sleep(0.05)
    raise AssertionError("no port")


def test_negative_the_credential_is_never_on_the_command_line_or_in_the_output(tmp_path):
    process = _spawn(tmp_path, 9)
    try:
        _wait_for_port(tmp_path)
        cmdline = pathlib.Path(f"/proc/{process.pid}/cmdline").read_bytes().decode()
        assert TOKEN not in cmdline and "asm:" not in cmdline
        environ = pathlib.Path(f"/proc/{process.pid}/environ").read_bytes().decode()
        assert TOKEN in environ, "it is in the environment of that one process, as designed"
    finally:
        process.terminate()
        out, err = process.communicate(timeout=5)
    assert TOKEN.encode() not in out + err


def test_it_stops_after_its_maximum_lifetime(tmp_path):
    process = _spawn(tmp_path, 9, lifetime="2")
    _wait_for_port(tmp_path)
    assert process.wait(timeout=8) == 0


def test_it_stops_when_the_shell_that_started_it_is_gone(tmp_path):
    """The runner kills a command's process group; this covers the case where only the shell is killed."""
    env = {**os.environ, fw.CREDENTIAL_ENV: TOKEN}
    shell = subprocess.Popen(
        ["sh", "-c", f"{sys.executable} {SCRIPT} --upstream 127.0.0.1:9 --port-file {tmp_path}/port --max-lifetime 60 & echo $! ; sleep 30"],
        env=env, stdout=subprocess.PIPE, text=True,
    )
    pid = int(shell.stdout.readline())
    _wait_for_port(tmp_path)
    shell.kill()
    shell.wait()
    for _ in range(80):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    os.kill(pid, 9)
    raise AssertionError("the forwarder outlived its shell")


@pytest.mark.parametrize("head", [
    b"CONNECT host.example:443 HTTP/1.0\n\n",                                  # testssl: bare LF, no headers
    b"CONNECT host.example:443 HTTP/1.1\nHost: host.example:443\n\n",
    b"CONNECT host.example:443 HTTP/1.1\r\nHost: host.example:443\n\n",      # mixed endings
])
def test_a_client_that_ends_its_lines_with_a_bare_lf_is_served_too(tmp_path, head):
    """Found with the real testssl: it sends `CONNECT ip:443 HTTP/1.0` + LF LF. Waiting for CRLF CRLF made it time out."""
    async def scenario():
        up = Upstream()
        await up.start()
        task, port = await _start(up, tmp_path / "port")
        got = await _exchange(port, head, wait=0.4)
        task.cancel()
        await up.stop()
        return up, got

    up, got = _run(scenario())
    assert got.startswith(b"HTTP/1.1 200 Connection Established")
    sent = up.heads[0]
    assert b"\n\n" not in sent.replace(b"\r\n", b"") and BASIC.encode() in sent
    assert sent.splitlines()[0].startswith(b"CONNECT host.example:443")


def test_negative_a_bare_cr_or_lf_inside_a_header_value_cannot_inject_a_second_header(tmp_path):
    """The head is normalized to CRLF lines; a client cannot smuggle a Proxy-Authorization of its own in that way."""
    head = fw.rewrite_head(b"GET http://x/ HTTP/1.1\nHost: x\nproxy-authorization: Basic Zm9yZ2Vk\n", "Basic ours")
    assert head.count(b"Proxy-Authorization: Basic ours") == 1 and b"Zm9yZ2Vk" not in head
    assert head.endswith(b"\r\n\r\n") and b"\n\n" not in head.replace(b"\r\n", b"")


def test_rewrite_head_keeps_every_other_line_in_order_and_ends_with_a_blank_line():
    head = b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\nProxy-Authorization: x\r\nUser-Agent: u"
    out = fw.rewrite_head(head, "Basic abc")
    assert out == b"CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic abc\r\nHost: a:443\r\nUser-Agent: u\r\n\r\n"
