#!/usr/bin/env python3
"""Loopback forwarder that adds the run's proxy credentials for a tool that cannot send them (REQ-EGRESS-010, GitHub #81).

The egress proxy learns the engagement of a request from a signed run token that the tool presents as proxy
credentials (`http://asm:<token>@egress-proxy:3128`). Most tools can. testssl takes `--proxy host:port` only, and
Chromium refuses a proxy URL with credentials (ERR_NO_SUPPORTED_PROXIES). For those the command starts this forwarder
for its own lifetime and points the tool at it:

    tool --(plain proxy, 127.0.0.1:<port>)--> forwarder --(adds Proxy-Authorization)--> egress proxy

It is a pass-through, not a proxy of its own: every connection goes to the ONE upstream named at start, whatever the
client asked for, so it decides nothing about scope (the egress proxy still does) and cannot be steered to another
destination. It changes exactly one thing in the request head - the Proxy-Authorization header, which it sets and
never takes from the client - and relays every other byte unchanged in both directions (a CONNECT tunnel stays opaque).

    ASM_PROXY_CREDENTIAL=<token> python3 egress_forwarder.py --upstream egress-proxy:3128 --user asm --port-file F

The credential comes from the environment, never from the command line. The port is chosen by the system and written to
the port file once the forwarder is listening. It stops when its parent process is gone, after --max-lifetime seconds,
or when it is killed (the runner kills a command's whole process group). Standard library only.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import os
import re
import sys
import time

CREDENTIAL_ENV = "ASM_PROXY_CREDENTIAL"
_CREDENTIAL_RE = re.compile(r"^[A-Za-z0-9._-]{1,1024}$")
_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_UPSTREAM_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9.-]{0,252}):([0-9]{1,5})$")

HEAD_READ_TIMEOUT_S = 10.0
MAX_HEAD_BYTES = 65536
RELAY_CHUNK = 65536
IDLE_TIMEOUT_S = 300.0
EOF_GRACE_S = 5.0
MAX_CONNECTIONS = 64
UPSTREAM_CONNECT_TIMEOUT_S = 10.0
PARENT_CHECK_S = 1.0


class StartError(Exception):
    pass


def parse_upstream(text: str) -> tuple[str, int]:
    match = _UPSTREAM_RE.match(text or "")
    if not match or not 1 <= int(match.group(2)) <= 65535:
        raise StartError("upstream must be host:port")
    return match.group(1), int(match.group(2))


def authorization_value(user: str, credential: str) -> str:
    if not _USER_RE.match(user or ""):
        raise StartError("unsafe user name")
    if not _CREDENTIAL_RE.match(credential or ""):
        raise StartError("the credential is missing or unsafe")
    return "Basic " + base64.b64encode(f"{user}:{credential}".encode("ascii")).decode("ascii")


def _split_head(buffer: bytes) -> tuple[bytes, bytes] | None:
    """(head without its blank line, whatever follows) once the blank line has arrived, else None. A client may end its
    lines with CRLF or with a bare LF (testssl does); whichever blank line comes first ends the head."""
    ends = [(buffer.find(marker), marker) for marker in (b"\r\n\r\n", b"\n\n")]
    found = [(at, marker) for at, marker in ends if at >= 0]
    if not found:
        return None
    at, marker = min(found)
    return buffer[:at], buffer[at + len(marker):]


def rewrite_head(head: bytes, authorization: str) -> bytes:
    """The request head with Proxy-Authorization set to ours: any the client sent is dropped first, so the client can
    neither supply nor override the identity. The result always uses CRLF and ends with the blank line."""
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    request_line, headers = lines[0].rstrip(b"\r"), lines[1:]
    kept = [h.rstrip(b"\r") for h in headers if h.strip() and not h.lower().startswith(b"proxy-authorization:")]
    return b"\r\n".join([request_line, b"Proxy-Authorization: " + authorization.encode("ascii"), *kept]) + b"\r\n\r\n"


async def _read_head(reader: asyncio.StreamReader) -> tuple[bytes, bytes] | None:
    """(head without its blank line, bytes read beyond it), or None when the client is too slow, too large or gone."""
    buffer = b""
    deadline = time.monotonic() + HEAD_READ_TIMEOUT_S
    while True:
        split = _split_head(buffer)
        if split is not None:
            return split if len(split[0]) <= MAX_HEAD_BYTES else None
        remaining = deadline - time.monotonic()
        if remaining <= 0 or len(buffer) > MAX_HEAD_BYTES:
            return None
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
        except asyncio.TimeoutError:
            return None
        if not chunk:
            return None
        buffer += chunk


async def _pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            try:
                chunk = await asyncio.wait_for(src.read(RELAY_CHUNK), timeout=IDLE_TIMEOUT_S)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            if dst.can_write_eof():
                dst.write_eof()
        except (ConnectionError, OSError, RuntimeError):
            pass


async def _relay(a_reader, a_writer, b_reader, b_writer) -> None:
    first = asyncio.ensure_future(_pump(a_reader, b_writer))
    second = asyncio.ensure_future(_pump(b_reader, a_writer))
    done, pending = await asyncio.wait({first, second}, return_when=asyncio.FIRST_COMPLETED)
    if pending:
        # One side ended: give the other a moment to deliver what is in flight (a TLS close_notify answer), then stop.
        await asyncio.wait(pending, timeout=EOF_GRACE_S)
        for task in pending:
            task.cancel()


class Forwarder:
    def __init__(self, upstream: tuple[str, int], authorization: str):
        self.upstream = upstream
        self.authorization = authorization
        self._slots = asyncio.Semaphore(MAX_CONNECTIONS)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._slots.locked():
            await self._refuse(writer, 503, "forwarder_busy")
            return
        async with self._slots:
            try:
                await self._serve(reader, writer)
            except (ConnectionError, OSError):
                pass
            finally:
                writer.close()

    async def _serve(self, reader, writer) -> None:
        got = await _read_head(reader)
        if got is None:
            await self._refuse(writer, 408, "forwarder_head_unreadable")
            return
        head, rest = got
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(*self.upstream), timeout=UPSTREAM_CONNECT_TIMEOUT_S,
            )
        except (OSError, asyncio.TimeoutError):
            await self._refuse(writer, 502, "forwarder_upstream_unavailable")
            return
        try:
            up_writer.write(rewrite_head(head, self.authorization) + rest)
            await up_writer.drain()
            await _relay(reader, writer, up_reader, up_writer)
        finally:
            up_writer.close()

    @staticmethod
    async def _refuse(writer: asyncio.StreamWriter, code: int, reason: str) -> None:
        body = reason.encode()
        try:
            writer.write(
                f"HTTP/1.1 {code} Blocked\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
            )
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        writer.close()


def _write_port_file(path: str, port: int) -> None:
    temporary = f"{path}.tmp"
    with open(temporary, "w", encoding="ascii") as handle:
        handle.write(str(port))
    os.replace(temporary, path)  # the reader sees either nothing or the whole number


async def _watch_parent(parent_pid: int, deadline: float | None, server: asyncio.AbstractServer) -> None:
    while True:
        await asyncio.sleep(PARENT_CHECK_S)
        if os.getppid() != parent_pid or (deadline is not None and time.monotonic() >= deadline):
            server.close()
            return


async def serve(upstream: tuple[str, int], authorization: str, port_file: str, max_lifetime: float | None) -> None:
    forwarder = Forwarder(upstream, authorization)
    server = await asyncio.start_server(forwarder.handle, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    _write_port_file(port_file, port)
    deadline = None if not max_lifetime else time.monotonic() + max_lifetime
    watcher = asyncio.ensure_future(_watch_parent(os.getppid(), deadline, server))
    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        watcher.cancel()


def main(argv: list[str] | None = None, environ: dict[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--upstream", required=True, help="host:port of the egress proxy")
    parser.add_argument("--user", default="asm")
    parser.add_argument("--port-file", required=True, help="where the chosen port is written once listening")
    parser.add_argument("--max-lifetime", type=float, default=3600.0, help="seconds; 0 = no limit")
    args = parser.parse_args(argv)
    environ = os.environ if environ is None else environ
    try:
        upstream = parse_upstream(args.upstream)
        authorization = authorization_value(args.user, environ.get(CREDENTIAL_ENV, ""))
    except StartError as exc:
        print(f"egress_forwarder: {exc}", file=sys.stderr)
        return 2
    try:
        asyncio.run(serve(upstream, authorization, args.port_file, args.max_lifetime))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
