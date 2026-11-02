"""REQ-EGRESS-010 (GitHub #81): testssl and the screenshot browser cannot send proxy credentials, so their command runs a
loopback forwarder that does. These tests build the real command with the real runner client and RUN it in a real shell,
against the real forwarder file, a stand-in egress proxy that records what it receives, and stand-in `testssl` and
`chromium` programs that behave like the real ones in the one way that matters here: they speak to the proxy they are
told to use, with no credentials of their own."""

from __future__ import annotations

import base64
import os
import pathlib
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
from types import SimpleNamespace

import pytest

from app import tool_runner_client as trc

REPO = pathlib.Path(__file__).resolve().parents[2]
FORWARDER = REPO / "tool-runner" / "egress_forwarder.py"
TOKEN = ".".join(["v1", "eyJlIjoiMSJ9", "c2lnbmF0dXJl"])
RUN = "22222222-2222-4222-8222-222222222222"
BASIC = "Basic " + base64.b64encode(f"asm:{TOKEN}".encode()).decode()


class StandInProxy:
    """Records the head of every connection and answers CONNECT with 200 and anything else with 200 OK."""

    def __init__(self):
        self.heads: list[str] = []
        self._server = socket.socket()
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(16)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while True:
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.heads.append(data.split(b"\r\n\r\n")[0].decode("latin-1"))
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: stand-in\r\n\r\n")
            time.sleep(0.2)
        finally:
            conn.close()

    def close(self):
        self._server.close()


FAKE_TESTSSL = textwrap.dedent('''\
    #!%(python)s
    import glob, socket, sys
    argv = sys.argv[1:]
    hostport = argv[argv.index("--proxy") + 1]
    out = argv[argv.index("--jsonfile") + 1]
    host, port = hostport.rsplit(":", 1)
    holders = []
    for path in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            raw = open(path, "rb").read()
        except OSError:
            continue
        # The shell that was handed the whole command line necessarily holds the token in that string (as it does for
        # every tool whose proxy URL carries it); the property under test is that no OTHER process does.
        if b"%(token)s" in raw and raw.split(b"\\0")[0].rsplit(b"/", 1)[-1] not in (b"bash", b"sh"):
            holders.append(raw[:60])
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(b"CONNECT host.example:443 HTTP/1.1\\r\\nHost: host.example:443\\r\\n\\r\\n")
    reply = s.recv(4096).split(b"\\r\\n")[0].decode()
    open(out, "w").write('{"proxy": "%%s", "reply": "%%s", "token_on_a_command_line": %%s}' %% (hostport, reply, "true" if holders else "false"))
''')

FAKE_CHROMIUM = textwrap.dedent('''\
    #!%(python)s
    import socket, sys
    argv = sys.argv[1:]
    proxy = [a for a in argv if a.startswith("--proxy-server=")][0].split("=", 1)[1]
    shot = [a for a in argv if a.startswith("--screenshot=")][0].split("=", 1)[1]
    host, port = proxy.replace("http://", "").rsplit(":", 1)
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(b"CONNECT host.example:443 HTTP/1.1\\r\\n\\r\\n")
    s.recv(4096)
    open(shot, "wb").write(b"\\x89PNG fake " + proxy.encode())
''')


@pytest.fixture()
def env(tmp_path, monkeypatch):
    proxy = StandInProxy()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, template in (("testssl", FAKE_TESTSSL), ("chromium", FAKE_CHROMIUM)):
        path = bindir / name
        path.write_text(template % {"python": sys.executable, "token": TOKEN})
        path.chmod(0o755)
    (bindir / "python3").symlink_to(sys.executable)
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    monkeypatch.setattr(trc, "EGRESS_PROXY_URL", f"http://127.0.0.1:{proxy.port}")
    monkeypatch.setattr(trc, "EGRESS_RUN_TOKENS", True)
    monkeypatch.setattr(trc, "FORWARDER_PATH", str(FORWARDER))
    shell_env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "TMPDIR": str(scratch)}
    yield SimpleNamespace(proxy=proxy, shell_env=shell_env, scratch=scratch, bindir=bindir)
    proxy.close()


def _runner(monkeypatch, captured):
    runner = trc.ToolRunnerClient()
    runner._egress_tokens = trc._EgressTokens(lambda run: {"token": TOKEN, "expires_in": 600})

    def post(path, payload, scan_run_id, budget_s=None):
        captured.update(path=path, payload=payload)
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"stdout": "", "stderr": "", "return_code": 0, "success": True})

    monkeypatch.setattr(runner, "_post_cancellable", post)
    return runner


def _command(monkeypatch, tool, args=None, target="https://host.example"):
    captured: dict = {}
    result = _runner(monkeypatch, captured).run(tool, target, dict(args or {}), scan_run_id=RUN)
    return captured["payload"]["command"], result


def _shell(command, env, timeout=60):
    return subprocess.run(["bash", "-c", command], env=env.shell_env, capture_output=True, text=True, timeout=timeout)


def _forwarders_running() -> list[str]:
    """The processes whose command line names the forwarder. Read from /proc, not from `ps`: the public export is verified in a slim container
    that has no `ps`, and a test must not depend on a binary the thing it tests does not need."""
    found = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            args = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
        except OSError:
            continue    # the process ended while we looked
        if "egress_forwarder.py" in args and "pytest" not in args:
            found.append(f"{entry.name} {args}")
    return found


# --- the command that is built ---------------------------------------------------------------------------------------

def test_the_command_runs_the_forwarder_with_the_credential_in_its_environment_not_its_arguments(monkeypatch, env):
    command, _ = _command(monkeypatch, "testssl")
    assert f"ASM_PROXY_CREDENTIAL={TOKEN} python3 {FORWARDER} --upstream 127.0.0.1:{env.proxy.port} --user asm" in command
    assert f"--proxy 127.0.0.1:${{{trc.FORWARDER_PORT_VAR}}}" in command and "@127.0.0.1" not in command
    assert command.count(TOKEN) == 1


def test_negative_the_stored_command_shows_the_placeholder_and_never_the_token(monkeypatch, env):
    _, result = _command(monkeypatch, "testssl")
    assert TOKEN not in result["command"] and "ASM_PROXY_CREDENTIAL=redacted" in result["command"]
    _, result = _command(monkeypatch, "screenshot")
    assert TOKEN not in result["command"] and "ASM_PROXY_CREDENTIAL=redacted" in result["command"]


def test_negative_with_no_token_the_command_is_the_old_plain_one(monkeypatch, env):
    monkeypatch.setattr(trc, "EGRESS_RUN_TOKENS", False)
    for tool in ("testssl", "screenshot"):
        command, _ = _command(monkeypatch, tool)
        assert "egress_forwarder" not in command and TOKEN not in command
        assert f"127.0.0.1:{env.proxy.port}" in command


# --- the command, run ------------------------------------------------------------------------------------------------

def test_testssl_reaches_the_proxy_with_the_credentials_it_cannot_send_itself(monkeypatch, env):
    command, _ = _command(monkeypatch, "testssl", {"ip": "203.0.113.9"})
    done = _shell(command, env)
    assert done.returncode == 0, done.stderr
    assert '"reply": "HTTP/1.1 200 Connection Established"' in done.stdout
    assert f"Proxy-Authorization: {BASIC}" in env.proxy.heads[0]
    assert env.proxy.heads[0].startswith("CONNECT host.example:443 HTTP/1.1")


def test_the_screenshot_browser_reaches_the_proxy_with_the_credentials_and_its_picture_still_comes_back(monkeypatch, env):
    command, _ = _command(monkeypatch, "screenshot")
    done = _shell(command, env)
    assert done.returncode == 0, done.stderr
    picture = base64.b64decode(done.stdout.strip())
    assert picture.startswith(b"\x89PNG fake http://127.0.0.1:")
    assert f"Proxy-Authorization: {BASIC}" in env.proxy.heads[0]


def test_negative_only_the_shell_holds_the_token_on_a_command_line_never_the_forwarder_or_the_tool(monkeypatch, env):
    command, _ = _command(monkeypatch, "testssl")
    done = _shell(command, env)
    assert '"token_on_a_command_line": false' in done.stdout.replace("\n", "")


def test_negative_the_forwarder_and_its_files_are_gone_when_the_command_ends(monkeypatch, env):
    before = _forwarders_running()
    command, _ = _command(monkeypatch, "testssl")
    assert _shell(command, env).returncode == 0
    time.sleep(0.5)
    assert _forwarders_running() == before
    assert list(env.scratch.iterdir()) == [], "the forwarder's temporary directory is removed"


def test_negative_when_the_forwarder_cannot_start_the_command_fails_visibly_and_the_tool_never_runs(monkeypatch, env):
    monkeypatch.setattr(trc, "FORWARDER_PATH", "/nonexistent/egress_forwarder.py")
    marker = env.scratch / "tool-ran"
    (env.bindir / "testssl").write_text(f"#!/bin/sh\ntouch {marker}\n")
    command, _ = _command(monkeypatch, "testssl")
    done = _shell(command, env)
    assert done.returncode == 70 and "egress forwarder did not start" in done.stderr
    assert not marker.exists(), "the tool must not run without the identity it was meant to carry"
    assert env.proxy.heads == []


def test_negative_the_runners_group_kill_takes_the_forwarder_with_it(monkeypatch, env):
    """HexStrike starts a command in its own session and kills the process group on cancel or timeout."""
    (env.bindir / "testssl").write_text("#!/bin/sh\nsleep 30\n")
    command, _ = _command(monkeypatch, "testssl")
    before = _forwarders_running()
    process = subprocess.Popen(["bash", "-c", command], env=env.shell_env, start_new_session=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if len(_forwarders_running()) > len(before):
            break
        time.sleep(0.1)
    assert len(_forwarders_running()) > len(before), "the forwarder came up"
    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    process.wait()
    for _ in range(50):
        if _forwarders_running() == before:
            return
        time.sleep(0.1)
    raise AssertionError("the forwarder survived the group kill")


def test_two_commands_at_once_each_get_their_own_forwarder_and_port(monkeypatch, env):
    commands = [_command(monkeypatch, "testssl")[0] for _ in range(3)]   # each has its own output file name
    results = []

    def go(command):
        results.append(_shell(command, env))

    threads = [threading.Thread(target=go, args=(c,)) for c in commands]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r.returncode == 0 and '"reply": "HTTP/1.1 200' in r.stdout for r in results), [(r.returncode, r.stdout[:200], r.stderr[:200]) for r in results]
    ports = {r.stdout.split('"proxy": "127.0.0.1:')[1].split('"')[0] for r in results}
    assert len(ports) == 3 and len(env.proxy.heads) == 3


@pytest.mark.parametrize("hostile", ["", "a b", "a;touch /tmp/x", "$(id)", "a'b", "a\nb", "x" * 1025])
def test_negative_a_credential_that_could_change_the_shape_of_the_command_never_reaches_the_wrapper(env, hostile):
    scope = trc._PROXY_CREDENTIAL.set(hostile)
    try:
        with pytest.raises(ValueError, match="unsafe proxy credential"):
            trc._with_forwarder("true", {})
    finally:
        trc._PROXY_CREDENTIAL.reset(scope)
