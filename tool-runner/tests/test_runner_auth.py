"""REQ-HARDEN-001: the tool-runner execution boundary rejects any request that
does not carry the shared secret, fails closed when misconfigured, and never
runs an insecure production boundary. Health probes stay open.

These test the pure predicate directly (no Flask needed) plus the build-time
patch that injects it into the vendored HexStrike server."""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import runner_auth  # noqa: E402
from runner_auth import enforce_production_token, is_authorized  # noqa: E402

TOKEN = "s3cret-runner-token"


def test_command_requires_matching_token():
    # The high-value target: arbitrary shell execution.
    assert is_authorized("/api/command", TOKEN, TOKEN) is True
    assert is_authorized("/api/command", "wrong", TOKEN) is False
    assert is_authorized("/api/command", None, TOKEN) is False
    assert is_authorized("/api/command", "", TOKEN) is False


def test_dedicated_tool_endpoints_require_matching_token():
    for path in ("/api/tools/nmap", "/api/tools/nuclei", "/api/processes/list"):
        assert is_authorized(path, TOKEN, TOKEN) is True
        assert is_authorized(path, "nope", TOKEN) is False
        assert is_authorized(path, None, TOKEN) is False


def test_health_is_always_open():
    # The Compose/K8s liveness probe carries no secret and reveals nothing.
    assert is_authorized("/health", None, TOKEN) is True
    assert is_authorized("/health", None, None) is True


def test_unconfigured_token_denies_everything_but_health():
    # A misconfigured runner must not silently accept unauthenticated commands.
    assert is_authorized("/api/command", None, None) is False
    assert is_authorized("/api/command", "anything", None) is False
    assert is_authorized("/api/command", "anything", "") is False
    assert is_authorized("/health", None, None) is True


def test_production_startup_rejects_missing_or_default_token():
    with pytest.raises(RuntimeError, match="runner_api_token"):
        enforce_production_token("production", None)
    with pytest.raises(RuntimeError, match="runner_api_token"):
        enforce_production_token("production", "")
    with pytest.raises(RuntimeError, match="runner_api_token"):
        enforce_production_token("production", runner_auth._DEV_DEFAULT_TOKEN)


def test_production_startup_accepts_real_token_and_dev_is_lenient():
    enforce_production_token("production", "a-real-strong-secret")  # no raise
    enforce_production_token("development", None)                   # no raise
    enforce_production_token(None, None)                            # no raise


# A fixture containing every exact anchor patch_source needs, so we can run the
# real build-time patch end-to-end and prove the auth gate is injected before
# any route. If upstream HexStrike changes an anchor, the real Docker build
# fails (each _replace_once expects exactly one match) - this keeps the unit
# test honest about that contract too.
_FIXTURE = '''\
from flask import Flask, request, jsonify
import os
import time
import subprocess
import signal
import re

app = Flask(__name__)

def register(process_obj, pid):
    active_processes[pid] = {
                "process": process_obj,
                "start_time": time.time(),
    }

class Runner:
    def start(self):
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

    def terminate_one(self, pid):
                    process_obj = process_info["process"]
                    if process_obj and process_obj.poll() is None:
                        process_obj.terminate()
                        time.sleep(1)  # Give it a chance to terminate gracefully
                        if process_obj.poll() is None:
                            process_obj.kill()  # Force kill if still running

                        active_processes[pid]["status"] = "terminated"
                        logger.warning(f"🛑 TERMINATED: Process {pid} - {process_info['command'][:50]}...")
                        return True

    def on_timeout(self):
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.error(f"🔪 FORCE KILL: Process {self.process.pid} not responding to termination")
                    self.process.kill()

                self.return_code = -1

@app.route("/api/processes/list", methods=["GET"])
def list_processes():
        processes = ProcessManager.list_active_processes()

        # Add calculated fields for each process
        return jsonify(processes)

def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Execute a shell command with enhanced features
    """

    # Check cache first
    if use_cache:
        cached_result = cache.get(command, {})
        if cached_result:
            return cached_result

    # Execute command
    executor = EnhancedCommandExecutor(command)
    result = executor.execute()

    # Cache successful results
    if use_cache and result.get("success", False):
        cache.set(command, {}, result)

    return result
'''


def test_patch_injects_fail_closed_auth_gate_end_to_end():
    from patch_hexstrike import patch_source

    patched = patch_source(_FIXTURE)

    # The gate is present, imports the testable predicate, reads the header and
    # the configured token, and returns 401 fail-closed.
    assert "@app.before_request" in patched
    assert "_asm_enforce_runner_auth" in patched
    assert "from runner_auth import is_authorized" in patched
    assert "runner_auth_required" in patched
    # It is wired immediately after app creation, before the route it must guard.
    assert patched.index("def _asm_enforce_runner_auth") < patched.index('@app.route("/api/processes/list"')
    # Exactly one gate injected.
    assert patched.count("def _asm_enforce_runner_auth") == 1


def test_patched_execute_command_never_serves_or_stores_a_cached_result():
    """REQ-CONCUR-001: the dedicated /api/tools/* endpoints call
    execute_command(command) with the upstream default use_cache=True and ignore
    the request's use_cache. Live 2026-09-29 a resumed scan got nikto/nmap
    results replayed in ~20ms. Run the patched function itself: the same command
    twice, with the caller asking for the cache, must execute twice."""
    from typing import Any, Dict

    from patch_hexstrike import patch_source

    patched = patch_source(_FIXTURE)
    fn_src = patched[patched.index("def execute_command("):]
    executed: list[str] = []

    class _Cache:
        def __init__(self):
            self.store = {}

        def get(self, command, params):
            return self.store.get(command)

        def set(self, command, params, result):
            self.store[command] = result

    class _Executor:
        def __init__(self, command, timeout=300):
            self.command = command

        def execute(self):
            executed.append(self.command)
            return {"success": True, "stdout": "fresh"}

    cache = _Cache()
    cache.store["nikto -h https://a.example"] = {"success": True, "stdout": "STALE"}
    namespace = {"Dict": Dict, "Any": Any, "cache": cache, "EnhancedCommandExecutor": _Executor,
                 "_asm_command_timeout": lambda: 300}
    exec(fn_src, namespace)  # noqa: S102 - the test fixture, not external input

    first = namespace["execute_command"]("nikto -h https://a.example")
    second = namespace["execute_command"]("nikto -h https://a.example", use_cache=True)
    assert first["stdout"] == second["stdout"] == "fresh"
    assert executed == ["nikto -h https://a.example"] * 2
    assert list(cache.store) == ["nikto -h https://a.example"] and cache.store["nikto -h https://a.example"]["stdout"] == "STALE"


def test_req_pipe_007_patched_execute_command_enforces_the_declared_budget():
    """The executor gets the per-request budget, not the fixed upstream cap."""
    from typing import Any, Dict

    from patch_hexstrike import patch_source

    patched = patch_source(_FIXTURE)
    fn_src = patched[patched.index("def execute_command("):]
    seen: list[tuple[str, int]] = []

    class _Cache:
        def get(self, command, params):
            return None

        def set(self, command, params, result):
            pass

    class _Executor:
        def __init__(self, command, timeout=300):
            self.command, self.timeout = command, timeout

        def execute(self):
            seen.append((self.command, self.timeout))
            return {"success": True}

    namespace = {"Dict": Dict, "Any": Any, "cache": _Cache(), "EnhancedCommandExecutor": _Executor,
                 "_asm_command_timeout": lambda: 1234}
    exec(fn_src, namespace)  # noqa: S102 - the test fixture, not external input
    namespace["execute_command"]("nuclei -u https://a.example")
    assert seen == [("nuclei -u https://a.example", 1234)]


def test_req_pipe_007_the_patch_reads_the_budget_from_the_request_header_and_clamps_it():
    from patch_hexstrike import patch_source

    patched = patch_source(_FIXTURE)
    assert "from runner_budget import BUDGET_HEADER as _ASM_BUDGET_HEADER" in patched
    assert "request.headers.get(_ASM_BUDGET_HEADER) if has_request_context() else None" in patched
    assert "_asm_budget_timeout(requested, COMMAND_TIMEOUT)" in patched
    assert patched.count("def _asm_command_timeout") == 1


def test_req_pipe_007_budget_rule_default_bounds_and_clamp():
    import runner_budget as rb

    assert rb.command_timeout(None, 300) == 300
    assert rb.command_timeout("90", 300) == 90
    assert rb.command_timeout(90, 300) == 90
    assert rb.command_timeout(str(rb.HARD_MAX_SECONDS), 300) == rb.HARD_MAX_SECONDS
    assert rb.HARD_MAX_SECONDS == 1800  # johannes, 2026-09-29: 30 minutes


def test_negative_req_pipe_007_a_request_can_never_exceed_the_hard_maximum():
    import runner_budget as rb

    assert rb.command_timeout("1801", 300) == rb.HARD_MAX_SECONDS
    assert rb.command_timeout("99999999", 300) == rb.HARD_MAX_SECONDS
    # A misconfigured default is bounded too.
    assert rb.command_timeout(None, 10**9) == rb.HARD_MAX_SECONDS


def test_negative_req_pipe_007_malformed_or_non_positive_budgets_get_the_default():
    import runner_budget as rb

    for bad in ("", "abc", "-5", "0", "1e9", "12.5", " ", "0x10", None):
        assert rb.command_timeout(bad, 300) == 300, bad


def test_negative_patch_fails_loudly_when_the_budget_anchors_change():
    from patch_hexstrike import patch_source

    with pytest.raises(RuntimeError, match="per-request command budget"):
        patch_source(_FIXTURE.replace("executor = EnhancedCommandExecutor(command)", "executor = Other(command)"))
    with pytest.raises(RuntimeError):
        patch_source(_FIXTURE.replace("app = Flask(__name__)", "application = Flask(__name__)"))


def test_the_dockerfile_ships_the_budget_module_next_to_the_server():
    dockerfile = (pathlib.Path(__file__).resolve().parents[1] / "runner.Dockerfile").read_text()
    assert "COPY runner_budget.py /tmp/runner_budget.py" in dockerfile
    assert "cp /tmp/runner_budget.py /opt/hexstrike/runner_budget.py" in dockerfile


def test_negative_patch_fails_loudly_when_the_cache_anchor_changes():
    from patch_hexstrike import patch_source

    with pytest.raises(RuntimeError, match="result cache disabled"):
        patch_source(_FIXTURE.replace("    # Check cache first", "    # check the cache"))
