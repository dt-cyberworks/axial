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
