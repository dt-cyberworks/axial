# Build-time hardening patch for the HexStrike execution boundary.
#
# Upstream serializes subprocess.Popen objects in its process API and can only
# terminate the shell process. This patch adds scan-run ownership, JSON-safe
# listing, and process-group termination. Changed upstream source fails build.

from __future__ import annotations

import pathlib
import sys


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"HexStrike patch {label!r}: expected one match, found {count}")
    return source.replace(old, new)


def patch_source(source: str) -> str:
    source = _replace_once(
        source,
        "from flask import Flask, request, jsonify",
        "from flask import Flask, request, jsonify, has_request_context",
        "flask request context",
    )
    # REQ-HARDEN-001: authenticate every request to the execution boundary.
    # Upstream HexStrike ships NO auth and binds 0.0.0.0; inject a fail-closed
    # shared-secret gate right after the Flask app is created, before any route
    # can run. The predicate lives in runner_auth.py (copied next to this file
    # in the image) so it is unit-testable without Flask.
    source = _replace_once(
        source,
        "app = Flask(__name__)",
        "app = Flask(__name__)\n"
        "\n"
        "from runner_auth import is_authorized as _asm_is_authorized, RUNNER_TOKEN_HEADER as _ASM_RUNNER_TOKEN_HEADER\n"
        "\n"
        "@app.before_request\n"
        "def _asm_enforce_runner_auth():\n"
        "    # REQ-HARDEN-001: fail-closed shared-secret gate on the execution boundary.\n"
        "    if not _asm_is_authorized(\n"
        "        request.path,\n"
        "        request.headers.get(_ASM_RUNNER_TOKEN_HEADER),\n"
        "        os.environ.get('RUNNER_API_TOKEN'),\n"
        "    ):\n"
        "        return jsonify({'error': 'runner_auth_required'}), 401",
        "runner auth before_request gate",
    )
    source = _replace_once(
        source,
        '''                "process": process_obj,
                "start_time": time.time(),''',
        '''                "process": process_obj,
                # The worker supplies this only after Scope-Gateway authorization.
                # It is ownership metadata for cancellation, never permission.
                "scan_run_id": request.headers.get("X-ASM-Scan-Run-ID") if has_request_context() else None,
                "start_time": time.time(),''',
        "scan-run process ownership",
    )
    source = _replace_once(
        source,
        '''            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )''',
        '''            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                # Isolate the shell plus all tool children so cancellation can
                # terminate the complete command tree without touching others.
                start_new_session=True
            )''',
        "process group creation",
    )
    source = _replace_once(
        source,
        '''                    process_obj = process_info["process"]
                    if process_obj and process_obj.poll() is None:
                        process_obj.terminate()
                        time.sleep(1)  # Give it a chance to terminate gracefully
                        if process_obj.poll() is None:
                            process_obj.kill()  # Force kill if still running

                        active_processes[pid]["status"] = "terminated"
                        logger.warning(f"🛑 TERMINATED: Process {pid} - {process_info['command'][:50]}...")
                        return True''',
        '''                    process_obj = process_info["process"]
                    if process_obj and process_obj.poll() is None:
                        pgid = os.getpgid(process_obj.pid)
                        os.killpg(pgid, signal.SIGTERM)
                        time.sleep(1)  # Give the complete command group a chance to terminate.
                        try:
                            # Kill any child that survived after the shell exited.
                            os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass

                        active_processes[pid]["status"] = "terminated"
                        logger.warning(f"🛑 TERMINATED: Process {pid} - {process_info['command'][:50]}...")
                        return True''',
        "process group termination",
    )
    source = _replace_once(
        source,
        '''                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.error(f"🔪 FORCE KILL: Process {self.process.pid} not responding to termination")
                    self.process.kill()

                self.return_code = -1''',
        '''                # Terminate the complete tool process group, not only
                # the shell created by shell=True.
                pgid = os.getpgid(self.process.pid)
                os.killpg(pgid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.error(f"🔪 FORCE KILL: Process group {pgid} not responding to termination")
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

                self.return_code = -1''',
        "timeout process group termination",
    )
    source = _replace_once(
        source,
        '''        processes = ProcessManager.list_active_processes()

        # Add calculated fields for each process''',
        '''        processes = {
            pid: {key: value for key, value in info.items() if key != "process"}
            for pid, info in ProcessManager.list_active_processes().items()
        }

        # Add calculated fields for each process''',
        "JSON-safe process list",
    )
    marker = '@app.route("/api/processes/list", methods=["GET"])\ndef list_processes():'
    endpoint = (
        '@app.route("/api/processes/terminate-scan-run/<scan_run_id>", methods=["POST"])\n'
        'def terminate_scan_run_processes(scan_run_id):\n'
        '    # Terminate only process groups registered to one exact ASM scan run.\n'
        '    if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", scan_run_id):\n'
        '        return jsonify({"success": False, "error": "invalid scan_run_id"}), 400\n'
        '    with process_lock:\n'
        '        pids = [\n'
        '            pid for pid, info in active_processes.items()\n'
        '            if info.get("scan_run_id") == scan_run_id\n'
        '        ]\n'
        '    terminated = [pid for pid in pids if ProcessManager.terminate_process(pid)]\n'
        '    return jsonify({\n'
        '        "success": True,\n'
        '        "matched_count": len(pids),\n'
        '        "terminated_count": len(terminated),\n'
        '        "terminated_pids": terminated,\n'
        '    })\n\n\n'
        '@app.route("/api/processes/list", methods=["GET"])\n'
        'def list_processes():'
    )
    source = _replace_once(source, marker, endpoint, "run termination endpoint")
    return source


def main() -> None:
    path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "hexstrike_server.py")
    path.write_text(patch_source(path.read_text()))


if __name__ == "__main__":
    main()
