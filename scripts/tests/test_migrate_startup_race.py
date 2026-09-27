"""Regression: on a genuinely fresh Postgres volume, `depends_on: postgres:
condition: service_healthy` (backed by `pg_isready`) can report healthy during
the short internal-restart window between initdb and Postgres truly accepting
the configured role's real password - `pg_isready` only checks that SOME
server accepts connections, not that our credentials already work on it.
Observed in practice on this project's first-ever fresh-volume production
bring-up: several migration statements failed with "password authentication
failed" before the migrate step gave up. The migrate entrypoint now waits for
a REAL authenticated query to succeed before running any migration.

This starts a real Postgres container and a migrate-equivalent script
(extracted from the actual rendered docker-compose.yml entrypoint) against it
concurrently, so the wait loop has to do genuine work - not just pass because
Postgres happened to already be ready. Skipped when Docker is unavailable."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
POSTGRES_IMAGE = "postgres:16@sha256:be01cf82fc7dbba824acf0a82e150b4b360f3ff93c6631d7844af431e841a95c"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "version"], capture_output=True, check=True, timeout=15)
        return True
    except Exception:  # noqa: BLE001
        return False


def _rm(*names: str) -> None:
    for name in names:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)


def _rendered_migrate_script() -> str:
    """The actual migrate entrypoint from docker-compose.yml, with compose's
    `$$`-escaping collapsed to the real `$` a shell inside the container sees."""
    out = subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "docker-compose.yml"), "config", "--format", "json"],
        capture_output=True, text=True, timeout=60, check=True, cwd=ROOT,
    )
    entrypoint = json.loads(out.stdout)["services"]["migrate"]["entrypoint"]
    return entrypoint[2].replace("$$", "$")


def test_migrate_script_waits_before_the_first_stop_on_error_statement():
    """Structural guard: the retry loop must run BEFORE any ON_ERROR_STOP=1
    statement, or a transient early failure still aborts the whole step."""
    script = _rendered_migrate_script()
    wait_idx = script.index("waiting for postgres to accept")
    first_hard_stmt_idx = script.index("ON_ERROR_STOP=1")
    assert wait_idx < first_hard_stmt_idx


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_migrate_script_survives_postgres_not_immediately_ready(tmp_path):
    """Functional: run the real migrate script concurrently with Postgres
    starting up (not pre-warmed), proving the wait loop lets it succeed instead
    of failing on the first not-ready connection attempt."""
    net = "asm-migrate-race-test-net"
    pg, migrate = "asm-migrate-race-test-pg", "asm-migrate-race-test-migrate"
    _rm(pg, migrate)
    subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)
    subprocess.run(["docker", "network", "create", net], capture_output=True, timeout=15, check=True)
    try:
        script = _rendered_migrate_script()
        # Drop the /migrations loop and proxy-role rotation - this test only
        # proves the wait-for-real-auth behavior, not the full migration set.
        wait_only = script.split("psql \"$DB\" -v ON_ERROR_STOP=1 -c \"CREATE TABLE")[0]
        wait_only += 'echo MIGRATE_RACE_TEST_REACHED_REAL_AUTH\n'
        script_path = tmp_path / "migrate.sh"
        script_path.write_text(wait_only)

        # Start Postgres and the migrate script back-to-back, with NO warm-up
        # delay, so the script has to actually wait rather than find Postgres
        # already accepting the real credentials.
        subprocess.run([
            "docker", "run", "-d", "--rm", "--name", pg, "--network", net, "--network-alias", "postgres",
            "-e", "POSTGRES_USER=asm_race", "-e", "POSTGRES_PASSWORD=race-test-secret", "-e", "POSTGRES_DB=asm_race",
            POSTGRES_IMAGE,
        ], capture_output=True, check=True, timeout=30)

        # Deliberately NOT --rm: we need to inspect/read logs after it exits,
        # and the script can finish in ~1-2s, racing an auto-remove against our
        # own polling. Cleaned up explicitly in the `finally` block below.
        subprocess.run([
            "docker", "run", "-d", "--name", migrate, "--network", net,
            "-e", "POSTGRES_USER=asm_race", "-e", "POSTGRES_PASSWORD=race-test-secret", "-e", "POSTGRES_DB=asm_race",
            "-v", f"{script_path}:/migrate.sh:ro", "--entrypoint", "sh",
            POSTGRES_IMAGE, "/migrate.sh",
        ], capture_output=True, check=True, timeout=30)

        deadline = time.monotonic() + 90
        exit_code = None
        while time.monotonic() < deadline:
            inspect = subprocess.run(
                ["docker", "inspect", migrate, "--format", "{{.State.Status}} {{.State.ExitCode}}"],
                capture_output=True, text=True, timeout=15, check=True,
            )
            status, code = inspect.stdout.split()
            if status == "exited":
                exit_code = int(code)
                break
            time.sleep(1)
        logs_proc = subprocess.run(["docker", "logs", migrate], capture_output=True, text=True, timeout=15)
        logs = logs_proc.stdout + logs_proc.stderr

        assert "MIGRATE_RACE_TEST_REACHED_REAL_AUTH" in logs, f"migrate script never reached real auth; logs:\n{logs}"
        assert exit_code == 0, f"migrate script exited {exit_code}; logs:\n{logs}"
        # It had to wait at least once - proves this genuinely exercised the
        # retry path, not a lucky immediate connection.
        assert "waiting for postgres to accept the real application credentials" in logs, (
            f"expected at least one retry iteration; logs:\n{logs}"
        )
    finally:
        _rm(pg, migrate)
        subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)
