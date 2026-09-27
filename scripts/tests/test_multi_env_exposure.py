"""REQ-MULTIENV-001/002: two named environments (int, prod) on one host, behind
one shared edge proxy. Renders the real merged configs via `docker compose
config` and asserts:
  - the no-edge overlay never publishes anything on a public interface (the
    shared edge, not this file, is the sole public listener);
  - int and prod, rendered with their generated envs, never collide on a
    published (host_ip, port) pair;
  - the shared edge compose project is the only thing that could plausibly
    expose 80/443 (network_mode: host is the deliberate, documented exception).

Skipped when Docker/compose or PyYAML is unavailable."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from gen_production_env import build_env, render  # noqa: E402


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "compose", "version"], capture_output=True, check=True, timeout=30)
        return True
    except Exception:  # noqa: BLE001
        return False


def _render(env_file: Path, *files: str, profiles: tuple[str, ...] = ()) -> dict:
    cmd = ["docker", "compose", "--env-file", str(env_file)]
    for f in files:
        cmd += ["-f", str(ROOT / f)]
    for p in profiles:
        cmd += ["--profile", p]
    cmd += ["config", "--format", "json"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=True, cwd=ROOT)
    return json.loads(out.stdout)


def _published(config: dict) -> set[tuple[str, str]]:
    rows = set()
    for svc in config.get("services", {}).values():
        for p in svc.get("ports", []) or []:
            if isinstance(p, dict):
                rows.add((str(p.get("host_ip", "0.0.0.0")), str(p.get("published"))))
    return rows


@pytest.fixture(scope="module")
def rendered(tmp_path_factory):
    if not _docker_available():
        pytest.skip("docker/compose not available")
    tmp = tmp_path_factory.mktemp("multienv")
    prod_env = tmp / ".env.prod"
    int_env = tmp / ".env.int"
    prod_env.write_text(render(build_env("scan.example.org", env_name="prod")))
    int_env.write_text(render(build_env("scan-int.example.org", env_name="int")))
    prod_cfg = _render(prod_env, "docker-compose.yml", "docker-compose.prod-noedge.yml", profiles=("runner",))
    int_cfg = _render(int_env, "docker-compose.yml", "docker-compose.prod-noedge.yml", profiles=("runner",))
    return prod_cfg, int_cfg


def test_noedge_overlay_publishes_nothing_publicly(rendered):
    for cfg in rendered:
        public = [(hip, pub) for (hip, pub) in _published(cfg) if hip in ("0.0.0.0", "::")]
        assert not public, f"no-edge overlay must publish nothing publicly, found: {public}"


def test_noedge_overlay_has_no_caddy_service(rendered):
    for cfg in rendered:
        assert "caddy" not in cfg.get("services", {})


def test_control_plane_and_minio_bind_loopback_in_both_envs(rendered):
    for cfg in rendered:
        svcs = cfg["services"]
        cp_ports = [p for p in svcs["control-plane"].get("ports", []) if isinstance(p, dict)]
        mi_ports = [p for p in svcs["minio"].get("ports", []) if isinstance(p, dict)]
        assert all(p.get("host_ip") == "127.0.0.1" for p in cp_ports), cp_ports
        assert all(p.get("host_ip") == "127.0.0.1" for p in mi_ports), mi_ports


def test_prod_and_int_never_collide_on_published_ports(rendered):
    prod_cfg, int_cfg = rendered
    prod_ports = _published(prod_cfg)
    int_ports = _published(int_cfg)
    overlap = prod_ports & int_ports
    assert not overlap, f"prod and int published the same (host_ip, port): {overlap}"


def test_prod_and_int_use_distinct_project_identity(rendered):
    prod_cfg, int_cfg = rendered
    assert prod_cfg["name"] != int_cfg["name"]
    assert prod_cfg["services"]["postgres"]["environment"]["POSTGRES_DB"] != \
        int_cfg["services"]["postgres"]["environment"]["POSTGRES_DB"]


def _network_names(config: dict) -> set[str]:
    return {net["name"] for net in config.get("networks", {}).values()}


def test_prod_and_int_use_disjoint_internal_network_names(rendered):
    """REQ-MULTIENV-004 negative test. Found live 2026-08-09: both environments'
    internal networks (ctrl/runner/control/egress/edge) were hardcoded to the
    same literal names, so `docker network inspect asm_ctrl` showed both
    asm_int-postgres-1 and asm_prod-postgres-1 attached to the identical
    network - Docker's embedded DNS then resolved the 'postgres' hostname to
    either container at random, and int's migrate step intermittently
    authenticated against prod's database instead of its own."""
    prod_cfg, int_cfg = rendered
    prod_nets = _network_names(prod_cfg)
    int_nets = _network_names(int_cfg)
    assert len(prod_nets) == 5 and len(int_nets) == 5, (prod_nets, int_nets)
    overlap = prod_nets & int_nets
    assert not overlap, f"prod and int share internal Docker network name(s): {overlap}"


def test_unnamed_environment_keeps_the_historical_literal_network_names():
    """The ASM_NETWORK_PREFIX default (unset -> 'asm') must reproduce the exact
    pre-REQ-MULTIENV-004 literal names, because lab/lab-compose.yml hardcodes
    'asm_ctrl' as an external network for the lab test loop and is not itself
    parameterized by any environment name."""
    if not _docker_available():
        pytest.skip("docker/compose not available")
    env = {k: v for k, v in os.environ.items() if k != "ASM_NETWORK_PREFIX"}
    out = subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "docker-compose.yml"), "config", "--format", "json"],
        capture_output=True, text=True, timeout=120, check=True, cwd=ROOT, env=env,
    )
    cfg = json.loads(out.stdout)
    assert _network_names(cfg) == {"asm_edge", "asm_ctrl", "asm_runner", "asm_control", "asm_egress"}


def test_scope_signing_secret_reaches_the_container_via_a_named_env_file(tmp_path_factory):
    """Regression: control-plane's SCOPE_SIGNING_SECRET was only ever wired via
    the fixed-path `env_file: .env` service directive, which resolves relative
    to the compose project directory and does NOT fire for a differently-named
    file (.env.prod/.env.int) selected via --env-file - it silently fell back
    to the insecure class default, which then correctly crashed the production
    credential gate at container startup. Uses --project-directory pointed at
    an empty directory (no literal .env) so this cannot pass by accident
    because of an incidental .env elsewhere."""
    if not _docker_available():
        pytest.skip("docker/compose not available")
    empty_project_dir = tmp_path_factory.mktemp("emptyproject")
    env_file = tmp_path_factory.mktemp("namedenv") / ".env.int"
    env = build_env("scan-int.example.org", env_name="int")
    env_file.write_text(render(env))

    cmd = [
        "docker", "compose", "--project-directory", str(empty_project_dir),
        "--env-file", str(env_file),
        "-f", str(ROOT / "docker-compose.yml"), "-f", str(ROOT / "docker-compose.prod-noedge.yml"),
        "--profile", "runner", "config", "--format", "json",
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=True)
    cfg = json.loads(out.stdout)
    actual = cfg["services"]["control-plane"]["environment"].get("SCOPE_SIGNING_SECRET")
    assert actual == env["SCOPE_SIGNING_SECRET"], (
        "SCOPE_SIGNING_SECRET did not reach the control-plane container via the "
        "named env file (regression: only env_file: .env delivered it, which "
        "never fires for a differently-named --env-file)"
    )
    assert actual not in ("", "change-me-in-dev")


def test_shared_edge_is_the_only_service_using_host_networking():
    if not _docker_available():
        pytest.skip("docker/compose not available")
    env_file = Path(__file__).resolve().parents[0] / "_edge_test.env"
    env_file.write_text(
        "ASM_DOMAIN_PROD=scan.example.org\nASM_DOMAIN_INT=scan-int.example.org\n"
    )
    try:
        cfg = _render(env_file, "docker-compose.edge.yml")
    finally:
        env_file.unlink(missing_ok=True)
    assert cfg["services"]["edge"]["network_mode"] == "host"
    assert len(cfg["services"]) == 1  # the shared edge project defines exactly one service
