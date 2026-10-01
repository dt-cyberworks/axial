"""REQ-HARDEN-003: every long-running service runs with least privilege.

Renders the real merged compose config and fails if control-plane, worker,
egress-proxy or an edge proxy lacks `cap_drop: [ALL]`, no-new-privileges and a
read-only root filesystem. Services that legitimately differ are listed below,
each with its reason. Skipped when Docker/compose is unavailable."""

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

# Services that must run with cap_drop ALL, no-new-privileges and a read-only
# root. `caps` is the exact set they may add back (none unless documented).
HARDENED = {
    "control-plane": set(),
    "worker": set(),
    "egress-proxy": set(),
    # REQ-INSTALL-002: the object store's entrypoint starts as root, fixes /data's
    # ownership and drops to its own uid-1000 user with su-exec - exactly these three
    # capabilities, verified against the real image (the server process holds none).
    "seaweedfs": {"CHOWN", "SETUID", "SETGID"},
}
# The edge proxy binds 80/443 on the host network: NET_BIND_SERVICE is the one
# capability it provably needs. It still runs as root (REQ-HARDEN-004, backlog).
EDGE_CAPS = {"NET_BIND_SERVICE"}

# Not covered by this test, with the reason. The runner and the raw-egress
# gateway are hardened separately (REQ-HARDEN-001/002 and their own settings);
# the rest are third-party images whose hardening needs their own verification.
EXCEPTIONS = {
    "tool-runner": "needs cap_net_raw on nmap; hardened by REQ-HARDEN-001 (own settings)",
    "raw-egress-gateway": "owns the nftables rules; hardened by REQ-HARDEN-002",
    "postgres": "third-party image, initialises its data directory as root",
    "redis": "third-party image",
    "migrate": "one-shot job, not a long-running service",
}


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "compose", "version"], capture_output=True, check=True, timeout=30)
        return True
    except Exception:  # noqa: BLE001
        return False


def _render(env: dict[str, str], env_file: Path | None, *files: str) -> dict:
    cmd = ["docker", "compose"]
    if env_file:
        cmd += ["--env-file", str(env_file)]
    for f in files:
        cmd += ["-f", str(ROOT / f)]
    cmd += ["--profile", "runner", "--profile", "production", "config", "--format", "json"]
    out = subprocess.run(
        cmd, capture_output=True, text=True, timeout=120, check=True, cwd=ROOT,
        env={**os.environ, **env},
    )
    return json.loads(out.stdout)


@pytest.fixture(scope="module")
def configs(tmp_path_factory):
    if not _docker_available():
        pytest.skip("docker/compose not available")
    tmp = tmp_path_factory.mktemp("hardening")
    env_file = tmp / ".env.prod"
    env_file.write_text(render(build_env("scan.example.org", env_name="prod")))
    return {
        "dev": _render({}, env_file, "docker-compose.yml"),
        "prod": _render({}, env_file, "docker-compose.yml", "docker-compose.prod.yml"),
        "prod-noedge": _render({}, env_file, "docker-compose.yml", "docker-compose.prod-noedge.yml"),
        "shared-edge": _render(
            {"ASM_DOMAIN_PROD": "scan.example.org", "ASM_DOMAIN_INT": "scan-int.example.org"},
            None, "docker-compose.edge.yml",
        ),
    }


def _problems(name: str, svc: dict, allowed_caps: set[str]) -> list[str]:
    problems = []
    if svc.get("cap_drop") != ["ALL"]:
        problems.append(f"{name}: cap_drop must be [ALL], got {svc.get('cap_drop')}")
    if set(svc.get("cap_add") or []) != allowed_caps:
        problems.append(f"{name}: cap_add must be exactly {sorted(allowed_caps)}, got {svc.get('cap_add')}")
    if "no-new-privileges:true" not in (svc.get("security_opt") or []):
        problems.append(f"{name}: no-new-privileges:true missing")
    if svc.get("read_only") is not True:
        problems.append(f"{name}: read_only must be true")
    if svc.get("privileged"):
        problems.append(f"{name}: must not be privileged")
    return problems


@pytest.mark.parametrize("target", ["dev", "prod", "prod-noedge"])
def test_negative_python_services_drop_every_capability_and_are_read_only(configs, target):
    services = configs[target]["services"]
    problems = []
    for name, caps in HARDENED.items():
        problems += _problems(name, services[name], caps)
    assert not problems, "\n".join(problems)


def test_negative_the_edge_keeps_only_net_bind_service(configs):
    problems = _problems("shared-edge", configs["shared-edge"]["services"]["edge"], EDGE_CAPS)
    problems += _problems("prod caddy", configs["prod"]["services"]["caddy"], EDGE_CAPS)
    assert not problems, "\n".join(problems)


def test_writable_paths_are_explicit_tmpfs_or_volumes(configs):
    """A read-only root needs somewhere to write: /tmp for the Python services
    (Celery beat schedule, temp files); the edge's state stays in its volumes."""
    services = configs["dev"]["services"]
    for name in HARDENED:
        targets = [t["target"] if isinstance(t, dict) else t.split(":")[0] for t in services[name].get("tmpfs") or []]
        assert "/tmp" in targets, f"{name} has no /tmp tmpfs"
    edge = configs["shared-edge"]["services"]["edge"]
    volume_targets = {v["target"] for v in edge["volumes"]}
    assert {"/data", "/config"} <= volume_targets


def test_every_long_running_service_is_either_hardened_or_a_documented_exception(configs):
    """A new service must be hardened (added to HARDENED) or listed with a reason."""
    known = set(HARDENED) | set(EXCEPTIONS) | {"caddy", "edge"}
    for target in ("dev", "prod"):
        unknown = set(configs[target]["services"]) - known
        assert not unknown, f"{target}: new service(s) {sorted(unknown)} - harden them or list in EXCEPTIONS with a reason"
