"""REQ-PRODDEPLOY-001: on a public host the production compose profile must
publish ONLY Caddy (80/443). Every other service - control-plane, Postgres,
everything - must be bound to loopback or not published at all, and
backing-service credentials must actually be the injected secrets (not the dev
defaults). REQ-INSTALL-002 tightens this for the object store: it publishes
NO port at all (the old rule only bound its console to loopback), sits on a
network only the control-plane joins, and runs with the injected credentials.

This renders the real merged config via `docker compose config` with a
production-shaped env and asserts the exposure. It is skipped when Docker/compose
is unavailable so the unit suite stays runnable without infra."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

PROD_ENV = {
    "ENVIRONMENT": "production",
    "ASM_DOMAIN": "scan.example.test",
    "CONTROL_PLANE_PUBLISH_HOST": "127.0.0.1",
    "POSTGRES_USER": "asm_prod",
    "POSTGRES_PASSWORD": "prod-pg-secret-xyz",
    "POSTGRES_DB": "asm_prod",
    "DATABASE_URL": "postgresql+psycopg://asm_prod:prod-pg-secret-xyz@postgres:5432/asm_prod",
    "PROXY_DB_PASSWORD": "prod-proxy-secret-xyz",
    "PROXY_DATABASE_URL": "postgresql+psycopg://asm_proxy_ro:prod-proxy-secret-xyz@postgres:5432/asm_prod",
    "S3_ACCESS_KEY": "asm-prod-access",
    "S3_SECRET_KEY": "prod-object-secret-xyz",
    "OPERATOR_API_TOKEN": "t-operator",
    "INTERNAL_API_TOKEN": "t-internal",
    "SCOPE_SIGNING_SECRET": "t-scope",
    "RAW_EGRESS_SIGNING_SECRET": "t-rawegress",
    "RUNNER_API_TOKEN": "t-runner",
    "RAW_EGRESS_API_TOKEN": "t-raw-egress-api",
    "OOB_TOKEN": "t-oob-token",
    "MFA_ENCRYPTION_KEY": "not-the-dev-default-key=",
    "SETTINGS_ENCRYPTION_KEY": "KUX7ADnLj8eEdXJGw-F9-rjiLPnNWw9l82jFw4RluRc=",
}


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


def _published(config: dict) -> list[tuple[str, str, str]]:
    rows = []
    for name, svc in config.get("services", {}).items():
        for p in svc.get("ports", []) or []:
            if isinstance(p, dict):
                rows.append((name, str(p.get("host_ip", "0.0.0.0")), str(p.get("published"))))
    return rows


@pytest.fixture(scope="module")
def prod_config(tmp_path_factory):
    if not _docker_available():
        pytest.skip("docker/compose not available")
    env_file = tmp_path_factory.mktemp("prodenv") / ".env"
    env_file.write_text("\n".join(f"{k}={v}" for k, v in PROD_ENV.items()) + "\n")
    return _render(env_file, "docker-compose.yml", "docker-compose.prod.yml",
                   profiles=("runner", "production"))


def test_only_caddy_is_publicly_published(prod_config):
    public = [(n, hip, pub) for (n, hip, pub) in _published(prod_config) if hip in ("0.0.0.0", "::")]
    assert public, "expected at least Caddy to be published"
    assert all(n == "caddy" for (n, _, _) in public), f"non-caddy public exposure: {public}"
    published_ports = {pub for (_, _, pub) in public}
    assert published_ports <= {"80", "443"}, f"caddy publishes unexpected ports: {published_ports}"


def test_control_plane_binds_loopback_and_the_object_store_publishes_nothing(prod_config):
    binds = {n: hip for (n, hip, _) in _published(prod_config)}
    assert binds.get("control-plane") == "127.0.0.1", binds
    # [Negative test] REQ-INSTALL-002: stricter than the former console rule - not even loopback.
    assert "seaweedfs" not in binds, binds
    assert not prod_config["services"]["seaweedfs"].get("ports"), prod_config["services"]["seaweedfs"].get("ports")


def test_backing_services_use_injected_credentials(prod_config):
    svcs = prod_config["services"]
    pg = svcs["postgres"]["environment"]
    assert pg["POSTGRES_PASSWORD"] == "prod-pg-secret-xyz"
    assert pg["POSTGRES_USER"] == "asm_prod"
    store = svcs["seaweedfs"]["environment"]
    # The store's credentials must be the injected S3 secret, never a public default.
    assert store["AWS_ACCESS_KEY_ID"] == "asm-prod-access"
    assert store["AWS_SECRET_ACCESS_KEY"] == "prod-object-secret-xyz"
    for default in ("minioadmin", "asm-dev-access", "asm-dev-secret-change-me"):
        assert default not in (store["AWS_ACCESS_KEY_ID"], store["AWS_SECRET_ACCESS_KEY"])


def test_object_store_is_isolated_pinned_and_hardened_in_production(prod_config):
    """REQ-INSTALL-002: only the control-plane may reach the store; its unauthenticated
    admin interfaces are never exposed; the image is pinned; it is hardened like its
    neighbours as far as the image allows."""
    svcs = prod_config["services"]
    store = svcs["seaweedfs"]
    assert set(store["networks"]) == {"objstore"}, store["networks"]
    assert prod_config["networks"]["objstore"]["internal"] is True
    members = {n for n, s in svcs.items() if "objstore" in (s.get("networks") or {})}
    assert members == {"seaweedfs", "control-plane"}, f"who can reach the object store: {members}"
    assert re.fullmatch(r"chrislusf/seaweedfs:\d+\.\d+@sha256:[0-9a-f]{64}", store["image"]), store["image"]
    assert store["cap_drop"] == ["ALL"] and set(store.get("cap_add", [])) <= {"CHOWN", "SETUID", "SETGID"}
    assert store["read_only"] is True
    assert "no-new-privileges:true" in store["security_opt"]
    assert store.get("healthcheck"), "the object store needs a health check"
    # The unauthenticated master/volume/filer interfaces must stay on the loopback, the optional ones off.
    command = " ".join(str(c) for c in store["command"])
    for needed in ("-ip.bind=127.0.0.1", "-s3.ip.bind=0.0.0.0", "-s3.port.iceberg=0", "-s3.port.lance=0"):
        assert needed in command, f"{needed} missing from the object store command"


# GitHub issue #17: docker-compose.prod.yml set ENVIRONMENT=production on
# control-plane only - every other service with a fail-closed production
# startup guard (worker, egress-proxy, raw-egress-gateway, and especially
# tool-runner, which had NO override at all) silently kept running its dev
# defaults, including tool-runner accepting the publicly-known dev token as
# valid authentication to an arbitrary-command execution boundary.
_GUARDED_SERVICES = ("control-plane", "worker", "egress-proxy", "raw-egress-gateway", "tool-runner")


def test_every_guarded_service_gets_production_environment(prod_config):
    missing = [
        name for name in _GUARDED_SERVICES
        if prod_config["services"][name]["environment"].get("ENVIRONMENT") != "production"
    ]
    assert not missing, f"services missing ENVIRONMENT=production: {missing}"


def _render_missing(tmp_path_factory, missing_key: str) -> subprocess.CompletedProcess:
    """Like the prod_config fixture, but WITHOUT `missing_key` in the env -
    and without check=True, since the point of these tests is to observe the
    failure, not raise past it."""
    env_file = tmp_path_factory.mktemp("prodenv-missing") / ".env"
    env = {k: v for k, v in PROD_ENV.items() if k != missing_key}
    env_file.write_text("\n".join(f"{k}={v}" for k, v in env.items()) + "\n")
    cmd = ["docker", "compose", "--env-file", str(env_file)]
    for f in ("docker-compose.yml", "docker-compose.prod.yml"):
        cmd += ["-f", str(ROOT / f)]
    for p in ("runner", "production"):
        cmd += ["--profile", p]
    cmd += ["config", "--format", "json"]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=ROOT)


@pytest.mark.parametrize("missing_key", [
    "RUNNER_API_TOKEN", "RAW_EGRESS_API_TOKEN", "OOB_TOKEN", "CONTROL_PLANE_PUBLISH_HOST",
    # REQ-INSTALL-002: production must not run the object store with the public development credential.
    "S3_ACCESS_KEY", "S3_SECRET_KEY",
])
def test_negative_config_fails_closed_when_a_required_prod_var_is_missing(tmp_path_factory, missing_key):
    """GitHub issue #17: these three vars previously had only a documented,
    never an enforced, requirement - omitting them silently fell back to an
    insecure/public default instead of refusing to start."""
    if not _docker_available():
        pytest.skip("docker/compose not available")
    result = _render_missing(tmp_path_factory, missing_key)
    assert result.returncode != 0, f"docker compose config should have failed with {missing_key} unset"
    assert missing_key in result.stderr


def test_dev_config_keeps_the_local_defaults_and_still_hides_the_object_store():
    """Guard: the dev profile keeps Postgres' asm default (local development is not
    disrupted), and even in development the object store publishes no port
    (REQ-INSTALL-002: the filer UI it would offer has no login)."""
    if not _docker_available():
        pytest.skip("docker/compose not available")
    cfg = _render(ROOT / ".env.example", "docker-compose.yml", profiles=("runner",)) \
        if (ROOT / ".env.example").exists() else _render_empty()
    binds = {n: hip for (n, hip, _) in _published(cfg)}
    assert "seaweedfs" not in binds, binds
    assert cfg["services"]["postgres"]["environment"]["POSTGRES_PASSWORD"] == "asm"
    members = {n for n, s in cfg["services"].items() if "objstore" in (s.get("networks") or {})}
    assert members == {"seaweedfs", "control-plane"}, members


def _render_empty() -> dict:
    empty = ROOT / "scripts" / "tests" / "_empty.env"
    empty.write_text("")
    try:
        return _render(empty, "docker-compose.yml", profiles=("runner",))
    finally:
        empty.unlink(missing_ok=True)


# --- REQ-COVER-004: the optional self-hosted interaction server ---

@pytest.fixture(scope="module")
def oob_config(tmp_path_factory):
    if not _docker_available():
        pytest.skip("docker/compose not available")
    env_file = tmp_path_factory.mktemp("oobenv") / ".env"
    env_file.write_text("\n".join(f"{k}={v}" for k, v in PROD_ENV.items()) + "\n")
    return _render(env_file, "docker-compose.yml", "docker-compose.prod.yml",
                   profiles=("runner", "production", "oob"))


def test_interaction_server_is_loopback_only_dns_only_by_default(oob_config):
    rows = [(hip, pub) for (n, hip, pub) in _published(oob_config) if n == "interactsh"]
    assert rows, "interactsh publishes its DNS port"
    assert all(hip == "127.0.0.1" for hip, _ in rows), rows
    ports = [p for p in oob_config["services"]["interactsh"]["ports"]]
    assert {(p["target"], p["protocol"]) for p in ports} == {(5353, "udp"), (5353, "tcp")}, ports


def test_interaction_server_is_hardened_and_isolated(oob_config):
    svc = oob_config["services"]["interactsh"]
    assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"]
    assert "@sha256:" in svc["image"]
    assert set(svc["networks"]) == {"edge"}
    assert oob_config["networks"]["oob"]["internal"] is True
    for forbidden in ("-wildcard", "-wc", "-ldap", "-smb", "-ftp", "-responder"):
        assert forbidden not in svc["command"], forbidden
    assert "t-oob-token" in svc["command"]


def test_only_gateway_and_relay_join_the_oob_network(oob_config):
    members = {n for n, s in oob_config["services"].items() if "oob" in (s.get("networks") or {})}
    assert members == {"oob-relay", "raw-egress-gateway"}, members


def test_oob_relay_is_hardened_and_names_the_oob_domain(oob_config):
    svc = oob_config["services"]["oob-relay"]
    assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"]
    assert "@sha256:" in svc["image"]
    assert not svc.get("ports"), "the relay is never published"
    assert svc["networks"]["oob"]["aliases"] == ["oob.invalid"]
    assert oob_config["services"]["raw-egress-gateway"]["environment"]["OOB_SERVER_HOST"] == "oob.invalid"
