#!/usr/bin/env python3
"""Generate a hardened production .env for the ASM stack (REQ-PRODDEPLOY-002).

Produces every secret the production credential gate
(control-plane/app/config.py::reject_insecure_production_defaults) demands,
plus the loopback publish bindings and matching backing-service credentials so
Postgres / MinIO / the egress-proxy read-only role all agree. Standard library
only - no dependency on `cryptography` (the MFA key is a Fernet-compatible
urlsafe-base64 of 32 random bytes, exactly what Fernet.generate_key() emits).

Usage (single environment - docs/deployment-ionos.md):
    python3 scripts/gen_production_env.py --domain scan.example.com
    python3 scripts/gen_production_env.py --domain scan.example.com --out .env.production --force

Usage (multi-environment / shared edge, REQ-MULTIENV-002 - one call per named
environment on the host, e.g. "prod" and "int"):
    python3 scripts/gen_production_env.py --domain scan.example.com --env-name prod --out .env.prod
    python3 scripts/gen_production_env.py --domain scan-int.example.com --env-name int --out .env.int

--env-name picks non-colliding defaults (COMPOSE_PROJECT_NAME, Postgres user/db,
CONTROL_PLANE_PUBLISH_PORT, MINIO_CONSOLE_PUBLISH_PORT) so two environments'
generated files never collide on a shared host; override any of them explicitly
if you need a third environment or different ports.

The output file is chmod 600 and must NEVER be committed. Copy it to the
production host as `.env` (compose auto-loads `.env` for both interpolation and
the services' env_file), then follow docs/deployment-ionos.md.
"""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import stat
import sys
from pathlib import Path


def _token(nbytes: int = 32) -> str:
    # urlsafe: only [A-Za-z0-9_-], safe inside URLs and SQL string literals.
    return secrets.token_urlsafe(nbytes)


def _fernet_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


# REQ-MULTIENV-002: non-colliding defaults per named environment. A third
# environment (or different ports) can always be set explicitly via the CLI flags.
_ENV_PORT_DEFAULTS = {
    "prod": {"api_port": 8000, "minio_console_port": 9001},
    "int": {"api_port": 8001, "minio_console_port": 9002},
}


def build_env(
    domain: str, *, env_name: str = "prod",
    api_port: int | None = None, minio_console_port: int | None = None,
) -> dict[str, str]:
    defaults = _ENV_PORT_DEFAULTS.get(env_name, _ENV_PORT_DEFAULTS["prod"])
    api_port = api_port if api_port is not None else defaults["api_port"]
    minio_console_port = minio_console_port if minio_console_port is not None else defaults["minio_console_port"]

    pg_user = f"asm_{env_name}"
    pg_db = f"asm_{env_name}"
    pg_password = _token(24)
    proxy_password = _token(24)
    s3_access = f"asm-{env_name}-" + secrets.token_hex(4)
    s3_secret = _token(24)

    return {
        "ENVIRONMENT": "production",
        # REQ-MULTIENV-002: distinct project name -> distinct containers/
        # volumes (pgdata, miniodata, ...) even on the same host/repo
        # checkout. Compose reads this from --env-file as a project-name
        # fallback; the runbook also passes an explicit -p for clarity.
        "COMPOSE_PROJECT_NAME": f"asm_{env_name}",
        # REQ-MULTIENV-004: a SEPARATE variable, not COMPOSE_PROJECT_NAME -
        # `docker compose config` auto-populates COMPOSE_PROJECT_NAME from the
        # checkout directory name whenever it isn't already set, so a
        # `${COMPOSE_PROJECT_NAME:-asm}` default inside docker-compose.yml
        # never actually falls back to 'asm' in practice. This variable is
        # never implicitly set by Compose itself, so its default only applies
        # for single-environment (dev) use, where it must stay literally
        # 'asm' to match lab-compose.yml's hardcoded external network
        # reference. Kept equal to COMPOSE_PROJECT_NAME here on purpose.
        "ASM_NETWORK_PREFIX": f"asm_{env_name}",
        # --- public entrypoint ---
        "ASM_DOMAIN": domain,
        # Everything except Caddy binds to loopback (REQ-PRODDEPLOY-001).
        # With the shared-edge topology (docker-compose.prod-noedge.yml) there
        # is no per-environment Caddy at all; these still gate the app's own
        # ports to loopback-only, and the PORT keeps two environments distinct.
        "CONTROL_PLANE_PUBLISH_HOST": "127.0.0.1",
        "CONTROL_PLANE_PUBLISH_PORT": str(api_port),
        "MINIO_CONSOLE_PUBLISH_HOST": "127.0.0.1",
        "MINIO_CONSOLE_PUBLISH_PORT": str(minio_console_port),
        # --- Postgres (container creds + app URL must match) ---
        "POSTGRES_USER": pg_user,
        "POSTGRES_PASSWORD": pg_password,
        "POSTGRES_DB": pg_db,
        "DATABASE_URL": f"postgresql+psycopg://{pg_user}:{pg_password}@postgres:5432/{pg_db}",
        # --- egress-proxy read-only role (rotated by the migrate service) ---
        "PROXY_DB_PASSWORD": proxy_password,
        "PROXY_DATABASE_URL": f"postgresql+psycopg://asm_proxy_ro:{proxy_password}@postgres:5432/{pg_db}",
        # --- object store (MinIO root creds come from these) ---
        "S3_ACCESS_KEY": s3_access,
        "S3_SECRET_KEY": s3_secret,
        "S3_ENDPOINT": "http://minio:9000",
        "S3_BUCKET": "asm-evidence",
        # --- application secrets (all gate-checked) ---
        "OPERATOR_API_TOKEN": _token(32),  # gate-required though the shared path is rejected in prod
        "INTERNAL_API_TOKEN": _token(32),
        "SCOPE_SIGNING_SECRET": _token(32),
        "RAW_EGRESS_SIGNING_SECRET": _token(32),
        "RUNNER_API_TOKEN": _token(32),
        "RAW_EGRESS_API_TOKEN": _token(32),  # docker-compose.prod.yml requires it (issue #22)
        "OOB_TOKEN": _token(32),  # REQ-COVER-004: interaction-server token (prod overlay requires it)
        "MFA_ENCRYPTION_KEY": _fernet_key(),
        # --- bounded operational values (must stay within the gate's ranges) ---
        "RAW_EGRESS_LEASE_TTL_SECONDS": "900",
        "NMAP_MAX_RATE": "1000",
        "RAW_EGRESS_MAX_CONCURRENT_LEASES": "2",
        # --- LLM provider: set later via the Settings GUI (leave blank here) ---
        "LLM_BASE_URL": "",
        "LLM_API_KEY": "",
        "LLM_MODEL": "",
    }


HEADER = """\
# ASM production environment - generated by scripts/gen_production_env.py
# DO NOT COMMIT. Copy to the production host as `.env` (chmod 600).
# The LLM provider is intentionally blank; configure it in Settings after login.
# See docs/deployment-ionos.md for the full deployment runbook.
"""


def render(env: dict[str, str]) -> str:
    lines = [HEADER]
    for key, value in env.items():
        lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a hardened production .env for the ASM stack.")
    parser.add_argument("--domain", required=True, help="Public hostname pointing at the VPS (for Caddy HTTPS).")
    parser.add_argument("--out", default=".env.production", help="Output path (default: .env.production).")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing output file.")
    parser.add_argument(
        "--env-name", default="prod",
        help="Named environment on a shared host (REQ-MULTIENV-002), e.g. 'prod' or 'int'. "
             "Picks non-colliding defaults for the project name, Postgres db/user, and ports.",
    )
    parser.add_argument("--api-port", type=int, default=None, help="Override CONTROL_PLANE_PUBLISH_PORT.")
    parser.add_argument("--minio-console-port", type=int, default=None, help="Override MINIO_CONSOLE_PUBLISH_PORT.")
    args = parser.parse_args()

    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"refusing to overwrite existing {out} (use --force)", file=sys.stderr)
        return 1

    env = build_env(args.domain, env_name=args.env_name, api_port=args.api_port,
                    minio_console_port=args.minio_console_port)
    out.write_text(render(env), encoding="utf-8")
    out.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600

    print(f"wrote {out} (0600) with {len(env)} entries for domain {args.domain!r} (env-name={args.env_name!r})")
    print("Next: review it, copy to the production host, then follow docs/deployment-ionos.md.")
    print("The LLM provider is blank - set it in Settings after the first admin logs in.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
