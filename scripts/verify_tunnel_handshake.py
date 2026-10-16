#!/usr/bin/env python3
"""REQ-EGRESS-004: prove nuclei's raw-request templates are not stalled by the egress proxy.

nuclei sends every `unsafe: true` template through its own raw HTTP client. That client waited 60 s
for a header line in the proxy's reply to CONNECT, sent nothing through the tunnel and gave up, so
those checks never reached a target while still reading "complete" (found on int, 2026-10-02: one
nuclei shard took 545 s instead of 14 s). A unit test can model that client; only the real nuclei
binary can prove it. This runs the real proxy handler and the real nuclei from the tool-runner image
against a real Caddy, on a throwaway internal Docker network without internet access, and fails if
any raw-request template takes noticeably longer through the proxy than it does without one.

The raw-request templates are not listed here: they are read from the image's own template index,
so a template update that adds one is checked too.

    python3 scripts/verify_tunnel_handshake.py
    python3 scripts/verify_tunnel_handshake.py --proxy-app-dir /path/to/other/egress-proxy/app   # prove a build fails
    python3 scripts/verify_tunnel_handshake.py --proxy-app-dir image   # judge the code baked into the built image

Needs Docker and three local images (the tool-runner and the egress-proxy built from this checkout,
and `caddy:2-alpine`). Exit code 0 = the proxy adds no stall to any template, 1 = a template was stalled by the proxy,
2 = the check could not run. A template that is slow on its own (some smuggling checks deliberately
wait for the server) is not a failure: each one is timed without the proxy first and judged against that.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "tunnel_handshake_proxy_harness.py"
DEFAULT_PROXY_APP = ROOT / "egress-proxy" / "app"
IMAGE_CODE = "image"  # --proxy-app-dir value: use the code inside the proxy image, mount nothing over it
DEFAULT_TOOL_RUNNER = os.environ.get("TOOL_RUNNER_IMAGE", "asm_business-tool-runner:latest")
DEFAULT_PROXY_IMAGE = os.environ.get("EGRESS_PROXY_IMAGE", "asm_business-egress-proxy:latest")
CADDY_IMAGE = "caddy:2-alpine"
TARGET_HOST = "tunnel-check-target"
TARGET = f"https://{TARGET_HOST}:8443"
PROXY_HOST = "tunnel-check-proxy"
# The stall this guards against is 60 s per request. A tunnel that works adds well under a second;
# the margin only has to sit far below 60 s and far above timing noise.
DEFAULT_MARGIN_SECONDS = 15.0
SETTLE_SECONDS = 3
# Same shape as the production invocation (worker/app/tool_runner_client.py): per-request timeout,
# one retry, the proxy, no interactsh. Tag filters are left out on purpose: the templates are named.
NUCLEI_FLAGS = "-disable-update-check -silent -no-color -rate-limit 50 -timeout 8 -retries 1 -no-interactsh"
CADDYFILE = f"""{{
\tauto_https disable_redirects
\tadmin off
}}
{TARGET_HOST}:8443 {{
\ttls internal
\trespond / "ok" 200
\trespond "not found" 404
}}
"""

Run = Callable[..., subprocess.CompletedProcess]


class CheckCannotRun(Exception):
    """An environment problem (no Docker, missing image): not a verdict on the proxy."""


def docker(args: list[str], *, run: Run = subprocess.run, check: bool = False, timeout: int = 300):
    return run(["docker", *args], capture_output=True, text=True, check=check, timeout=timeout)


def require_images(images: list[str], *, run: Run = subprocess.run) -> None:
    for image in images:
        try:
            found = docker(["image", "inspect", image], run=run, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CheckCannotRun(f"docker is not usable: {exc}") from exc
        if found.returncode != 0:
            raise CheckCannotRun(f"image {image} is not present locally (build it from this checkout first)")


def parse_template_list(output: str) -> list[str]:
    """Template paths from the image: one absolute path per line; anything else is noise."""
    return sorted({line.strip() for line in output.splitlines() if line.strip().startswith("/") and line.strip().endswith(".yaml")})


def unsafe_templates(tool_runner: str, *, run: Run = subprocess.run) -> list[str]:
    script = (
        "python3 /opt/asm/nuclei_index.py select --group all --out /dev/stdout "
        "| grep '^/opt/nuclei-templates/' | xargs grep -l 'unsafe: true'"
    )
    found = docker(["run", "--rm", "--entrypoint", "sh", tool_runner, "-c", script], run=run, timeout=180)
    templates = parse_template_list(found.stdout)
    if not templates:
        raise CheckCannotRun("the image's template index lists no unsafe: true template, so there is nothing to check")
    return templates


def time_template(network: str, tool_runner: str, template: str, *, via_proxy: bool, run: Run = subprocess.run,
                  clock=time.monotonic) -> float:
    proxy = f"-p http://{PROXY_HOST}:3128" if via_proxy else ""
    started = clock()
    docker(
        ["run", "--rm", "--network", network, "--entrypoint", "sh", tool_runner, "-c",
         f"timeout 150 nuclei -u {TARGET} -t {template} {NUCLEI_FLAGS} {proxy} >/dev/null 2>&1"],
        run=run, timeout=200,
    )
    return clock() - started


def evaluate(direct: dict[str, float], proxied: dict[str, float], margin: float) -> list[str]:
    """The templates the proxy made slower by more than the margin (what a stalled tunnel looks like).
    A template that is slow without the proxy is judged against its own time, not against a fixed limit."""
    return sorted(t for t, seconds in proxied.items() if seconds - direct[t] > margin)


def app_mount(proxy_app_dir: str) -> list[str]:
    """The docker arguments that put the proxy code under test into the container: a directory is mounted
    read-only over the image's own code; `image` mounts nothing, so the built image itself is judged."""
    return [] if proxy_app_dir == IMAGE_CODE else ["-v", f"{proxy_app_dir}:/app/app:ro"]


def verify(args, *, run: Run = subprocess.run) -> int:
    require_images([args.tool_runner, args.proxy_image, CADDY_IMAGE], run=run)
    if args.proxy_app_dir != IMAGE_CODE and not (Path(args.proxy_app_dir) / "proxy.py").is_file():
        raise CheckCannotRun(f"{args.proxy_app_dir} is not an egress-proxy app directory")
    templates = unsafe_templates(args.tool_runner, run=run)
    network = f"tunnel-check-{uuid.uuid4().hex[:8]}"
    containers: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        caddyfile = Path(tmp) / "Caddyfile"
        caddyfile.write_text(CADDYFILE, encoding="utf-8")
        caddyfile.chmod(0o644)
        try:
            docker(["network", "create", "--internal", network], run=run, check=True, timeout=60)
            docker(["run", "-d", "--rm", "--name", TARGET_HOST + network[-8:], "--network", network,
                    "--network-alias", TARGET_HOST, "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro", CADDY_IMAGE],
                   run=run, check=True, timeout=120)
            containers.append(TARGET_HOST + network[-8:])
            docker(["run", "-d", "--rm", "--name", PROXY_HOST + network[-8:], "--network", network,
                    "--network-alias", PROXY_HOST, *app_mount(args.proxy_app_dir),
                    "-v", f"{HARNESS}:/app/harness.py:ro", "--entrypoint", "python", args.proxy_image, "harness.py"],
                   run=run, check=True, timeout=120)
            containers.append(PROXY_HOST + network[-8:])
            time.sleep(SETTLE_SECONDS)
            with ThreadPoolExecutor(max_workers=8) as pool:
                direct = dict(zip(templates, pool.map(
                    lambda t: time_template(network, args.tool_runner, t, via_proxy=False, run=run), templates)))
                proxied = dict(zip(templates, pool.map(
                    lambda t: time_template(network, args.tool_runner, t, via_proxy=True, run=run), templates)))
        except subprocess.CalledProcessError as exc:
            raise CheckCannotRun(f"could not set up the throwaway environment: {exc.stderr or exc}") from exc
        finally:
            for name in containers:
                docker(["rm", "-f", name], run=run, timeout=60)
            docker(["network", "rm", network], run=run, timeout=60)
    stalled = evaluate(direct, proxied, args.margin)
    print(f"  {'direct':>8} {'proxy':>8}")
    for template in templates:
        verdict = "STALLED" if template in stalled else "ok"
        print(f"  {direct[template]:7.1f}s {proxied[template]:7.1f}s  {verdict:8} {Path(template).name}")
    if stalled:
        print(f"FAIL: the proxy made {len(stalled)} of {len(templates)} raw-request templates more than "
              f"{args.margin:.0f} s slower (the stall this check exists for).")
        return 1
    print(f"PASS: the proxy added no more than {args.margin:.0f} s to any of {len(templates)} raw-request templates.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--tool-runner", default=DEFAULT_TOOL_RUNNER)
    parser.add_argument("--proxy-image", default=DEFAULT_PROXY_IMAGE)
    parser.add_argument("--proxy-app-dir", default=str(DEFAULT_PROXY_APP), help="the egress-proxy `app` directory to test, or `image` for the code baked into the proxy image")
    parser.add_argument("--margin", type=float, default=DEFAULT_MARGIN_SECONDS,
                        help="seconds the proxy may add to one template compared with running it without the proxy")
    args = parser.parse_args(argv)
    try:
        return verify(args)
    except CheckCannotRun as exc:
        print(f"cannot run: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
