"""REQ-MULTIENV-001 / REQ-IAM-010: the edge Caddyfiles must route API paths to
the backend BEFORE falling back to serving the SPA's index.html.

Caddy's GLOBAL directive execution order runs file_server/try_files before
reverse_proxy regardless of the order written in the Caddyfile - confirmed by
local reproduction: a matcher-scoped `reverse_proxy` with no enclosing `route{}`
block silently lost to the SPA fallback, so EVERY API call (auth, engagements,
...) served the SPA's index.html (HTTP 200) instead of reaching the backend.
An explicit `route {}` block forces the written top-to-bottom order instead.

This is Caddy runtime semantics, not something a text/regex check can catch -
so this test actually runs the real Caddyfiles (re-addressed from a domain to
a local port, so no real ACME/DNS is involved) against a stub backend in
Docker. Skipped when Docker is unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PYTHON_ALPINE = "python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
CADDY_ALPINE = "caddy:2-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "version"], capture_output=True, check=True, timeout=15)
        return True
    except Exception:  # noqa: BLE001
        return False


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, **kw)


def _rm(*names: str) -> None:
    for name in names:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)


def _get_raw(url: str, tries: int = 20, headers: dict[str, str] | None = None):
    """Like _get, but returns the raw response object (so callers can read
    response headers, e.g. Content-Encoding) instead of just status+body."""
    last_exc = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(url, headers=headers or {})
            return urllib.request.urlopen(req, timeout=2)
        except urllib.error.HTTPError as exc:
            return exc
        except Exception as exc:  # noqa: BLE001 - connection refused/reset while starting up
            last_exc = exc
            time.sleep(0.5)
    raise AssertionError(f"never got a response from {url}: {last_exc}")


def _get(url: str, tries: int = 20, headers: dict[str, str] | None = None) -> tuple[int, str]:
    """GET url, retrying only on connection failures (server not up yet). Any
    HTTP status - including 404/502 - is a real response, not a retry trigger:
    it proves *something* answered, which is exactly what these tests check."""
    last_exc = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=2) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001 - connection refused/reset while starting up
            last_exc = exc
            time.sleep(0.5)
    raise AssertionError(f"never got a response from {url}: {last_exc}")


def _wait_for_stub_backend(name: str, port: str, tries: int = 60) -> None:
    """Block until the stub backend inside container `name` accepts
    connections. Caddy can come up before it on a slower host (a CI runner)
    and answer 502, which _get would rightly treat as a real response."""
    probe = (f"import urllib.request\n"
             f"urllib.request.urlopen('http://127.0.0.1:{port}/', timeout=1)")
    for _ in range(tries):
        if _run(["docker", "exec", name, "python3", "-c", probe]).returncode == 0:
            return
        time.sleep(0.5)
    raise AssertionError(f"stub backend {name} never listened on port {port}")


# A real browser's top-level navigation Accept header always leads with
# text/html; the SPA's own fetch()/XHR calls never send this (client.ts sets
# no Accept override, so fetch()'s default is "*/*").
_HTML_NAVIGATION_HEADERS = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
_XHR_HEADERS = {"Accept": "application/json"}


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_edge_caddyfile_routes_api_before_spa_fallback(tmp_path):
    """edge/Caddyfile (single-environment, hardcoded 'control-plane:8000')."""
    net = "asm-edge-test-net"
    backend, caddy = "asm-edge-test-backend", "asm-edge-test-caddy"
    _rm(backend, caddy)
    subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)
    assert _run(["docker", "network", "create", net]).returncode == 0
    try:
        assert _run([
            "docker", "run", "-d", "--rm", "--name", backend,
            "--network", net, "--network-alias", "control-plane",
            PYTHON_ALPINE, "python3", "-m", "http.server", "8000",
        ]).returncode == 0
        _wait_for_stub_backend(backend, "8000")

        text = (ROOT / "edge" / "Caddyfile").read_text()
        assert "route {" in text, "expected an explicit route{} block in edge/Caddyfile"
        text = text.replace("{$ASM_DOMAIN} {", ":18080 {", 1)
        caddyfile = tmp_path / "Caddyfile"
        caddyfile.write_text(text)
        frontend = tmp_path / "frontend"
        frontend.mkdir()
        (frontend / "index.html").write_text("SPA_FALLBACK_MARKER")

        assert _run([
            "docker", "run", "-d", "--rm", "--name", caddy,
            "--network", net, "-p", "18080:18080",
            "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro",
            "-v", f"{frontend}:/srv/frontend:ro",
            CADDY_ALPINE,
        ]).returncode == 0

        status_api, body_api = _get("http://127.0.0.1:18080/auth/me")
        status_spa, body_spa = _get("http://127.0.0.1:18080/some/client/route")

        # The API path must reach the stub backend (Python http.server's own
        # 404 page, since /auth/me is not a real file it serves), NEVER the SPA
        # fallback - the historical bug served SPA_FALLBACK_MARKER here with a
        # 200, silently never reaching the backend.
        assert "SPA_FALLBACK_MARKER" not in body_api, (
            "API path served the SPA fallback instead of reverse_proxy - "
            "the route{} ordering fix has regressed"
        )
        assert status_api == 404 and "Error response" in body_api  # http.server's own 404 page: reached the stub backend

        # A client-side SPA route (not a real file, not an API path) must still
        # fall back to index.html.
        assert status_spa == 200
        assert "SPA_FALLBACK_MARKER" in body_spa
    finally:
        _rm(backend, caddy)
        subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_edge_shared_caddyfile_routes_api_before_spa_fallback(tmp_path):
    """edge-shared/Caddyfile (multi-environment, host networking, both site blocks)."""
    backend_prod, backend_int, caddy = (
        "asm-edge-shared-test-backend-prod", "asm-edge-shared-test-backend-int", "asm-edge-shared-test-caddy",
    )
    _rm(backend_prod, backend_int, caddy)
    try:
        for name, port in ((backend_prod, "18091"), (backend_int, "18092")):
            assert _run([
                "docker", "run", "-d", "--rm", "--name", name, "--network", "host",
                PYTHON_ALPINE, "python3", "-m", "http.server", port,
            ]).returncode == 0
            _wait_for_stub_backend(name, port)

        text = (ROOT / "edge-shared" / "Caddyfile").read_text()
        assert text.count("route {") == 2, "expected an explicit route{} block in both site blocks"
        text = text.replace("{$ASM_DOMAIN_PROD} {", ":18081 {", 1)
        text = text.replace("{$ASM_DOMAIN_INT} {", ":18082 {", 1)
        caddyfile = tmp_path / "Caddyfile"
        caddyfile.write_text(text)
        frontend_prod, frontend_int = tmp_path / "frontend-prod", tmp_path / "frontend-int"
        frontend_prod.mkdir()
        frontend_int.mkdir()
        (frontend_prod / "index.html").write_text("SPA_FALLBACK_PROD")
        (frontend_int / "index.html").write_text("SPA_FALLBACK_INT")

        assert _run([
            "docker", "run", "-d", "--rm", "--name", caddy, "--network", "host",
            "-e", "PROD_API_PORT=18091", "-e", "INT_API_PORT=18092",
            "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro",
            "-v", f"{frontend_prod}:/srv/frontend-prod:ro",
            "-v", f"{frontend_int}:/srv/frontend-int:ro",
            CADDY_ALPINE,
        ]).returncode == 0

        for label, api_port, spa_marker in (("prod", "18081", "SPA_FALLBACK_PROD"), ("int", "18082", "SPA_FALLBACK_INT")):
            status_api, body_api = _get(f"http://127.0.0.1:{api_port}/auth/me")
            status_spa, body_spa = _get(f"http://127.0.0.1:{api_port}/some/client/route")
            assert spa_marker not in body_api, f"[{label}] API path served the SPA fallback, not the backend"
            assert status_api == 404 and "Error response" in body_api, f"[{label}] did not reach the stub backend"
            assert status_spa == 200
            assert spa_marker in body_spa, f"[{label}] SPA fallback route did not serve its own frontend"
    finally:
        _rm(backend_prod, backend_int, caddy)


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_edge_caddyfile_spa_routes_survive_hard_navigation_despite_api_prefix_overlap(tmp_path):
    """edge/Caddyfile: /engagements/:id, bare /settings, and /admin/users are
    real frontend SPA routes at the exact same path shape as real API
    prefixes. Found live in production: a hard refresh at /settings or
    /engagements/<id> got the backend's 404 JSON instead of the SPA shell
    (over-broad prefix match), and /admin/* was missing from the matcher
    entirely, so every admin API call silently got index.html instead of ever
    reaching the backend."""
    net = "asm-edge-test-net2"
    backend, caddy = "asm-edge-test-backend2", "asm-edge-test-caddy2"
    _rm(backend, caddy)
    subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)
    assert _run(["docker", "network", "create", net]).returncode == 0
    try:
        assert _run([
            "docker", "run", "-d", "--rm", "--name", backend,
            "--network", net, "--network-alias", "control-plane",
            PYTHON_ALPINE, "python3", "-m", "http.server", "8000",
        ]).returncode == 0
        _wait_for_stub_backend(backend, "8000")

        text = (ROOT / "edge" / "Caddyfile").read_text()
        text = text.replace("{$ASM_DOMAIN} {", ":18083 {", 1)
        caddyfile = tmp_path / "Caddyfile"
        caddyfile.write_text(text)
        frontend = tmp_path / "frontend"
        frontend.mkdir()
        (frontend / "index.html").write_text("SPA_FALLBACK_MARKER")

        assert _run([
            "docker", "run", "-d", "--rm", "--name", caddy,
            "--network", net, "-p", "18083:18083",
            "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro",
            "-v", f"{frontend}:/srv/frontend:ro",
            CADDY_ALPINE,
        ]).returncode == 0

        base = "http://127.0.0.1:18083"

        # /admin/users: previously missing from the matcher entirely -
        # silently served the SPA fallback for every admin API call.
        status, body = _get(f"{base}/admin/users", headers=_XHR_HEADERS)
        assert "SPA_FALLBACK_MARKER" not in body, "/admin/users served the SPA instead of the backend"
        assert status == 404 and "Error response" in body

        # A hard navigation/refresh at a real SPA route that overlaps an API
        # prefix must still get the SPA shell, not the backend's 404.
        for path in ("/settings", "/engagements/019fa8b1-ea8f-7308-9464-0811b85fcc47", "/admin/users"):
            status, body = _get(f"{base}{path}", headers=_HTML_NAVIGATION_HEADERS)
            assert status == 200 and "SPA_FALLBACK_MARKER" in body, (
                f"hard navigation to {path} did not get the SPA shell (over-broad API prefix match)"
            )

        # The app's own XHR/fetch calls to those same path shapes must still
        # reach the backend - the fix must not have broken real API routing.
        for path in ("/settings/llm", "/engagements/019fa8b1-ea8f-7308-9464-0811b85fcc47"):
            status, body = _get(f"{base}{path}", headers=_XHR_HEADERS)
            assert "SPA_FALLBACK_MARKER" not in body, f"XHR call to {path} was wrongly served the SPA fallback"
            assert status == 404 and "Error response" in body
    finally:
        _rm(backend, caddy)
        subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_edge_shared_caddyfile_spa_routes_survive_hard_navigation_despite_api_prefix_overlap(tmp_path):
    """edge-shared/Caddyfile: same fix, multi-environment host-networking variant."""
    backend_prod, caddy = "asm-edge-shared-test-backend-prod2", "asm-edge-shared-test-caddy2"
    _rm(backend_prod, caddy)
    try:
        assert _run([
            "docker", "run", "-d", "--rm", "--name", backend_prod, "--network", "host",
            PYTHON_ALPINE, "python3", "-m", "http.server", "18093",
        ]).returncode == 0
        _wait_for_stub_backend(backend_prod, "18093")

        text = (ROOT / "edge-shared" / "Caddyfile").read_text()
        text = text.replace("{$ASM_DOMAIN_PROD} {", ":18084 {", 1)
        text = text.replace("{$ASM_DOMAIN_INT} {", ":18085 {", 1)
        caddyfile = tmp_path / "Caddyfile"
        caddyfile.write_text(text)
        frontend_prod, frontend_int = tmp_path / "frontend-prod", tmp_path / "frontend-int"
        frontend_prod.mkdir()
        frontend_int.mkdir()
        (frontend_prod / "index.html").write_text("SPA_FALLBACK_PROD")
        (frontend_int / "index.html").write_text("SPA_FALLBACK_INT")

        assert _run([
            "docker", "run", "-d", "--rm", "--name", caddy, "--network", "host",
            "-e", "PROD_API_PORT=18093", "-e", "INT_API_PORT=18093",
            "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro",
            "-v", f"{frontend_prod}:/srv/frontend-prod:ro",
            "-v", f"{frontend_int}:/srv/frontend-int:ro",
            CADDY_ALPINE,
        ]).returncode == 0

        base = "http://127.0.0.1:18084"
        status, body = _get(f"{base}/admin/users", headers=_XHR_HEADERS)
        assert "SPA_FALLBACK_PROD" not in body
        assert status == 404 and "Error response" in body

        for path in ("/settings", "/engagements/019fa8b1-ea8f-7308-9464-0811b85fcc47", "/admin/users"):
            status, body = _get(f"{base}{path}", headers=_HTML_NAVIGATION_HEADERS)
            assert status == 200 and "SPA_FALLBACK_PROD" in body, f"hard navigation to {path} did not get the SPA shell"

        for path in ("/settings/llm", "/engagements/019fa8b1-ea8f-7308-9464-0811b85fcc47"):
            status, body = _get(f"{base}{path}", headers=_XHR_HEADERS)
            assert "SPA_FALLBACK_PROD" not in body
            assert status == 404 and "Error response" in body
    finally:
        _rm(backend_prod, caddy)


# GitHub issue #21: /callback/openwire/{token} (REQ-AGENT-027) was not routed
# at the edge at all - it fell through to the SPA fallback exactly like the
# original bug this file's other tests guard against, so a probed target's
# CVE-2023-46604 confirmation request never reached the control plane.

@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_edge_caddyfile_routes_callback_to_backend_not_spa(tmp_path):
    """edge/Caddyfile: /callback* must reach the backend, from a client that
    sends no special Accept header (the realistic shape of a target's HTTP
    client, unlike a browser's text/html-leading navigation) AND from one
    that sends Accept: text/html (some HTTP client libraries do) - unlike
    /admin* etc., there is no real SPA route at this path, so it must never
    fall through regardless of Accept header."""
    net = "asm-edge-test-net-cb"
    backend, caddy = "asm-edge-test-backend-cb", "asm-edge-test-caddy-cb"
    _rm(backend, caddy)
    subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)
    assert _run(["docker", "network", "create", net]).returncode == 0
    try:
        assert _run([
            "docker", "run", "-d", "--rm", "--name", backend,
            "--network", net, "--network-alias", "control-plane",
            PYTHON_ALPINE, "python3", "-m", "http.server", "8000",
        ]).returncode == 0
        _wait_for_stub_backend(backend, "8000")

        text = (ROOT / "edge" / "Caddyfile").read_text()
        assert "/callback*" in text, "expected a /callback* matcher in edge/Caddyfile"
        text = text.replace("{$ASM_DOMAIN} {", ":20286 {", 1)
        caddyfile = tmp_path / "Caddyfile"
        caddyfile.write_text(text)
        frontend = tmp_path / "frontend"
        frontend.mkdir()
        (frontend / "index.html").write_text("SPA_FALLBACK_MARKER")

        assert _run([
            "docker", "run", "-d", "--rm", "--name", caddy,
            "--network", net, "-p", "20286:20286",
            "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro",
            "-v", f"{frontend}:/srv/frontend:ro",
            CADDY_ALPINE,
        ]).returncode == 0

        base = "http://127.0.0.1:20286"
        for label, headers in (("no-accept-override", {}), ("html-accept", _HTML_NAVIGATION_HEADERS)):
            status, body = _get(f"{base}/callback/openwire/some-token", headers=headers)
            assert "SPA_FALLBACK_MARKER" not in body, f"[{label}] /callback served the SPA instead of the backend"
            assert status == 404 and "Error response" in body, f"[{label}] /callback did not reach the stub backend"

        # Negative: a genuinely unknown path must still fall back to the SPA -
        # the fix must not have become "route everything".
        status, body = _get(f"{base}/some/unknown/path", headers=_HTML_NAVIGATION_HEADERS)
        assert status == 200 and "SPA_FALLBACK_MARKER" in body
    finally:
        _rm(backend, caddy)
        subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_edge_shared_caddyfile_routes_callback_to_backend_not_spa(tmp_path):
    """edge-shared/Caddyfile: same fix, both site blocks."""
    backend_prod, backend_int, caddy = (
        "asm-edge-shared-test-backend-prod-cb", "asm-edge-shared-test-backend-int-cb", "asm-edge-shared-test-caddy-cb",
    )
    _rm(backend_prod, backend_int, caddy)
    try:
        for name, port in ((backend_prod, "20296"), (backend_int, "20297")):
            assert _run([
                "docker", "run", "-d", "--rm", "--name", name, "--network", "host",
                PYTHON_ALPINE, "python3", "-m", "http.server", port,
            ]).returncode == 0
            _wait_for_stub_backend(name, port)

        text = (ROOT / "edge-shared" / "Caddyfile").read_text()
        assert text.count("path /callback*") == 2, "expected a /callback* matcher in both site blocks"
        text = text.replace("{$ASM_DOMAIN_PROD} {", ":20287 {", 1)
        text = text.replace("{$ASM_DOMAIN_INT} {", ":20288 {", 1)
        caddyfile = tmp_path / "Caddyfile"
        caddyfile.write_text(text)
        frontend_prod, frontend_int = tmp_path / "frontend-prod", tmp_path / "frontend-int"
        frontend_prod.mkdir()
        frontend_int.mkdir()
        (frontend_prod / "index.html").write_text("SPA_FALLBACK_PROD")
        (frontend_int / "index.html").write_text("SPA_FALLBACK_INT")

        assert _run([
            "docker", "run", "-d", "--rm", "--name", caddy, "--network", "host",
            "-e", "PROD_API_PORT=20296", "-e", "INT_API_PORT=20297",
            "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro",
            "-v", f"{frontend_prod}:/srv/frontend-prod:ro",
            "-v", f"{frontend_int}:/srv/frontend-int:ro",
            CADDY_ALPINE,
        ]).returncode == 0

        for label, api_port, spa_marker in (("prod", "20287", "SPA_FALLBACK_PROD"), ("int", "20288", "SPA_FALLBACK_INT")):
            for accept_label, headers in (("no-accept-override", {}), ("html-accept", _HTML_NAVIGATION_HEADERS)):
                status, body = _get(f"http://127.0.0.1:{api_port}/callback/openwire/some-token", headers=headers)
                assert spa_marker not in body, f"[{label}/{accept_label}] /callback served the SPA fallback"
                assert status == 404 and "Error response" in body, f"[{label}/{accept_label}] did not reach the stub backend"
    finally:
        _rm(backend_prod, backend_int, caddy)


# REQ-PRODDEPLOY-003 (GitHub issue #13): gzip must never apply to the API
# paths, only to the static SPA shell. Caddy's default gzip encoder has a
# minimum-length threshold (~512 bytes) below which it never compresses
# regardless of matcher - both payloads below are padded well past that, so
# an observed absence of Content-Encoding on the API path is actually this
# fix, not just a too-small body.
_PADDED_BODY = ("hello " * 200).strip()  # ~1200 bytes


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_edge_caddyfile_never_compresses_api_responses(tmp_path):
    """edge/Caddyfile: the static shell gets gzip, the API paths never do."""
    net = "asm-edge-test-net3"
    backend, caddy = "asm-edge-test-backend3", "asm-edge-test-caddy3"
    _rm(backend, caddy)
    subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)
    assert _run(["docker", "network", "create", net]).returncode == 0
    try:
        backend_root = tmp_path / "backend_root"
        (backend_root / "auth").mkdir(parents=True)
        (backend_root / "auth" / "me").write_text(_PADDED_BODY)
        assert _run([
            "docker", "run", "-d", "--rm", "--name", backend,
            "--network", net, "--network-alias", "control-plane",
            "-v", f"{backend_root}:/srv:ro", "-w", "/srv",
            PYTHON_ALPINE, "python3", "-m", "http.server", "8000",
        ]).returncode == 0
        _wait_for_stub_backend(backend, "8000")

        text = (ROOT / "edge" / "Caddyfile").read_text()
        assert "encode @not_api gzip" in text, "expected encode to be scoped away from the API paths"
        text = text.replace("{$ASM_DOMAIN} {", ":19180 {", 1)
        caddyfile = tmp_path / "Caddyfile"
        caddyfile.write_text(text)
        frontend = tmp_path / "frontend"
        frontend.mkdir()
        (frontend / "index.html").write_text(f"<html>{_PADDED_BODY}</html>")

        assert _run([
            "docker", "run", "-d", "--rm", "--name", caddy,
            "--network", net, "-p", "19180:19180",
            "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro",
            "-v", f"{frontend}:/srv/frontend:ro",
            CADDY_ALPINE,
        ]).returncode == 0

        base = "http://127.0.0.1:19180"
        gzip_headers = {"Accept-Encoding": "gzip"}

        resp_static = _get_raw(f"{base}/", tries=20, headers=gzip_headers)
        assert resp_static.headers.get("Content-Encoding") == "gzip", (
            "the static SPA shell must still be gzip-compressed"
        )

        resp_api = _get_raw(f"{base}/auth/me", tries=20, headers={**gzip_headers, **_XHR_HEADERS})
        assert resp_api.headers.get("Content-Encoding") != "gzip", (
            "an API response must never be gzip-compressed (BREACH exposure, GitHub issue #13)"
        )
    finally:
        _rm(backend, caddy)
        subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_edge_shared_caddyfile_never_compresses_api_responses(tmp_path):
    """edge-shared/Caddyfile: same fix, both the prod and int site blocks."""
    backend, caddy = "asm-edge-shared-test-backend3", "asm-edge-shared-test-caddy3"
    _rm(backend, caddy)
    try:
        backend_root = tmp_path / "backend_root"
        (backend_root / "engagements").mkdir(parents=True)
        (backend_root / "engagements" / "foo").write_text(_PADDED_BODY)
        assert _run([
            "docker", "run", "-d", "--rm", "--name", backend, "--network", "host",
            "-v", f"{backend_root}:/srv:ro", "-w", "/srv",
            PYTHON_ALPINE, "python3", "-m", "http.server", "19183",
        ]).returncode == 0
        _wait_for_stub_backend(backend, "19183")

        text = (ROOT / "edge-shared" / "Caddyfile").read_text()
        assert text.count("encode @not_api gzip") == 2, "expected encode scoped away from API paths in both blocks"
        text = text.replace("{$ASM_DOMAIN_PROD} {", ":19181 {", 1)
        text = text.replace("{$ASM_DOMAIN_INT} {", ":19182 {", 1)
        caddyfile = tmp_path / "Caddyfile"
        caddyfile.write_text(text)
        frontend_prod, frontend_int = tmp_path / "frontend-prod", tmp_path / "frontend-int"
        frontend_prod.mkdir()
        frontend_int.mkdir()
        (frontend_prod / "index.html").write_text(f"<html>{_PADDED_BODY}</html>")
        (frontend_int / "index.html").write_text(f"<html>{_PADDED_BODY}</html>")

        assert _run([
            "docker", "run", "-d", "--rm", "--name", caddy, "--network", "host",
            "-e", "PROD_API_PORT=19183", "-e", "INT_API_PORT=19183",
            "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro",
            "-v", f"{frontend_prod}:/srv/frontend-prod:ro",
            "-v", f"{frontend_int}:/srv/frontend-int:ro",
            CADDY_ALPINE,
        ]).returncode == 0

        gzip_headers = {"Accept-Encoding": "gzip"}
        for label, port in (("prod", "19181"), ("int", "19182")):
            base = f"http://127.0.0.1:{port}"
            resp_static = _get_raw(f"{base}/", tries=20, headers=gzip_headers)
            assert resp_static.headers.get("Content-Encoding") == "gzip", f"[{label}] static shell must be compressed"

            resp_api = _get_raw(f"{base}/engagements/foo", tries=20, headers={**gzip_headers, **_XHR_HEADERS})
            assert resp_api.headers.get("Content-Encoding") != "gzip", f"[{label}] API response must never be compressed"
    finally:
        _rm(backend, caddy)


# --- REQ-WEBSEC-001: browser hardening headers on every response ------------

EXPECTED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
        "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


def _assert_security_headers(url: str, label: str) -> None:
    resp = _get_raw(url, headers=_XHR_HEADERS if "/auth/" in url else _HTML_NAVIGATION_HEADERS)
    for name, value in EXPECTED_SECURITY_HEADERS.items():
        assert resp.headers.get(name) == value, f"[{label}] {name}: got {resp.headers.get(name)!r}"
    # The stub backend (python http.server) sends its own Server banner; the
    # edge must strip it, not merely add headers next to it.
    assert resp.headers.get("Server") is None, f"[{label}] Server banner leaked: {resp.headers.get('Server')!r}"


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_edge_caddyfile_sends_security_headers_on_spa_and_api(tmp_path):
    net = "asm-edge-websec-net"
    backend, caddy = "asm-edge-websec-backend", "asm-edge-websec-caddy"
    _rm(backend, caddy)
    subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)
    assert _run(["docker", "network", "create", net]).returncode == 0
    try:
        assert _run(["docker", "run", "-d", "--rm", "--name", backend, "--network", net,
                     "--network-alias", "control-plane", PYTHON_ALPINE, "python3", "-m", "http.server", "8000"]).returncode == 0
        _wait_for_stub_backend(backend, "8000")
        text = (ROOT / "edge" / "Caddyfile").read_text().replace("{$ASM_DOMAIN} {", ":18100 {", 1)
        (tmp_path / "Caddyfile").write_text(text)
        (tmp_path / "frontend").mkdir()
        (tmp_path / "frontend" / "index.html").write_text("SPA")
        assert _run(["docker", "run", "-d", "--rm", "--name", caddy, "--network", net, "-p", "18100:18100",
                     "-v", f"{tmp_path / 'Caddyfile'}:/etc/caddy/Caddyfile:ro",
                     "-v", f"{tmp_path / 'frontend'}:/srv/frontend:ro", CADDY_ALPINE]).returncode == 0
        _assert_security_headers("http://127.0.0.1:18100/engagements/some-id", "edge SPA")
        _assert_security_headers("http://127.0.0.1:18100/auth/me", "edge API (proxied)")
    finally:
        _rm(backend, caddy)
        subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_edge_shared_caddyfile_sends_security_headers_for_both_environments(tmp_path):
    backend, caddy = "asm-edge-shared-websec-backend", "asm-edge-shared-websec-caddy"
    _rm(backend, caddy)
    try:
        assert _run(["docker", "run", "-d", "--rm", "--name", backend, "--network", "host",
                     PYTHON_ALPINE, "python3", "-m", "http.server", "18103"]).returncode == 0
        _wait_for_stub_backend(backend, "18103")
        text = (ROOT / "edge-shared" / "Caddyfile").read_text()
        text = text.replace("{$ASM_DOMAIN_PROD} {", ":18101 {", 1).replace("{$ASM_DOMAIN_INT} {", ":18102 {", 1)
        (tmp_path / "Caddyfile").write_text(text)
        for env in ("prod", "int"):
            (tmp_path / f"frontend-{env}").mkdir()
            (tmp_path / f"frontend-{env}" / "index.html").write_text(f"SPA_{env}")
        assert _run(["docker", "run", "-d", "--rm", "--name", caddy, "--network", "host",
                     "-e", "PROD_API_PORT=18103", "-e", "INT_API_PORT=18103",
                     "-v", f"{tmp_path / 'Caddyfile'}:/etc/caddy/Caddyfile:ro",
                     "-v", f"{tmp_path / 'frontend-prod'}:/srv/frontend-prod:ro",
                     "-v", f"{tmp_path / 'frontend-int'}:/srv/frontend-int:ro", CADDY_ALPINE]).returncode == 0
        for port, env in ((18101, "prod"), (18102, "int")):
            _assert_security_headers(f"http://127.0.0.1:{port}/settings", f"{env} SPA")
            _assert_security_headers(f"http://127.0.0.1:{port}/auth/me", f"{env} API (proxied)")
    finally:
        _rm(backend, caddy)


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_edge_caddyfile_cache_policy_keeps_console_and_api_apart(tmp_path):
    """REQ-WEBSEC-003: /engagements/<id> is both a console route (HTML) and an
    API route (JSON); a browser must never answer one from the other's cache."""
    net = "asm-edge-cache-net"
    backend, caddy = "asm-edge-cache-backend", "asm-edge-cache-caddy"
    _rm(backend, caddy)
    subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)
    assert _run(["docker", "network", "create", net]).returncode == 0
    try:
        assert _run(["docker", "run", "-d", "--rm", "--name", backend, "--network", net,
                     "--network-alias", "control-plane", PYTHON_ALPINE, "python3", "-m", "http.server", "8000"]).returncode == 0
        _wait_for_stub_backend(backend, "8000")
        (tmp_path / "Caddyfile").write_text((ROOT / "edge" / "Caddyfile").read_text().replace("{$ASM_DOMAIN} {", ":18110 {", 1))
        (tmp_path / "frontend" / "assets").mkdir(parents=True)
        (tmp_path / "frontend" / "index.html").write_text("SPA")
        (tmp_path / "frontend" / "assets" / "index-abc123.js").write_text("console.log(1)")
        assert _run(["docker", "run", "-d", "--rm", "--name", caddy, "--network", net, "-p", "18110:18110",
                     "-v", f"{tmp_path / 'Caddyfile'}:/etc/caddy/Caddyfile:ro",
                     "-v", f"{tmp_path / 'frontend'}:/srv/frontend:ro", CADDY_ALPINE]).returncode == 0
        base = "http://127.0.0.1:18110"
        for headers, label in ((_HTML_NAVIGATION_HEADERS, "console page"), (_XHR_HEADERS, "API request")):
            resp = _get_raw(f"{base}/engagements/019fa8b1-ea8f-7308-9464-0811b85fcc47", headers=headers)
            assert resp.headers.get("Cache-Control") == "no-store", label
            assert "Accept" in [v.strip() for v in ",".join(resp.headers.get_all("Vary") or []).split(",")], label
        assert _get_raw(f"{base}/new", headers=_HTML_NAVIGATION_HEADERS).headers.get("Cache-Control") == "no-cache"
        assert _get_raw(f"{base}/assets/index-abc123.js").headers.get("Cache-Control") == \
            "public, max-age=31536000, immutable"
    finally:
        _rm(backend, caddy)
        subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=15)

