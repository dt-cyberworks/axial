"""TC-IAM-027: the deploy check fails on a console that would be refused (no header) or kept
stale (app shell cached without revalidation), and passes on a good one - also against the
header the real client source defines."""

from __future__ import annotations

import functools
import http.server
import importlib.util
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("check_deployed_console", ROOT / "scripts" / "check_deployed_console.py")
cdc = importlib.util.module_from_spec(_spec)
sys.modules["check_deployed_console"] = cdc
_spec.loader.exec_module(cdc)

INDEX = '<!doctype html><html><head><script type="module" crossorigin src="/assets/index-AbC123.js"></script></head></html>'
GOOD_BUNDLE = 'const fp={"X-Requested-With":"asm-console"};async function ne(){}'
OLD_BUNDLE = "async function ne(s){return fetch(s,{credentials:'include'})}"


def build(root: Path, bundle: str, index: str = INDEX) -> Path:
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(index)
    (root / "assets" / "index-AbC123.js").write_text(bundle)
    return root


def serve(root: Path, shell_cache_control: str | None):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def end_headers(self):
            if self.path == "/" and shell_cache_control is not None:
                self.send_header("Cache-Control", shell_cache_control)
            super().end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(root)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture()
def served(tmp_path):
    servers = []

    def start(bundle, cache_control="no-cache"):
        server, url = serve(build(tmp_path / f"dist{len(servers)}", bundle), cache_control)
        servers.append(server)
        return url

    yield start
    for server in servers:
        server.shutdown()


NAME, VALUE = "X-Requested-With", "asm-console"


def test_the_expected_header_is_read_from_the_real_client_source():
    assert cdc.expected_header() == (NAME, VALUE)


def test_a_good_console_passes_by_url_and_by_directory(served, tmp_path):
    assert cdc.main([served(GOOD_BUNDLE)]) == 0
    assert cdc.main(["--dir", str(build(tmp_path / "plain", GOOD_BUNDLE))]) == 0


def test_negative_a_console_without_the_header_fails(served, tmp_path, capsys):
    assert cdc.main([served(OLD_BUNDLE)]) == 1
    assert "403" in capsys.readouterr().err
    assert cdc.main(["--dir", str(build(tmp_path / "old", OLD_BUNDLE))]) == 1


def test_negative_a_header_name_without_the_value_fails():
    with pytest.raises(cdc.CheckFailed):
        cdc.check_bundle('x={"X-Requested-With":"something-else"}', NAME, VALUE)


@pytest.mark.parametrize("cache_control", [None, "public, max-age=31536000, immutable", "max-age=3600"])
def test_negative_an_app_shell_that_can_be_kept_without_asking_fails(served, cache_control):
    assert cdc.main([served(GOOD_BUNDLE, cache_control)]) == 1


@pytest.mark.parametrize("cache_control", ["no-cache", "no-store", "max-age=0, must-revalidate"])
def test_an_app_shell_that_revalidates_passes(served, cache_control):
    assert cdc.main([served(GOOD_BUNDLE, cache_control)]) == 0


def test_negative_a_page_that_is_not_a_built_console_fails(tmp_path):
    (tmp_path / "index.html").write_text("<html>hello</html>")
    assert cdc.main(["--dir", str(tmp_path)]) == 1


def test_negative_an_entry_script_missing_from_the_directory_fails(tmp_path):
    (tmp_path / "index.html").write_text(INDEX)
    assert cdc.main(["--dir", str(tmp_path)]) == 1


def test_negative_an_unreachable_server_fails_instead_of_passing():
    assert cdc.main(["http://127.0.0.1:9"]) == 1
