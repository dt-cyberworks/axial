#!/usr/bin/env python3
"""REQ-IAM-027: prove the console an environment serves sends the anti-CSRF header.

The API refuses every cookie-authenticated change that arrives without
`X-Requested-With: asm-console` (REQ-IAM-019). The console is deployed apart from the API, so
an old bundle can end up next to a new API, and nothing noticed: API-level checks use a Bearer
credential, which needs no header. This reads what a browser would be served and fails when

* the page's entry script does not contain the header the source defines, or
* the app shell (`/`) can be cached without revalidation, so a browser keeps an old page.

Standard library only. Either a URL (what the edge serves) or a directory (a build output, or
the directory the edge serves from) can be checked:

    python3 scripts/check_deployed_console.py https://console.example.org
    python3 scripts/check_deployed_console.py --dir frontend/dist
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT_SOURCE = ROOT / "frontend" / "src" / "api" / "client.ts"
HEADER_PATTERN = re.compile(r'const CONSOLE_HEADERS = \{ "([^"]+)": "([^"]+)" \}')
ENTRY_PATTERN = re.compile(r'<script[^>]*type="module"[^>]*\ssrc="([^"]+)"')
# A browser may reuse a cached app shell without asking the server only when it has a
# freshness lifetime. `no-cache` / `no-store` / `max-age=0` all force a revalidation.
REVALIDATING = re.compile(r"no-cache|no-store|max-age=0\b")


class CheckFailed(Exception):
    pass


def expected_header(source: Path = CLIENT_SOURCE) -> tuple[str, str]:
    """The header name and value the console source sends, so the check cannot drift from it."""
    match = HEADER_PATTERN.search(source.read_text(encoding="utf-8"))
    if match is None:
        raise CheckFailed(f"{source}: CONSOLE_HEADERS not found; update this check with the client")
    return match.group(1), match.group(2)


def entry_path(index_html: str) -> str:
    match = ENTRY_PATTERN.search(index_html)
    if match is None:
        raise CheckFailed("the app shell has no module script, so it is not a built console")
    return match.group(1)


def check_bundle(bundle: str, name: str, value: str) -> None:
    # A minifier may rename the constant but never the string literals.
    for literal in (name, value):
        if literal not in bundle:
            raise CheckFailed(
                f"the served entry script does not contain {literal!r}: this console does not send "
                f"'{name}: {value}', so every change from it will be refused with 403")


def check_cache_control(cache_control: str | None) -> None:
    if cache_control is None or not REVALIDATING.search(cache_control.lower()):
        raise CheckFailed(
            f"the app shell is served with Cache-Control {cache_control!r}; it must revalidate "
            "(no-cache) or a browser keeps showing an old console after a deploy")


def check_url(base_url: str, name: str, value: str, timeout: float = 20.0) -> list[str]:
    base = base_url.rstrip("/")

    def get(path: str):
        try:
            with urllib.request.urlopen(base + path, timeout=timeout) as response:  # noqa: S310
                return response.read().decode("utf-8", "replace"), response.headers
        except urllib.error.URLError as exc:
            raise CheckFailed(f"GET {base + path} failed: {exc}") from exc

    index, headers = get("/")
    entry = entry_path(index)
    check_cache_control(headers.get("Cache-Control"))
    bundle, _ = get(entry if entry.startswith("/") else "/" + entry)
    check_bundle(bundle, name, value)
    return [f"{base}/ serves {entry}", f"{entry} sends '{name}: {value}'", "app shell revalidates"]


def check_dir(directory: Path, name: str, value: str) -> list[str]:
    index = directory / "index.html"
    if not index.is_file():
        raise CheckFailed(f"{index} does not exist")
    entry = entry_path(index.read_text(encoding="utf-8")).lstrip("/")
    bundle = directory / entry
    if not bundle.is_file():
        raise CheckFailed(f"index.html names {entry}, which is not in {directory}")
    check_bundle(bundle.read_text(encoding="utf-8", errors="replace"), name, value)
    return [f"{directory}/index.html uses {entry}", f"{entry} sends '{name}: {value}'"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", nargs="?", help="base URL the console is served from")
    parser.add_argument("--dir", type=Path, help="a built console directory instead of a URL")
    args = parser.parse_args(argv)
    if bool(args.url) == bool(args.dir):
        parser.error("give either a URL or --dir")
    try:
        name, value = expected_header()
        notes = check_url(args.url, name, value) if args.url else check_dir(args.dir, name, value)
    except CheckFailed as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    for note in notes:
        print(f"ok: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
