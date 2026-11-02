#!/usr/bin/env python3
"""REQ-LENS-004 (GitHub issue #82): a Lens Agent analysis stays on the All findings page and survives a reload.

Drives the real console (Vite dev server, system Chrome through Playwright) against a small stand-in API that
behaves like the control plane does for these four calls: the Lens request saves the text into the finding's
evidence, and the finding list returns it from there. What the stand-in assumes about the server is proven
against the real server by
`control-plane/tests/integration/test_lens_explanation_survives_reload.py`.

No login, no database, no LLM and no scan. It needs the console's dependencies (`npm ci` in frontend/),
Playwright for Python (`pip install playwright`) and Google Chrome:

    python frontend/browser_tests/finding_lens_stays_open.py

Exit status 0 when every check passed, 1 otherwise.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

FRONTEND = Path(__file__).resolve().parents[1]
# A name that never resolves: a request the stand-in misses fails instead of reaching a real API.
API = "http://asm-api.invalid"

ENGAGEMENT_ID = "11111111-1111-4111-8111-111111111111"
FINDING_ID = "22222222-2222-4222-8222-222222222222"
TITLE = "Missing Security Headers"
LENS_TEXT = (
    "## What it is\nA browser security header is missing.\n\n"
    "## What to do\n1. Send the header on every response.\n2. Check it with a scan afterwards."
)
LENS_MARKER = "Send the header on every response."
NO_LENS_YET = "Lens Agent has not explained this finding yet."
NOW = dt.datetime.now(dt.timezone.utc).isoformat()


class StandInApi:
    """The control plane as far as this page can tell, with the order of its calls recorded."""

    def __init__(self) -> None:
        self.lens_saved: dict | None = None
        self.fail_next_lens = False
        self.log: list[str] = []

    def count(self, entry: str) -> int:
        return self.log.count(entry)

    def finding(self) -> dict:
        evidence: dict = {"tool": "nikto", "missing_headers": ["content-security-policy"]}
        if self.lens_saved:
            evidence["lens_agent"] = self.lens_saved
        return {
            "id": FINDING_ID, "engagement_id": ENGAGEMENT_ID, "engagement_title": "Lens fixture",
            "engagement_owner": "Test Owner", "asset_id": None, "service_id": None,
            "asset_value": "app.example.test", "asset_type": "domain", "target_ip": None, "service_port": 443,
            "service_protocol": "https", "service_product": None, "service_version": None,
            "category": "misconfig", "title": TITLE, "cve_ids": [], "cvss_base": None, "epss": None,
            "confidence": "validated", "status": "open", "status_note": None, "status_changed_at": None,
            "status_changed_by": None, "severity": "low", "risk_score": 37.5, "evidence": evidence,
            "raw_ref": None, "first_seen": NOW, "last_seen": NOW,
        }

    def engagement(self) -> dict:
        return {
            "id": ENGAGEMENT_ID, "title": "Lens fixture", "source": "own_domain", "status": "active",
            "operating_mode": "assessment", "authorized_from": NOW, "authorized_until": NOW, "created_at": NOW,
            "owner_user_id": "u1", "owner_name": "Test Owner", "owner_email": "owner@example.test", "can_manage": True,
        }

    def answer(self, method: str, path: str) -> tuple[int, object]:
        route = path.split("?", 1)[0]
        if method == "GET" and route == "/auth/me":
            return 200, {"id": "u1", "email": "owner@example.test", "display_name": "Test Owner",
                         "role": "operator", "status": "active"}
        if method == "GET" and route == "/engagements":
            return 200, [self.engagement()]
        if method == "GET" and route == "/findings":
            self.log.append("list")
            return 200, {"items": [self.finding()], "total": 1, "limit": 50, "offset": 0,
                         "counts_by_status": {"open": 1, "resolved": 0, "accepted_risk": 0, "false_positive": 0},
                         "counts_by_severity": {"low": 1}}
        if method == "POST" and route == f"/engagements/{ENGAGEMENT_ID}/findings/{FINDING_ID}/lens-explanation":
            self.log.append("lens")
            if self.fail_next_lens:
                self.fail_next_lens = False
                return 503, {"detail": "no LLM provider configured"}
            if self.lens_saved:
                source = "cached"
            else:
                source = "llm"
                self.lens_saved = {"explanation": LENS_TEXT, "generated_at": NOW, "model": "test-model", "truncated": False}
            return 200, {"finding_id": FINDING_ID, "explanation": self.lens_saved["explanation"], "source": source,
                         "generated_at": NOW, "model": "test-model", "truncated": False}
        if method == "GET" and route == "/inbox/count":
            return 200, {"count": 0}
        if method == "GET" and route == "/approvals":
            return 200, []
        self.log.append(f"unmocked {method} {route}")
        return 404, {"detail": "not part of this check"}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_console(port: int, cache_dir: str) -> subprocess.Popen:
    vite = FRONTEND / "node_modules" / ".bin" / "vite"
    if not vite.exists():
        sys.exit(f"{vite} is missing - run `npm ci` in frontend/ first")
    # The console's own config with a private dependency cache: another dev server on the same checkout
    # (or an earlier run of this check) must not trigger a re-optimise-and-reload in the middle of the check.
    config = Path(cache_dir) / "vite.config.mjs"
    config.write_text(
        f'import {{ mergeConfig }} from {json.dumps(str(FRONTEND / "node_modules" / "vite" / "dist" / "node" / "index.js"))};\n'
        f'import base from {json.dumps(str(FRONTEND / "vite.config.ts"))};\n'
        f'export default mergeConfig(base, {{ root: {json.dumps(str(FRONTEND))}, cacheDir: {json.dumps(str(Path(cache_dir) / "cache"))} }});\n'
    )
    process = subprocess.Popen(
        [str(vite), "--config", str(config), "--port", str(port), "--strictPort", "--host", "127.0.0.1"], cwd=FRONTEND,
        env={**os.environ, "VITE_API_BASE_URL": API}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        if process.poll() is not None:
            sys.exit("the console's dev server exited before it was ready")
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1).read()
            return process
        except OSError:
            time.sleep(0.3)
    process.kill()
    sys.exit("the console's dev server did not come up within 60 seconds")


def main() -> int:
    api = StandInApi()
    port = free_port()
    scratch = tempfile.TemporaryDirectory(prefix="asm-lens-check-")
    console = start_console(port, scratch.name)
    base = f"http://127.0.0.1:{port}"
    results: list[tuple[bool, str]] = []

    def check(ok: bool, name: str) -> None:
        results.append((ok, name))
        print(f"{'ok' if ok else 'not ok'} - {name}")

    def cors(origin: str) -> dict:
        return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Headers": "content-type, x-requested-with", "Access-Control-Allow-Methods": "GET, POST, OPTIONS"}

    def handle(route, request) -> None:
        headers = cors(base)
        if request.method == "OPTIONS":
            route.fulfill(status=204, headers=headers)
            return
        if request.method == "POST" and request.url.endswith("/lens-explanation"):
            page.wait_for_timeout(300)  # a provider call takes a moment; the button shows "Asking Lens..." meanwhile
        status, body = api.answer(request.method, request.url[len(API):])
        route.fulfill(status=status, headers=headers, content_type="application/json", body=json.dumps(body))

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="chrome", headless=True)
            page = browser.new_context(viewport={"width": 1440, "height": 900}).new_page()
            page.route(f"{API}/**", handle)
            # The console reloads the list on a 15 s timer; a fake clock lets the check cross it without waiting.
            page.clock.install()

            def wait_for(condition, what: str, seconds: float = 10) -> bool:
                deadline = time.time() + seconds
                while time.time() < deadline:
                    if condition():
                        return True
                    page.wait_for_timeout(50)
                print(f"  (timed out waiting for {what})")
                return False

            def detail_open() -> bool:
                return page.locator(".finding-detail-row").count() == 1

            def lens_shown() -> bool:
                return page.locator(".lens-output").get_by_text(LENS_MARKER).count() == 1

            def toggle_row() -> None:
                # The title cell: the middle of the row is the engagement column, whose link leaves the page.
                page.locator(".finding-row strong", has_text=TITLE).click()

            def lens_state(label: str) -> str:
                return f"{label}: detail open={detail_open()}, Lens text shown={lens_shown()}"

            page.goto(f"{base}/findings", wait_until="domcontentloaded")
            page.get_by_text(TITLE).first.wait_for(timeout=20000)

            # --- open the finding; nothing explained yet --------------------------------------------------
            toggle_row()
            wait_for(detail_open, "the finding to open")
            check(page.get_by_text(NO_LENS_YET).count() == 1, "a finding without a saved analysis says so")

            # --- a failed request: an error, the finding stays open, nothing is saved ----------------------
            api.fail_next_lens = True
            page.get_by_role("button", name="Explain with Lens Agent").click()
            wait_for(lambda: page.locator(".lens-output .error-block").count() == 1, "the Lens error to show")
            check(detail_open() and not lens_shown() and api.lens_saved is None,
                  "a failed Lens request shows its error, keeps the finding open and saves nothing")

            # --- the request that works: text appears, the list reloads, the finding stays open ------------
            lists_before = api.count("list")
            page.get_by_role("button", name="Explain with Lens Agent").click()
            # Not waiting for the text itself: the reported bug shows it for a moment and then closes the finding,
            # so the state to judge is the one after the reload and a settling second.
            reloaded = wait_for(lambda: api.count("list") > lists_before, "the list to reload after the Lens request")
            page.wait_for_timeout(1000)  # a close that follows the reload would land within this second
            check(reloaded, "the console reloads the finding list right after the Lens request")
            check(detail_open() and lens_shown(), lens_state("after the reload"))
            check(page.get_by_role("button", name="Show Lens analysis").count() == 1,
                  "the button now reads 'Show Lens analysis'")
            check(page.locator(".lens-output h4", has_text="What to do").count() == 1,
                  "the standard Lens sections render as headings")

            # --- the timed reload does not close it either --------------------------------------------------
            lists_before = api.count("list")
            page.clock.run_for(16000)
            timed = wait_for(lambda: api.count("list") > lists_before, "the 15 s reload")
            page.wait_for_timeout(1000)
            check(timed, "the console reloads the finding list again on its timer")
            check(detail_open() and lens_shown(), lens_state("after the timed reload"))

            # --- close and open again: same text, no second request -----------------------------------------
            toggle_row()
            check(not detail_open(), "clicking the row closes the finding")
            toggle_row()
            wait_for(detail_open, "the finding to open")
            check(lens_shown() and api.count("lens") == 2,
                  "reopening shows the same text and sends no further Lens request (2 requests so far: the failed and the successful one)")

            # --- reload the page: the saved text comes back from the server --------------------------------
            page.reload(wait_until="domcontentloaded")
            page.get_by_text(TITLE).first.wait_for(timeout=20000)
            toggle_row()
            wait_for(detail_open, "the finding to open")
            check(lens_shown(), "after a page reload the finding shows the analysis the server saved")
            check(page.get_by_role("button", name="Show Lens analysis").count() == 1,
                  "after a page reload the button reads 'Show Lens analysis'")
            check(api.count("lens") == 2, "the page reload sent no Lens request")

            unmocked = [entry for entry in api.log if entry.startswith("unmocked")]
            if unmocked:
                print(f"  (requests the stand-in did not know, answered 404: {sorted(set(unmocked))})")
            browser.close()
    finally:
        console.terminate()
        try:
            console.wait(timeout=10)
        except subprocess.TimeoutExpired:
            console.kill()
        scratch.cleanup()

    failed = [name for ok, name in results if not ok]
    print(f"{len(results) - len(failed)} of {len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
