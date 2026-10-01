#!/usr/bin/env python3
"""Generate the manual's screenshots (REQ-MANUAL-004).

    make manual-screenshots          # needs docker, node_modules in frontend/, and `make uat-venv`

One command builds its own throwaway stack (a database, a control plane built from the
working tree, a console built from the working tree), fills it with the demo data of
control-plane/scripts/manual_demo_seed.py, signs in as the demo accounts in a real
browser, writes docs/manual/img/*.png and removes everything again. It never reads,
writes or stops the developer's own stack: every container, network and port is new,
named `asm-manual-<id>`, bound to 127.0.0.1, with secrets generated for this run only.

Before every screenshot the text of the page is checked with the rule set the manual
itself is checked with (scripts/check_manual.py: private markers, addresses outside the
documentation ranges, email addresses outside the reserved example domains). A hit
aborts the run before the image is written.
"""

from __future__ import annotations

import argparse
import base64
import http.server
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_manual  # noqa: E402  (the same rule set as the manual check)

IMG = ROOT / "docs" / "manual" / "img"
MAX_BYTES = check_manual.MAX_IMAGE_BYTES
DESKTOP = {"width": 1280, "height": 800}
PHONE = {"width": 390, "height": 844}
TALL = {"width": 1280, "height": 1180}
# The Account page lists each session's address and browser. A real proxy tells the control plane the
# client's address in X-Forwarded-For (it trusts that from private peers), so the demo browser says it
# is a documentation address, with a browser name that carries no four-part version number.
BROWSER = {
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130 Safari/537.36",
    "extra_http_headers": {"X-Forwarded-For": "203.0.113.7"},
}


class LeakError(RuntimeError):
    """A page showed something that must not be in a public manual."""


# --------------------------------------------------------------------------------------------- the stack


def _run(*args: str, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, text=True, capture_output=True, **kwargs)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _fernet_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


class _SpaHandler(http.server.SimpleHTTPRequestHandler):
    """Serves the built console; unknown paths fall back to index.html like the real edge."""

    def __init__(self, *args, directory: str, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)

    def do_GET(self):  # noqa: N802
        path = self.translate_path(self.path.split("?", 1)[0])
        if not os.path.isfile(path):
            self.path = "/index.html"
        super().do_GET()

    def log_message(self, *args):  # quiet
        pass


@dataclass
class Stack:
    """Everything the screenshots need, and the means to remove all of it."""

    run_id: str = field(default_factory=lambda: secrets.token_hex(4))
    keep: bool = False
    api_port: int = 0
    web_port: int = 0
    password: str = field(default_factory=lambda: "Demo-" + secrets.token_urlsafe(18))
    seeded: dict = field(default_factory=dict)
    _tmp: Path | None = None
    _server: http.server.ThreadingHTTPServer | None = None

    @property
    def prefix(self) -> str:
        return f"asm-manual-{self.run_id}"

    @property
    def api_url(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    @property
    def web_url(self) -> str:
        return f"http://127.0.0.1:{self.web_port}"

    def log(self, message: str) -> None:
        print(f"[manual-screenshots] {message}", flush=True)

    # -- lifecycle ------------------------------------------------------------------------------
    def __enter__(self) -> "Stack":
        self._tmp = Path(tempfile.mkdtemp(prefix=f"{self.prefix}-"))
        self.api_port, self.web_port = _free_port(), _free_port()
        try:
            self._start()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *exc) -> None:
        if self.keep:
            self.log(f"--keep: leaving {self.prefix}-* and {self._tmp} in place; remove them by hand")
            return
        if self._server:
            self._server.shutdown()
        for name in ("cp", "redis", "db"):
            _run("docker", "rm", "-f", f"{self.prefix}-{name}", check=False)
        _run("docker", "network", "rm", self.prefix, check=False)
        _run("docker", "image", "rm", self.prefix, check=False)
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
        self.log("stack removed")

    # -- steps ----------------------------------------------------------------------------------
    def _start(self) -> None:
        env_db = {"user": "asm", "password": secrets.token_urlsafe(18), "name": "asm"}
        self.log(f"building the control plane image from the working tree ({self.prefix})")
        _run("docker", "build", "-q", "-t", self.prefix, str(ROOT / "control-plane"))
        _run("docker", "network", "create", self.prefix)
        _run("docker", "run", "-d", "--name", f"{self.prefix}-db", "--network", self.prefix, "-e", f"POSTGRES_USER={env_db['user']}",
             "-e", f"POSTGRES_PASSWORD={env_db['password']}", "-e", f"POSTGRES_DB={env_db['name']}", "postgres:16")
        _run("docker", "run", "-d", "--name", f"{self.prefix}-redis", "--network", self.prefix, "redis:7-alpine")
        self._wait_for_database(env_db)
        self._migrate(env_db)

        dsn = f"postgresql+psycopg://{env_db['user']}:{env_db['password']}@{self.prefix}-db:5432/{env_db['name']}"
        env = {
            "DATABASE_URL": dsn, "REDIS_URL": f"redis://{self.prefix}-redis:6379/0", "ENVIRONMENT": "development",
            "INTERNAL_API_TOKEN": secrets.token_urlsafe(24), "OPERATOR_API_TOKEN": secrets.token_urlsafe(24),
            "SCOPE_SIGNING_SECRET": secrets.token_urlsafe(24), "MFA_ENCRYPTION_KEY": _fernet_key(),
            "SETTINGS_ENCRYPTION_KEY": _fernet_key(), "CORS_ALLOWED_ORIGINS": self.web_url,
            "PUBLIC_BASE_URL": self.api_url,
        }
        flags = [x for key, value in env.items() for x in ("-e", f"{key}={value}")]
        self.log("seeding the demo data")
        seeded = _run("docker", "run", "--rm", "--network", self.prefix, *flags, "-e", f"MANUAL_DEMO_PASSWORD={self.password}",
                      self.prefix, "python", "scripts/manual_demo_seed.py")
        self.seeded = json.loads(seeded.stdout.strip().splitlines()[-1])
        _run("docker", "run", "-d", "--name", f"{self.prefix}-cp", "--network", self.prefix, "-p", f"127.0.0.1:{self.api_port}:8000",
             *flags, self.prefix)
        self._wait_for_api()
        self._build_console()
        self._serve_console()

    def _wait_for_database(self, db: dict) -> None:
        # A fresh data directory restarts once after initdb; one answer is not enough.
        answers = 0
        for _ in range(90):
            probe = _run("docker", "exec", f"{self.prefix}-db", "psql", "-U", db["user"], "-d", db["name"], "-tAc", "SELECT 1", check=False)
            answers = answers + 1 if probe.returncode == 0 and probe.stdout.strip() == "1" else 0
            if answers >= 3:
                return
            time.sleep(1)
        raise RuntimeError("the throwaway database did not become ready")

    def _migrate(self, db: dict) -> None:
        migrations = sorted((ROOT / "control-plane" / "migrations").glob("*.sql"))
        self.log(f"applying {len(migrations)} migrations")
        for path in migrations:
            with path.open("rb") as handle:
                done = subprocess.run(["docker", "exec", "-i", f"{self.prefix}-db", "psql", "-U", db["user"], "-d", db["name"],
                                       "-q", "-v", "ON_ERROR_STOP=1"], stdin=handle, capture_output=True)
            if done.returncode != 0:
                raise RuntimeError(f"migration {path.name} failed: {done.stderr.decode()[-400:]}")

    def _wait_for_api(self) -> None:
        import urllib.request

        for _ in range(60):
            try:
                with urllib.request.urlopen(f"{self.api_url}/health", timeout=2) as reply:
                    if reply.status == 200:
                        return
            except OSError:
                time.sleep(1)
        logs = _run("docker", "logs", "--tail", "30", f"{self.prefix}-cp", check=False)
        raise RuntimeError(f"the throwaway control plane did not become ready:\n{logs.stdout}{logs.stderr}")

    def _build_console(self) -> None:
        self.log("building the console from the working tree")
        vite = ROOT / "frontend" / "node_modules" / ".bin" / "vite"
        if not vite.exists():
            raise RuntimeError("frontend/node_modules is missing; run `npm ci` in frontend/ first")
        # A console built for the manual carries no optional manual link, whatever the shell exports.
        env = {k: v for k, v in os.environ.items() if not k.startswith("VITE_")} | {"VITE_API_BASE_URL": self.api_url}
        built = subprocess.run([str(vite), "build", "--outDir", str(self._tmp / "console"), "--emptyOutDir"],
                               cwd=ROOT / "frontend", env=env, capture_output=True, text=True)
        if built.returncode != 0:
            raise RuntimeError(f"console build failed:\n{built.stdout[-800:]}{built.stderr[-800:]}")

    def _serve_console(self) -> None:
        directory = str(self._tmp / "console")
        handler = lambda *a, **k: _SpaHandler(*a, directory=directory, **k)  # noqa: E731
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", self.web_port), handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def add_pending_approval(self) -> None:
        _run("docker", "exec", f"{self.prefix}-cp", "python", "scripts/manual_demo_seed.py", "--pending-approval",
             self.seeded["engagements"]["retail"], self.seeded["runs"]["retail_running"])


# --------------------------------------------------------------------------------------------- the shots


@dataclass
class Shot:
    name: str                              # file stem in docs/manual/img/
    who: str | None                        # "admin", "operator" or None (signed out)
    path: str                              # {main} {draft} {retail} {latest} {running} come from the seed
    ready: str                             # selector that proves the screen has loaded
    act: Callable | None = None            # click, expand, scroll to the part the page is about
    viewport: dict = field(default_factory=lambda: DESKTOP)
    element: str | None = None             # photograph only this part (a tall page without the sidebar)
    pending_approval: bool = False


def _click_tab(label: str) -> Callable:
    return lambda page: page.get_by_role("button", name=label, exact=True).click()


def _open_finding(title: str) -> Callable:
    def act(page) -> None:
        row = page.locator("tr.finding-row", has_text=title).first
        row.click()
        page.locator("tr.finding-detail-row").first.wait_for()
        page.evaluate("(el) => window.scrollTo(0, el.getBoundingClientRect().top + window.scrollY)", row.element_handle())
    return act


def _scroll_to_top(selector: str) -> Callable:
    """Put the top of the first match at the top of the window, so the shot starts at that part."""
    return lambda page: page.evaluate(
        "(el) => window.scrollTo(0, el.getBoundingClientRect().top + window.scrollY)", page.locator(selector).first.element_handle())


def _open_menu(page) -> None:
    page.locator("button.menu-button").click()
    page.locator("#primary-navigation").wait_for(state="visible")


def _open_agent_step(page) -> None:
    page.get_by_role("button", name="Vector Agent", exact=True).click()
    page.locator(".agent-step-head").first.wait_for()
    page.locator(".agent-step-head").nth(1).click()


SHOTS: list[Shot] = [
    Shot("sign-in", None, "/login", "#email"),
    Shot("overview", "operator", "/", "h1:has-text('Operator overview')"),
    Shot("all-findings", "operator", "/findings", "h1:has-text('All findings')"),
    Shot("wizard-step-1", "operator", "/new", "h1:has-text('New engagement')"),
    Shot("engagement-findings", "operator", "/engagements/{main}", "tr.finding-row"),
    Shot("engagement-read-only", "analyst", "/engagements/{main}", ".read-only-notice"),
    Shot("finding-detail", "operator", "/engagements/{main}", "tr.finding-row",
         act=_open_finding("Exposed .git directory"), viewport=TALL),
    Shot("engagement-assets", "operator", "/engagements/{main}?tab=assets", "h1", viewport=TALL),
    Shot("engagement-runs", "operator", "/engagements/{main}?tab=runs", "h2:has-text('Runs')"),
    Shot("edit-tool-grants", "operator", "/engagements/{main}/edit#tool-grants", "h2:has-text('Campaign tool overrides')",
         act=_scroll_to_top("#tool-grants"), viewport=TALL),
    Shot("run-progress", "operator", "/engagements/{main}/runs/{latest}", "h2:has-text('Scan progress')"),
    Shot("run-plan", "operator", "/engagements/{main}/runs/{latest}", "button.tab:has-text('Plan')",
         act=_click_tab("Plan"), element="main.workspace"),
    Shot("run-diff", "operator", "/engagements/{main}/runs/{latest}", "button.tab:has-text('Diff')", act=_click_tab("Diff")),
    Shot("run-agent", "operator", "/engagements/{main}/runs/{latest}", "button.tab:has-text('Vector Agent')",
         act=_open_agent_step),
    Shot("run-activity", "operator", "/engagements/{main}/runs/{latest}", "button.tab:has-text('Activity')",
         act=_click_tab("Activity")),
    Shot("run-live", "operator", "/engagements/{retail}/runs/{running}", ".current-activity-banner"),
    Shot("audit", "operator", "/engagements/{main}/audit", "h1"),
    Shot("account", "operator", "/account", "h2:has-text('Two-factor authentication')", viewport=TALL),
    Shot("admin-settings", "admin", "/admin", "h1:has-text('Settings')"),
    Shot("admin-users", "admin", "/admin", "button.tab:has-text('Users')", act=_click_tab("Users")),
    Shot("admin-account-audit", "admin", "/admin", "button.tab:has-text('Account audit')", act=_click_tab("Account audit")),
    Shot("phone-navigation", "operator", "/", "button.menu-button", act=_open_menu, viewport=PHONE),
    # Last: the popup it shows stays on every page until it is decided.
    Shot("approval-popup", "operator", "/engagements/{main}", "h2:has-text('Approval required')", pending_approval=True),
]


def _fill(path: str, seeded: dict) -> str:
    ids = {**seeded["engagements"], "latest": seeded["runs"]["main_latest"], "running": seeded["runs"]["retail_running"]}
    return path.format(**ids)


def _guard(page, name: str) -> None:
    """Abort before anything is written if the page shows what a public manual must not."""
    text = page.evaluate("document.body.innerText") + "\n" + page.evaluate(
        "Array.from(document.querySelectorAll('[title],[aria-label],input,textarea')).map(e => "
        "[e.title, e.getAttribute('aria-label'), e.value, e.placeholder].filter(Boolean).join(' ')).join('\\n')")
    found = check_manual.private_content(text)
    if found:
        raise LeakError(f"{name}: " + "; ".join(found))


def _login(browser, stack: Stack, email: str, secret: str):
    import pyotp

    context = browser.new_context(viewport=DESKTOP, **BROWSER)
    page = context.new_page()
    page.goto(f"{stack.web_url}/login", wait_until="domcontentloaded")
    page.fill("#email", email)
    page.fill("#password", stack.password)
    page.click("button[type=submit]")
    page.wait_for_selector("#code", timeout=20000)
    for attempt in range(3):
        page.fill("#code", pyotp.TOTP(secret).now())
        page.click("button[type=submit]")
        page.locator(".error-block").or_(page.get_by_text("New engagement")).first.wait_for(timeout=15000)
        if page.get_by_text("New engagement").count():
            break
        if attempt == 2:
            raise RuntimeError(f"sign-in as {email} failed: {page.locator('.error-block').inner_text()}")
        time.sleep(31 - time.time() % 30)  # the server accepts a code once per 30 s step
    return context, context.storage_state()


def run(stack: Stack, only: set[str] | None) -> list[Path]:
    from playwright.sync_api import sync_playwright

    accounts = {a["email"]: a for a in stack.seeded["accounts"]}
    roles = {"admin": accounts["demo.admin@example.com"], "operator": accounts["demo.operator@example.com"],
             "analyst": accounts["sam.analyst@example.com"]}
    IMG.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome")
        sessions = {}
        try:
            for who in sorted({s.who for s in SHOTS if s.who and (not only or s.name in only)}):
                context, state = _login(browser, stack, roles[who]["email"], roles[who]["totp_secret"])
                context.close()
                sessions[who] = state
            approval_added = False
            for shot in SHOTS:
                if only and shot.name not in only:
                    continue
                if shot.pending_approval and not approval_added:
                    stack.add_pending_approval()
                    approval_added = True
                context = browser.new_context(viewport=shot.viewport, storage_state=sessions.get(shot.who), **BROWSER)
                page = context.new_page()
                try:
                    page.goto(stack.web_url + _fill(shot.path, stack.seeded), wait_until="domcontentloaded")
                    page.locator(shot.ready).first.wait_for(timeout=20000)
                    if shot.act:
                        shot.act(page)
                    page.wait_for_timeout(700)  # let the queries behind the screen settle
                    _guard(page, shot.name)
                    target = IMG / f"{shot.name}.png"
                    if shot.element:
                        page.locator(shot.element).first.screenshot(path=str(target))
                    else:
                        page.screenshot(path=str(target))
                finally:
                    context.close()
                size = target.stat().st_size
                if size > MAX_BYTES:
                    target.unlink()
                    raise RuntimeError(f"{shot.name}.png is {size} bytes; the limit is {MAX_BYTES}")
                written.append(target)
                print(f"  {target.relative_to(ROOT)} ({size // 1024} KB)")
        finally:
            browser.close()
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", nargs="+", metavar="NAME", help="regenerate only these screenshots")
    parser.add_argument("--keep", action="store_true", help="leave the throwaway stack running for inspection")
    args = parser.parse_args()
    only = set(args.only) if args.only else None
    unknown = (only or set()) - {s.name for s in SHOTS}
    if unknown:
        print(f"unknown screenshot(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    try:
        with Stack(keep=args.keep) as stack:
            written = run(stack, only)
    except LeakError as exc:
        print(f"ABORTED, nothing more was written: {exc}", file=sys.stderr)
        return 3
    print(f"{len(written)} screenshot(s) written to {IMG.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
