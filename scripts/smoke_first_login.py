#!/usr/bin/env python3
"""Drive a fresh install's first login end to end (REQ-INSTALL-001). Standard library only.

What an installer does after `make bootstrap-admin`: sign in with the temporary
password, choose a real password, enroll a TOTP authenticator, land in a session,
then sign out and sign in again with password + TOTP. If any step cannot complete -
for example the 2026-10-01 defect where an empty MFA key made enrollment answer
500 while /health was green - this exits 1 at that step.

    smoke_first_login.py BASE_URL EMAIL TEMP_PASSWORD_FILE [--connect IP] [--insecure]

TEMP_PASSWORD_FILE holds the output of bootstrap_admin ("temporary password: ...").
It is read, never printed. --connect IP opens the TCP connection to IP while still
presenting BASE_URL's host name (SNI and Host header): the production proxy only
answers to its configured name, and CI has no DNS for it. --insecure skips
certificate verification (the proxy's internal CA on a CI runner).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import http.cookiejar
import json
import re
import secrets
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def totp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


class Client:
    def __init__(self, base_url: str, connect: str | None, insecure: bool):
        self.base = base_url.rstrip("/")
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        pinned = connect

        class _Connection(http.client.HTTPSConnection):
            def connect(self):  # noqa: D102 - open the socket to the pinned IP, keep the name for SNI
                sock = socket.create_connection((pinned or self.host, self.port), self.timeout)
                self.sock = context.wrap_socket(sock, server_hostname=self.host)

        class _Handler(urllib.request.HTTPSHandler):
            def https_open(self, req):  # noqa: D102
                return self.do_open(_Connection, req, context=context)

        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), _Handler(context=context))

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, object]:
        request = urllib.request.Request(
            self.base + path, method=method, headers={"content-type": "application/json"},
            data=json.dumps(body).encode() if body is not None else None,
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode(errors="replace")[:300]


def step(label: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {label} {detail}".rstrip(), flush=True)
    if not ok:
        sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("base_url")
    parser.add_argument("email")
    parser.add_argument("temp_password_file")
    parser.add_argument("--connect", default=None)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    found = re.search(r"temporary password:\s*(\S+)", open(args.temp_password_file, encoding="utf-8").read())
    if not found:
        step("read the temporary password from the bootstrap output", False, "(no 'temporary password:' line)")
    new_password = secrets.token_urlsafe(18)
    client = Client(args.base_url, args.connect, args.insecure)

    status, data = client.call("POST", "/auth/login", {"email": args.email, "password": found.group(1)})
    step("sign in with the temporary password", status == 200 and data["status"] == "set_password",
         f"-> {status} {data['status'] if status == 200 else data}")
    status, data = client.call("POST", "/auth/password/set-first", {"challenge_id": data["challenge_id"], "new_password": new_password})
    step("choose the first real password", status == 200 and data["status"] == "mfa_enroll",
         f"-> {status} {data['status'] if status == 200 else data}")
    challenge = data["challenge_id"]
    status, data = client.call("POST", "/auth/mfa/enroll", {"challenge_id": challenge})
    step("start TOTP enrollment", status == 200 and bool(data.get("secret")),
         f"-> {status}" + ("" if status == 200 else f" {data}"))
    secret = data["secret"]
    status, data = client.call("POST", "/auth/mfa/enroll/confirm", {"challenge_id": challenge, "code": totp(secret, int(time.time() // 30))})
    step("confirm TOTP and receive a session with backup codes", status == 200 and bool(data.get("backup_codes")),
         f"-> {status}" + (f", {len(data['backup_codes'])} backup codes" if status == 200 else f" {data}"))
    status, data = client.call("GET", "/auth/me")
    step("the session authenticates /auth/me", status == 200 and data["email"] == args.email, f"-> {status}")
    status, _ = client.call("GET", "/engagements")
    step("an authenticated API call works (GET /engagements)", status == 200, f"-> {status}")

    # A TOTP code is single-use: wait for the next 30-second window before signing in again.
    used = int(time.time() // 30)
    while int(time.time() // 30) == used:
        time.sleep(1)
    client.jar.clear()
    status, data = client.call("POST", "/auth/login", {"email": args.email, "password": new_password})
    step("sign in again with the new password", status == 200 and data["status"] == "mfa_verify", f"-> {status}")
    status, _ = client.call("POST", "/auth/login/mfa", {"challenge_id": data["challenge_id"], "code": totp(secret, int(time.time() // 30))})
    step("the second sign-in completes with TOTP", status == 200, f"-> {status}")
    status, _ = client.call("GET", "/auth/me")
    step("the new session works", status == 200, f"-> {status}")
    print("FIRST LOGIN OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
