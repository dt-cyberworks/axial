"""Log masking for the HexStrike execution boundary (REQ-TESTACCT-012, GitHub #89).

Upstream HexStrike logs every command it runs and every line the command prints (`EXECUTING: curl ... --data-raw 'username=..&password=..'`,
`STDOUT: Set-Cookie: ...`). With a test account the command line carries the password, and the target's answer can carry a session
cookie or even the password again. The container log is stored by Docker until the container is replaced, so a secret that is erased from
the database on revoke would still be on disk here.

Two rules, both applied to every log record of the process (a record factory, so no handler or logger can bypass them):

  1. Secrets the caller DECLARES for a request. The worker puts every recognized form of the test-account secrets that request carries in
     the `X-ASM-Log-Mask` header (base64 of a JSON list). They are kept in memory only, for `TTL_SECONDS`, and replaced wherever they occur.
  2. Credential-bearing headers and URL credentials, by shape: `Set-Cookie:`, `Cookie:`, `Authorization:`, `Proxy-Authorization:`,
     `X-Api-Key:` values and `user:password@` in a URL. These cannot be declared in advance (a login's session id does not exist until
     the target answers).

Stdlib only, like runner_auth.py and runner_budget.py, so the rules are unit-testable without Flask; patch_hexstrike.py injects them.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import threading
import time

LOG_MASK_HEADER = "X-ASM-Log-Mask"
MASK = "[masked]"
MIN_LENGTH = 8              # a shorter string would mask ordinary words; the platform refuses such a secret anyway
MAX_ENTRIES = 256
MAX_HEADER_CHARS = 16000
TTL_SECONDS = 900

_HEADER_VALUE_RE = re.compile(r"(?i)(?<![\w-])(set-cookie|cookie|authorization|proxy-authorization|x-api-key)(\s*:\s*)[^\r\n']*")
_URL_CREDENTIAL_RE = re.compile(r"(?<=://)[^/\s:@'\"]+:[^/\s@'\"]+@")

_lock = threading.Lock()
_entries: dict[str, float] = {}     # text -> time it expires
_installed = False


def decode(header_value: str | None) -> list[str]:
    """The strings a caller declared. Anything that is not base64 of a JSON list of strings declares nothing."""
    if not header_value or len(header_value) > MAX_HEADER_CHARS:
        return []
    try:
        decoded = json.loads(base64.b64decode(header_value.encode(), validate=True).decode())
    except (ValueError, UnicodeError):
        return []
    if not isinstance(decoded, list):
        return []
    return [s for s in decoded if isinstance(s, str) and len(s) >= MIN_LENGTH]


def encode(strings: list[str]) -> str | None:
    """The header value for `strings` (the worker's side): longest forms are kept first if the cap is reached."""
    kept: list[str] = []
    for text in sorted({s for s in strings if isinstance(s, str) and len(s) >= MIN_LENGTH}, key=len):
        trial = base64.b64encode(json.dumps(kept + [text]).encode()).decode()
        if len(trial) > MAX_HEADER_CHARS:
            break
        kept.append(text)
    return base64.b64encode(json.dumps(kept).encode()).decode() if kept else None


def register(header_value: str | None, now: float | None = None) -> int:
    """Remember the strings of one request; returns how many were declared."""
    strings = decode(header_value)
    if not strings:
        return 0
    moment = time.time() if now is None else now
    with _lock:
        for text in [t for t, until in _entries.items() if until <= moment]:
            del _entries[text]
        for text in strings:
            _entries[text] = moment + TTL_SECONDS
        while len(_entries) > MAX_ENTRIES:
            del _entries[min(_entries, key=_entries.get)]
    return len(strings)


def forget_all() -> None:
    with _lock:
        _entries.clear()


def mask(text: str, now: float | None = None) -> str:
    moment = time.time() if now is None else now
    with _lock:
        declared = sorted((t for t, until in _entries.items() if until > moment), key=len, reverse=True)
    for secret in declared:
        if secret in text:
            text = text.replace(secret, MASK)
    text = _HEADER_VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)
    return _URL_CREDENTIAL_RE.sub(f"{MASK}@", text)


def install() -> None:
    """Wrap the log-record factory once: every record of every logger is masked as it is created."""
    global _installed
    if _installed:
        return
    previous = logging.getLogRecordFactory()

    def factory(*args, **kwargs):
        record = previous(*args, **kwargs)
        try:
            text = record.getMessage()
        except Exception:  # noqa: BLE001 - a malformed record is the logger's problem, not a reason to lose the line
            return record
        masked = mask(text)
        if masked != text:
            record.msg, record.args = masked, ()
        return record

    logging.setLogRecordFactory(factory)
    _installed = True
