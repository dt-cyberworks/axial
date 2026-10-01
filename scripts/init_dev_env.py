#!/usr/bin/env python3
"""Create or complete the local-evaluation `.env` (REQ-INSTALL-003).

`.env.example` deliberately ships NO encryption key (a key in source is a leaked
key - see the 2026-07-30 incident), so a fresh `cp .env.example .env` left
MFA_ENCRYPTION_KEY empty: the stack started and /health was green, but the first
user's MFA enrollment failed and nobody could ever log in. This script closes
that gap without shipping a key:

  * `.env` missing  -> copied from `.env.example` (mode 0600), then completed;
  * `.env` present  -> only EMPTY secret values are filled, with a freshly
    generated Fernet-compatible key each (they differ, so a leak of one does
    not expose the other); every value that is already set is left untouched;
  * `ENVIRONMENT=production` in `.env` -> not modified at all: a production
    file comes from scripts/gen_production_env.py, and an empty key there must
    stay an error (the production gate refuses to start), not be auto-filled.

Idempotent, standard library only (the documented prerequisites contain no
Python packages), prints which keys it generated but never their values.

Usage:  python3 scripts/init_dev_env.py [--env-file .env] [--example .env.example]
        (normally run by `make env`, which `make up` depends on)
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import stat
import sys
from pathlib import Path

# Keys that must hold a Fernet key and have no usable default.
FERNET_KEYS = ("MFA_ENCRYPTION_KEY", "SETTINGS_ENCRYPTION_KEY")

_LINE = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$")


def fernet_key() -> str:
    """Same format as cryptography's Fernet.generate_key(): urlsafe base64 of 32 random bytes."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def _is_empty(value: str) -> bool:
    return value.strip().strip("\"'").strip() == ""


def _value_of(lines: list[str], key: str) -> str | None:
    for line in lines:
        match = _LINE.match(line)
        if match and match.group("key") == key:
            return match.group("value")
    return None


def complete(lines: list[str]) -> tuple[list[str], list[str]]:
    """Return (new_lines, generated_key_names). Never alters a non-empty value."""
    out = list(lines)
    generated: list[str] = []
    for key in FERNET_KEYS:
        current = _value_of(out, key)
        if current is not None and not _is_empty(current):
            continue
        value = fernet_key()
        replaced = False
        for index, line in enumerate(out):
            match = _LINE.match(line)
            if match and match.group("key") == key:
                out[index] = f"{key}={value}"
                replaced = True
                break
        if not replaced:
            out.append(f"{key}={value}")
        generated.append(key)
    return out, generated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--example", default=".env.example")
    args = parser.parse_args(argv)
    env_path, example_path = Path(args.env_file), Path(args.example)

    created = False
    if not env_path.exists():
        if not example_path.exists():
            print(f"error: {env_path} is missing and so is {example_path}", file=sys.stderr)
            return 1
        text = example_path.read_text(encoding="utf-8")
        created = True
    else:
        text = env_path.read_text(encoding="utf-8")

    lines = text.splitlines()
    environment = _value_of(lines, "ENVIRONMENT")
    if environment is not None and environment.strip().strip("\"'").lower() == "production":
        print(f"{env_path}: ENVIRONMENT=production - left untouched "
              "(generate it with scripts/gen_production_env.py)")
        return 0

    new_lines, generated = complete(lines)
    if created or generated:
        # Create 0600 from the start; the file will hold secrets.
        fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(new_lines) + "\n")
        if created:
            print(f"created {env_path} from {example_path}")
    if generated:
        print(f"generated {', '.join(generated)} in {env_path} (values not printed)")
    if not created and not generated:
        print(f"{env_path}: nothing to do")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
