"""What the agent is told about its ffuf arguments (REQ-RETEST-009).

The Scope Gateway validates ffuf arguments strictly (control-plane/app/gateway/args_safety.py) and answers only
`unsafe_arguments`. One stray space in one of 21 candidates made a whole proposal fail that way, and the agent could
not tell which argument to correct. This module (a) removes harmless whitespace before the proposal is sent and (b)
says, in words, which argument breaks which rule when the gateway still refuses it. The gateway's validator is not
loosened by any of this; the rules below are a deliberate copy across the process boundary, and
scripts/tests/test_ffuf_args_parity.py fails when the two disagree.
"""

from __future__ import annotations

import re

WORDLIST_KEYS = ("common", "raft-medium-dirs", "raft-medium-files", "quickhits", "directory-list-medium")
FUZZ_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*FUZZ[A-Za-z0-9._~!$&'()*+,;=:@/%-]*$")
EXTENSION_RE = re.compile(r"^\.?[A-Za-z0-9]{1,8}$")
CANDIDATE_RE = re.compile(r"^[A-Za-z0-9._~/-]{1,128}$")
ALLOWED_KEYS = {"wordlist", "path", "extensions", "extra_candidates"}
MAX_EXTENSIONS = 10
MAX_CANDIDATES = 200


def _clean(entries: object) -> object:
    """Strip whitespace around string entries and drop empty ones; anything that is not a list is left for the
    problem description."""
    if not isinstance(entries, list):
        return entries
    out = []
    for entry in entries:
        if isinstance(entry, str):
            entry = entry.strip()
            if not entry:
                continue
        out.append(entry)
    return out


def normalize_ffuf_args(args: dict) -> dict:
    """Harmless whitespace only. Nothing is rewritten, added or widened."""
    cleaned = dict(args)
    for key in ("extensions", "extra_candidates"):
        if key in cleaned:
            cleaned[key] = _clean(cleaned[key])
    return cleaned


def describe_ffuf_problem(args: dict) -> str | None:
    """The first rule the arguments break, in words for the agent, or None when they would pass."""
    extra = set(args) - ALLOWED_KEYS
    if extra:
        return f"argument(s) {', '.join(sorted(map(repr, extra)))} are not allowed; the allowed ones are {', '.join(sorted(ALLOWED_KEYS))}"
    wordlist = str(args.get("wordlist", "common"))
    if wordlist not in WORDLIST_KEYS:
        return f"wordlist {wordlist!r} is not allowed; choose one of {', '.join(WORDLIST_KEYS)}"
    path = args.get("path", "/FUZZ")
    if not isinstance(path, str) or len(path) > 512 or not FUZZ_PATH_RE.match(path):
        return "path must start with / , contain FUZZ, be at most 512 characters and use only plain path characters"
    extensions = args.get("extensions", [])
    if not isinstance(extensions, list) or len(extensions) > MAX_EXTENSIONS:
        return f"extensions must be a list of at most {MAX_EXTENSIONS} entries"
    for entry in extensions:
        if not isinstance(entry, str) or not EXTENSION_RE.match(entry):
            return f"extensions entry {entry!r} is not allowed: a file extension of up to 8 letters or digits, such as php or .bak"
    candidates = args.get("extra_candidates", [])
    if not isinstance(candidates, list) or len(candidates) > MAX_CANDIDATES:
        return f"extra_candidates must be a list of at most {MAX_CANDIDATES} entries"
    for entry in candidates:
        if not isinstance(entry, str) or not CANDIDATE_RE.match(entry):
            return (
                f"extra_candidates entry {entry!r} is not allowed: only letters, digits and . _ ~ / - , "
                "1 to 128 characters, no spaces"
            )
    return None
