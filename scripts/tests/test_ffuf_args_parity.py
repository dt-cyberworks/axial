"""REQ-RETEST-009: the worker's description of the ffuf argument rules and the gateway's validator must agree.

The worker explains to the agent why the gateway refused its arguments (worker/app/agent_args.py). That explanation is
a copy of the rules across the process boundary, so it must never say "allowed" for something the gateway refuses, or
the reverse. Both modules are loaded by path (they are separate packages that are both called `app`).
"""

from __future__ import annotations

import importlib.util
import itertools
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gateway = _load("gateway_args_safety", "control-plane/app/gateway/args_safety.py")
worker = _load("worker_agent_args", "worker/app/agent_args.py")

WORDLISTS = ["common", "quickhits", "raft-medium-dirs", "/etc/passwd", "nope", ""]
PATHS = ["/FUZZ", "/api/FUZZ", "/FUZZ.php", "/nothing", "FUZZ", "/FUZZ;id", "/a b/FUZZ", "/" + "a" * 600 + "FUZZ"]
EXTENSIONS = [[], ["php"], [".bak"], ["php;id"], ["toolongextension"], [" php"], ["a"] * 11, "php", [1]]
CANDIDATES = [
    [], [".git/config"], ["a b"], [" Procfile"], ["a;b"], ["$(id)"], ["x" * 129], ["x" * 128], ["a/../b"], ["a|b"],
    ["ok"] * 200, ["ok"] * 201, "admin", [None], ["é"],
]


def _worker_accepts(args: dict) -> bool:
    return worker.describe_ffuf_problem(args) is None


def test_the_worker_rules_and_the_gateway_validator_accept_the_same_inputs():
    checked = 0
    for wordlist, path, extensions, candidates in itertools.product(WORDLISTS, PATHS, EXTENSIONS, CANDIDATES):
        args = {"wordlist": wordlist, "path": path, "extensions": extensions, "extra_candidates": candidates}
        assert gateway._ffuf_args_safe(args) == _worker_accepts(args), args
        checked += 1
    assert checked > 5000


def test_an_unknown_argument_is_refused_by_both():
    args = {"wordlist": "common", "headers": {"X": "y"}}
    assert gateway._ffuf_args_safe(args) is False
    assert _worker_accepts(args) is False


def test_the_wordlist_keys_are_the_same_in_both_places():
    assert set(worker.WORDLIST_KEYS) == set(gateway._FFUF_WORDLISTS)


def test_normalizing_never_makes_the_gateway_accept_something_unsafe():
    # Whatever the worker sends after normalizing is judged by the unchanged gateway rules: for every input the
    # normalized form is accepted only if each remaining entry is itself a plain token.
    for candidates in CANDIDATES:
        raw = {"wordlist": "common", "path": "/FUZZ", "extensions": [], "extra_candidates": candidates}
        cleaned = worker.normalize_ffuf_args(raw)
        if gateway._ffuf_args_safe(cleaned):
            for entry in cleaned["extra_candidates"]:
                assert isinstance(entry, str) and entry == entry.strip() and gateway._CANDIDATE_RE.match(entry)
