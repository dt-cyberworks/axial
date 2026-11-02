"""REQ-EGRESS-006 (GitHub #81): the control plane that mints a run token and the proxy that verifies it must agree.

`verify` exists twice, in control-plane/app/gateway/egress_identity.py (which also mints) and in
egress-proxy/app/run_token.py (which cannot mint), because they are separate processes with separate packages that
are both called `app`. If one accepted a token the other refuses, a run would be attributed to an engagement by one
and refused by the other - or worse, accepted by the proxy on a rule the control plane does not hold. Both are loaded
by path and judge the same corpus."""

from __future__ import annotations

import ast
import base64
import importlib.util
import itertools
import json
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


control_plane = _load("parity_cp_egress_identity", "control-plane/app/gateway/egress_identity.py")
proxy = _load("parity_proxy_run_token", "egress-proxy/app/run_token.py")

SECRET = "-".join(["parity", "secret"])
E, R = str(uuid.UUID(int=1)), str(uuid.UUID(int=2))
NOW = 1_800_000_000


def _outcome(module, token, secret=SECRET, now=NOW):
    try:
        identity = module.verify(secret, token, now=now)
        return ("ok", identity.engagement_id, identity.scan_run_id, identity.issued_at, identity.expires_at)
    except module.TokenInvalid as exc:
        return ("refused", exc.reason)


def _signed(claims) -> str:
    body = control_plane._b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    return f"v1.{body}.{control_plane._mac(SECRET, body)}"


def _corpus() -> list[tuple[str, str]]:
    good = control_plane.mint(SECRET, E, R, 600, now=NOW)
    version, body, signature = good.split(".")
    other_key = control_plane.mint("another", E, R, 600, now=NOW)
    cases = {
        "valid": good,
        "valid, other ids": control_plane.mint(SECRET, str(uuid.UUID(int=77)), str(uuid.UUID(int=78)), 3600, now=NOW),
        "valid, short": control_plane.mint(SECRET, E, R, 1, now=NOW),
        "another key": other_key,
        "flipped signature": f"{version}.{body}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}",
        "truncated signature": f"{version}.{body}.{signature[:-3]}",
        "extra part": good + ".x",
        "no signature": f"{version}.{body}.",
        "no body": f"{version}..{signature}",
        "version 2": f"v2.{body}.{signature}",
        "empty": "",
        "just dots": "..",
        "long": "v1." + "a" * 3000 + ".b",
        "unicode": "v1.é.é",
        "non-json body": f"v1.{control_plane._b64url(b'nope')}.{control_plane._mac(SECRET, control_plane._b64url(b'nope'))}",
        "list body": _signed([1, 2, 3]),
        "string body": _signed("abc"),
    }
    base = {"e": E, "r": R, "i": NOW, "x": NOW + 600}
    for field, value in itertools.product(("e", "r", "i", "x"), ("not-a-uuid", 5, None, True, 1.5, "", [], {})):
        cases[f"claim {field}={value!r}"] = _signed({**base, field: value})
    for missing in base:
        cases[f"missing {missing}"] = _signed({k: v for k, v in base.items() if k != missing})
    cases["expires with issue"] = _signed({**base, "x": NOW})
    cases["expires before issue"] = _signed({**base, "x": NOW - 5})
    cases["extra claim"] = _signed({**base, "z": 1})
    return list(cases.items())


def test_both_verifiers_accept_and_refuse_the_same_tokens_for_the_same_reason():
    disagreements = [
        (name, _outcome(control_plane, token), _outcome(proxy, token))
        for name, token in _corpus() if _outcome(control_plane, token) != _outcome(proxy, token)
    ]
    assert not disagreements, disagreements


def test_both_verifiers_agree_across_time_around_the_expiry_and_the_leeway():
    token = control_plane.mint(SECRET, E, R, 600, now=NOW)
    for offset in (-10_000, -1, 0, 1, 599, 600, 601, 600 + 4, 600 + 5, 600 + 6, 700, 10_000):
        assert _outcome(control_plane, token, now=NOW + offset) == _outcome(proxy, token, now=NOW + offset), offset


def test_the_corpus_has_both_kinds_of_answer_so_agreement_means_something():
    outcomes = {_outcome(control_plane, token)[0:2] for _, token in _corpus()}
    assert ("ok", E) in outcomes and any(o[0] == "refused" for o in outcomes)
    reasons = {o[1] for o in outcomes if o[0] == "refused"}
    assert {"malformed", "unsupported_version", "bad_signature", "bad_claims"} <= reasons


def test_the_proxy_cannot_mint():
    assert not hasattr(proxy, "mint")


def test_the_basic_credential_the_proxy_reads_is_the_one_the_runner_builds():
    """`http://asm:<token>@host` makes a client send `Basic base64("asm:<token>")`."""
    token = control_plane.mint(SECRET, E, R, 600, now=time.time())
    header = "Basic " + base64.b64encode(f"{proxy.PROXY_USER}:{token}".encode()).decode()
    assert proxy.verify_proxy_authorization(header, SECRET).scan_run_id == R


def _frozenset_literal(relative: str, name: str) -> set[str]:
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name:
            call = node.value
            assert isinstance(call, ast.Call) and getattr(call.func, "id", "") == "frozenset", f"{name} is not a frozenset literal"
            return {e.value for e in call.args[0].elts}
    raise AssertionError(f"{name} not found in {relative}")


def test_the_gateway_and_the_runner_name_the_same_identity_headers():
    """REQ-EGRESS-008: the Scope Gateway refuses them in a proposal and the runner's curl builder drops them."""
    gateway = _frozenset_literal("control-plane/app/gateway/args_safety.py", "PLATFORM_HEADERS")
    runner = _frozenset_literal("worker/app/tool_runner_client.py", "_PLATFORM_HEADERS")
    assert gateway == runner == {"proxy-authorization", "x-asm-engagement-id"}


def test_the_proxy_never_forwards_the_headers_the_gateway_forbids_a_caller_to_set():
    proxy_source = (ROOT / "egress-proxy/app/proxy.py").read_text(encoding="utf-8")
    forwarded = ast.literal_eval(next(
        line.split("=", 1)[1].strip() for line in proxy_source.splitlines() if line.startswith("_NEVER_FORWARDED")
    ))
    assert {"proxy-authorization", "x-asm-engagement-id"} <= set(forwarded)
