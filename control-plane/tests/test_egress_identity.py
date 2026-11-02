"""REQ-EGRESS-006 (GitHub #81): the signed run identity the egress proxy verifies."""

from __future__ import annotations

import base64
import json
import uuid

import pytest

from app.gateway import egress_identity as ident

SECRET = "-".join(["t", "egress", "run", "secret"])
OTHER_SECRET = "-".join(["another", "secret"])
ENGAGEMENT = uuid.UUID("11111111-1111-4111-8111-111111111111")
RUN = uuid.UUID("22222222-2222-4222-8222-222222222222")
NOW = 1_800_000_000.0


def _token(**over):
    args = dict(secret=SECRET, engagement_id=ENGAGEMENT, scan_run_id=RUN, ttl_seconds=600, now=NOW)
    args.update(over)
    return ident.mint(args.pop("secret"), args.pop("engagement_id"), args.pop("scan_run_id"), args.pop("ttl_seconds"), **args)


def _signed(payload: dict, secret: str = SECRET) -> str:
    """A token with the right signature over arbitrary claims, to reach the claim checks."""
    body = ident._b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    return f"{ident.VERSION}.{body}.{ident._mac(secret, body)}"


def test_a_minted_token_proves_its_engagement_and_run():
    got = ident.verify(SECRET, _token(), now=NOW + 1)
    assert got == ident.RunIdentity(str(ENGAGEMENT), str(RUN), int(NOW), int(NOW) + 600)


def test_the_token_fits_the_userinfo_of_a_proxy_url_without_encoding():
    token = _token()
    assert all(c.isalnum() or c in "-_." for c in token)
    assert len(token) < 400 and token.startswith("v1.") and token.count(".") == 2


def test_two_tokens_for_the_same_run_differ_only_by_their_time():
    assert _token(now=NOW) != _token(now=NOW + 1)


@pytest.mark.parametrize("token", [
    "", "x", "v1", "v1.a", "v1.a.b.c", ".." , "v1..", "v1.a.", "v1..b", "a.b.c", "v1." + "a" * 2000 + ".b", "\x00", "v1.é.é",
])
def test_negative_a_malformed_token_is_refused_with_a_reason_and_nothing_else(token):
    with pytest.raises(ident.TokenInvalid) as caught:
        ident.verify(SECRET, token, now=NOW)
    assert caught.value.reason in {"malformed", "unsupported_version", "bad_signature"}


@pytest.mark.parametrize("bad", [None, 7, b"v1.a.b", ["v1", "a", "b"]])
def test_negative_a_value_that_is_not_a_string_is_malformed(bad):
    with pytest.raises(ident.TokenInvalid) as caught:
        ident.verify(SECRET, bad, now=NOW)
    assert caught.value.reason == "malformed"


def test_negative_another_version_is_refused_before_anything_else():
    body = _token().split(".")[1]
    with pytest.raises(ident.TokenInvalid) as caught:
        ident.verify(SECRET, f"v2.{body}.x", now=NOW)
    assert caught.value.reason == "unsupported_version"


def test_negative_a_token_signed_with_another_key_is_refused():
    with pytest.raises(ident.TokenInvalid) as caught:
        ident.verify(SECRET, _token(secret=OTHER_SECRET), now=NOW)
    assert caught.value.reason == "bad_signature"


def test_negative_an_empty_key_verifies_nothing():
    with pytest.raises(ident.TokenInvalid) as caught:
        ident.verify("", _token(), now=NOW)
    assert caught.value.reason == "malformed"


def test_negative_any_changed_claim_breaks_the_signature():
    version, body, signature = _token().split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    for field, value in (("e", str(uuid.uuid4())), ("r", str(uuid.uuid4())), ("x", claims["x"] + 3600), ("i", claims["i"] - 1)):
        changed = ident._b64url(json.dumps({**claims, field: value}, sort_keys=True, separators=(",", ":")).encode())
        with pytest.raises(ident.TokenInvalid) as caught:
            ident.verify(SECRET, f"{version}.{changed}.{signature}", now=NOW)
        assert caught.value.reason == "bad_signature", field


def test_negative_a_changed_signature_is_refused():
    version, body, signature = _token().split(".")
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
    with pytest.raises(ident.TokenInvalid) as caught:
        ident.verify(SECRET, f"{version}.{body}.{flipped}", now=NOW)
    assert caught.value.reason == "bad_signature"


def test_negative_the_mac_includes_a_context_so_another_purpose_cannot_replay_it():
    body = _token().split(".")[1]
    import hashlib
    import hmac
    without_context = ident._b64url(hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).digest())
    with pytest.raises(ident.TokenInvalid) as caught:
        ident.verify(SECRET, f"v1.{body}.{without_context}", now=NOW)
    assert caught.value.reason == "bad_signature"


def test_a_token_is_valid_until_its_expiry_and_a_few_seconds_beyond():
    token = _token(ttl_seconds=600)
    assert ident.verify(SECRET, token, now=NOW + 600).scan_run_id == str(RUN)
    assert ident.verify(SECRET, token, now=NOW + 600 + ident.LEEWAY_SECONDS).scan_run_id == str(RUN)


def test_negative_an_expired_token_is_refused():
    with pytest.raises(ident.TokenInvalid) as caught:
        ident.verify(SECRET, _token(ttl_seconds=600), now=NOW + 600 + ident.LEEWAY_SECONDS + 1)
    assert caught.value.reason == "expired"


@pytest.mark.parametrize("claims", [
    {"e": "not-a-uuid", "r": str(RUN), "i": 1, "x": 2},
    {"e": str(ENGAGEMENT), "r": 5, "i": 1, "x": 2},
    {"e": str(ENGAGEMENT), "r": str(RUN), "i": "1", "x": 2},
    {"e": str(ENGAGEMENT), "r": str(RUN), "i": 1, "x": True},
    {"e": str(ENGAGEMENT), "r": str(RUN), "i": 1.5, "x": 2},
    {"e": str(ENGAGEMENT), "r": str(RUN), "i": 10, "x": 10},       # expires when it was issued
    {"e": str(ENGAGEMENT), "r": str(RUN), "i": 10, "x": 5},
    {"e": str(ENGAGEMENT), "r": str(RUN), "i": 1},                  # no expiry at all
    {"r": str(RUN), "i": 1, "x": 2},
])
def test_negative_a_validly_signed_token_with_unusable_claims_is_refused(claims):
    with pytest.raises(ident.TokenInvalid) as caught:
        ident.verify(SECRET, _signed(claims), now=0)
    assert caught.value.reason == "bad_claims"


def test_negative_a_signed_body_that_is_not_json_is_refused():
    body = ident._b64url(b"not json")
    with pytest.raises(ident.TokenInvalid) as caught:
        ident.verify(SECRET, f"v1.{body}.{ident._mac(SECRET, body)}", now=0)
    assert caught.value.reason == "bad_claims"


@pytest.mark.parametrize("kwargs", [
    {"secret": ""}, {"ttl_seconds": 0}, {"ttl_seconds": -5}, {"ttl_seconds": 86401},
    {"engagement_id": "not-a-uuid"}, {"scan_run_id": ""},
])
def test_negative_minting_refuses_unusable_input(kwargs):
    with pytest.raises(ValueError):
        _token(**kwargs)


def test_verification_never_raises_anything_but_token_invalid_for_garbage():
    import random
    rng = random.Random(81)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-_.=+/%é "
    for _ in range(400):
        garbage = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 120)))
        try:
            ident.verify(SECRET, garbage, now=NOW)
        except ident.TokenInvalid:
            pass
