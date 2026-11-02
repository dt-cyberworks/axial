"""REQ-TESTACCT-013 (GitHub #89, R4): the tool runner's own log never holds a test account's secret or a credential-bearing header.

Found by the live verification on the dev stack: upstream HexStrike logs `EXECUTING: curl ... --data-raw 'username=alice&password=...'`
and every line the command prints, and Docker keeps that log until the container is replaced - after the database had erased the secret.
The audit trail, every table and every other service log were clean; this one was not."""

from __future__ import annotations

import base64
import io
import json
import logging
import pathlib
import sys
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import runner_logmask as lm  # noqa: E402

PASSWORD = "Sh0p pw/ab12cd34ef&x+y"
URL_FORM = "Sh0p%20pw%2Fab12cd34ef%26x%2By"
COMMAND = ("curl --globoff -sS -i -X POST --max-time 20 -x http://asm:v1.eyJlIjoiMDFhMTk3MzE.74j7qJPokuGM1fT@egress-proxy:3128 "
           f"-H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: sid=OLD-SESSION-1234' --data-raw 'username=alice&password={URL_FORM}' "
           "http://latoy:8000/login | head -c 16384")


@pytest.fixture(autouse=True)
def _clean():
    lm.forget_all()
    yield
    lm.forget_all()


def header(*strings: str) -> str:
    return base64.b64encode(json.dumps(list(strings)).encode()).decode()


# --- the declared secrets -----------------------------------------------------------------------------------------------------


def test_a_declared_secret_is_masked_wherever_it_occurs_in_a_line():
    assert lm.register(header(PASSWORD, URL_FORM)) == 2
    masked = lm.mask(COMMAND)
    assert URL_FORM not in masked and "password=[masked]" in masked
    assert lm.mask(f"Login failed for alice. The password was: {PASSWORD}") == "Login failed for alice. The password was: [masked]"


def test_nothing_is_masked_before_a_request_declares_it():
    assert URL_FORM in lm.mask(COMMAND), "the rule is not a guess: it masks what the worker declared, plus the shapes below"


def test_a_longer_secret_is_replaced_whole_even_when_a_shorter_one_is_inside_it():
    lm.register(header("password-12", "password-12-and-more"))
    assert lm.mask("x password-12-and-more y") == "x [masked] y"


def test_a_declaration_expires():
    lm.register(header(PASSWORD), now=1000.0)
    assert lm.mask(f"pw {PASSWORD}", now=1000.0 + lm.TTL_SECONDS - 1) == "pw [masked]"
    assert lm.mask(f"pw {PASSWORD}", now=1000.0 + lm.TTL_SECONDS + 1) == f"pw {PASSWORD}"


def test_the_number_of_remembered_strings_is_bounded_and_the_oldest_go_first():
    for index in range(lm.MAX_ENTRIES + 20):
        lm.register(header(f"secret-value-{index:04d}"), now=1000.0 + index)
    assert len(lm._entries) == lm.MAX_ENTRIES
    assert "secret-value-0000" not in lm._entries and f"secret-value-{lm.MAX_ENTRIES + 19:04d}" in lm._entries


@pytest.mark.parametrize("bad", [None, "", "not base64 !!", base64.b64encode(b"not json").decode(), base64.b64encode(b'{"a": 1}').decode(),
                                 base64.b64encode(b"[1, 2, null]").decode(), "A" * (lm.MAX_HEADER_CHARS + 1)])
def test_negative_a_malformed_declaration_declares_nothing_and_does_not_fail(bad):
    assert lm.register(bad) == 0
    assert lm.mask("ordinary line 12345678") == "ordinary line 12345678"


def test_negative_a_short_string_is_never_masked_it_would_hide_ordinary_words():
    assert lm.register(header("short", "a", "1234567")) == 0
    assert lm.mask("a short line 1234567") == "a short line 1234567"


# --- by shape: what cannot be declared in advance -----------------------------------------------------------------------------


@pytest.mark.parametrize("line,gone", [
    ("Set-Cookie: sid=NEW-SESSION-9999; HttpOnly; Path=/", "NEW-SESSION-9999"),
    ("set-cookie: sid=NEW-SESSION-9999", "NEW-SESSION-9999"),
    ("Cookie: sid=OLD-SESSION-1234", "OLD-SESSION-1234"),
    ("Authorization: Bearer abcdef0123456789", "abcdef0123456789"),
    ("Proxy-Authorization: Basic YWxpY2U6cHc=", "YWxpY2U6cHc="),
    ("X-Api-Key: 0123456789abcdef", "0123456789abcdef"),
])
def test_a_credential_bearing_header_value_is_masked_with_no_declaration(line, gone):
    masked = lm.mask(line)
    assert gone not in masked and "[masked]" in masked
    assert masked.split(":")[0].lower() == line.split(":")[0].lower(), "the header's name stays, so a log is still readable"


def test_the_executing_line_keeps_its_shape_and_loses_every_credential():
    lm.register(header(URL_FORM))
    masked = lm.mask(f"🚀 EXECUTING: {COMMAND}")
    for gone in (URL_FORM, "OLD-SESSION-1234", "v1.eyJlIjoiMDFhMTk3MzE", "74j7qJPokuGM1fT"):
        assert gone not in masked, gone
    assert "curl --globoff -sS -i -X POST --max-time 20" in masked and "http://latoy:8000/login" in masked
    assert "-H 'Content-Type: application/x-www-form-urlencoded'" in masked, "an ordinary header is left alone"
    assert "-x http://[masked]@egress-proxy:3128" in masked


@pytest.mark.parametrize("line", [
    "Content-Type: application/x-www-form-urlencoded", "Server: nginx/1.25", "Location: https://example.com:8443/path",
    "GET http://host:3128/path@thing HTTP/1.1", "📤 STDOUT: {\"ok\": true, \"user\": \"alice\"}", "Cookies are tasty",
])
def test_negative_ordinary_lines_are_untouched(line):
    assert lm.mask(line) == line


# --- every log record, by any logger -------------------------------------------------------------------------------------------


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(lm, "_installed", False)
    previous = logging.getLogRecordFactory()
    lm.install()
    yield
    logging.setLogRecordFactory(previous)


def capture(logger_name: str):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    logger = logging.getLogger(logger_name)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return stream, logger, handler


def test_every_logger_and_handler_gets_the_masked_message(installed):
    lm.register(header(PASSWORD, URL_FORM))
    for name in ("hexstrike_server", "werkzeug", "some.other.module"):
        stream, logger, handler = capture(name)
        try:
            logger.info(f"📤 STDOUT: Login failed. The password was: {PASSWORD}")
            logger.info("with args: %s and %s", PASSWORD, "Set-Cookie: sid=zzzzzzzz1")
            logger.warning("EXECUTING: %s", COMMAND)
        finally:
            logger.removeHandler(handler)
        out = stream.getvalue()
        assert PASSWORD not in out and "sid=zzzzzzzz1" not in out and URL_FORM not in out and "OLD-SESSION-1234" not in out, (name, out)
        assert out.count("[masked]") >= 4


def test_installing_twice_wraps_the_factory_once(installed):
    before = logging.getLogRecordFactory()
    lm.install()
    assert logging.getLogRecordFactory() is before


def test_a_line_with_a_percent_sign_survives_masking(installed):
    lm.register(header(PASSWORD))
    stream, logger, handler = capture("pct")
    try:
        logger.info("100%% done, password %s, and a literal 50%% sign", PASSWORD)
    finally:
        logger.removeHandler(handler)
    assert "100% done, password [masked], and a literal 50% sign" in stream.getvalue()


# --- the build -----------------------------------------------------------------------------------------------------------------


def test_the_patch_installs_the_mask_and_registers_declarations_only_after_the_auth_gate():
    from patch_hexstrike import patch_source
    from test_runner_auth import _FIXTURE

    patched = patch_source(_FIXTURE)
    assert "from runner_logmask import LOG_MASK_HEADER" in patched and patched.count("_asm_install_log_mask()") == 1
    gate = patched.index("def _asm_enforce_runner_auth")
    refusal = patched.index("runner_auth_required'}), 401")
    registration = patched.index("_asm_register_log_mask(request.headers.get(_ASM_LOG_MASK_HEADER))")
    assert gate < refusal < registration < patched.index('@app.route("/api/processes/list"'), "an unauthenticated caller cannot declare anything"
    assert patched.index("_asm_install_log_mask()") < gate, "installed before the first request can be served"


def test_negative_the_patch_fails_loudly_when_an_anchor_moves():
    from patch_hexstrike import patch_source
    from test_runner_auth import _FIXTURE

    with pytest.raises(RuntimeError):
        patch_source(_FIXTURE.replace("app = Flask(__name__)", "application = Flask(__name__)"))


def test_the_dockerfile_ships_the_module_next_to_the_server():
    dockerfile = (HERE.parent / "runner.Dockerfile").read_text()
    assert "COPY runner_logmask.py /tmp/runner_logmask.py" in dockerfile
    assert "cp /tmp/runner_logmask.py /opt/hexstrike/runner_logmask.py" in dockerfile


def test_the_worker_and_the_runner_agree_on_the_header_and_its_limits():
    client = (HERE.parents[1] / "worker" / "app" / "tool_runner_client.py").read_text()
    assert f'LOG_MASK_HEADER = "{lm.LOG_MASK_HEADER}"' in client
    assert f"LOG_MASK_MIN_LENGTH = {lm.MIN_LENGTH}" in client
    assert f"LOG_MASK_MAX_CHARS = {lm.MAX_HEADER_CHARS}" in client


def test_encode_is_decoded_by_register_and_respects_the_cap():
    assert lm.decode(lm.encode([PASSWORD, URL_FORM])) == sorted([PASSWORD, URL_FORM], key=len)
    huge = [f"{index:04d}" + "x" * 400 for index in range(200)]
    encoded = lm.encode(huge)
    assert encoded is not None and len(encoded) <= lm.MAX_HEADER_CHARS and lm.decode(encoded)
    assert lm.encode([]) is None and lm.encode(["short"]) is None
