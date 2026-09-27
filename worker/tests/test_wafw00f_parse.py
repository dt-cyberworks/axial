from app.wafw00f_parse import parse_wafw00f

DETECTED = """
[*] Checking https://example.com
[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.
[~] Number of requests: 12
"""

NO_WAF = """
[*] Checking https://example.org
[+] Generic Detection results:
[-] No WAF detected by the generic detection
[~] Number of requests: 7
"""


def test_detects_named_waf():
    assert parse_wafw00f(DETECTED) == "Cloudflare"


def test_no_waf_returns_none():
    assert parse_wafw00f(NO_WAF) is None


def test_empty_returns_none():
    assert parse_wafw00f("") is None
