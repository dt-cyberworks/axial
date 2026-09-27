from app.nikto_parse import parse_nikto_missing_headers

NIKTO_SAMPLE = """
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          172.24.0.3
+ Target Hostname:    metasploitable2
+ Target Port:        80
+ Start Time:         2026-07-11 18:00:00
---------------------------------------------------------------------------
+ Server: Apache/2.2.8 (Ubuntu) DAV/2
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content in a different fashion.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-3268: /doc/: Directory indexing found.
+ 7535 requests: 0 error(s) and 4 item(s) reported
+ End Time:           2026-07-11 18:00:10 (10 seconds)
"""


def test_detects_missing_frame_options_and_content_type():
    missing = parse_nikto_missing_headers(NIKTO_SAMPLE)
    assert "x-frame-options" in missing
    assert "x-content-type-options" in missing


def test_does_not_flag_headers_not_mentioned():
    missing = parse_nikto_missing_headers(NIKTO_SAMPLE)
    assert "content-security-policy" not in missing
    assert "strict-transport-security" not in missing


def test_empty_output_returns_empty_list():
    assert parse_nikto_missing_headers("") == []


# nikto >= 2.5 (Live-Format gegen echte Domain / nginx). Der urspruengliche
# Parser fand hier nichts - dieser Test verankert den Fix.
NIKTO_25_SAMPLE = """
+ Server: nginx
+ [999100] /images: Uncommon header(s) 'x-request-id' found, with contents: abc.
+ [013587] /: Suggested security header missing: content-security-policy. See: https://...
+ [013587] /: Suggested security header missing: permissions-policy. See: https://...
+ [013587] /: Suggested security header missing: strict-transport-security. See: https://...
+ 1455 requests: 0 errors and 4 items reported on the remote host
"""


def test_detects_new_suggested_missing_format():
    missing = parse_nikto_missing_headers(NIKTO_25_SAMPLE)
    assert "content-security-policy" in missing
    assert "permissions-policy" in missing
    assert "strict-transport-security" in missing
    # x-frame-options wird in diesem Sample NICHT gemeldet
    assert "x-frame-options" not in missing
