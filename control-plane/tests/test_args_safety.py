from app.gateway.args_safety import args_are_safe


def test_nmap_allows_safe_service_scan():
    assert args_are_safe("nmap", {"flags": ["-sV", "-p"]})


def test_nmap_blocks_exploit_scripts():
    assert not args_are_safe("nmap", {"flags": ["-sV", "--script=exploit-all"]})


def test_nuclei_forbids_dangerous_tags_allows_conservative():
    # Konservative Invocation wird im Body-Builder erzwungen; leere args sind
    # der Standard-Dispatch-Pfad und sicher.
    assert args_are_safe("nuclei", {})
    assert args_are_safe("nuclei", {"tags": ["exposure", "cve"]})
    # dos/intrusive/fuzz duerfen nie durch (auch nicht von einem Vector Agent).
    assert not args_are_safe("nuclei", {"tags": ["intrusive"]})
    assert not args_are_safe("nuclei", {"tags": ["dos"]})
    assert not args_are_safe("nuclei", {"tags": ["fuzz"]})


def test_httpx_blocks_write_methods():
    assert args_are_safe("httpx", {"method": "GET"})
    assert not args_are_safe("httpx", {"method": "DELETE"})


def test_default_cred_check_limits_attempts():
    assert args_are_safe("default-cred-check", {"max_attempts": 3, "wordlist": "default"})
    assert not args_are_safe("default-cred-check", {"max_attempts": 50, "wordlist": "default"})
    assert not args_are_safe("default-cred-check", {"max_attempts": 1, "wordlist": "rockyou.txt"})


def test_http_request_allows_read_methods_with_custom_headers():
    # Der Pentest-Mehrwert: beliebige Header/Pfad, aber nicht-destruktiv.
    assert args_are_safe("http_request", {"method": "GET", "path": "/api/users",
                                          "headers": {"X-Internal": "true", "X-Api-Key": "guess"}})
    assert args_are_safe("http_request", {"method": "HEAD", "path": "/"})
    assert args_are_safe("http_request", {"method": "OPTIONS", "path": "/api"})


def test_http_request_write_methods_are_structurally_valid():
    # REQ-HTTP-002: schreibende Methoden sind STRUKTURELL gueltig (die read/write-
    # Policy - autonom vs Freigabe - entscheidet das Gateway, nicht args_safety).
    for m in ("POST", "PUT", "DELETE", "PATCH"):
        assert args_are_safe("http_request", {"method": m, "path": "/api/users"})
    # Unbekannte Methode bleibt ungueltig.
    assert not args_are_safe("http_request", {"method": "TRACE", "path": "/"})


def test_http_request_state_changing_classification():
    from app.gateway.args_safety import http_request_is_state_changing
    assert http_request_is_state_changing({"method": "POST", "path": "/"})
    assert http_request_is_state_changing({"method": "GET", "path": "/", "body": "x=1"})  # Body = write
    assert not http_request_is_state_changing({"method": "GET", "path": "/"})


def test_http_request_body_bounds():
    assert args_are_safe("http_request", {"method": "POST", "path": "/", "body": "user=admin"})
    assert not args_are_safe("http_request", {"method": "POST", "path": "/", "body": "x" * 20000})


def test_http_request_blocks_header_and_path_injection():
    # CRLF-Injektion in Header/Pfad muss scheitern.
    assert not args_are_safe("http_request", {"method": "GET", "path": "/a\r\nHost: evil"})
    assert not args_are_safe("http_request", {"method": "GET", "path": "/", "headers": {"X-A": "b\r\nX-C: d"}})
    assert not args_are_safe("http_request", {"method": "GET", "path": "/", "headers": {"bad header": "x"}})
    # Unbekannte Argumente werden abgelehnt (kein Schmuggel).
    assert not args_are_safe("http_request", {"method": "GET", "path": "/", "data": "x"})


def test_ffuf_allows_curated_wordlist_and_fuzz_path():
    assert args_are_safe("ffuf", {"wordlist": "common", "path": "/FUZZ"})
    assert args_are_safe("ffuf", {"wordlist": "raft-medium-dirs", "path": "/api/FUZZ",
                                  "extensions": ["php", ".bak"]})
    # Gezielte Kandidatenliste statt Wortliste (Intruder-artig).
    assert args_are_safe("ffuf", {"wordlist": "common", "path": "/users/FUZZ",
                                  "extra_candidates": ["1", "2", "admin", "backup"]})


def test_ffuf_rejects_raw_wordlist_path():
    # Wortliste NUR ueber Allowlist-Schluessel - kein roher Dateipfad (Datei-Leak).
    assert not args_are_safe("ffuf", {"wordlist": "/etc/passwd", "path": "/FUZZ"})
    assert not args_are_safe("ffuf", {"wordlist": "unknown-list", "path": "/FUZZ"})


def test_ffuf_requires_fuzz_placeholder_and_safe_path():
    assert not args_are_safe("ffuf", {"wordlist": "common", "path": "/admin"})  # kein FUZZ
    assert not args_are_safe("ffuf", {"wordlist": "common", "path": "/FUZZ\r\nHost: x"})
    assert not args_are_safe("ffuf", {"wordlist": "common", "path": "FUZZ"})     # muss mit / anfangen


def test_ffuf_rejects_bad_extensions_candidates_and_unknown_args():
    assert not args_are_safe("ffuf", {"wordlist": "common", "path": "/FUZZ", "extensions": ["php; rm -rf"]})
    assert not args_are_safe("ffuf", {"wordlist": "common", "path": "/FUZZ", "extra_candidates": ["ok", "bad;cmd"]})
    assert not args_are_safe("ffuf", {"wordlist": "common", "path": "/FUZZ", "extra_candidates": ["x"] * 201})
    assert not args_are_safe("ffuf", {"wordlist": "common", "path": "/FUZZ", "rate": 9999})


def test_nmap_allows_only_bounded_full_tcp_profile():
    assert args_are_safe("nmap", {
        "flags": ["-sS", "-p"],
        "ports": "1-65535",
        "max_rate": 300,
        "port_profile": "full_tcp",
    })
    assert not args_are_safe("nmap", {
        "flags": ["-sS", "-p"],
        "ports": "1-65535",
        "max_rate": 5000,
        "port_profile": "full_tcp",
    })
    assert not args_are_safe("nmap", {
        "flags": ["-sS", "-p"],
        "ports": "1-65535",
        "max_rate": 300,
        "port_profile": "full_tcp",
        "additional_args": "--script exploit",
    })


def test_configured_tcp_allows_a_bounded_comma_separated_segment_list():
    """REQ-PORTSCOPE-003: configured_tcp may carry one nmap -p segment per
    matched per-target scope range - standard nmap syntax, capped and
    individually bounds-checked, not a free-form string."""
    assert args_are_safe("nmap", {
        "flags": ["-sS", "-p"], "ports": "22,443,8000-8100", "max_rate": 300,
        "port_profile": "configured_tcp",
    })
    assert not args_are_safe("nmap", {
        # a segment with an out-of-bounds port must still fail even inside a list
        "flags": ["-sS", "-p"], "ports": "22,70000", "max_rate": 300,
        "port_profile": "configured_tcp",
    })
    assert not args_are_safe("nmap", {
        # more segments than the cap
        "flags": ["-sS", "-p"], "ports": ",".join(str(p) for p in range(1, 10)), "max_rate": 300,
        "port_profile": "configured_tcp",
    })
    assert not args_are_safe("nmap", {
        "flags": ["-sS", "-p"], "ports": "", "max_rate": 300, "port_profile": "configured_tcp",
    })


def test_full_tcp_rejects_a_segment_list_even_if_it_sums_to_the_full_range():
    """full_tcp must mean one literal, unrestricted 1-65535 segment - a list
    that happens to cover the same total range is not the same authorization
    and must not be accepted as a substitute."""
    assert not args_are_safe("nmap", {
        "flags": ["-sS", "-p"], "ports": "1-32767,32768-65535", "max_rate": 300,
        "port_profile": "full_tcp",
    })


def test_host_discovery_allows_only_bounded_sn_sweep():
    """REQ-CIDRDISC-002: liveness-only -sn, no ports at all - not a port scan
    under a different profile name."""
    assert args_are_safe("nmap", {
        "flags": ["-sn"], "max_rate": 500, "port_profile": "host_discovery",
    })
    assert not args_are_safe("nmap", {
        "flags": ["-sn"], "max_rate": 5000, "port_profile": "host_discovery",
    })
    assert not args_are_safe("nmap", {
        # a port scan flag under host_discovery must still be rejected
        "flags": ["-sS"], "max_rate": 500, "port_profile": "host_discovery",
    })
    assert not args_are_safe("nmap", {
        # any ports value at all disqualifies a liveness-only sweep
        "flags": ["-sn"], "ports": "80,443", "max_rate": 500, "port_profile": "host_discovery",
    })


def test_raw_tcp_probe_tools_allow_only_empty_args():
    """REQ-AGENT-025: redis-probe/activemq-banner take no structured args at
    all - the bytes sent (or not) are a fixed, server-side registry entry,
    never agent-supplied. Any argument at all must be rejected, not just an
    unrecognized one."""
    assert args_are_safe("redis-probe", {})
    assert args_are_safe("activemq-banner", {})
    assert not args_are_safe("redis-probe", {"port": 6379})
    assert not args_are_safe("redis-probe", {"send": "EVAL 'x' 0"})
    assert not args_are_safe("activemq-banner", {"host": "evil.example"})


def test_negative_the_openwire_probe_rejects_any_agent_supplied_argument():
    """REQ-AGENT-027: same guarantee as REQ-AGENT-025 above - the packet is
    built server-side (worker/app/openwire_payload.py) from a curated table
    plus a callback URL the worker itself requests. An agent that could
    supply, say, a gadget name or raw bytes here would defeat the entire
    curation model this tool's R4 approval depends on."""
    assert args_are_safe("activemq-openwire-probe", {})
    assert not args_are_safe("activemq-openwire-probe", {"gadget": "something-else"})
    assert not args_are_safe("activemq-openwire-probe", {"_send_bytes": b"\x00\x01"})
    assert not args_are_safe("activemq-openwire-probe", {"callback_url": "https://attacker.example"})
