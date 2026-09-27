from app.nmap_parse import nmap_xml_target_count, parse_nmap_grepable, parse_nmap_xml, parse_nmap_xml_live_hosts

METASPLOITABLE_SAMPLE = (
    "# Nmap 7.94 scan initiated\n"
    "Host: 10.0.0.5 ()\tPorts: "
    "21/open/tcp//ftp//vsftpd 2.3.4/, "
    "22/open/tcp//ssh//OpenSSH 4.7p1 Debian 8ubuntu1//, "
    "23/closed/tcp//telnet///, "
    "3306/open/tcp//mysql//MySQL 5.0.51a-3ubuntu5/\t"
    "Ignored State: closed (996)\n"
    "# Nmap done\n"
)


def test_parses_open_ports_only():
    services = parse_nmap_grepable(METASPLOITABLE_SAMPLE)
    ports = {s["port"] for s in services}
    assert ports == {21, 22, 3306}
    assert 23 not in ports  # closed -> ausgefiltert


def test_extracts_product_string():
    services = parse_nmap_grepable(METASPLOITABLE_SAMPLE)
    by_port = {s["port"]: s for s in services}
    assert "vsftpd 2.3.4" in by_port[21]["product"]
    assert "OpenSSH" in by_port[22]["product"]


def test_empty_input_returns_empty_list():
    assert parse_nmap_grepable("") == []


def test_ignores_non_host_lines():
    assert parse_nmap_grepable("# just a comment\nnot a host line\n") == []

NMAP_XML_SAMPLE = """<?xml version="1.0"?>
<nmaprun scanner="nmap"><host><status state="up"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6" extrainfo="Ubuntu"/></port>
<port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
</ports></host><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>"""


def test_parses_machine_readable_xml_services():
    services = parse_nmap_xml(NMAP_XML_SAMPLE)
    # REQ-CORR-001: product_name/version are kept separate from the joined
    # `product` display string, so live CVE correlation gets a clean version
    # instead of having to re-parse it back out of the joined string.
    assert services == [{
        "port": 22,
        "protocol": "tcp",
        "service_name": "ssh",
        "product": "OpenSSH 9.6 Ubuntu",
        "product_name": "OpenSSH",
        "version": "9.6",
    }]
    assert nmap_xml_target_count(NMAP_XML_SAMPLE) == 1


def test_malformed_or_empty_xml_fails_truthfully():
    import pytest

    with pytest.raises(ValueError, match="nmap_xml_empty"):
        parse_nmap_xml("")
    with pytest.raises(ValueError, match="nmap_xml_malformed"):
        parse_nmap_xml("<nmaprun>")


# REQ-CIDRDISC-002/003: -sn (host-discovery-only) output.
NMAP_XML_SN_SAMPLE = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><status state="up"/><address addr="203.0.113.1" addrtype="ipv4"/></host>
<host><status state="down"/><address addr="203.0.113.2" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="203.0.113.3" addrtype="ipv4"/></host>
<runstats><hosts up="2" down="1" total="3"/></runstats>
</nmaprun>"""


def test_parse_live_hosts_returns_only_up_addresses():
    assert parse_nmap_xml_live_hosts(NMAP_XML_SN_SAMPLE) == ["203.0.113.1", "203.0.113.3"]


def test_parse_live_hosts_returns_empty_list_when_nothing_is_up():
    sample = (
        '<?xml version="1.0"?><nmaprun scanner="nmap">'
        '<host><status state="down"/><address addr="203.0.113.9" addrtype="ipv4"/></host>'
        '<runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>'
    )
    assert parse_nmap_xml_live_hosts(sample) == []


def test_parse_live_hosts_malformed_or_empty_xml_fails_truthfully():
    import pytest

    with pytest.raises(ValueError, match="nmap_xml_empty"):
        parse_nmap_xml_live_hosts("")
    with pytest.raises(ValueError, match="nmap_xml_malformed"):
        parse_nmap_xml_live_hosts("<nmaprun>")
