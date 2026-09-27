"""Parser fuer nmap Grepable-Output (-oG -). Bewusst als reine, DB-freie
Funktion gehalten, damit sie ohne Infra getestet werden kann.

Zeilenformat (Beispiel):
  Host: 10.0.0.5 ()  Ports: 21/open/tcp//ftp//vsftpd 2.3.4/, 22/open/tcp//ssh//OpenSSH 4.7p1//
"""

from __future__ import annotations

import xml.etree.ElementTree as ET


def parse_nmap_grepable(text: str) -> list[dict]:
    services: list[dict] = []
    for line in text.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        ports_part = line.split("Ports:", 1)[1].split("\tIgnored State:")[0]
        for entry in ports_part.split(","):
            fields = [f.strip() for f in entry.strip().split("/")]
            if len(fields) < 7:
                continue
            port, state, protocol, _owner, service_name, _rpc, version_desc = fields[:7]
            if state != "open":
                continue
            services.append({
                "port": int(port) if port.isdigit() else None,
                "protocol": protocol or "tcp",
                "service_name": service_name,
                "product": version_desc or service_name or "unknown",
            })
    return services


def parse_nmap_xml_port_states(text: str) -> list[dict]:
    """Parse every reported TCP/UDP port state from one complete XML document."""
    if not text.strip():
        raise ValueError("nmap_xml_empty")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("nmap_xml_malformed") from exc
    if root.tag != "nmaprun":
        raise ValueError("nmap_xml_root_invalid")

    rows: list[dict] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue
        for port_node in host.findall("./ports/port"):
            state_node = port_node.find("state")
            port_text = port_node.get("portid", "")
            if state_node is None or not port_text.isdigit():
                continue
            state = state_node.get("state", "unknown")
            if state not in {"open", "closed", "filtered", "open|filtered", "unfiltered"}:
                state = "unknown"
            service = port_node.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            # REQ-CORR-001: keep nmap's own product/version/extrainfo separate
            # (not just a joined display string) - live CVE correlation needs
            # a clean version to check against NVD's affected-version ranges,
            # and re-parsing the joined string later is strictly less reliable
            # than never discarding the structure nmap already gives us.
            product_name = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            extrainfo = service.get("extrainfo", "") if service is not None else ""
            product = " ".join(part.strip() for part in (product_name, version, extrainfo) if part and part.strip())
            rows.append({
                "port": int(port_text),
                "protocol": port_node.get("protocol", "tcp"),
                "state": state,
                "service_name": service_name,
                "product": product or service_name or "unknown",
                "product_name": product_name.strip() or None,
                "version": version.strip() or None,
            })
    return rows


def parse_nmap_xml(text: str) -> list[dict]:
    """Parse open services; malformed or empty XML raises truthfully."""
    return [
        {key: value for key, value in row.items() if key != "state"}
        for row in parse_nmap_xml_port_states(text)
        if row["state"] == "open"
    ]


def parse_nmap_xml_live_hosts(text: str) -> list[str]:
    """REQ-CIDRDISC-002/003: parse `-sn` (host-discovery-only) XML output into
    the IP addresses of hosts nmap reports up. No port/service data at all -
    this is a liveness sweep, not a scan."""
    if not text.strip():
        raise ValueError("nmap_xml_empty")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("nmap_xml_malformed") from exc
    if root.tag != "nmaprun":
        raise ValueError("nmap_xml_root_invalid")

    live: list[str] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = host.find("./address[@addrtype='ipv4']")
        if addr is None:
            addr = host.find("./address[@addrtype='ipv6']")
        addr_value = addr.get("addr") if addr is not None else None
        if addr_value:
            live.append(addr_value)
    return live


def nmap_xml_target_count(text: str) -> int:
    """Return Nmap runstats total-host count; malformed output raises."""
    if not text.strip():
        raise ValueError("nmap_xml_empty")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("nmap_xml_malformed") from exc
    hosts = root.find("./runstats/hosts")
    if hosts is None:
        raise ValueError("nmap_xml_host_stats_missing")
    try:
        return int(hosts.get("total", ""))
    except ValueError as exc:
        raise ValueError("nmap_xml_host_stats_invalid") from exc
