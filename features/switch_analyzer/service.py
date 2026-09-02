from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from features.configuration_studio.service import create_engine
from . import runtime_parser

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Global-command line patterns for DNS servers / domain name across the
# vendors this analyzer sees. These live outside the shared SwitchConfig
# model (which doesn't have dedicated DNS fields) so they're pulled
# straight out of the raw, uncategorized "global_commands" bucket that
# every switch parser already collects.
DNS_SERVER_PATTERNS = [
    re.compile(r"^ip name-server\s+(.+)$", re.IGNORECASE),
    re.compile(r"^dns\s+server\s+(\S+)", re.IGNORECASE),
    re.compile(r"^ip dns server-address\s+(\S+)", re.IGNORECASE),
]
DOMAIN_NAME_PATTERNS = [
    re.compile(r"^ip domain[- ]name\s+(\S+)", re.IGNORECASE),
    re.compile(r"^dns\s+domain\s+(\S+)", re.IGNORECASE),
]

# Light-touch SNMP line recognition. This intentionally does not try to
# fully model every vendor's SNMP grammar — it just pulls out the
# handful of fields worth surfacing on a dashboard, and always keeps
# the raw commands available for anyone who wants the full detail.
SNMP_PATTERNS = {
    "community": [
        re.compile(r"^snmp-server community (\S+)", re.IGNORECASE),
        re.compile(r"^snmp-agent community \S+ cipher \S+", re.IGNORECASE),
    ],
    "location": [
        re.compile(r"^snmp-server location\s+(.+)$", re.IGNORECASE),
        re.compile(r"^snmp-agent sys-info location\s+(.+)$", re.IGNORECASE),
    ],
    "contact": [
        re.compile(r"^snmp-server contact\s+(.+)$", re.IGNORECASE),
        re.compile(r"^snmp-agent sys-info contact\s+(.+)$", re.IGNORECASE),
    ],
    "host": [
        re.compile(r"^snmp-server host\s+(\S+)", re.IGNORECASE),
        re.compile(r"^snmp-agent target-host trap address udp-domain\s+(\S+)", re.IGNORECASE),
    ],
}


def analyze(text: str, *, filename: str = "pasted-switch-config.txt", vendor: str = "Auto Detect") -> dict[str, Any]:
    """Parse a switch configuration and return an analyzer-friendly summary.

    Reuses the same Cisco/Huawei/Aruba switch parsers that power
    Configuration Studio's conversion engine — this module is read-only
    analysis, not conversion, so no target vendor is involved.
    """
    engine = create_engine()

    tmp_dir = Path("/tmp") if Path("/tmp").exists() else Path.cwd()
    tmp_path = tmp_dir / f"switch-analyzer-{abs(hash(text)) % (10 ** 8)}-{Path(filename).name}"
    tmp_path.write_text(text, encoding="utf-8")

    try:
        config = engine.parse(
            tmp_path,
            source_vendor=vendor,
            source_device_type="Switch",
        )
    finally:
        tmp_path.unlink(missing_ok=True)

    detected_vendor = str(getattr(config, "source_vendor", "") or vendor)

    lines = text.splitlines()
    interface_brief = runtime_parser.parse_interface_brief(lines)
    if detected_vendor.lower() == "huawei":
        interface_brief = _normalize_huawei_brief_keys(interface_brief)
    neighbors = runtime_parser.parse_neighbors(lines)
    port_channels = runtime_parser.parse_port_channels(lines)
    os_version = runtime_parser.parse_version(lines)
    routing_table = runtime_parser.parse_ip_route_table(lines)
    arp_table = runtime_parser.parse_arp_table(lines)

    interfaces = _build_interfaces(config, interface_brief)
    routes = _build_routes(config)
    vlans = _build_vlans(config)
    dns = _extract_dns(config)
    snmp = _extract_snmp(config)

    up_count = sum(1 for item in interfaces if item["status"] == "up")
    down_count = sum(1 for item in interfaces if item["status"] == "down")

    return {
        "hostname": config.hostname or Path(filename).stem,
        "vendor": detected_vendor,
        "device_type": getattr(config, "source_device_type", "Switch"),
        "os_version": os_version,
        "interfaces": interfaces,
        "routes": routes,
        "routing_table": routing_table,
        "arp_table": arp_table,
        "neighbors": neighbors,
        "port_channels": port_channels,
        "vlans": vlans,
        "dns": dns,
        "snmp": snmp,
        "routing_protocols": _routing_protocol_summary(config),
        "spanning_tree_commands": list(getattr(config, "spanning_tree_commands", [])),
        "ntp_commands": list(getattr(config, "ntp_commands", [])),
        "aaa_commands": list(getattr(config, "aaa_commands", [])),
        "logging_commands": list(getattr(config, "logging_commands", [])),
        "cards": {
            "total_interfaces": len(interfaces),
            "interfaces_up": up_count,
            "interfaces_down": down_count,
            "total_vlans": len(vlans),
            "total_routes": len(routes),
            "dns_servers": len(dns["servers"]),
            "neighbor_count": len(neighbors),
            "port_channel_count": len(port_channels),
            "arp_entries": len(arp_table),
        },
    }


def _normalize_huawei_brief_keys(interface_brief: dict[str, dict]) -> dict[str, dict]:
    from features.configuration_studio.converter_engine.parsers.switch.huawei import HuaweiSwitchParser
    return {
        HuaweiSwitchParser.normalize_interface_name(name): value
        for name, value in interface_brief.items()
    }


def _build_interfaces(config, interface_brief: dict[str, dict] | None = None) -> list[dict[str, Any]]:
    interface_brief = interface_brief or {}
    results = []
    for item in getattr(config, "interfaces", []):
        vlan = item.access_vlan if item.access_vlan is not None else item.native_vlan
        brief = interface_brief.get(item.name) or interface_brief.get(item.name.lower()) or {}
        # "show ip interface brief" / "display ip interface brief" reports
        # the actual line/protocol state — more authoritative than just
        # inferring "up" from the absence of a "shutdown" config line.
        status = brief.get("status") or ("down" if item.shutdown else "up")
        if status == "administratively down":
            status = "down"
        results.append({
            "name": item.name,
            "status": status,
            "protocol": brief.get("protocol", ""),
            "mode": item.mode or "",
            "vlan": vlan if vlan is not None else "",
            "ip_address": item.ip_address or brief.get("ip_address", ""),
            "description": item.description or "",
            "port_security": "Enabled" if item.port_security_enabled else "",
            "source": "show/display" if brief else "config",
        })

    # Interfaces that only appear in the runtime brief (e.g. sub-interfaces
    # or ports with no config block at all) still deserve a row.
    existing_names = {item["name"].lower() for item in results}
    for name, brief in interface_brief.items():
        if name.lower() in existing_names:
            continue
        status = brief.get("status", "")
        results.append({
            "name": name,
            "status": "down" if status == "administratively down" else status,
            "protocol": brief.get("protocol", ""),
            "mode": "",
            "vlan": "",
            "ip_address": brief.get("ip_address", ""),
            "description": "",
            "port_security": "",
            "source": "show/display",
        })

    return results


def _build_routes(config) -> list[dict[str, Any]]:
    results = []
    for route in getattr(config, "routes", []):
        results.append({
            "destination": route.destination,
            "mask": route.mask,
            "next_hop": route.next_hop,
            "distance": route.distance if route.distance is not None else "",
        })
    return results


def _build_vlans(config) -> list[dict[str, Any]]:
    results = []
    for vlan in getattr(config, "vlans", []):
        results.append({"vlan_id": vlan.vlan_id, "name": vlan.name})
    return results


def _routing_protocol_summary(config) -> dict[str, list[str]]:
    return {
        "ospf": list(getattr(config, "ospf_commands", [])),
        "eigrp": list(getattr(config, "eigrp_commands", [])),
        "default_gateway": getattr(config, "default_gateway", "") or "",
    }


def _extract_dns(config) -> dict[str, Any]:
    servers: list[str] = []
    domain = ""

    for line in getattr(config, "global_commands", []):
        text = str(line).strip()

        for pattern in DNS_SERVER_PATTERNS:
            match = pattern.match(text)
            if match:
                for token in match.group(1).split():
                    if IPV4_RE.match(token) and token not in servers:
                        servers.append(token)
                break

        for pattern in DOMAIN_NAME_PATTERNS:
            match = pattern.match(text)
            if match and not domain:
                domain = match.group(1)
                break

    return {"servers": servers, "domain": domain}


def _extract_snmp(config) -> dict[str, Any]:
    commands = list(getattr(config, "snmp_commands", []))
    summary = {"communities": [], "locations": [], "contacts": [], "hosts": []}

    for line in commands:
        text = str(line).strip()

        for pattern in SNMP_PATTERNS["community"]:
            match = pattern.match(text)
            if match and match.groups() and match.group(1) not in summary["communities"]:
                summary["communities"].append(match.group(1))

        for pattern in SNMP_PATTERNS["location"]:
            match = pattern.match(text)
            if match and match.group(1) not in summary["locations"]:
                summary["locations"].append(match.group(1))

        for pattern in SNMP_PATTERNS["contact"]:
            match = pattern.match(text)
            if match and match.group(1) not in summary["contacts"]:
                summary["contacts"].append(match.group(1))

        for pattern in SNMP_PATTERNS["host"]:
            match = pattern.match(text)
            if match and match.group(1) not in summary["hosts"]:
                summary["hosts"].append(match.group(1))

    return {
        "enabled": bool(commands),
        "summary": summary,
        "raw_commands": commands,
    }
