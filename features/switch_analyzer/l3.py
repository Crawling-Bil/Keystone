"""Layer-3 view of one switch capture: gateways, static routes, OSPF, ACLs.

Everything here is read from the capture's own text (the running-config and
the ``show ip route`` / ``display ip routing-table`` / ``show access-list`` /
``display acl all`` outputs), vendor by vendor, so a Cisco switch and its
Huawei replacement can be put side by side (see ``compare.l3_compare``).

What it returns (``result["l3"]``)::

    interfaces      every interface that has an IPv4 address (SVI, routed port,
                    loopback, management): address, state, helper addresses,
                    ACL / traffic-policy bound, OSPF area
    default_routes  ``ip route 0.0.0.0 0.0.0.0``, ``ip route-static 0.0.0.0 ...``
                    and the L2-switch ``ip default-gateway``
    static_routes   every static route, once (a capture that echoes the route
                    lines three times still has one route)
    routing_table   how many routes the device's own table printed, by protocol
    ospf            processes (router-id, networks, passive interfaces,
                    redistribution) and the interfaces that actually run OSPF,
                    with findings such as "configured but no interface enabled"
    other_protocols EIGRP / BGP / RIP / IS-IS headers found in the config
    acls            definitions (name, rules), where each one is applied, and
                    the number of ACLs the device itself reported
    findings        things worth reading first

OSPF participation follows the vendors' own rules: Cisco / Nexus enable OSPF on
an interface either with ``network <addr> <wildcard> area <a>`` (the interface
address must fall inside the range) or with ``ip ospf <pid> area <a>`` /
``ip router ospf <pid> area <a>`` on the interface; Huawei with ``network``
inside ``area <a>`` or ``ospf enable <pid> area <a>`` on the interface. A
``router ospf`` that has neither forms no neighbour and advertises nothing.

Only IPv4 is read. HSRP / VRRP virtual addresses are taken from the interface
rows the analyzer already built, not parsed again here.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_IPV4_RE = re.compile(rf"^{_IPV4}$")
_IFACE_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z\-]*\d[\w/.:\-]*$")

# --------------------------------------------------------------------------
# Statements
# --------------------------------------------------------------------------


def _statements(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Top-level statements of a configuration dump: a column-0 line and the
    indented lines under it. A blank line, a prompt, ``!`` or ``#`` ends one."""
    out: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            current = None
            continue
        if line[0] in " \t":
            if current is not None:
                current[1].append(line)
            continue
        current = (line.strip(), [])
        out.append(current)
    return out


def _is_ip(token: str) -> bool:
    if not _IPV4_RE.match(token):
        return False
    return all(int(part) <= 255 for part in token.split("."))


def _prefix_from(token: str) -> int | None:
    """Prefix length from a dotted netmask or a plain number."""
    if _is_ip(token):
        try:
            return ipaddress.IPv4Network(f"0.0.0.0/{token}").prefixlen
        except ValueError:
            return None
    if token.isdigit() and 0 <= int(token) <= 32:
        return int(token)
    return None


def _network(ip: str, prefix: int) -> str:
    try:
        return str(ipaddress.IPv4Interface(f"{ip}/{prefix}").network)
    except ValueError:
        return ""


# --------------------------------------------------------------------------
# Interface names
# --------------------------------------------------------------------------

_IF_PREFIXES = [
    ("tengigabitethernet", "te"), ("twentyfivegige", "twe"), ("fortygigabitethernet", "fo"),
    ("hundredgige", "hu"), ("gigabitethernet", "gi"), ("fastethernet", "fa"),
    ("port-channel", "po"), ("eth-trunk", "po"), ("vlanif", "vlan"), ("loopback", "lo"),
    ("ethernet", "eth"), ("tunnel", "tu"), ("gig", "gi"), ("ten", "te"),
]


def ifkey(name: str) -> str:
    """One comparable key per interface: ``GigabitEthernet0/1`` = ``Gi0/1`` =
    ``gi0/1``; ``Vlanif53`` = ``Vlan53``; ``Eth-Trunk1`` = ``Port-channel1``."""
    text = (name or "").strip().lower()
    match = re.match(r"^([a-z][a-z\-]*)\s*(\d.*)$", text)
    if not match:
        return text
    prefix, rest = match.groups()
    for long_name, short in _IF_PREFIXES:
        if prefix == long_name or prefix == short:
            return f"{short}{rest}"
    return f"{prefix}{rest}"


def _interface_kind(name: str) -> tuple[str, int | None]:
    text = name.strip()
    low = text.lower()
    svi = re.match(r"^(?:vlan|vlanif)\s*(\d+)$", low)
    if svi:
        return "SVI", int(svi.group(1))
    if low.startswith(("loopback", "lo")) and re.match(r"^(loopback|lo)\d", low):
        return "Loopback", None
    if low.startswith(("mgmt", "meth", "management")) or low == "fastethernet0":
        return "Management", None
    if low.startswith(("port-channel", "eth-trunk", "po")) and re.match(r"^(port-channel|eth-trunk|po)\d", low):
        return ("Sub-interface" if "." in low else "Port-channel"), None
    if "." in low and re.search(r"\d\.\d", low):
        return "Sub-interface", None
    if low.startswith("tunnel"):
        return "Tunnel", None
    return "Routed port", None


# --------------------------------------------------------------------------
# Interfaces
# --------------------------------------------------------------------------

_VRF_CHILD_RE = re.compile(
    r"^(?:ip\s+)?vrf\s+(?:forwarding|member)\s+(\S+)$|^ip\s+binding\s+vpn-instance\s+(\S+)$", re.IGNORECASE
)


def _parse_address(tokens: list[str]) -> dict[str, Any] | None:
    """``ip address ...`` tokens after the keyword pair, any vendor."""
    if not tokens:
        return None
    first = tokens[0].lower()
    if first in {"dhcp", "dhcp-alloc", "dhcp-bootp", "negotiated"}:
        return {"source": "dhcp", "ip": "", "prefix_len": None, "secondary": False}
    if first == "unnumbered":
        return {"source": "unnumbered", "ip": "", "prefix_len": None, "secondary": False}
    prefix: int | None = None
    ip = ""
    rest = tokens[1:]
    if "/" in tokens[0]:
        ip, _, length = tokens[0].partition("/")
        prefix = _prefix_from(length) if length.isdigit() else None
    else:
        ip = tokens[0]
        if rest:
            prefix = _prefix_from(rest[0])
            rest = rest[1:]
    if not _is_ip(ip) or prefix is None:
        return None
    secondary = any(token.lower() in {"secondary", "sub"} for token in rest)
    return {"source": "static", "ip": ip, "prefix_len": prefix, "secondary": secondary}


def _parse_interface_block(name: str, children: list[str]) -> dict[str, Any]:
    kind, vlan_id = _interface_kind(name)
    entry: dict[str, Any] = {
        "name": name, "key": ifkey(name), "kind": kind, "vlan_id": vlan_id,
        "ip": "", "prefix_len": None, "network": "", "address_source": "",
        "secondary": [], "description": "", "shutdown": False, "vrf": "",
        "helpers": [], "acl_in": "", "acl_out": "", "traffic_policies": [], "traffic_filters": [],
        "ospf": None,
    }
    ospf: dict[str, Any] = {}
    for raw in children:
        line = raw.strip()
        low = line.lower()
        if low.startswith("description "):
            entry["description"] = line[len("description "):].strip()
        elif low == "shutdown":
            entry["shutdown"] = True
        elif low == "no shutdown":
            entry["shutdown"] = False
        elif low.startswith("ip address "):
            address = _parse_address(line.split()[2:])
            if address is None:
                continue
            if address["source"] != "static":
                entry["address_source"] = address["source"]
            elif address["secondary"]:
                entry["secondary"].append(f"{address['ip']}/{address['prefix_len']}")
            else:
                entry["ip"], entry["prefix_len"] = address["ip"], address["prefix_len"]
                entry["address_source"] = "static"
        elif low == "no ip address":
            entry["ip"], entry["prefix_len"], entry["address_source"] = "", None, ""
        else:
            vrf = _VRF_CHILD_RE.match(line)
            if vrf:
                entry["vrf"] = vrf.group(1) or vrf.group(2) or ""
                continue
            helper = re.match(rf"^(?:ip helper-address|dhcp relay server-ip)\s+(?:global\s+)?({_IPV4})", line, re.IGNORECASE)
            if helper:
                entry["helpers"].append(helper.group(1))
                continue
            access = re.match(r"^ip access-group\s+(\S+)\s+(in|out)\b", line, re.IGNORECASE)
            if access:
                entry["acl_in" if access.group(2).lower() == "in" else "acl_out"] = access.group(1)
                continue
            policy = re.match(r"^traffic-policy\s+(\S+)\s+(inbound|outbound)\b", line, re.IGNORECASE)
            if policy:
                entry["traffic_policies"].append({"policy": policy.group(1), "direction": policy.group(2).lower()})
                continue
            tfilter = re.match(r"^traffic-filter\s+(inbound|outbound)\s+(?:ipv6\s+)?acl\s+(?:name\s+)?(\S+)", line, re.IGNORECASE)
            if tfilter:
                entry["traffic_filters"].append({"acl": tfilter.group(2), "direction": tfilter.group(1).lower()})
                continue
            # OSPF on the interface (Cisco, Nexus, Huawei)
            enable = re.match(r"^(?:ip ospf|ip router ospf|ospf enable)\s+(\S+)\s+area\s+(\S+)", line, re.IGNORECASE)
            if enable:
                ospf["process"], ospf["area"] = enable.group(1), enable.group(2)
                continue
            aruba_area = re.match(r"^ip ospf area\s+(\S+)", line, re.IGNORECASE)
            if aruba_area:
                ospf["process"], ospf["area"] = "", aruba_area.group(1)
                continue
            net_type = re.match(r"^(?:ip ospf network|ospf network-type)\s+(.+)$", line, re.IGNORECASE)
            if net_type:
                ospf["network_type"] = net_type.group(1).strip()
                continue
            cost = re.match(r"^(?:ip ospf cost|ospf cost)\s+(\d+)", line, re.IGNORECASE)
            if cost:
                ospf["cost"] = int(cost.group(1))
    if entry["ip"] and entry["prefix_len"] is not None:
        entry["network"] = _network(entry["ip"], entry["prefix_len"])
    if "area" in ospf:
        entry["ospf"] = ospf
    elif ospf:
        entry["ospf_settings"] = ospf
    return entry


def _merge_interface(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """The same interface printed twice (a capture that also ran
    ``show run interface X``): keep what either copy says."""
    merged = dict(old)
    for key, value in new.items():
        if key in {"helpers"}:
            merged[key] = list(dict.fromkeys(list(old.get(key) or []) + list(value or [])))
        elif key in {"secondary"}:
            merged[key] = list(dict.fromkeys(list(old.get(key) or []) + list(value or [])))
        elif key in {"traffic_policies", "traffic_filters"}:
            merged[key] = list(old.get(key) or []) + [item for item in (value or []) if item not in (old.get(key) or [])]
        elif key == "shutdown":
            merged[key] = bool(old.get(key)) or bool(value)
        elif value in ("", None, [], {}):
            continue
        else:
            merged[key] = value
    return merged


def _parse_interfaces(statements: list[tuple[str, list[str]]], vendor: str) -> list[dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for header, children in statements:
        name = ""
        match = re.match(r"^interface\s+(\S+)\s*$", header, re.IGNORECASE) or re.match(r"^interface\s+((?:vlan|loopback|lag)\s+\d+)\s*$", header, re.IGNORECASE)
        if match:
            name = re.sub(r"\s+", "", match.group(1)) if " " in match.group(1) else match.group(1)    # AOS-CX writes "interface vlan 130"
        elif vendor.lower() == "aruba":
            vlan = re.match(r"^vlan\s+(\d+)\s*$", header, re.IGNORECASE)
            if vlan and any(child.strip().lower().startswith("ip address ") for child in children):
                name = f"Vlan{vlan.group(1)}"
        if not name:
            continue
        entry = _parse_interface_block(name, children)
        key = entry["key"]
        if key in found:
            found[key] = _merge_interface(found[key], entry)
        else:
            found[key] = entry
            order.append(key)
    rows = [found[key] for key in order]
    return [row for row in rows if row["ip"] or row["address_source"] or row["secondary"]]


# --------------------------------------------------------------------------
# Static routes
# --------------------------------------------------------------------------

_ROUTE_KEYWORDS = {"permanent", "multicast", "global", "inherit-cost", "no-advertise", "bfd"}


def _route_row(vrf: str, dest: str, prefix: int, tokens: list[str], vendor_style: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        "vrf": vrf, "destination": dest, "prefix_len": prefix, "cidr": f"{dest}/{prefix}",
        "next_hop": "", "interface": "", "distance": None, "tag": "", "track": "",
        "description": "", "permanent": False, "discard": False,
    }
    i = 0
    while i < len(tokens):
        token = tokens[i]
        low = token.lower()
        if _is_ip(token) and not row["next_hop"]:
            row["next_hop"] = token
        elif low in {"name", "description"} and i + 1 < len(tokens):
            row["description"] = " ".join(tokens[i + 1:]) if low == "description" else tokens[i + 1]
            if low == "description":
                break
            i += 1
        elif low in {"preference", "distance"} and i + 1 < len(tokens) and tokens[i + 1].isdigit():
            row["distance"] = int(tokens[i + 1])
            i += 1
        elif low == "tag" and i + 1 < len(tokens):
            row["tag"] = tokens[i + 1]
            i += 1
        elif low == "track" and i + 1 < len(tokens):
            row["track"] = tokens[i + 1]
            i += 1
            # Huawei "track nqa admin test"
            while i + 1 < len(tokens) and tokens[i + 1].lower() not in {"preference", "tag", "description"} and vendor_style == "huawei":
                row["track"] += " " + tokens[i + 1]
                i += 1
        elif low == "permanent":
            row["permanent"] = True
        elif low in {"null0", "blackhole", "reject"}:
            row["discard"] = True
            row["interface"] = "Null0" if low == "null0" else low
        elif token.isdigit() and row["distance"] is None and vendor_style in {"ios", "nxos", "aruba"}:
            row["distance"] = int(token)
        elif _IFACE_TOKEN_RE.match(token) and not row["interface"]:
            row["interface"] = token
        elif low in _ROUTE_KEYWORDS:
            pass
        i += 1
    return row


def _parse_ios_route(rest: list[str], vrf: str) -> dict[str, Any] | None:
    """Cisco IOS / Aruba: ``DEST MASK ...`` or ``DEST/LEN ...``; Nexus ``DEST/LEN ...``."""
    if not rest:
        return None
    if "/" in rest[0]:
        dest, _, length = rest[0].partition("/")
        prefix = _prefix_from(length) if length.isdigit() else None
        tail = rest[1:]
    else:
        dest = rest[0]
        prefix = _prefix_from(rest[1]) if len(rest) > 1 else None
        tail = rest[2:]
    if not _is_ip(dest) or prefix is None:
        return None
    return _route_row(vrf, str(ipaddress.IPv4Network(f"{dest}/{prefix}", strict=False).network_address), prefix, tail, "ios")


def _parse_huawei_route(rest: list[str]) -> dict[str, Any] | None:
    vrf = ""
    if len(rest) >= 2 and rest[0].lower() == "vpn-instance":
        vrf, rest = rest[1], rest[2:]
    if len(rest) < 2:
        return None
    dest = rest[0]
    prefix = _prefix_from(rest[1])
    if not _is_ip(dest) or prefix is None:
        return None
    return _route_row(vrf, str(ipaddress.IPv4Network(f"{dest}/{prefix}", strict=False).network_address), prefix, rest[2:], "huawei")


def _parse_static_routes(statements: list[tuple[str, list[str]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(static routes, ip default-gateway entries); each once."""
    routes: list[dict[str, Any]] = []
    gateways: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    gw_seen: set[str] = set()

    def add(row: dict[str, Any] | None, via: str) -> None:
        if row is None:
            return
        row["via"] = via
        key = (row["vrf"], row["cidr"], row["next_hop"], row["interface"])
        if key in seen:
            # The same route printed again: keep the copy that says more.
            existing = next(r for r in routes if (r["vrf"], r["cidr"], r["next_hop"], r["interface"]) == key)
            for field in ("distance", "tag", "track", "description"):
                if existing[field] in ("", None) and row[field] not in ("", None):
                    existing[field] = row[field]
            return
        seen.add(key)
        routes.append(row)

    for header, children in statements:
        low = header.lower()
        if low.startswith("ip route-static "):
            add(_parse_huawei_route(header.split()[2:]), "ip route-static")
        elif low.startswith("ip route "):
            tokens = header.split()[2:]
            vrf = ""
            if len(tokens) >= 2 and tokens[0].lower() == "vrf":
                vrf, tokens = tokens[1], tokens[2:]
            add(_parse_ios_route(tokens, vrf), "ip route")
        elif low.startswith("vrf context "):
            vrf_name = header.split(None, 2)[2].strip()
            for child in children:
                text = child.strip()
                if text.lower().startswith("ip route "):
                    add(_parse_ios_route(text.split()[2:], vrf_name), "ip route")
        elif low.startswith("ip default-gateway "):
            token = header.split()[2] if len(header.split()) > 2 else ""
            if _is_ip(token) and token not in gw_seen:
                gw_seen.add(token)
                gateways.append({"next_hop": token, "via": "ip default-gateway"})
    return routes, gateways


# --------------------------------------------------------------------------
# Device-printed routing table
# --------------------------------------------------------------------------

_PROTOCOL_GROUPS = [
    ("Connected", {"c", "direct"}),
    ("Local", {"l", "local"}),
    ("Static", {"s", "s*", "static", "rip-static"}),
    ("OSPF", {"o", "o*", "ia", "n1", "n2", "e1", "e2", "o_ase", "o_nssa", "ospf", "o*e2", "o*ia"}),
    ("EIGRP", {"d", "d*", "ex", "eigrp"}),
    ("BGP", {"b", "b*", "bgp", "ibgp", "ebgp"}),
    ("RIP", {"r", "rip"}),
    ("IS-IS", {"i", "su", "l1", "l2", "ia", "isis", "is-is"}),
    ("FHRP", {"hsrp", "vrrp", "glbp"}),   # NX-OS: the virtual-IP /32 a first-hop redundancy protocol installs
]


def _protocol_group(label: str) -> str:
    low = (label or "").strip().lower()
    # NX-OS names the routing process after the protocol: "ospf-1", "eigrp-100", "bgp-65000", "isis-core"
    process = re.fullmatch(r"([a-z]+)-[\w.]+", low)
    candidates = [low] + ([process.group(1)] if process and process.group(1) != "is" else [])
    for candidate in candidates:
        for group, members in _PROTOCOL_GROUPS:
            if candidate in members:
                return group
    if low.startswith("o"):
        return "OSPF"
    return "Other" if low else ""


protocol_group = _protocol_group   # public name: service.py tags every routing-table row with it


def _routing_table_summary(routing_table: list[dict[str, Any]], clean: list[str]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for row in routing_table:
        group = _protocol_group(row.get("protocol", ""))
        if group:
            counts[group] = counts.get(group, 0) + 1
    last_resort = ""
    last_resort_seen = False
    for line in clean:
        match = re.search(rf"Gateway of last resort is\s+(?:({_IPV4})|(not set))", line, re.IGNORECASE)
        if match:
            last_resort_seen = True
            last_resort = match.group(1) or ""
    if not last_resort_seen:
        # NX-OS prints no "Gateway of last resort" line; the default route of the default VRF says the same thing
        default = next((row for row in routing_table if row.get("destination") == "0.0.0.0/0" and row.get("vrf", "default") in ("default", "")
                        and row.get("next_hop")), None)
        if default:
            last_resort, last_resort_seen = default["next_hop"], True
    return {
        "captured": bool(routing_table),
        "total": len(routing_table),
        "by_protocol": counts,
        "gateway_of_last_resort": last_resort,
        "gateway_of_last_resort_seen": last_resort_seen,
    }


# --------------------------------------------------------------------------
# OSPF
# --------------------------------------------------------------------------

_OSPF_HEADER_CISCO = re.compile(r"^router ospf(?:\s+(\S+?))?(?:\s+vrf\s+(\S+))?\s*$", re.IGNORECASE)
_OSPF_HEADER_HUAWEI = re.compile(r"^ospf(?:\s+(\d+))?(?:\s+router-id\s+(\S+))?(?:\s+vpn-instance\s+(\S+))?\s*$", re.IGNORECASE)
_OSPF_NOISE = {"log-adjacency-changes", "nsf", "ispf"}


def _wildcard_matches(ip: str, network: str, wildcard: str) -> bool:
    try:
        ip_i = int(ipaddress.IPv4Address(ip))
        net_i = int(ipaddress.IPv4Address(network))
        wild_i = int(ipaddress.IPv4Address(wildcard))
    except ValueError:
        return False
    mask = ~wild_i & 0xFFFFFFFF
    return (ip_i & mask) == (net_i & mask)


def _wildcard_to_cidr(network: str, wildcard: str) -> str:
    try:
        wild_i = int(ipaddress.IPv4Address(wildcard))
        if wild_i & (wild_i + 1):
            return f"{network} {wildcard}"
        prefix = 32 - wild_i.bit_length()
        return str(ipaddress.IPv4Network(f"{network}/{prefix}", strict=False))
    except ValueError:
        return f"{network} {wildcard}"


def _parse_ospf_process(header: str, children: list[str]) -> dict[str, Any] | None:
    huawei = _OSPF_HEADER_HUAWEI.match(header)
    cisco = _OSPF_HEADER_CISCO.match(header)
    if cisco and not huawei:
        process = {"id": cisco.group(1) or "", "vrf": cisco.group(2) or "", "router_id": ""}
        style = "cisco"
    elif huawei:
        process = {"id": huawei.group(1) or "1", "vrf": huawei.group(3) or "", "router_id": huawei.group(2) or ""}
        style = "huawei"
    else:
        return None
    process.update({
        "networks": [], "passive_default": False, "passive_interfaces": [], "active_interfaces": [],
        "redistribute": [], "default_information": "", "reference_bandwidth": "", "other": [],
    })
    area = ""
    for raw in children:
        line = raw.strip()
        low = line.lower()
        if not line or low in _OSPF_NOISE:
            continue
        if low.startswith("router-id "):
            process["router_id"] = line.split(None, 1)[1].strip()
        elif low == "passive-interface default" or low == "silent-interface all":
            process["passive_default"] = True
        elif low.startswith(("passive-interface ", "silent-interface ")) and not low.startswith("no "):
            process["passive_interfaces"].append(line.split(None, 1)[1].strip())
        elif low.startswith(("no passive-interface ", "undo silent-interface ")):
            process["active_interfaces"].append(line.split()[-1].strip())
        elif low.startswith(("redistribute ", "import-route ")):
            process["redistribute"].append(line.split(None, 1)[1].strip())
        elif low.startswith(("default-information originate", "default-route-advertise")):
            process["default_information"] = line
        elif low.startswith(("auto-cost reference-bandwidth", "bandwidth-reference")):
            process["reference_bandwidth"] = line.split()[-1]
        elif low.startswith("area ") and style == "huawei":
            area = line.split()[1]
        elif low.startswith("network "):
            parts = line.split()
            if len(parts) >= 5 and parts[3].lower() == "area" and _is_ip(parts[1]) and _is_ip(parts[2]):
                process["networks"].append({"network": parts[1], "wildcard": parts[2], "area": parts[4]})
            elif len(parts) >= 3 and _is_ip(parts[1]) and _is_ip(parts[2]) and area:
                process["networks"].append({"network": parts[1], "wildcard": parts[2], "area": area})
            else:
                process["other"].append(line)
        else:
            process["other"].append(line)
    return process


def _merge_ospf_process(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """The same process printed twice (the full config, then a filtered echo)."""
    merged = dict(old)
    for key, value in new.items():
        if isinstance(value, list):
            merged[key] = list(old.get(key) or [])
            for item in value:
                if item not in merged[key]:
                    merged[key].append(item)
        elif isinstance(value, bool):
            merged[key] = bool(old.get(key)) or value
        elif value:
            merged[key] = value
    return merged


def _parse_ospf(statements: list[tuple[str, list[str]]], interfaces: list[dict[str, Any]]) -> dict[str, Any]:
    processes: dict[tuple[str, str], dict[str, Any]] = {}
    for header, children in statements:
        process = _parse_ospf_process(header, children)
        if process is None:
            continue
        key = (process["id"], process["vrf"])
        processes[key] = _merge_ospf_process(processes[key], process) if key in processes else process
    process_list = list(processes.values())
    participating: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []

    def passive_state(process: dict[str, Any], name: str) -> bool:
        key = ifkey(name)
        if key in {ifkey(item) for item in process["passive_interfaces"]}:
            return True
        if process["passive_default"]:
            return key not in {ifkey(item) for item in process["active_interfaces"]}
        return False

    for iface in interfaces:
        if not iface["ip"]:
            continue
        explicit = iface.get("ospf")
        chosen: dict[str, Any] | None = None
        how = ""
        area = ""
        if explicit:
            wanted = explicit.get("process", "")
            chosen = next((p for p in process_list if (not wanted or p["id"] == wanted) and p["vrf"] == iface["vrf"]), None)
            chosen = chosen or next((p for p in process_list if not wanted or p["id"] == wanted), None)
            area = explicit["area"]
            how = "interface command"
        else:
            best: tuple[int, dict[str, Any], str] | None = None
            for process in process_list:
                if process["vrf"] != iface["vrf"]:
                    continue
                for net in process["networks"]:
                    if _wildcard_matches(iface["ip"], net["network"], net["wildcard"]):
                        specificity = bin(int(ipaddress.IPv4Address(net["wildcard"]))).count("1")
                        if best is None or specificity < best[0]:
                            best = (specificity, process, net["area"])
            if best is not None:
                chosen, area, how = best[1], best[2], "network statement"
        if chosen is None and explicit is None:
            continue
        passive = passive_state(chosen, iface["name"]) if chosen else False
        participating.append({
            "interface": iface["name"], "ip": f"{iface['ip']}/{iface['prefix_len']}", "network": iface["network"],
            "process": chosen["id"] if chosen else (explicit or {}).get("process", ""),
            "area": area, "how": how, "passive": passive, "shutdown": iface["shutdown"],
            "network_type": (explicit or {}).get("network_type", "") or iface.get("ospf_settings", {}).get("network_type", ""),
            "cost": (explicit or {}).get("cost") or iface.get("ospf_settings", {}).get("cost") or "",
        })
        iface["ospf_area"] = area
    for process in process_list:
        mine = [row for row in participating if row["process"] == process["id"]]
        if not mine and not process["networks"]:
            findings.append({
                "level": "warning", "code": "ospf_no_interfaces",
                "text": (
                    f"OSPF process {process['id'] or '(default)'} is configured but no interface runs it: no network "
                    "statement and no interface-level area command. It forms no neighbour and advertises nothing."
                ),
            })
        elif not mine:
            findings.append({
                "level": "warning", "code": "ospf_network_matches_nothing",
                "text": (
                    f"OSPF process {process['id'] or '(default)'} has network statements, but none matches the IP address "
                    "of an interface on this device."
                ),
            })
        elif all(row["passive"] for row in mine):
            findings.append({
                "level": "warning", "code": "ospf_all_passive",
                "text": (
                    f"Every interface in OSPF process {process['id'] or '(default)'} is passive: prefixes are advertised "
                    "but no neighbour can form on this device."
                ),
            })
        process["interface_count"] = len(mine)
        process["areas"] = sorted({row["area"] for row in mine} | {net["area"] for net in process["networks"]})
        for net in process["networks"]:
            net["cidr"] = _wildcard_to_cidr(net["network"], net["wildcard"])
            net["matched_interfaces"] = [
                iface["name"] for iface in interfaces
                if iface["ip"] and iface["vrf"] == process["vrf"] and _wildcard_matches(iface["ip"], net["network"], net["wildcard"])
            ]
    return {
        "configured": bool(process_list),
        "processes": process_list,
        "interfaces": participating,
        "findings": findings,
    }


_OTHER_PROTOCOL_HEADERS = [
    ("EIGRP", re.compile(r"^router eigrp\s+(\S+)", re.IGNORECASE)),
    ("BGP", re.compile(r"^router bgp\s+(\S+)", re.IGNORECASE)),
    ("BGP", re.compile(r"^bgp\s+(\d+)\s*$", re.IGNORECASE)),
    ("RIP", re.compile(r"^router rip\b\s*(\S*)", re.IGNORECASE)),
    ("RIP", re.compile(r"^rip\s+(\d+)\s*$", re.IGNORECASE)),
    ("IS-IS", re.compile(r"^router isis\b\s*(\S*)", re.IGNORECASE)),
    ("IS-IS", re.compile(r"^isis\s+(\d+)\s*$", re.IGNORECASE)),
]


def _parse_other_protocols(statements: list[tuple[str, list[str]]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for header, children in statements:
        for protocol, pattern in _OTHER_PROTOCOL_HEADERS:
            match = pattern.match(header)
            if match and (protocol, match.group(1)) not in seen:
                seen.add((protocol, match.group(1)))
                out.append({"protocol": protocol, "process": match.group(1), "lines": [header] + [c.strip() for c in children]})
    return out


# --------------------------------------------------------------------------
# ACLs
# --------------------------------------------------------------------------

_CISCO_ACL_HEADER = re.compile(r"^(ip|ipv6|mac)\s+access-list\s+(?:(extended|standard)\s+)?(\S+)\s*$", re.IGNORECASE)
_HUAWEI_ACL_HEADER = re.compile(r"^acl\s+(?:(ipv6|mac)\s+)?(?:(number)\s+(\d+)|(name)\s+(\S+))(?:\s+(.*))?$", re.IGNORECASE)
_RULE_RE = re.compile(r"^(?:\d+\s+)?(permit|deny)\b", re.IGNORECASE)


_SYSTEM_ACL_RE = re.compile(r"^(?:AutoQos-|copp-system-|CISCO-CWA-|preauth_ipv|implicit_|CMP-NAT)", re.IGNORECASE)
_RULE_LINE_CAP = 200


def _rule_text(child: str, huawei: bool) -> str:
    text = child.strip()
    if huawei:
        # "rule 5 permit ip source 10.0.0.0 0.0.0.255" -> without the sequence number
        return re.sub(r"^rule\s+\d+\s+", "", text, flags=re.IGNORECASE)
    return re.sub(r"^\d+\s+", "", text)


def _parse_acl_definitions(statements: list[tuple[str, list[str]]]) -> list[dict[str, Any]]:
    definitions: dict[str, dict[str, Any]] = {}

    def put(name: str, family: str, kind: str, rule_lines: list[str]) -> None:
        if name in definitions:
            # the same ACL printed twice: keep the longer copy
            if len(rule_lines) > len(definitions[name]["rule_lines"]):
                definitions[name]["rule_lines"] = rule_lines
                definitions[name]["rules"] = len(rule_lines)
        else:
            definitions[name] = {
                "name": name, "family": family, "kind": kind, "rules": len(rule_lines),
                "rule_lines": rule_lines[:_RULE_LINE_CAP], "system": bool(_SYSTEM_ACL_RE.match(name)),
            }

    numbered: dict[str, list[str]] = {}
    for header, children in statements:
        cisco = _CISCO_ACL_HEADER.match(header)
        if cisco and cisco.group(3).lower() not in {"resequence", "logging", "log-update", "include-comment"}:
            rules = [_rule_text(child, False) for child in children if _RULE_RE.match(child.strip())]
            put(cisco.group(3), cisco.group(1).lower(), (cisco.group(2) or "").lower(), rules)
            continue
        huawei = _HUAWEI_ACL_HEADER.match(header)
        if huawei:
            family = (huawei.group(1) or "ip").lower()
            name = huawei.group(5) or huawei.group(3)
            extra = (huawei.group(6) or "").lower()
            kind = "advance" if "advance" in extra else ("basic" if "basic" in extra else "")
            rules = [_rule_text(child, True) for child in children if child.strip().lower().startswith("rule ")]
            put(name, family, kind, rules)
            continue
        numbered_rule = re.match(r"^access-list\s+(\d+)\s+((?:permit|deny)\b.*)$", header, re.IGNORECASE)
        if numbered_rule:
            numbered.setdefault(numbered_rule.group(1), []).append(numbered_rule.group(2))
    for number, rules in numbered.items():
        put(number, "ip", "numbered", rules)
    return list(definitions.values())


def _parse_traffic_policies(statements: list[tuple[str, list[str]]]) -> dict[str, list[str]]:
    """Huawei ``traffic policy`` -> classifier -> ``if-match acl`` chain:
    {policy: [acl, ...]}."""
    classifier_acls: dict[str, list[str]] = {}
    policy_classifiers: dict[str, list[str]] = {}
    for header, children in statements:
        classifier = re.match(r"^traffic classifier\s+(\S+)", header, re.IGNORECASE)
        if classifier:
            acls = []
            for child in children:
                match = re.match(r"^\s*if-match\s+(?:ipv6-)?acl\s+(?:name\s+)?(\S+)", child, re.IGNORECASE)
                if match:
                    acls.append(match.group(1))
            classifier_acls.setdefault(classifier.group(1), [])
            classifier_acls[classifier.group(1)].extend(a for a in acls if a not in classifier_acls[classifier.group(1)])
            continue
        policy = re.match(r"^traffic policy\s+(\S+)", header, re.IGNORECASE)
        if policy:
            names = []
            for child in children:
                match = re.match(r"^\s*classifier\s+(\S+)", child, re.IGNORECASE)
                if match:
                    names.append(match.group(1))
            policy_classifiers.setdefault(policy.group(1), [])
            policy_classifiers[policy.group(1)].extend(n for n in names if n not in policy_classifiers[policy.group(1)])
    return {
        policy: list(dict.fromkeys(acl for name in names for acl in classifier_acls.get(name, [])))
        for policy, names in policy_classifiers.items()
    }


def _parse_acl_bindings(
    statements: list[tuple[str, list[str]]],
    interfaces: list[dict[str, Any]],
    policy_acls: dict[str, list[str]],
    defined: set[str],
) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for iface in interfaces:
        for direction, acl in (("in", iface["acl_in"]), ("out", iface["acl_out"])):
            if acl:
                bindings.append({
                    "target": iface["name"], "kind": "interface", "acl": acl, "direction": direction,
                    "via": "ip access-group", "defined": acl in defined,
                })
        for item in iface["traffic_filters"]:
            bindings.append({
                "target": iface["name"], "kind": "interface", "acl": item["acl"],
                "direction": "in" if item["direction"] == "inbound" else "out",
                "via": "traffic-filter", "defined": item["acl"] in defined,
            })
        for item in iface["traffic_policies"]:
            acls = policy_acls.get(item["policy"], [])
            direction = "in" if item["direction"] == "inbound" else "out"
            if acls:
                for acl in acls:
                    bindings.append({
                        "target": iface["name"], "kind": "interface", "acl": acl, "direction": direction,
                        "via": f"traffic-policy {item['policy']}", "defined": acl in defined,
                    })
            else:
                bindings.append({
                    "target": iface["name"], "kind": "interface", "acl": "", "direction": direction,
                    "via": f"traffic-policy {item['policy']} (no ACL in its classifiers)", "defined": True,
                })
    for header, children in statements:
        vty = re.match(r"^line vty\s+(.+)$|^user-interface vty\s+(.+)$", header, re.IGNORECASE)
        if not vty:
            continue
        target = "vty " + (vty.group(1) or vty.group(2)).strip()
        for child in children:
            text = child.strip()
            cisco = re.match(r"^access-class\s+(\S+)\s+(in|out)\b", text, re.IGNORECASE)
            huawei = re.match(r"^acl\s+(?:name\s+)?(\S+)\s+(inbound|outbound)\b", text, re.IGNORECASE)
            if cisco:
                bindings.append({"target": target, "kind": "vty", "acl": cisco.group(1), "direction": cisco.group(2).lower(),
                                 "via": "access-class", "defined": cisco.group(1) in defined})
            elif huawei:
                bindings.append({"target": target, "kind": "vty", "acl": huawei.group(1),
                                 "direction": "in" if huawei.group(2).lower() == "inbound" else "out",
                                 "via": "acl", "defined": huawei.group(1) in defined})
    unique: list[dict[str, Any]] = []
    for item in bindings:
        if item not in unique:
            unique.append(item)
    return unique


_PROMPT_CMD_RE = re.compile(r"^(?:<[^>]*>|\[[^\]]*\]|\S+[#>])\s*(.*)$")
_REPORTED_HEADER_RE = re.compile(
    r"^(?:Standard IP|Extended IP|IP|IPv6|Extended MAC|Standard MAC|MAC|Extended IPv6) access[- ]list\s+(\S+)", re.IGNORECASE
)


def _reported_acl_names(clean: list[str]) -> list[str] | None:
    """The ACL names the DEVICE printed for `show access-lists` /
    `show ip access-lists` (one header per ACL). For Huawei `display acl all`
    only the total is printed ("Total nonempty ACL number is N"), so the list
    stays empty there and ``reported_count`` carries the number. None when
    the capture did not run either command."""
    ran = False
    names: list[str] = []
    in_cisco_output = False
    for line in clean:
        stripped = line.strip()
        prompt = _PROMPT_CMD_RE.match(stripped)
        command = prompt.group(1).strip().lower() if prompt and re.match(r"^(?:<[^>]*>|\[[^\]]*\]|\S+[#>])", stripped) else ""
        if command or (prompt and stripped.endswith(("#", ">"))):
            in_cisco_output = bool(re.match(r"^(?:sh|show)\s+(?:ip\s+)?access-lists?\b", command))
            if in_cisco_output or re.match(r"^(?:dis|display)\s+acl\s+all\b", command):
                ran = True
            continue
        if in_cisco_output:
            match = _REPORTED_HEADER_RE.match(stripped)
            if match and match.group(1) not in names:
                names.append(match.group(1))
        if re.search(r"Total nonempty ACL number is\s+\d+", line, re.IGNORECASE):
            ran = True
    return names if ran else None


def _reported_huawei_total(clean: list[str]) -> int | None:
    total = None
    for line in clean:
        match = re.search(r"Total nonempty ACL number is\s+(\d+)", line, re.IGNORECASE)
        if match:
            total = int(match.group(1))
    return total


_PLAIN_NAME_RE = re.compile(r"[\w.\-]+")


def _acl_references(statements: list[tuple[str, list[str]]], definitions: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Where an ACL is used OTHER than on an interface or a VTY line: a
    route-map / class-map / NAT / SNMP / traffic classifier names it. Returns
    {acl: ["route-map GTOPAS permit 10", ...]}.

    A name counts when it stands apart: no letter, digit, "_", "." or "-" before or after it.  For a name made only of those characters that is the same as
    "the name is one of the words of the line" (a word = a run of those characters), so each line is cut into its words once and the names are looked up in
    that set; a name with any other character (a space, a slash) keeps the regular expression.  A big configuration holds hundreds of ACLs and thousands of
    lines: looking every name up in every line with a regular expression took seconds."""
    refs: dict[str, list[str]] = {item["name"]: [] for item in definitions}
    if not refs:
        return refs
    plain = {name for name in refs if _PLAIN_NAME_RE.fullmatch(name)}
    patterns = {name: re.compile(rf"(?<![\w.\-]){re.escape(name)}(?![\w.\-])") for name in refs if name not in plain}
    for header, children in statements:
        low = header.lower()
        if low.startswith(("interface ", "line vty", "user-interface")) or _CISCO_ACL_HEADER.match(header) or _HUAWEI_ACL_HEADER.match(header):
            continue
        words = set(_PLAIN_NAME_RE.findall(header))
        for child in children:
            words.update(_PLAIN_NAME_RE.findall(child))
        hits = list(words & plain)
        hits += [name for name, pattern in patterns.items() if pattern.search(header) is not None or any(pattern.search(child) for child in children)]
        for name in hits:
            context = header if len(header) <= 80 else header[:77] + "..."
            if context not in refs[name] and len(refs[name]) < 8:
                refs[name].append(context)
    return refs


def _build_acls(
    statements: list[tuple[str, list[str]]], interfaces: list[dict[str, Any]], clean: list[str]
) -> dict[str, Any]:
    definitions = _parse_acl_definitions(statements)
    defined = {item["name"] for item in definitions}
    bindings = _parse_acl_bindings(statements, interfaces, _parse_traffic_policies(statements), defined)
    applied = {item["acl"] for item in bindings if item["acl"]}
    references = _acl_references(statements, definitions)
    for item in definitions:
        item["applied"] = item["name"] in applied
        item["referenced_by"] = references.get(item["name"], [])
    reported = _reported_acl_names(clean)
    huawei_total = _reported_huawei_total(clean)
    reported_count = huawei_total if huawei_total is not None else (len(reported) if reported is not None else None)
    return {
        "definitions": definitions,
        "bindings": bindings,
        "reported_count": reported_count,
        "reported_names": reported or [],
        # ACLs the device reports that are not in the running-config: system /
        # default ACLs (Nexus copp-system-*, ISE preauth_*, auto-qos ones).
        "reported_not_in_config": [name for name in (reported or []) if name not in defined],
    }


# --------------------------------------------------------------------------
# Whole view
# --------------------------------------------------------------------------


def _routing_enabled(statements: list[tuple[str, list[str]]], clean: list[str]) -> bool | None:
    """IOS: `ip routing` / `no ip routing`. None where the line does not exist
    (NX-OS, Huawei and Aruba always route; a config-less capture says nothing)."""
    headers = {header.lower() for header, _ in statements}
    if "no ip routing" in headers:
        return False
    if "ip routing" in headers:
        return True
    return None


def build_l3(
    clean: list[str],
    vendor: str,
    *,
    interfaces: list[dict[str, Any]] | None = None,
    routing_table: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The Layer-3 view of one capture. ``interfaces`` are the analyzer's own
    interface rows (state, HSRP/VRRP address are copied from them);
    ``routing_table`` is ``runtime_parser.parse_ip_route_table``."""
    statements = _statements(clean)
    l3_interfaces = _parse_interfaces(statements, vendor)
    static_routes, gateways = _parse_static_routes(statements)
    ospf = _parse_ospf(statements, l3_interfaces)
    acls = _build_acls(statements, l3_interfaces, clean)

    by_key = {ifkey(item.get("name", "")): item for item in (interfaces or [])}
    for iface in l3_interfaces:
        live = by_key.get(iface["key"])
        iface["status"] = (live or {}).get("status", "")
        iface["status_detail"] = (live or {}).get("status_detail", "")
        iface["virtual_ip"] = (live or {}).get("hsrp_vrrp_ip", "") or ""
        iface["address"] = (
            f"{iface['ip']}/{iface['prefix_len']}" if iface["ip"]
            else ("DHCP" if iface["address_source"] == "dhcp" else iface["address_source"].title())
        )

    default_routes = [
        {"next_hop": row["next_hop"] or row["interface"], "via": row["via"],
         "vrf": row["vrf"], "distance": row["distance"], "description": row["description"], "interface": row["interface"]}
        for row in static_routes if row["cidr"] == "0.0.0.0/0"
    ]
    for gateway in gateways:
        default_routes.append({"next_hop": gateway["next_hop"], "via": gateway["via"], "vrf": "", "distance": None,
                               "description": "", "interface": ""})

    table = _routing_table_summary(routing_table or [], clean)
    routing = _routing_enabled(statements, clean)
    findings: list[dict[str, str]] = list(ospf["findings"])
    active_networks = {
        item["network"] for item in l3_interfaces
        if item["kind"] in {"SVI", "Routed port", "Port-channel", "Sub-interface"} and item["ip"] and not item["shutdown"]
    }
    if routing is not True and len(active_networks) >= 2 and _looks_like_ios_switch(statements, l3_interfaces) and vendor.lower() == "cisco":
        findings.append({
            "level": "info", "code": "ip_routing_off",
            "text": (
                f"{len(active_networks)} active interfaces have IP addresses in different subnets, but `ip routing` is "
                "not in the configuration, so this IOS switch does not route between them (traffic leaves through "
                "`ip default-gateway`). A Huawei switch always routes between its Vlanif interfaces."
            ),
        })
    if not static_routes and not default_routes and not table["captured"] and not l3_interfaces:
        findings.append({"level": "info", "code": "no_l3_found", "text": "No Layer-3 configuration was found in this capture (include the running-config)."})

    return {
        "interfaces": l3_interfaces,
        "default_routes": default_routes,
        "static_routes": static_routes,
        "routing_table": table,
        "routing_enabled": routing,
        "ospf": ospf,
        "other_protocols": _parse_other_protocols(statements),
        "acls": acls,
        "findings": findings,
    }


def _looks_like_ios_switch(statements: list[tuple[str, list[str]]], interfaces: list[dict[str, Any]]) -> bool:
    """An IOS / IOS-XE switch with VLAN interfaces. NX-OS (`feature ...`, `vrf context`,
    `mgmt0`) always routes, and an IOS *router* does not print `ip routing` because it
    is on by default, so neither may be told "ip routing is off"."""
    headers = [header.lower() for header, _ in statements]
    if any(header.startswith(("feature ", "vrf context ", "vdc ", "nv overlay")) for header in headers):
        return False
    if any(item["name"].lower().startswith("mgmt") for item in interfaces):
        return False
    return any(item["kind"] == "SVI" and item["ip"] and not item["shutdown"] for item in interfaces)
