"""Reduce one Switch Analyzer result to the facts a topology needs (a ``Device``)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .names import (canon_port, is_ip, short_host, speed_from_port, speed_from_transceiver, split_serial,
                    strip_capability_prefix)


@dataclass
class HalfEdge:
    """What one device says about one of its own ports: 'on this port I see that device'."""

    local_port: str            # canonical
    remote_name: str           # as advertised
    remote_port: str           # canonical, '' when unknown
    protocols: set[str] = field(default_factory=set)
    remote_ip: str = ""
    remote_serial: str = ""
    remote_platform: str = ""
    remote_caps: str = ""
    native_vlan: str = ""
    duplex: str = ""
    remote_chassis: str = ""   # 12 hex digits, lower case
    remote_port_desc: str = ""
    raw_local: str = ""
    raw_remote: str = ""


@dataclass
class Device:
    key: str                   # unique node key, set by the graph builder
    hostname: str              # short, upper-case
    fqdn: str = ""
    source: str = ""           # file name
    captured: bool = True
    vendor: str = ""
    model: str = ""
    os_version: str = ""
    mgmt_ip: str = ""
    ips: set[str] = field(default_factory=set)
    serials: set[str] = field(default_factory=set)
    macs: set[str] = field(default_factory=set)         # own chassis / stack-member MACs, 12 hex digits
    stack_members: int = 1
    halves: list[HalfEdge] = field(default_factory=list)
    bundles: dict[str, list[str]] = field(default_factory=dict)       # Po name -> canonical member ports
    bundle_of: dict[str, str] = field(default_factory=dict)           # canonical member port -> Po name
    bundle_info: dict[str, dict[str, str]] = field(default_factory=dict)  # Po name -> protocol/status/description
    descriptions: dict[str, str] = field(default_factory=dict)        # canonical port -> description
    port_modes: dict[str, str] = field(default_factory=dict)
    port_native: dict[str, str] = field(default_factory=dict)
    vpc_domain: str = ""
    vpc_role: str = ""
    vpc_peer_link: str = ""
    vpc_keepalive: str = ""
    vpc_ids: dict[str, str] = field(default_factory=dict)             # Po name -> vPC id
    stp_blocking: set[str] = field(default_factory=set)               # canonical ports
    mac_table: list[dict[str, Any]] = field(default_factory=list)
    arp_table: list[dict[str, Any]] = field(default_factory=list)
    role_hint: str = ""
    caps: str = ""
    coverage: dict[str, bool] = field(default_factory=dict)   # which commands the capture contained
    l3: list[dict[str, Any]] = field(default_factory=list)    # routed interfaces: name, ip, prefix_len, vrf, kind
    host_ports: dict[str, int] = field(default_factory=dict)
    speeds: dict[str, int] = field(default_factory=dict)              # canonical port -> rated speed in Mbit/s (transceiver, else port name)
    member_state: dict[str, str] = field(default_factory=dict)        # canonical bundle member -> LACP/PAgP flag letter (P = bundled)
    vpc_health: dict[str, str] = field(default_factory=dict)          # peer_status, keepalive_status, consistency_status, peer_link_status
    vpc_member_status: dict[str, dict[str, str]] = field(default_factory=dict)   # Po name -> {status, consistency}
    carried: bool = False                                             # restored from a previous run instead of a capture in this run
    actual_speeds: dict[str, int] = field(default_factory=dict)       # canonical port -> negotiated / operational speed in Mbit/s (link up only)
    duplex: dict[str, str] = field(default_factory=dict)              # canonical port -> full / half (link up only)
    port_state: dict[str, str] = field(default_factory=dict)          # canonical port -> up / down / admin down
    capture_gap: str = ""                                             # why the capture is incomplete (cut at the top, no running-config ...)
    wireless_clients: dict[str, int] = field(default_factory=dict)    # canonical access-point port -> client MACs learned behind it

    @property
    def label_lines(self) -> list[str]:
        return [self.hostname, " ".join(x for x in (self.model, "STACK" if self.stack_members > 1 else "") if x), self.mgmt_ip]


_MGMT_WORDS = ("mgmt", "management", "oob")


def _merge_arp(plain: list[dict[str, Any]], by_vrf: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The default-VRF table plus the ``show ip arp vrf X`` tables; a row both contain keeps its VRF name."""
    tagged = {(r.get("ip_address"), r.get("mac_address"), r.get("interface")) for r in by_vrf}
    return [dict(r) for r in plain if (r.get("ip_address"), r.get("mac_address"), r.get("interface")) not in tagged] + [dict(r) for r in by_vrf]


def _pick_mgmt_ip(l3: dict[str, Any]) -> tuple[str, set[str]]:
    interfaces = [row for row in (l3 or {}).get("interfaces", []) if row.get("ip")]
    ips = {row["ip"] for row in interfaces}
    ranking: list[tuple[int, str]] = []
    for row in interfaces:
        name = str(row.get("name", "")).lower()
        desc = str(row.get("description", "")).lower()
        vrf = str(row.get("vrf", "")).lower()
        score = 9
        if name.startswith("mgmt") or any(w in vrf for w in _MGMT_WORDS):
            score = 0
        elif name.startswith("loopback0") or name == "lo0" or name.startswith("loopback"):
            score = 1
        elif any(w in desc for w in _MGMT_WORDS):
            score = 2
        elif name in ("vlan1", "vlanif1"):
            score = 3
        elif row.get("kind") == "SVI":
            score = 5
        ranking.append((score, row["ip"]))
    ranking.sort(key=lambda item: item[0])
    return (ranking[0][1] if ranking else ""), ips


def _model(result: dict[str, Any]) -> str:
    hint = ((result.get("detection") or {}).get("model_hint") or "").strip()
    modules = (result.get("inventory") or {}).get("modules") or []
    for module in modules:
        slot = str(module.get("slot", "")).lower()
        if slot.startswith(("chassis", "switch 1")) and module.get("pid"):
            return str(module["pid"])
    return hint


def _os_info(result: dict[str, Any]) -> dict[str, Any]:
    info = result.get("os_version")
    return info if isinstance(info, dict) else {"os_version": info or ""}


def _system_mac(result: dict[str, Any]) -> str:
    """Base MAC of an Aruba CX switch (``show system``): the chassis ID its neighbors print in LLDP."""
    system = result.get("system")
    return str(system.get("base_mac", "")) if isinstance(system, dict) else ""


_SPEED_TEXT = re.compile(r"(\d+(?:\.\d+)?)\s*([GM])b(?:ps|/s)?", re.IGNORECASE)


def _speed_mbps_text(text: Any) -> int:
    """``1 Gb/s``, ``10 Mb/s``, ``25Gbps`` -> Mbit/s (0 when the text holds no speed)."""
    found = _SPEED_TEXT.search(str(text or ""))
    if not found:
        return 0
    value = float(found.group(1))
    return int(round(value * (1000 if found.group(2).upper() == "G" else 1)))


def _stack_members(result: dict[str, Any]) -> int:
    serials = result.get("serials") or {}
    members = serials.get("members") or []
    if len(members) > 1:
        return len(members)
    stack = (result.get("inventory") or {}).get("stack") or {}
    return int(stack.get("member_count") or 1)


def _serials(result: dict[str, Any]) -> set[str]:
    serials = result.get("serials") or {}
    found = {str(serials.get("serial_number", "")).strip().upper()}
    found |= {str(m.get("serial", "")).strip().upper() for m in serials.get("members", [])}
    for module in (result.get("inventory") or {}).get("modules", []):
        if re.match(r"^(chassis|switch \d+)$", str(module.get("slot", "")).strip().lower()):
            found.add(str(module.get("serial", "")).strip().upper())
    return {s for s in found if len(s) >= 6}


_MAC_RE = re.compile(r"^[0-9a-fA-F]{4}[.\-:]?[0-9a-fA-F]{4}[.\-:]?[0-9a-fA-F]{4}$|^(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")


def mac12(text: str) -> str:
    """'38fd.f8d7.6378', '38:FD:F8:D7:63:78' and '38fd-f8d7-6378' all become '38fdf8d76378'; anything else ''."""
    value = (text or "").strip()
    if not _MAC_RE.match(value):
        return ""
    return re.sub(r"[^0-9a-f]", "", value.lower())


_NOT_A_VALUE = {"", "null", "none", "n/a", "-", "not advertised", "not-advertised"}


def _value(text: Any) -> str:
    """Devices print 'null' or 'not advertised' for an LLDP field they do not fill in; that is no name, model or capability."""
    text = str(text or "").strip()
    return "" if text.lower() in _NOT_A_VALUE else text


def _dotted(mac: str) -> str:
    return f"{mac[0:4]}.{mac[4:8]}.{mac[8:12]}"


def _halves(neighbors: list[dict[str, Any]]) -> list[HalfEdge]:
    merged: dict[tuple[str, str], HalfEdge] = {}
    for row in neighbors:
        local = canon_port(str(row.get("local_interface", "")))
        if not local:
            continue
        name, serial = split_serial(_value(row.get("neighbor_id")))
        chassis = mac12(str(row.get("chassis_id", "")))
        if not name and chassis:
            name = _dotted(chassis)                 # a neighbor without a system name is identified by its chassis MAC
        remote_port = canon_port(strip_capability_prefix(str(row.get("remote_interface", ""))))
        if chassis and remote_port and mac12(remote_port) == chassis:
            remote_port = ""                        # the port id is the MAC address: no port name to show
        if not name:
            continue
        key = (local, short_host(name) + "|" + remote_port)
        half = merged.get(key)
        if half is None:
            half = merged[key] = HalfEdge(local, name, remote_port, raw_local=str(row.get("local_interface", "")),
                                          raw_remote=str(row.get("remote_interface", "")))
        half.protocols.add(str(row.get("protocol", "")).upper() or "?")
        half.remote_serial = half.remote_serial or serial or str(row.get("serial", "")).strip().upper()
        half.remote_chassis = half.remote_chassis or mac12(str(row.get("chassis_id", "")))
        half.remote_port_desc = half.remote_port_desc or _value(row.get("port_description"))
        ip = str(row.get("management_address", "")).strip()
        if is_ip(ip):
            half.remote_ip = half.remote_ip or ip
        platform = _value(row.get("platform"))
        if platform and not (str(row.get("protocol", "")).upper() == "LLDP" and ("Software" in platform or len(platform) > 40)):
            half.remote_platform = half.remote_platform or platform      # an LLDP OS banner is not a model
        half.remote_caps = half.remote_caps or _value(row.get("capabilities"))
        half.native_vlan = half.native_vlan or _value(row.get("native_vlan"))
        half.duplex = half.duplex or str(row.get("duplex", "")).strip()
    return _one_device_per_port(list(merged.values()))


def _same_neighbor(a: HalfEdge, b: HalfEdge) -> bool:
    """CDP and LLDP name one device two ways (Meraki and Cisco access points: CDP prints the MAC as the device ID, LLDP the system
    name and the MAC as chassis ID). Same port, and the name of one is the chassis ID or the management address of the other."""
    for first, second in ((a, b), (b, a)):
        name_mac = mac12(first.remote_name)
        if name_mac and name_mac == second.remote_chassis:
            return True
    return bool(a.remote_ip and a.remote_ip == b.remote_ip and a.protocols != b.protocols)


def _one_device_per_port(halves: list[HalfEdge]) -> list[HalfEdge]:
    by_port: dict[str, list[HalfEdge]] = {}
    for half in halves:
        by_port.setdefault(half.local_port, []).append(half)
    result: list[HalfEdge] = []
    for items in by_port.values():
        kept: list[HalfEdge] = []
        for half in items:
            twin = next((other for other in kept if _same_neighbor(other, half)), None)
            if twin is None:
                kept.append(half)
                continue
            # keep the real name over a MAC-address name, and every field either protocol knew
            if mac12(twin.remote_name) and not mac12(half.remote_name):
                twin.remote_name = half.remote_name
            twin.protocols |= half.protocols
            twin.remote_port = twin.remote_port or half.remote_port
            for field_name in ("remote_serial", "remote_chassis", "remote_ip", "remote_platform", "remote_caps", "remote_port_desc", "native_vlan", "duplex"):
                if not getattr(twin, field_name):
                    setattr(twin, field_name, getattr(half, field_name))
        result.extend(kept)
    return result


_COVERAGE_COMMANDS = {
    "cdp": ("cdp neighbors detail", "cdp neighbor"),
    "lldp": ("lldp neighbors", "lldp neighbor", "lldp info remote-device"),
    "bundles": ("etherchannel summary", "port-channel summary", "eth-trunk", "lacp"),
    "vpc": ("show vpc", "mlag", "vsx"),
    "inventory": ("show inventory", "display device", "display esn"),
    "mac": ("mac address-table", "mac-address", "mac address"),
    "arp": ("ip arp", "display arp"),
}


def _coverage(result: dict[str, Any]) -> dict[str, bool]:
    rows = (result.get("coverage") or {}).get("rows") or []
    found = {}
    for key, needles in _COVERAGE_COMMANDS.items():
        found[key] = any(row.get("status") != "missing" and any(n in str(row.get("command", "")).lower() for n in needles) for row in rows)
    # a capture without a coverage table (pasted fragment) still counts when the parsed table has rows
    found["cdp"] = found["cdp"] or any(n.get("protocol") == "CDP" for n in result.get("neighbors") or [])
    found["lldp"] = found["lldp"] or any(n.get("protocol") == "LLDP" for n in result.get("neighbors") or [])
    found["mac"] = found["mac"] or bool(result.get("mac_table"))
    found["arp"] = found["arp"] or bool(result.get("arp_table"))
    return found


_OS_TEXT = (
    re.compile(r"^\s*NXOS:\s*version\s+(\S+)", re.M | re.I),                                  # NX-OS: "NXOS: version 10.5(6) [Maintenance Release]"
    re.compile(r"^\s*Cisco IOS XE Software, Version\s+(\S+)", re.M | re.I),                    # IOS XE
    re.compile(r"^\s*Cisco IOS Software,.*?Version\s+([^,\s]+)", re.M | re.I),                 # classic IOS
)


def os_from_text(text: str) -> str:
    """Software version read straight from a ``show version`` block, for captures the analyzer could not parse it from
    (for example when an earlier command list repeats the words ``show version`` before the real output)."""
    for pattern in _OS_TEXT:
        found = pattern.search(text)
        if found:
            return found.group(1).rstrip(",")
    return ""


def device_from_analysis(result: dict[str, Any], source: str) -> Device:
    fqdn = str(result.get("hostname") or "").strip()
    host = short_host(fqdn) or short_host(source.rsplit(".", 1)[0])
    l3 = result.get("l3") or {}
    mgmt_ip, ips = _pick_mgmt_ip(l3)
    device = Device(
        key="", hostname=host, fqdn=fqdn, source=source,
        vendor=str(result.get("vendor") or (result.get("detection") or {}).get("vendor_used") or ""),
        model=_model(result) or str(_os_info(result).get("model") or ""), os_version=str(_os_info(result).get("os_version") or ""),
        mgmt_ip=mgmt_ip, ips=ips, serials=_serials(result), stack_members=_stack_members(result),
        halves=_halves(result.get("neighbors") or []),
        mac_table=list(result.get("mac_table") or []), arp_table=_merge_arp(result.get("arp_table") or [], result.get("arp_vrf_table") or []),
    )
    device.coverage = _coverage(result)
    device.l3 = [{"name": canon_port(str(row.get("name", ""))), "ip": row["ip"], "prefix_len": row.get("prefix_len"),
                  "vrf": str(row.get("vrf", "")), "kind": str(row.get("kind", "")), "shutdown": bool(row.get("shutdown")),
                  "description": str(row.get("description", "")), "status": str(row.get("status", "")), "secondary": [str(s) for s in (row.get("secondary") or [])][:4]}
                 for row in l3.get("interfaces", []) if row.get("ip") and row.get("prefix_len")]
    for bundle in result.get("port_channels") or []:
        name = canon_port(str(bundle.get("name", "")))
        members = [canon_port(m.strip()) for m in str(bundle.get("members", "")).split(",") if m.strip()]
        device.bundles[name] = members
        device.bundle_info[name] = {"protocol": str(bundle.get("protocol", "")), "status": str(bundle.get("status", "")),
                                    "description": str(bundle.get("description", "")), "mode": str(bundle.get("mode", ""))}
        for member in members:
            device.bundle_of[member] = name
    for member in ((result.get("inventory") or {}).get("stack") or {}).get("members") or []:
        if mac12(str(member.get("mac", ""))):
            device.macs.add(mac12(str(member["mac"])))
    if _system_mac(result):
        device.macs.add(_system_mac(result))
    for row in result.get("interfaces") or []:
        port = canon_port(str(row.get("name", "")))
        state = str(row.get("status", "")).strip().lower()
        if port and state in ("up", "down", "admin down"):
            device.port_state[port] = state
        if port and state == "up":
            mbps = int(row.get("speed_mbps") or 0) or _speed_mbps_text(row.get("speed"))
            if mbps:
                device.actual_speeds[port] = mbps
            if str(row.get("duplex", "")).lower() in ("full", "half"):
                device.duplex[port] = str(row["duplex"]).lower()
        if row.get("description"):
            device.descriptions[port] = str(row["description"])
        if row.get("mode"):
            device.port_modes[port] = str(row["mode"])
        for member in row.get("bundle_members") or []:
            member_port = canon_port(str(member.get("port", "")))
            if member_port and member_port not in device.bundle_of:
                device.bundle_of[member_port] = port
                device.bundles.setdefault(port, []).append(member_port)
    for row in result.get("transceivers") or []:
        port = canon_port(str(row.get("interface", "")))
        speed = speed_from_transceiver(f"{row.get('type', '')} {row.get('pid', '')}")
        if port and speed and row.get("present", True):
            device.speeds[port] = speed
    for row in result.get("interfaces") or []:
        port = canon_port(str(row.get("name", "")))
        if port and port not in device.speeds and not port.lower().startswith(("po", "vlan", "lo")) and speed_from_port(port):
            device.speeds[port] = speed_from_port(port)
    for row in (result.get("trunks") or {}).get("rows") or []:
        port, native = canon_port(str(row.get("port", ""))), str(row.get("native_vlan", "")).strip()
        if port and native.isdigit():
            device.port_native[port] = native
            if str(row.get("mode", "")).lower() in ("trunk", "on", "desirable", "auto") or "trunk" in str(row.get("status", "")).lower():
                device.port_modes.setdefault(port, "trunk")
    for bundle in result.get("port_channels") or []:
        for state in bundle.get("member_states") or []:
            flag, member = str(state.get("flag", "")).strip(), canon_port(str(state.get("port", "")))
            if member and flag:
                device.member_state[member] = flag
    vpc = result.get("vpc_mlag") or {}
    summary = vpc.get("summary") or {}
    if summary.get("domain_id") and vpc.get("source") == "live":      # a configuration-only capture has no vPC state to judge
        device.vpc_health = {key: str(summary.get(key, "")) for key in ("peer_status", "keepalive_status", "consistency_status", "peer_link_status")}
        for member in vpc.get("members") or []:
            if member.get("port"):
                device.vpc_member_status[canon_port(str(member["port"]))] = {"status": str(member.get("status", "")),
                                                                          "consistency": str(member.get("consistency", ""))}
        device.vpc_domain = str(summary["domain_id"])
        device.vpc_role = str(summary.get("role", ""))
        device.vpc_peer_link = canon_port(str(summary.get("peer_link", "")))
        device.vpc_keepalive = str(summary.get("peer_keepalive_dest_ip", ""))
        for member in vpc.get("members") or []:
            if member.get("port") and member.get("id"):
                device.vpc_ids[canon_port(str(member["port"]))] = str(member["id"])
    stp = result.get("spanning_tree") or {}
    for row in stp.get("ports") or []:
        role = str(row.get("role", "")).lower()
        # Aruba CX prints a port that is down as role Disabled / state Down; the analyzer shortens that to DIS. It is not blocking.
        if role.startswith("dis") or str(row.get("role_name", "")).lower() == "disabled" or str(row.get("state_name", "")).lower() in ("down", "disabled"):
            continue
        if str(row.get("state", "")).upper() in ("BLK", "DIS", "DISCARDING", "BLOCKING") or "altn" in role:
            device.stp_blocking.add(canon_port(str(row.get("interface", ""))))
    return device
