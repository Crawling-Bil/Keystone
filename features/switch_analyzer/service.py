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
    transceivers = runtime_parser.parse_transceivers(lines)
    poe = runtime_parser.parse_poe(lines)
    vpc_mlag = runtime_parser.parse_vpc_mlag(lines)
    inventory = runtime_parser.parse_inventory(lines)

    interfaces = _build_interfaces(config, interface_brief)
    routes = _build_routes(config)
    vlans = _build_vlans(config)
    dns = _extract_dns(config)
    snmp = _extract_snmp(config)
    dhcp = _build_dhcp(config, interfaces)

    _enrich_port_channels(port_channels, interfaces)
    vpc_mlag = _apply_vpc_mlag_config_fallback(vpc_mlag, config, interfaces)
    inventory = _apply_stack_config_fallback(inventory, config)
    poe = _apply_poe_config_fallback(poe, config)

    # Transceiver rows only carry install/type data — cross-reference the
    # already-built interface table for the up/down status the user asked
    # to see alongside each transceiver, instead of re-parsing it.
    #
    # The interfaces table is keyed by whatever name "show ip interface
    # brief" / "display ip interface brief" (or the running-config) used,
    # which for Cisco is always the FULL interface name
    # ("GigabitEthernet1/1/1"). A Catalyst transceiver row's interface
    # comes from "show inventory" instead, which uses the SHORT form
    # ("Gi1/1/1") — a real capture confirmed this mismatch left every
    # transceiver's status blank even though the underlying up/down data
    # was already correctly parsed. Index by both forms so either lookup
    # style hits.
    status_by_interface: dict[str, str] = {}
    for item in interfaces:
        status_by_interface[item["name"]] = item["status"]
        short_name = runtime_parser._short_cisco_interface_name(item["name"])
        status_by_interface.setdefault(short_name, item["status"])
    for item in transceivers:
        status = status_by_interface.get(item["interface"])
        if status is None:
            short_name = runtime_parser._short_cisco_interface_name(item["interface"])
            status = status_by_interface.get(short_name, "")
        item["status"] = status

    up_count = sum(1 for item in interfaces if item["status"] == "up")
    down_count = sum(1 for item in interfaces if item["status"] == "down")

    pbr_summary = _build_pbr_summary(config)

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
        "dhcp": dhcp,
        "transceivers": transceivers,
        "poe": poe,
        "vpc_mlag": vpc_mlag,
        "inventory": inventory,
        "routing_protocols": _routing_protocol_summary(config),
        "pbr": pbr_summary,
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
            "transceiver_count": len(transceivers),
            "poe_port_count": len(poe),
            "vpc_mlag_count": len(vpc_mlag["members"]),
            "stack_mode": inventory["stack"]["mode"] or "Unknown",
            "dhcp_pool_count": len(dhcp["pools"]),
            "dhcp_snooping_enabled": dhcp["snooping"]["enabled"],
            "has_custom_routing": pbr_summary["has_custom_routing"],
        },
    }


def _normalize_huawei_brief_keys(interface_brief: dict[str, dict]) -> dict[str, dict]:
    from features.configuration_studio.converter_engine.parsers.switch.huawei import HuaweiSwitchParser
    return {
        HuaweiSwitchParser.normalize_interface_name(name): value
        for name, value in interface_brief.items()
    }


def _format_allowed_vlans(allowed_vlans: list[str] | None, mode: str = "", vendor: str = "") -> str:
    """Render Interface.allowed_vlans (a list like ["100", "101-110"] or
    the single-element ["all"] Cisco/Huawei both use for 'allow every
    VLAN') the way the user asked to see it on the Port-Channel/Eth-
    Trunk and vPC/M-LAG tables: "100, 101, 102" or "All".

    A trunk port with NO "switchport trunk allowed vlan ..." line at
    all is a real, common case (confirmed on a real Catalyst 3650:
    Po1/Po2/Po3 are "switchport mode trunk" with no allowed-vlan line),
    and on Cisco that means every VLAN is allowed by default — "show
    interface trunk" reports "1-4094" for exactly these ports. Huawei's
    default is different (an unrestricted "port link-type trunk" only
    passes VLAN 1 until an explicit "port trunk allow-pass vlan ..."
    line is added), and no real capture in this project has shown that
    exact case, so this only fills in "All" for a Cisco source rather
    than guess at the Huawei default.
    """
    if allowed_vlans:
        if len(allowed_vlans) == 1 and allowed_vlans[0].strip().lower() == "all":
            return "All"
        return ", ".join(allowed_vlans)
    if mode.strip().lower() == "trunk" and vendor.strip().lower() == "cisco":
        return "All"
    return ""


def _mask_to_prefix_length(mask: str) -> int | None:
    """Dotted-decimal subnet mask -> CIDR prefix length (e.g.
    "255.255.254.0" -> 23), for combining with an interface's own IP
    address into "x.x.x.x/y" form. Returns None for anything that isn't
    a clean 4-octet dotted mask (so callers can fall back to the bare
    IP rather than show a nonsense prefix).
    """
    octets = mask.split(".")
    if len(octets) != 4:
        return None
    bits = 0
    for octet in octets:
        if not octet.isdigit():
            return None
        value = int(octet)
        if not 0 <= value <= 255:
            return None
        bits += bin(value).count("1")
    return bits


def _format_ip_with_mask(ip_address: str, subnet_mask: str = "") -> str:
    """Render an interface's IP the way the user asked to see it:
    "x.x.x.x/y" (falls back to the bare IP when no usable mask is
    available — never invents one). Also passes through an already-
    CIDR value untouched, which covers Huawei's "display ip interface
    brief" ("IP Address/Mask" column prints e.g. "10.85.28.2/23" as a
    single token already) once that command's own row-parsing is fixed
    to actually match real output (see runtime_parser._HUAWEI_IF_BRIEF_ROW).
    """
    ip_address = (ip_address or "").strip()
    if not ip_address or "/" in ip_address:
        return ip_address
    prefix = _mask_to_prefix_length(subnet_mask) if subnet_mask else None
    if prefix is None:
        return ip_address
    return f"{ip_address}/{prefix}"


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
        ip_address = item.ip_address or brief.get("ip_address", "")
        subnet_mask = item.subnet_mask or brief.get("subnet_mask", "")
        results.append({
            "name": item.name,
            "status": status,
            "protocol": brief.get("protocol", ""),
            "mode": item.mode or "",
            "vlan": vlan if vlan is not None else "",
            "ip_address": _format_ip_with_mask(ip_address, subnet_mask),
            "description": item.description or "",
            "port_security": "Enabled" if item.port_security_enabled else "",
            # HSRP virtual IP (Cisco "standby <group> ip <vip>") or its
            # Huawei VRRP equivalent ("vrrp vrid <id> virtual-ip <vip>",
            # huawei.py) — surfaced under one vendor-neutral column
            # rather than two, since a given interface only ever runs
            # one or the other.
            "hsrp_vrrp_ip": item.hsrp_virtual_ip or getattr(item, "vrrp_virtual_ip", "") or "",
            "allowed_vlans": _format_allowed_vlans(
                getattr(item, "allowed_vlans", None),
                item.mode or "",
                str(getattr(config, "source_vendor", "") or ""),
            ),
            "poe_enabled": bool(getattr(item, "poe_enabled", False)),
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
            "ip_address": _format_ip_with_mask(brief.get("ip_address", ""), brief.get("subnet_mask", "")),
            "description": "",
            "port_security": "",
            "hsrp_vrrp_ip": "",
            "allowed_vlans": "",
            "poe_enabled": False,
            "source": "show/display",
        })

    return results


def _canonical_interface_key(name: str) -> str:
    """Lower-case, punctuation-stripped key so the same physical/logical
    interface can be matched across differently-formatted names, e.g. a
    port-channel summary table's short "Po7" against a config block's
    "port-channel7" (see _port_channel_interface_key), or "Eth-Trunk1"
    against itself when case differs.
    """
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


_PO_SHORT_NAME_RE = re.compile(r"^Po(\d+)$", re.IGNORECASE)
_ETH_TRUNK_NAME_RE = re.compile(r"^Eth-Trunk(\d+)$", re.IGNORECASE)


def _port_channel_interface_key(name: str) -> str:
    """'show etherchannel/port-channel summary' reports the short Cisco
    form ("Po7"), while the interface's own config block is named
    "Port-channel7" / "port-channel7" — expand the short form to the
    same canonical key _build_interfaces() would produce for it.

    Huawei's 'display eth-trunk' summary reports "Eth-Trunk7" — this
    does NOT already match its own config block, despite what this
    function used to assume: HuaweiSwitchParser.normalize_interface_name
    rewrites "interface Eth-Trunk7" to "Port-channel7" when building
    config.interfaces (so the two vendors' Interface rows share one
    naming scheme), so _build_interfaces() never produces an "Eth-
    Trunk7"-named row at all — the raw canonical key of "Eth-Trunk7"
    ("ethtrunk7") could never hit "portchannel7" and Huawei's Port-
    Channel/Eth-Trunk table silently got NO Description/Mode/VLAN
    enrichment (confirmed on a real S5755 live capture, every Eth-Trunk
    row came back blank). Expand it the same way "Po7" is expanded.
    """
    po_match = _PO_SHORT_NAME_RE.match(name or "")
    if po_match:
        return _canonical_interface_key(f"portchannel{po_match.group(1)}")
    eth_trunk_match = _ETH_TRUNK_NAME_RE.match(name or "")
    if eth_trunk_match:
        return _canonical_interface_key(f"portchannel{eth_trunk_match.group(1)}")
    return _canonical_interface_key(name)


def _enrich_port_channels(port_channels: list[dict[str, Any]], interfaces: list[dict[str, Any]]) -> None:
    """Cross-reference each Port-Channel/Eth-Trunk summary row (from the
    live 'show port-channel summary' / 'display eth-trunk' parser, which
    only ever carries Name/Protocol/Status/Members) against the same
    interface's own config block — already fully parsed by
    _build_interfaces() — to add Description/Mode/VLAN, the same way a
    physical port already shows them. Mutates each dict in place so the
    single-device view, the compare view, and the Excel export all pick
    it up from the one place it's computed.
    """
    by_key = {_canonical_interface_key(item["name"]): item for item in interfaces}
    for pc in port_channels:
        iface = by_key.get(_port_channel_interface_key(pc.get("name", "")))
        pc["description"] = iface["description"] if iface else ""
        pc["mode"] = iface["mode"] if iface else ""
        pc["vlan"] = iface["vlan"] if iface else ""
        # Trunk-allowed VLANs on the port-channel/Eth-Trunk itself (e.g.
        # "100, 101, 102" or "All") — same already-parsed
        # Interface.allowed_vlans field a physical trunk port uses,
        # cross-referenced the same way Description/Mode/VLAN already are.
        pc["allowed_vlans"] = iface["allowed_vlans"] if iface else ""
        # A Port-Channel/Eth-Trunk can be a routed port (Cisco "no
        # switchport" + "ip address ...", Huawei "undo portswitch" +
        # "ip address ...", both now set Interface.mode = "routed" —
        # see cisco.py/huawei.py) — surface its IP address the same way
        # a routed physical port already does, instead of leaving the
        # user to cross-reference the Interfaces tab by hand.
        pc["ip_address"] = iface["ip_address"] if iface else ""


def _apply_vpc_mlag_config_fallback(
    vpc_mlag: dict[str, Any], config, interfaces: list[dict[str, Any]]
) -> dict[str, Any]:
    """vpc_mlag as parsed so far only ever comes from a LIVE status
    command — 'show vpc brief'/'show vpc role' (Cisco NX-OS) or 'display
    m-lag brief'/'display m-lag summary' (Huawei) — which only exist on
    a device that is actually up and has formed a peer session. A draft
    config for a switch that hasn't been deployed yet (exactly the "new
    Huawei draft" / Device B case in Compare Devices) was never live, so
    it never ran those commands — the table is correctly empty, not
    buggy, because there is genuinely no vPC/M-LAG STATE to report yet.

    What the draft DOES have is the static configuration itself:
      * Cisco/NX-OS "vpc domain <id>", "vpc peer-link" / "vpc <id>" —
        SwitchConfig.vpc_domain_id / Interface.is_vpc_peer_link /
        Interface.vpc_id, populated by cisco.py.
      * Huawei M-LAG "dfs-group <id>", "peer-link <id>" / "dfs-group
        <id> m-lag <member-id>" — SwitchConfig.mlag_dfs_group_id /
        Interface.is_mlag_peer_link / Interface.mlag_id, populated by
        huawei.py. Confirmed real VRP syntax on a real S5755 M-LAG
        pair (TTC-SWCODI-MN/BU-DMZ).
    So when there's no live status, fall back to reporting that
    configuration instead of leaving the tab blank — clearly labeled
    "configured (not active)" rather than an up/down state, since
    there's no peer to actually check consistency against.

    Also fills in, on top of either the live table or the fallback
    above, several fields the user asked for that a live status command
    never actually prints: the peer-keepalive (vPC) / dual-active
    detection (M-LAG) source+peer IPs (confirmed on a real Nexus 9108:
    even a real live "sh vpc peer-keepalive" only ever shows the
    DESTINATION address, never this switch's own source IP — the
    complete picture only ever comes from the static config either
    way), which port-channel/Eth-Trunk is the peer-link, and the VLANs
    allowed on the peer-link and each member port (joining the already-
    enriched interfaces table's allowed_vlans/vlan, the same fields
    _enrich_port_channels already surfaces for a plain port-channel).
    """
    interfaces_by_key = {_canonical_interface_key(item["name"]): item for item in interfaces}

    def vlans_for(port_name: str) -> str:
        iface = interfaces_by_key.get(_port_channel_interface_key(port_name))
        if not iface:
            return ""
        return iface["allowed_vlans"] or (str(iface["vlan"]) if iface["vlan"] != "" else "")

    config_interfaces = list(getattr(config, "interfaces", []))
    vpc_domain_id = getattr(config, "vpc_domain_id", None)
    mlag_dfs_group_id = getattr(config, "mlag_dfs_group_id", None)
    peer_link_iface = next(
        (i for i in config_interfaces if getattr(i, "is_vpc_peer_link", False) or getattr(i, "is_mlag_peer_link", False)),
        None,
    )
    members_config = [
        i for i in config_interfaces
        if getattr(i, "vpc_id", None) is not None or getattr(i, "mlag_id", None) is not None
    ]

    if vpc_mlag["members"] or vpc_mlag["summary"]:
        vpc_mlag["source"] = "live"
    elif vpc_domain_id is None and mlag_dfs_group_id is None and peer_link_iface is None and not members_config:
        vpc_mlag["source"] = "none"
        return vpc_mlag
    else:
        vpc_mlag["summary"] = {
            "domain_id": str(vpc_domain_id if vpc_domain_id is not None else (mlag_dfs_group_id or "")),
            "peer_link": peer_link_iface.name if peer_link_iface else "",
        }
        vpc_mlag["members"] = [
            {
                "id": str(i.vpc_id if getattr(i, "vpc_id", None) is not None else i.mlag_id),
                "port": i.name,
                "status": "configured (not active)",
                "consistency": "",
                "vlans": vlans_for(i.name),
            }
            for i in members_config
        ]
        vpc_mlag["source"] = "config"

    summary = vpc_mlag.get("summary") or {}

    if not summary.get("peer_link") and peer_link_iface:
        summary["peer_link"] = peer_link_iface.name

    if summary.get("peer_link") and "peer_link_vlans" not in summary:
        peer_link_vlans = vlans_for(summary["peer_link"])
        if not peer_link_vlans and peer_link_iface:
            # A peer-link with no explicit allow-list carries every
            # VLAN by default on both vendors — Cisco vPC's peer-link
            # is a normal trunk defaulting to "all" the same as any
            # other unrestricted trunk (see _format_allowed_vlans), and
            # Huawei's M-LAG peer-link auto-carries every VLAN in the
            # local VLAN database with no allow-list mechanism at all
            # ("port vlan exclude" is exclude-only) — confirmed on a
            # real S5755 M-LAG peer-link's own authoring comments.
            peer_link_vlans = "All"
        summary["peer_link_vlans"] = peer_link_vlans

    keepalive_source_ip = (
        getattr(config, "vpc_peer_keepalive_source_ip", "")
        or getattr(config, "mlag_dual_active_source_ip", "")
    )
    keepalive_dest_ip = (
        getattr(config, "vpc_peer_keepalive_dest_ip", "")
        or getattr(config, "mlag_dual_active_peer_ip", "")
    )
    keepalive_vrf = getattr(config, "vpc_peer_keepalive_vrf", "")
    if keepalive_source_ip:
        summary.setdefault("peer_keepalive_source_ip", keepalive_source_ip)
    if keepalive_dest_ip:
        summary.setdefault("peer_keepalive_dest_ip", keepalive_dest_ip)
    if keepalive_vrf:
        summary.setdefault("peer_keepalive_vrf", keepalive_vrf)

    for member in vpc_mlag["members"]:
        if not member.get("vlans"):
            member["vlans"] = vlans_for(member.get("port", ""))

    vpc_mlag["summary"] = summary
    return vpc_mlag


def _apply_stack_config_fallback(inventory: dict[str, Any], config) -> dict[str, Any]:
    """inventory["stack"] as parsed so far only ever comes from a LIVE
    'show switch' (Cisco StackWise) or 'display stack' (Huawei) table —
    a draft config for a switch that has never been deployed has no such
    section at all. Confirmed on a real S5755 draft: two "stack member N
    renumber N" / "stack member N priority N" blocks declaring a
    2-member stack, but zero "display stack" output anywhere in the
    file (it was never live), so stack detection reported "Unknown"
    even though the switch IS statically configured to form one.

    Mirrors _apply_vpc_mlag_config_fallback's pattern exactly: when
    there's no live table, fall back to the static declaration instead
    (Huawei's SwitchConfig.stack_members_config, populated by
    huawei.py's "stack"/"stack member ..." parsing), clearly labeled
    "configured (not active)" rather than a real up/down state. Role is
    inferred from priority — Huawei iStack elects the highest-priority
    member Master — which matches this project's own real draft's
    "Switch 1 (Master)" / "Switch 2 (Standby)" authoring comments.

    Cisco StackWise has no equivalent static pre-declaration in the
    running-config (stack membership there is purely a live, chassis-
    detected fact via 'show switch'), so this fallback only ever fires
    for a Huawei source until that changes.
    """
    if inventory["stack"]["members"]:
        return inventory

    stack_members_config = list(getattr(config, "stack_members_config", []))
    if not stack_members_config:
        return inventory

    priorities = [m.priority for m in stack_members_config if m.priority is not None]
    highest_priority = max(priorities) if priorities else None

    members = []
    for member in sorted(stack_members_config, key=lambda m: m.member_id):
        if member.priority is not None and highest_priority is not None:
            role = "Master" if member.priority == highest_priority else "Standby"
        else:
            role = ""
        members.append({
            "slot": str(member.member_id),
            "role": role,
            "mac": "",
            "state": "configured (not active)",
            "priority": member.priority if member.priority is not None else "",
        })

    inventory["stack"] = {
        "mode": "Stack" if len(members) > 1 else "Standalone",
        "member_count": len(members),
        "members": members,
        "source": "config",
    }
    return inventory


def _apply_poe_config_fallback(poe: list[dict[str, Any]], config) -> list[dict[str, Any]]:
    """poe as parsed so far only ever comes from a LIVE per-port table
    ('show power inline' on Cisco, 'show power-over-ethernet' on Aruba)
    or the CDP-detail power-drawn fallback. No real Huawei capture in
    this project has a live per-port PoE table at all — 'display poe
    information' / 'display poe-power' only ever print a slot/PSE-level
    power BUDGET (Power Max Value(mW), Available Power(mW), ...), never
    a per-port admin/oper state, confirmed across every real PoE-capable
    S5735 access switch draft in this project (none has ever been
    deployed with anything actually plugged in yet).

    What every one of those drafts DOES have is each port's own "poe
    enable" config line (Interface.poe_enabled, huawei.py) — so, mirroring
    the vPC/M-LAG and stack config-only fallback pattern, fall back to
    reporting THAT instead of leaving the tab blank: one row per
    PoE-enabled port, clearly labeled "configured (not active)" rather
    than a real oper state, since there's no live table to confirm
    against. Only fires when parse_poe() found nothing live to show —
    a real live table (once one exists in a real capture) always wins.
    """
    if poe:
        return poe

    fallback = []
    for item in getattr(config, "interfaces", []):
        if not getattr(item, "poe_enabled", False):
            continue
        fallback.append({
            "interface": item.name,
            "admin_status": "enabled",
            "oper_status": "configured (not active)",
            "power_watts": "",
            "device": "",
            "class": "",
            "max_watts": "",
            "source": "config (poe enable)",
        })
    return fallback


def _build_routes(config) -> list[dict[str, Any]]:
    results = []
    for route in getattr(config, "routes", []):
        results.append({
            "destination": route.destination,
            "mask": route.mask,
            "next_hop": route.next_hop,
            "distance": route.distance if route.distance is not None else "",
            # Optional Huawei "ip route-static ... track <id>" clause
            # (ties this route to a track object in config.track_objects
            # — see _build_pbr_summary's track_objects table for what
            # it's tracking). Blank for every route without one, which
            # is the overwhelming majority in real captures.
            "track_id": route.track_id if getattr(route, "track_id", None) is not None else "",
        })
    return results


def _build_dhcp(config, interfaces: list[dict[str, Any]]) -> dict[str, Any]:
    """DHCP tab: server pools, per-interface relay/helper addresses, and
    DHCP Snooping status (global, per-VLAN, Option 82, per-interface
    trust/rate-limit) — all pulled from the same already-parsed
    SwitchConfig used for every other tab, no new parsing pass needed.

    Every field this reads was validated against real capture data this
    round: Cisco "ip dhcp pool"/"ip helper-address"/"ip dhcp snooping
    ..." (TTC-SWCO-PABXGA-3650, GTOPAS-PKU-SWCO-C3650, TTC-SWAC-LAN-
    2960) all worked already; Huawei's "dhcp snooping enable ipv4" /
    "dhcp snooping enable vlan <range>" / "dhcp snooping trusted" did
    NOT (see huawei.py's parser fixes this same round) — those real
    VRP command forms were previously unrecognized, so this tab would
    have silently shown DHCP Snooping as off on every real Huawei
    device that actually has it configured.
    """
    pools = []
    for pool in getattr(config, "dhcp_pools", []):
        pools.append({
            "name": pool.name,
            "network": pool.network,
            "mask": pool.mask,
            "gateway": ", ".join(pool.gateway),
            "dns_servers": ", ".join(pool.dns_servers),
            "domain_name": pool.domain_name,
            "lease": pool.lease,
            "options": list(pool.options),
        })

    helper_addresses = []
    trusted_interfaces = []
    rate_limited_interfaces = []
    for item in getattr(config, "interfaces", []):
        if getattr(item, "helper_addresses", None):
            helper_addresses.append({"interface": item.name, "servers": list(item.helper_addresses)})
        if getattr(item, "dhcp_snooping_trusted", False):
            trusted_interfaces.append(item.name)
        rate_limit = getattr(item, "dhcp_snooping_rate_limit_pps", None)
        if rate_limit is not None:
            rate_limited_interfaces.append({"interface": item.name, "limit_pps": rate_limit})

    return {
        "pools": pools,
        "helper_addresses": helper_addresses,
        "snooping": {
            "enabled": bool(getattr(config, "dhcp_snooping_enabled", False)),
            "vlans": list(getattr(config, "dhcp_snooping_vlans", [])),
            "option82_enabled": bool(getattr(config, "dhcp_snooping_option82_enabled", False)),
            "trusted_interfaces": trusted_interfaces,
            "rate_limited_interfaces": rate_limited_interfaces,
        },
        "raw_commands": list(getattr(config, "dhcp_commands", [])),
    }


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


def _build_pbr_summary(config) -> dict[str, Any]:
    """Policy-Based Routing / SLA-Track / NQA — everything that makes a
    device's real forwarding behavior different from a plain static/
    dynamic routing table, surfaced so a reviewer can tell "this device
    has custom route configuration" without having to hand-inspect the
    raw config. Union of the two vendors' own PBR mechanisms:

      Cisco: "ip sla <id>" probes + "track <id> ip sla <id>
      reachability" objects + "route-map ... set ip next-hop
      verify-availability ... track <id>" clauses applied via "ip
      policy route-map <name>" (either statically under an interface,
      OR — a real, currently-active pattern on TAM 2026's Catalyst
      3650 stacks — dynamically via an EEM applet's SNMP-OID
      link-state watch, which never shows up under the interface at
      all).

      Huawei: "nqa test-instance admin <name>" probes + optional
      "track <id> nqa admin <name>" objects + "traffic classifier /
      traffic behavior / traffic policy" MQC chains applied via
      "traffic-policy <name> {inbound|outbound}" under an interface.

    Every field here traces back to real capture data confirmed this
    round (GTOPAS-MKS/PKU/MND/SMG-SWCO-C3650.txt for the Cisco side,
    GTOPAS-MKS-SWCODI-S5755-FIX.txt for the live-deployed Huawei side,
    draft_huawei_master.txt / ADM-SWCODI-S5755.txt for the Huawei
    numbered-track-object template form) — see TAM
    memory-keystone.md Section 1ac. Single Device's Routing tab and
    Compare Devices' Routes section both read this same structure (no
    vendor-specific UI branching needed).
    """

    sla_tests: list[dict[str, Any]] = []

    for sla in getattr(config, "ip_sla_entries", []):
        sla_tests.append({
            "kind": "IP SLA",
            "id": f"IP SLA {sla.sla_id}",
            "test_type": sla.test_type,
            "destination": sla.destination,
            "frequency": sla.frequency if sla.frequency is not None else "",
            "timeout": sla.timeout if sla.timeout is not None else "",
            "probe_count": "",
        })

    for nqa in getattr(config, "nqa_test_instances", []):
        sla_tests.append({
            "kind": "NQA",
            "id": f"NQA {nqa.test_name}",
            "test_type": nqa.test_type,
            "destination": nqa.destination,
            "frequency": nqa.frequency if nqa.frequency is not None else "",
            "timeout": nqa.timeout if nqa.timeout is not None else "",
            "probe_count": nqa.probe_count if nqa.probe_count is not None else "",
        })

    track_objects: list[dict[str, Any]] = []
    for track in getattr(config, "track_objects", []):
        if track.nqa_name:
            tracks_desc = f"NQA {track.nqa_name}"
        elif track.sla_id is not None:
            tracks_desc = f"IP SLA {track.sla_id}"
        else:
            tracks_desc = ""
        track_objects.append({
            "track_id": track.track_id,
            "tracks": tracks_desc,
        })

    # Interface -> PBR-policy application, unified across both vendors'
    # own mechanism ("ip policy route-map" for Cisco, "traffic-policy
    # ... inbound/outbound" for Huawei) so the UI needs no per-vendor
    # branching.
    pbr_bindings: list[dict[str, Any]] = []
    for iface in getattr(config, "interfaces", []):
        policy_name = getattr(iface, "ip_policy_route_map", "") or ""
        if policy_name:
            pbr_bindings.append({
                "interface": iface.name,
                "policy_name": policy_name,
                "direction": "",
                "mechanism": "ip policy route-map",
            })
        for direction, attr in (
            ("inbound", "traffic_policy_inbound"),
            ("outbound", "traffic_policy_outbound"),
        ):
            policy_name = getattr(iface, attr, "") or ""
            if policy_name:
                pbr_bindings.append({
                    "interface": iface.name,
                    "policy_name": policy_name,
                    "direction": direction,
                    "mechanism": "traffic-policy",
                })

    # PBR policies themselves — Cisco route-map clauses and Huawei
    # traffic-policy classifier/behavior bindings, unified into one
    # "policy name / sequence / match / action / tracked-by" shape.
    pbr_policies: list[dict[str, Any]] = []

    for route_map in getattr(config, "route_maps", []):
        for clause in route_map.clauses:
            tracked_by = (
                f"Track {clause.set_next_hop_track_id}"
                if clause.set_next_hop_track_id is not None
                else ""
            )
            pbr_policies.append({
                "vendor_mechanism": "Cisco route-map",
                "policy_name": route_map.name,
                "sequence": clause.sequence,
                "action": clause.action,
                "match": f"ACL {clause.match_acl}" if clause.match_acl else "",
                "set_next_hop": clause.set_next_hop,
                "tracked_by": tracked_by,
            })

    classifiers_by_name = {c.name: c for c in getattr(config, "traffic_classifiers", [])}
    behaviors_by_name = {b.name: b for b in getattr(config, "traffic_behaviors", [])}

    for policy in getattr(config, "traffic_policies", []):
        for binding in policy.bindings:
            classifier = classifiers_by_name.get(binding.classifier)
            behavior = behaviors_by_name.get(binding.behavior)

            match = ""
            if classifier and classifier.acl_numbers:
                match = "ACL " + ", ".join(classifier.acl_numbers)

            set_next_hop = behavior.redirect_next_hop if behavior else ""
            if behavior and behavior.track_nqa_name:
                tracked_by = f"NQA {behavior.track_nqa_name}"
            elif behavior and behavior.track_id is not None:
                tracked_by = f"Track {behavior.track_id}"
            else:
                tracked_by = ""

            pbr_policies.append({
                "vendor_mechanism": "Huawei traffic-policy",
                "policy_name": policy.name,
                "sequence": binding.precedence if binding.precedence is not None else "",
                "action": "redirect",
                "match": match,
                "set_next_hop": set_next_hop,
                "tracked_by": tracked_by,
            })

    eem_dynamic_pbr = []
    for eem in getattr(config, "eem_pbr_bindings", []):
        eem_dynamic_pbr.append({
            "applet_name": eem.applet_name,
            "route_map_name": eem.route_map_name,
            "action": eem.action,
            "target_interfaces": list(eem.target_interfaces),
            "trigger_description": eem.trigger_description,
        })

    has_custom_routing = bool(
        sla_tests or track_objects or pbr_bindings or pbr_policies or eem_dynamic_pbr
    )

    return {
        "sla_tests": sla_tests,
        "track_objects": track_objects,
        "pbr_policies": pbr_policies,
        "pbr_bindings": pbr_bindings,
        "eem_dynamic_pbr": eem_dynamic_pbr,
        "has_custom_routing": has_custom_routing,
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
