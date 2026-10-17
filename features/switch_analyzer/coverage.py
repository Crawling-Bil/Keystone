"""Coverage of one switch capture: which commands were read, which were not, and which are missing.

The Router Analyzer has a Coverage tab; this is the switch equivalent. It answers three
questions an engineer asks after uploading a capture:

* *Was my command understood?*  Each ``show`` / ``display`` command found in the file gets a
  status: ``analyzed`` (a parser read it), ``covered`` (a second copy, or a partial view of the
  running-config, so another block was used), ``ignored`` (help request, no output, or not
  something this analyzer uses), ``not parsed`` (a recognised command with no parser, or a
  parser that read no rows from a long output) and ``error`` (the device rejected the command).
* *Which tab does it feed?*  Every spec names the tab it fills, so the page can show only the
  tabs that have data.
* *What is missing?*  The commands of this vendor's collect list that the analyzer can read and
  the capture does not contain, each with what it would add. ``tests/test_switch_coverage.py``
  checks that every command listed here really is in the matching collect list.

Nothing here reads a table itself: it classifies command blocks. For the three tables that are never
legitimately empty when their command printed a long output (ARP, MAC, routing table) the number of
rows the parser produced is taken from the finished result, so a layout the parser does not know
(for example the NX-OS ``show ip route``) shows up as ``not parsed`` instead of looking healthy.
Tables that are often empty on a healthy device (neighbours, port-channels, PoE) are never judged this way.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from . import aoscx, capture_text, show_tables

SH = r"sh(?:ow)?"
DIS = r"dis(?:p(?:l(?:a(?:y)?)?)?)?"

TONE = {"analyzed": "ok", "covered": "ok", "ignored": "mute", "not parsed": "warn", "error": "bad", "missing": "warn"}


@dataclass(frozen=True)
class Spec:
    key: str
    label: str                       # name shown in the Coverage tab
    patterns: tuple[str, ...]        # fullmatch against the lower-cased, single-spaced command
    tab: str                         # tab of the Single Device page this command fills
    feeds: str                       # what it fills, for the "analyzed" note
    adds: str                        # what it would add, for the "missing" note
    command: dict[str, str]          # vendor -> command shown when it is missing
    rows: Callable[[dict[str, Any]], int | None] | None = None   # rows the parser produced, None = not checkable
    strict: bool = False             # True: a captured command that gave no rows is "not parsed" however short its output is


def _n(key: str) -> Callable[[dict[str, Any]], int | None]:
    return lambda result: len(result.get(key) or [])


def _path(*keys: str) -> Callable[[dict[str, Any]], int | None]:
    """Row count from a nested value of the result: a list gives its length, a dict its number of keys."""
    def count(result: dict[str, Any]) -> int | None:
        value: Any = result
        for key in keys:
            value = (value or {}).get(key) if isinstance(value, dict) else None
        return len(value) if isinstance(value, (list, dict)) else (1 if value else 0)
    return count


def _extra(key: str) -> Callable[[dict[str, Any]], int | None]:
    """Rows a nxos_extras parser produced for one command (``result["extras"]``)."""
    return lambda result: int((result.get("extras") or {}).get(key, 0))


def _stp_rows(result: dict[str, Any]) -> int:
    stp = result.get("spanning_tree") or {}
    return len(stp.get("instances") or []) + (1 if stp.get("note") or stp.get("summary") else 0)


def _licence_rows(result: dict[str, Any]) -> int:
    detail = ((result.get("health") or {}).get("licence") or {}).get("detail") or {}
    return (len(detail.get("entitlements") or []) + len(detail.get("rtu") or []) + len(detail.get("status") or [])
            + int(detail.get("features_listed") or 0))     # NX-OS `show license usage` lists features, not entitlements


SPECS: tuple[Spec, ...] = (
    Spec("config", "Configuration", (rf"{SH} run(?:ning-config)?(?: all)?", rf"{DIS} cu(?:r(?:r(?:e(?:n(?:t(?:-configuration)?)?)?)?)?)?"),
         "overview", "interfaces, VLANs, static routes, ACLs, DNS, SNMP, DHCP and every configuration check",
         "interfaces, VLANs, static routes, ACLs, DNS, SNMP, DHCP and every configuration check",
         {"cisco": "show running-config", "aruba": "show running-config", "aoscx": "show running-config", "huawei": "display current-configuration"}),
    Spec("version", "Version", (rf"{SH} ver(?:sion)?", rf"{DIS} ver(?:sion)?"), "overview", "model, software version and uptime",
         "model, software version, uptime and reload reason",
         {"cisco": "show version", "aruba": "show version", "aoscx": "show version", "huawei": "display version"}),
    Spec("inventory", "Inventory", (rf"{SH} inv(?:entory)?(?: raw)?", rf"{DIS} device(?: elabel(?: brief)?)?", rf"{DIS} elabel(?: brief)?", rf"{SH} modules", rf"{SH} system", rf"{SH} system inventory", rf"{SH} switch", rf"{DIS} stack"),
         "overview", "serial numbers, stack members, modules", "serial numbers, stack members and modules",
         {"cisco": "show inventory", "aruba": "show system", "aoscx": "show system inventory", "huawei": "display device elabel brief"}),
    Spec("vsf", "VSF stack", (rf"{SH} vsf(?: (?:detail|member(?: \d+)?|link(?: detail)?|topology))?",), "overview", "VSF members, roles, topology and split detection",
         "the VSF members and their roles, the topology (ring or chain) and the split-detection method", {"aoscx": "show vsf"},
         lambda result: len(((result.get("inventory") or {}).get("stack") or {}).get("members") or []), True),
    Spec("interfaces", "Interface status", (rf"{SH} int(?:erfaces?)? stat(?:us)?", rf"{SH} ip int(?:erfaces?)? br(?:ief)?", rf"{SH} int(?:erfaces?)? br(?:ief)?", rf"{DIS} int(?:erface)? br(?:ief)?", rf"{DIS} int(?:erface)? desc(?:ription)?", rf"{DIS} ip int(?:erface)? br(?:ief)?", rf"{SH} int(?:erfaces?)?", rf"{DIS} int(?:erface)?"),
         "interfaces", "live up / down / admin-down state of every port", "the live up / down / admin-down state of every port (without it ports show as unknown)",
         {"cisco": "show interfaces status", "aruba": "show interfaces brief", "aoscx": "show interface", "huawei": "display interface brief"}),
    Spec("vlan", "VLAN table", show_tables.PATTERNS["vlan"], "vlans", "VLAN IDs, names, state and access ports", "VLAN IDs and names as the device sees them",
         {"cisco": "show vlan brief", "aoscx": "show vlan"}, _path("vlan_summary", "listed"), True),
    Spec("vlan_summary", "VLAN count", show_tables.PATTERNS["vlan_summary"], "vlans", "how many VLANs the device has (checked against the VLAN table)",
         "how many VLANs the device counts", {"cisco": "show vlan summary"}, _path("vlan_summary", "device"), True),
    Spec("int_desc", "Interface descriptions", show_tables.PATTERNS["int_desc"], "interfaces", "description and up / down state of every interface",
         "the description and state of every interface", {"cisco": "show interface description"}, _path("interface_descriptions", "rows"), True),
    Spec("trunk", "Trunks", show_tables.PATTERNS["trunk"], "trunks", "trunk ports with native, allowed, active and forwarding VLANs",
         "which ports trunk and which VLANs each one carries", {"cisco": "show interface trunk"}, _path("trunks", "rows"), True),
    Spec("stp", "Spanning tree", show_tables.PATTERNS["stp"], "stp", "root bridge, port roles and states of every STP instance",
         "the root bridge, port roles and states of every VLAN", {"cisco": "show spanning-tree", "aoscx": "show spanning-tree"}, _stp_rows, True),
    Spec("arp_summary", "ARP count", show_tables.PATTERNS["arp_summary"], "arp", "how many ARP entries the device has (checked against the ARP table)",
         "how many ARP entries the device counts", {"cisco": "show ip arp summary"}, _path("table_checks", "arp", "device"), True),
    Spec("mac_count", "MAC count", show_tables.PATTERNS["mac_count"], "mac", "how many MAC entries the device has, per VLAN (checked against the MAC table)",
         "how many MAC addresses the device counts, per VLAN", {"cisco": "show mac address-table count"}, _path("table_checks", "mac", "device"), True),
    Spec("lic_usage", "Licence usage", show_tables.PATTERNS["lic_usage"], "health", "licences in use and their state", "the licences in use, their type and state",
         {"cisco": "show license usage"}, _licence_rows, True),
    Spec("lic_all", "Licence status", show_tables.PATTERNS["lic_all"], "health", "licence mode, registration, evaluation time left and term dates",
         "the licence mode, registration, evaluation time left and term dates", {"cisco": "show license all"}, _licence_rows, True),
    Spec("neighbors", "CDP / LLDP neighbours", (rf"{SH} cdp nei(?:ghbors?)?(?: detail)?", rf"{SH} lldp nei(?:ghbors?)?(?: (?:detail|system-detail))?", rf"{DIS} lldp nei(?:ghbor)?(?: brief)?", rf"{SH} lldp info remote-device(?: detail)?", rf"{SH} lldp neighbou?r-info(?: detail)?"),
         "neighbors", "neighbour table", "the neighbour on every port (what is plugged in where)",
         {"cisco": "show cdp neighbors detail", "aruba": "show lldp info remote-device", "aoscx": "show lldp neighbor-info detail", "huawei": "display lldp neighbor brief"}),
    Spec("portchannel", "Port-channels", (rf"{SH} (?:etherchannel|port-channel) summary", rf"{DIS} eth-trunk(?: \d+)?", rf"{SH} lag(?: brief)?", rf"{SH} lacp (?:aggregates?|configuration)"), "portchannels", "port-channel members and state",
         "which ports are bundled and whether each one is up",
         {"cisco": "show etherchannel summary", "nxos": "show port-channel summary", "aoscx": "show lag", "huawei": "display eth-trunk"}),
    Spec("arp", "ARP table", (rf"{SH} ip arp", rf"{SH} arp", rf"{DIS} arp"), "arp", "ARP entries", "the ARP table (IP to MAC to port)",
         {"cisco": "show ip arp", "aruba": "show arp", "aoscx": "show arp", "huawei": "display arp"}, _n("arp_table")),
    Spec("mac", "MAC address table", (rf"{SH} mac address-table", rf"{SH} mac-address-table", rf"{SH} mac-address", rf"{SH} mac address-table dynamic", rf"{DIS} mac-address"),
         "mac", "learned MAC addresses", "the learned MAC addresses and the port each one sits on",
         {"cisco": "show mac address-table", "aruba": "show mac-address", "aoscx": "show mac-address-table", "huawei": "display mac-address"}, _n("mac_table")),
    Spec("route", "Routing table", (rf"{SH} ip route", rf"{DIS} ip routing-table"), "routing", "the device's own routing table", "the routes the device actually uses",
         {"cisco": "show ip route", "aruba": "show ip route", "aoscx": "show ip route", "huawei": "display ip routing-table"}, _n("routing_table")),
    Spec("acl", "Access lists", (rf"{SH} (?:ip )?access-lists?(?: \S+)?", rf"{DIS} acl all"), "routing", "the ACLs the device reports (checked against the configuration)",
         "the ACLs the device itself reports, to catch lists that exist on the device but not in the file", {}),
    Spec("transceivers", "Transceivers", (rf"{SH} int(?:erfaces?)? transceiver(?: detail)?", rf"{SH} inter transceiver", rf"{SH} transceiver", rf"{DIS} int(?:erface)? transceiver(?: verbose)?", rf"{DIS} transceiver(?: verbose)?"),
         "transceivers", "transceiver list", "installed transceivers and their optical readings",
         {"cisco": "show interfaces transceiver", "aruba": "show interfaces transceiver", "aoscx": "show interface transceiver", "huawei": "display transceiver verbose"}),
    Spec("poe", "PoE", (rf"{SH} power inline", rf"{SH} power-over-ethernet(?: brief)?", rf"{DIS} poe (?:information|power|power-state)"), "poe", "PoE power per port", "PoE power per port",
         {"cisco": "show power inline", "aruba": "show power-over-ethernet brief", "aoscx": "show power-over-ethernet", "huawei": "display poe information"}),
    Spec("vpcmlag", "vPC / M-LAG", (rf"{SH} vpc(?: brief)?", rf"{DIS} m-lag (?:summary|brief)", rf"{DIS} dfs-group(?: \d+)?(?: heartbeat| m-lag brief)?"), "vpcmlag", "vPC / M-LAG state", "vPC / M-LAG state",
         {"cisco": "show vpc brief", "huawei": "display dfs-group m-lag brief"}),
    Spec("stp_summary", "Spanning-tree summary", show_tables.PATTERNS["stp_summary"], "health", "root-bridge VLANs, PortFast / BPDU Guard defaults", "the spanning-tree mode, root-bridge VLANs and PortFast / BPDU Guard defaults",
         {"cisco": "show spanning-tree summary"}),
    Spec("lacp", "LACP neighbours", (rf"{SH} lacp (?:\d+ )?neighbors?(?: detail)?", rf"{SH} lacp int(?:erfaces?)?(?: \S+)?"), "health", "LACP partner and state per member", "the LACP partner and state of every member port",
         {"cisco": "show lacp neighbor", "aoscx": "show lacp interface"}),
    Spec("env", "Environment", (rf"{SH} env(?:ironment)?(?: all)?", rf"{SH} environment (?:fan|power-supply|temperature|power-consumption)"), "health", "power supply, fan and temperature state", "power supply, fan and temperature state",
         {"cisco": "show env all", "nxos": "show environment", "aoscx": "show environment fan"}),
    Spec("licence", "Licence", show_tables.PATTERNS["lic_summary"], "health", "licence level and Smart Account", "the licence level and Smart Account", {}),
    Spec("vpc_detail", "vPC detail", (rf"{SH} vpc (?:role|peer-keepalive|consistency-parameters global)",), "health", "vPC role, keep-alive state and whether the two peers agree",
         "the vPC role, keep-alive state and whether the two peers agree", {"cisco": "show vpc role"}),
    Spec("vpc_link", "vPC peer-link counters", (rf"{SH} vpc statistics peer-link",), "vpcmlag", "the peer-link port-channel counters (rates, errors, discards)",
         "the peer-link port-channel counters", {"cisco": "show vpc statistics peer-link"}, _extra("vpc_link"), True),
    Spec("vpc_ka", "vPC keep-alive statistics", (rf"{SH} vpc statistics peer-keepalive",), "vpcmlag", "keep-alive messages sent and received and peer state changes",
         "keep-alive messages sent and received and peer state changes", {"cisco": "show vpc statistics peer-keepalive"}, _extra("vpc_ka"), True),
    Spec("fhrp_live", "VRRP groups", (rf"{DIS} vrrp",), "routing", "state of every VRRP group (Master / Backup)", "state of every VRRP group (Master / Backup)",
         {"huawei": "display vrrp"}, _extra("fhrp_live"), True),
    Spec("hsrp_live", "HSRP groups", (rf"{SH} hsrp(?: all| detail| active| standby| ipv4| ipv6| group \d+| interface \S+(?: \d+(?:/\d+)*)?(?: all)?)?", rf"{SH} hsrp brief", rf"{SH} standby brief"),
         "routing", "live state of every HSRP group (Active / Standby, priority, preempt, hello and hold timers, the peer)",
         "the live state of every HSRP group (Active / Standby, priority, preempt, timers, the peer, a group that is disabled)",
         {"nxos": "show hsrp all", "cisco": "show standby brief"}, _extra("hsrp_live"), True),
    Spec("hsrp_summary", "HSRP summary", (rf"{SH} hsrp summary",), "routing", "HSRP group totals and packet counters (checked against the groups listed)",
         "the HSRP group totals and packet counters", {"nxos": "show hsrp summary"}, _extra("hsrp_summary"), True),
    Spec("ospf_nbr", "OSPF neighbours", (rf"{SH} ip ospf nei(?:ghbors?)?(?: vrf \S+)?",), "routing", "live OSPF adjacencies (state, role, uptime, address, interface)",
         "the live OSPF adjacencies (state, role, address, interface)", {"nxos": "show ip ospf neighbors vrf all", "cisco": "show ip ospf neighbor"}, _extra("ospf_nbr")),
    Spec("ospf_nbr_summary", "OSPF neighbour summary", (rf"{SH} ip ospf nei(?:ghbors?)? summary(?: vrf \S+)?",), "routing", "OSPF neighbours per interface and state (checked against the neighbour table)",
         "the OSPF neighbours per interface and state", {"nxos": "show ip ospf neighbors summary vrf all"}, _extra("ospf_nbr_summary")),
    Spec("ospf_intf", "OSPF interfaces", (rf"{SH} ip ospf interface brief(?: vrf \S+)?",), "routing", "OSPF interfaces (area, cost, state, neighbours, status)",
         "the OSPF interfaces (area, cost, state, neighbours, status)", {"nxos": "show ip ospf interface brief vrf all", "cisco": "show ip ospf interface brief"}, _extra("ospf_intf"), True),
    Spec("ospf_db", "OSPF database", (rf"{SH} ip ospf(?: \S+)? database(?: vrf \S+)?",), "routing", "the link-state database summary (LSAs per type and area, every Router LSA)",
         "the link-state database summary (LSAs per type and area, every Router LSA)", {"nxos": "show ip ospf database", "cisco": "show ip ospf database"}, _extra("ospf_db"), True),
    Spec("sysres", "System resources", (rf"{SH} system resources",), "health", "CPU, memory, load average and process count", "CPU, memory and load average",
         {"cisco": "show system resources"}, _extra("sysres"), True),
    Spec("pc_balance", "Port-channel load balancing", (rf"{SH} port-channel load-balance",), "portchannels", "the hash that chooses the member link of a bundle", "the load-balancing hash",
         {"cisco": "show port-channel load-balance"}, _extra("pc_balance"), True),
    Spec("pc_usage", "Port-channel numbers", (rf"{SH} port-channel usage",), "portchannels", "port-channel numbers in use", "the port-channel numbers in use",
         {"cisco": "show port-channel usage"}, _extra("pc_usage"), True),
    Spec("pc_traffic", "Port-channel traffic share", (rf"{SH} port-channel traffic",), "portchannels", "each member's share of its bundle's traffic", "each member's share of its bundle's traffic",
         {"cisco": "show port-channel traffic"}, _extra("pc_traffic"), True),
    Spec("lacp_counters", "LACP counters", (rf"{SH} lacp counters",), "portchannels", "LACPDUs sent and received and packet errors per member", "LACPDUs sent and received and packet errors per member",
         {"cisco": "show lacp counters"}, _extra("lacp_counters"), True),
    Spec("lacp_keys", "LACP system ids and keys", (rf"{SH} lacp port-channel(?: \S+)?",), "portchannels", "LACP system ids and keys of every bundle", "the LACP system ids and keys of every bundle",
         {"cisco": "show lacp port-channel"}, _extra("lacp_keys"), True),
    Spec("stp_vrp", "Spanning tree (VRP)", (rf"{DIS} stp(?: brief)?",), "health", "spanning-tree mode, root bridge, BPDU protection and port roles",
         "the spanning-tree mode, root bridge, BPDU protection and port roles", {"huawei": "display stp brief"}),
    Spec("flash", "Software images", (rf"{SH} flash(?: _detail)?",), "health", "primary and secondary software image", "which software image is primary and which is the fallback",
         {"aruba": "show flash"}),
    Spec("logs", "Logs", (rf"{SH} logg?(?:i(?:n(?:g)?)?)?(?: (?:last \d+|logfile|buffered?|nvram|-[a-z]+|\d+))*", rf"{DIS} (?:logbuffer|trapbuffer|logfile)(?: [^|\s]+)*", rf"{SH} events(?: -[a-z](?: \S+)?)*"), "logs",
         "interface flaps, err-disable, MAC flapping, spanning-tree and LACP events", "the device's own log: interface flaps, err-disable, MAC flapping, spanning-tree and LACP events",
         {"cisco": "show logging", "nxos": "show logging last 1000", "aruba": "show logging", "aoscx": "show logging", "huawei": "display logbuffer"}, lambda result: int((result.get("logs") or {}).get("message_count") or 0)),
)
BY_KEY = {spec.key: spec for spec in SPECS}

# What a capture of each vendor is expected to contain (all are in that vendor's collect list;
# tests/test_switch_coverage.py keeps the two in step).
EXPECTED = {
    "cisco": ("config", "version", "inventory", "interfaces", "vlan", "neighbors", "portchannel", "arp", "mac", "route", "stp_summary", "env", "logs"),
    "aruba": ("config", "version", "inventory", "interfaces", "neighbors", "arp", "mac", "logs"),
    "huawei": ("config", "version", "inventory", "interfaces", "neighbors", "portchannel", "arp", "mac", "route", "logs"),
    "aoscx": ("config", "version", "inventory", "vsf", "interfaces", "vlan", "neighbors", "portchannel", "lacp", "arp", "mac", "route", "stp", "env", "logs"),
}

# Commands that are fine to have in a capture but that the Switch Analyzer does not use.
_NOT_USED = (
    (rf"{SH} clock", "capture time, not used"), (rf"{DIS} clock", "capture time, not used"),
    (rf"{SH} (?:users|history|line|terminal|privilege|whoami)", "session information, not used"),
    (rf"{SH} environment (?:led|power-supply input-voltage|power-redundancy)", "read for no tab (the fans, power supplies, temperatures and power draw are read)"),
    (rf"{SH} track", "object tracking, not used"),
    (rf"{SH} port-channel compatibility-parameters", "reference text: what a member port must match to join a bundle. It is not state of this device"),
    (rf"{SH} event manager policy registered", "Embedded Event Manager policies (the system-supplied Mandatory.* scripts are not configuration); not used"),
    (rf"{DIS} (?:users|history-command)", "session information, not used"),
    (rf"{SH} (?:flash:?|boot|file systems)(?: .*)?", "file system information, not used"), (r"dir(?: .*)?", "file system information, not used"),
    (rf"{SH} tech(?:-support)?(?: .*)?", "tech-support is not parsed; the individual commands are"), (rf"{DIS} diagnostic-information.*", "diagnostic bundle, not parsed"),
)
# A command whose whole answer is its own title: the feature behind it is not in use. (pattern, most lines that still count as "empty", note)
_EMPTY_ANSWERS = (
    (rf"{SH} ip sla (?:configuration|statistics|summary)(?: \d+)?", 2, "no IP SLA operation is configured (the command printed only its title)"),
)

# NX-OS answers "% Invalid command" to every command of a feature that is not enabled.
_NXOS_FEATURE = {"vpc": "vpc", "lldp": "lldp", "lacp": "lacp", "standby": "hsrp", "hsrp": "hsrp", "ospf": "ospf", "bgp": "bgp", "eigrp": "eigrp", "pim": "pim", "vrrp": "vrrp"}
_COVERED_BY_CONFIG = (rf"{SH} start(?:up-config)?", rf"{DIS} saved-configuration")
_HELP_END = "?"
_ERROR = re.compile(
    r"^\s*(?:%\s*(?:Invalid input|Invalid command|Incomplete command|Ambiguous command|Unrecognized command|Unknown command)|"
    r"Error:\s*(?:Unrecognized command|Wrong parameter|Incomplete command|Too many parameters|Ambiguous command)|"
    r"Invalid input\b|Unknown (?:command|interface|vrf)\b|Command not (?:found|supported)\b)", re.IGNORECASE)
_BARE = {"show", "sh", "display", "disp", "dis"}
_LONG_OUTPUT = 25   # lines; a legend plus a header (a CDP or route table with no rows) stays below this


def vendor_key(vendor: str) -> str:
    low = (vendor or "").lower()
    return "huawei" if "huawei" in low else ("aruba" if "aruba" in low else "cisco")


def command_blocks(clean: list[str]) -> list[dict[str, Any]]:
    """Every ``show`` / ``display`` command in the capture with the number of output lines under it."""
    blocks: list[dict[str, Any]] = []
    for index, line in enumerate(clean):
        parts = capture_text.split_command(line)
        if not parts:
            continue
        command, tail = parts
        if command in _BARE and tail:
            # "display  vlan summary" (two spaces): capture_text reads the second word as redrawn output
            command, tail = f"{command} {tail}", ""
        output, _cursor = capture_text._block_after(clean, index + 1, [tail] if tail else [])
        error = next((row.strip() for row in output[:3] if _ERROR.match(row)), "")
        blocks.append({"command": command, "lines": len(output), "error": error, "index": index})
    return blocks


def _match(command: str, patterns: tuple[str, ...]) -> bool:
    return any(re.fullmatch(pattern, command) for pattern in patterns)


def _spec_for(command: str) -> Spec | None:
    for spec in SPECS:
        if _match(command, spec.patterns):
            return spec
    return None


def _is_partial_config(command: str) -> bool:
    """``show running-config interface Gi1/0/1`` or ``display current-configuration | include ntp``."""
    return bool(re.match(rf"(?:{SH} run(?:ning-config)?|{DIS} cu\w*(?:-configuration)?)\s+\S", command)) and not _match(command, BY_KEY["config"].patterns)


def command_for(spec: Spec, family: str, nxos: bool = False) -> str:
    """The command a "not in this capture" message names: the Nexus spelling on a Nexus, else the vendor's, else the Cisco one."""
    return (spec.command.get("nxos") if nxos else None) or spec.command.get(family) or spec.command.get("cisco") or spec.label


def _feature_hint(command: str, error: str, clean: list[str], answered: set[str], has_config: bool) -> str:
    """For NX-OS ``% Invalid command at '^' marker``: name the feature the command belongs to and say whether the configuration enables it.

    ``answered``: features whose other commands printed output in this capture (so the feature runs, and it is this spelling the device refuses).
    ``has_config``: the capture holds a running-config; without it "not in the configuration" would only mean "the file has no configuration"."""
    if "invalid command" not in error.lower():
        return ""
    words = command.split()
    feature = next((_NXOS_FEATURE[word] for word in words[1:3] if word in _NXOS_FEATURE), "")
    if not feature:
        return ". NX-OS answers this way for a command of a feature that is not enabled or that this release does not have"
    # `show standby ...` is the IOS spelling; the Cisco Nexus 9000 NX-API CLI reference (HSRP commands) lists `show hsrp` and `show hsrp brief`
    spelling = ". NX-OS spells the HSRP commands `show hsrp` / `show hsrp brief`" if "standby" in words[1:3] else ""
    # the NX-API CLI reference (OSPF commands) lists `show ip ospf interface brief vrf all`, not `show ip ospf brief ...`
    if feature == "ospf" and re.match(r"show ip ospf (?:\S+ )?brief\b", command):
        spelling = ". NX-OS documents `show ip ospf interface brief vrf all` (the interface summary) and `show ip ospf neighbors summary vrf all`"
    if feature in answered:
        return f". Other {feature.upper()} commands answered in this capture, so the feature runs and it is this spelling that the device refuses{spelling}"
    if not has_config:
        return f". This capture has no running-config, so whether `feature {feature}` is enabled cannot be checked here{spelling}"
    enabled = any(re.fullmatch(rf"feature {feature}\b.*", line.strip()) for line in clean)
    if enabled:
        return f". `feature {feature}` is in the configuration, so this release or platform does not have the command{spelling}"
    return f". `feature {feature}` is not in the configuration: the feature is not enabled on this device{spelling}"


def build_coverage(clean: list[str], vendor: str, result: dict[str, Any]) -> dict[str, Any]:
    """``{"rows": [...], "present": {spec key: tab}, "missing": [...], "counts": {...}}``."""
    family = "aoscx" if aoscx.is_aoscx(clean) else vendor_key(vendor)
    # a Nexus spells some commands differently from a Catalyst; a top-level `feature <name>` line exists on NX-OS only (IOS has no such statement)
    nxos = family == "cisco" and ((result.get("health") or {}).get("family") == "nxos" or any(re.match(r"feature [a-z][\w-]*\s*$", line) for line in clean))
    blocks = command_blocks(clean)
    rows: list[dict[str, Any]] = []
    # The same command run twice: the longest copy is the one a parser reads. Different commands that
    # fill the same table (show interfaces status, show ip interface brief) are each analyzed.
    longest: dict[str, int] = {}
    seen_keys: set[str] = set()
    for block in blocks:
        spec = _spec_for(block["command"])
        if spec and not block["error"] and block["lines"]:
            longest[block["command"]] = max(longest.get(block["command"], 0), block["lines"])
            seen_keys.add(spec.key)
    has_full_config = any(
        _match(b["command"], BY_KEY["config"].patterns) and b["lines"] > 20 and not b["error"] for b in blocks)

    # features (hsrp, ospf, vpc ...) that have a command with real output in this capture
    config_text = has_full_config or any(re.match(r"(?:hostname|feature|vrf context|ip routing)\b|interface \S", line) for line in clean)
    answered = {_NXOS_FEATURE[word] for b in blocks if not b["error"] and b["lines"] for word in b["command"].split()[1:3] if word in _NXOS_FEATURE}
    used_once: set[str] = set()
    for block in blocks:
        command, lines = block["command"], block["lines"]
        status, note, tab = "not parsed", "recognised command but this analyzer has no parser for it yet", ""
        spec = _spec_for(command)
        if block["error"]:
            status, note = "error", f"the device rejected the command ({block['error'][:60]}){_feature_hint(command, block['error'], clean, answered, config_text)}"
            tab = spec.tab if spec else ""
        elif command.endswith(_HELP_END):
            status, note = "ignored", "help request"
        elif not lines:
            status, note = "ignored", "no output (half-typed, or the terminal swallowed it)"
        elif spec:
            tab = spec.tab
            if lines < longest.get(command, 0) or (command in used_once and lines == longest.get(command, 0)):
                status, note = "covered", "the same command appears again; the longest copy is the one read"
            else:
                used_once.add(command)
                status, note = "analyzed", spec.feeds[:1].upper() + spec.feeds[1:]
                count = spec.rows(result) if spec.rows else None
                if count == 0 and (lines > _LONG_OUTPUT or spec.strict):
                    status = "not parsed"
                    note = f"{lines} lines of output but no rows were read; the layout may be one this parser does not know"
                    tab = ""
                elif count == 0:
                    note = f"{note}. The table is empty"
        elif _is_partial_config(command):
            tab = "overview"
            if has_full_config:
                status, note = "covered", "partial view of the configuration; the full configuration is analyzed"
            else:
                status, note = "analyzed", "partial configuration only: interfaces and settings outside this view are not seen"
        elif _match(command, _COVERED_BY_CONFIG):
            status, note = "covered", "the running-config is analyzed instead"
        else:
            for pattern, why in _NOT_USED:
                if re.fullmatch(pattern, command):
                    status, note = "ignored", why
                    break
            else:
                for pattern, most, why in _EMPTY_ANSWERS:
                    if re.fullmatch(pattern, command) and lines <= most:
                        status, note = "ignored", why
                        break
        rows.append({"command": command, "status": status, "lines": lines, "note": note, "tone": TONE[status], "tab": tab})

    seen = seen_keys
    missing = []
    for key in EXPECTED.get(family, ()):
        spec = BY_KEY[key]
        if key in seen:
            continue
        shown = command_for(spec, family, nxos)
        found = spec.rows(result) if spec.rows else None
        if found:
            # A terminal can swallow the echo of a command while its output still lands in the file; the parser
            # finds that table by its header. It is read, so it is not "missing" (the rows prove it).
            rows.append({"command": shown, "status": "analyzed", "lines": 0, "tone": "ok", "tab": spec.tab,
                         "note": f"The table is in the capture ({found} rows) but the command line that printed it is not; it was read by its header"})
            seen_keys.add(key)
            continue
        missing.append({"command": shown, "status": "missing", "lines": 0, "note": "Not in this capture. Would add " + spec.adds + ".", "tone": "warn", "tab": spec.tab, "key": key})
    # LACP state needs `show lacp neighbor` once there are port-channels (Cisco)
    if family == "cisco" and result.get("port_channels") and "lacp" not in seen:
        spec = BY_KEY["lacp"]
        missing.append({"command": spec.command["cisco"], "status": "missing", "lines": 0, "note": "Not in this capture. Would add " + spec.adds + ".", "tone": "warn", "tab": spec.tab, "key": "lacp"})

    # The configuration says the device runs HSRP / OSPF but no command that shows its live state was captured
    if family == "cisco":
        if (result.get("fhrp") or {}).get("config_hsrp") and "hsrp_live" not in seen:
            spec = BY_KEY["hsrp_live"]
            missing.append({"command": command_for(spec, family, nxos), "status": "missing", "lines": 0, "note": "Not in this capture. Would add " + spec.adds + ".", "tone": "warn", "tab": spec.tab, "key": "hsrp_live"})
        if ((result.get("l3") or {}).get("ospf") or {}).get("configured") and "ospf_nbr" not in seen:
            spec = BY_KEY["ospf_nbr"]
            missing.append({"command": command_for(spec, family, nxos), "status": "missing", "lines": 0, "note": "Not in this capture. Would add " + spec.adds + ".", "tone": "warn", "tab": spec.tab, "key": "ospf_nbr"})

    counts: dict[str, int] = {}
    for row in rows + missing:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    analyzed_tabs = sorted({row["tab"] for row in rows if row["status"] == "analyzed" and row["tab"]})
    return {
        "family": family,
        "rows": rows + missing,
        "counts": counts,
        "commands": len(blocks),
        "analyzed_tabs": analyzed_tabs,
        "present": sorted(seen_keys),
    }
