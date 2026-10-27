"""Health and hygiene checks for one Cisco IOS / IOS XE switch capture.

Built from the Jalin sample captures (one core stack, four access switches, a
router and a wireless controller, all IOS XE) and the LXS Po7 / Eth-Trunk1 case:
the Switch Analyzer read tables but never judged them. This module reads what the
capture already contains and returns:

* ``findings``: deterministic rules, each with a code, a severity, the evidence and
  a documentation link. Nothing is guessed: a rule fires only on lines that are in
  the capture, and a command that was not captured is reported as "not captured",
  never as "healthy".
* ``stp``, ``lacp``, ``environment``, ``licence``, ``software``: the parsed tables
  behind the Health tab.
* ``capture.missing``: the useful commands this capture does not contain.

Scope: Cisco IOS / IOS XE here; Cisco NX-OS, Huawei VRP / YunShan OS and ArubaOS-Switch are handled by ``health_other.py`` and
return the same shape. Any other platform returns ``supported: False`` with a note; its tables are still shown by the rest of the analyzer.
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text, licence_detail, show_tables
from .finding_context import vlan_phrase

try:  # Cisco links already opened and checked for the Router Analyzer
    from features.router_analyzer.refs import REFS as _ROUTER_REFS
except Exception:  # pragma: no cover - the router analyzer is optional here
    _ROUTER_REFS = {}

_L2 = "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/"
DOCS: dict[str, tuple[str, str]] = {
    "etherchannel": (
        "Catalyst 9300 Layer 2 guide (17.9) - Configuring EtherChannels",
        _L2 + "17-9/configuration_guide/lyr2/b_179_lyr2_9300_cg/configuring_etherchannels.html",
    ),
    "stp": (
        "Catalyst 9300 Layer 2 guide (17.12) - Configuring Spanning Tree Protocol",
        _L2 + "17-12/configuration_guide/lyr2/b_1712_lyr2_9300_cg/configuring_spanning_tree_protocol.html",
    ),
    "dai": (
        "Catalyst 9300 Security guide (17.12) - Configuring Dynamic ARP Inspection",
        _L2 + "17-12/configuration_guide/sec/b_1712_sec_9300_cg/configuring_dynamic_arp_inspection.html",
    ),
    "harden": ("Cisco Guide to Harden Cisco IOS Devices", _ROUTER_REFS.get("harden_ios", "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html")),
    "aaa": ("Cisco IOS XE 16 - Configuring AAA", _ROUTER_REFS.get("aaa", "")),
    "ssh": ("Cisco IOS XE 16 - Secure Shell configuration guide", _ROUTER_REFS.get("ssh", "")),
    "snmp": ("Cisco IOS XE 16 - SNMP configuration guide", _ROUTER_REFS.get("snmp", "")),
    "ntp": ("Cisco IOS XE 17 - Setting time and calendar services", _ROUTER_REFS.get("ntp", "")),
    "password_types": ("Cisco - Understanding the differences between enable password and enable secret", _ROUTER_REFS.get("password_types", "")),
    "smart_eval": ("Cisco TAC - Renew Expired License Period (Smart Licensing evaluation)", licence_detail.EVAL_EXPIRED_DOC),
    "smart_license": ("Cisco - Smart Licensing Using Policy: troubleshooting", _ROUTER_REFS.get("smart_lic_troubleshoot", "")),
    "smart_slp_nxos": ("Cisco - Configure Smart Licensing Using Policy on Nexus 9000 (reporting rules, ACK)",
                       "https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/220643-configure-smart-licensing-using-policy-o.html"),
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# show etherchannel summary flags (Cisco IOS XE Layer 2 guide, EtherChannel)
MEMBER_FLAGS = {
    "P": "bundled", "s": "suspended", "D": "down", "I": "stand-alone", "H": "hot-standby",
    "w": "waiting", "u": "unsuitable for bundling", "d": "default port", "f": "failed to allocate aggregator",
    "M": "not in use (min-links)", "m": "not in use (no aggregator)",
}

# 802.1AX LACP state bits, in the order Cisco prints them in hex (bit 0 = 0x01)
LACP_STATE_BITS = ["Activity", "Short timeout", "Aggregation", "Synchronization", "Collecting", "Distributing", "Defaulted", "Expired"]

# Commands that make the Health tab more complete, with what each one adds.
USEFUL_COMMANDS = [
    ("show spanning-tree summary", show_tables.PATTERNS["stp_summary"][0], "root bridge VLANs, PortFast / BPDU Guard defaults"),
    ("show etherchannel summary", r"sh(?:ow)? (?:etherchannel|port-channel) summary", "bundle state of every port-channel member"),
    ("show lacp neighbor", r"sh(?:ow)? lacp (?:\d+ )?neighbors?(?: detail)?", "LACP partner and state per member"),
    ("show env all", r"sh(?:ow)? env(?:ironment)?(?: all)?", "power supply, fan and temperature state"),
    ("show license summary", show_tables.PATTERNS["lic_summary"][0], "licence level and Smart Account"),
    ("show mac address-table", r"sh(?:ow)? mac(?:-| )address-table", "learned MAC addresses"),
    ("show ip arp", r"sh(?:ow)? ip arp", "ARP entries"),
]


def _finding(code: str, severity: str, title: str, text: str, *, where: str = "", doc: str = "") -> dict[str, Any]:
    entry: dict[str, Any] = {
        "code": code,
        "severity": severity,
        "level": "warning" if severity in ("high", "medium") else "info",
        "title": title,
        "text": text,
        "where": where,
    }
    ref = DOCS.get(doc)
    if ref and ref[1]:
        entry["doc"] = {"title": ref[0], "url": ref[1]}
    return entry


# ---------------------------------------------------------------- helpers

def _output(clean: list[str], pattern: str) -> list[str] | None:
    blocks = capture_text.command_outputs(clean, [pattern])
    return max(blocks, key=len) if blocks else None


def _short(name: str) -> str:
    """GigabitEthernet1/0/9 -> Gi1/0/9, Port-channel7 -> Po7 (the form Cisco tables print)."""
    for full, short in (
        ("TwentyFiveGigE", "Twe"), ("TwoGigabitEthernet", "Tw"), ("TenGigabitEthernet", "Te"),
        ("FortyGigabitEthernet", "Fo"), ("HundredGigE", "Hu"), ("GigabitEthernet", "Gi"),
        ("FastEthernet", "Fa"), ("Port-channel", "Po"), ("Ethernet", "Eth"),
    ):
        if name.startswith(full):
            return short + name[len(full):]
    return name


def _running_config(clean: list[str]) -> list[str]:
    block = _output(clean, r"sh(?:ow)? run(?:ning-config)?(?: all)?")
    if block:
        return block
    # A bare configuration file has no command echo: use it when it looks like one.
    if any(line.startswith("hostname ") for line in clean) and any(line.startswith("interface ") for line in clean):
        return clean
    return []


def _config_blocks(config: list[str]) -> tuple[list[str], dict[str, list[str]]]:
    """(global lines, {interface name: its sub-commands})."""
    top: list[str] = []
    blocks: dict[str, list[str]] = {}
    current: list[str] | None = None
    for raw in config:
        line = raw.rstrip()
        if not line or line.strip() == "!":
            current = None
            continue
        if line.startswith("interface "):
            current = blocks.setdefault(line[len("interface "):].strip(), [])
            continue
        if line[0] in " \t" and current is not None:
            current.append(line.strip())
            continue
        current = None
        if not line[0].isspace():
            top.append(line.strip())
    return top, blocks


def _expand_vlan_text(text: str) -> list[int]:
    vlans: list[int] = []
    for part in re.findall(r"VLAN0*(\d+)(?:\s*-\s*VLAN0*(\d+))?", text, re.IGNORECASE):
        low = int(part[0])
        high = int(part[1]) if part[1] else low
        vlans.extend(range(low, high + 1))
    return vlans


# ---------------------------------------------------------------- parsers

def parse_stp_summary(lines: list[str] | None) -> dict[str, Any]:
    info: dict[str, Any] = {}
    if not lines:
        return info
    root_text = ""
    collecting = False
    for line in lines:
        text = line.strip()
        match = re.match(r"^Switch is in (\S+) mode", text, re.IGNORECASE)
        if match:
            info["mode"] = match.group(1)
        match = re.match(r"^Root bridge for:\s*(.*)$", text, re.IGNORECASE)
        if match:
            root_text, collecting = match.group(1), True
            continue
        if collecting:
            if text and re.match(r"^(VLAN\d|,|\d)", text, re.IGNORECASE) and ":" not in text and " is " not in text:
                root_text += " " + text
                continue
            collecting = False
        # IOS prints "Portfast Default"; NX-OS prints "Port Type Default" and "Edge Port [PortFast] BPDU Guard Default"
        for key, label in (("portfast_default", r"(?:Portfast Default|Port Type Default)"),
                           ("bpduguard_default", r"(?:Portfast BPDU Guard Default|Edge Port \[PortFast\] BPDU Guard Default)"),
                           ("bpdufilter_default", r"(?:Portfast BPDU Filter Default|Edge Port \[PortFast\] BPDU Filter Default)"),
                           ("loopguard_default", r"Loopguard Default"), ("bridge_assurance", r"Bridge Assurance")):
            match = re.match(rf"^{label}\s+is\s+(\w+)", text, re.IGNORECASE)
            if match:
                value = match.group(1).lower()
                info[key] = "disabled" if value == "disable" else "enabled" if value == "enable" else value
        match = re.match(r"^vPC peer-switch\s+is\s+(.+)$", text, re.IGNORECASE)
        if match:
            info["vpc_peer_switch"] = match.group(1).strip()
    if "mode" in info or root_text:
        root_vlans = _expand_vlan_text(root_text)
        info["root_for"] = root_text.strip() or "none"
        info["root_vlan_count"] = len(root_vlans)
    return info


def parse_etherchannel_flags(lines: list[str] | None) -> dict[str, dict[str, Any]]:
    """{"Po7": {"state": "SU", "protocol": "LACP", "members": [{"port": "Gi1/0/9", "flag": "P"}]}}"""
    result: dict[str, dict[str, Any]] = {}
    if not lines:
        return result
    current: dict[str, Any] | None = None
    member = re.compile(r"^(\S+)\(([A-Za-z])\)$")
    for line in lines:
        match = re.match(r"^\s*(\d+)\s+(Po\d+)\(([A-Za-z]+)\)\s*(.*)$", line)
        if match:
            _group, name, state, rest = match.groups()
            tokens = rest.split()
            members = [member.match(t) for t in tokens]
            ports = [{"port": m.group(1), "flag": m.group(2)} for m in members if m]
            others = [t for t, m in zip(tokens, members) if not m]
            current = {"state": state, "protocol": others[-1] if others else "", "members": ports}
            result[name] = current
            continue
        if current is not None and line.strip():
            tokens = line.split()
            found = [member.match(t) for t in tokens]
            if all(found):
                current["members"].extend({"port": m.group(1), "flag": m.group(2)} for m in found)
    return result


def parse_lacp_neighbors(lines: list[str] | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not lines:
        return rows
    group = ""
    for line in lines:
        match = re.match(r"^\s*Channel group (\d+) neighbors", line, re.IGNORECASE)
        if match:
            group = match.group(1)
            continue
        match = re.match(
            r"^\s*(\S+)\s+([SFAP]+)\s+(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\d+s?)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s*$",
            line, re.IGNORECASE,
        )
        if not match:
            continue
        port, flags, priority, dev_id, age, _admin, oper_key, number, state = match.groups()
        value = int(state, 16)
        healthy = (value & 0x3C) == 0x3C and not (value & 0xC0)
        rows.append({
            "group": group, "port": port, "flags": flags, "priority": priority, "partner_id": dev_id, "age": age,
            "partner_key": oper_key, "partner_port": number, "state": state.lower(),
            "state_bits": ", ".join(name for bit, name in enumerate(LACP_STATE_BITS) if value & (1 << bit)),
            "healthy": healthy,
        })
    return rows


_ENV_GOOD = {"good", "green", "normal", "ok"}


def parse_environment(lines: list[str] | None) -> dict[str, Any]:
    result: dict[str, Any] = {"sensors": [], "fans": [], "power_supplies": [], "problems": 0}
    if not lines:
        return result
    sensor = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 :/_.-]*?)\s+(\S+)\s+(GOOD|GREEN|YELLOW|RED|Normal|Warning|Critical|Fault\w*|Bad|Shutdown|N/A)\s+(.*?)\s*$")
    fan = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(OK|\S+)\s+(Front to Back|Back to Front|\S+ to \S+)\s*$")
    psu = re.compile(r"^\s*(\d+[A-Z])\s+(\S+)\s+(\S+)\s+(OK|\S+(?: \S+)?)\s+(Good|Bad|n/a|\S+)\s+(Good|Bad|n/a|\S+)\s+(\d+)\s*$")
    for line in lines:
        match = psu.match(line)
        if match and re.search(r"\d", match.group(2) + match.group(3)):
            slot, pid, serial, status, sys_pwr, poe_pwr, watts = match.groups()
            bad = status.lower() != "ok" or sys_pwr.lower() not in ("good", "n/a")
            result["power_supplies"].append({"slot": slot, "pid": pid, "serial": serial, "status": status, "system_power": sys_pwr, "poe_power": poe_pwr, "watts": watts, "problem": bad})
            result["problems"] += bad
            continue
        match = fan.match(line)
        if match:
            switch, number, speed, state, airflow = match.groups()
            bad = state.lower() != "ok"
            result["fans"].append({"switch": switch, "fan": number, "speed": speed, "state": state, "airflow": airflow, "problem": bad})
            result["problems"] += bad
            continue
        match = sensor.match(line)
        if match and not line.lstrip().lower().startswith(("sensor ", "switch ")):
            name, location, state, reading = match.groups()
            bad = state.lower() not in _ENV_GOOD and state.lower() != "n/a"
            result["sensors"].append({"name": name.strip(), "location": location, "state": state, "reading": reading, "problem": bad})
            result["problems"] += bad
    return result


def parse_licence(lines: list[str] | None) -> dict[str, Any]:
    result: dict[str, Any] = {"smart_account": "", "virtual_account": "", "licenses": []}
    if not lines:
        return result
    for line in lines:
        match = re.match(r"^\s*Smart Account:\s*(.*?)(?:\s+As of .*)?$", line)
        if match:
            result["smart_account"] = match.group(1).strip()
        match = re.match(r"^\s*Virtual Account:\s*(.*)$", line)
        if match:
            result["virtual_account"] = match.group(1).strip()
        match = re.match(r"^\s*(\S.*?)\s+\((.*?)\)\s+(\d+)\s+(IN USE|NOT IN USE|EVAL.*|\S.*)$", line)
        if match and "Entitlement" not in line:
            result["licenses"].append({"license": match.group(1).strip(), "tag": match.group(2), "count": int(match.group(3)), "status": match.group(4).strip()})
    return result


def parse_software(lines: list[str] | None) -> dict[str, Any]:
    info: dict[str, Any] = {}
    for line in lines or []:
        match = re.search(r"\buptime is (.+)$", line)
        if match and "uptime" not in info:
            text = match.group(1).strip()
            info["uptime"] = text
            days = 0
            for amount, unit in re.findall(r"(\d+)\s+(year|week|day)s?", text):
                days += int(amount) * {"year": 365, "week": 7, "day": 1}[unit]
            info["uptime_days"] = days
        match = re.search(r"Last reload reason:\s*(.+)$", line)
        if match:
            info["last_reload_reason"] = match.group(1).strip()
        match = re.search(r"System returned to ROM by (.+)$", line)
        if match:
            info["last_reload"] = match.group(1).strip()
    return info


# ---------------------------------------------------------------- rules

def _channel_attributes(lines: list[str]) -> dict[str, str]:
    """The settings that decide whether a member may join its port-channel."""
    attrs = {"mode": "dynamic auto", "access vlan": "1", "trunk allowed": "all", "native vlan": "1", "routed": "no"}
    for line in lines:
        match = re.match(r"^switchport mode (.+)$", line)
        if match:
            attrs["mode"] = match.group(1).strip()
        match = re.match(r"^switchport access vlan (\d+)$", line)
        if match:
            attrs["access vlan"] = match.group(1)
        match = re.match(r"^switchport trunk allowed vlan (?:add )?(.+)$", line)
        if match:
            attrs["trunk allowed"] = match.group(1).replace(" ", "")
        match = re.match(r"^switchport trunk native vlan (\d+)$", line)
        if match:
            attrs["native vlan"] = match.group(1)
        if line == "no switchport":
            attrs["routed"] = "yes"
    return attrs


def _compared_keys(po_attrs: dict[str, str]) -> list[str]:
    if po_attrs["routed"] == "yes":
        return ["routed"]
    if po_attrs["mode"] == "trunk":
        return ["mode", "trunk allowed", "native vlan"]
    return ["mode", "access vlan"]


def _rules_channels(top: list[str], blocks: dict[str, list[str]], flags: dict[str, dict[str, Any]], lacp: list[dict[str, Any]],
                    lacp_captured: bool, interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    admin_down = {_short(item["name"]) for item in interfaces if item.get("status") == "admin down"}

    members: dict[str, list[tuple[str, str]]] = {}
    for name, lines in blocks.items():
        for line in lines:
            match = re.match(r"^channel-group (\d+) mode (\w+)", line)
            if match:
                members.setdefault(match.group(1), []).append((name, match.group(2)))

    for group, ports in sorted(members.items(), key=lambda item: int(item[0])):
        po_name = f"Port-channel{group}"
        po_lines = blocks.get(po_name)
        modes = {mode for _port, mode in ports}
        if len(modes) > 1:
            listed = ", ".join(f"{_short(p)} {m}" for p, m in ports)
            findings.append(_finding(
                "SW-LACP-005", "medium", f"Po{group} members use different channel-group modes",
                f"{listed}. Members of one channel must negotiate the same way (all LACP active/passive, or all `on`).",
                where=f"Po{group}", doc="etherchannel"))
        if po_lines is None:
            continue
        po_attrs = _channel_attributes(po_lines)
        for port, _mode in ports:
            attrs = _channel_attributes(blocks[port])
            diffs = [(key, attrs[key], po_attrs[key]) for key in _compared_keys(po_attrs) if attrs[key] != po_attrs[key]]
            if diffs:
                detail = "; ".join(f"{key}: member {mine} / Po{group} {theirs}" for key, mine, theirs in diffs)
                findings.append(_finding(
                    "SW-LACP-002", "high", f"{_short(port)} does not match Po{group}",
                    f"{detail}. Cisco suspends a member whose port mode or VLAN does not match the other ports "
                    f"of the channel, so it never bundles and sends no LACPDUs. Set the same switchport mode and VLAN on the physical port.",
                    where=_short(port), doc="etherchannel"))

    for name, info in flags.items():
        bundle_down = info["state"].upper().startswith(("SD", "RD"))
        for member in info["members"]:
            flag = member["flag"]
            meaning = MEMBER_FLAGS.get(flag, "unknown flag")
            if flag == "P":
                continue
            if flag == "D" and (member["port"] in admin_down or bundle_down):
                continue  # unused or shut down on purpose: the interface table already says so
            severity = {"s": "high", "I": "medium", "w": "medium", "u": "medium", "f": "medium", "H": "info", "D": "medium"}.get(flag, "low")
            findings.append(_finding(
                "SW-LACP-001", severity, f"{name} member {member['port']} is {meaning} ({flag})",
                f"`show etherchannel summary` lists {member['port']} with flag ({flag}) = {meaning}. "
                "A suspended or stand-alone member is not carrying the bundle: check its configuration against the port-channel and `show lacp neighbor`.",
                where=member["port"], doc="etherchannel"))

    if lacp_captured:
        seen = {(row["group"], row["port"]) for row in lacp}
        for row in lacp:
            if row["partner_id"] == "0000.0000.0000":
                findings.append(_finding(
                    "SW-LACP-004", "high", f"No LACP partner answered on {row['port']}",
                    "The partner system ID is all zeros: this port has not received a usable LACPDU from the far end. Check that the remote port is in LACP mode and that its channel group is configured.",
                    where=row["port"], doc="etherchannel"))
            elif not row["healthy"]:
                findings.append(_finding(
                    "SW-LACP-003", "medium", f"LACP partner state {row['state']} on {row['port']}",
                    f"Partner flags set: {row['state_bits'] or 'none'}. A bundled link shows 0x3d (Activity, Aggregation, Synchronization, Collecting, Distributing); "
                    "here the partner is not collecting and distributing.", where=row["port"], doc="etherchannel"))
        for name, info in flags.items():
            if info["protocol"].upper() != "LACP":
                continue
            group = re.sub(r"\D", "", name)
            for member in info["members"]:
                if (group, member["port"]) not in seen and member["flag"] != "P":
                    findings.append(_finding(
                        "SW-LACP-004", "high", f"No LACP partner listed for {member['port']}",
                        f"`show lacp neighbor` has no row for {member['port']} in channel group {group}, and the port is not bundled.",
                        where=member["port"], doc="etherchannel"))
    return findings


def _rules_stp(top: list[str], blocks: dict[str, list[str]], stp: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    explicit = any(re.match(r"^spanning-tree (vlan \S+ (priority|root)|mst \S+ (priority|root))", line) for line in top)
    if stp.get("root_vlan_count") and not explicit:
        findings.append(_finding(
            "SW-STP-001", "medium", f"Root bridge for {stp['root_vlan_count']} VLAN(s) with no spanning-tree priority configured",
            f"`show spanning-tree summary` says this switch is root for {vlan_phrase(stp['root_for'], 160)}, but the configuration has no `spanning-tree vlan ... priority` or `root primary`. "
            "The root is then whichever switch has the lowest MAC address. Set an explicit priority on the intended core or distribution switch and leave access switches at the default.",
            doc="stp"))
    edge = [name for name, lines in blocks.items() if "spanning-tree portfast" in lines]
    unguarded = [name for name in edge if "spanning-tree bpduguard enable" not in blocks[name]]
    global_guard = any(re.match(r"^spanning-tree portfast (edge )?bpduguard default", line) for line in top)
    if unguarded and not global_guard:
        findings.append(_finding(
            "SW-STP-002", "medium", f"{len(unguarded)} PortFast port(s) without BPDU Guard",
            f"PortFast is set on {', '.join(_short(n) for n in unguarded[:6])}{' ...' if len(unguarded) > 6 else ''} and neither `spanning-tree bpduguard enable` "
            "nor `spanning-tree portfast bpduguard default` is configured. A switch plugged into such a port can change the topology.",
            doc="stp"))
    mode = str(stp.get("mode") or "")
    if mode and "pvst" in mode.lower() and "rapid" not in mode.lower():
        findings.append(_finding("SW-STP-003", "low", f"Spanning-tree mode is {mode}",
                                 "Classic PVST converges in tens of seconds; rapid-pvst or mst is the usual choice on current switches.", doc="stp"))
    return findings


def _rules_management(top: list[str], blocks: dict[str, list[str]], dhcp: dict[str, Any], interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    users = [line for line in top if line.startswith("username ")]
    if not any(line.startswith("aaa new-model") for line in top):
        detail = f"{len(users)} local username(s) are the only accounts" if users else "no central authentication is configured"
        findings.append(_finding("SW-AAA-001", "medium", "AAA is not enabled",
                                 f"There is no `aaa new-model`: {detail}. Logins cannot use TACACS+/RADIUS, per-user accounting or command authorization.", doc="aaa"))
    weak = [line.split()[1] for line in users if re.search(r"\s(password)\s+[07]\s", line) or re.search(r"\spassword\s+\S+$", line) and " secret " not in line]
    md5 = [line.split()[1] for line in users if re.search(r"\ssecret\s+5\s", line)]
    if weak:
        findings.append(_finding("SW-USER-001", "medium", f"{len(weak)} local user(s) stored with a reversible or plain password",
                                 f"Users: {', '.join(weak[:6])}. `password` (type 0/7) is not hashed; use `username NAME secret 9 ...` (scrypt) instead. Hashes are never shown here.", doc="password_types"))
    if md5:
        findings.append(_finding("SW-USER-002", "low", f"{len(md5)} local user(s) use an MD5 (type 5) secret",
                                 "Type 5 is a salted MD5 hash; type 8 or 9 is stronger on current IOS XE.", doc="password_types"))
    if any(re.match(r"^enable password\b", line) for line in top):
        findings.append(_finding("SW-ENA-001", "medium", "`enable password` is configured",
                                 "`enable password` is stored reversibly; `enable secret` is hashed. Remove the password line.", doc="password_types"))
    if any(re.match(r"^ip http server\b", line) for line in top):
        findings.append(_finding("SW-HTTP-001", "medium", "Plain HTTP management server is enabled",
                                 "`ip http server` serves the web UI without encryption. If the web UI is needed use `ip http secure-server` only and `no ip http server`.", doc="harden"))
    communities = [line for line in top if re.match(r"^snmp-server community\s", line)]
    if communities:
        rw = [line for line in communities if re.search(r"\sRW\b", line, re.IGNORECASE)]
        findings.append(_finding(
            "SW-SNMP-001", "medium" if rw else "low", f"{len(communities)} SNMP v1/v2c community string(s)" + (f", {len(rw)} read-write" if rw else ""),
            "Community strings travel in clear text and are shared secrets. Prefer SNMPv3 with authPriv; restrict any community with an ACL. String names are not shown here.", doc="snmp"))
    if not any(re.match(r"^logging (host )?\d+\.\d+\.\d+\.\d+|^logging host\b|^logging server\b", line) for line in top):
        findings.append(_finding("SW-LOG-001", "low", "No remote syslog server",
                                 "Logs stay in the switch buffer and are lost on reload. Add `logging host <ip>` to a collector.", doc="harden"))
    ntp = [line for line in top if re.match(r"^ntp (server|peer)\b", line)]
    if not ntp:
        findings.append(_finding("SW-NTP-001", "medium", "No NTP server", "Log timestamps and certificates depend on the clock. Add at least two `ntp server` lines.", doc="ntp"))
    elif len(ntp) == 1:
        findings.append(_finding("SW-NTP-001", "low", "Only one NTP server", "One source cannot be cross-checked; configure at least two.", doc="ntp"))
    if not any(re.match(r"^ip ssh version 2\b", line) for line in top):
        findings.append(_finding("SW-SSH-001", "info", "SSH version 2 is not set explicitly",
                                 "`ip ssh version 2` is not in the configuration. Confirm with `show ip ssh` that SSHv1 is not accepted.", doc="ssh"))

    pools = len((dhcp or {}).get("pools") or [])
    snooping = bool(((dhcp or {}).get("snooping") or {}).get("enabled"))
    if not snooping and pools:
        findings.append(_finding("SW-DHCP-001", "medium", f"DHCP server with {pools} pool(s) and DHCP snooping off",
                                 "This switch hands out leases but does not inspect DHCP traffic on its ports, so a rogue DHCP server on an access VLAN is not stopped. "
                                 "Dynamic ARP Inspection also depends on the snooping binding table.", doc="dai"))
    elif not snooping and any(item.get("mode") == "access" for item in interfaces):
        findings.append(_finding("SW-DHCP-001", "low", "DHCP snooping is not enabled",
                                 "Access ports exist but `ip dhcp snooping` is not configured: rogue DHCP servers and ARP spoofing are not filtered.", doc="dai"))

    trunks = [name for name, lines in blocks.items() if "switchport mode trunk" in lines]
    open_trunks = [name for name in trunks if not any(l.startswith("switchport trunk allowed vlan") for l in blocks[name])]
    if open_trunks:
        findings.append(_finding("SW-TRK-001", "low", f"{len(open_trunks)} trunk port(s) allow all VLANs (1-4094)",
                                 f"No `switchport trunk allowed vlan` on {', '.join(_short(n) for n in open_trunks[:6])}{' ...' if len(open_trunks) > 6 else ''}; "
                                 "every VLAN, including unused ones, is carried and can be flooded. Limit trunks to the VLANs that are needed.", doc="harden"))
    if any("switchport mode access" in lines for lines in blocks.values()) and not any(l.startswith("storm-control") for lines in blocks.values() for l in lines):
        findings.append(_finding("SW-STORM-001", "info", "No storm-control on any port",
                                 "No interface has `storm-control`. A broadcast storm on an access port is not rate-limited.", doc="harden"))
    return findings


def _rules_device(env: dict[str, Any], licence: dict[str, Any], software: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in env["sensors"]:
        if item["problem"]:
            findings.append(_finding("SW-ENV-001", "medium", f"Sensor {item['name']} is {item['state']}", f"{item['name']} (location {item['location']}): {item['reading']}.", where=item["name"]))
    for item in env["fans"]:
        if item["problem"]:
            findings.append(_finding("SW-ENV-002", "high", f"Fan {item['fan']} on switch {item['switch']} is {item['state']}", f"Speed {item['speed']} rpm.", where=f"fan {item['fan']}"))
    for item in env["power_supplies"]:
        if item["problem"]:
            findings.append(_finding("SW-ENV-003", "high", f"Power supply {item['slot']} is {item['status']}", f"{item['pid']}: system power {item['system_power']}.", where=f"PSU {item['slot']}"))
    in_use = [row for row in licence["licenses"] if row["status"].upper() == "IN USE"]
    account = licence["smart_account"].strip().lower()
    if in_use and account in ("<none>", "none"):
        findings.append(_finding("SW-LIC-001", "info", "Licences in use, no Smart Account",
                                 f"{len(in_use)} licence(s) are IN USE but the device reports no Smart Account. Perpetual licences are not affected; subscription licences need registration or a usage report under Smart Licensing Using Policy.", doc="smart_license"))
    days = software.get("uptime_days") or 0
    if days >= 365:
        findings.append(_finding("SW-VER-001", "info", f"No reload for {software.get('uptime')}",
                                 f"Last reload: {software.get('last_reload_reason') or software.get('last_reload') or 'not reported'}. A switch that has been up this long runs a release from before that date; compare it with the release Cisco currently recommends for this platform."))
    return findings


def _is_nxos(clean: list[str]) -> bool:
    """True when the device itself runs NX-OS.

    The words "NX-OS" / "Nexus" also appear in a CDP neighbour's software banner (``show cdp neighbors
    detail``), so a Catalyst 9300X with a Nexus uplink was given NX-OS rules and asked for ``show vpc``.
    The device's own ``show version`` decides when the capture has one; only an excerpt without it falls
    back to looking for the words in the head of the capture."""
    own = max(capture_text.command_outputs(clean, [r"show ver(?:sion)?", r"sh ver(?:sion)?"]), key=len, default=[])
    if own:
        return any(re.search(r"Cisco Nexus Operating System|NX-OS", line) for line in own[:120])
    return any(re.search(r"NX-OS|Nexus", line) for line in clean[:3000])


# ---------------------------------------------------------------- entry point

def build_health(clean: list[str], vendor: str, *, interfaces: list[dict[str, Any]], port_channels: list[dict[str, Any]],
                 dhcp: dict[str, Any] | None = None) -> dict[str, Any]:
    nxos = _is_nxos(clean)
    family = "nxos" if (vendor.lower() == "cisco" and nxos) else vendor.lower() if vendor.lower() in ("huawei", "aruba") else ""
    if family:
        from . import health_other
        other = health_other.build(clean, family, interfaces=interfaces, port_channels=port_channels)
        if other is not None:
            return other
    if vendor.lower() != "cisco" or nxos:
        return {
            "supported": False,
            "scope": "Cisco IOS / IOS XE, NX-OS, Huawei VRP and ArubaOS-Switch",
            "note": "Health checks cover Cisco IOS / IOS XE, Cisco NX-OS, Huawei VRP / YunShan OS and ArubaOS-Switch captures. The other tabs show every table this capture contains.",
            "findings": [], "counts": {}, "stp": {}, "lacp": [], "environment": {"sensors": [], "fans": [], "power_supplies": [], "problems": 0},
            "licence": {"smart_account": "", "virtual_account": "", "licenses": [], "detail": {}}, "software": {}, "capture": {"missing": []},
        }

    config = _running_config(clean)
    top, blocks = _config_blocks(config)
    found = {label: _output(clean, pattern) for label, pattern, _adds in USEFUL_COMMANDS}
    stp = parse_stp_summary(found["show spanning-tree summary"])
    flags = parse_etherchannel_flags(found["show etherchannel summary"])
    lacp = parse_lacp_neighbors(found["show lacp neighbor"])
    env = parse_environment(found["show env all"])
    licence = parse_licence(found["show license summary"])
    # `show license usage` / `show license all`: entitlements, evaluation state and subscription terms
    licence["detail"] = licence_detail.build_licence_detail(clean)
    software = parse_software(_output(clean, r"sh(?:ow)? version") or [])

    # Member state and LACP partner next to each port-channel row (Port-Channel tab).
    lacp_by_port = {row["port"]: row for row in lacp}
    for item in port_channels:
        info = flags.get(item.get("name", ""))
        if info:
            item["member_states"] = [
                {"port": m["port"], "flag": m["flag"], "meaning": MEMBER_FLAGS.get(m["flag"], "")} for m in info["members"]]
        # service._enrich_port_channels turns the member list into "Gi1/0/1, Gi2/0/1" text.
        raw_members = item.get("members") or []
        names = [part.strip() for part in raw_members.split(",")] if isinstance(raw_members, str) else list(raw_members)
        partners = sorted({lacp_by_port[m]["partner_id"] for m in names if m in lacp_by_port})
        if partners:
            item["lacp_partner"] = ", ".join(partners)

    findings: list[dict[str, Any]] = []
    # Bundle state comes from show output and needs no configuration; the rules that
    # say something is *missing* from the configuration need the running-config.
    findings += _rules_channels(top, blocks, flags, lacp, found["show lacp neighbor"] is not None, interfaces)
    if config:
        findings += _rules_stp(top, blocks, stp)
        findings += _rules_management(top, blocks, dhcp or {}, interfaces)
    findings += _rules_device(env, licence, software)
    for item in licence_detail.licence_findings(licence["detail"]):
        findings.append(_finding(item["code"], item["severity"], item["title"], item["text"], where=item["where"], doc=item["doc"]))
    from . import iosxe_extras                       # CPU, memory, queue drops, BGP neighbors, route counts (the commands the collect list asks for)
    live = iosxe_extras.analyse(clean)
    findings += live["findings"]
    findings.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["code"], item["where"]))

    counts = {level: sum(1 for item in findings if item["severity"] == level) for level in SEVERITY_ORDER}
    missing = [{"command": label, "adds": adds} for label, _pattern, adds in USEFUL_COMMANDS if found[label] is None]
    if not config:
        missing.insert(0, {"command": "show running-config", "adds": "every configuration check on this tab"})
    return {
        "supported": True, "scope": "Cisco IOS / IOS XE", "family": "ios", "note": "",
        "findings": findings, "counts": counts, "stp": stp, "lacp": lacp, "environment": env,
        "licence": licence, "software": software, "capture": {"missing": missing, "config_found": bool(config)},
        "extra_tables": live["tables"], "extra_counts": live["counts"],
    }
