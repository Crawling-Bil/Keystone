"""Live switch state parsed from show-command output: interface state
(up / down / admin down), the ARP table and the MAC address table.

Interface state model
---------------------
Every interface ends up in exactly one of four states:

``up``          the port is administratively enabled and the link is up.
``down``        the port is enabled but has no link (cable unplugged, far end
                down, err-disabled, no transceiver ...). Needs attention.
``admin down``  the port was shut down on purpose (``shutdown`` on Cisco and
                Huawei, ``disable`` on ArubaOS-Switch). Intentional by
                definition: it is how an engineer parks a port.
``unknown``     the capture has no live state for the port and the config does
                not shut it down, so the only honest statement is "enabled,
                link state not captured".

How each vendor reports "administratively down" (the signal that is lost when
it is folded into plain "down"):

* Cisco IOS ``show ip interface brief``      Status = "administratively down"
* Cisco IOS ``show interfaces status``       Status = "disabled"
  ("err-disabled" is NOT intentional: the switch shut the port itself.)
* Cisco NX-OS ``show interface brief``       Reason = "Administratively down"
* Cisco NX-OS ``show ip interface brief``    "admin-down"
* Cisco NX-OS ``show interface status``      Status = "disabled"
* Huawei VRP ``display interface brief``     PHY = "*down"
* Huawei VRP ``display interface``           "current state : Administratively DOWN"
* ArubaOS-Switch ``show interfaces brief``   Enabled = "No"
* any vendor's running-config                ``shutdown`` / ``disable``

Vendor references (opened and read when this was written):
  Cisco IOS    err-disabled is a state the switch enters on its own and is listed by
               ``show interfaces status``; shutdown / no shutdown is the manual way out:
               https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/69980-errdisable-recovery.html
  Cisco IOS-XE ``show ip arp``, Age column: "-" marks an address local to the device:
               https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr/command/ipaddr-xe-3se-3850-cr-book/ipaddr-xe-3se-3850-cr-book_chapter_010.html
  Cisco NX-OS  a port that is enabled but disabled at runtime shows err-disabled, not
               administratively down; ``show interface status err-disabled``:
               https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/101x/configuration/interfaces/cisco-nexus-9000-nx-os-interfaces-configuration-guide-101x/b-cisco-nexus-9000-nx-os-interfaces-configuration-guide-93x_chapter_01110.html
  Aruba AOS-S  ``show interfaces brief`` columns (Port, Type, Enabled, Status ...) and
               ``show mac-address``:
               https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/KB/content/kb/sho-int-bri.htm
               https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/WC/content/wc/sho-mac-add-vla-por-mac-add-tun.htm

The vendor pages do not define every status word (for example Huawei's ``*down``
legend, Cisco ``disabled`` in ``show interfaces status`` or the NX-OS Reason text);
those meanings are taken from the legends printed by the devices themselves in the
Oct 2026 TAM captures, which tests/fixtures/real_captures keeps in masked form.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from . import show_tables
from .capture_text import best_output, find_blocks

UP = "up"
DOWN = "down"
ADMIN_DOWN = "admin down"
UNKNOWN = "unknown"

# --------------------------------------------------------------------------
# Interface naming
# --------------------------------------------------------------------------

_PREFIX_CANON = [
    (re.compile(r"^(?:tengigabitethernet|tengige|tengig|te)(?=\d)"), "te"),
    (re.compile(r"^(?:twentyfivegige|twentyfive|twe|25ge)(?=\d)"), "twe"),
    (re.compile(r"^(?:twogigabitethernet|tw)(?=\d)"), "tw"),
    (re.compile(r"^(?:fortygigabitethernet|fortygige|fo|40ge)(?=\d)"), "fo"),
    (re.compile(r"^(?:hundredgige|hu|100ge)(?=\d)"), "hu"),
    (re.compile(r"^(?:xgigabitethernet|xge)(?=\d)"), "xge"),
    (re.compile(r"^(?:gigabitethernet|gige|gig|gi|ge)(?=\d)"), "ge"),
    (re.compile(r"^(?:fastethernet|fa)(?=\d)"), "fa"),
    (re.compile(r"^(?:port-channel|portchannel|po|eth-trunk|ethtrunk|lag)(?=\d)"), "po"),
    (re.compile(r"^(?:vlanif|vlan|vl)(?=\d)"), "vlan"),
    (re.compile(r"^(?:loopback|lo)(?=\d)"), "lo"),
    (re.compile(r"^(?:ethernet|eth)(?=\d)"), "eth"),
    (re.compile(r"^(?:mgmt|meth)(?=\d)"), "mgmt"),
]


def interface_key(name: str) -> str:
    """Canonical lookup key so "Gi1/0/1", "GigabitEthernet1/0/1" and the
    Huawei "GE1/0/1" all meet, as do "Po1"/"Port-channel1"/"Eth-Trunk1" and
    "Eth1/1"/"Ethernet1/1"."""
    value = re.sub(r"\s+", "", (name or "").strip().lower())
    for pattern, canon in _PREFIX_CANON:
        if pattern.match(value):
            return pattern.sub(canon, value, count=1)
    return value


def _obs(name: str, state: str, detail: str, source: str, protocol: str = "", **extra: Any) -> dict[str, Any]:
    entry = {"name": name, "state": state, "detail": detail, "source": source, "protocol": protocol}
    entry.update(extra)
    return entry


# --------------------------------------------------------------------------
# Cisco IOS / NX-OS: "show interfaces status"
# --------------------------------------------------------------------------

_STATUS_WORDS = {
    "connected": (UP, "connected"),
    "up": (UP, "up"),
    "disabled": (ADMIN_DOWN, "disabled"),
    "notconnect": (DOWN, "notconnect"),
    "notconnec": (DOWN, "notconnect"),
    "err-disabled": (DOWN, "err-disabled"),
    "errdisabled": (DOWN, "err-disabled"),
    "err-disable": (DOWN, "err-disabled"),
    "inactive": (DOWN, "inactive (VLAN not active)"),
    "monitoring": (UP, "monitoring (SPAN destination)"),
    "suspnd": (DOWN, "suspended"),
    "suspended": (DOWN, "suspended"),
    "sfp-not-present": (DOWN, "no transceiver"),
    "sfpabsent": (DOWN, "no transceiver"),
    "xcvrabsen": (DOWN, "no transceiver"),
    "xcvrabsent": (DOWN, "no transceiver"),
    "nonparticipating": (DOWN, "nonparticipating"),
    "linkflape": (DOWN, "link flap error-disabled"),
    "down": (DOWN, "down"),
    "faulty": (DOWN, "faulty"),
    "noopermem": (DOWN, "no operational members"),
    "channeldo": (DOWN, "channel down"),
    "routed": (UP, "routed"),
}

_STATUS_HEADER_RE = re.compile(r"^\s*Port\s+(?:Name\s+)?Status\s+Vlan\b", re.IGNORECASE)
_DASH_RE = re.compile(r"^[\s\-+=]+$")


def _parse_interface_status_table(section: list[str]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    columns: dict[str, int] | None = None
    for line in section:
        if _STATUS_HEADER_RE.match(line):
            columns = {}
            for label in ("Name", "Status", "Vlan", "Duplex", "Speed", "Type"):
                position = line.find(label)
                if position >= 0:
                    columns[label] = position
            continue
        if columns is None or _DASH_RE.match(line):
            continue
        first_data_col = columns.get("Name", columns["Status"])
        port = line[:first_data_col].strip()
        if not port or " " in port:
            # Misaligned row: fall back to "<port> ... <known status word> ..."
            tokens = line.split()
            if not tokens:
                continue
            port = tokens[0]
            status_word = next((t for t in tokens[1:] if t.lower() in _STATUS_WORDS), "")
        else:
            end = columns.get("Vlan", len(line))
            status_word = line[columns["Status"]:end].strip().split(" ")[0] if len(line) > columns["Status"] else ""
            if status_word.lower() not in _STATUS_WORDS:
                tokens = line.split()
                status_word = next((t for t in tokens[1:] if t.lower() in _STATUS_WORDS), status_word)
        mapped = _STATUS_WORDS.get(status_word.lower())
        if not mapped:
            continue
        state, detail = mapped
        results[port] = _obs(port, state, detail, "show interfaces status", **_status_speed(line, columns))
    return results


def _speed_mbps(text: str) -> int | None:
    """Speed column of "show interfaces status": ``1000``, ``a-100``, ``10G``, ``a-10G`` -> Mbit/s; ``auto`` / blank -> None."""
    found = re.fullmatch(r"(?:a-)?(\d+)(G|M)?", text.strip(), re.IGNORECASE)
    if not found:
        return None
    value = int(found.group(1))
    unit = (found.group(2) or "").upper()
    return value * 1000 if unit == "G" else value


def _status_speed(line: str, columns: dict[str, int]) -> dict[str, Any]:
    """Duplex and speed of one row. An ``a-`` prefix means auto-negotiated (Cisco: "Ethernet 10/100/1000Mb half/full duplex
    auto-negotiation", https://www.cisco.com/c/en/us/support/docs/lan-switching/ethernet/10561-3.html); a bare number was
    configured by hand. ``auto`` alone means the port has not negotiated a rate (down).

    The two columns are found by their words, not by header position: NX-OS rows are not aligned with their header."""
    found = _DUPLEX_SPEED_RE.search(line)
    if not found:
        return {}
    duplex_text, speed_text = found.group(1).lower(), found.group(2)
    extra: dict[str, Any] = {}
    speed = _speed_mbps(speed_text)
    if speed:
        extra["speed_mbps"] = speed
        extra["speed_auto"] = speed_text.lower().startswith("a-")
    duplex = duplex_text.removeprefix("a-")
    if duplex in ("full", "half"):
        extra["duplex"] = duplex
        extra["duplex_auto"] = duplex_text.startswith("a-")
    return extra


_DUPLEX_SPEED_RE = re.compile(r"\s((?:a-)?(?:full|half|auto))\s+((?:a-)?(?:auto|\d+[GM]?))(?=\s|$)", re.IGNORECASE)


# --------------------------------------------------------------------------
# Cisco IOS: "show ip interface brief"
# --------------------------------------------------------------------------

_IOS_IP_BRIEF_ROW = re.compile(
    r"^(\S+)\s+(\S+)\s+(?:YES|NO)\s+\S+\s+(administratively down|up|down|deleted|standby|reset)\s+(up|down)\S*\s*$",
    re.IGNORECASE,
)
# NX-OS: "Vlan201   192.0.2.3   protocol-up/link-up/admin-up"
_NXOS_IP_BRIEF_ROW = re.compile(
    r"^(\S+)\s+(\S+)\s+protocol-(up|down)/link-(up|down)/admin-(up|down)\b",
    re.IGNORECASE,
)


def _parse_ip_interface_brief(section: list[str]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for raw_line in section:
        line = raw_line.strip()
        match = _IOS_IP_BRIEF_ROW.match(line)
        if match:
            name, ip_address, status, protocol = match.groups()
            status = status.lower()
            if status == "administratively down":
                state, detail = ADMIN_DOWN, "administratively down"
            elif status == "up" and protocol.lower() == "up":
                state, detail = UP, "up"
            elif status == "up":
                # Line is up but the line protocol is down: not forwarding
                # (LACP-suspended member, err-disabled by a protocol, no
                # keepalive ...). It needs attention, so it is "down".
                state, detail = DOWN, "line up, protocol down"
            else:
                state, detail = DOWN, status
            results[name] = _obs(
                name, state, detail, "show ip interface brief", protocol.lower(),
                ip_address="" if ip_address.lower() == "unassigned" else ip_address,
            )
            continue
        match = _NXOS_IP_BRIEF_ROW.match(line)
        if match:
            name, ip_address, protocol, link, admin = match.groups()
            if admin.lower() == "down":
                state, detail = ADMIN_DOWN, "admin-down"
            elif link.lower() == "down":
                state, detail = DOWN, "link-down"
            elif protocol.lower() == "down":
                state, detail = DOWN, "link up, protocol down"
            else:
                state, detail = UP, "up"
            results[name] = _obs(
                name, state, detail, "show ip interface brief", protocol.lower(),
                ip_address="" if ip_address.lower() == "unassigned" else ip_address,
            )
    return results


# --------------------------------------------------------------------------
# Cisco NX-OS: "show interface brief"
# --------------------------------------------------------------------------

# Ethernet / port-channel rows:
#   Eth1/12  --  eth  routed  down  Administratively down   auto(D) --
#   Eth1/1   1   eth  trunk   down  Link not connected      auto(D) --
#   Po1      1   eth  trunk   up    none                    a-10G(D)  lacp
_NXOS_BRIEF_ETH_ROW = re.compile(
    r"^(\S+)\s+(\S+)\s+(?:eth|port-channel|pc)\s+(\S+)\s+(up|down)\s+(.+?)\s{2,}\S+(?:\s+\S+)?\s*$",
    re.IGNORECASE,
)
# Vlan / loopback rows: "Vlan216   --   up   --"
_NXOS_BRIEF_VLAN_ROW = re.compile(r"^((?:Vlan|Lo|loopback|nve|Tunnel)\S*\d)\s+\S+\s+(up|down)\s+(.*)$", re.IGNORECASE)
# mgmt row: "mgmt0  --  up  192.0.2.26  1000  1500"
_NXOS_BRIEF_MGMT_ROW = re.compile(r"^(mgmt\d+)\s+\S+\s+(up|down)\s+(\S+)\s+\d+\s+\d+\s*$", re.IGNORECASE)


def _parse_nxos_interface_brief(section: list[str]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for raw_line in section:
        line = raw_line.strip()
        match = _NXOS_BRIEF_ETH_ROW.match(line)
        if match:
            name, _vlan, _mode, status, reason = match.groups()
            reason = reason.strip()
            if status.lower() == "up":
                state, detail = UP, "up"
            elif "administratively down" in reason.lower():
                state, detail = ADMIN_DOWN, "Administratively down"
            else:
                state, detail = DOWN, reason
            results[name] = _obs(name, state, detail, "show interface brief")
            continue
        match = _NXOS_BRIEF_MGMT_ROW.match(line)
        if match:
            name, status, _ip = match.groups()
            results[name] = _obs(name, UP if status.lower() == "up" else DOWN, status.lower(), "show interface brief")
            continue
        match = _NXOS_BRIEF_VLAN_ROW.match(line)
        if match:
            name, status, reason = match.groups()
            if status.lower() == "up":
                state, detail = UP, "up"
            elif "administratively down" in reason.lower():
                state, detail = ADMIN_DOWN, "Administratively down"
            else:
                state, detail = DOWN, reason.strip() or "down"
            results[name] = _obs(name, state, detail, "show interface brief")
    return results


# --------------------------------------------------------------------------
# ArubaOS-Switch: "show interfaces brief"
# --------------------------------------------------------------------------

# "1   100/1000T  | No  Yes  Up  1000FDx  MDI  off  0"
# "16  100/1000T  | No  No   Down 1000FDx  Auto off  0"  <- Enabled = No: disabled
_ARUBA_BRIEF_ROW = re.compile(r"^(\S+)\s+[^|]*?\|\s*(?:Yes|No)\s+(Yes|No)\s+(Up|Down)\b", re.IGNORECASE)
# "show interface status": "3   Up  Auto  100FDx  100/1000T  No  214" (link state only)
_ARUBA_STATUS_HEADER = re.compile(r"^\s*Port\s+Name\s+Status\s+Config-mode\b", re.IGNORECASE)
_ARUBA_STATUS_ROW = re.compile(r"^\s*(\S+)\s+(?:.*?\s)?(Up|Down)(?:\s+|$)", re.IGNORECASE)


def _parse_aruba_brief(section: list[str]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for raw_line in section:
        match = _ARUBA_BRIEF_ROW.match(raw_line.strip())
        if not match:
            continue
        port, enabled, link = match.groups()
        if link.lower() == "up":
            state, detail = UP, "Up"
        elif enabled.lower() == "no":
            state, detail = ADMIN_DOWN, "Enabled = No"
        else:
            state, detail = DOWN, "Down"
        results[port] = _obs(port, state, detail, "show interfaces brief")
    return results


def _parse_aruba_status(section: list[str]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    columns: dict[str, int] | None = None
    for line in section:
        if _ARUBA_STATUS_HEADER.match(line):
            columns = {label: line.find(label) for label in ("Port", "Name", "Status", "Config-mode")}
            continue
        if columns is None or _DASH_RE.match(line):
            continue
        port = line[: columns["Name"]].strip()
        status = line[columns["Status"]:columns["Config-mode"]].strip()
        if not port or status.lower() not in ("up", "down"):
            continue
        results[port] = _obs(
            port, UP if status.lower() == "up" else DOWN, status, "show interface status"
        )
    return results


# --------------------------------------------------------------------------
# Huawei VRP: "display interface brief" / "description" / "display ip interface brief"
# --------------------------------------------------------------------------

_HW_STATE_WORD = r"(?:\*|\^|!)?(?:up|down)(?:\([a-z]{1,2}\))?"
_HW_BRIEF_ROW = re.compile(
    rf"^\s*(\S+)\s+({_HW_STATE_WORD})\s+({_HW_STATE_WORD})\b(?:\s+\d+(?:\.\d+)?%\s+\d+(?:\.\d+)?%\s+\d+\s+\d+)?\s*(.*)$",
    re.IGNORECASE,
)
_HW_IP_BRIEF_ROW = re.compile(
    rf"^\s*(\S+)\s+(\S+)\s+({_HW_STATE_WORD})\s+({_HW_STATE_WORD})(?:\s+\S+)?\s*$",
    re.IGNORECASE,
)


def _hw_phy_state(phy: str) -> tuple[str, str]:
    phy = phy.lower()
    if phy.startswith("*"):
        return ADMIN_DOWN, "*down (administratively down)"
    if phy.startswith("^"):
        return DOWN, "^down (standby)"
    if phy.startswith("!"):
        return DOWN, "!down (FIB overload)"
    if phy.startswith("up"):
        return UP, phy
    return DOWN, phy


def _parse_huawei_interface_brief(section: list[str], source: str) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for raw_line in section:
        line = raw_line.strip()
        low = line.lower()
        if low.startswith(("interface", "phy:", "*down", "^down", "!down", "(", "inuti", "the number")):
            continue
        match = _HW_BRIEF_ROW.match(line)
        if not match:
            continue
        name, phy, protocol, _rest = match.groups()
        state, detail = _hw_phy_state(phy)
        proto = re.sub(r"^[*^!]", "", protocol.lower())
        if state == UP and proto.startswith("down"):
            # The physical link is up, so the port is "up". Huawei's Protocol
            # column is the IPv4/line protocol; a Vlanif without an IP address
            # is up/down by design, so it is noted, not turned into "down".
            detail = "phy up, protocol down"
        results[name] = _obs(name, state, detail, source, proto)
    return results


def _parse_huawei_ip_interface_brief(section: list[str]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for raw_line in section:
        line = raw_line.strip()
        low = line.lower()
        if low.startswith(("interface", "*down", "^down", "!down", "(", "the number")):
            continue
        match = _HW_IP_BRIEF_ROW.match(line)
        if not match:
            continue
        name, ip_address, phy, protocol = match.groups()
        state, detail = _hw_phy_state(phy)
        proto = re.sub(r"^[*^!]", "", protocol.lower())
        if state == UP and proto.startswith("down"):
            detail = "phy up, IPv4 protocol down (no IP address or not routable)"
        results[name] = _obs(
            name, state, detail, "display ip interface brief", proto,
            ip_address="" if ip_address.lower() == "unassigned" else ip_address,
        )
    return results


# --------------------------------------------------------------------------
# Long form: "show interfaces" / "display interface"
# --------------------------------------------------------------------------

_IOS_LONG_RE = re.compile(
    r"^(\S+) is (administratively down|down|up)(?:\s*\(([^)]*)\))?(?:, line protocol is (up|down)(?:\s*\(([^)]*)\))?)?",
    re.IGNORECASE,
)
_HW_LONG_RE = re.compile(
    r"^(\S+)\s+current state\s*:\s*(Administratively DOWN|DOWN|UP)\b", re.IGNORECASE
)


def _parse_long_interfaces(section: list[str]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for raw_line in section:
        line = raw_line.strip()
        match = _IOS_LONG_RE.match(line)
        if match:
            name, status, extra, protocol, proto_extra = match.groups()
            status = status.lower()
            if status == "administratively down":
                state, detail = ADMIN_DOWN, "administratively down"
            elif status == "up" and (protocol or "up").lower() == "up":
                state, detail = UP, "up"
            elif status == "up":
                state, detail = DOWN, f"line up, protocol down ({proto_extra})" if proto_extra else "line up, protocol down"
            else:
                state, detail = DOWN, (extra or proto_extra or "down")
            results[name] = _obs(name, state, detail, "show interfaces", (protocol or "").lower())
            continue
        match = _HW_LONG_RE.match(line)
        if match:
            name, status = match.groups()
            status = status.lower()
            if status.startswith("administratively"):
                state, detail = ADMIN_DOWN, "Administratively DOWN"
            elif status == "up":
                state, detail = UP, "UP"
            else:
                state, detail = DOWN, "DOWN"
            results[name] = _obs(name, state, detail, "display interface")
    return results


# --------------------------------------------------------------------------
# Command patterns
# --------------------------------------------------------------------------

_P_IF_STATUS = [r"sh(?:ow)? int(?:erfaces?)? stat(?:us)?"]
_P_IP_BRIEF = [r"sh(?:ow)? ip int(?:erface)? br(?:ief)?", r"sh(?:ow)? ip interfaces? brief"]
_P_IF_BRIEF = [r"sh(?:ow)? int(?:erfaces?)? br(?:ief)?"]
_P_HW_BRIEF = [r"dis(?:p(?:l(?:a(?:y)?)?)?)? int(?:erface)? br(?:ief)?"]
_P_HW_DESC = [r"dis(?:p(?:l(?:a(?:y)?)?)?)? int(?:erface)? desc(?:ription)?"]
_P_HW_IP_BRIEF = [r"dis(?:p(?:l(?:a(?:y)?)?)?)? ip int(?:erface)? br(?:ief)?"]
_P_LONG = [r"sh(?:ow)? int(?:erfaces?)?", r"dis(?:p(?:l(?:a(?:y)?)?)?)? int(?:erface)?"]

# Source priority: earlier wins when sources disagree on up vs down.
_PRIORITY = [
    "show interfaces status",
    "show interface brief",
    "show interfaces brief",
    "show interface status",
    "display interface brief",
    "display interface description",
    "show ip interface brief",
    "show interfaces description",
    "display ip interface brief",
    "show interfaces",
    "display interface",
    "show interface",
]


_P_CISCO_DESC = list(show_tables.PATTERNS["int_desc"])
_H_CISCO_DESC = (r"Interface\s+Status\s+Protocol\s+Description",)


def _parse_cisco_interface_description(section: list[str]) -> dict[str, dict[str, Any]]:
    """``show interface description`` (IOS / IOS XE): the state of every interface in two words, Status and Protocol.

    Same reading as ``show ip interface brief``: Status ``up`` with Protocol ``up`` is up, ``up`` / ``down`` is a link
    that does not forward (a VLAN interface without an active port, a suspended LACP member), ``admin down`` is a shutdown.
    """
    results: dict[str, dict[str, Any]] = {}
    for row in show_tables.parse_interface_descriptions(section):
        status, protocol = row["status"], row["protocol"]
        if not status:
            continue            # NX-OS prints only the description
        if status in ("admin down", "administratively down"):
            state, detail = ADMIN_DOWN, "administratively down"
        elif status == "up" and protocol == "up":
            state, detail = UP, "up"
        elif status == "up":
            state, detail = DOWN, "line up, protocol down"
        else:
            state, detail = DOWN, status
        results[row["interface"]] = _obs(row["interface"], state, detail, "show interfaces description", protocol)
    return results


def _collect(lines: list[str], patterns: list[str], parser, headers: tuple[str, ...] = ()) -> dict[str, dict[str, Any]]:
    """Parse every occurrence of a command (found by its echo AND by its
    table header) and merge them: all interfaces seen in any run are kept
    and, for an interface seen twice, the later run wins."""
    merged: dict[str, dict[str, Any]] = {}
    for _index, block in find_blocks(lines, patterns, headers):
        merged.update(parser(block))
    return merged


_H_IF_STATUS = (r"Port\s+(?:Name\s+)?Status\s+Vlan\s+Duplex",)
_H_ARUBA_STATUS = (r"Port\s+Name\s+Status\s+Config-mode",)
_H_IP_BRIEF = (r"Interface\s+IP-Address\s+OK\?\s+Method\s+Status\s+Protocol", r"Interface\s+IP Address\s+Interface Status")
_H_NXOS_BRIEF = (
    r"Ethernet\s+VLAN\s+Type\s+Mode\s+Status\s+Reason", r"Port-channel\s+VLAN\s+Type\s+Mode\s+Status\s+Reason",
    r"Port\s+VRF\s+Status\s+IP Address\s+Speed\s+MTU", r"Interface\s+Secondary VLAN\(Type\)\s+Status\s+Reason",
)
_H_ARUBA_BRIEF = (r"Port\s+Type\s+\|\s+Alert\s+Enabled\s+Status",)
_H_HW_BRIEF = (r"Interface\s+PHY\s+Protocol\s+InUti\s+OutUti",)
_H_HW_DESC = (r"Interface\s+PHY\s+Protocol\s+Description",)
_H_HW_IP_BRIEF = (r"Interface\s+IP Address/Mask\s+Physical\s+Protocol",)


def observe_interface_states(lines: list[str]) -> dict[str, list[dict[str, Any]]]:
    """All live observations per interface key, from every source present."""
    by_key: dict[str, list[dict[str, Any]]] = {}

    def add(parsed: dict[str, dict[str, Any]]) -> None:
        for name, entry in parsed.items():
            by_key.setdefault(interface_key(name), []).append(entry)

    add(_collect(lines, _P_IF_STATUS, _parse_interface_status_table, _H_IF_STATUS))
    add(_collect(lines, _P_IP_BRIEF, _parse_ip_interface_brief, _H_IP_BRIEF))
    # "show interface(s) brief" is NX-OS on a Nexus and ArubaOS-Switch on a
    # ProCurve; both row shapes are anchored so each parser ignores the other.
    add(_collect(lines, _P_IF_BRIEF, _parse_nxos_interface_brief, _H_NXOS_BRIEF))
    add(_collect(lines, _P_IF_BRIEF, _parse_aruba_brief, _H_ARUBA_BRIEF))
    add(_collect(lines, _P_IF_STATUS, _parse_aruba_status, _H_ARUBA_STATUS))
    add(_collect(lines, _P_HW_BRIEF, lambda s: _parse_huawei_interface_brief(s, "display interface brief"), _H_HW_BRIEF))
    add(_collect(lines, _P_HW_DESC, lambda s: _parse_huawei_interface_brief(s, "display interface description"), _H_HW_DESC))
    add(_collect(lines, _P_HW_IP_BRIEF, _parse_huawei_ip_interface_brief, _H_HW_IP_BRIEF))
    add(_collect(lines, _P_CISCO_DESC, _parse_cisco_interface_description, _H_CISCO_DESC))
    add(_collect(lines, _P_LONG, _parse_long_interfaces))
    return by_key


def add_observations(by_key: dict[str, list[dict[str, Any]]], observations: Iterable[dict[str, Any]]) -> None:
    """Add observations read elsewhere (ArubaOS-CX ``show interface``) to the per-interface lists."""
    for entry in observations:
        by_key.setdefault(interface_key(entry["name"]), []).append(entry)


def resolve_state(observations: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    """Collapse the observations of one interface into one live state.

    The highest-priority source decides up/down; any live source that says
    "admin down" wins over a plain "down" from another source (the port is
    parked on purpose even if one table only says "down")."""
    items = list(observations)
    if not items:
        return None

    def rank(entry: dict[str, Any]) -> int:
        try:
            return _PRIORITY.index(entry["source"])
        except ValueError:
            return len(_PRIORITY)

    items.sort(key=rank)
    chosen = dict(items[0])
    admin = next((e for e in items if e["state"] == ADMIN_DOWN), None)
    if admin is not None and chosen["state"] == DOWN:
        chosen = dict(admin)
    chosen["sources"] = sorted({e["source"] for e in items}, key=lambda s: _PRIORITY.index(s) if s in _PRIORITY else 99)
    if not chosen.get("protocol"):
        chosen["protocol"] = next((e["protocol"] for e in items if e.get("protocol")), "")
    if not chosen.get("ip_address"):
        chosen["ip_address"] = next((e.get("ip_address", "") for e in items if e.get("ip_address")), "")
    for extra_key in ("speed_mbps", "speed_auto", "duplex", "duplex_auto"):
        if extra_key not in chosen:
            value = next((e[extra_key] for e in items if extra_key in e), None)
            if value is not None:
                chosen[extra_key] = value
    states = {e["state"] for e in items}
    if UP in states and (DOWN in states or ADMIN_DOWN in states):
        chosen["conflict"] = True
    return chosen


# --------------------------------------------------------------------------
# Config-derived admin state ("shutdown" / ArubaOS-Switch "disable")
# --------------------------------------------------------------------------

_IF_HEADER_RE = re.compile(r"^\s*interface\s+(\S.*?)\s*$", re.IGNORECASE)
# Top-level statements that can only start a new section. Used to close an
# interface block when the capture lost its indentation.
_GLOBAL_STARTERS = re.compile(
    r"^(?:router|ip|ipv6|vlan|line|snmp-server|snmp-agent|hostname|sysname|spanning-tree|stp|aaa|banner|logging|"
    r"info-center|ntp|ntp-service|username|local-user|enable|service|class-map|policy-map|access-list|acl|crypto|"
    r"errdisable|vtp|boot|clock|archive|stack|user-interface|dhcp|dns|ssh|telnet|mac-address|lldp|cdp|"
    r"qos|traffic|diffserv|radius|tacacs|feature|vrf|vpc|end|return|module|trunk|password|timesync|"
    r"sntp|web-management|time|loop-protect|aruba-central|ntp server|domain)\b",
    re.IGNORECASE,
)


def _expand_aruba_ports(spec: str) -> list[str]:
    """ArubaOS-Switch lets one "interface" line name several ports:
    "15", "A1-A4", "1-3,7", "Trk1"."""
    ports: list[str] = []
    for part in re.split(r"\s*,\s*", spec.strip()):
        match = re.fullmatch(r"([A-Za-z]?)(\d+)-([A-Za-z]?)(\d+)", part)
        if match and match.group(1) == match.group(3):
            prefix, start, _prefix2, end = match.groups()
            if 0 <= int(end) - int(start) <= 512:
                ports.extend(f"{prefix}{n}" for n in range(int(start), int(end) + 1))
                continue
        if part:
            ports.append(part)
    return ports


def config_admin_state(lines: list[str], vendor: str = "") -> dict[str, dict[str, Any]]:
    """Per-interface admin state read from the running-config.

    Returns {interface_key: {"name", "admin_down", "keyword"}} for every
    interface block found. ``admin_down`` is True when the block holds
    ``shutdown`` (Cisco / Huawei / ArubaOS-CX) or ``disable`` (ArubaOS-
    Switch) and False after ``no shutdown`` / ``undo shutdown``."""
    aruba = vendor.strip().lower() == "aruba"
    results: dict[str, dict[str, Any]] = {}
    current: list[str] = []
    strict: bool | None = None  # True once the block's first body line is indented

    def close() -> None:
        nonlocal current, strict
        current, strict = [], None

    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        indented = raw[:1] in (" ", "\t")
        header = _IF_HEADER_RE.match(raw)
        if header and (not indented or not current):
            spec = header.group(1)
            close()
            current = _expand_aruba_ports(spec) if aruba else [spec]
            for name in current:
                results.setdefault(interface_key(name), {"name": name, "admin_down": False, "keyword": ""})
            continue
        if not current:
            continue
        if stripped in ("!", "#", "return") or (aruba and stripped.lower() == "exit"):
            close()
            continue
        if strict is None:
            strict = indented
        if strict and not indented:
            close()
            continue
        if not strict and not indented and _GLOBAL_STARTERS.match(stripped):
            close()
            continue
        word = re.sub(r"\s+", " ", stripped.lower())
        if word in ("shutdown", "disable"):
            for name in current:
                results[interface_key(name)].update(admin_down=True, keyword=word)
        elif word in ("no shutdown", "undo shutdown", "no disable"):
            for name in current:
                results[interface_key(name)].update(admin_down=False, keyword=word)
    return results


# --------------------------------------------------------------------------
# ARP table
# --------------------------------------------------------------------------

_RE_MAC_DOTTED = r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
_RE_MAC_HUAWEI = r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
_RE_MAC_ARUBA = r"[0-9a-fA-F]{6}-[0-9a-fA-F]{6}"
_RE_IP = r"\d{1,3}(?:\.\d{1,3}){3}"

# IOS: "Internet  192.0.2.105   65   0011.2233.4455  ARPA   Vlan10"
_ARP_IOS = re.compile(
    rf"^Internet\s+({_RE_IP})\s+(\S+)\s+({_RE_MAC_DOTTED}|Incomplete)\s+(\S+)(?:\s+(\S+))?\s*$", re.IGNORECASE
)
# NX-OS: "192.0.2.2   00:01:02  0011.2233.4466  Vlan218   +"
_ARP_NXOS = re.compile(
    rf"^({_RE_IP})\s+(\d{{1,3}}:\d{{2}}:\d{{2}}|\d+(?:\.\d+)?|-)\s+({_RE_MAC_DOTTED}|INCOMPLETE?)\s+(\S+)(?:\s+(\S+))?\s*$", re.IGNORECASE
)
# ArubaOS-Switch: "192.0.2.1   001122-334455   dynamic   25"
_ARP_ARUBA = re.compile(rf"^({_RE_IP})\s+({_RE_MAC_ARUBA})\s+(\S+)\s+(\S+)\s*$", re.IGNORECASE)
# Huawei: "192.0.2.1   0011-2233-4455   10   D/25   Eth-Trunk1"  (older VRP: EXPIRE(M) TYPE=DYNAMIC)
#         "192.0.2.11  0011-2233-4466        I      Vlanif25"
_ARP_HUAWEI = re.compile(
    rf"^({_RE_IP})\s+({_RE_MAC_HUAWEI}|Incomplete)\s+(?:(\d+)\s+)?([A-Za-z]+(?:-\S+)?)(?:/(\S+))?\s+(\S+)(?:\s+(\S+))?\s*$",
    re.IGNORECASE,
)

_P_ARP = [r"sh(?:ow)? ip arp", r"sh(?:ow)? arp", r"dis(?:p(?:l(?:a(?:y)?)?)?)? arp"]
_HUAWEI_ARP_TYPE = {"D": "dynamic", "S": "static", "I": "interface", "O": "openflow", "R": "remote"}


def _parse_arp_section(section: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_line in section:
        line = raw_line.strip()
        m = _ARP_IOS.match(line)
        if m:
            ip, age, mac, _encap, interface = m.groups()
            incomplete = mac.lower().startswith("incomplet")
            # Age "-" means the entry never ages out: the switch's own
            # address on that interface, or a static ARP entry.
            kind = "incomplete" if incomplete else ("static" if age == "-" else "dynamic")
            rows.append({
                "ip_address": ip, "mac_address": "" if incomplete else mac, "age": age,
                "interface": interface or "", "type": kind, "vlan": "",
                "state": "incomplete" if incomplete else "resolved",
            })
            continue
        m = _ARP_NXOS.match(line)
        if m:
            ip, age, mac, interface, flags = m.groups()
            incomplete = mac.lower().startswith("incomplet")
            rows.append({
                "ip_address": ip, "mac_address": "" if incomplete else mac, "age": age,
                "interface": interface, "type": "incomplete" if incomplete else ("static" if age == "-" else "dynamic"),
                "vlan": "", "state": "incomplete" if incomplete else "resolved", "flags": flags or "",
            })
            continue
        m = _ARP_ARUBA.match(line)
        if m:
            ip, mac, kind, port = m.groups()
            rows.append({
                "ip_address": ip, "mac_address": mac, "age": "", "interface": port,
                "type": kind.lower(), "vlan": "", "state": "resolved",
            })
            continue
        m = _ARP_HUAWEI.match(line)
        if m:
            ip, mac, expire, kind, vlan, interface, _vpn = m.groups()
            incomplete = mac.lower().startswith("incomplet")
            rows.append({
                "ip_address": ip, "mac_address": "" if incomplete else mac, "age": expire or "",
                "interface": interface,
                "type": "incomplete" if incomplete else (
                    _HUAWEI_ARP_TYPE.get(kind.upper(), kind.lower()) if len(kind) <= 2 else kind.lower()
                ),
                "vlan": vlan if vlan and vlan != "--" else "",
                "state": "incomplete" if incomplete else "resolved",
            })
    return rows


_H_ARP = (
    r"Protocol\s+Address\s+Age\s*\(min\)\s+Hardware Addr\s+Type\s+Interface",
    r"Address\s+Age\s+MAC Address\s+Interface\s+Flags",
    r"IP Address\s+MAC Address\s+Type\s+Port\b",
    r"IP ADDRESS\s+MAC ADDRESS\s+EXP",
)


# Totals the device prints at the end / top of the SAME output. If the table
# holds fewer rows than the device says it printed, the capture lost lines
# (terminal scrollback, a paused --More-- session, a dropped log chunk), and the
# analyzer must say so instead of quietly showing a partial table as complete.
_ARP_TOTALS = (
    (re.compile(r"^\s*Total number of entries:\s*(\d+)", re.IGNORECASE), "Total number of entries"),
    (re.compile(r"^\s*Total:\s*(\d+)\s+Dynamic:", re.IGNORECASE), "Total"),
)
_MAC_TOTALS = (
    (re.compile(r"^\s*Total Mac Addresses for this criterion:\s*(\d+)", re.IGNORECASE), "Total Mac Addresses for this criterion"),
    (re.compile(r"^\s*Total items(?: displayed)?\s*[:=]\s*(\d+)", re.IGNORECASE), "Total items"),
)


def _reported_total(section: list[str], patterns) -> tuple[int | None, str]:
    for line in section:
        for pattern, label in patterns:
            match = pattern.match(line)
            if match:
                return int(match.group(1)), label
    return None, ""


def _best_block(blocks: list[tuple[int, list[str]]], counter) -> tuple[int, list[str]]:
    """The occurrence with the most parsed rows (ties go to the later run)."""
    best_index, best, best_count = 0, [], -1
    for index, block in blocks:
        count = counter(block)
        if count >= best_count and (count > 0 or best_count < 0):
            best_index, best, best_count = index, block, count
    return best_index, best


def _table_meta(section: list[str], parsed: int, patterns, preface: list[str] | None = None) -> dict[str, Any]:
    # ``preface`` = the few lines printed before a block that was found by its
    # table header (NX-OS prints "Total number of entries: 204" ABOVE the header).
    reported, source = _reported_total(list(preface or []) + section, patterns)
    return {
        "reported": reported,
        "source": source,
        "parsed": parsed,
        "complete": reported is None or parsed >= reported,
        # False when the capture has no such command at all (an empty table then means
        # "not captured", not "the device has no entries").
        "captured": True,
    }


def parse_arp_with_meta(lines: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    blocks = find_blocks(lines, _P_ARP, _H_ARP)
    if not blocks:
        return [], {"reported": None, "source": "", "parsed": 0, "complete": True, "captured": False}
    start, chosen = _best_block(blocks, lambda s: len(_parse_arp_section(s)))
    parsed_rows = _parse_arp_section(chosen)
    seen: set[tuple[str, str, str]] = set()
    rows: list[dict[str, Any]] = []
    for row in parsed_rows:
        key = (row["ip_address"], row["mac_address"], row["interface"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
    return rows, _table_meta(chosen, len(parsed_rows), _ARP_TOTALS, lines[max(0, start - 4):start])


def parse_arp(lines: list[str]) -> list[dict[str, Any]]:
    return parse_arp_with_meta(lines)[0]


# ARP of a named VRF: "show ip arp vrf WAN", "show arp vrf 1", "show ip arp vrf all" (NX-OS, one "IP ARP Table for context X" section per VRF),
# Huawei "display arp vpn-instance X".  The plain table above is the default VRF; the Topology Builder reads both.
_P_ARP_VRF = [r"sh(?:ow)? ip arp vrf \S+", r"sh(?:ow)? arp vrf \S+", r"dis(?:p(?:l(?:a(?:y)?)?)?)? arp vpn-instance \S+"]
_ARP_VRF_IN_COMMAND = re.compile(r"(?:vrf|vpn-instance)\s+(\S+)", re.IGNORECASE)
_ARP_CONTEXT = re.compile(r"IP ARP Table for context\s+(\S+)", re.IGNORECASE)


def parse_arp_vrf(lines: list[str]) -> list[dict[str, Any]]:
    """ARP rows of every ``show ip arp vrf <name>`` block, each row tagged with its VRF; empty when the capture holds none."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for start, block in find_blocks(lines, _P_ARP_VRF):
        found = _ARP_VRF_IN_COMMAND.search(lines[start])
        base = found.group(1) if found else ""
        base = "" if base.lower() == "all" else base
        sections: list[tuple[str, list[str]]] = [(base, [])]
        for line in block:
            context = _ARP_CONTEXT.search(line)
            if context:
                sections.append((context.group(1), []))
            else:
                sections[-1][1].append(line)
        for vrf, section in sections:
            for row in _parse_arp_section(section):
                key = (vrf, row["ip_address"], row["mac_address"], row["interface"])
                if key not in seen:
                    seen.add(key)
                    rows.append({**row, "vrf": vrf})
    return rows


# --------------------------------------------------------------------------
# MAC address table
# --------------------------------------------------------------------------

# IOS: " All    0100.0ccc.cccc    STATIC      CPU" / "  10    0011.2233.4455    DYNAMIC     Gi1/0/1"
_MAC_IOS = re.compile(rf"^[*+]?\s*(All|\d{{1,4}})\s+({_RE_MAC_DOTTED})\s+(\S+)\s+(\S.*?)\s*$", re.IGNORECASE)
# NX-OS: "*  201     0011.2233.4455   dynamic  0         F      F    Eth1/3"
_MAC_NXOS = re.compile(
    rf"^[*+GOC~]?\s*(\d{{1,4}}|-)\s+({_RE_MAC_DOTTED})\s+(\S+)\s+(\S+)\s+([FT-])\s+([FT-])\s+(\S.*?)\s*$", re.IGNORECASE
)
# ArubaOS-Switch: "001122-334455     25    213"
_MAC_ARUBA_ROW = re.compile(rf"^\s*({_RE_MAC_ARUBA})\s+(\S+)\s+(\d{{1,4}})\s*$", re.IGNORECASE)
# Huawei: "0011-2233-4455 1/-/-         10GE1/0/2           dynamic            8720"
_MAC_HUAWEI_ROW = re.compile(
    rf"^[*#]?\s*({_RE_MAC_HUAWEI})\s+(\d+|-)(?:/[^\s/]+)*\s+(\S+)\s+(\S+)(?:\s+(\d+))?\s*$", re.IGNORECASE
)

_P_MAC = [
    r"sh(?:ow)? mac address-table",
    r"sh(?:ow)? mac-address-table",
    r"sh(?:ow)? mac-address",
    r"sh(?:ow)? mac address-table dynamic",
    r"dis(?:p(?:l(?:a(?:y)?)?)?)? mac-address",
]


def _parse_mac_section(section: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    protocols_style = any(re.match(r"^\s*Vlan\s+Mac Address\s+Type\s+Protocols", line, re.IGNORECASE) for line in section)
    for raw_line in section:
        line = raw_line.rstrip()
        m = _MAC_NXOS.match(line.lstrip(" ") if line[:1] == " " else line)
        if m:
            vlan, mac, kind, age, _secure, _ntfy, port = m.groups()
            rows.append({"vlan": vlan, "mac_address": mac, "type": kind.lower(), "interface": port, "age": age})
            continue
        m = _MAC_IOS.match(line)
        if m:
            vlan, mac, kind, rest = m.groups()
            port = rest.split()[-1] if protocols_style else rest
            rows.append({"vlan": vlan, "mac_address": mac, "type": kind.lower(), "interface": port, "age": ""})
            continue
        m = _MAC_ARUBA_ROW.match(line)
        if m:
            mac, port, vlan = m.groups()
            rows.append({"vlan": vlan, "mac_address": mac, "type": "", "interface": port, "age": ""})
            continue
        m = _MAC_HUAWEI_ROW.match(line)
        if m:
            mac, vlan, port, kind, age = m.groups()
            rows.append({
                "vlan": "" if vlan == "-" else vlan, "mac_address": mac, "type": kind.lower(),
                "interface": port, "age": age or "",
            })
    return rows


_H_MAC = (
    r"Vlan\s+Mac Address\s+Type\s+(?:Ports|Protocols\s+Port)",
    r"VLAN\s+MAC Address\s+Type\s+age\s+Secure\s+NTFY\s+Ports",
    r"MAC Address\s+Port\s+VLAN\s*$",
    r"MAC Address\s+VLAN/VSI(?:/BD)?\s+Learned-From\s+Type",
)


def is_system_mac(row: dict[str, Any]) -> bool:
    """True for the switch's own entries: Catalyst CPU rows ("All 0100.0ccc.cccc
    STATIC CPU" - protocol multicast and the box's own MACs) and NX-OS gateway /
    supervisor rows (``sup-eth1(R)``). They exist on every switch by design, so a
    before/after comparison must not report them as hosts that went missing."""
    port = str(row.get("interface", "")).strip().lower()
    return port == "cpu" or port.startswith("sup-eth") or str(row.get("vlan", "")).strip().lower() == "all"


def parse_mac_table_with_meta(lines: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    blocks = find_blocks(lines, _P_MAC, _H_MAC)
    if not blocks:
        return [], {"reported": None, "source": "", "parsed": 0, "complete": True, "captured": False}
    start, chosen = _best_block(blocks, lambda s: len(_parse_mac_section(s)))
    parsed_rows = _parse_mac_section(chosen)
    seen: set[tuple[str, str, str]] = set()
    rows: list[dict[str, Any]] = []
    for row in parsed_rows:
        key = (row["vlan"], row["mac_address"], row["interface"])
        if key in seen:
            continue
        seen.add(key)
        row["system"] = is_system_mac(row)
        rows.append(row)
    return rows, _table_meta(chosen, len(parsed_rows), _MAC_TOTALS, lines[max(0, start - 4):start])


def parse_mac_table(lines: list[str]) -> list[dict[str, Any]]:
    return parse_mac_table_with_meta(lines)[0]
