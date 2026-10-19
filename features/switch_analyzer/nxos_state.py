"""Nexus state commands that the collect list marks "not parsed yet": modules, features, boot variables, reset reasons, cores and crashed
processes, switchport modes, interface error counters, transceiver DOM, port-channel membership, vPC orphan ports, spanning-tree roots, VRFs and syslog servers.

Every layout below was read from real NX-OS 10.4(5) and 10.5(4) captures of Nexus 93108TC-FX and 93180YC-FX3 switches (a vPC aggregation pair and four vPC
top-of-rack switches).  Each parser takes the lines of one command and returns plain rows; ``analyse`` turns them into the tables the Single Device page adds
to its tabs and into findings that use only what the device itself prints (an alarm flag, a counter that is not zero, a status that is not ok).  A command
that was not captured, or that the device rejected, adds nothing.

Sources (pages found by search while writing this module):

* Cisco, Cisco Nexus 9000 Series NX-OS Interfaces Configuration Guide, Release 10.4(x), Configuring Basic Interface Parameters:
  https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/configuration/interfaces/cisco-nexus-9000-series-nx-os-interfaces-configuration-guide-release-104x/m_configuring_basic_interface_parameters_93x.html
* Cisco, Cisco Nexus 9000 Series NX-OS Layer 2 Switching Configuration Guide, Release 10.4(x):
  https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/configuration/layer-2-switching/cisco-nexus-9000-series-nx-os-layer-2-switching-configuration-guide-104x/cisco-nexus-9000-series-nx-os-layer-2-switching-configuration-guide-104x_index.html
* Cisco, Troubleshoot Unexpected Reloads or Crashes on Nexus 9000 (``show cores``, ``show system reset-reason``, ``show processes log``):
  https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/221551-troubleshoot-unexpected-reloads-or-crash.html
* Cisco, Cisco Nexus 9000 Series NX-OS Troubleshooting Guide, Release 10.4(x), Troubleshooting Installations, Upgrades, and Reboots:
  https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/troubleshooting/cisco-nexus-9000-series-nx-os-troubleshooting-guide-104x/m-troubleshooting-installations-upgrades-and-reboots.html
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text

DOCS = {
    "interfaces": ("Cisco Nexus 9000 Series NX-OS Interfaces Configuration Guide, Release 10.4(x) - Configuring Basic Interface Parameters",
                   "https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/configuration/interfaces/cisco-nexus-9000-series-nx-os-interfaces-configuration-guide-release-104x/m_configuring_basic_interface_parameters_93x.html"),
    "stp": ("Cisco Nexus 9000 Series NX-OS Layer 2 Switching Configuration Guide, Release 10.4(x)",
            "https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/configuration/layer-2-switching/cisco-nexus-9000-series-nx-os-layer-2-switching-configuration-guide-104x/cisco-nexus-9000-series-nx-os-layer-2-switching-configuration-guide-104x_index.html"),
    "troubleshooting": ("Cisco - Troubleshoot Unexpected Reloads or Crashes on Nexus 9000",
                        "https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/221551-troubleshoot-unexpected-reloads-or-crash.html"),
    "install": ("Cisco Nexus 9000 Series NX-OS Troubleshooting Guide, Release 10.4(x) - Troubleshooting Installations, Upgrades, and Reboots",
                "https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/troubleshooting/cisco-nexus-9000-series-nx-os-troubleshooting-guide-104x/m-troubleshooting-installations-upgrades-and-reboots.html"),
}

_ERROR = re.compile(r"^\s*(?:%|\^\s*$|invalid (?:input|command)|error:)", re.IGNORECASE)


def _runs(clean: list[str], pattern: str) -> list[list[str]]:
    out = []
    for block in capture_text.command_outputs(clean, [pattern]):
        if block and not any(_ERROR.match(line) for line in block[:3]):
            out.append(block)
    return out


def _fullest(clean: list[str], pattern: str, rows) -> list[str]:
    best: list[str] = []
    best_rows = -1
    for block in _runs(clean, pattern):
        count = rows(block)
        if count > best_rows:
            best, best_rows = block, count
    return best


# ------------------------------------------------------------------ show feature

def parse_features(lines: list[str]) -> list[dict[str, Any]]:
    """``show feature``: one row per feature instance (``eigrp  1  disabled``)."""
    rows = []
    for line in lines:
        match = re.match(r"^(\S+)\s+(\d+)\s+(enabled|disabled)\s*$", line.strip())
        if match:
            rows.append({"feature": match[1], "instance": int(match[2]), "state": match[3]})
    return rows


# ------------------------------------------------------------------ show module

def parse_modules(lines: list[str]) -> list[dict[str, Any]]:
    """``show module``: the module table plus its Sw / Hw and serial tables, joined on the module number."""
    modules: dict[int, dict[str, Any]] = {}
    section = ""
    for line in lines:
        text = line.strip()
        if re.match(r"^Mod\s+Ports\s+Module-Type", text):
            section = "main"
            continue
        if re.match(r"^Mod\s+Sw\s+Hw", text):
            section = "versions"
            continue
        if re.match(r"^Mod\s+MAC-Address", text):
            section = "serials"
            continue
        if re.match(r"^Mod\s+Online Diag", text) or re.match(r"^Mod\s+Diag", text):
            section = "diag"
            continue
        if section == "main":
            match = re.match(r"^(\d+)\s+(\d+)\s+(.+?)\s{2,}(\S+)\s+(.+?)\s*$", text)
            if match:
                modules[int(match[1])] = {"module": int(match[1]), "ports": int(match[2]), "type": match[3].strip(), "model": match[4], "status": match[5].strip()}
        elif section == "versions":
            match = re.match(r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", text)
            if match and int(match[1]) in modules:
                modules[int(match[1])].update({"software": match[2], "hardware": match[3], "slot": match[4]})
        elif section == "serials":
            match = re.match(r"^(\d+)\s+(.+?)\s{2,}(\S+)\s*$", text)
            if match and int(match[1]) in modules:
                modules[int(match[1])].update({"mac": match[2].strip(), "serial": match[3]})
    return [modules[key] for key in sorted(modules)]


# ------------------------------------------------------------------ show boot

def parse_boot(lines: list[str]) -> dict[str, Any]:
    """``show boot``: the boot variables now and for the next reload."""
    info: dict[str, Any] = {"current": {}, "next": {}}
    target = ""
    for line in lines:
        text = line.strip()
        if text.startswith("Current Boot Variables"):
            target = "current"
        elif text.startswith("Boot Variables on next reload"):
            target = "next"
        elif target:
            match = re.match(r"^(NXOS|Kickstart|System|BIOS) variable\s*=\s*(\S+)", text, re.IGNORECASE)
            if match:
                info[target][match[1].lower()] = match[2]
                continue
            match = re.match(r"^Boot POAP\s+(Enabled|Disabled)", text, re.IGNORECASE)
            if match:
                info[target]["poap"] = match[1].lower()
    return info if info["current"] or info["next"] else {}


def image_version(image: str) -> str:
    """``bootflash:/nxos64-cs.10.5.4.M.bin`` -> ``10.5(4)``; ``nxos.9.3.8.bin`` -> ``9.3(8)``; '' when the name has no version."""
    match = re.search(r"\.(\d+)\.(\d+)\.(\d+)(?:\.[A-Za-z])?\.bin$", image)
    return f"{match[1]}.{match[2]}({match[3]})" if match else ""


# ------------------------------------------------------------------ show system reset-reason

def parse_reset_reason(lines: list[str]) -> list[dict[str, str]]:
    """``show system reset-reason``: numbered entries newest first (``1) At ... after Tue Jun 23 14:46:06 2026`` / Reason / Service / Version)."""
    rows: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in lines:
        text = line.strip()
        match = re.match(r"^(\d+)\)\s+At\s+\d+\s+usecs after\s+(.+)$", text)
        if match:
            current = {"index": match[1], "time": match[2].strip(), "reason": "", "service": "", "version": ""}
            rows.append(current)
            continue
        if current is None:
            continue
        for key, label in (("reason", "Reason:"), ("service", "Service:"), ("version", "Version:")):
            if text.startswith(label):
                current[key] = text[len(label):].strip()
    return rows


# ------------------------------------------------------------------ show cores / show processes log

def parse_cores(lines: list[str]) -> list[dict[str, str]]:
    """``show cores``: one row per core file; the table is empty when nothing crashed."""
    rows = []
    for line in lines:
        match = re.match(r"^(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d{4}-\d{2}-\d{2}\s+\S+)\s*$", line.strip())
        if match:
            rows.append({"vdc": match[1], "module": match[2], "instance": match[3], "process": match[4], "pid": match[5], "time": match[6]})
    return rows


def parse_processes_log(lines: list[str]) -> list[dict[str, str]]:
    """``show processes log``: ``1  ntp  1234  N  Y  N  2026-10-01 10:00:00`` (VDC, process, PID, normal-exit, stack, core, time)."""
    rows = []
    for line in lines:
        match = re.match(r"^(\d+)\s+(\S+)\s+(\d+)\s+([YN])\s+([YN])\s+([YN])\s+(.+?)\s*$", line.strip())
        if match:
            rows.append({"vdc": match[1], "process": match[2], "pid": match[3], "normal_exit": match[4], "stack": match[5], "core": match[6], "time": match[7]})
    return rows


# ------------------------------------------------------------------ show interface switchport

def parse_switchport(lines: list[str]) -> list[dict[str, str]]:
    """``show interface switchport``: one record per ``Name:`` block (mode, access VLAN, native VLAN, allowed VLANs)."""
    rows: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in lines:
        text = line.strip()
        match = re.match(r"^Name:\s*(\S+)", text)
        if match:
            current = {"interface": match[1], "switchport": "", "mode": "", "access_vlan": "", "native_vlan": "", "allowed": ""}
            rows.append(current)
            continue
        if current is None:
            continue
        for key, label in (("switchport", "Switchport:"), ("mode", "Operational Mode:"), ("access_vlan", "Access Mode VLAN:"),
                           ("native_vlan", "Trunking Native Mode VLAN:"), ("allowed", "Trunking VLANs Allowed:")):
            if text.startswith(label):
                current[key] = text[len(label):].strip()
    return rows


# ------------------------------------------------------------------ show interface counters errors

_PHYSICAL_ERRORS = ("Align-Err", "FCS-Err", "Xmit-Err", "Rcv-Err", "UnderSize", "Runts", "Giants", "Symbol-Err", "IntMacTx-Er", "IntMacRx-Er", "Late-Col", "Exces-Col")


def parse_counters_errors(lines: list[str]) -> list[dict[str, Any]]:
    """``show interface counters errors``: NX-OS prints up to three tables (Align / FCS / Xmit / Rcv / UnderSize / OutDiscards, then collisions and Runts, then
    Giants / SQETest / Deferred / IntMac / Symbol); the counters of one port are merged into one row (``--`` = not supported on that port)."""
    columns: list[str] = []
    by_port: dict[str, dict[str, int | None]] = {}
    for line in lines:
        text = line.strip()
        if text.startswith("Port") and re.search(r"[A-Za-z]-[A-Za-z]|Runts|Giants|UnderSize", text):
            columns = text.split()[1:]
            continue
        if not columns:
            continue
        parts = text.split()
        if len(parts) == len(columns) + 1 and all(re.fullmatch(r"\d+|--", value) for value in parts[1:]):
            counters = by_port.setdefault(parts[0], {})
            counters.update({name: (int(value) if value != "--" else None) for name, value in zip(columns, parts[1:])})
    return [{"port": port, "counters": counters} for port, counters in by_port.items()]


# ------------------------------------------------------------------ show interface transceiver details

_DOM_ROWS = {"Temperature": "temperature", "Voltage": "voltage", "Current": "current", "Tx Power": "tx_power", "Rx Power": "rx_power"}
_NUMBER = r"(-?\d+(?:\.\d+)?|N/A)"


def parse_transceiver_details(lines: list[str]) -> list[dict[str, Any]]:
    """``show interface transceiver details``: per port the optic identity and, when it has DOM, current / alarm / warning thresholds.

    Each DOM row is ``Rx Power  -3.36 dBm  2.00 dBm  -13.90 dBm  -1.00 dBm  -9.90 dBm`` = current, high alarm, low alarm, high warning, low warning.  A
    ``--`` / ``++`` / ``-`` / ``+`` flag the device prints right after the current value says it is outside a threshold.
    """
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in lines:
        text = line.strip()
        port = re.match(r"^(Ethernet\d+/\d+(?:/\d+)?)$", text)
        if port:
            current = {"port": port[1], "present": None, "type": "", "name": "", "part": "", "serial": "", "dom": False, "readings": {}}
            rows.append(current)
            continue
        if current is None:
            continue
        if text.startswith("transceiver is not present"):
            current["present"] = False
        elif text.startswith("transceiver is not applicable"):
            current["present"] = None
        elif text.startswith("transceiver is present"):
            current["present"] = True
        elif text.startswith("type is "):
            current["type"] = text[8:].strip()
        elif text.startswith("name is "):
            current["name"] = text[8:].strip()
        elif text.startswith("part number is "):
            current["part"] = text[15:].strip()
        elif text.startswith("serial number is "):
            current["serial"] = text[17:].strip()
        elif text.startswith("DOM is not supported"):
            current["dom"] = False
        else:
            match = re.match(rf"^(Temperature|Voltage|Current|Tx Power|Rx Power)\s+{_NUMBER}\s*(?:[A-Za-z]+)?\s*([+\-]{{1,2}})?\s+{_NUMBER}\s*[A-Za-z]*\s+{_NUMBER}\s*[A-Za-z]*\s+{_NUMBER}\s*[A-Za-z]*\s+{_NUMBER}\s*[A-Za-z]*\s*$", text)
            if match:
                def number(value: str) -> float | None:
                    return None if value == "N/A" else float(value)
                current["dom"] = True
                current["readings"][_DOM_ROWS[match[1]]] = {"value": number(match[2]), "flag": match[3] or "", "alarm_high": number(match[4]), "alarm_low": number(match[5]),
                                                           "warn_high": number(match[6]), "warn_low": number(match[7])}
    return rows


def dom_state(reading: dict[str, Any]) -> str:
    """alarm / warning / ok / n/a for one DOM reading, from the thresholds the optic itself reports."""
    value = reading.get("value")
    if value is None:
        return "n/a"
    flag = reading.get("flag", "")
    if flag in ("++", "--") or (reading.get("alarm_high") is not None and value > reading["alarm_high"]) or (reading.get("alarm_low") is not None and value < reading["alarm_low"]):
        return "alarm"
    if flag in ("+", "-") or (reading.get("warn_high") is not None and value > reading["warn_high"]) or (reading.get("warn_low") is not None and value < reading["warn_low"]):
        return "warning"
    return "ok"


# ------------------------------------------------------------------ show port-channel database

def parse_port_channel_database(lines: list[str]) -> list[dict[str, Any]]:
    """``show port-channel database``: per bundle the member count, the first operational port and each member's mode and state."""
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in lines:
        text = line.strip()
        head = re.match(r"^(port-channel\d+)$", text)
        if head:
            current = {"channel": head[1], "update": "", "total": 0, "up": 0, "first": "", "age": "", "members": []}
            rows.append(current)
            continue
        if current is None:
            continue
        match = re.match(r"^(\d+) ports? in total,\s*(\d+) ports? up", text)
        if match:
            current["total"], current["up"] = int(match[1]), int(match[2])
            continue
        if text.startswith("Last membership update is "):
            current["update"] = text[len("Last membership update is "):].rstrip(".")
        elif text.startswith("First operational port is "):
            current["first"] = text[len("First operational port is "):].strip()
        elif text.startswith("Age of the port-channel is "):
            current["age"] = text[len("Age of the port-channel is "):].strip()
        member = re.match(r"^(?:Ports:\s+)?(Ethernet\d+/\d+(?:/\d+)?)\s+\[(\S+)\s*\]\s+\[(\S+)\]\s*(\*)?\s*$", text)
        if member:
            current["members"].append({"port": member[1], "mode": member[2], "state": member[3], "first": bool(member[4])})
    return rows


# ------------------------------------------------------------------ show vpc orphan-ports

def parse_orphan_ports(lines: list[str]) -> list[dict[str, Any]]:
    """``show vpc orphan-ports``: ``VLAN  Orphan Ports`` rows; the port list wraps onto continuation lines."""
    rows: list[dict[str, Any]] = []
    started = False
    for line in lines:
        if re.match(r"^\s*VLAN\s+Orphan Ports", line):
            started = True
            continue
        if not started or re.match(r"^\s*-+\s", line) or not line.strip():
            continue
        match = re.match(r"^(\d+)\s+(\S.*?)\s*$", line.strip()) if re.match(r"^\S", line) else None
        if match:
            rows.append({"vlan": int(match[1]), "text": match[2]})
        elif rows:
            rows[-1]["text"] += " " + line.strip()
    for row in rows:
        row["ports"] = [item.strip() for item in row.pop("text").split(",") if item.strip()]
    return rows


# ------------------------------------------------------------------ show spanning-tree root

def parse_stp_root(lines: list[str]) -> list[dict[str, Any]]:
    """``show spanning-tree root``: one row per VLAN (``VLAN0002  4098 cced.4dcb.8f67  0  2  20  15  This bridge is root``)."""
    rows = []
    for line in lines:
        match = re.match(r"^(VLAN\d+|MST\d+)\s+(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$", line.strip(), re.IGNORECASE)
        if match:
            rows.append({"instance": match[1], "vlan": int(re.sub(r"\D", "", match[1])), "priority": int(match[2]), "root": match[3].lower(), "cost": int(match[4]),
                         "hello": int(match[5]), "max_age": int(match[6]), "forward_delay": int(match[7]),
                         "root_port": match[8].strip(), "local_root": match[8].strip().lower().startswith("this bridge")})
    return rows


# ------------------------------------------------------------------ show vrf / show vrf interface

def parse_vrf(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        match = re.match(r"^(\S.*?)\s+(\d+)\s+(Up|Down)\s+(.*?)\s*$", line.strip())
        if match and not line.startswith("VRF-Name"):
            rows.append({"vrf": match[1].strip(), "id": match[2], "state": match[3], "reason": match[4].strip() or "--"})
    return rows


def parse_vrf_interface(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        match = re.match(r"^(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s*$", line.strip())
        if match and match[1] != "Interface":
            rows.append({"interface": match[1], "vrf": match[2], "id": match[3]})
    return rows


# ------------------------------------------------------------------ show logging server

def parse_logging_servers(lines: list[str]) -> dict[str, Any]:
    info: dict[str, Any] = {"enabled": None, "servers": []}
    current: dict[str, str] | None = None
    for line in lines:
        text = line.strip()
        match = re.match(r"^Logging server:\s*(enabled|disabled)", text, re.IGNORECASE)
        if match:
            info["enabled"] = match[1].lower() == "enabled"
            continue
        match = re.match(r"^\{(\S+)\}$", text)
        if match:
            current = {"server": match[1], "status": "", "severity": "", "facility": "", "vrf": "", "port": ""}
            info["servers"].append(current)
            continue
        if current is None:
            continue
        for key, label in (("status", "server status:"), ("severity", "server severity:"), ("facility", "server facility:"), ("vrf", "server VRF:"), ("port", "server port:")):
            if text.startswith(label):
                current[key] = text[len(label):].strip()
    return info if info["servers"] or info["enabled"] is not None else {}


# ------------------------------------------------------------------ show ip route summary

def parse_route_summary(lines: list[str]) -> list[dict[str, Any]]:
    """``show ip route summary``: per VRF the route and path totals and the best paths per protocol."""
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_best = False
    for line in lines:
        text = line.strip()
        match = re.match(r'^IP Route Table for VRF "([^"]+)"', text)
        if match:
            current = {"vrf": match[1], "routes": None, "paths": None, "protocols": {}}
            rows.append(current)
            in_best = False
            continue
        if current is None:
            continue
        match = re.match(r"^Total number of routes:\s*(\d+)", text)
        if match:
            current["routes"] = int(match[1])
        match = re.match(r"^Total number of paths:\s*(\d+)", text)
        if match:
            current["paths"] = int(match[1])
        if text.startswith("Best paths per protocol"):
            in_best = True
            continue
        if text.startswith("Number of routes per mask-length"):
            in_best = False
        match = re.match(r"^(\S+)\s*:\s*(\d+)", text)
        if in_best and match:
            current["protocols"][match[1]] = int(match[2])
    return [row for row in rows if row["routes"] is not None]


# ------------------------------------------------------------------ findings and tables

def _finding(code: str, severity: str, title: str, text: str, where: str, doc: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"code": code, "severity": severity, "level": "warning" if severity in ("high", "medium") else "info", "title": title, "text": text, "where": where}
    ref = DOCS.get(doc)
    if ref:
        entry["doc"] = {"title": ref[0], "url": ref[1]}
    return entry


_ACL_ENTRY = re.compile(r"^\s+\d+\s+(?:permit|deny)\s+\S+\s+(.*)$")
_GLUED_COMMAND = re.compile(r"[A-Za-z0-9](?:show|terminal|ping|traceroute)\s+\S+")
_ADDRESS_LIKE = re.compile(r"^[0-9A-Za-z.\-]*\d\.[0-9A-Za-z.\-]*(?:/\d+)?$")
_IPV4_OR_CIDR = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")


def _broken_acl_lines(clean: list[str]) -> list[str]:
    """ACL entries of the running-configuration that a type-ahead command landed in: a glued ``show ...`` or an address that is not an IPv4 / CIDR."""
    bad: list[str] = []
    for line in clean:
        match = _ACL_ENTRY.match(line)
        if not match:
            continue
        text = line.strip()
        if _GLUED_COMMAND.search(text):
            bad.append(text)
            continue
        for token in match.group(1).split():
            if token.count(".") >= 3 and _ADDRESS_LIKE.match(token) and not _IPV4_OR_CIDR.match(token):      # three dots: an address, not a MAC (two dots)
                bad.append(text)
                break
    return bad


def _short(items: list[str], limit: int = 8) -> str:
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def _table(tab: str, table_id: str, title: str, hint: str, columns: list[tuple[str, str]], rows: list[dict[str, Any]], status: str = "") -> dict[str, Any]:
    return {"tab": tab, "id": table_id, "title": title, "hint": hint,
            "columns": [{"key": key, "label": label, **({"status": True} if key == status else {})} for key, label in columns], "rows": rows}


_BENIGN_RESET = re.compile(r"upgrade|cli command reload|reload|power ?cycled|admin|requested by|user|install|patch", re.IGNORECASE)


def analyse(clean: list[str]) -> dict[str, Any]:
    """``{"tables": [...], "counts": {key: rows}, "findings": [...]}`` for the commands of this module found in ``clean``."""
    tables: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    findings: list[dict[str, Any]] = []

    features = parse_features(_fullest(clean, r"sh(?:ow)? feature", lambda b: len(parse_features(b))))
    if features:
        enabled = sorted({row["feature"] for row in features if row["state"] == "enabled"})
        counts["features"] = len(features)
        tables.append(_table("health", "nx-features", "Features enabled", "From show feature. Only the features that are enabled; instances of one feature are listed once. A feature that is off answers `% Invalid command` to its show commands.",
                             [("feature", "Feature"), ("instances", "Instances"), ("state", "State")],
                             [{"feature": name, "instances": ", ".join(str(r["instance"]) for r in features if r["feature"] == name and r["state"] == "enabled"), "state": "enabled"} for name in enabled], "state"))
        risky = [name for name in enabled if name in ("telnetServer", "telnet", "tftp-server", "ftp-server")]
        if risky:
            findings.append(_finding("SW-NX-FEAT-001", "medium", f"Clear-text management feature enabled: {', '.join(risky)}",
                                     "show feature lists " + ", ".join(risky) + " as enabled. Telnet, TFTP and FTP send credentials and files unencrypted; use SSH and SCP / SFTP instead.", ", ".join(risky), "troubleshooting"))

    modules = parse_modules(_fullest(clean, r"sh(?:ow)? mod(?:ule)?", lambda b: len(parse_modules(b))))
    if modules:
        counts["modules"] = len(modules)
        tables.append(_table("health", "nx-modules", "Modules", "From show module. A fixed Nexus 9300 lists its line card (module 1) and the virtual supervisor (module 27).",
                             [("module", "Mod"), ("type", "Type"), ("model", "Model"), ("ports", "Ports"), ("software", "Software"), ("hardware", "Hardware"), ("serial", "Serial"), ("status", "Status")],
                             [{**row, "software": row.get("software", "—"), "hardware": row.get("hardware", "—"), "serial": row.get("serial", "—")} for row in modules], "status"))
        bad = [row for row in modules if not re.match(r"^(?:ok|active|ha-standby|standby)\b", row["status"], re.IGNORECASE)]
        if bad:
            findings.append(_finding("SW-NX-MOD-001", "high", f"{len(bad)} module(s) not in a working state",
                                     "show module: " + "; ".join(f"module {row['module']} ({row['model']}) is {row['status']}" for row in bad[:6])
                                     + ". A module that is not `ok` (or `active` / `ha-standby` for a supervisor) is not forwarding. Check `show module internal exception-log` and `show diagnostic result module all`.",
                                     ", ".join(f"module {row['module']}" for row in bad[:4]), "troubleshooting"))
        versions = sorted({row["software"] for row in modules if row.get("software")})
        if len(versions) > 1:
            findings.append(_finding("SW-NX-MOD-002", "medium", "Modules run different software versions",
                                     "show module: " + ", ".join(versions) + ". Line cards and the supervisor of one chassis must run the same release.", "show module", "troubleshooting"))

    boot = parse_boot(_fullest(clean, r"sh(?:ow)? boot", lambda b: 1 if parse_boot(b) else 0))
    if boot:
        counts["boot"] = 1
        current, nxt = boot["current"], boot["next"]
        rows = []
        for key in sorted(set(current) | set(nxt)):
            rows.append({"variable": {"nxos": "NXOS image", "poap": "POAP", "kickstart": "Kickstart image", "system": "System image", "bios": "BIOS"}.get(key, key),
                         "current": current.get(key, "—"), "next": nxt.get(key, "—"), "same": "yes" if current.get(key) == nxt.get(key) else "NO"})
        tables.append(_table("health", "nx-boot", "Boot variables", "From show boot: what the switch booted and what it will boot after the next reload.",
                             [("variable", "Variable"), ("current", "Current"), ("next", "On next reload"), ("same", "Same")], rows, "same"))
        if current.get("nxos") and nxt.get("nxos") and current["nxos"] != nxt["nxos"]:
            findings.append(_finding("SW-NX-BOOT-001", "medium", "The next reload boots a different NX-OS image",
                                     f"show boot: current {current['nxos']}, on next reload {nxt['nxos']}. The switch will come back on another release than the one running now; "
                                     "confirm that is intended (an upgrade that was staged) before reloading.", "show boot", "install"))
        if nxt.get("poap") == "enabled" or current.get("poap") == "enabled":
            findings.append(_finding("SW-NX-BOOT-002", "low", "POAP is enabled at boot",
                                     "show boot: Boot POAP Enabled. With POAP on, a switch that boots without a startup-configuration looks for a DHCP / script server and provisions itself from it. "
                                     "Disable it on a switch that is in production (`no boot poap enable`).", "show boot", "install"))

    resets = parse_reset_reason(_fullest(clean, r"sh(?:ow)? system reset-reason", lambda b: len(parse_reset_reason(b))))
    if resets:
        counts["reset_reason"] = len(resets)
        tables.append(_table("health", "nx-reset-reason", "Reset reasons", "From show system reset-reason, newest first.",
                             [("index", "#"), ("time", "When"), ("reason", "Reason"), ("service", "Service"), ("version", "Version")], resets))
        odd = [row for row in resets if row["reason"] and not _BENIGN_RESET.search(row["reason"])]
        if odd:
            findings.append(_finding("SW-NX-RST-001", "high" if odd[0] is resets[0] else "medium", f"{len(odd)} reset(s) with a reason other than an upgrade or an admin action",
                                     "show system reset-reason: " + "; ".join(f"{row['time']}: {row['reason']}" + (f" ({row['service']})" if row["service"] else "") for row in odd[:4])
                                     + ". A kernel panic, watchdog or hardware reset is not an operator action; check `show cores` and `show logging nvram`.", odd[0]["time"], "troubleshooting"))

    cores = parse_cores(_fullest(clean, r"sh(?:ow)? cores", lambda b: len(parse_cores(b))))
    core_block = _runs(clean, r"sh(?:ow)? cores")
    if cores:
        counts["cores"] = len(cores)
        tables.append(_table("health", "nx-cores-list", "Core files", "From show cores: a process crashed and left a core file.",
                             [("process", "Process"), ("module", "Module"), ("pid", "PID"), ("time", "Date")], cores))
        findings.append(_finding("SW-NX-CORE-001", "high", f"{len(cores)} core file(s) recorded",
                                 "show cores: " + "; ".join(f"{row['process']} (pid {row['pid']}) at {row['time']}" for row in cores[:5])
                                 + ". A core file means a process crashed. Copy it off the switch (`copy core:... `) and open a TAC case with `show tech-support`.", cores[0]["process"], "troubleshooting"))
    elif core_block:
        counts["cores"] = 1       # the command ran and printed an empty table: no crash, and that is an answer

    crashed = parse_processes_log(_fullest(clean, r"sh(?:ow)? processes log", lambda b: len(parse_processes_log(b))))
    if crashed:
        counts["processes_log"] = len(crashed)
        tables.append(_table("health", "nx-processes-log", "Process log", "From show processes log: processes that exited or crashed.",
                             [("process", "Process"), ("pid", "PID"), ("normal_exit", "Normal exit"), ("stack", "Stack"), ("core", "Core"), ("time", "Created")], crashed))
        abnormal = [row for row in crashed if row["normal_exit"] == "N"]
        if abnormal:
            findings.append(_finding("SW-NX-PROC-001", "medium", f"{len(abnormal)} process exit(s) were not normal",
                                     "show processes log: " + "; ".join(f"{row['process']} (pid {row['pid']}) {row['time']}" for row in abnormal[:5]) + ". Check `show logging last 200` around those times.",
                                     abnormal[0]["process"], "troubleshooting"))
    elif _runs(clean, r"sh(?:ow)? processes log"):
        counts["processes_log"] = 1

    xcvrs = parse_transceiver_details(_fullest(clean, r"sh(?:ow)? int(?:erfaces?)? transceivers? detail(?:s)?", lambda b: len(parse_transceiver_details(b))))
    if xcvrs:
        counts["xcvr_details"] = len(xcvrs)
        present = [row for row in xcvrs if row["present"]]
        table_rows = []
        problems: list[tuple[str, str, str]] = []       # (state, port, text)
        for row in present:
            rx = row["readings"].get("rx_power")
            tx = row["readings"].get("tx_power")
            temp = row["readings"].get("temperature")
            states = {name: dom_state(reading) for name, reading in row["readings"].items()}
            worst = "alarm" if "alarm" in states.values() else "warning" if "warning" in states.values() else "ok" if states else "no DOM"
            table_rows.append({"port": row["port"], "type": row["type"] or "—", "name": row["name"] or "—", "part": row["part"] or "—", "serial": row["serial"] or "—",
                               "rx": f"{rx['value']:.2f} dBm" if rx and rx["value"] is not None else "—", "tx": f"{tx['value']:.2f} dBm" if tx and tx["value"] is not None else "—",
                               "temp": f"{temp['value']:.1f} C" if temp and temp["value"] is not None else "—", "dom": worst})
            for name, state in states.items():
                if state in ("alarm", "warning"):
                    reading = row["readings"][name]
                    problems.append((state, row["port"], f"{row['port']} {name.replace('_', ' ')} {reading['value']}"))
        tables.append(_table("transceivers", "nx-xcvr-dom", "Transceiver diagnostics (DOM)", "From show interface transceiver details. DOM is the optic's own reading; the alarm and warning limits are the ones the optic reports. "
                             "A port with no transceiver, or a copper port, is not listed.",
                             [("port", "Port"), ("type", "Type"), ("name", "Vendor"), ("part", "Part number"), ("serial", "Serial"), ("rx", "Rx power"), ("tx", "Tx power"), ("temp", "Temperature"), ("dom", "DOM state")],
                             table_rows, "dom"))
        alarms = [item for item in problems if item[0] == "alarm"]
        warns = [item for item in problems if item[0] == "warning"]
        dark = [row["port"] for row in present if row["readings"].get("rx_power") and row["readings"]["rx_power"]["value"] is not None and row["readings"]["rx_power"]["value"] <= -40.0]
        if dark:
            findings.append(_finding("SW-NX-XCVR-003", "low", f"{len(dark)} installed optic(s) receive no light",
                                     "show interface transceiver details: Rx power is -40.00 dBm (the receiver's floor) on " + _short(dark) + ". The optic is present but nothing arrives: "
                                     "if the port should carry traffic, the far end is down or unplugged, the fibre is broken or the strands are crossed: check the far end and clean the connectors. On a port that is meant to be unused it is normal.", _short(dark, 4), "interfaces"))
        alarms = [item for item in alarms if item[1] not in dark or "rx power" not in item[2]]
        if alarms:
            findings.append(_finding("SW-NX-XCVR-001", "high", f"{len(alarms)} transceiver reading(s) in alarm",
                                     "show interface transceiver details: " + _short([item[2] for item in alarms]) + ". A reading beyond the alarm limit the optic itself reports; replace or clean the optic, and check the cable.",
                                     _short(sorted({item[1] for item in alarms}), 4), "interfaces"))
        if warns:
            findings.append(_finding("SW-NX-XCVR-002", "low", f"{len(warns)} transceiver reading(s) beyond a warning limit",
                                     "show interface transceiver details: " + _short([item[2] for item in warns]) + ". A warning is the early stage of an alarm.", _short(sorted({item[1] for item in warns}), 4), "interfaces"))
        no_dom = [row["port"] for row in present if not row["readings"]]
        if no_dom:
            counts["xcvr_no_dom"] = len(no_dom)

    errors = parse_counters_errors(_fullest(clean, r"sh(?:ow)? int(?:erfaces?)? counters errors", lambda b: len(parse_counters_errors(b))))
    if errors:
        counts["counters_errors"] = len(errors)
        bad = [row for row in errors if any(value for value in row["counters"].values() if value)]
        if bad:
            tables.append(_table("interfaces", "nx-counter-errors", "Interfaces with error counters", "From show interface counters errors: only ports with a counter that is not zero. The counters are cumulative since they were last cleared.",
                                 [("port", "Port"), ("errors", "Counters that are not zero")],
                                 [{"port": row["port"], "errors": ", ".join(f"{name} {value}" for name, value in row["counters"].items() if value)} for row in bad]))
            phys = [row for row in bad if any((row["counters"].get(name) or 0) for name in _PHYSICAL_ERRORS)]
            if phys:
                findings.append(_finding("SW-NX-ERR-001", "medium", f"{len(phys)} port(s) count receive / transmit errors",
                                         "show interface counters errors: " + _short([f"{row['port']} (" + ", ".join(f"{name} {value}" for name, value in row["counters"].items() if value and name in _PHYSICAL_ERRORS) + ")" for row in phys])
                                         + ". FCS and alignment errors are damaged frames on the wire: a bad cable, a dirty or failing optic, or a duplex / speed mismatch. Clear the counters (`clear counters interface <port>`) and see whether they grow.",
                                         _short([row["port"] for row in phys], 4), "interfaces"))
            discards = [row for row in bad if (row["counters"].get("OutDiscards") or 0) and row not in phys]
            if discards:
                findings.append(_finding("SW-NX-ERR-002", "low", f"{len(discards)} port(s) discard outgoing frames",
                                         "show interface counters errors: " + _short([f"{row['port']} OutDiscards {row['counters']['OutDiscards']}" for row in discards])
                                         + ". Output discards are congestion (a full egress queue), not a cabling error.", _short([row["port"] for row in discards], 4), "interfaces"))

    switchports = [row for row in parse_switchport(_fullest(clean, r"sh(?:ow)? int(?:erfaces?)? switchport", lambda b: len(parse_switchport(b)))) if row["switchport"].lower() == "enabled"]
    if switchports:
        counts["switchport"] = len(switchports)
        trunks = [row for row in switchports if row["mode"].lower() == "trunk"]
        access = [row for row in switchports if row["mode"].lower() == "access"]
        tables.append(_table("trunks", "nx-switchport", "Switchport modes", "From show interface switchport: the operational mode of every L2 port, with the VLANs it carries.",
                             [("interface", "Interface"), ("mode", "Mode"), ("access_vlan", "Access VLAN"), ("native_vlan", "Native VLAN"), ("allowed", "Allowed VLANs")],
                             [{**row, "access_vlan": row["access_vlan"] if row["mode"].lower() == "access" else "—", "native_vlan": row["native_vlan"] if row["mode"].lower() == "trunk" else "—",
                               "allowed": row["allowed"] if row["mode"].lower() == "trunk" else "—"} for row in switchports]))
        open_trunks = [row["interface"] for row in trunks if re.fullmatch(r"1-4094", row["allowed"].replace(" ", ""))]
        if open_trunks:
            findings.append(_finding("SW-NX-SWP-001", "low", f"{len(open_trunks)} trunk(s) allow every VLAN (1-4094)",
                                     "show interface switchport: " + _short(open_trunks) + ". A trunk with no `switchport trunk allowed vlan` carries every VLAN, including ones the far end should never see, and widens the spanning-tree domain. "
                                     "Prune each trunk to the VLANs it needs.", _short(open_trunks, 4), "interfaces"))
        native1 = [row["interface"] for row in trunks if row["native_vlan"].startswith("1 ") or row["native_vlan"] == "1"]
        if native1:
            findings.append(_finding("SW-NX-SWP-002", "info", f"{len(native1)} trunk(s) use VLAN 1 as the native VLAN",
                                     "show interface switchport: " + _short(native1) + ". VLAN 1 untagged on a trunk is the default; a deliberate native VLAN other than 1 avoids untagged traffic joining the default VLAN.",
                                     _short(native1, 4), "interfaces"))
        vlan1 = [row["interface"] for row in access if row["access_vlan"].startswith("1 ") or row["access_vlan"] == "1"]
        if vlan1:
            findings.append(_finding("SW-NX-SWP-003", "low", f"{len(vlan1)} access port(s) sit in the default VLAN 1",
                                     "show interface switchport: " + _short(vlan1) + ". A port left in VLAN 1 is usually unused; put it in an unused VLAN and shut it down.", _short(vlan1, 4), "interfaces"))

    pcs = parse_port_channel_database(_fullest(clean, r"sh(?:ow)? port-channel database", lambda b: len(parse_port_channel_database(b))))
    if pcs:
        counts["pc_database"] = len(pcs)
        tables.append(_table("portchannels", "nx-pc-database", "Port-channel membership (database)", "From show port-channel database: the members of each bundle, their LACP mode and state, and the first operational port.",
                             [("channel", "Port-channel"), ("members_up", "Members up"), ("first", "First operational port"), ("members", "Members"), ("update", "Last membership update"), ("age", "Age")],
                             [{"channel": row["channel"], "members_up": f"{row['up']} / {row['total']}", "first": row["first"] or "—",
                               "members": ", ".join(f"{m['port']} [{m['mode'].strip()}][{m['state']}]" for m in row["members"]) or "—", "update": row["update"] or "—", "age": row["age"] or "—"} for row in pcs]))
        partial = [row for row in pcs if row["total"] and row["up"] < row["total"]]
        if partial:
            findings.append(_finding("SW-NX-PC-001", "medium", f"{len(partial)} port-channel(s) have members that are not up",
                                     "show port-channel database: " + _short([f"{row['channel']} {row['up']}/{row['total']}" for row in partial]) + ". A bundle runs with fewer links than configured: lost bandwidth and redundancy.",
                                     _short([row["channel"] for row in partial], 4), "interfaces"))
        failed = [row for row in pcs if row["update"] and not row["update"].lower().startswith("successful")]
        if failed:
            findings.append(_finding("SW-NX-PC-002", "medium", f"{len(failed)} port-channel(s) report a failed membership update",
                                     "show port-channel database: " + _short([f"{row['channel']}: {row['update']}" for row in failed]) + ".", _short([row["channel"] for row in failed], 4), "interfaces"))

    orphans = parse_orphan_ports(_fullest(clean, r"sh(?:ow)? vpc orphan-ports", lambda b: len(parse_orphan_ports(b))))
    if orphans:
        counts["orphan_ports"] = len(orphans)
        ports = sorted({port for row in orphans for port in row["ports"]}, key=lambda name: (not name.lower().startswith("eth"), name))
        tables.append(_table("vpcmlag", "nx-orphan-ports", "vPC orphan ports", "From show vpc orphan-ports: ports that carry a vPC VLAN but are not part of a vPC. If the peer-link fails, an orphan port on the secondary peer is cut off from the vPC side.",
                             [("vlan", "VLAN"), ("ports", "Orphan ports")], [{"vlan": row["vlan"], "ports": ", ".join(row["ports"])} for row in orphans]))
        findings.append(_finding("SW-NX-VPC-020", "low", f"{len(ports)} orphan port(s) on vPC VLANs",
                                 "show vpc orphan-ports: " + _short(ports, 12) + ". A device on an orphan port is single-attached to this peer; if the vPC secondary suspends its vPC ports after a peer-link failure, "
                                 "orphan ports are not suspended and traffic can be black-holed. Attach it with a vPC, or use `vpc orphan-port suspend` on ports that must follow the vPC.", _short(ports, 4), "troubleshooting"))
    elif _runs(clean, r"sh(?:ow)? vpc orphan-ports"):
        counts["orphan_ports"] = 1

    roots = parse_stp_root(_fullest(clean, r"sh(?:ow)? spanning-tree root", lambda b: len(parse_stp_root(b))))
    if roots:
        counts["stp_root"] = len(roots)
        tables.append(_table("stp", "nx-stp-root", "Spanning-tree root per VLAN", "From show spanning-tree root: the root bridge each VLAN has chosen, the cost to it and the port that leads there.",
                             [("instance", "Instance"), ("priority", "Root priority"), ("root", "Root bridge"), ("cost", "Cost"), ("root_port", "Root port")],
                             [{"instance": row["instance"], "priority": row["priority"], "root": row["root"], "cost": row["cost"], "root_port": row["root_port"]} for row in roots]))
        local = [row for row in roots if row["local_root"]]
        foreign = [row for row in roots if not row["local_root"]]
        by_root: dict[str, list[dict[str, Any]]] = {}
        for row in foreign:
            by_root.setdefault(row["root"], []).append(row)
        default_rows = [row for row in foreign if row["priority"] > 0 and row["priority"] - row["vlan"] >= 32768]
        if default_rows:
            roots_used = sorted({row["root"] for row in default_rows})
            vlans = sorted({row["vlan"] for row in default_rows})
            own = f"this bridge is root for {len(local)} VLAN(s) (its configured priority is lower), but " if local else ""
            findings.append(_finding("SW-NX-STP-ROOT-001", "medium", f"{len(vlans)} VLAN(s) are rooted at a bridge with the default priority",
                                     "show spanning-tree root: " + own + "VLAN " + _short([str(v) for v in vlans], 12) + " have these root bridges: " + _short(roots_used, 6)
                                     + ", each with the default priority (32768 + VLAN). A bridge that wins on its MAC address alone is a chance outcome, and it is often an access switch or a device nobody manages as a root. "
                                     "Set `spanning-tree vlan <list> priority` on the bridges that should be root for these VLANs.", _short(roots_used, 3), "stp"))
        zero = [row for row in roots if row["priority"] == 0]
        if zero:
            findings.append(_finding("SW-NX-STP-ROOT-002", "low", f"Root priority 0 for VLAN {_short([str(row['vlan']) for row in zero], 6)}",
                                     "show spanning-tree root: " + _short([f"{row['instance']} root {row['root']}" for row in zero]) + f" with priority 0, the lowest value there is. A bridge was set to priority 0 by hand (or a device is forcing the root); "
                                     "nothing can take the root from it, and its failure moves the root to an unplanned bridge.", _short([row["instance"] for row in zero], 4), "stp"))
        far = [row for row in foreign if row["cost"] >= 10000]
        if far:
            findings.append(_finding("SW-NX-STP-ROOT-003", "low", f"{len(far)} VLAN(s) have a very high root path cost",
                                     "show spanning-tree root: " + _short([f"{row['instance']} cost {row['cost']} via {row['root_port']}" for row in far]) + ". A path cost this high means the path to the root crosses slow links (a 10 Mb/s or 100 Mb/s hop) or many bridges.",
                                     _short([row["instance"] for row in far], 4), "stp"))

    vrfs = parse_vrf(_fullest(clean, r"sh(?:ow)? vrf", lambda b: len(parse_vrf(b))))
    if vrfs:
        counts["vrf"] = len(vrfs)
        tables.append(_table("routing", "nx-vrf", "VRFs", "From show vrf.", [("vrf", "VRF"), ("id", "ID"), ("state", "State"), ("reason", "Reason")], vrfs, "state"))
        down = [row for row in vrfs if row["state"] == "Down"]
        if down:
            findings.append(_finding("SW-NX-VRF-001", "medium", f"{len(down)} VRF(s) are down", "show vrf: " + _short([f"{row['vrf']} ({row['reason']})" for row in down]) + ".", _short([row["vrf"] for row in down], 4), "troubleshooting"))
    vrf_if = parse_vrf_interface(_fullest(clean, r"sh(?:ow)? vrf interface", lambda b: len(parse_vrf_interface(b))))
    if vrf_if:
        counts["vrf_interface"] = len(vrf_if)
        grouped: dict[str, list[str]] = {}
        for row in vrf_if:
            grouped.setdefault(row["vrf"], []).append(row["interface"])
        tables.append(_table("routing", "nx-vrf-interface", "Interfaces per VRF", "From show vrf interface.",
                             [("vrf", "VRF"), ("count", "Interfaces"), ("interfaces", "Interface list")],
                             [{"vrf": vrf, "count": len(names), "interfaces": _short(names, 24)} for vrf, names in grouped.items()]))

    syslog = parse_logging_servers(_fullest(clean, r"sh(?:ow)? logging server", lambda b: len(parse_logging_servers(b).get("servers", []))))
    if syslog:
        counts["logging_server"] = len(syslog["servers"]) or 1
        if syslog["servers"]:
            tables.append(_table("logs", "nx-logging-server", "Syslog servers", "From show logging server: the remote syslog servers the switch sends to and the status of each.",
                                 [("server", "Server"), ("status", "Status"), ("severity", "Severity"), ("facility", "Facility"), ("vrf", "VRF"), ("port", "Port")], syslog["servers"], "status"))
            bad = [row for row in syslog["servers"] if row["status"] and not re.match(r"no errors", row["status"], re.IGNORECASE)]
            if bad:
                findings.append(_finding("SW-NX-LOG-002", "medium", f"{len(bad)} syslog server(s) report an error",
                                         "show logging server: " + _short([f"{row['server']}: {row['status']}" for row in bad]) + ". Logs may not be reaching the collector; check the route (and `use-vrf`) to it.",
                                         _short([row["server"] for row in bad], 4), "troubleshooting"))
        elif syslog.get("enabled") is False:
            findings.append(_finding("SW-NX-LOG-003", "low", "Remote syslog is disabled", "show logging server: Logging server: disabled. Logs stay on the switch (bootflash and the log buffer).", "show logging server", "troubleshooting"))

    summary = parse_route_summary(_fullest(clean, r"sh(?:ow)? ip route summary(?: vrf \S+)?", lambda b: len(parse_route_summary(b))))
    if summary:
        counts["route_summary"] = len(summary)
        tables.append(_table("routing", "nx-route-summary", "Route summary", "From show ip route summary: totals per VRF and the best paths per protocol.",
                             [("vrf", "VRF"), ("routes", "Routes"), ("paths", "Paths"), ("protocols", "Best paths per protocol")],
                             [{"vrf": row["vrf"], "routes": row["routes"], "paths": row["paths"] if row["paths"] is not None else "—",
                               "protocols": ", ".join(f"{name} {count}" for name, count in row["protocols"].items()) or "—"} for row in summary]))

    broken = _broken_acl_lines(clean)
    if broken:
        counts["acl_capture_damage"] = len(broken)
        findings.append(_finding("SW-NX-CAP-001", "medium", f"{len(broken)} ACL line(s) in the capture are damaged",
                                 "Commands typed while the previous output was still printing were written into the middle of the running-configuration: "
                                 + _short([f"'{text}'" for text in broken], 3)
                                 + ". The rule is incomplete or has a corrupted address, and the lines after it can lose their ACL. "
                                 "Capture again with the commands sent one at a time (or paste the whole list only after the prompt returns) and compare `show access-lists` with the saved configuration.",
                                 _short([text[:60] for text in broken], 2), ""))
    return {"tables": tables, "counts": counts, "findings": findings}
