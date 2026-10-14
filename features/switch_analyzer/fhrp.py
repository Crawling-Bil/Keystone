"""First-hop redundancy: the HSRP / VRRP groups a switch is configured for, and the live VRRP state Huawei prints.

Two sources, both read from real captures:

* the configuration -- NX-OS ``hsrp <group>`` blocks under an interface (a Nexus 9000 pair member with 39 groups, and the vPC pair of another site), Huawei
  ``vrrp vrid <n> virtual-ip <ip>`` lines under a ``Vlanif`` (an S5755 pair).  The IOS / IOS XE ``standby <group> ...`` and ``vrrp <group> ip ...`` forms are read
  from the published syntax; no capture of ours uses them yet.
* ``display vrrp`` (Huawei): the state of every group (Master / Backup / Initialize ...).
* ``show hsrp`` / ``show hsrp all`` / ``show hsrp brief`` / ``show hsrp summary`` (Cisco NX-OS) and ``show standby brief`` (IOS / IOS XE): the live state, read by
  ``fhrp_live.py`` from a real Nexus 9000 vPC pair and merged into the same table.  ``show standby`` / ``show vrrp`` in full stay "not parsed" in the Coverage tab:
  no capture of ours has them populated.

Only what the configuration says is shown.  An option that is not configured is left blank (the protocol default applies); the page never states a default of its own.
An authentication *type* is shown, never the key or the string.  Nothing here is judged: whether the two peers of a pair agree on priority and preemption needs both
devices, and a single capture cannot say.

Sources (pages opened while writing this module):

* Cisco, Cisco Nexus 9000 Series NX-OS Unicast Routing Configuration Guide, Release 10.4(x), Configuring HSRP (``hsrp version``, ``hsrp <group>``, ``ip``, ``priority``,
  ``preempt``, ``timers``, ``authentication``, ``track``, ``name``, ``mac-address``; default priority 100, preemption off by default):
  https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/unicast-routing-configuration/cisco-nexus-9000-series-nx-os-unicast-routing-configuration-guide/m_configuring_hsrp.html
* Cisco, Cisco Nexus 9000 Series NX-API CLI Reference, HSRP Commands (the NX-OS show commands are ``show hsrp`` and ``show hsrp brief``):
  https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/hsrp-commands/

The Huawei VRRP command reference pages (support.huawei.com) could not be opened from here, so for Huawei only ``vrrp vrid <n> virtual-ip`` and the ``display vrrp``
table are taken from captures; ``priority`` and ``undo ... preempt-mode`` follow the VRP syntax and read as blank when the line is not exactly that.
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text, fhrp_live
from .live_state import interface_key

DOCS = {
    "hsrp": ("Cisco - Nexus 9000 NX-OS Unicast Routing Configuration Guide 10.4(x), Configuring HSRP",
             "https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/unicast-routing-configuration/cisco-nexus-9000-series-nx-os-unicast-routing-configuration-guide/m_configuring_hsrp.html"),
    "hsrp_show": ("Cisco - Nexus 9000 NX-API CLI Reference, HSRP Commands", "https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/hsrp-commands/"),
}

_INTERFACE = re.compile(r"^interface\s+(\S.*?)\s*$")
_IP = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)"
_VRRP_ROW = re.compile(r"^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(" + _IP + r")\s*$")
_ERROR = re.compile(r"^\s*(?:%|\^\s*$|error:|invalid)", re.IGNORECASE)


def _group(interface: str, protocol: str, group: str, family: str = "") -> dict[str, Any]:
    return {"interface": interface, "protocol": protocol, "group": group, "family": family, "virtual_ip": [], "priority": "", "preempt": "", "timers": "", "version": "", "auth": "",
            "track": [], "name": "", "state": "", "mac": "", "state_detail": "", "cfg_priority": "", "active": "", "standby": "", "changes": "", "last_change": "", "vmac": "", "live": False}


def _blocks(clean: list[str]) -> list[tuple[str, list[str]]]:
    """``[(interface, indented lines under it)]``: a stanza ends at the first line that starts in column 0 (``!``, ``#`` and a blank line included)."""
    blocks: list[tuple[str, list[str]]] = []
    current: list[str] | None = None
    for raw in clean:
        found = _INTERFACE.match(raw)
        if found:
            current = []
            blocks.append((found.group(1), current))
            continue
        if current is not None:
            if raw[:1] in (" ", "\t") and raw.strip():
                current.append(raw.rstrip())
            else:
                current = None
    return blocks


def _timers(text: str) -> str:
    numbers = re.findall(r"(msec\s+)?(\d+)", text)
    if len(numbers) < 2:
        return ""
    return " / ".join(f"{value} {'ms' if unit else 's'}" for unit, value in numbers[:2])


def _auth(text: str) -> str:
    """The authentication type only: ``text``, ``md5`` or ``md5 key-chain`` for HSRP, ``simple`` / ``md5`` / ``hmac-sha256`` for VRRP.  Never the string or the key."""
    words = text.split()
    if not words:
        return ""
    first = words[0].lower()
    if first == "md5":
        return "md5 (key chain)" if len(words) > 1 and words[1].lower() == "key-chain" else "md5"
    return first if first in {"text", "simple", "hmac-sha256", "key-chain"} else "configured"


def _apply_hsrp(group: dict[str, Any], line: str) -> None:
    """One line under NX-OS ``hsrp <n>``."""
    keyword, _, rest = line.partition(" ")
    keyword = keyword.lower()
    rest = rest.strip()
    if keyword == "ip":
        found = re.match(rf"({_IP})(?:\s+secondary)?$", rest)
        if found:
            group["virtual_ip"].append(found.group(1) + (" (secondary)" if rest.endswith("secondary") else ""))
        elif rest.lower() == "autoconfig":
            group["virtual_ip"].append("autoconfig")
    elif keyword == "priority":
        found = re.match(r"(\d+)", rest)
        if found:
            group["priority"] = found.group(1)
    elif keyword == "preempt":
        group["preempt"] = "on" + (f" (delay {rest[len('delay'):].strip()})" if rest.lower().startswith("delay") and rest[len("delay"):].strip() else "")
    elif keyword == "timers":
        group["timers"] = _timers(rest)
    elif keyword == "authentication":
        group["auth"] = _auth(rest)
    elif keyword == "track":
        group["track"].append(rest)
    elif keyword == "name":
        group["name"] = rest
    elif keyword == "mac-address":
        group["mac"] = rest


def _nxos_groups(interface: str, lines: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    version = ""
    current: dict[str, Any] | None = None
    base = 0
    for raw in lines:
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        found = re.match(r"hsrp (\d+)(?: (ipv4|ipv6))?$", line, re.IGNORECASE)
        if found:
            current = _group(interface, "HSRP", found.group(1), (found.group(2) or "ipv4").lower())
            base = indent
            out.append(current)
            continue
        found = re.match(r"hsrp version (\d)$", line, re.IGNORECASE)
        if found:
            version = found.group(1)
            current = None
            continue
        if current is not None and indent > base:
            _apply_hsrp(current, line)
        else:
            current = None
    for item in out:
        item["version"] = version or "1"      # version 1 is the default (Cisco guide); the line is printed only when it was changed
    return out


def _ios_groups(interface: str, lines: list[str]) -> list[dict[str, Any]]:
    """IOS / IOS XE: ``standby <group> ip|priority|preempt|timers|authentication|track|name ...`` and ``vrrp <group> ip|priority|preempt|timers advertise|authentication ...``."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    version = ""
    for raw in lines:
        line = raw.strip()
        found = re.match(r"standby version (\d)$", line, re.IGNORECASE)
        if found:
            version = found.group(1)
            continue
        found = re.match(r"(standby|vrrp)\s+(?:(\d+)\s+)?(ip|ipv6|priority|preempt|timers|authentication|track|name|mac-address)\b\s*(.*)$", line, re.IGNORECASE)
        if not found:
            continue
        protocol = "HSRP" if found.group(1).lower() == "standby" else "VRRP"
        number = found.group(2) or "0"
        group = groups.setdefault((protocol, number), _group(interface, protocol, number))
        keyword, rest = found.group(3).lower(), found.group(4).strip()
        if keyword in {"ip", "ipv6"}:
            _apply_hsrp(group, f"ip {rest}")
        elif keyword == "timers":
            group["timers"] = _timers(re.sub(r"^advertise\s+", "", rest))
        else:
            _apply_hsrp(group, f"{keyword} {rest}")
    for item in groups.values():
        if item["protocol"] == "HSRP":
            item["version"] = version or "1"
    return list(groups.values())


def _huawei_groups(interface: str, lines: list[str]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for raw in lines:
        line = raw.strip()
        found = re.match(r"(undo\s+)?vrrp vrid (\d+)\s+(.*)$", line, re.IGNORECASE)
        if not found:
            continue
        undo, number, rest = bool(found.group(1)), found.group(2), found.group(3).strip()
        group = groups.setdefault(number, _group(interface, "VRRP", number))
        low = rest.lower()
        if undo:
            if low.startswith("preempt-mode"):
                group["preempt"] = "off"
            continue
        if low.startswith("virtual-ip"):
            addresses = re.findall(_IP, rest[len("virtual-ip"):])
            group["virtual_ip"].extend(addresses[:1])
        elif low.startswith("priority"):
            value = re.match(r"priority\s+(\d+)\s*$", low)
            if value:
                group["priority"] = value.group(1)
        elif low.startswith("preempt-mode"):
            delay = re.search(r"delay\s+(\d+)", low)
            group["preempt"] = "on" + (f" (delay {delay.group(1)} s)" if delay else "")
        elif low.startswith("authentication-mode"):
            group["auth"] = _auth(rest[len("authentication-mode"):])
        elif low.startswith("track"):
            group["track"].append(re.sub(r"\s+", " ", rest))
    return list(groups.values())


def config_groups(clean: list[str]) -> list[dict[str, Any]]:
    """Every HSRP / VRRP group in the interface stanzas of the capture, once per (interface, protocol, group)."""
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for interface, lines in _blocks(clean):
        if not any(re.match(r"\s*(?:hsrp|standby|vrrp|undo vrrp)\b", line, re.IGNORECASE) for line in lines):
            continue
        for group in _nxos_groups(interface, lines) + _ios_groups(interface, lines) + _huawei_groups(interface, lines):
            key = (interface.lower(), group["protocol"], group["group"])
            if key not in seen:
                seen.add(key)
                out.append(group)
    return out


def parse_display_vrrp(lines: list[str]) -> list[dict[str, str]]:
    """Huawei ``display vrrp``: ``VRID State Interface Type Virtual IP`` rows.  The ``Total:6 Master:6 Backup:0`` line is only a summary of them."""
    rows = []
    for line in lines:
        found = _VRRP_ROW.match(line)
        if found:
            rows.append({"group": found.group(1), "state": found.group(2), "interface": found.group(3), "type": found.group(4), "virtual_ip": found.group(5)})
    return rows


def _live_rows(clean: list[str]) -> list[dict[str, str]]:
    best: list[dict[str, str]] = []
    for index, block in capture_text.find_blocks(clean, [r"dis(?:p(?:l(?:a(?:y)?)?)?)? vrrp"]):
        if block and _ERROR.match(block[0]):
            continue
        rows = parse_display_vrrp(block)
        if len(rows) > len(best):
            best = rows
    return best


def _column(key: str, label: str, **extra: Any) -> dict[str, Any]:
    return {"key": key, "label": label, **extra}


# the colour of a state cell (the page looks the lower-cased text up in this map)
STATE_TONES = {"active": "ok", "standby": "ok", "master": "ok", "backup": "ok", "listen": "warn", "speak": "warn", "learn": "warn", "initial": "bad", "init": "bad", "initialize": "bad",
               "disabled": "bad"}


def _merge_hsrp(groups: list[dict[str, Any]], live: list[dict[str, Any]]) -> None:
    """Put each live HSRP row on the configured group it belongs to (same interface and group), or add it when the configuration was not captured."""
    index = {(interface_key(group["interface"]), group["group"]): group for group in groups if group["protocol"] == "HSRP" and group["family"] != "ipv6"}
    for row in live:
        key = (row["key"], row["group"])
        target = index.get(key) if row["family"] == "ipv4" else None
        if target is None:
            target = _group(row["interface"], "HSRP", row["group"], row["family"])
            groups.append(target)
            if row["family"] == "ipv4":
                index[key] = target
        target["live"] = True
        target["state"], target["state_detail"] = row["state"], row["state_detail"]
        if row["virtual_ip"] and row["virtual_ip"] not in target["virtual_ip"]:
            target["virtual_ip"].append(row["virtual_ip"])
        configured = target["priority"]
        target["priority"] = row["priority"] or target["priority"]
        target["cfg_priority"] = row["cfg_priority"] or configured
        if row["preempt"] and not (row["preempt"] == "on" and target["preempt"].startswith("on")):
            target["preempt"] = row["preempt"]
        if row["hello"]:
            target["timers"] = f"{row['hello']} / {row['hold']}"
        target["version"] = row["version"] or target["version"]
        target["auth"] = row["auth"] or target["auth"]
        target["name"] = row["name"] or target["name"]
        target["active"] = fhrp_live.peer_text(row["active"], row["active_priority"])
        target["standby"] = fhrp_live.peer_text(row["standby"], row["standby_priority"])
        target["changes"], target["last_change"] = row["changes"], row["last_change"]
        target["vmac"] = row["vmac"]


def analyse(clean: list[str], host: str | None = None) -> dict[str, Any]:
    """``{"tables": [...], "counts": {...}, "groups": [...], "summary": {...}, "findings": [...]}``.

    One table on the Routing tab: the configured groups with the live state merged in (Huawei ``display vrrp``, NX-OS ``show hsrp``, IOS ``show standby brief``), or the live
    groups alone when only the show commands were captured.  A second table holds the ``show hsrp summary`` numbers.  ``host`` limits the live commands to one prompt."""
    groups = config_groups(clean)
    live = _live_rows(clean)
    hsrp = fhrp_live.read(clean, host)
    state_of = {(row["interface"].lower(), row["group"]): row["state"] for row in live}
    for group in groups:
        group["state"] = state_of.get((group["interface"].lower(), group["group"]), "") if group["protocol"] == "VRRP" else ""
    known = {(group["interface"].lower(), group["group"]) for group in groups if group["protocol"] == "VRRP"}
    for row in live:
        if (row["interface"].lower(), row["group"]) not in known:
            item = _group(row["interface"], "VRRP", row["group"])
            item["virtual_ip"] = [row["virtual_ip"]]
            item["state"] = row["state"]
            groups.append(item)
    _merge_hsrp(groups, hsrp["groups"])
    summary = hsrp["summary"]
    findings = fhrp_live.findings(hsrp["groups"], summary)
    base = {"groups": hsrp["groups"], "summary": summary, "findings": findings, "listed": len(hsrp["groups"]), "reported": summary.get("total_groups"),
            "config_hsrp": sum(1 for group in groups if group["protocol"] == "HSRP" and not group["live"])}
    if not groups:
        return {"tables": [], "counts": {}, **base}
    def priority_text(group: dict[str, Any]) -> str:
        if group["priority"] and group["cfg_priority"] and group["priority"] != group["cfg_priority"]:
            return f"{group['priority']} (configured {group['cfg_priority']})"
        return group["priority"] or "—"
    rows = [{"interface": group["interface"], "protocol": group["protocol"] + (" IPv6" if group["family"] == "ipv6" else ""), "group": group["group"],
             "virtual_ip": ", ".join(group["virtual_ip"]) or "—", "state": group["state"] or "—", "state_detail": group["state_detail"] or "—", "priority": priority_text(group),
             "preempt": group["preempt"] or "—", "active": group["active"] or "—", "standby": group["standby"] or "—",
             "timers": group["timers"] or "—", "version": group["version"] or "—", "auth": group["auth"] or "—", "track": "; ".join(group["track"]) or "—", "name": group["name"] or "—",
             "changes": group["changes"] or "—", "last_change": group["last_change"] or "—", "vmac": group["vmac"] or "—"}
            for group in groups]
    sources = []
    if live:
        sources.append("display vrrp")
    if hsrp["groups"]:
        sources.append("show hsrp" if "detail" in hsrp["commands"] or "brief" in hsrp["commands"] else "show standby brief")
    state_label = "State" if len(sources) != 1 else f"State ({sources[0]})"
    columns = [_column("interface", "Interface"), _column("protocol", "Protocol"), _column("group", "Group"), _column("virtual_ip", "Virtual IP"),
               _column("state", state_label, status=True, tones=STATE_TONES), _column("state_detail", "State detail"),
               _column("priority", "Priority"), _column("preempt", "Preempt"), _column("active", "Active router"), _column("standby", "Standby router"),
               _column("timers", "Hello / hold"), _column("version", "HSRP version"), _column("auth", "Authentication"), _column("track", "Tracking"), _column("name", "Name"),
               _column("changes", "State changes"), _column("last_change", "Last change"), _column("vmac", "Virtual MAC")]
    optional = {"state", "state_detail", "active", "standby", "timers", "version", "auth", "track", "name", "changes", "last_change", "vmac"}
    used = {key for key in optional if any(row[key] != "—" for row in rows)}
    columns = [column for column in columns if column["key"] not in optional or column["key"] in used]
    hint = ("HSRP / VRRP groups" + (" from the configuration" if any(not group["live"] for group in groups) else "")
            + (" and the live state (" + ", ".join(sources) + ")" if sources else "")
            + ". A dash means the option is not configured or not captured, so the protocol default applies. The authentication type is shown, never the key or the string. "
              "Comparing priority and preemption between the two peers needs both devices' captures (Compare Devices).")
    tables = [{"tab": "routing", "id": "fhrp-groups", "title": "First-hop redundancy (HSRP / VRRP)", "hint": hint, "columns": columns, "rows": rows}]
    summary_table = fhrp_live.summary_rows(summary, len(hsrp["groups"]))
    if summary_table:
        tables.append({"tab": "routing", "id": "hsrp-summary", "title": "HSRP summary (show hsrp summary)",
                       "hint": "Totals the device keeps for HSRP. Packets for unknown groups are hellos for a group this switch does not run.",
                       "columns": [_column("metric", "Item"), _column("value", "Value")], "rows": summary_table})
    return {"tables": tables, "counts": {"fhrp": len(groups), "fhrp_live": len(live), "hsrp_live": len(hsrp["groups"]), "hsrp_summary": len(summary)}, **base}
