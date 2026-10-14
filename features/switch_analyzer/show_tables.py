"""Tables from Cisco ``show`` commands that the Coverage tab used to list as "not parsed".

* ``show vlan`` / ``show vlan brief``         -> the VLAN database (status, ports, type, MTU)
* ``show vlan summary``                       -> how many VLANs the device says it has
* ``show interface description``              -> description and live state of every interface
* ``show interface trunk``                    -> every trunk with its native, allowed, active and forwarding VLANs
* ``show ip arp summary``                     -> ARP entries the device counts (and how many are incomplete)
* ``show mac address-table count``            -> MAC entries the device counts, per VLAN and in total

The spanning-tree and licence outputs have their own modules (``stp_detail``, ``licence_detail``).

IOS accepts any unique prefix of a keyword (``sh int desc``, ``sh int tru``, ``sh vlan sum``), so every
command pattern here accepts the same abbreviations. The same ``PATTERNS`` feed the Coverage tab, which
keeps "this command was understood" and "this command was parsed" from drifting apart.

Reference for the output layouts (Cisco Catalyst 9300 command reference and Layer 2 configuration guide):
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/command_reference/b_179_9300_cr.html
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text


def _w(word: str, minimum: int, plural: bool = False) -> str:
    """Regex for ``word`` as the IOS parser accepts it: any prefix of at least ``minimum`` letters."""
    head, tail = word[:minimum], word[minimum:]
    pattern = "(?:s)?" if plural else ""
    for letter in reversed(tail):
        pattern = f"(?:{re.escape(letter)}{pattern})?"
    return re.escape(head) + pattern


SHOW = r"sh(?:o(?:w)?)?"
INTERFACE = _w("interface", 3, plural=True)
LICENSE = _w("license", 3)

PATTERNS: dict[str, tuple[str, ...]] = {
    "vlan": (rf"{SHOW} vlan(?: {_w('brief', 2)})?",),
    "vlan_summary": (rf"{SHOW} vlan {_w('summary', 1)}",),
    "int_desc": (rf"{SHOW} {INTERFACE} {_w('description', 2)}",),
    "trunk": (rf"{SHOW} {INTERFACE} {_w('trunk', 3)}",),
    "arp_summary": (rf"{SHOW} ip arp {_w('summary', 1)}",),
    "stp": (rf"{SHOW} {_w('spanning-tree', 2)}(?: {_w('active', 1)}| vlan [\d,\- ]+)?",),
    "stp_summary": (rf"{SHOW} {_w('spanning-tree', 2)} {_w('summary', 1)}",),
    "lic_usage": (rf"{SHOW} {LICENSE} {_w('usage', 1)}",),
    "lic_all": (rf"{SHOW} {LICENSE} {_w('all', 1)}",),
    "lic_summary": (rf"{SHOW} {LICENSE} {_w('summary', 1)}",),
    "mac_count": (rf"{SHOW} mac(?:-| )a\S* {_w('count', 1)}",),
}

BUILT_IN_VLANS = frozenset({1002, 1003, 1004, 1005})   # FDDI / Token Ring placeholders every Catalyst lists


def blocks(clean: list[str], key: str) -> list[list[str]]:
    """Output of every run of the command, with error replies (``% Invalid input``) left out."""
    out = []
    for block in capture_text.command_outputs(clean, PATTERNS[key]):
        if block and not re.match(r"^\s*(?:%|\^|invalid input|error:)", block[0], re.IGNORECASE):
            out.append(block)
    return out


def _longest(clean: list[str], key: str) -> list[str]:
    found = blocks(clean, key)
    return max(found, key=len) if found else []


def expand_vlans(text: str) -> list[int]:
    """``1,10,21-23`` -> [1, 10, 21, 22, 23]. ``none`` and junk give an empty list."""
    out: list[int] = []
    for part in re.split(r"[,\s]+", text or ""):
        match = re.fullmatch(r"(\d{1,4})(?:-(\d{1,4}))?", part)
        if not match:
            continue
        low = int(match.group(1))
        high = int(match.group(2) or low)
        if low <= high <= 4094:
            out.extend(range(low, high + 1))
    return out


# ------------------------------------------------------------------ show vlan

def _column_starts(dashes: str) -> list[int]:
    return [match.start() for match in re.finditer(r"-+", dashes)]


def _cut(line: str, starts: list[int], index: int) -> str:
    end = starts[index + 1] if index + 1 < len(starts) else len(line)
    return line[starts[index]:end].strip() if starts[index] < len(line) else ""


_VLAN_FALLBACK = re.compile(r"^(\d{1,4})\s+(\S.*?)\s+(active|act/\S+|sus\S*|\S*shut)\s*(.*)$", re.IGNORECASE)


def parse_vlan_db(lines: list[str]) -> list[dict[str, Any]]:
    """VLAN rows of ``show vlan`` / ``show vlan brief`` with type, SAID and MTU from the second table."""
    rows: dict[int, dict[str, Any]] = {}
    order: list[int] = []
    starts: list[int] = []
    mode = ""            # "main" | "type" | "span" | "private"
    last: dict[str, Any] | None = None
    private: list[dict[str, Any]] = []
    span: list[int] = []
    for index, line in enumerate(lines):
        text = line.strip()
        if re.match(r"^VLAN\s+Name\s+Status\s+Ports", text, re.IGNORECASE):
            mode, last = "main", None
            starts = []
            if index + 1 < len(lines) and re.match(r"^\s*-{2,}\s+-{2,}", lines[index + 1]):
                starts = _column_starts(lines[index + 1])
            continue
        if re.match(r"^VLAN ID\s+Name\s+\|\s+Status", text, re.IGNORECASE):
            mode, last = "aruba", None          # ArubaOS-Switch: "VLAN ID Name | Status Voice Jumbo"
            continue
        if re.match(r"^VLAN\s+Type\s+(SAID|Vlan-mode)", text, re.IGNORECASE):
            mode, last = "type", None
            continue
        if re.match(r"^Remote SPAN VLANs?", text, re.IGNORECASE):
            mode, last = "span", None
            continue
        if re.match(r"^Primary\s+Secondary\s+Type", text, re.IGNORECASE):
            mode, last = "private", None
            continue
        if not text or re.match(r"^-{3,}[\s-]*$", text):
            continue
        if mode == "main":
            row = None
            if len(starts) >= 4:
                first = _cut(line, starts, 0)
                if first.isdigit():
                    row = (int(first), _cut(line, starts, 1), _cut(line, starts, 2), _cut(line, starts, 3))
                elif not first and last is not None and not _cut(line, starts, 1):
                    last["ports"].extend(p for p in re.split(r"[,\s]+", _cut(line, starts, 3)) if p)
                    continue
            else:
                match = _VLAN_FALLBACK.match(text)
                if match:
                    row = (int(match.group(1)), match.group(2).strip(), match.group(3), match.group(4))
                elif last is not None and re.match(r"^\s+\S", line):
                    last["ports"].extend(p for p in re.split(r"[,\s]+", text) if p)
                    continue
            if row is None:
                continue
            vlan_id, name, status, ports = row
            if vlan_id in rows:
                last = rows[vlan_id]
                continue
            last = {"vlan_id": vlan_id, "name": name, "status": status.lower(), "ports": [p for p in re.split(r"[,\s]+", ports) if p],
                    "type": "", "said": "", "mtu": "", "mode": "", "builtin": vlan_id in BUILT_IN_VLANS}
            rows[vlan_id] = last
            order.append(vlan_id)
        elif mode == "aruba":
            match = re.match(r"^(\d{1,4})\s+(.+?)\s+\|\s+(\S+)\s+(Yes|No)\s+(Yes|No)\s*$", text, re.IGNORECASE)
            if match and int(match.group(1)) not in rows:
                vlan_id = int(match.group(1))
                rows[vlan_id] = {"vlan_id": vlan_id, "name": match.group(2).strip(), "status": match.group(3).lower(), "ports": [],
                                 "type": match.group(3), "said": "", "mtu": "", "mode": "voice" if match.group(4).lower() == "yes" else "",
                                 "builtin": False}
                order.append(vlan_id)
        elif mode == "type":
            match = re.match(r"^(\d{1,4})\s+(\w+)\s+(\d+)\s+(\d+)\b", text)
            if match and int(match.group(1)) in rows:
                item = rows[int(match.group(1))]
                item["type"], item["said"], item["mtu"] = match.group(2), match.group(3), int(match.group(4))
                continue
            match = re.match(r"^(\d{1,4})\s+(\w+)\s+(\S+)$", text)          # NX-OS: VLAN Type Vlan-mode
            if match and int(match.group(1)) in rows:
                item = rows[int(match.group(1))]
                item["type"], item["mode"] = match.group(2), match.group(3)
        elif mode == "span":
            span.extend(expand_vlans(text))
        elif mode == "private":
            match = re.match(r"^(\d{1,4})\s+(\d{1,4})\s+(\S+)\s*(.*)$", text)
            if match:
                private.append({"primary": int(match.group(1)), "secondary": int(match.group(2)), "type": match.group(3),
                                "ports": [p for p in re.split(r"[,\s]+", match.group(4)) if p]})
    result = [rows[key] for key in order]
    for item in result:
        item["port_count"] = len(item["ports"])
        item["remote_span"] = item["vlan_id"] in span
    for entry in private:
        for key in (entry["primary"], entry["secondary"]):
            if key in rows:
                rows[key]["private"] = f"{entry['type']} (primary {entry['primary']}, secondary {entry['secondary']})"
    return result


def parse_vlan_summary(lines: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in lines:
        for key, pattern in (
            ("existing", r"Number of existing VLANs\s*:\s*(\d+)"),
            ("vtp", r"Number of existing VTP VLANs\s*:\s*(\d+)"),
            ("user", r"Number of existing user VLANs\s*:\s*(\d+)"),
            ("extended", r"Number of existing extended VLANs\s*:\s*(\d+)"),
        ):
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                out[key] = int(match.group(1))
    return out


def build_vlan_db(clean: list[str]) -> dict[str, Any]:
    """``{"rows": [...], "summary": {...}, "captured": bool, "complete": bool}``."""
    found = blocks(clean, "vlan")
    parsed = [parse_vlan_db(block) for block in found]
    rows = max(parsed, key=lambda items: (len(items), sum(1 for item in items if item["type"]))) if parsed else []
    summary: dict[str, int] = {}
    for block in blocks(clean, "vlan_summary"):
        summary = parse_vlan_summary(block) or summary
    existing = summary.get("existing")
    return {
        "captured": bool(found),
        "rows": rows,
        "summary": summary,
        # fewer rows than the device counted: the capture lost lines (the type table repeats nothing, so rows == VLANs)
        "complete": existing is None or not rows or len(rows) >= existing,
        "source": "show vlan" if any(b for b in found) else "",
    }


# ------------------------------------------------------- show interface description

_DESC_ROW = re.compile(
    r"^(?P<name>\S+)\s+(?P<status>admin down|administratively down|[*^!]?[A-Za-z]+(?:\([A-Za-z]+\))?)\s+"
    r"(?P<protocol>[*^!]?[A-Za-z]+(?:\([A-Za-z]+\))?)(?:\s+(?P<description>\S.*?))?\s*$"
)
_DESC_STATUS_OK = {"up", "down", "admin down", "administratively down", "deleted", "monitoring", "err-disabled", "notconnect", "connected", "disabled"}


def parse_interface_descriptions(lines: list[str]) -> list[dict[str, str]]:
    """Rows of ``show interface description`` (IOS / IOS XE: Interface, Status, Protocol, Description;
    NX-OS: Interface, Description)."""
    rows: list[dict[str, str]] = []
    style = ""
    for line in lines:
        text = line.strip()
        if not text or re.match(r"^-{3,}[\s-]*$", text):
            continue
        if re.match(r"^Interface\s+Status\s+Protocol\s+Description", text, re.IGNORECASE):
            style = "ios"
            continue
        if re.match(r"^(?:Interface|Port)\s+Description$", text, re.IGNORECASE):
            style = "nxos"
            continue
        if style == "ios":
            match = _DESC_ROW.match(text)
            if match and match.group("status").lower() in _DESC_STATUS_OK:
                rows.append({"interface": match.group("name"), "status": match.group("status").lower(),
                             "protocol": match.group("protocol").lower(), "description": (match.group("description") or "").strip().strip('"')})
        elif style == "nxos":
            match = re.match(r"^(\S+)\s+(\S.*)$", text)
            if match:
                description = match.group(2).strip()
                rows.append({"interface": match.group(1), "status": "", "protocol": "", "description": "" if description == "--" else description})
    return rows


def build_descriptions(clean: list[str]) -> dict[str, Any]:
    found = blocks(clean, "int_desc")
    parsed = [parse_interface_descriptions(block) for block in found]
    rows = max(parsed, key=len) if parsed else []
    return {"captured": bool(found), "rows": rows, "described": sum(1 for row in rows if row["description"])}


# ------------------------------------------------------------ show interface trunk

_TRUNK_STATUS_ROW = re.compile(r"^(\S+)\s+(on|off|auto|desirable|nonegotiate)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", re.IGNORECASE)
_TRUNK_LIST_ROW = re.compile(r"^(\S+)\s+((?:\d{1,4}(?:-\d{1,4})?)(?:,\s*\d{1,4}(?:-\d{1,4})?)*,?|none)\s*$", re.IGNORECASE)
_TRUNK_SECTIONS = (("allowed and active", "active"), ("forwarding state", "forwarding"), ("allowed on trunk", "allowed"),
                   ("err-disabled", "errdisabled"), ("pruned", "pruned"))
# NX-OS: "Port  Native  Status  Port / Vlan  Channel" then "Eth1/1  1  trunking  --" (the Port Channel it belongs to, or --)
_TRUNK_NXOS_ROW = re.compile(r"^(\S+)\s+(\d{1,4})\s+(\S+)\s+(--|\S+)\s*$")


def parse_trunks(lines: list[str]) -> list[dict[str, Any]]:
    """One row per trunk port: Mode / Encapsulation / Status / Native VLAN, then the three VLAN lists."""
    rows: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    section = ""
    last: tuple[str, str] | None = None
    for line in lines:
        text = line.strip()
        if not text:
            continue
        if re.fullmatch(r"-{5,}", text):
            last = None            # NX-OS draws a dashed rule around every table; it ends a wrapped VLAN list
            continue
        if re.match(r"^Port\s+Mode\s+Encapsulation\s+Status\s+Native", text, re.IGNORECASE):
            section, last = "status", None
            continue
        if re.match(r"^Port\s+Native\s+Status\s+Port\s*$", text, re.IGNORECASE):
            section, last = "nxos_status", None
            continue
        if re.match(r"^Port\s+STP Forwarding\s*$", text, re.IGNORECASE):
            section, last = "forwarding", None          # NX-OS 9000 names the forwarding list "STP Forwarding"
            continue
        header = re.match(r"^Port\s+Vlans?\s+(.*)$", text, re.IGNORECASE)
        if header:
            low = header.group(1).lower()
            section = next((key for needle, key in _TRUNK_SECTIONS if needle in low), "")
            last = None
            continue
        if section == "nxos_status":
            match = _TRUNK_NXOS_ROW.match(text)
            if match and not re.match(r"^-+$", match.group(1)):
                port = match.group(1)
                channel = "" if match.group(4) == "--" else match.group(4)
                rows[port] = {"port": port, "mode": "trunk", "encapsulation": "", "status": match.group(3).lower(), "native_vlan": match.group(2),
                              "port_channel": channel, "allowed": "", "active": "", "forwarding": "", "errdisabled": "", "pruned": ""}
                order.append(port)
        elif section == "status":
            match = _TRUNK_STATUS_ROW.match(text)
            if match:
                port = match.group(1)
                rows[port] = {"port": port, "mode": match.group(2).lower(), "encapsulation": match.group(3), "status": match.group(4).lower(),
                              "native_vlan": match.group(5), "port_channel": "", "allowed": "", "active": "", "forwarding": "", "errdisabled": "", "pruned": ""}
                order.append(port)
        elif section and section != "nxos_status":
            match = _TRUNK_LIST_ROW.match(text)
            if match and match.group(1) in rows:
                rows[match.group(1)][section] = match.group(2).rstrip(",")
                last = (match.group(1), section)
            elif last is not None and re.match(r"^[\d,\-\s]+$", text):
                port, key = last
                rows[port][key] = (rows[port][key].rstrip(",") + "," + text.replace(" ", "")).strip(",")
    result = [rows[port] for port in order]
    for row in result:
        row["allowed_all"] = row["allowed"].replace(" ", "") == "1-4094"
        row["active_count"] = len(expand_vlans(row["active"]))
        row["forwarding_count"] = len(expand_vlans(row["forwarding"]))
        row["allowed_count"] = len(expand_vlans(row["allowed"]))
    return result


def build_trunks(clean: list[str]) -> dict[str, Any]:
    found = blocks(clean, "trunk")
    parsed = [parse_trunks(block) for block in found]
    rows = max(parsed, key=len) if parsed else []
    return {"captured": bool(found), "rows": rows}


# ------------------------------------------------------------ ARP and MAC counters

def parse_arp_summary_nxos(lines: list[str]) -> dict[str, Any]:
    """NX-OS: ``IP ARP Table - Adjacency Summary`` then ``Resolved : 155`` / ``Incomplete : 25 (Throttled : 0)`` / ``Unknown : 0`` / ``Total : 180``."""
    values: dict[str, int] = {}
    for line in lines:
        match = re.match(r"^\s*(Resolved|Incomplete|Unknown|Total)\s*:\s*(\d+)(?:\s*\(\s*Throttled\s*:\s*(\d+)\s*\))?", line, re.IGNORECASE)
        if match:
            values[match.group(1).lower()] = int(match.group(2))
            if match.group(3) is not None:
                values["throttled"] = int(match.group(3))
    if "total" not in values:
        return {}
    return {"total": values["total"], "incomplete": values.get("incomplete", 0), "resolved": values.get("resolved"),
            "unknown": values.get("unknown"), "throttled": values.get("throttled"), "source": "show ip arp summary"}


def build_arp_summary(clean: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for block in blocks(clean, "arp_summary"):
        for line in block:
            match = re.search(r"(\d+)\s+IP ARP entr(?:y|ies),\s*with\s+(\d+)\s+of them incomplete", line, re.IGNORECASE)
            if match:
                out = {"total": int(match.group(1)), "incomplete": int(match.group(2)), "source": "show ip arp summary"}
        out = parse_arp_summary_nxos(block) or out
    return out


def parse_mac_count(lines: list[str]) -> dict[str, Any]:
    vlans: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    out: dict[str, Any] = {}
    dynamic = static = 0
    for line in lines:
        text = line.strip()
        match = re.match(r"^Mac Entries for Vlan\s+(\d+)\s*:", text, re.IGNORECASE)
        if match:
            current = {"vlan": int(match.group(1)), "dynamic": 0, "static": 0, "total": 0}
            vlans.append(current)
            continue
        if re.match(r"^MAC Entries for all VLANs?\s*:", text, re.IGNORECASE):
            current = None
            out["scope"] = "all VLANs"
            continue
        match = re.match(r"^Total Dynamic Address Count\s*:\s*(\d+)", text, re.IGNORECASE)
        if match:
            out["dynamic"] = int(match.group(1))
            continue
        match = re.match(r"^Total Static\s+Address Count\s*:\s*(\d+)", text, re.IGNORECASE)
        if match:
            out["static"] = int(match.group(1))
            continue
        match = re.match(r"^Total Mac Address(?:es)? In Use\s*:\s*(\d+)", text, re.IGNORECASE) or re.match(
            r"^Total MAC Addresses in Use[^:]*:\s*(\d+)", text, re.IGNORECASE)
        if match:
            out["total"] = int(match.group(1))
            continue
        match = re.match(r"^Total Mac Address Space Available\s*:\s*(\d+)", text, re.IGNORECASE)
        if match:
            out["available"] = int(match.group(1))
            continue
        if current is not None:
            match = re.match(r"^Dynamic Address Count\s*:\s*(\d+)", text, re.IGNORECASE)
            if match:
                current["dynamic"] = int(match.group(1))
                continue
            match = re.match(r"^Static\s+Address Count\s*:\s*(\d+)", text, re.IGNORECASE)
            if match:
                current["static"] = int(match.group(1))
                continue
            match = re.match(r"^Total Mac Addresses\s*:\s*(\d+)", text, re.IGNORECASE)
            if match:
                current["total"] = int(match.group(1))
                continue
        # NX-OS prints one block for all VLANs: "Dynamic Local Address Count: 50", "Static Remote ... Count: 0"
        match = re.match(r"^(Dynamic|Static|Secure)\b[^:]*Count\s*:\s*(\d+)", text, re.IGNORECASE)
        if match and current is None:
            if match.group(1).lower() == "dynamic":
                dynamic += int(match.group(2))
            else:
                static += int(match.group(2))
    if vlans:
        out["vlans"] = vlans
        out.setdefault("scope", "per VLAN")
        out.setdefault("dynamic", sum(v["dynamic"] for v in vlans))
        out.setdefault("static", sum(v["static"] for v in vlans))
        out.setdefault("total", sum(v["total"] or v["dynamic"] + v["static"] for v in vlans))
    elif out and "total" in out:
        out.setdefault("dynamic", dynamic)
        out.setdefault("static", static)
    return out if "total" in out else {}


def build_mac_count(clean: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for block in blocks(clean, "mac_count"):
        out = parse_mac_count(block) or out
    if out:
        out["source"] = "show mac address-table count"
    return out


def build(clean: list[str]) -> dict[str, Any]:
    """Everything this module reads, keyed the way the result carries it."""
    return {
        "vlan_db": build_vlan_db(clean),
        "descriptions": build_descriptions(clean),
        "trunks": build_trunks(clean),
        "arp_summary": build_arp_summary(clean),
        "mac_count": build_mac_count(clean),
    }
