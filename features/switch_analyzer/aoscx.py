"""ArubaOS-CX (HPE Aruba Networking CX 6000 / 6100 / 6200 / 6300 / 8xxx / 10000) show-command readers.

AOS-CX is a different operating system from ArubaOS-Switch (ProCurve / 2540 / 2930), with its own CLI, so the readers for
the latter cannot parse it. Interfaces are named ``member/slot/port`` (``1/1/24``), aggregates ``lagN``, VLAN interfaces
``vlanN``; a VSF stack prints one chassis per member (``3/1/12`` is port 12 of member 3).

Every table here is read from a command whose output was seen in a real capture of a 6200F VSF stack (JL724B, ML.10.16.1020)
or a standalone switch, unless a function says otherwise:

* ``show version``, ``show system inventory``, ``show vsf``, ``show vlan`` (+ ``summary``), ``show interface`` (every port,
  ``vlanN`` and ``lagN`` block), ``show interface transceiver``, ``show interface trunk``, ``show ip interface brief``,
  ``show arp``, ``show mac-address-table`` (+ ``count``), ``show ip route``, ``show lldp neighbor-info`` (+ ``detail``),
  ``show lag`` (+ ``brief``), ``show lacp interface`` / ``aggregate`` / ``configuration``, ``show spanning-tree``,
  ``show environment fan|led|power-supply|power-consumption|power-redundancy|temperature``, ``show clock``,
  ``show logging`` (event log, see ``logs.py``).
* ``show interface brief`` is accepted but **has not been seen in a capture**: its columns are located from the header line,
  and nothing is read if that header is not the expected one.

Documentation (opened and read):

* ``show interface`` syntax and the per-interface fields (Admin state, Link state, Link transitions, Rate and Statistic tables),
  AOS-CX 10.16 Fundamentals: https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/HTML/fundamentals_8400/Content/Chp_IfaceCfg/Iface_cmds/sho-int-10.htm
* ``show vsf`` member roles (Conductor, Standby, Member, In Other Fragment), topology (Ring, Chain) and status (No Split, Active
  Fragment, Inactive Fragment), AOS-CX 10.16 VSF Guide: https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/vsf.pdf
* ``show lacp interfaces`` state letters and Forwarding State (up, down, lacp-block), AOS-CX 10.16 Link Aggregation Guide:
  https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/link_aggregation.pdf
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text

# ----------------------------------------------------------------------------------------------------------------------
# Detection
# ----------------------------------------------------------------------------------------------------------------------

_BANNER = re.compile(
    r"^\s*AOS-CX\s*$|^!Version AOS-CX\b|^\s*Build ID\s*:\s*AOS-CX:|^\s*Admin state is (?:up|down)\s*$|^\s*Interface \d+/\d+/\d+ is (?:up|down)\b"
    r"|\bEvent\|\d+\|LOG_[A-Z]+\|"
)
_DETECT_CACHE: list[tuple[list[str], bool]] = []


def is_aoscx(clean: list[str]) -> bool:
    """True when the capture is ArubaOS-CX output (``show version`` banner, config header, ``show interface`` blocks or event-log lines)."""
    for cached, answer in _DETECT_CACHE:
        if cached is clean and len(cached) == len(clean):
            return answer
    answer = any(_BANNER.search(line) for line in clean)
    _DETECT_CACHE.append((clean, answer))
    del _DETECT_CACHE[:-4]
    return answer


# ----------------------------------------------------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------------------------------------------------

_RE_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
_RE_IP = r"\d{1,3}(?:\.\d{1,3}){3}"
_PORT = r"\d+/\d+/\d+"
_ERROR = re.compile(r"^\s*(?:%|Invalid input|Unknown (?:command|interface|vrf)\b|Unknown interface|Command not found|Incomplete command|Ambiguous command|Error\b)", re.IGNORECASE)


def _outputs(clean: list[str], patterns: list[str]) -> list[list[str]]:
    """Output of every run of a command, skipping runs that are only the device's error message."""
    found = []
    for block in capture_text.command_outputs(clean, patterns):
        if block and _ERROR.match(block[0]) and len(block) <= 2:
            continue
        found.append(block)
    return found


def _best(blocks: list[list[str]], counter=len) -> list[str]:
    """The run with the most rows (later run on a tie)."""
    best: list[str] = []
    best_count = -1
    for block in blocks:
        count = counter(block)
        if count >= best_count:
            best, best_count = block, count
    return best


def _to_int(text: str | None) -> int | None:
    value = re.sub(r"[^\d-]", "", text or "")
    return int(value) if re.fullmatch(r"-?\d+", value) else None


def _dash_spans(line: str) -> list[tuple[int, int]]:
    return [(match.start(), match.end()) for match in re.finditer(r"-+", line)]


def _header_columns(header: str, labels: list[str]) -> dict[str, int]:
    """Start column of each label in a fixed-width header (labels are looked up left to right)."""
    columns: dict[str, int] = {}
    cursor = 0
    for label in labels:
        position = header.find(label, cursor)
        if position < 0:
            return {}
        columns[label] = position
        cursor = position + len(label)
    return columns


def _slice(line: str, columns: dict[str, int], labels: list[str]) -> dict[str, str]:
    starts = [columns[label] for label in labels]
    out: dict[str, str] = {}
    for index, label in enumerate(labels):
        end = starts[index + 1] if index + 1 < len(labels) else len(line)
        out[label] = line[starts[index]:end].strip() if starts[index] < len(line) else ""
    return out


def expand_ports(text: str) -> list[str]:
    """``1/1/27-1/1/28,2/1/27,lag1`` -> ``['1/1/27', '1/1/28', '2/1/27', 'lag1']`` (a range stays within one member / slot)."""
    ports: list[str] = []
    for part in re.split(r"\s*,\s*", (text or "").strip().strip(",")):
        if not part:
            continue
        match = re.fullmatch(rf"(\d+)/(\d+)/(\d+)-(\d+)/(\d+)/(\d+)", part)
        if match:
            m1, s1, p1, m2, s2, p2 = (int(x) for x in match.groups())
            if (m1, s1) == (m2, s2) and 0 <= p2 - p1 <= 256:
                ports.extend(f"{m1}/{s1}/{n}" for n in range(p1, p2 + 1))
                continue
        lag = re.fullmatch(r"lag(\d+)-lag(\d+)", part, re.IGNORECASE)
        if lag and 0 <= int(lag.group(2)) - int(lag.group(1)) <= 256:
            ports.extend(f"lag{n}" for n in range(int(lag.group(1)), int(lag.group(2)) + 1))
            continue
        ports.append(part)
    return ports


# ----------------------------------------------------------------------------------------------------------------------
# show version / show clock
# ----------------------------------------------------------------------------------------------------------------------

def parse_version(clean: list[str]) -> dict[str, str]:
    """``show version``: release, build and image details."""
    best: dict[str, str] = {}
    for block in _outputs(clean, [r"sh(?:ow)? ver(?:sion)?"]):
        info: dict[str, str] = {}
        for line in block:
            match = re.match(r"^\s*(Version|Build Date|Build ID|Build SHA|Active Image|Service OS Version|BIOS Version|Hot Patches)\s*:\s*(.*?)\s*$", line)
            if match:
                info[match.group(1)] = match.group(2)
        if info.get("Version") and len(info) >= len(best):
            best = info
    if not best:
        return {}
    return {
        "os_version": best.get("Version", ""), "build_date": best.get("Build Date", ""), "build_id": best.get("Build ID", ""),
        "active_image": best.get("Active Image", ""), "service_os": best.get("Service OS Version", ""), "bios": best.get("BIOS Version", ""),
        "hot_patches": best.get("Hot Patches", ""),
    }


def parse_clock(clean: list[str]) -> dict[str, str]:
    """``show clock``: ``Mon Oct 12 20:21:00 WIB 2026`` and the configured time zone."""
    for block in _outputs(clean, [r"sh(?:ow)? clock"]):
        info: dict[str, str] = {}
        for line in block:
            text = line.strip()
            if re.match(r"^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", text):
                info["time"] = text
            match = re.match(r"^System is configured for timezone\s*:\s*(\S+)", text)
            if match:
                info["timezone"] = match.group(1)
        if info:
            return info
    return {}


# ----------------------------------------------------------------------------------------------------------------------
# show system inventory / show vsf
# ----------------------------------------------------------------------------------------------------------------------

def parse_system_inventory(clean: list[str]) -> list[dict[str, str]]:
    """``show system inventory``: one row per chassis, power supply, fan, module and transceiver (columns come from the dash line)."""
    rows: list[dict[str, str]] = []
    for block in _outputs(clean, [r"sh(?:ow)? system inventory"]):
        spans: list[tuple[int, int]] = []
        header_seen = False
        found: list[dict[str, str]] = []
        for line in block:
            if re.match(r"^\s*Type\s+Location\s+Product", line):
                header_seen = True
                continue
            if header_seen and re.match(r"^\s*-{3,}(?:\s+-{3,}){3,}\s*$", line):
                spans = _dash_spans(line)
                continue
            if not spans or not line.strip():
                continue
            cells = []
            for index, (start, _end) in enumerate(spans):
                stop = spans[index + 1][0] if index + 1 < len(spans) else len(line)
                cells.append(line[start:stop].strip())
            while len(cells) < 6:
                cells.append("")
            kind, location, product, description, serial, hardware = cells[:6]
            if not kind or not product:
                continue
            found.append({"type": kind, "location": location, "product_number": product, "description": description, "serial": serial, "hardware": hardware})
        if len(found) >= len(rows):
            rows = found
    return rows


def parse_vsf(clean: list[str]) -> dict[str, Any]:
    """``show vsf``: topology, split status and the member table (Conductor / Standby / Member)."""
    best: dict[str, Any] = {}
    for block in _outputs(clean, [r"sh(?:ow)? vsf"]):
        info: dict[str, Any] = {"fields": {}, "members": []}
        for line in block:
            text = line.strip()
            match = re.match(rf"^(\d+)\s+({_RE_MAC})\s+(\S+)\s+(.+?)\s*$", text)
            if match:
                info["members"].append({"slot": match.group(1), "mac": match.group(2).lower(), "model": match.group(3), "role": match.group(4)})
                continue
            match = re.match(r"^([A-Za-z][A-Za-z \-]+?)\s*:\s*(.*?)\s*$", text)
            if match and not text.startswith(("Mbr", "---")):
                info["fields"][match.group(1)] = match.group(2)
        if info["members"] and len(info["members"]) >= len(best.get("members", [])):
            best = info
    return best


def build_inventory(clean: list[str]) -> dict[str, Any]:
    """``(modules, stack)`` in the shapes ``runtime_parser.parse_inventory`` returns, plus the VSF fields."""
    rows = parse_system_inventory(clean)
    vsf = parse_vsf(clean)
    chassis = [row for row in rows if row["type"].lower() == "chassis"]
    members = [{"slot": m["slot"], "role": m["role"], "mac": m["mac"], "state": vsf["fields"].get("Status", "")} for m in vsf.get("members", [])]
    stack_size = max(len(members), len(chassis))
    stacked = stack_size >= 2
    modules: list[dict[str, str]] = []
    for row in rows:
        kind = row["type"]
        if kind.lower() == "transceiver":
            continue                       # listed by parse_transceivers (it also needs the interface status)
        if kind.lower() == "chassis":
            slot = row["location"] if stacked else "Chassis"
        else:
            slot = f"{kind} {row['location']}".strip()
        modules.append({"slot": slot, "description": row["description"], "pid": row["product_number"], "serial": row["serial"]})
    if not members and stacked:
        members = [{"slot": row["location"], "role": "", "mac": "", "state": ""} for row in chassis]
    return {
        "modules": modules,
        "stack": {"mode": "Stack" if stacked else "Standalone", "member_count": stack_size or (1 if rows else 0), "members": members,
                  "type": "VSF" if stacked else "", "secondary": vsf.get("fields", {}).get("Secondary", ""), "topology": vsf.get("fields", {}).get("Topology", ""), "split": vsf.get("fields", {}).get("Status", ""),
                  "split_detection": vsf.get("fields", {}).get("Split Detection Method", "")},
        "chassis": chassis,
        "transceivers": [row for row in rows if row["type"].lower() == "transceiver"],
    }


def model_of(chassis: list[dict[str, str]]) -> str:
    """``6200F 24G 4SFP+ Switch (JL724B)`` from the first chassis row; a mixed stack lists every distinct model."""
    models: list[str] = []
    for row in chassis:
        text = f"{row['description']} ({row['product_number']})" if row["description"] else row["product_number"]
        if text and text not in models:
            models.append(text)
    return ", ".join(models)


# ----------------------------------------------------------------------------------------------------------------------
# show interface (long form, every port / vlanN / lagN / mgmt block)
# ----------------------------------------------------------------------------------------------------------------------

_IF_HEADER = re.compile(r"^\s*(?:Interface|Aggregate)\s+(\S+)\s+is\s+(.*?)\s*$")
_STAT_ROWS = {"packets": "packets", "bytes": "bytes", "jumbos": "jumbos", "dropped": "dropped", "pause frames": "pause", "errors": "errors",
              "crc/fcs": "crc", "collision": "collisions", "runts": "runts", "giants": "giants"}
_PER_PORT_COMMAND = [r"sh(?:ow)? int(?:erfaces?)?", rf"sh(?:ow)? int(?:erfaces?)? (?:{_PORT}|lag ?\d+|vlan ?\d+|mgmt|loopback ?\d+)"]


def _kind_of(name: str) -> str:
    low = name.lower()
    if re.fullmatch(_PORT, low):
        return "port"
    if low.startswith("lag"):
        return "lag"
    if low.startswith("vlan"):
        return "vlan"
    if low.startswith("mgmt"):
        return "mgmt"
    if low.startswith("loopback"):
        return "loopback"
    return "other"


def _duration(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def parse_interfaces(clean: list[str]) -> dict[str, dict[str, Any]]:
    """Every interface block of ``show interface`` (and per-interface ``show interface <name>``) by name.

    A block starts with ``Interface 1/1/1 is up`` (or ``Interface 1/1/2 is down (Administratively down)``, ``Aggregate lag1 is up``)
    and runs to the next one. Rate and Statistic tables are read by their row labels; ``n/a`` and missing values are ``None``.
    """
    result: dict[str, dict[str, Any]] = {}
    for block in _outputs(clean, _PER_PORT_COMMAND):
        current: dict[str, Any] | None = None
        table = ""
        for raw in block:
            header = _IF_HEADER.match(raw)
            if header:
                name, state = header.group(1), header.group(2)
                oper = "up" if state.lower().startswith("up") else "down" if state.lower().startswith("down") else state.lower()
                reason = ""
                paren = re.search(r"\(([^)]*)\)", state)
                if paren:
                    reason = paren.group(1).strip()
                current = {
                    "name": name, "kind": _kind_of(name), "oper_state": oper, "reason": reason, "admin_state": "", "link_state": "",
                    "link_since": "", "link_duration": "", "transitions": None, "description": "", "mac": "", "mtu": None, "type": "",
                    "duplex": "", "speed_mbps": None, "autoneg": None, "mdi": "", "flow_control": "", "vlan_mode": "", "access_vlan": None,
                    "native_vlan": None, "allowed_vlans": "", "ipv4": [], "members": [], "lag_mode": "", "lacp_rate": "", "hash": "",
                    "rx": {}, "tx": {}, "total": {}, "rate_rx_mbps": None, "rate_tx_mbps": None, "util_rx": None, "util_tx": None,
                }
                result[name] = current
                table = ""
                continue
            if current is None:
                continue
            line = raw.rstrip()
            text = line.strip()
            if not text:
                continue
            if re.match(r"^Rate\s+RX\s+TX", text) or re.match(r"^Rates\s+RX\s+TX", text):
                table = "rate"
                continue
            if re.match(r"^Statistics?\s+RX\s+TX", text):
                table = "stat"
                continue
            if table in ("rate", "stat"):
                if re.match(r"^-{5,}", text):
                    continue
                row = re.match(r"^(.+?)\s{2,}(\S+)\s+(\S+)(?:\s+(\S+))?\s*$", text)
                if row:
                    label = row.group(1).strip().lower()
                    rx, tx, total = (None if value in ("n/a", "-", None) else _number(value) for value in (row.group(2), row.group(3), row.group(4)))
                    if table == "rate":
                        if label == "mbits / sec":
                            current["rate_rx_mbps"], current["rate_tx_mbps"] = rx, tx
                        elif label == "utilization %":
                            current["util_rx"], current["util_tx"] = rx, tx
                        continue
                    key = _STAT_ROWS.get(label) or (label if label in ("unicast", "multicast", "broadcast") else None)
                    if key:
                        current["rx"][key], current["tx"][key], current["total"][key] = rx, tx, total
                    continue
            match = re.match(r"^Admin state is (\w+)", text)
            if match:
                current["admin_state"] = match.group(1).lower()
                continue
            match = re.match(r"^Link state:\s*(.*)$", text)
            if match:
                current["link_state"] = match.group(1)
                state_match = re.match(r"^(up|down)(?:\s+for\s+(.*?))?(?:\s+\(since\s+(.*)\))?\s*$", match.group(1))
                if state_match:
                    current["link_duration"] = _duration(state_match.group(2) or "")
                    current["link_since"] = (state_match.group(3) or "").strip()
                continue
            match = re.match(r"^Link transitions:\s*(\d+)", text)
            if match:
                # an unused SFP+ cage prints 281473470948432 (2**48 - 1 - n): a counter that is not valid, not 281 trillion link changes
                value = int(match.group(1))
                current["transitions"] = value if value < 10**9 else None
                current["transitions_invalid"] = value >= 10**9
                continue
            match = re.match(r"^Description\s*:\s*(.*)$", text)
            if match:
                current["description"] = match.group(1).strip()
                continue
            match = re.match(rf"^Hardware:\s*Ethernet,\s*MAC Address:\s*({_RE_MAC})", text)
            if match or re.match(r"^MAC Address\s*:", text):
                mac = re.search(_RE_MAC, text)
                current["mac"] = mac.group(0).lower() if mac else ""
                continue
            match = re.match(r"^MTU\s+(\d+)", text)
            if match:
                current["mtu"] = int(match.group(1))
                continue
            match = re.match(r"^Type\s+(\S.*)$", text)
            if match and not text.startswith("Type :"):
                current["type"] = "" if match.group(1).strip() == "--" else match.group(1).strip()
                continue
            match = re.match(r"^Mode\s*:\s*(\S+)", text)
            if match:
                current["lag_vlan_mode"] = match.group(1).lower()
                continue
            if text in ("Full-duplex", "Half-duplex"):
                current["duplex"] = "full" if text.startswith("Full") else "half"
                continue
            match = re.match(r"^Speed\s*(?::\s*)?(\d+)\s*Mb/s", text)
            if match:
                current["speed_mbps"] = int(match.group(1))
                continue
            match = re.match(r"^Auto-negotiation is (on|off)", text)
            if match:
                current["autoneg"] = match.group(1) == "on"
                continue
            match = re.match(r"^MDI mode:\s*(\S+)", text)
            if match:
                current["mdi"] = match.group(1)
                continue
            match = re.match(r"^Flow-control:\s*(\S+)", text)
            if match:
                current["flow_control"] = match.group(1)
                continue
            match = re.match(r"^VLAN Mode:\s*(\S+)", text)
            if match:
                current["vlan_mode"] = match.group(1)
                continue
            match = re.match(r"^Access VLAN:\s*(\d+)", text)
            if match:
                current["access_vlan"] = int(match.group(1))
                continue
            match = re.match(r"^Native VLAN:\s*(\d+)", text)
            if match:
                current["native_vlan"] = int(match.group(1))
                continue
            match = re.match(r"^Allowed VLAN List:\s*(.*)$", text)
            if match:
                current["allowed_vlans"] = match.group(1).strip()
                continue
            match = re.match(rf"^IPv4 address\s+({_RE_IP}(?:/\d+)?)", text)
            if match:
                current["ipv4"].append(match.group(1))
                continue
            match = re.match(r"^Aggregated-interfaces\s*:\s*(.*)$", text)
            if match:
                current["members"] = match.group(1).split()
                continue
            match = re.match(r"^Aggregate mode\s*:\s*(\S+)", text)
            if match:
                current["lag_mode"] = match.group(1).lower()
                continue
            match = re.match(r"^LACP rate\s*:\s*(\S+)", text)
            if match:
                current["lacp_rate"] = match.group(1).lower()
                continue
            match = re.match(r"^Hash\s*:\s*(\S+)", text)
            if match:
                current["hash"] = match.group(1)
                continue
        # a block ended: nothing to flush
    return result


def _number(text: str | None) -> float | int | None:
    if text is None:
        return None
    value = text.replace(",", "")
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    return None


def interface_observations(clean: list[str]) -> list[dict[str, Any]]:
    """Live-state observations (``live_state._obs`` shape) from ``show interface``, ``show interface brief`` and ``show ip interface brief``."""
    from . import live_state                       # live_state imports show_tables; keep this module importable on its own

    observations: list[dict[str, Any]] = []
    for name, item in parse_interfaces(clean).items():
        admin = item["admin_state"]
        oper = item["oper_state"]
        if admin == "down" or (item["reason"] and "administratively" in item["reason"].lower()):
            state, detail = live_state.ADMIN_DOWN, "administratively down"
        elif oper == "up":
            state, detail = live_state.UP, "up"
            if item["speed_mbps"]:
                detail = f"up at {_speed_text(item['speed_mbps'])}"
        elif oper == "down":
            state, detail = live_state.DOWN, "down"
        else:
            continue
        extra = {"description": item["description"], "vlan_mode": item["vlan_mode"], "access_vlan": item["access_vlan"], "native_vlan": item["native_vlan"],
                 "allowed_vlans": item["allowed_vlans"], "ip_address": item["ipv4"][0] if item["ipv4"] else "", "speed_mbps": item["speed_mbps"]}
        observations.append(live_state._obs(name, state, detail, "show interface", oper, **extra))
    for name, row in parse_interface_brief(clean).items():
        observations.append(live_state._obs(name, row["state"], row["detail"], "show interface brief", row["oper"]))
    for name, row in parse_ip_interface_brief(clean).items():
        observations.append(live_state._obs(name, row["state"], row["detail"], "show ip interface brief", row["oper"], ip_address=row["ip_address"]))
    return observations


def _speed_text(mbps: int) -> str:
    return f"{mbps // 1000} Gb/s" if mbps >= 1000 and mbps % 1000 == 0 else f"{mbps} Mb/s"


_BRIEF_LABELS = ["Port", "Native", "Mode", "Type", "Enabled", "Status", "Reason", "Speed", "Description"]


def parse_interface_brief(clean: list[str]) -> dict[str, dict[str, str]]:
    """``show interface brief`` -> state per port. Columns are located from the header; any other header is ignored."""
    result: dict[str, dict[str, str]] = {}
    for block in _outputs(clean, [r"sh(?:ow)? int(?:erfaces?)? br(?:ief)?"]):
        columns: dict[str, int] = {}
        labels: list[str] = []
        for line in block:
            if re.match(r"^\s*Port\s+Native\b", line):
                found = _header_columns(line, ["Port", "Native", "Mode", "Type", "Enabled", "Status", "Reason"])
                if found:
                    labels = ["Port", "Native", "Mode", "Type", "Enabled", "Status", "Reason"]
                    speed = line.find("Speed")
                    description = line.find("Description")
                    columns = dict(found)
                    if speed > found["Reason"]:
                        columns["Speed"], labels = speed, labels + ["Speed"]
                    if description > max(columns.values()):
                        columns["Description"], labels = description, labels + ["Description"]
                continue
            if not columns or re.match(r"^\s*(?:-{3,}|VLAN\b|\(Mb/s\))", line) or not line.strip():
                continue
            cells = _slice(line, columns, labels)
            port = cells.get("Port", "")
            if not re.fullmatch(r"\S+", port) or not re.fullmatch(rf"{_PORT}|lag\d+|vlan\d+|mgmt|loopback\d+", port):
                continue
            enabled = cells.get("Enabled", "").lower()
            status = cells.get("Status", "").lower()
            reason = cells.get("Reason", "")
            if enabled == "no" or "administratively" in reason.lower():
                state, detail = "admin down", "administratively down"
            elif status == "up":
                state, detail = "up", "up"
            elif status == "down":
                state, detail = "down", reason or "down"
            else:
                continue
            result[port] = {"state": state, "detail": detail, "oper": status}
    return result


def parse_ip_interface_brief(clean: list[str]) -> dict[str, dict[str, str]]:
    """``show ip interface brief``: ``vlan150   192.0.2.1/29   up/up`` (link / admin)."""
    result: dict[str, dict[str, str]] = {}
    for block in _outputs(clean, [r"sh(?:ow)? ip int(?:erface)? br(?:ief)?"]):
        for line in block:
            match = re.match(rf"^\s*(vlan\d+|{_PORT}|lag\d+|mgmt|loopback\d+)\s+(No Address|{_RE_IP}(?:/\d+)?|\S+)\s+(up|down)/(up|down)\s*$", line, re.IGNORECASE)
            if not match:
                continue
            name, address, link, admin = match.groups()
            link, admin = link.lower(), admin.lower()
            if admin == "down":
                state, detail = "admin down", "administratively down"
            elif link == "up":
                state, detail = "up", "up"
            else:
                state, detail = "down", "link down"
            result[name] = {"state": state, "detail": detail, "oper": link, "ip_address": "" if address.lower() == "no address" else address}
    return result


# ----------------------------------------------------------------------------------------------------------------------
# show vlan / show vlan summary / show interface trunk
# ----------------------------------------------------------------------------------------------------------------------

def parse_vlan_table(clean: list[str]) -> dict[str, Any]:
    """``show vlan``: ``VLAN  Name  Status  Reason  Type  Interfaces`` (the interface list wraps onto continuation lines).

    Returns the row shape ``show_tables.parse_vlan_database`` produces (``vlan_id``, ``name``, ``status``, ``ports``), plus ``reason``
    and ``type``. Port ranges (``1/1/27-1/1/28``) are expanded to one name per port.
    """
    best: list[dict[str, Any]] = []
    for block in _outputs(clean, [r"sh(?:ow)? vlan"]):
        columns: dict[str, int] = {}
        rows: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None
        for line in block:
            if re.match(r"^\s*VLAN\s+Name\s+Status\s+Reason\s+Type\s+Interfaces", line):
                columns = _header_columns(line, ["VLAN", "Name", "Status", "Reason", "Type", "Interfaces"])
                continue
            if not columns or re.match(r"^\s*-{5,}\s*$", line):
                continue
            if re.match(r"^\s*\d+\s", line) and not line[:1].isspace():
                cells = _slice(line, columns, ["VLAN", "Name", "Status", "Reason", "Type", "Interfaces"])
                if not cells["VLAN"].isdigit():
                    continue
                current = {"vlan_id": int(cells["VLAN"]), "name": cells["Name"], "status": cells["Status"].lower(), "reason": cells["Reason"],
                           "type": cells["Type"].lower(), "ports_text": cells["Interfaces"]}
                rows.append(current)
            elif current is not None and line[:1].isspace() and line.strip():
                current["ports_text"] += line.strip()
        for row in rows:
            row["ports"] = expand_ports(row.pop("ports_text"))
        if len(rows) >= len(best):
            best = rows
    return {"rows": best, "captured": bool(best)}


def parse_vlan_summary(clean: list[str]) -> dict[str, int]:
    for block in _outputs(clean, [r"sh(?:ow)? vlan summary"]):
        info: dict[str, int] = {}
        for line in block:
            match = re.match(r"^\s*Number of (existing|static|dynamic|port-access) VLANs\s*:\s*(\d+)", line)
            if match:
                info[match.group(1)] = int(match.group(2))
        if info:
            return info
    return {}


def parse_trunks(clean: list[str]) -> list[dict[str, Any]]:
    """``show interface trunk``: ``Port  Native VLAN  Trunk VLANs`` (only the aggregates and ports the device lists as trunks)."""
    rows: list[dict[str, Any]] = []
    for block in _outputs(clean, [r"sh(?:ow)? int(?:erfaces?)? trunks?"]):
        found = []
        for line in block:
            match = re.match(rf"^\s*(lag\d+|{_PORT})\s+(\d+)\s+(\S.*?)\s*$", line)
            if match:
                port, native, allowed = match.groups()
                found.append({"port": port, "mode": "trunk", "encapsulation": "802.1q", "status": "trunking", "native_vlan": native, "port_channel": "",
                              "allowed": allowed, "active": "", "forwarding": "", "errdisabled": "", "pruned": "", "allowed_all": allowed.lower() == "all",
                              "active_count": 0, "forwarding_count": 0, "allowed_count": 0})
        if len(found) >= len(rows):
            rows = found
    return rows


# ----------------------------------------------------------------------------------------------------------------------
# show arp / show mac-address-table / show ip route
# ----------------------------------------------------------------------------------------------------------------------

def parse_arp(clean: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """``show arp``: ``IPv4 Address  MAC  Port  Physical Port  State`` -> ARP rows and the device's own entry count."""
    best: list[dict[str, Any]] = []
    reported: int | None = None
    for block in _outputs(clean, [r"sh(?:ow)? arp(?: vrf \S+)?"]):
        rows = []
        total = None
        for line in block:
            tokens = line.split()
            if len(tokens) >= 4 and re.fullmatch(_RE_IP, tokens[0]) and (re.fullmatch(_RE_MAC, tokens[1]) or tokens[1].lower() == "incomplete"):
                ip, mac, l3 = tokens[:3]
                state = tokens[-1].lower()
                physical = tokens[3] if len(tokens) >= 5 else ""
                vlan = re.fullmatch(r"vlan(\d+)", l3, re.IGNORECASE)
                rows.append({"ip_address": ip, "mac_address": "" if mac.lower() == "incomplete" else mac.lower(), "age": "", "interface": l3,
                             "type": "incomplete" if state in ("incomplete", "failed") else ("static" if state in ("permanent", "static") else "dynamic"),
                             "vlan": vlan.group(1) if vlan else "", "state": state, "physical_port": physical})
            total_match = re.match(r"^\s*Total Number Of ARP Entries Listed:\s*(\d+)", line, re.IGNORECASE)
            if total_match:
                total = int(total_match.group(1))
        if len(rows) >= len(best):
            best, reported = rows, total
    meta = {"reported": reported, "source": "Total Number Of ARP Entries Listed", "parsed": len(best), "complete": reported is None or len(best) >= reported, "captured": True} if best or reported is not None else None
    return best, meta


def parse_mac_table(clean: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """``show mac-address-table``: ``MAC Address  VLAN  Type  Port`` and the ``Number of MAC addresses`` line above the table."""
    best: list[dict[str, Any]] = []
    reported: int | None = None
    for block in _outputs(clean, [r"sh(?:ow)? mac-address-table", r"sh(?:ow)? mac-address-table (?:dynamic|static)", r"sh(?:ow)? mac-address-table vlan \d+"]):
        rows = []
        total = None
        for line in block:
            match = re.match(rf"^\s*({_RE_MAC})\s+(\d+)\s+(\S+)\s+(\S+)\s*$", line)
            if match:
                mac, vlan, kind, port = match.groups()
                rows.append({"vlan": vlan, "mac_address": mac.lower(), "type": kind.lower(), "interface": port, "age": "", "system": False})
            total_match = re.match(r"^\s*Number of MAC addresses\s*:\s*(\d+)", line)
            if total_match:
                total = int(total_match.group(1))
        if len(rows) >= len(best):
            best, reported = rows, total
    meta = {"reported": reported, "source": "Number of MAC addresses", "parsed": len(best), "complete": reported is None or len(best) >= reported, "captured": True} if best or reported is not None else None
    return best, meta


def parse_mac_count(clean: list[str]) -> dict[str, Any]:
    for block in _outputs(clean, [r"sh(?:ow)? mac-address-table count"]):
        for line in block:
            match = re.match(r"^\s*Number of MAC addresses\s*:\s*(\d+)", line)
            if match:
                return {"total": int(match.group(1)), "scope": "switch", "source": "show mac-address-table count"}
    return {}


_ORIGIN = {"C": "Connected", "S": "Static", "L": "Local", "R": "RIP", "B": "BGP", "O": "OSPF", "D": "DHCP"}


def parse_routes(clean: list[str]) -> list[dict[str, Any]]:
    """``show ip route``: ``Prefix  Nexthop  Interface  VRF(egress)  Origin/Type  Distance/Metric  Age``.

    Rows use the shape the IOS and NX-OS readers return (``protocol``, ``destination``, ``next_hop``, ``interface``) plus ``vrf``,
    ``distance``, ``metric``, ``age`` and ``detail`` (OSPF / BGP route type). ``protocol`` is the origin letter the device prints
    (``C`` connected, ``S`` static, ``L`` local, ``O`` OSPF ...) except DHCP, written ``dhcp`` because ``D`` is EIGRP on Cisco.
    An equal-cost route prints extra next-hop lines without a prefix; they repeat the previous prefix.
    """
    best: list[dict[str, Any]] = []
    for block in _outputs(clean, [r"sh(?:ow)? ip route(?: vrf \S+)?(?: \S+)?"]):
        vrf = "default"
        rows: list[dict[str, Any]] = []
        previous = ""
        for line in block:
            vrf_match = re.match(r"^\s*VRF:\s*(\S+)", line)
            if vrf_match:
                vrf, previous = vrf_match.group(1), ""
                continue
            match = re.match(
                rf"^\s*(?P<prefix>{_RE_IP}/\d+)?\s+(?P<nexthop>{_RE_IP}|-)\s+(?P<iface>\S+)\s+(?P<vrfe>\S+)\s+(?P<origin>[A-Z]+)(?:/(?P<kind>[A-Z0-9]+))?\s+\[(?P<dist>\d+)/(?P<metric>\d+)\]\s+(?P<age>\S+)\s*$",
                line)
            if not match:
                continue
            prefix = match.group("prefix") or previous
            if not prefix:
                continue
            previous = prefix
            origin = match.group("origin")
            nexthop = match.group("nexthop")
            rows.append({
                "protocol": "dhcp" if origin == "D" else origin, "destination": prefix, "next_hop": "" if nexthop == "-" else nexthop,
                "interface": match.group("iface"), "vrf": vrf, "distance": match.group("dist"), "metric": match.group("metric"),
                "age": "" if match.group("age") == "-" else match.group("age"), "detail": match.group("kind") or "",
                "origin_name": _ORIGIN.get(origin, origin), "attached": nexthop == "-",
            })
        if len(rows) >= len(best):
            best = rows
    return best


# ----------------------------------------------------------------------------------------------------------------------
# LLDP / LAG / LACP
# ----------------------------------------------------------------------------------------------------------------------

def parse_lldp(clean: list[str]) -> list[dict[str, str]]:
    """``show lldp neighbor-info detail`` (key / value blocks, preferred) or the fixed-width ``show lldp neighbor-info`` table."""
    neighbors: list[dict[str, str]] = []
    for block in _outputs(clean, [r"sh(?:ow)? lldp neighbou?r-info detail"]):
        found: list[dict[str, str]] = []
        entry: dict[str, str] | None = None
        for line in block:
            text = line.strip()
            match = re.match(rf"^Port\s*:\s*({_PORT})\s*$", text)
            if match:
                entry = {"protocol": "LLDP", "local_interface": match.group(1), "neighbor_id": "", "remote_interface": "", "platform": "", "chassis_id": "",
                         "management_address": "", "port_description": "", "ttl": "", "capabilities": "", "port_vlan": ""}
                found.append(entry)
                continue
            if entry is None:
                continue
            for label, key in (("Neighbor System-Name", "neighbor_id"), ("Neighbor System-Description", "platform"), ("Neighbor Chassis-ID", "chassis_id"),
                               ("Neighbor Management-Address", "management_address"), ("Neighbor Port-ID", "remote_interface"),
                               ("Neighbor Port-Desc", "port_description"), ("TTL", "ttl"), ("Chassis Capabilities Enabled", "capabilities"),
                               ("Neighbor Port VLAN ID", "port_vlan")):
                match = re.match(rf"^{re.escape(label)}\s*:\s*(.*)$", text)
                if match:
                    entry[key] = match.group(1).strip()
                    break
        for entry in found:
            if not entry["neighbor_id"]:
                entry["neighbor_id"] = entry["chassis_id"]
        if len(found) >= len(neighbors):
            neighbors = found
    if neighbors:
        return neighbors
    for block in _outputs(clean, [r"sh(?:ow)? lldp neighbou?r-info"]):
        columns: dict[str, int] = {}
        labels = ["LOCAL-PORT", "CHASSIS-ID", "PORT-ID", "PORT-DESC", "TTL", "SYS-NAME"]
        found = []
        for line in block:
            if re.match(r"^\s*LOCAL-PORT\s+CHASSIS-ID\s+PORT-ID", line):
                columns = _header_columns(line, labels)
                continue
            if not columns or re.match(r"^\s*-{5,}\s*$", line):
                continue
            cells = _slice(line, columns, labels)
            if re.fullmatch(_PORT, cells["LOCAL-PORT"]):
                found.append({"protocol": "LLDP", "local_interface": cells["LOCAL-PORT"], "neighbor_id": cells["SYS-NAME"] or cells["CHASSIS-ID"],
                              "remote_interface": cells["PORT-ID"], "platform": "", "chassis_id": cells["CHASSIS-ID"], "management_address": "",
                              "port_description": cells["PORT-DESC"], "ttl": cells["TTL"], "capabilities": "", "port_vlan": ""})
        if len(found) >= len(neighbors):
            neighbors = found
    return neighbors


def parse_lag(clean: list[str]) -> dict[str, dict[str, Any]]:
    """``show lag``: one block per aggregate (``Aggregate lag1 is up``) with its members, mode and hash; ``show lag brief`` adds the table."""
    lags: dict[str, dict[str, Any]] = {}
    for block in _outputs(clean, [r"sh(?:ow)? lag(?: \S+)?"]):
        current: dict[str, Any] | None = None
        system_id = ""
        for line in block:
            text = line.strip()
            match = re.match(r"^System-ID\s*:\s*(\S+)", text)
            if match:
                system_id = match.group(1).lower()
                continue
            match = re.match(r"^Aggregate\s+(lag\d+)\s+is\s+(\S+)", text, re.IGNORECASE)
            if match:
                current = lags.setdefault(match.group(1).lower(), {"name": match.group(1).lower(), "members": [], "system_id": system_id})
                current.update(oper_state=match.group(2).lower(), system_id=system_id)
                continue
            if current is None:
                continue
            for pattern, key in ((r"^Admin state is (\w+)", "admin_state"), (r"^Description\s*:\s*(.*)$", "description"), (r"^Type\s*:\s*(\S+)", "type"),
                                 (r"^Lacp Fallback\s*:\s*(\S+)", "fallback"), (rf"^MAC Address\s*:\s*({_RE_MAC})", "mac"), (r"^Aggregate mode\s*:\s*(\S+)", "mode"),
                                 (r"^Hash\s*:\s*(\S+)", "hash"), (r"^LACP rate\s*:\s*(\S+)", "lacp_rate"), (r"^Mode\s*:\s*(\S+)", "vlan_mode")):
                match = re.match(pattern, text)
                if match:
                    current[key] = match.group(1).strip().lower() if key not in ("description",) else match.group(1).strip()
                    break
            else:
                match = re.match(r"^Aggregated-interfaces\s*:\s*(.*)$", text)
                if match:
                    current["members"] = match.group(1).split()
                    continue
                match = re.match(r"^Speed\s*:\s*(\d+)\s*Mb/s", text)
                if match:
                    current["speed_mbps"] = int(match.group(1))
    for block in _outputs(clean, [r"sh(?:ow)? lag brief"]):
        for line in block:
            match = re.match(r"^\s*(lag\d+)\s+(\S+)\s+(\S+)\s+(yes|no)\s+(up|down)\s+(\d+)\s*$", line, re.IGNORECASE)
            if match:
                name = match.group(1).lower()
                item = lags.setdefault(name, {"name": name, "members": [], "system_id": ""})
                item.setdefault("mode", match.group(2).lower())
                item.setdefault("vlan_mode", match.group(3).lower())
                item.setdefault("admin_state", "up" if match.group(4).lower() == "yes" else "down")
                item.setdefault("oper_state", match.group(5).lower())
                item.setdefault("speed_mbps", int(match.group(6)))
    return lags


def parse_lacp(clean: list[str]) -> dict[str, Any]:
    """``show lacp interface``: Actor and Partner tables (``Intf  Aggr  Port  Port  State  System-ID  System  Aggr  Forwarding``).

    ``rows`` has one entry per member port with the actor and partner state letters, the partner system ID and the forwarding state.
    """
    best: dict[str, Any] = {"rows": [], "system_id": "", "priority": ""}
    for block in _outputs(clean, [r"sh(?:ow)? lacp int(?:erfaces?)?(?: \S+)?"]):
        section = ""
        actor: dict[str, dict[str, Any]] = {}
        partner: dict[str, dict[str, Any]] = {}
        order: list[tuple[str, str]] = []
        for line in block:
            text = line.strip()
            if re.match(r"^Actor details", text):
                section = "actor"
                continue
            if re.match(r"^Partner details", text):
                section = "partner"
                continue
            match = re.match(rf"^({_PORT})\s+(lag\d+)\b(.*)$", text)
            if not match or not section:
                continue
            port, aggr, rest = match.groups()
            fields = rest.split()
            record: dict[str, Any] = {"port": port, "aggregate": aggr, "port_id": "", "port_priority": "", "state": "", "system_id": "", "system_priority": "", "key": "", "forwarding": ""}
            if section == "actor":
                # `1/1/23   lag1   24   1   ALFNCD   aa:bb:..  65534  1   up`   or   `1/1/24   lag1   down` (member that is not aggregating)
                if len(fields) >= 6 and re.fullmatch(_RE_MAC, fields[3]):
                    record.update(port_id=fields[0], port_priority=fields[1], state=fields[2], system_id=fields[3].lower(), system_priority=fields[4], key=fields[5],
                                  forwarding=fields[6] if len(fields) > 6 else "")
                elif fields and fields[-1] in ("up", "down", "lacp-block"):
                    record["forwarding"] = fields[-1]
                actor[port] = record
                order.append((port, aggr))
            else:
                if len(fields) >= 6 and re.fullmatch(_RE_MAC, fields[3]):
                    record.update(port_id=fields[0], port_priority=fields[1], state=fields[2], system_id=fields[3].lower(), system_priority=fields[4], key=fields[5])
                partner[port] = record
        rows = []
        for port, aggr in order:
            local, remote = actor.get(port, {}), partner.get(port, {})
            rows.append({"port": port, "aggregate": aggr, "actor_state": local.get("state", ""), "actor_port_id": local.get("port_id", ""),
                         "forwarding": local.get("forwarding", ""), "partner_state": remote.get("state", ""), "partner_system_id": remote.get("system_id", ""),
                         "partner_port_id": remote.get("port_id", ""), "partner_key": remote.get("key", ""), "actor_key": local.get("key", "")})
        if len(rows) >= len(best["rows"]):
            best["rows"] = rows
    for block in _outputs(clean, [r"sh(?:ow)? lacp (?:configuration|aggregates?)"]):
        for line in block:
            match = re.match(rf"^\s*System-ID\s*:\s*({_RE_MAC})", line)
            if match:
                best["system_id"] = match.group(1).lower()
            match = re.match(r"^\s*System-priority\s*:\s*(\d+)", line)
            if match:
                best["priority"] = match.group(1)
    return best


def lacp_state_healthy(state: str) -> bool:
    """A partner that is aggregating and in sync: Aggregable (F), InSync (N), Collecting (C) and Distributing (D), and neither expired (X) nor on defaults (E)."""
    letters = set(state or "")
    return {"F", "N", "C", "D"} <= letters and not ({"X", "E", "I"} & letters)


# ----------------------------------------------------------------------------------------------------------------------
# show interface transceiver
# ----------------------------------------------------------------------------------------------------------------------

def parse_transceivers(clean: list[str], inventory_rows: list[dict[str, str]] | None = None) -> list[dict[str, Any]]:
    """``show interface transceiver`` (Port, Type, Product Number, Serial, Part Number); ``show system inventory`` supplies the long description."""
    described = {row["location"]: row for row in (inventory_rows or [])}
    rows: list[dict[str, Any]] = []
    for block in _outputs(clean, [r"sh(?:ow)? int(?:erfaces?)? transceivers?"]):
        found = []
        for line in block:
            match = re.match(rf"^\s*({_PORT})\s+(\S+(?: \S+)*?)\s{{2,}}(\S+)\s+(\S+)\s+(\S+)\s*$", line)
            if not match:
                match = re.match(rf"^\s*({_PORT})\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s*$", line)
            if match:
                port, kind, product, serial, part = match.groups()
                entry = described.get(port, {})
                found.append({"interface": port, "present": True, "type": entry.get("description") or kind, "vendor_part_number": product, "pid": product,
                              "serial_number": serial if serial not in ("--", "N/A") else "", "part_number": part or "", "short_type": kind})
        if len(found) >= len(rows):
            rows = found
    if not rows and inventory_rows:
        rows = [{"interface": row["location"], "present": True, "type": row["description"], "vendor_part_number": row["product_number"], "pid": row["product_number"],
                 "serial_number": row["serial"], "part_number": "", "short_type": ""} for row in inventory_rows]
    return rows


# ----------------------------------------------------------------------------------------------------------------------
# show spanning-tree
# ----------------------------------------------------------------------------------------------------------------------

_STP_ROLE = {"root": ("Root", "Root port"), "designated": ("Desg", "Designated"), "alternate": ("Altn", "Alternate"), "backup": ("Back", "Backup"),
             "disabled": ("Dis", "Disabled"), "master": ("Mstr", "Master"), "boundary": ("Boun", "Boundary")}
_STP_STATE = {"forwarding": ("FWD", "Forwarding"), "blocking": ("BLK", "Blocking"), "discarding": ("BLK", "Discarding"), "learning": ("LRN", "Learning"),
              "listening": ("LIS", "Listening"), "down": ("DIS", "Down")}


def parse_spanning_tree(clean: list[str]) -> dict[str, Any]:
    """``show spanning-tree``: the global header, then one block per VLAN (RPVST) or instance (MSTP) with a port table.

    The result has the shape of ``stp_detail.build_spanning_tree`` so the Spanning Tree tab and the findings read it unchanged.
    """
    instances: dict[str, dict[str, Any]] = {}
    summary: dict[str, str] = {}
    protocol = ""
    captured = False
    for block in _outputs(clean, [r"sh(?:ow)? spanning-tree"]):
        captured = True
        current: dict[str, Any] | None = None
        side = ""
        in_ports = False
        for line in block:
            text = line.strip()
            match = re.match(r"^Spanning tree status\s*:\s*(\S+)(?:\s+Protocol:\s*(\S+))?", text)
            if match:
                summary["Spanning tree status"] = match.group(1)
                protocol = (match.group(2) or protocol).lower()
                continue
            match = re.match(r"^(Extended System-id|Ignore PVID Inconsistency|Path cost method|RPVST-MSTP Interconnect VLAN|Current Virtual Ports Count|Maximum Allowed Virtual Ports)\s*:\s*(.+)$", text)
            if match:
                summary[match.group(1)] = match.group(2).strip()
                continue
            match = re.match(r"^(VLAN\d+|MST\d+|CIST|MST0)\s*$", text, re.IGNORECASE) if not line[:1].isspace() else None
            if match:
                name = match.group(1).upper()
                vlan = re.match(r"VLAN0*(\d+)$", name)
                current = {"id": name, "vlan": int(vlan.group(1)) if vlan else None, "protocol": protocol, "is_root": False, "root_priority": None, "root_address": "",
                           "root_cost": None, "root_port": "", "bridge_priority": None, "bridge_address": "", "hello": None, "max_age": None, "forward_delay": None,
                           "ports": [], "root_ports": 0, "blocking": 0, "inconsistent": 0, "topology_changes": None, "last_change": ""}
                instances[name] = current
                side, in_ports = "", False
                continue
            if current is None:
                continue
            match = re.match(r"^Root ID\s+Priority\s*:\s*(\d+)", text)
            if match:
                current["root_priority"], side, in_ports = int(match.group(1)), "root", False
                continue
            match = re.match(r"^Bridge ID\s+Priority\s*:\s*(\d+)", text)
            if match:
                current["bridge_priority"], side, in_ports = int(match.group(1)), "bridge", False
                continue
            if re.match(r"^This bridge is the root", text):
                current["is_root"] = True
                continue
            match = re.match(rf"^MAC-Address:\s*({_RE_MAC})", text)
            if match and side:
                current[f"{side}_address"] = match.group(1).lower()
                continue
            match = re.match(r"^Hello time\(in seconds\):(\d+)\s+Max Age\(in seconds\):(\d+)", text)
            if match and side == "bridge":
                current["hello"], current["max_age"] = int(match.group(1)), int(match.group(2))
                continue
            match = re.match(r"^Forward Delay\(in seconds\):(\d+)", text)
            if match and side == "bridge":
                current["forward_delay"] = int(match.group(1))
                continue
            if re.match(r"^Port\s+Role\s+State\s+Cost", text):
                in_ports, side = True, ""
                continue
            match = re.match(r"^Number of topology changes\s*:\s*(\d+)", text)
            if match:
                current["topology_changes"] = int(match.group(1))
                in_ports = False
                continue
            match = re.match(r"^Last topology change occurred\s*:\s*(.+)$", text)
            if match:
                current["last_change"] = match.group(1).strip()
                continue
            if in_ports:
                match = re.match(rf"^(\S+)\s+(Root|Designated|Alternate|Backup|Disabled|Master|Boundary)\s+(Forwarding|Blocking|Discarding|Learning|Listening|Down)\s+(\d+)\s+(\d+)\s+(\S+)(?:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+))?\s*$", text, re.IGNORECASE)
                if match:
                    port, role, state, cost, priority, kind = match.groups()[:6]
                    role_code, role_name = _STP_ROLE[role.lower()]
                    state_code, state_name = _STP_STATE[state.lower()]
                    current["ports"].append({
                        "instance": current["id"], "interface": port, "role": role_code, "role_name": role_name, "state": state_code, "state_name": state_name,
                        "cost": int(cost), "priority": int(priority), "port_number": 0, "type": kind, "inconsistent": "", "broken": False,
                        "bpdu_tx": int(match.group(7)) if match.group(7) else None, "bpdu_rx": int(match.group(8)) if match.group(8) else None,
                        "tcn_tx": int(match.group(9)) if match.group(9) else None, "tcn_rx": int(match.group(10)) if match.group(10) else None,
                    })
    result = sorted(instances.values(), key=lambda item: (item["vlan"] is None, item["vlan"] or 0, item["id"]))
    for item in result:
        if item["root_address"] and item["root_address"] == item["bridge_address"]:
            item["is_root"] = True
        item["root_ports"] = sum(1 for port in item["ports"] if port["role"] == "Root")
        item["blocking"] = sum(1 for port in item["ports"] if port["state"] in ("BLK", "BKN"))
        root = next((port for port in item["ports"] if port["role"] == "Root"), None)
        item["root_port"] = root["interface"] if root else ""
    ports = [port for item in result for port in item["ports"]]
    roots = sorted({item["root_address"] for item in result if item["root_address"]})
    enabled = summary.get("Spanning tree status", "").lower() == "enabled"
    return {
        "captured": captured, "enabled": enabled and bool(result), "note": "" if result else ("Spanning tree is disabled." if captured and summary and not enabled else ""),
        "summary": summary, "protocol": protocol, "instances": result, "ports": ports,
        "root_for": [item["id"] for item in result if item["is_root"]], "root_bridges": len(roots),
        "blocking": sum(1 for port in ports if port["state"] in ("BLK", "BKN")), "broken": [],
    }


# ----------------------------------------------------------------------------------------------------------------------
# show environment ...
# ----------------------------------------------------------------------------------------------------------------------

def _env_row(kind: str, name: str, location: str, state: str, reading: str, problem: bool) -> dict[str, Any]:
    return {"type": kind, "name": name, "location": location, "state": state, "reading": reading, "problem": problem}


def parse_environment(clean: list[str]) -> list[dict[str, Any]]:
    """Fans, power supplies, temperature sensors and power draw of ``show environment fan|power-supply|temperature|power-consumption``.

    A row is a problem when the device's own status word is not ``ok`` / ``normal`` (fans, PSU, sensors).
    """
    rows: list[dict[str, Any]] = []
    for block in _outputs(clean, [r"sh(?:ow)? environment fan"]):
        found = []
        for line in block:
            match = re.match(r"^\s*(\S+-\d+/\d+/\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$", line)
            if match:
                name, _product, _serial, speed, direction, status, rpm = match.groups()
                member = re.search(r"(\d+)/\d+/\d+$", name)
                found.append(_env_row("Fan", name, f"member {member.group(1)}" if member else "", status, f"{speed}, {direction}, {rpm} rpm", status.lower() not in ("ok", "normal")))
        if len(found) >= len([r for r in rows if r["type"] == "Fan"]):
            rows = [r for r in rows if r["type"] != "Fan"] + found
    for block in _outputs(clean, [r"sh(?:ow)? environment power-supply"]):
        found = []
        for line in block:
            match = re.match(r"^\s*(\d+/\d+)\s+(\S+)\s+(\S+)\s+(\S+(?: \S+)*?)\s+(AC|DC)\s+(\S+)\s+(\d+)\s*$", line)
            if match:
                name, _product, _serial, status, source, volts, watts = match.groups()
                found.append(_env_row("Power supply", name, f"member {name.split('/')[0]}", status, f"{source} {volts}, {watts} W maximum", status.lower() not in ("ok", "normal")))
        if len(found) >= len([r for r in rows if r["type"] == "Power supply"]):
            rows = [r for r in rows if r["type"] != "Power supply"] + found
    for block in _outputs(clean, [r"sh(?:ow)? environment temperature"]):
        found = []
        for line in block:
            match = re.match(r"^\s*(\d+/\d+)-(.+?)\s{2,}(\S+)\s+(-?\d+(?:\.\d+)?)\s*C\s+(\S+)\s*$", line)
            if match:
                slot, sensor, _module, value, status = match.groups()
                found.append(_env_row("Temperature", sensor.strip(), f"member {slot.split('/')[0]}", status, f"{float(value):g} °C", status.lower() not in ("normal", "ok")))
        if len(found) >= len([r for r in rows if r["type"] == "Temperature"]):
            rows = [r for r in rows if r["type"] != "Temperature"] + found
    for block in _outputs(clean, [r"sh(?:ow)? environment power-consumption"]):
        found = []
        for line in block:
            match = re.match(r"^\s*(\d+)\s+(.+?)\s{2,}(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\S+)\s+(\S+)\s*$", line)
            if match:
                name, description, instant, average, _out_i, _out_a = match.groups()
                found.append(_env_row("Power draw", f"Member {name}", description.strip(), "", f"{float(instant):g} W now, {float(average):g} W average", False))
        if len(found) >= len([r for r in rows if r["type"] == "Power draw"]):
            rows = [r for r in rows if r["type"] != "Power draw"] + found
    return rows


def environment_commands_seen(clean: list[str]) -> dict[str, bool]:
    return {
        "fan": bool(_outputs(clean, [r"sh(?:ow)? environment fan"])),
        "power-supply": bool(_outputs(clean, [r"sh(?:ow)? environment power-supply"])),
        "temperature": bool(_outputs(clean, [r"sh(?:ow)? environment temperature"])),
    }


# ----------------------------------------------------------------------------------------------------------------------
# Event log lines (``show logging``): used by logs.py and the Health tab
# ----------------------------------------------------------------------------------------------------------------------

#   2026-09-26T06:59:41.287428+00:00 6200 crash-tools[446]: Event|1206|LOG_INFO|||Module rebooted. Reason : ...
_EVENT = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<proc>[\w.\-]+)\[(?P<pid>\d+)\]:\s*"
    r"Event\|(?P<id>\d+)\|(?P<level>LOG_[A-Z]+)\|(?P<module>[^|]*)\|(?P<inst>[^|]*)\|(?P<text>.*)$"
)
LEVEL = {"LOG_EMERG": 0, "LOG_ALERT": 1, "LOG_CRIT": 2, "LOG_ERR": 3, "LOG_WARN": 4, "LOG_WARNING": 4, "LOG_NOTICE": 5, "LOG_INFO": 6, "LOG_DEBUG": 7}


def parse_event(line: str) -> dict[str, Any] | None:
    """One event-log line -> ``{style, ts, ident, tag, sev, text, module, name}`` (the ``logs.parse_message`` shape) or None."""
    if "Event|" not in line:
        return None
    match = _EVENT.match(line.strip())
    if not match:
        return None
    proc, event_id = match.group("proc"), match.group("id")
    return {"style": "aoscx", "ts": match.group("ts"), "ident": f"{proc}-{event_id}", "tag": proc, "sev": LEVEL.get(match.group("level"), 6),
            "text": match.group("text").strip(), "module": proc, "name": event_id}


_OFFSET = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


def _offset_minutes(ts: str) -> int | None:
    match = _OFFSET.search(ts)
    if not match:
        return None
    text = match.group(1)
    if text == "Z":
        return 0
    sign = 1 if text[0] == "+" else -1
    digits = text[1:].replace(":", "")
    return sign * (int(digits[:2]) * 60 + int(digits[2:]))


def normalise_times(messages: list[dict[str, Any]]) -> str:
    """Rewrite every ``ts`` to the UTC offset of the newest message (the switch prints UTC until its time zone is applied at boot).

    Returns that offset as text (``+07:00``). Lines already in that offset are not touched.
    """
    from datetime import datetime, timedelta, timezone

    target = None
    for message in reversed(messages):
        target = _offset_minutes(message["ts"])
        if target is not None:
            break
    if target is None:
        return ""
    zone = timezone(timedelta(minutes=target))
    label = f"{'+' if target >= 0 else '-'}{abs(target) // 60:02d}:{abs(target) % 60:02d}"
    for message in messages:
        offset = _offset_minutes(message["ts"])
        if offset is None or offset == target:
            continue
        text = message["ts"]
        try:
            stamp = datetime.fromisoformat(text.replace("Z", "+00:00") if text.endswith("Z") else text)
        except ValueError:
            continue
        message["ts"] = stamp.astimezone(zone).isoformat(timespec="microseconds" if "." in text else "seconds")
    return label


_DOC_ROOT = "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/"
# Event Log Message Reference Guide, AOS-CX 10.15 (the newest edition checked; the captures are 10.16). Pages opened 2026-10-12.
EVENT_DOCS = {
    "rpvst": _DOC_ROOT + "RPVST.htm", "lacp": _DOC_ROOT + "LACP.htm", "interface": _DOC_ROOT + "INTERFACE.htm", "vsf": _DOC_ROOT + "VSF.htm",
    "port_access": _DOC_ROOT + "PORT_ACCESS.htm", "acl": _DOC_ROOT + "ACL.htm", "ssh": _DOC_ROOT + "SSH_SERVER.htm",
    "sysmon": _DOC_ROOT + "SYSMON.htm", "lldp": _DOC_ROOT + "LLDP.htm", "ntp": _DOC_ROOT + "NTP.htm", "power": _DOC_ROOT + "POWER.htm",
    "home": "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/home.htm",
}
# Guides and command pages opened 2026-10-12.
GUIDE_DOCS = {
    "stp_edge": "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/HTML/l2_bridging_8400/Content/Chp_stp/use-caseMSTP_SpanEdgePorts.htm",
    "stp_port_type": "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/HTML/l2_bridging_8400/Content/Chp_stp/mstp_cmds/spa-tre-por-typ.htm",
    "acl": "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/acls_832x-93xx-100xx.pdf",
    "lag": "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/link_aggregation.pdf",
    "vsf": "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/vsf.pdf",
    "interface": "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/HTML/fundamentals_8400/Content/Chp_IfaceCfg/Iface_cmds/sho-int-10.htm",
}

_TC_GENERATED = re.compile(r"Topology change generated on port (\S+) on VLAN (\d+)")
_TC_RECEIVED = re.compile(r"Topology change received on port (\S+) from source: \S+ on VLAN (\d+)")
_ROOT_CHANGED = re.compile(r"Root changed from (\d+):\s*(\S+) to (\d+):\s*(\S+) on VLAN (\d+)")
_STARVED = re.compile(r"starved for (.+?) on port (\S+) from \S+ on VLAN (\d+)")
_LAG_STATE = re.compile(r"LAG (\d+) State change for interface (\S+): Actor state: (\S+), Partner state (\S+)")
_LACP_PORT = re.compile(r"for interface (\S+) LAG(?: sport)?:? ?(\d+)")
_PVID = re.compile(r"PVID mismatch on (\S+) pvid = (\d+), Neighbor \S+ port_id = (\S+) pvid = (\d+)")
_PORT_ACCESS = re.compile(r"Port (\S+) is (blocked|unblocked) by port-access")
_MAC_VLAN = re.compile(r"(Created|Deleted) Mac based VLAN entry.*? on port (\S+)")
_ACL_HIT = re.compile(r"List (\S+), seq# (\d+),? (permitted|denied)")
_ACL_STAT = re.compile(r"^(\S+) on (\S+) \((\S+)\):")
_SSH_FAIL = re.compile(r"User (\S+) login from (\S+) for SSH session")


def _bump(table: dict[str, Any], key: str, amount: int = 1) -> None:
    table[key] = table.get(key, 0) + amount


def _top(table: dict[str, Any], size: int = 8) -> list[tuple[str, Any]]:
    return sorted(table.items(), key=lambda item: (-item[1], item[0]))[:size]


def log_facts(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Facts the Health and Logs tabs take from the event log (Event Log Message Reference Guide ids, see ``EVENT_DOCS``).

    * ``boot``: time stamp and reason of the first ``Module rebooted`` event (1206) and the boot count (1235);
    * ``memory``: per module the newest and the highest ``Current system memory usage for module N/N is N%`` (6303);
    * ``ssh``: failed logins (5210) with the source addresses and the account names tried, successful logins (5209);
    * ``ntp``: connection established / lost counts (1105 / 1106);
    * ``vsf``: split-detection status text (9968), link-up events (9923), lost members (9913), heartbeat loss (9920);
    * ``stp``: topology changes generated (5007) and received (5006) per port, root changes per VLAN (5003), BPDU starvation (5005);
    * ``lacp``: state changes per LAG (1321), partners out of sync (1310) and lost (1311) per member port;
    * ``port_access``: blocked / unblocked counts per port (10502 / 10503) and MAC-based VLAN entries created per port (2108);
    * ``acl``: ACL log messages (10001 / 10002) per ACL, and how many of them were permits and denies;
    * ``pvid``: LLDP PVID mismatches per port (113);
    * ``buffer``: the event-log "almost full" (1223) and "wrapped" (1224) notices;
    * ``firmware``: ``Non-failsafe update needed`` notices (7210);
    * ``last_ts``: time stamp of the last message of the log (the newest one, in the offset ``normalise_times`` chose).
    """
    facts: dict[str, Any] = {
        "boot": {}, "boot_count": None, "memory": {}, "unsupported_transceivers": False, "firmware": [],
        "ssh": {"failed": 0, "ok": 0, "sources": {}, "users": {}, "last_failed": ""},
        "ntp": {"up": 0, "lost": 0, "last_lost": ""},
        "vsf": {"split_detection": "", "link_up": 0, "link_down": 0, "lost_members": 0, "heartbeat_lost": 0},
        "stp": {"generated": {}, "received": {}, "root_changes": {}, "last_root": {}, "starved": {}, "generated_total": 0, "received_total": 0},
        "lacp": {"state_changes": {}, "out_of_sync": {}, "lost": {}, "partner_detected": 0},
        "port_access": {"blocked": {}, "unblocked": {}, "mac_vlan_created": {}},
        "acl": {"messages": 0, "names": {}, "permitted": 0, "denied": 0},
        "pvid": {},
        "buffer": {"almost_full": "", "wrapped": ""}, "last_ts": "",
    }
    stp, lacp, pa, acl, ssh = facts["stp"], facts["lacp"], facts["port_access"], facts["acl"], facts["ssh"]
    for message in messages:
        if message["style"] != "aoscx":
            continue
        facts["last_ts"] = message["ts"]
        name, text = message["name"], message["text"]
        tag = message["tag"]
        if tag == "ops-switchd":
            if name == "10001":
                acl["messages"] += 1
                match = _ACL_HIT.search(text)
                if match:
                    _bump(acl["names"], match.group(1))
                    acl["permitted" if match.group(3) == "permitted" else "denied"] += 1
            elif name == "10002":
                acl["messages"] += 1
                match = _ACL_STAT.match(text)
                if match:
                    _bump(acl["names"], match.group(1))
            elif name == "2108":
                match = _MAC_VLAN.search(text)
                if match:
                    _bump(pa["mac_vlan_created"], match.group(2))
            continue
        if name == "403" or name == "404" or name == "104" or name == "105" or name == "106":
            continue
        if name == "1206" and "Module rebooted" in text:
            if not facts["boot"]:
                reason = re.search(r"Reason\s*:\s*(.*?)(?:,\s*Version:|$)", text)
                facts["boot"] = {"ts": message["ts"], "reason": (reason.group(1).strip() if reason else "")[:160]}
        elif name == "1235":
            match = re.search(r"boot count is\s*:\s*(\d+)", text)
            if match:
                facts["boot_count"] = int(match.group(1))
        elif name == "6303":
            match = re.search(r"module\s+(\d+/\d+)\s+is\s+(\d+)%", text)
            if match:
                module, value = match.group(1), int(match.group(2))
                item = facts["memory"].setdefault(module, {"last": value, "max": value, "last_ts": message["ts"], "max_ts": message["ts"], "samples": 0})
                item["last"], item["last_ts"] = value, message["ts"]
                item["samples"] += 1
                if value > item["max"]:
                    item["max"], item["max_ts"] = value, message["ts"]
        elif name == "5210":
            ssh["failed"] += 1
            ssh["last_failed"] = message["ts"]
            match = _SSH_FAIL.search(text)
            if match:
                _bump(ssh["users"], match.group(1))
                _bump(ssh["sources"], match.group(2))
        elif name == "5209":
            ssh["ok"] += 1
        elif name == "1105":
            facts["ntp"]["up"] += 1
        elif name == "1106":
            facts["ntp"]["lost"] += 1
            facts["ntp"]["last_lost"] = message["ts"]
        elif name == "9968":
            match = re.search(r"reason\s+(.*?)\.?$", text)
            facts["vsf"]["split_detection"] = match.group(1) if match else text
        elif name == "9923":
            facts["vsf"]["link_up"] += 1
        elif name == "9924":
            facts["vsf"]["link_down"] += 1
        elif name == "9913":
            facts["vsf"]["lost_members"] += 1
        elif name == "9920":
            facts["vsf"]["heartbeat_lost"] += 1
        elif name == "5007":
            match = _TC_GENERATED.search(text)
            if match:
                _bump(stp["generated"], match.group(1))
                stp["generated_total"] += 1
        elif name == "5006":
            match = _TC_RECEIVED.search(text)
            if match:
                _bump(stp["received"], match.group(1))
                stp["received_total"] += 1
        elif name == "5003":
            match = _ROOT_CHANGED.search(text)
            if match:
                vlan = match.group(5)
                _bump(stp["root_changes"], vlan)
                stp["last_root"][vlan] = {"old": f"{match.group(1)}:{match.group(2)}", "new": f"{match.group(3)}:{match.group(4)}", "ts": message["ts"]}
        elif name == "5005":
            match = _STARVED.search(text)
            if match:
                _bump(stp["starved"], match.group(2))
        elif name == "1321":
            match = _LAG_STATE.search(text)
            if match:
                _bump(lacp["state_changes"], f"lag{match.group(1)}")
        elif name == "1310":
            match = _LACP_PORT.search(text)
            if match:
                _bump(lacp["out_of_sync"], match.group(1))
        elif name == "1311":
            match = _LACP_PORT.search(text)
            if match:
                _bump(lacp["lost"], match.group(1))
        elif name == "1309":
            lacp["partner_detected"] += 1
        elif name == "10502" or name == "10503":
            match = _PORT_ACCESS.search(text)
            if match:
                _bump(pa[match.group(2)], match.group(1))
        elif name == "113":
            match = _PVID.search(text)
            if match:
                facts["pvid"][match.group(1)] = {"pvid": int(match.group(2)), "neighbor_port": match.group(3), "neighbor_pvid": int(match.group(4)),
                                                 "count": facts["pvid"].get(match.group(1), {}).get("count", 0) + 1}
        elif name == "1223":
            facts["buffer"]["almost_full"] = message["ts"]
        elif name == "1224":
            facts["buffer"]["wrapped"] = message["ts"]
        elif name == "7210":
            if len(facts["firmware"]) < 3:
                facts["firmware"].append(text[:200])
        elif name == "3801" and "allow-unsupported-transceiver" in text:
            facts["unsupported_transceivers"] = True
    return facts


# ----------------------------------------------------------------------------------------------------------------------
# Service shapes: what the Switch Analyzer tabs and the Health tab read
# ----------------------------------------------------------------------------------------------------------------------

LACP_LETTERS = {
    "A": "Active", "P": "Passive", "S": "Short timeout", "L": "Long timeout", "F": "Aggregable", "I": "Individual",
    "N": "In sync", "O": "Out of sync", "C": "Collecting", "D": "Distributing", "X": "Expired", "E": "Defaulted",
}


def lacp_letters_text(state: str) -> str:
    return ", ".join(LACP_LETTERS.get(letter, letter) for letter in (state or ""))


def build_vlan_db(clean: list[str]) -> dict[str, Any]:
    """``show vlan`` in the shape ``show_tables.build_vlan_db`` returns."""
    table = parse_vlan_table(clean)
    summary = parse_vlan_summary(clean)
    rows = [dict(row, builtin=row["vlan_id"] == 1, port_count=len(row.get("ports", [])), mtu="") for row in table.get("rows", [])]
    existing = summary.get("existing")
    return {"captured": bool(table.get("captured")), "rows": rows, "summary": summary, "source": "show vlan" if rows else "",
            "complete": existing is None or not rows or len(rows) >= existing}


def serials_view(inventory: dict[str, Any]) -> dict[str, Any]:
    """``serials.parse_serials`` shape from ``show system inventory`` (one chassis row per VSF member)."""
    from . import serials

    chassis = inventory.get("chassis", [])
    roles = {str(m.get("slot")): m.get("role", "") for m in inventory.get("stack", {}).get("members", [])}
    out = {"serial_number": "", "members": [], "display": "", "source": "", "checks": []}
    good = [row for row in chassis if serials.clean_serial(row.get("serial"))]
    if not good:
        return serials._finish(out)
    stacked = len(good) >= 2
    if stacked:
        out["members"] = [{"member": row["location"], "role": roles.get(row["location"], ""), "model": row["description"] or row["product_number"],
                           "serial": serials.clean_serial(row["serial"])} for row in good]
        lead = next((m for m in out["members"] if m["role"].lower() == "conductor"), out["members"][0])
        out["serial_number"] = lead["serial"]
    else:
        out["serial_number"] = serials.clean_serial(good[0]["serial"])
    out["source"] = "show system inventory"
    return serials._finish(out)


def port_channel_rows(lags: dict[str, dict[str, Any]], lacp: dict[str, Any], ifaces: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Rows of the Port-Channel tab: one per ``lagN`` with its members, the member LACP state and the partner system ID."""
    by_port: dict[str, dict[str, Any]] = {row["port"]: row for row in lacp.get("rows", [])}
    names = sorted(set(lags) | {row["aggregate"] for row in lacp.get("rows", [])}, key=lambda name: int(re.sub(r"\D", "", name) or 0))
    rows = []
    for name in names:
        lag = lags.get(name, {})
        detail = ifaces.get(name, {})
        members = lag.get("members") or sorted({row["port"] for row in lacp.get("rows", []) if row["aggregate"] == name})
        states = []
        partners: list[str] = []
        for port in members:
            row = by_port.get(port)
            if row is None:
                observed = ifaces.get(port, {})
                flag = "down" if observed.get("oper_state") == "down" else "no LACP"
                states.append({"port": port, "flag": flag, "meaning": "no LACP entry: link " + (observed.get("oper_state") or "state unknown")})
                continue
            forwarding = row["forwarding"] or "?"
            states.append({"port": port, "flag": forwarding,
                           "meaning": f"actor {row['actor_state'] or '-'}, partner {row['partner_state'] or '-'}" + (f" ({lacp_letters_text(row['partner_state'])})" if row["partner_state"] else "")})
            if row["partner_system_id"]:
                partners.append(row["partner_system_id"])
        mode = (lag.get("mode") or detail.get("lag_mode") or "").lower()
        rows.append({
            "name": name, "protocol": "LACP" if mode in ("active", "passive") else ("static" if mode in ("off", "static") else (mode or "")),
            "status": lag.get("oper_state") or detail.get("oper_state") or "", "members": ", ".join(members), "member_ports": list(members),   # `members` is text, as for every other vendor; the list is for the rules
            "description": lag.get("description", "") or detail.get("description", ""), "mode": lag.get("vlan_mode", "") or detail.get("vlan_mode", ""),
            "vlan": "", "allowed_vlans": "", "ip_address": "", "member_states": states,
            "lacp_partner": ", ".join(sorted(set(partners))), "lacp_mode": mode, "hash": lag.get("hash", "") or detail.get("hash", ""),
            "lacp_rate": lag.get("lacp_rate", "") or detail.get("lacp_rate", ""), "speed_mbps": lag.get("speed_mbps"),
        })
    return rows


def lacp_health_rows(lacp: dict[str, Any]) -> list[dict[str, Any]]:
    """The Health tab's LACP table (``health.parse_lacp_neighbors`` row shape) from ``show lacp interface``."""
    rows = []
    for row in lacp.get("rows", []):
        healthy = lacp_state_healthy(row["partner_state"]) and row["forwarding"] == "up"
        rows.append({
            "port": row["port"], "group": row["aggregate"], "partner_id": row["partner_system_id"] or "—", "partner_port": row["partner_port_id"] or "—",
            "healthy": healthy, "state": row["partner_state"] or "none",
            "state_bits": f"actor {row['actor_state'] or '-'} / partner {row['partner_state'] or '-'}: {lacp_letters_text(row['partner_state']) or 'no partner details'}",
            "flags": row["forwarding"] or "—", "age": "",
        })
    return rows


def interface_summary(ifaces: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Port-level facts the Health findings and the counters table use (physical ports only, not ``vlanN`` / ``lagN``)."""
    ports = [item for name, item in ifaces.items() if item.get("kind") == "port"]
    return {"ports": ports}


def build(clean: list[str]) -> dict[str, Any]:
    """Every AOS-CX table the Switch Analyzer takes from a capture, in the shapes its tabs use. ``clean`` must be an AOS-CX capture."""
    version = parse_version(clean)
    inventory = build_inventory(clean)
    ifaces = parse_interfaces(clean)
    lags = parse_lag(clean)
    lacp = parse_lacp(clean)
    arp_rows, arp_meta = parse_arp(clean)
    mac_rows, mac_meta = parse_mac_table(clean)
    trunks = parse_trunks(clean)
    lag_of = {port: name for name, lag in lags.items() for port in lag.get("members", [])}
    for row in trunks:
        row["port_channel"] = lag_of.get(row["port"], "")
        observed = ifaces.get(row["port"], {})
        if observed.get("oper_state") == "down":
            row["status"] = "not trunking (link down)"
    model = model_of(inventory["chassis"])
    clock = parse_clock(clean)
    return {
        "version": version, "clock": clock, "model": model,
        "os_version": {"os_version": version.get("os_version", ""), "model": model},
        "inventory": {"modules": inventory["modules"], "stack": inventory["stack"]},
        "serials": serials_view(inventory), "transceivers": parse_transceivers(clean, inventory["transceivers"]),
        "observations": interface_observations(clean), "interfaces": ifaces,
        "vlan_db": build_vlan_db(clean), "trunks": {"captured": bool(trunks) or bool(_outputs(clean, [r"sh(?:ow)? int(?:erfaces?)? trunks?"])), "rows": trunks},
        "stp": parse_spanning_tree(clean),
        "arp": arp_rows, "arp_meta": arp_meta, "mac": mac_rows, "mac_meta": mac_meta, "mac_count": parse_mac_count(clean),
        "routes": parse_routes(clean), "neighbors": parse_lldp(clean),
        "lags": lags, "lacp": lacp, "port_channels": port_channel_rows(lags, lacp, ifaces),
        "environment": parse_environment(clean),
    }
