from __future__ import annotations

import re

# Captures used across a full running-config + show-command bundle often
# separate each command's output with either a "------------------ show X"
# banner or a bare "#show X" / "hostname#show X" prompt echo (the same
# conventions the Wireless Analyzer's Cisco 9800 parser already handles).
_SECTION_BREAK_RE = re.compile(
    r"^(------------------\s*(show|display)\s|#\s*(show|display)\s|\S+[#>]\s*(show|display)\s)",
    re.IGNORECASE,
)


def _extract_section(lines: list[str], keywords: list[str]) -> list[str]:
    """Return the lines that follow the first occurrence of any keyword,
    stopping at the next command banner/prompt or a run of blank lines.
    """
    keywords_lower = [keyword.lower() for keyword in keywords]
    start = None

    for index, raw_line in enumerate(lines):
        low = raw_line.strip().lower()
        if any(keyword in low for keyword in keywords_lower):
            start = index + 1
            break

    if start is None:
        return []

    captured = []
    for line in lines[start:]:
        stripped = line.strip()
        if _SECTION_BREAK_RE.match(stripped):
            break
        if not stripped:
            continue
        captured.append(stripped)

    return captured


# =============================================================
# INTERFACE BRIEF (authoritative up/down status)
# =============================================================

_CISCO_IF_BRIEF_ROW = re.compile(
    r"^(\S+)\s+(\S+)\s+(YES|NO|)\s*(\S*)\s+(.+?)\s+(up|down|administratively down)$",
    re.IGNORECASE,
)
_HUAWEI_IF_BRIEF_ROW = re.compile(
    r"^(\S+)\s+(\S+)\s+(up|down|\*down|administratively down)\s+(up|down)\s*$",
    re.IGNORECASE,
)


def parse_interface_brief(lines: list[str]) -> dict[str, dict]:
    """Parse 'show ip interface brief' (Cisco) or 'display ip interface
    brief' (Huawei) into {interface_name: {ip_address, status, protocol}}.

    This is the authoritative interface state — a running-config only
    tells you whether an interface is administratively shut down, not
    whether the line protocol is actually up.
    """
    results: dict[str, dict] = {}

    cisco_section = _extract_section(lines, ["show ip interface brief"])
    for line in cisco_section:
        if line.lower().startswith("interface") and "ip-address" in line.lower():
            continue
        match = _CISCO_IF_BRIEF_ROW.match(line)
        if not match:
            continue
        name, ip_address, _ok, _method, status, protocol = match.groups()
        results[name] = {
            "ip_address": "" if ip_address.lower() == "unassigned" else ip_address,
            "status": status.strip().lower(),
            "protocol": protocol.strip().lower(),
        }

    huawei_section = _extract_section(lines, ["display ip interface brief"])
    for line in huawei_section:
        low = line.lower()
        if low.startswith("interface") or low.startswith("*down") and "physical" not in low:
            if "physical" in low or "protocol" in low:
                continue
        match = _HUAWEI_IF_BRIEF_ROW.match(line)
        if not match:
            continue
        name, ip_address, physical, protocol = match.groups()
        results[name] = {
            "ip_address": "" if ip_address.lower() == "unassigned" else ip_address,
            "status": physical.strip().lower().lstrip("*"),
            "protocol": protocol.strip().lower(),
        }

    return results


# =============================================================
# CDP / LLDP NEIGHBORS
# =============================================================

def _parse_neighbor_columns(tokens: list[str], start_idx: int = 0) -> dict | None:
    """Parse the column tokens that follow a CDP/LLDP Device ID:
    Local Interface (1-2 tokens) / Holdtime (digits) / Capability
    (one or more single-letter tokens) / Platform / Port ID (1-2 tokens).
    Column widths vary enough between devices that a fixed-width regex
    misses real-world output, so this walks the tokens instead.
    ``start_idx`` should be 1 when tokens[0] is still the Device ID
    (a short name that fit on the same line) and 0 when the Device ID
    already wrapped onto its own preceding line.
    """
    holdtime_idx = None
    for index in range(start_idx + 1, len(tokens)):
        if tokens[index].isdigit():
            holdtime_idx = index
            break
    if holdtime_idx is None or holdtime_idx <= start_idx:
        return None

    local_interface = " ".join(tokens[start_idx:holdtime_idx])
    index = holdtime_idx + 1
    while index < len(tokens) and len(tokens[index]) <= 2 and tokens[index].isalpha():
        index += 1
    if index >= len(tokens):
        return None
    platform = tokens[index]
    port_id = " ".join(tokens[index + 1:])
    return {"local_interface": local_interface, "platform": platform, "remote_interface": port_id}


def _parse_cdp_detail(lines: list[str]) -> list[dict]:
    """Parse 'show cdp neighbors detail' / 'sh cdp nei detail' output.

    Each neighbor is its own block, separated by a "----" divider line,
    with one field per line rather than a fixed-width table — a
    different format entirely from the brief summary table.
    """
    section = _extract_section(lines, [
        "show cdp neighbors detail", "sh cdp nei detail", "sh cdp neighbors detail",
    ])
    if not section:
        return []

    results = []
    current: dict = {}
    device_id_re = re.compile(r"^Device ID:\s*(.+)$", re.IGNORECASE)
    platform_re = re.compile(r"^Platform:\s*([^,]+),", re.IGNORECASE)
    interface_re = re.compile(
        r"^Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(\S+)", re.IGNORECASE
    )

    def flush():
        if current.get("neighbor_id"):
            results.append({
                "protocol": "CDP",
                "neighbor_id": current.get("neighbor_id", ""),
                "local_interface": current.get("local_interface", ""),
                "remote_interface": current.get("remote_interface", ""),
                "platform": current.get("platform", ""),
            })

    for line in section:
        if set(line) <= {"-"} and len(line) >= 5:
            flush()
            current = {}
            continue

        match = device_id_re.match(line)
        if match:
            current["neighbor_id"] = match.group(1).strip()
            continue

        match = platform_re.match(line)
        if match:
            platform = match.group(1).strip()
            platform = re.sub(r"^(cisco|huawei)\s+", "", platform, flags=re.IGNORECASE)
            current["platform"] = platform
            continue

        match = interface_re.match(line)
        if match:
            current["local_interface"] = match.group(1).strip()
            current["remote_interface"] = match.group(2).strip()
            continue

    flush()
    return results


def parse_neighbors(lines: list[str]) -> list[dict]:
    results = []

    cdp_section = _extract_section(lines, [
        "show cdp neighbors", "sh cdp nei", "show cdp nei", "sh cdp neighbors",
    ])
    pending_device_id = None
    for line in cdp_section:
        low = line.lower()
        if low.startswith("device id") or low.startswith("capability codes") or low.startswith("total cdp"):
            pending_device_id = None
            continue
        if low.startswith(("s ", "d ", "r ", "b ", "h ", "i ")) and "-" in line and pending_device_id is None:
            # Continuation of the multi-line "Capability Codes:" legend.
            continue
        tokens = line.split()
        if pending_device_id is not None:
            parsed = _parse_neighbor_columns(tokens, start_idx=0)
            device_id = pending_device_id
        else:
            parsed = _parse_neighbor_columns(tokens, start_idx=1)
            device_id = tokens[0] if tokens else ""
        if parsed is None:
            # No holdtime digit found — this line is a bare, too-long
            # Device ID that wrapped onto its own line.
            pending_device_id = line
            continue
        results.append({
            "protocol": "CDP",
            "neighbor_id": device_id,
            "local_interface": parsed["local_interface"],
            "remote_interface": parsed["remote_interface"],
            "platform": parsed["platform"],
        })
        pending_device_id = None

    lldp_cisco_section = _extract_section(lines, ["show lldp neighbors"])
    pending_lldp_id = None
    for line in lldp_cisco_section:
        low = line.lower()
        if low.startswith("device id") or "lldp is not enabled" in low or low.startswith("total entries"):
            pending_lldp_id = None
            continue
        tokens = line.split()
        # LLDP brief table: Device ID / Local Intf / Hold-time / Capability / Port ID
        holdtime_idx = None
        for index in range(1, len(tokens)):
            if tokens[index].isdigit():
                holdtime_idx = index
                break
        if holdtime_idx is None:
            pending_lldp_id = line
            continue
        device_id = pending_lldp_id or tokens[0]
        start_idx = 0 if pending_lldp_id else 1
        local_interface = " ".join(tokens[start_idx:holdtime_idx])
        remainder = tokens[holdtime_idx + 1:]
        port_id = remainder[-1] if remainder else ""
        results.append({
            "protocol": "LLDP",
            "neighbor_id": device_id,
            "local_interface": local_interface,
            "remote_interface": port_id,
            "platform": "",
        })
        pending_lldp_id = None

    lldp_huawei_section = _extract_section(lines, ["display lldp neighbor brief"])
    huawei_row_re = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+\d+$")
    for line in lldp_huawei_section:
        low = line.lower()
        if low.startswith("local intf") or low.startswith("---"):
            continue
        match = huawei_row_re.match(line)
        if match:
            local_intf, neighbor_dev, remote_intf = match.groups()
            results.append({
                "protocol": "LLDP",
                "neighbor_id": neighbor_dev,
                "local_interface": local_intf,
                "remote_interface": remote_intf,
                "platform": "",
            })

    detail_results = _parse_cdp_detail(lines)
    detail_ids = {item["neighbor_id"] for item in detail_results}
    # The detail dump repeats every neighbor the brief table already
    # listed, just with fuller interface names and an untruncated
    # platform string — prefer it over the brief row for that neighbor
    # instead of keeping both as separate near-duplicate entries.
    results = [item for item in results if item["neighbor_id"] not in detail_ids]
    results.extend(detail_results)

    return results


# =============================================================
# PORT-CHANNEL / ETH-TRUNK
# =============================================================

def parse_port_channels(lines: list[str]) -> list[dict]:
    results = []

    cisco_section = _extract_section(lines, ["show etherchannel summary", "sh etherchannel summary"])
    row_re = re.compile(r"^(\d+)\s+(Po\d+)\(([A-Za-z-]+)\)\s+(\S+)\s*(.*)$")
    for line in cisco_section:
        match = row_re.match(line)
        if not match:
            continue
        group, name, group_state, protocol, members_text = match.groups()
        members = re.findall(r"(\S+)\([A-Za-z]+\)", members_text)
        results.append({
            "name": name,
            "protocol": protocol,
            "status": group_state,
            "members": ", ".join(members),
        })

    # Huawei "display eth-trunk" is a multi-line block per trunk rather
    # than a single-line table, so it needs its own light state machine.
    trunk_header_re = re.compile(r"Eth-Trunk(\d+)'s state information", re.IGNORECASE)
    operate_status_re = re.compile(r"Operate status[:\s]+(\S+)", re.IGNORECASE)
    member_line_re = re.compile(r"^(\S+)\s+(Up|Down)\s+\d+", re.IGNORECASE)

    current_trunk = None
    for raw_line in lines:
        stripped = raw_line.strip()
        header_match = trunk_header_re.search(stripped)
        if header_match:
            if current_trunk:
                results.append(current_trunk)
            current_trunk = {
                "name": f"Eth-Trunk{header_match.group(1)}",
                "protocol": "Eth-Trunk",
                "status": "",
                "members": [],
            }
            continue
        if current_trunk is None:
            continue
        status_match = operate_status_re.search(stripped)
        if status_match:
            current_trunk["status"] = status_match.group(1)
            continue
        member_match = member_line_re.match(stripped)
        if member_match:
            current_trunk["members"].append(member_match.group(1))

    if current_trunk:
        results.append(current_trunk)

    for trunk in results:
        if isinstance(trunk.get("members"), list):
            trunk["members"] = ", ".join(trunk["members"])

    return results


# =============================================================
# OS VERSION
# =============================================================

def parse_version(lines: list[str]) -> dict:
    text = "\n".join(lines)

    cisco_version = re.search(r"Version\s+([\w.()\-]+)", text)
    cisco_model = re.search(r"[Cc]isco\s+(WS-\S+|C\d\S*|ISR\S*|ASR\S*|N\d\S*)", text)
    if cisco_version:
        return {
            "os_version": cisco_version.group(1).rstrip(","),
            "model": cisco_model.group(1) if cisco_model else "",
        }

    huawei_version = re.search(r"VRP.*?Version\s+([\d.]+\s*\([^)]*\))", text)
    huawei_model = re.search(r"HUAWEI\s+(\S+)\s+uptime", text, re.IGNORECASE)
    if huawei_version:
        return {
            "os_version": huawei_version.group(1),
            "model": huawei_model.group(1) if huawei_model else "",
        }

    return {"os_version": "", "model": ""}


# =============================================================
# IP ROUTING TABLE
# =============================================================

def parse_ip_route_table(lines: list[str]) -> list[dict]:
    results = []

    cisco_section = _extract_section(lines, ["show ip route", "sh ip route"])
    prefix_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

    for line in cisco_section:
        tokens = line.split()
        if not tokens:
            continue

        dest_idx = None
        for index, token in enumerate(tokens):
            if prefix_re.match(token):
                dest_idx = index
                break

        # No code before the destination means this isn't a route line
        # at all — e.g. "10.0.0.0/8 is variably subnetted, 154 subnets,
        # 11 masks" is just a subnet-count summary Cisco prints inline.
        if not dest_idx:
            continue

        # Route codes can be a single letter (C, S, L, O), two tokens
        # separated by a space (OSPF subtypes: "O E1", "O IA", "O N2"),
        # or one token with the subtype glued on ("O*E2" — the '*'
        # marks the candidate default route).
        code = " ".join(tokens[:dest_idx])
        destination = tokens[dest_idx]
        rest = tokens[dest_idx + 1:]

        if len(rest) >= 2 and rest[0] == "is" and rest[1] == "directly":
            results.append({
                "protocol": code,
                "destination": destination,
                "next_hop": "directly connected",
                "interface": rest[-1].rstrip(","),
            })
            continue

        if "via" in rest:
            via_idx = rest.index("via")
            if via_idx + 1 >= len(rest):
                continue
            next_hop = rest[via_idx + 1].rstrip(",")
            interface = rest[-1].rstrip(",") if len(rest) > via_idx + 2 else ""
            results.append({
                "protocol": code,
                "destination": destination,
                "next_hop": next_hop,
                "interface": interface,
            })

    huawei_section = _extract_section(lines, ["display ip routing-table"])
    huawei_row_re = re.compile(
        r"^(\S+/\d+)\s+(\S+)\s+\d+\s+\d+\s+\S+\s+(\S+)\s+(\S+)$"
    )
    for line in huawei_section:
        low = line.lower()
        if low.startswith("destination") or low.startswith("---") or "routing table" in low:
            continue
        match = huawei_row_re.match(line)
        if match:
            destination, protocol, next_hop, interface = match.groups()
            results.append({"protocol": protocol, "destination": destination, "next_hop": next_hop, "interface": interface})

    return results


# =============================================================
# ARP TABLE
# =============================================================

def parse_arp_table(lines: list[str]) -> list[dict]:
    results = []

    cisco_section = _extract_section(lines, ["show ip arp", "sh ip arp", "show arp", "sh arp"])
    row_re = re.compile(
        r"^Internet\s+(\S+)\s+(\S+)\s+([0-9a-fA-F.]{14})\s+\S+\s+(\S+)$"
    )
    for line in cisco_section:
        match = row_re.match(line)
        if match:
            ip_address, age, mac_address, interface = match.groups()
            results.append({
                "ip_address": ip_address,
                "mac_address": mac_address,
                "age": age,
                "interface": interface,
            })

    huawei_section = _extract_section(lines, ["display arp"])
    huawei_row_re = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{14})\s+(\S+)\s+\S+\s+(\S+)"
    )
    for line in huawei_section:
        low = line.lower()
        if low.startswith("ip address") or low.startswith("---"):
            continue
        match = huawei_row_re.match(line)
        if match:
            ip_address, mac_address, age, interface = match.groups()
            results.append({
                "ip_address": ip_address,
                "mac_address": mac_address,
                "age": age,
                "interface": interface,
            })

    return results
