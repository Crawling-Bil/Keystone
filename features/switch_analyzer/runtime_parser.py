from __future__ import annotations

import re

# Captures used across a full running-config + show-command bundle often
# separate each command's output with either a "------------------ show X"
# banner or a bare "#show X" / "hostname#show X" prompt echo (the same
# conventions the Wireless Analyzer's Cisco 9800 parser already handles).
#
# Real Cisco/Nexus captures often type the abbreviated "sh" instead of
# the full "show" (confirmed on a real N9108-DMZ capture where roughly
# two-thirds of the commands were "hostname# sh <rest>") — without
# recognizing that as a boundary too, a section that isn't followed by
# a full "show"/"display" command keeps capturing straight through
# every subsequent abbreviated command's output until it finally hits
# one that was typed in full, silently pulling in unrelated data. "sh"
# requires the trailing whitespace so it can't fire mid-word (e.g.
# "shutdown"). "display" has no common Huawei abbreviation this short,
# so it's left as the full word only.
_SECTION_BREAK_RE = re.compile(
    r"^(------------------\s*(show|display)\s|#\s*(show|display|sh)\s|\S+[#>]\s*(show|display|sh)\s)",
    re.IGNORECASE,
)
# Some real captures (confirmed on an Aruba 2540 ArubaOS-Switch bundle)
# type each command on its own bare line with no CLI prompt at all —
# just "show power-over-ethernet" / "show power-over-ethernet brief" /
# "show power-over-ethernet all" one after another. _SECTION_BREAK_RE
# only recognizes a banner/prompt in front of "show"/"display"/"sh", so
# without this a bare-line command boundary was invisible to it and a
# captured section ran straight through every later command's output
# too, all the way to EOF in the worst case — confirmed on that same
# capture, where the "show power-over-ethernet brief" per-port table
# (24 real ports, ~41W total) kept going into "show power-over-ethernet
# all"'s per-port dump and beyond, producing 52 bogus PoE rows and an
# ~8400W total instead of the real ~41W.
_BARE_COMMAND_RE = re.compile(r"^(show|display|sh)\s+\S", re.IGNORECASE)


def _extract_section(lines: list[str], keywords: list[str]) -> list[str]:
    """Return the lines that follow the first occurrence of the most-
    preferred keyword present, stopping at the next command banner/
    prompt (or bare command line).

    `keywords` is a preference-ordered list, most-specific/preferred
    command first (e.g. ["show vpc brief", "show vpc"]) — the whole
    file is searched for the first keyword before ever falling back to
    the second. This matters whenever two real, DIFFERENT commands are
    listed (not just "show X" vs its "sh X" abbreviation): a real
    capture commonly runs a bare summary command ("show
    power-over-ethernet") before the more useful per-port one ("...
    brief"), so scanning by raw line position instead of keyword
    preference would lock onto the wrong, less specific section
    whenever the generic command happens to appear earlier in the file
    — confirmed on a real Aruba 2540 capture, where this silently
    replaced the real 24-port PoE table with the single-row chassis
    summary further up the file.
    """
    keywords_lower = [keyword.lower() for keyword in keywords]
    start = None

    for keyword in keywords_lower:
        for index, raw_line in enumerate(lines):
            # The keyword must END the (stripped) line, not just appear
            # anywhere in it — a plain substring check made "show cdp
            # neighbors" match inside "show cdp neighbors detail" too (a
            # real collision hit on a real Aruba capture, since the brief
            # command's name is a literal prefix of the detail command's),
            # silently pulling the wrong, much longer section.
            if raw_line.strip().lower().endswith(keyword):
                start = index + 1
                break
        if start is not None:
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
        if _BARE_COMMAND_RE.match(stripped) and stripped.lower() not in keywords_lower:
            break
        captured.append(stripped)

    return captured


# =============================================================
# INTERFACE BRIEF (authoritative up/down status)
# =============================================================

_CISCO_IF_BRIEF_ROW = re.compile(
    r"^(\S+)\s+(\S+)\s+(YES|NO|)\s*(\S*)\s+(.+?)\s+(up|down|administratively down)$",
    re.IGNORECASE,
)
# Real "display ip interface brief" output always has a trailing VPN-
# instance column ("--" or a named instance like "management") after
# Physical/Protocol — e.g. "Vlanif201    10.85.28.2/23    up    up    --".
# The previous version of this regex required the line to END right
# after the Protocol column with only trailing whitespace, so it could
# NEVER match a real row — confirmed on a real S5755 draft capture,
# every single Vlanif/MEth/Eth-Trunk row in this table was silently
# dropped (0 of 10 rows parsed), leaving this command's data — the IP/
# Mask column included, already in CIDR form on real output ("x.x.x.x/
# y") — completely unused. Protocol can also carry a "(s)" spoofing
# suffix (e.g. "up(s)" on NULL0), hence "up\S*|down\S*" rather than a
# bare literal.
#
# The trailing VPN-instance column itself is only present on some real
# devices/software versions, not universally -- the pre-port Keystone
# baseline's own Huawei fixture (a real S5720 capture, still exercised
# by tests/test_switch_analyzer_runtime_parser.py) has no VPN-instance
# column at all ("Vlanif30   10.20.30.1/24   up   up", nothing after
# Protocol). Making it optional (rather than requiring exactly one
# trailing token) keeps both real formats working instead of trading
# one dropped-rows regression for the other.
_HUAWEI_IF_BRIEF_ROW = re.compile(
    r"^(\S+)\s+(\S+)\s+(up|down|\*down|\^down|administratively down)\s+(up\S*|down\S*)(?:\s+\S+)?\s*$",
    re.IGNORECASE,
)

# Huawei's "display ip interface brief" only lists L3-addressed interfaces
# (Vlanif/MEth/NULL/etc.) — a real S5755 draft capture confirmed it has NO
# rows at all for physical GE/25GE/100GE ports or Eth-Trunks. Physical
# port up/down instead comes from the separate "display interface brief"
# command (no "ip"), a different table: "Interface  PHY  Protocol  InUti
# OutUti  inErrors  outErrors", 7 whitespace-separated columns, with
# Eth-Trunk member ports indented under their trunk. PHY can be "up",
# "down", "*down" (administratively down) or "^down" (standby).
_HUAWEI_PHYSICAL_BRIEF_ROW = re.compile(
    r"^(\S+)\s+(up|down|\*down|\^down)\s+(up|down|\*down|\^down)\S*\s+"
    r"\d+(?:\.\d+)?%\s+\d+(?:\.\d+)?%\s+\d+\s+\d+\s*$",
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
            "status": physical.strip().lower().lstrip("*^"),
            "protocol": protocol.strip().lower(),
        }

    physical_section = _extract_section(lines, ["display interface brief"])
    for line in physical_section:
        if line.lower().startswith(("interface", "phy:", "*down", "^down", "(", "inuti")):
            continue
        match = _HUAWEI_PHYSICAL_BRIEF_ROW.match(line)
        if not match:
            continue
        name, phy, protocol = match.groups()
        if name in results:
            # Already have this interface from the L3 "display ip
            # interface brief" table (shouldn't normally happen — the two
            # commands cover disjoint interface types — but prefer the
            # existing entry rather than overwrite it).
            continue
        results[name] = {
            "ip_address": "",
            "status": phy.strip().lower().lstrip("*^"),
            "protocol": protocol.strip().lower(),
        }

    return results


# =============================================================
# CDP / LLDP NEIGHBORS
# =============================================================

_CAPABILITY_TOKEN_RE = re.compile(r"^[A-Za-z](,[A-Za-z])*$")


def _parse_neighbor_columns(tokens: list[str], start_idx: int = 0, has_platform: bool = True) -> dict | None:
    """Parse the column tokens that follow a CDP/LLDP Device ID.

    CDP's brief table ('show cdp neighbors') is 6 columns: Device ID /
    Local Intrfce / Holdtme / Capability (one or more single-letter
    codes) / Platform / Port ID. Cisco's LLDP brief table ('show lldp
    neighbors') is genuinely only 5 columns — Device ID / Local Intf /
    Hold-time / Capability / Port ID — there is no Platform field in
    the brief LLDP table at all (it only shows up in 'show lldp
    neighbors detail'), so ``has_platform=False`` skips straight from
    the capability codes to Port ID instead of consuming a token that
    isn't there. Column widths vary enough between real devices that a
    fixed-width regex misses real-world output, so this walks the
    tokens instead. ``start_idx`` should be 1 when tokens[0] is still
    the Device ID (a short name that fit on the same line) and 0 when
    the Device ID already wrapped onto its own preceding line.
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
    # Capability codes render differently by protocol: CDP prints them
    # as separate single-letter tokens ("S I"), LLDP prints them
    # comma-joined in one token ("B,R" / "B,R,T") — both match this,
    # neither a Port ID/interface token (always has a digit or slash)
    # nor a Platform string (always has a digit or hyphen in practice)
    # would.
    while index < len(tokens) and _CAPABILITY_TOKEN_RE.match(tokens[index]):
        index += 1
    if index >= len(tokens):
        return None
    if not has_platform:
        return {"local_interface": local_interface, "platform": "", "remote_interface": " ".join(tokens[index:])}
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


_HUAWEI_LLDP_BLOCK_HEADER_RE = re.compile(r"^(\S+)\s+has\s+(\d+)\s+neighbor\(s\)", re.IGNORECASE)


def _parse_huawei_lldp_detail(lines: list[str]) -> list[dict]:
    """Parse 'display lldp neighbor' (no "brief") — Huawei's per-port
    LLDP detail dump, one block per LOCAL interface:

        MEth0/0/0 has 1 neighbor(s):

        Neighbor index                     :1
        Chassis type                       :MAC Address
        Chassis ID                         :744d-6d51-c811
        Port ID subtype                    :Interface Name
        Port ID                            :MEth0/0/0
        Port description                   :--
        System name                        :TTC-SWCODI-BU-DMZ-S5755
        System description                 :Huawei Switch
        Huawei YunShan OS
        ...
        Device 1 infomation:
          Device serial number             :4E2650164008
          Device model name                :S5755-H48UM4Y2CZ

    A port with no neighbor prints "<if> has 0 neighbor(s)" (no colon,
    no body) — every physical port on the switch gets one of these two
    forms, confirmed on a real S5755 M-LAG pair capture (TTC-SWCODI-MN/
    BU-DMZ), which is also why this can't be parsed with a single
    fixed-width table the way the brief command can. "Device model
    name" is used as Platform here rather than the multi-line "System
    description" block (which is a free-text OS banner, not a single
    value) — the model number is the actual useful "what hardware is
    this" fact CDP's own Platform column normally carries.
    """
    section = _extract_section(lines, ["display lldp neighbor"])
    if not section:
        return []

    results: list[dict] = []
    current_iface: str | None = None
    current_block: list[str] = []

    def flush(iface: str | None, block_lines: list[str]) -> None:
        if not iface or not block_lines:
            return
        entries: list[dict] = []
        entry: dict = {}
        for raw in block_lines:
            if raw.lower().startswith("neighbor index"):
                if entry:
                    entries.append(entry)
                entry = {}
                continue
            if ":" not in raw:
                continue
            key, _, value = raw.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if value == "--":
                value = ""
            if key == "port id":
                entry["port_id"] = value
            elif key == "system name":
                entry["system_name"] = value
            elif key == "device model name":
                entry["model"] = value
        if entry:
            entries.append(entry)
        for parsed_entry in entries:
            results.append({
                "protocol": "LLDP",
                "neighbor_id": parsed_entry.get("system_name", ""),
                "local_interface": iface,
                "remote_interface": parsed_entry.get("port_id", ""),
                "platform": parsed_entry.get("model", ""),
            })

    for line in section:
        header_match = _HUAWEI_LLDP_BLOCK_HEADER_RE.match(line)
        if header_match:
            flush(current_iface, current_block)
            current_iface = header_match.group(1)
            current_block = []
            continue
        if current_iface is not None:
            current_block.append(line)
    flush(current_iface, current_block)

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
        # Same long-Device-ID-wraps-onto-its-own-line handling already
        # proven correct against real CDP-brief captures (Section 1q) —
        # a bare too-long Device ID with no holdtime digit on its line
        # becomes `pending_lldp_id` and gets stitched onto the next
        # line's columns, instead of the previous hand-rolled version
        # of this loop (which never handled wrapping at all and always
        # hardcoded platform to "" without even walking past the
        # capability-code tokens correctly).
        if pending_lldp_id is not None:
            parsed = _parse_neighbor_columns(tokens, start_idx=0, has_platform=False)
            device_id = pending_lldp_id
        else:
            parsed = _parse_neighbor_columns(tokens, start_idx=1, has_platform=False)
            device_id = tokens[0] if tokens else ""
        if parsed is None:
            pending_lldp_id = line
            continue
        results.append({
            "protocol": "LLDP",
            "neighbor_id": device_id,
            "local_interface": parsed["local_interface"],
            "remote_interface": parsed["remote_interface"],
            # Genuinely absent, not a parsing gap — Cisco's LLDP BRIEF
            # table has no Platform column at all (unlike CDP's), it
            # only appears in 'show lldp neighbors detail'.
            "platform": "",
        })
        pending_lldp_id = None

    # "display lldp neighbor brief" real column order is Local Interface
    # / Exptime(s) / Neighbor Interface / Neighbor Device — the Exptime
    # digit is the SECOND column, not a trailing one. The previous
    # regex required the LAST token to be bare digits, which a real
    # device-name last column ("TTC-SWCODI-BU-DMZ-S5755") never is —
    # confirmed on a real S5755 M-LAG pair capture, this never matched
    # a single row. The header-skip check was also looking for "local
    # intf" when the real header says "Local Interface", so it never
    # actually fired either (harmless only because the old regex never
    # matched anyway).
    lldp_huawei_section = _extract_section(lines, ["display lldp neighbor brief"])
    huawei_row_re = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$")
    for line in lldp_huawei_section:
        low = line.lower()
        if low.startswith("local interface") or low.startswith("local intf") or low.startswith("---"):
            continue
        match = huawei_row_re.match(line)
        if not match:
            continue
        local_intf, col2, col3, col4 = match.groups()
        # Column order isn't consistent across real Huawei
        # devices/software versions: the pre-port Keystone baseline's
        # own fixture (and Huawei's documented command reference) uses
        # "Local Intf / Neighbor Dev / Neighbor Intf / Exptime" (digit
        # LAST), while the real S5755 capture this parser was
        # originally built against used "Local Interface / Exptime /
        # Neighbor Interface / Neighbor Device" (digit SECOND).
        # Exptime is always the bare-digit column, so use its position
        # to disambiguate instead of hardcoding one order and silently
        # dropping every row in the other.
        if col2.isdigit():
            remote_intf, neighbor_dev = col3, col4
        elif col4.isdigit():
            neighbor_dev, remote_intf = col2, col3
        else:
            continue
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

    # "display lldp neighbor" (no "brief") — Huawei's per-port LLDP
    # detail dump, the equivalent completeness upgrade CDP already gets
    # from "show cdp neighbors detail" above. Real per-port entries here
    # carry the actual device MODEL (e.g. "S5755-H48UM4Y2CZ") where the
    # brief table only ever gives a bare hostname, so prefer a detail
    # row over its own brief row by LOCAL interface (not neighbor_id —
    # an M-LAG pair reports the SAME peer hostname on several different
    # local ports at once, so de-duplicating by neighbor_id the way CDP
    # detail does would wrongly collapse those into one row).
    huawei_detail_results = _parse_huawei_lldp_detail(lines)
    huawei_detail_local_ifaces = {item["local_interface"] for item in huawei_detail_results}
    results = [
        item for item in results
        if not (item["protocol"] == "LLDP" and item["local_interface"] in huawei_detail_local_ifaces)
    ]
    results.extend(huawei_detail_results)

    results.extend(_parse_aruba_lldp_detail(lines))
    results.extend(_parse_aruba_cdp_detail(lines))

    return results


_ARUBA_CDP_PORT_RE = re.compile(r"^Port\s*:\s*(\S+)", re.IGNORECASE)
_ARUBA_CDP_DEVICE_ID_RE = re.compile(r"^Device ID\s*:\s*(\S.*?)\s*$", re.IGNORECASE)
_ARUBA_CDP_PLATFORM_RE = re.compile(r"^Platform\s*:\s*(\S.*?)\s*$", re.IGNORECASE)
_ARUBA_CDP_DEVICE_PORT_RE = re.compile(r"^Device Port\s*:\s*(\S.*?)\s*$", re.IGNORECASE)


def _parse_aruba_cdp_detail(lines: list[str]) -> list[dict]:
    """Parse ArubaOS-Switch 'show cdp neighbors detail'. Not part of the
    official collect-script checklist for Aruba (only LLDP is) — this
    device's real capture happened to include it anyway (ArubaOS-Switch
    supports CDP passthrough for discovering Cisco neighbors), so it's
    worth capturing when present. Real format uses 'Port :'/'Device ID
    :'/'Platform :'/'Device Port :' fields, entirely different from
    Cisco's own CDP-detail layout. Same real-data pattern as the LLDP
    parser above: each port prints two blocks, and the first is
    consistently the more useful one (a real Device ID/hostname rather
    than a bare IP repeated as the ID), so only the first per port is
    kept.
    """
    section = _extract_section(lines, ["show cdp neighbors detail"])
    if not section:
        return []

    results: list[dict] = []
    seen_ports: set[str] = set()
    current: dict = {}

    def flush():
        port = current.get("port")
        device_id = current.get("device_id")
        if port and device_id and port not in seen_ports:
            seen_ports.add(port)
            results.append({
                "protocol": "CDP",
                "neighbor_id": device_id,
                "local_interface": port,
                "remote_interface": current.get("device_port", ""),
                "platform": current.get("platform", ""),
            })

    for line in section:
        if set(line) <= {"-"} and len(line) >= 5:
            flush()
            current = {}
            continue
        match = _ARUBA_CDP_PORT_RE.match(line)
        if match:
            if current.get("port"):
                flush()
                current = {}
            current["port"] = match.group(1).strip()
            continue
        match = _ARUBA_CDP_DEVICE_ID_RE.match(line)
        if match and "device_id" not in current:
            current["device_id"] = match.group(1).strip()
            continue
        match = _ARUBA_CDP_PLATFORM_RE.match(line)
        if match and "platform" not in current:
            current["platform"] = match.group(1).strip()
            continue
        match = _ARUBA_CDP_DEVICE_PORT_RE.match(line)
        if match and "device_port" not in current:
            current["device_port"] = match.group(1).strip()

    flush()
    return results


_ARUBA_LLDP_LOCAL_PORT_RE = re.compile(r"^Local Port\s*:\s*(\S+)", re.IGNORECASE)
_ARUBA_LLDP_SYSNAME_RE = re.compile(r"^SysName\s*:\s*(\S.*?)\s*$", re.IGNORECASE)
_ARUBA_LLDP_PORTID_RE = re.compile(r"^PortId\s*:\s*(\S.*?)\s*$", re.IGNORECASE)


def _parse_aruba_lldp_detail(lines: list[str]) -> list[dict]:
    """Parse ArubaOS-Switch 'show lldp info remote-device detail'.

    Verified against a real ArubaOS-Switch 2540 capture: every neighbor
    prints as TWO divider-separated blocks for the same Local Port — one
    with ChassisType 'network-address'/'mac-address' (SysName is the
    neighbor's real hostname, e.g. "NRP2000/W" or a switch's hostname),
    and one with ChassisType 'local' (SysName is instead a generic OS
    name like "Linux" or a bare platform string like "cisco WS-C3750X-
    24P" — much less useful). This keeps only the first block seen per
    Local Port, since that's consistently the more informative one in
    the real capture rather than picking arbitrarily.
    """
    section = _extract_section(lines, ["show lldp info remote-device detail"])
    if not section:
        return []

    results: list[dict] = []
    seen_ports: set[str] = set()
    current: dict = {}

    def flush():
        local_port = current.get("local_port")
        sysname = current.get("sysname")
        if local_port and sysname and local_port not in seen_ports:
            seen_ports.add(local_port)
            results.append({
                "protocol": "LLDP",
                "neighbor_id": sysname,
                "local_interface": local_port,
                "remote_interface": current.get("port_id", ""),
                "platform": "",
            })

    for line in section:
        if set(line) <= {"-"} and len(line) >= 5:
            flush()
            current = {}
            continue
        match = _ARUBA_LLDP_LOCAL_PORT_RE.match(line)
        if match:
            if current.get("local_port"):
                flush()
                current = {}
            current["local_port"] = match.group(1).strip()
            continue
        match = _ARUBA_LLDP_SYSNAME_RE.match(line)
        if match and "sysname" not in current:
            current["sysname"] = match.group(1).strip()
            continue
        match = _ARUBA_LLDP_PORTID_RE.match(line)
        if match and "port_id" not in current:
            current["port_id"] = match.group(1).strip()

    flush()
    return results


# =============================================================
# PORT-CHANNEL / ETH-TRUNK
# =============================================================

def parse_port_channels(lines: list[str]) -> list[dict]:
    results = []

    # Cisco IOS/IOS-XE 'show etherchannel summary' (Group / Port-channel /
    # Protocol / Ports — 4 columns) and NX-OS 'show port-channel summary'
    # (Group / Port-Channel / Type / Protocol / Member Ports — 5 columns,
    # verified against a real N9108-DMZ capture) share the same
    # "<group> <name>(<status>) ..." row shape but differ in whether a
    # Type column (e.g. "Eth") sits between the name and the protocol.
    # Token-based parsing handles both without needing a vendor branch:
    # whatever token isn't a member-port token (interface name ending in
    # a parenthesized flag like "(P)"/"(D)") is either the Type or the
    # Protocol, and the protocol is always the last non-member token.
    # NX-OS also wraps long member lists onto continuation lines with no
    # group number — those get appended to the previous row.
    cisco_section = _extract_section(lines, [
        "show etherchannel summary", "sh etherchannel summary",
        "show port-channel summary", "sh port-channel summary",
    ])
    row_re = re.compile(r"^(\d+)\s+(Po\d+)\(([A-Za-z-]+)\)\s+(.*)$")
    member_token_re = re.compile(r"^\S+\([A-Za-z]+\)$")
    current: dict | None = None
    for line in cisco_section:
        match = row_re.match(line)
        if match:
            if current:
                results.append(current)
            group, name, group_state, remainder = match.groups()
            tokens = remainder.split()
            members = [token for token in tokens if member_token_re.match(token)]
            non_member_tokens = [token for token in tokens if token not in members]
            protocol = non_member_tokens[-1] if non_member_tokens else ""
            current = {
                "name": name,
                "protocol": protocol,
                "status": group_state,
                "members": [re.match(r"^(\S+)\(", m).group(1) for m in members],
            }
            continue

        # Continuation line: no group/name, just more member-port tokens
        # wrapped from the previous row (real on NX-OS when a port-
        # channel has more members than fit on one line).
        if current is not None:
            tokens = line.split()
            if tokens and all(member_token_re.match(token) for token in tokens):
                current["members"].extend(re.match(r"^(\S+)\(", m).group(1) for m in tokens)

    if current:
        results.append(current)

    # Huawei "display eth-trunk" is a multi-line block per trunk rather
    # than a single-line table, so it needs its own light state machine.
    #
    # Confirmed against 2 real S5735 stack members (PDC-DAYA-SWAC-05 and
    # STR2-SWAC-1-HRGA): the real status field is literally "Operating
    # Status" (not "Operate status" — a plain typo in the old regex that
    # meant the trunk's status was never captured), and the real member
    # table's 2nd column is the LACP/manual SELECTION state — "Selected"
    # or "Unselect" (ArubaOS/Cisco docs also call out a 3rd value,
    # "Individual", not yet seen in a real capture) — never "Up"/"Down"
    # as the old regex assumed, which meant every real member row was
    # silently dropped (zero Eth-Trunk members ever captured). This
    # holds even for "Working Mode: Static" trunks, not just LACP ones.
    # A separate "Partner:" sub-table follows with different columns
    # (SysPri/SystemID in place of Status/PortType) — it must NOT be
    # mistaken for another member row, which is why the value here is
    # anchored to the real selection-state vocabulary instead of a
    # generic "any second token" match.
    trunk_header_re = re.compile(r"Eth-Trunk(\d+)'s state information", re.IGNORECASE)
    # Same cross-device label variance as the LLDP column order above:
    # some real captures say "Operating Status", but the pre-port
    # Keystone baseline's own fixture (still exercised by
    # tests/test_switch_analyzer_runtime_parser.py) says "Operate
    # status" -- match either rather than only the newer label.
    # Likewise the member table's status column is "Selected"/
    # "Unselect"/"Individual" on some devices and a plain "Up"/"Down"
    # on others (the baseline fixture again uses "Up") -- accept both
    # vocabularies instead of only the newer one.
    operate_status_re = re.compile(r"Operat(?:e|ing)\s+[Ss]tatus[:\s]+(\S+)", re.IGNORECASE)
    member_line_re = re.compile(r"^(\S+)\s+(Selected|Unselect|Individual|Up|Down)\b", re.IGNORECASE)

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

# Real Huawei CLI's chassis-level "HUAWEI CloudEngine <model> uptime"
# banner always truncates the model to just its FAMILY ("S5735-S-V2",
# "S5755-H") — confirmed on 3 real captures (TTC-SWAC-C-S5735-FIX.txt,
# TTC-SWCODI-MN-DMZ-S5755-FIX.txt, GTOPAS-MKS-SWCODI-S5755-FIX.txt,
# the last a real 2-member stack). The FULL board type ("S5735-
# S24P4XE-V2", "S5755-H48UM4Y2CZ") only ever appears elsewhere — the
# same real captures confirm "display device elabel brief"'s Type
# column, "display device elabel"'s BoardType=/Model= field (under
# [Slot_1]), "display device"'s own Type column, and the per-stack-
# member version banner line ("<model>(Master) 1 : uptime is ...")
# all agree on one identical full value. Tried in this order — the
# elabel commands are the most structured/least likely to collide with
# unrelated text, "display device" next, the version banner last since
# it's derived by a looser regex.
_HUAWEI_ELABEL_BRIEF_SLOT_ROW_RE = re.compile(r"^(\d+)\s+--\s+(\S+)")
_HUAWEI_ELABEL_DETAIL_TYPE_RE = re.compile(r"^(?:BoardType|Model)=(\S+)")
_HUAWEI_DEVICE_BARE_SLOT_ROW_RE = re.compile(r"^(\d+)\s+-\s+(\S+)")


def _parse_huawei_full_model(lines: list[str]) -> str:
    for line in _extract_section(lines, ["display device elabel brief"]):
        match = _HUAWEI_ELABEL_BRIEF_SLOT_ROW_RE.match(line)
        if match:
            return match.group(2)

    for line in _extract_section(lines, ["display device elabel"]):
        match = _HUAWEI_ELABEL_DETAIL_TYPE_RE.match(line)
        if match and match.group(1):
            return match.group(1)

    for line in _extract_section(lines, ["display device"]):
        match = _HUAWEI_DEVICE_BARE_SLOT_ROW_RE.match(line)
        if match:
            return match.group(2)

    return ""


def _parse_cisco_chassis_pid(lines: list[str]) -> str:
    """'show version's own hardware line ("cisco WS-C3650-24TS (MIPS)
    processor...") frequently omits the SKU suffix real 'show
    inventory' carries in its PID field ("WS-C3650-24TS" vs. the real
    orderable "WS-C3650-24TS-S") — confirmed on 2 real Catalyst
    captures (GTOPAS-PKU-SWCO-C3650.txt, a stack, and the standalone
    TTC-SWDI-C-3560.txt). 'show inventory's FIRST entry is always the
    chassis/stack-level summary (NAME "1" on a standalone switch, NAME
    "c36xx Stack" on a stack) carrying that precise PID — every later
    entry in the same real captures (power supplies, stack ports,
    per-member chassis rows) repeats or narrows it, never contradicts
    it, so the first entry alone is enough.
    """
    entries = _parse_cisco_inventory_entries(lines)
    return entries[0].get("pid", "") if entries else ""


def parse_version(lines: list[str]) -> dict:
    text = "\n".join(lines)

    # ArubaOS-Switch checked FIRST and on its own markers, not as a
    # fallback: the generic Cisco regexes below (a bare "Version X" and
    # "Cisco <model-looking-token>" match anywhere in the whole file,
    # not inside a specific command section) used to be the only thing
    # tried against Aruba captures too — and matched real neighbor data
    # embedded elsewhere in the file (an LLDP/CDP-visible AP's own
    # "Version:"/platform string, an unrelated Cisco device mentioned
    # in neighbor output) instead of the switch's own identity,
    # confirmed on 3 real Aruba 2540 backups where this silently
    # reported another device's model/version as this switch's own.
    # "; <MODEL> Configuration Editor" is the standard ArubaOS-Switch
    # running-config header (present on every real capture in this
    # project) and "Software revision" is 'show system's own version
    # field — both markers are Aruba-specific and don't appear in real
    # Cisco/Huawei output, so checking them first is safe regardless of
    # which vendor the file turns out to be.
    aruba_version = re.search(r"Software revision\s*:\s*(\S+)", text)
    aruba_model = re.search(r";\s*(\S+)\s+Configuration Editor", text, re.IGNORECASE)
    if not aruba_model:
        module_type = re.search(r"^module\s+\d+\s+type\s+(\S+)", text, re.IGNORECASE | re.MULTILINE)
        if module_type:
            aruba_model = module_type
    if aruba_version or aruba_model:
        return {
            "os_version": aruba_version.group(1) if aruba_version else "",
            "model": aruba_model.group(1).upper() if aruba_model else "",
        }

    # From here on (NX-OS / Huawei / generic Cisco), detection is scoped
    # to the device's OWN "show version" (Cisco/NX-OS) / "display
    # version" (Huawei) command section instead of the whole capture —
    # confirmed a real, currently-active bug on GTOPAS-MKS-SWCODI-
    # C3650.txt (a real Cisco Catalyst 3650 stack backup): its "show
    # lldp neighbors detail" section verbatim-echoes an adjacent Huawei
    # neighbor's own "System Description" field, which happens to
    # contain "VRP (R) software, Version 5.170 (S5731
    # V200R022C00SPC500)" — a real Huawei switch's banner text, printed
    # here only because THIS project is a live Cisco-to-Huawei
    # migration, so a Cisco device's own capture routinely has Huawei
    # CDP/LLDP neighbors once nearby switches are cut over. Searching
    # the whole file for huawei_marker let that ONE neighbor-echoed
    # line hijack this Cisco device's own identity entirely: os_version
    # came back as the NEIGHBOR's VRP version string, and the Huawei
    # branch returned first — so the correct "cisco WS-C3650-24TS
    # (MIPS) processor" line further down was never even reached,
    # leaving Model blank in Single Device, Compare Devices, AND Sizing
    # Assessment (all three read this one shared os_version.model
    # field). Falls back to the whole file when no command-echo line
    # precedes the banner at all (e.g. a hand-trimmed fixture with no
    # prompt) — preserving the pre-existing generic-text-search
    # behavior for those.
    own_section = (
        _extract_section(lines, ["display version", "dis version"])
        or _extract_section(lines, ["show version", "sh version", "show ver", "sh ver"])
    )
    own_text = "\n".join(own_section) if own_section else text

    # Cisco NX-OS (Nexus) also checked before the generic Cisco regex,
    # for the same reason as the Aruba branch above: confirmed on a
    # real Nexus 93108TC-EX capture, the generic "Version X" search
    # matched "Lesser General Public License (LGPL) Version 2.1" — a
    # line from the SAME device's own "sh version" open-source-license
    # boilerplate, printed just above the real "NXOS: version 9.3(5)"
    # line — reporting "2.1" as the switch's OS version. The generic
    # Cisco model regex had the same problem from the opposite
    # direction: it matched a downstream neighbor's CDP platform string
    # ("Platform: cisco C9200L-24P-4G, ...", trailing comma and all)
    # instead of this device's own "cisco Nexus9000 C93108TC-EX
    # chassis" hardware line. Both markers here are unique to NX-OS's
    # own "show version" banner and don't appear in real IOS-XE/Aruba/
    # Huawei output.
    if "Cisco Nexus Operating System (NX-OS) Software" in own_text:
        nxos_version = re.search(r"NXOS:\s*version\s+([\w.()]+)", own_text) or re.search(
            r"Cisco Nexus Operating System \(NX-OS\) Software,\s*Version\s+([\w.()]+)", own_text
        )
        nxos_model = re.search(r"cisco\s+Nexus\d*\s+(\S+)\s+chassis", own_text, re.IGNORECASE)
        return {
            "os_version": nxos_version.group(1) if nxos_version else "",
            "model": nxos_model.group(1) if nxos_model else "",
        }

    # Huawei must be checked BEFORE the generic Cisco fallback below, not
    # after it — confirmed against 3 real S5735 captures, both real
    # Huawei "display version" banners ("Huawei YunShan OS\nVersion
    # 1.25.0.1 (S5700 V600R025C00SPC500)" on newer VRP/CloudEngine-style
    # firmware, and "VRP (R) software, Version 5.170 (S5731
    # V200R022C00SPC500)" on older firmware) also satisfy the generic
    # Cisco regex a few lines down (`Version\s+([\w.()\-]+)` happily
    # matches "1.25.0.1" or "5.170" out of either banner), so with the
    # old ordering the Cisco branch fired FIRST on every real Huawei
    # device and returned early with model="" — the Huawei-specific
    # branch further below was dead code that real captures never
    # reached at all. Neither Huawei banner format contains the literal
    # string "VRP" as the old Huawei regex required, which was a second,
    # independent bug on top of the ordering issue.
    huawei_marker = re.search(
        r"VRP\s*\(R\)\s*software|Huawei YunShan OS|HUAWEI\s+CloudEngine", own_text, re.IGNORECASE
    )
    if huawei_marker:
        huawei_version = re.search(r"Version\s+([\d.]+\s*\([^)]*\))", own_text)
        # Real banner: "HUAWEI CloudEngine S5735-S-V2 uptime is ...". The
        # old regex assumed "HUAWEI <model> uptime" with nothing between
        # "HUAWEI" and the model — it never accounted for the literal
        # "CloudEngine" token real S5735 firmware inserts there, so the
        # model was always blank even once the ordering bug above is
        # fixed. That chassis-level line is only ever the model FAMILY
        # though (see _parse_huawei_full_model above) — try the FULL
        # board type first (elabel/device commands, or the per-stack-
        # member "<model>(Master) 1 : uptime is ..." banner line), and
        # only fall back to the short chassis-level form if none of
        # those are present in this capture at all. These commands are
        # each individually section-scoped inside
        # _parse_huawei_full_model itself, so they're searched on the
        # full `lines`, not just `own_text`.
        huawei_model = _parse_huawei_full_model(lines)
        if not huawei_model:
            per_member_model = re.search(r"^(\S+)\(Master\)\s+\d+\s*:\s*uptime", own_text, re.IGNORECASE | re.MULTILINE)
            huawei_model = per_member_model.group(1) if per_member_model else ""
        if not huawei_model:
            chassis_model = re.search(r"HUAWEI\s+(?:CloudEngine\s+)?(\S+)\s+uptime", own_text, re.IGNORECASE)
            huawei_model = chassis_model.group(1) if chassis_model else ""
        return {
            "os_version": huawei_version.group(1) if huawei_version else "",
            "model": huawei_model,
        }

    cisco_version = re.search(r"Version\s+([\w.()\-]+)", own_text)
    if cisco_version:
        # Prefer 'show inventory's precise, orderable chassis PID
        # ("WS-C3650-24TS-S") over 'show version's own hardware line,
        # which real IOS-XE firmware frequently prints WITHOUT the SKU
        # suffix ("cisco WS-C3650-24TS (MIPS) processor...", missing
        # the "-S") — confirmed on GTOPAS-PKU-SWCO-C3650.txt and
        # TTC-SWDI-C-3560.txt (see _parse_cisco_chassis_pid). Only
        # falls back to the generic "show version" hardware-line regex
        # when the capture has no "show inventory" section at all.
        cisco_model = _parse_cisco_chassis_pid(lines)
        if not cisco_model:
            cisco_model_match = re.search(r"[Cc]isco\s+(WS-\S+|C\d\S*|ISR\S*|ASR\S*|N\d\S*)", own_text)
            cisco_model = cisco_model_match.group(1) if cisco_model_match else ""
        return {
            "os_version": cisco_version.group(1).rstrip(","),
            "model": cisco_model,
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


# =============================================================
# TRANSCEIVER INVENTORY
# =============================================================
#
# Cisco: verified against 3 real Catalyst 3650/2960 backups this project
# was given. 'show interface transceiver' on real IOS-XE does NOT print
# a present/type/Pid table (an earlier version of this parser assumed
# that format and it silently returned zero rows on every one of those
# real backups) — it prints a DOM/optical-monitoring table (Temperature/
# Voltage/Tx Power/Rx Power) with no type or serial number at all, or
# just "No transceiver present" on a device with no SFPs installed. The
# type/Pid/serial for an installed transceiver instead comes from 'show
# inventory', which lists each populated SFP port as its own NAME/DESCR/
# PID/SN entry (e.g. NAME: "GigabitEthernet1/1/2", DESCR: "1000BaseSX
# SFP"). So the Cisco path here is a join: inventory entries whose slot
# name IS an interface name are the transceiver list, and the DOM table
# (keyed by the CLI's own abbreviated interface name, e.g. "Gi1/1/2")
# adds presence-confirmation and optical readings on top.
#
# Aruba 'show transceiver' and Huawei 'display interface transceiver'
# are NOT yet verified against a real backup (none of the 5 real
# backups this project has seen so far are Aruba or Huawei) — both
# remain best-effort against documented CLI format until real sample
# output is available, same tolerant "skip what doesn't match, never
# guess a value" approach used everywhere else in this file.

_CISCO_INTERFACE_NAME_RE = re.compile(
    r"^(GigabitEthernet|TenGigabitEthernet|FortyGigabitEthernet|HundredGigE|"
    r"TwentyFiveGigE|FastEthernet|Ethernet|Gi|Te|Fo|Hu|Twe|Fa|Eth)\d+(/\d+)*$",
    re.IGNORECASE,
)
_CISCO_TRANSCEIVER_DOM_VALUE_RE = re.compile(r"^[+-]?[\d.]+$|^N/?A$", re.IGNORECASE)
_ARUBA_TRANSCEIVER_ROW = re.compile(r"^(\S+)\s+(\S.*?)\s{2,}(\S+)\s{2,}(\S+)")
_HUAWEI_TRANSCEIVER_HEADER = re.compile(r"^(\S+)\s+transceiver information:?$", re.IGNORECASE)


def _short_cisco_interface_name(name: str) -> str:
    """Abbreviate a full interface name the way Cisco's own tables do
    (GigabitEthernet1/1/2 -> Gi1/1/2), so a DOM-table row (which uses the
    short form) and a 'show inventory' entry (which uses the full form)
    for the same physical port can be matched up."""
    for full, short in (
        ("GigabitEthernet", "Gi"), ("TenGigabitEthernet", "Te"),
        ("FortyGigabitEthernet", "Fo"), ("HundredGigE", "Hu"),
        ("TwentyFiveGigE", "Twe"), ("FastEthernet", "Fa"), ("Ethernet", "Eth"),
    ):
        if name.startswith(full):
            return short + name[len(full):]
    return name


def _parse_cisco_transceiver_dom_row(line: str) -> dict | None:
    """Parse one row of the Cisco DOM/optical table. Column count varies
    by platform — a real Catalyst 3650 backup showed a 4-value layout
    (Temperature/Voltage/Tx/Rx) on one device and a 5-value layout
    (...with a Current(mA) column inserted) on another — so this reads
    by position from each end instead of a fixed-width regex: Tx/Rx
    Power are always the last two columns on every layout seen so far,
    Temperature/Voltage are always the first two.
    """
    tokens = line.strip().split()
    if len(tokens) < 5:
        return None
    port, *values = tokens
    if not all(_CISCO_TRANSCEIVER_DOM_VALUE_RE.match(value) for value in values):
        return None
    return {
        "temperature_c": values[0],
        "voltage_v": values[1],
        "tx_power_dbm": values[-2],
        "rx_power_dbm": values[-1],
        "_port": port,
    }


# NX-OS 'show interface transceiver' (no "detail"/"details" needed) does
# NOT print the DOM/optical table the Catalyst DOM-row parser above
# expects — it prints a bare-interface-name header line followed by an
# indented "field is value" block per interface, e.g.:
#
#   Ethernet1/49
#       transceiver is present
#       type is QSFP-40G-SR4
#       name is CISCO-FINISAR
#       part number is FTL410QE4C-C1
#       serial number is FIW2619045C
#   Ethernet1/50
#       transceiver is not present
#
# Verified against a real N9108-DMZ capture. Only "transceiver is
# present" ports are kept — "not present" (empty cage) and "not
# applicable" (a fixed copper port, no cage at all) add nothing to a
# sizing assessment, same as how the Cisco inventory-based path only
# lists modules that are actually installed.
_NXOS_TRANSCEIVER_IFACE_RE = re.compile(r"^(Ethernet\d+(?:/\d+)*|Eth\d+(?:/\d+)*)$", re.IGNORECASE)


def _parse_nxos_transceiver_blocks(dom_section: list[str]) -> list[dict]:
    results: list[dict] = []
    current: dict | None = None

    def flush():
        if current and current.get("present"):
            results.append({key: value for key, value in current.items() if key != "present"} | {"present": True})

    for line in dom_section:
        if _NXOS_TRANSCEIVER_IFACE_RE.match(line):
            flush()
            current = {"interface": line, "type": "", "vendor_part_number": "", "serial_number": "", "present": False}
            continue
        if current is None:
            continue
        low = line.lower()
        if low.startswith("transceiver is present"):
            current["present"] = True
        elif low.startswith("transceiver is not"):
            current["present"] = False
        elif low.startswith("type is "):
            current["type"] = line[len("type is "):].strip()
        elif low.startswith("part number is "):
            current["vendor_part_number"] = line[len("part number is "):].strip()
        elif low.startswith("serial number is "):
            current["serial_number"] = line[len("serial number is "):].strip()

    flush()
    return results


def parse_transceivers(lines: list[str]) -> list[dict]:
    results: list[dict] = []

    dom_by_short_name: dict[str, dict] = {}
    dom_section = _extract_section(lines, [
        "show interface transceiver", "show inter transceiver", "show int transceiver",
        "sh interface transceiver", "sh inter transceiver", "sh int transceiver",
    ])
    for line in dom_section:
        parsed = _parse_cisco_transceiver_dom_row(line)
        if parsed:
            port = parsed.pop("_port")
            dom_by_short_name[port] = parsed

    results.extend(_parse_nxos_transceiver_blocks(dom_section))

    for entry in _parse_cisco_inventory_entries(lines):
        if not _CISCO_INTERFACE_NAME_RE.match(entry["slot"]):
            continue
        dom = dom_by_short_name.get(_short_cisco_interface_name(entry["slot"]), {})
        results.append({
            "interface": entry["slot"],
            "present": True,
            "type": entry["description"],
            "vendor_part_number": entry["pid"],
            "serial_number": entry["serial"],
            **dom,
        })

    # Real command on ArubaOS-Switch (verified against a real 2540
    # capture) is 'show interfaces transceiver', not the bare 'show
    # transceiver' the collect-script checklist lists — matching both.
    aruba_section = _extract_section(lines, ["show interfaces transceiver", "show transceiver"])
    for line in aruba_section:
        low = line.lower()
        if low.startswith(("port", "----", "transceiver technical")):
            continue
        match = _ARUBA_TRANSCEIVER_ROW.match(line)
        if match:
            interface, transceiver_type, product_no, serial_no = match.groups()
            results.append({
                "interface": interface,
                "present": True,
                "type": transceiver_type.strip(),
                "vendor_part_number": product_no,
                "serial_number": serial_no,
            })

    current: dict | None = None
    for raw_line in lines:
        stripped = raw_line.strip()
        header_match = _HUAWEI_TRANSCEIVER_HEADER.match(stripped)
        if header_match:
            if current:
                results.append(current)
            current = {
                "interface": header_match.group(1),
                "present": True,
                "type": "",
                "vendor_part_number": "",
                "serial_number": "",
            }
            continue
        if current is None or ":" not in stripped:
            continue
        field, _, value = stripped.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field.startswith("transceiver type"):
            current["type"] = value
        elif field.startswith("vendor part number") and value and value.lower() != "none":
            current["vendor_part_number"] = value
        elif "serial number" in field:
            # Real field name confirmed on 2 real S5735 transceivers is
            # "Manu. Serial Number" (under a "Manufacture information:"
            # sub-section) — neither "vendor serial number" nor a bare
            # "serial number" as the old code required. Matched
            # tolerantly on substring so any vendor-prefixed variant
            # ("Manu.", "Vendor", etc.) is captured the same way.
            current["serial_number"] = value

    if current:
        results.append(current)

    return results


# =============================================================
# POE (Power over Ethernet)
# =============================================================
#
# Cisco 'show power inline' (Catalyst only — Nexus is not PoE-capable, so
# this section is simply absent there, which is expected). Aruba 'show
# power-over-ethernet brief' and Huawei 'display poe information' cover
# the same ground with vendor-specific column layouts.

_CISCO_POE_ROW = re.compile(
    r"^(\S+)\s+(auto|static|off|never)\s+(on|off|faulty|denied)\s+(\S+)\s+(.+?)\s+(\S+)\s+(\S+)$",
    re.IGNORECASE,
)
# ArubaOS-Switch "show power-over-ethernet brief" real column layout
# (confirmed against a real Aruba 2540 capture — 11 columns: Port,
# Pwr Enab, Pwr Priority, Pre-std Detect, Alloc Cfg, Alloc Actual,
# PSE Pwr Rsrvd (W), PD Pwr Draw (W), PoE Port Status, PLC Cls, PLC
# Type — e.g. "1  Yes  low  off  usage  lldp  6.8 W  6.4 W  Delivering
# 4  2"). The old 4-group regex only anchored on the 2nd token being a
# status word, which on this real table is actually "Pwr Enab"
# (Yes/No) rather than the port's Delivering/Searching status, so it
# was mislabeling columns and mapping the unrelated "Pre-std Detect"
# on/off flag into "power_watts" — silently producing a garbage
# wattage. "PD Pwr Draw" (what the connected device is actually
# drawing) is used as power_watts here, matching what the CDP-detail
# PoE fallback already reports for the "Power drawn" figure.
_ARUBA_POE_ROW = re.compile(
    r"^(\d+)\s+(Yes|No)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([\d.]+)\s*W\s+([\d.]+)\s*W\s+"
    r"(Delivering|Searching|Fault|Disabled|Denied)\s+(\S+)\s+(\S+)",
    re.IGNORECASE,
)
_HUAWEI_POE_ROW = re.compile(
    r"^(\S+)\s+(Enable|Disable|On|Off|Normal|Fault)\s+(\S+)\s+([\d.]+)\s+([\d.]+)", re.IGNORECASE
)


def _parse_poe_from_cdp_detail(lines: list[str]) -> list[dict]:
    """Fallback PoE source: derive per-port power draw from 'show cdp
    neighbors detail' instead of a dedicated PoE show command.

    Real-world finding (a real LXS-SWAC-GUEST-2960 capture never ran
    'show power inline' at all — only the 'power inline never' CONFIG
    line appears, on ports where PoE was explicitly disabled; there is
    no live PoE table in that capture to parse) — but every neighbor
    block in 'show cdp neighbors detail' for a powered device (an AP,
    an IP phone) already carries its own real, measured power draw:

        Interface: GigabitEthernet1/0/6,  Port ID (outgoing port): GigabitEthernet0
        ...
        Power drawn: 15.400 Watts

    This is genuinely useful for a sizing assessment even where it's
    not the primary source — it's the actual measured draw of a
    currently-connected device, which 'show power inline's own table
    doesn't always carry either (some platforms only show admin/oper
    state and a port limit, not real consumption). Deliberately not
    directly comparable to the live-table columns: there's no admin
    state or port class here, just what CDP itself reports, so those
    fields are left blank rather than invented, and `admin_status` is
    inferred purely from a block having a Power drawn line at all
    (only powered neighbors get a row — a connected-but-unpowered
    neighbor, e.g. a laptop, has no "Power drawn" line and is
    correctly skipped, not reported as 0 W).
    """
    section = _extract_section(lines, [
        "show cdp neighbors detail", "sh cdp nei detail", "sh cdp neighbors detail",
    ])
    if not section:
        return []

    results: list[dict] = []
    current: dict = {}
    device_id_re = re.compile(r"^Device ID:\s*(.+)$", re.IGNORECASE)
    interface_re = re.compile(r"^Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(\S+)", re.IGNORECASE)
    power_re = re.compile(r"^Power drawn:\s*([\d.]+)\s*Watts?", re.IGNORECASE)

    def flush():
        if current.get("interface") and current.get("power_watts"):
            results.append({
                "interface": current["interface"],
                "admin_status": "",
                "oper_status": "on",
                "power_watts": current["power_watts"],
                "device": current.get("neighbor_id", ""),
                "class": "",
                "max_watts": "",
                "source": "cdp-detail",
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
        match = interface_re.match(line)
        if match:
            current["interface"] = match.group(1).strip()
            continue
        match = power_re.match(line)
        if match:
            current["power_watts"] = match.group(1)
            continue

    flush()
    return results


def parse_poe(lines: list[str]) -> list[dict]:
    results: list[dict] = []

    cisco_section = _extract_section(lines, ["show power inline"])
    for line in cisco_section:
        low = line.lower()
        if low.startswith(("interface", "----")):
            continue
        match = _CISCO_POE_ROW.match(line)
        if match:
            interface, admin, oper, power, device, poe_class, max_power = match.groups()
            results.append({
                "interface": interface,
                "admin_status": admin,
                "oper_status": oper,
                "power_watts": power,
                "device": device.strip(),
                "class": poe_class,
                "max_watts": max_power,
                "source": "show power inline",
            })

    aruba_section = _extract_section(lines, ["show power-over-ethernet brief", "show power-over-ethernet"])
    for line in aruba_section:
        low = line.lower()
        if low.startswith(("port", "----")):
            continue
        match = _ARUBA_POE_ROW.match(line)
        if match:
            (interface, pwr_enab, _priority, _pre_std_detect, _alloc_cfg, _alloc_actual,
             pse_rsrvd_w, pd_draw_w, status, plc_cls, _plc_type) = match.groups()
            results.append({
                "interface": interface,
                "admin_status": "Enabled" if pwr_enab.lower() == "yes" else "Disabled",
                "oper_status": status,
                "power_watts": pd_draw_w,
                "device": "",
                "class": plc_cls,
                "max_watts": pse_rsrvd_w,
                "source": "show power-over-ethernet brief",
            })

    huawei_section = _extract_section(lines, ["display poe information"])
    for line in huawei_section:
        low = line.lower()
        if low.startswith("port") or low.startswith("----") or "slot" in low:
            continue
        match = _HUAWEI_POE_ROW.match(line)
        if match:
            interface, poe_status, pse_status, power_limit, power_consume = match.groups()
            results.append({
                "interface": interface,
                "admin_status": poe_status,
                "oper_status": pse_status,
                "power_watts": power_consume,
                "device": "",
                "class": "",
                "max_watts": power_limit,
                "source": "display poe information",
            })

    if not results:
        results = _parse_poe_from_cdp_detail(lines)

    return results


# =============================================================
# vPC (Nexus) / M-LAG (Huawei H-series)
# =============================================================
#
# Nexus 'show vpc brief' prints a "Field : Value" summary block followed
# by a "vPC status" table of individual port-channels. Huawei H 'display
# m-lag summary' prints the equivalent DFS-Group / keepalive summary, and
# 'display m-lag brief' lists the per-Eth-Trunk M-LAG membership. Only
# present on switches that actually run vPC or M-LAG — an empty result
# here is expected and normal for every other device in the fleet.

_KV_LINE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 /\-]+?)\s*:\s*(.+)$")
_VPC_FIELD_MAP = {
    "vpc domain id": "domain_id",
    "peer status": "peer_status",
    "vpc keep-alive status": "keepalive_status",
    "configuration consistency status": "consistency_status",
    "vpc role": "role",
    "number of vpcs configured": "vpc_count",
    "peer gateway": "peer_gateway",
}
_VPC_ROW_RE = re.compile(
    r"^(\d+)\s+(Po\d+)\s+(up|down)\s+(success|failed|not applicable)\s+(\S+)\s+(\S+)$", re.IGNORECASE
)
_MLAG_FIELD_MAP = {
    "dfs group id": "domain_id",
    "keepalive status": "keepalive_status",
    "priority": "role",
    "consistency check": "consistency_status",
}
_MLAG_ROW_RE = re.compile(r"^(Eth-Trunk\d+)\s+(\d+)\s+(\S+)\s+(\S+)", re.IGNORECASE)

# Real Huawei CloudEngine M-LAG live status commands, confirmed on a
# real S5755 M-LAG pair capture (TTC-SWCODI-MN/BU-DMZ) — "display
# m-lag summary" / "display m-lag brief" above are a DIFFERENT,
# apparently never-actually-seen-in-this-project command family that
# never matched a single real capture; the real CLI verbs are all
# "display dfs-group ...":
#
#   display dfs-group                    (per-group summary)
#   display dfs-group m-lag brief        (per-Eth-Trunk M-LAG member table)
#   display dfs-group <id> heartbeat     (Local/Peer keepalive detail)
_HUAWEI_DFS_GROUP_FIELD_MAP = {
    "dfs-group id": "domain_id",
    "dual-active address": "peer_keepalive_source_ip",
    "vpn-instance": "peer_keepalive_vrf",
    "configuration consistency check": "consistency_status",
}
# "6     Eth-Trunk 6    active-active    Down          inactive(*)-inactive  success"
# Real output puts a space inside "Eth-Trunk 6" (unlike every other
# Huawei command in this project, which always writes "Eth-Trunk6" with
# no space) — captured as two separate groups and rejoined without the
# space so it still matches _port_channel_interface_key's expansion.
_HUAWEI_MLAG_MEMBER_ROW_RE = re.compile(
    r"^(\d+)\s+Eth-Trunk\s*(\d+)\s+(\S+)\s+(up|down)\s+(\S+)\s+(\S+)\s*$", re.IGNORECASE
)
_HUAWEI_HEARTBEAT_CMD_RE = re.compile(r"display\s+dfs-group\s+\d+\s+heartbeat\s*$", re.IGNORECASE)


def _extract_section_matching(lines: list[str], pattern: re.Pattern) -> list[str]:
    """Like _extract_section, but the section-starting command line is
    found by a regex instead of an exact keyword suffix — needed for
    'display dfs-group <id> heartbeat', whose group ID varies per
    device rather than being a fixed literal string.
    """
    start = None
    for index, raw_line in enumerate(lines):
        if pattern.search(raw_line.strip()):
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
        if _BARE_COMMAND_RE.match(stripped):
            break
        captured.append(stripped)
    return captured


def _parse_huawei_dfs_heartbeat(lines: list[str]) -> dict[str, str]:
    """Parse 'display dfs-group <id> heartbeat':

        Heart beat status     : OK
        Local:
          Dfs-Group ID        : 1
          ...
          Heart beat state    : Master
        Peer:
          Dfs-Group ID        : 1
          ...
          Dual-active Address : 1.1.1.6
          Heart beat state    : Backup

    "Heart beat state" under Local is this switch's own M-LAG role
    (Master/Backup) — the closest real Huawei equivalent to Cisco vPC's
    "vPC role" field. The Peer block's own Dual-active Address is a
    live-confirmed version of the same peer IP the static "dual-active
    detection ... peer ..." config line already gives (see
    SwitchConfig.mlag_dual_active_peer_ip) — kept here too so a live
    value is preferred over the config-derived one when both exist.
    """
    section = _extract_section_matching(lines, _HUAWEI_HEARTBEAT_CMD_RE)
    if not section:
        return {}

    result: dict[str, str] = {}
    current_side = None
    for line in section:
        low = line.lower()
        if low == "local:":
            current_side = "local"
            continue
        if low == "peer:":
            current_side = "peer"
            continue
        match = _KV_LINE_RE.match(line)
        if not match:
            continue
        key = match.group(1).strip().lower()
        value = match.group(2).strip()
        if key == "heart beat status":
            result["keepalive_status"] = value
        elif key == "heart beat state" and current_side == "local":
            result["role"] = value
        elif key == "dual-active address" and current_side == "peer":
            result["peer_keepalive_dest_ip"] = value
    return result


def parse_vpc_mlag(lines: list[str]) -> dict:
    summary: dict[str, str] = {}
    members: list[dict] = []

    vpc_section = _extract_section(lines, ["show vpc brief", "show vpc", "sh vpc brief", "sh vpc"])
    for line in vpc_section:
        match = _KV_LINE_RE.match(line)
        if match and match.group(1).strip().lower() in _VPC_FIELD_MAP:
            summary[_VPC_FIELD_MAP[match.group(1).strip().lower()]] = match.group(2).strip()
    for line in vpc_section:
        match = _VPC_ROW_RE.match(line)
        if match:
            vpc_id, port, status, consistency, _reason, vlans = match.groups()
            members.append({"id": vpc_id, "port": port, "status": status, "consistency": consistency, "vlans": vlans})

    mlag_section = _extract_section(lines, ["display m-lag summary"])
    for line in mlag_section:
        match = _KV_LINE_RE.match(line)
        if match and match.group(1).strip().lower() in _MLAG_FIELD_MAP:
            summary[_MLAG_FIELD_MAP[match.group(1).strip().lower()]] = match.group(2).strip()

    mlag_brief_section = _extract_section(lines, ["display m-lag brief"])
    for line in mlag_brief_section:
        match = _MLAG_ROW_RE.match(line)
        if match:
            port, mlag_id, local_status, peer_status = match.groups()
            members.append({"id": mlag_id, "port": port, "status": local_status, "consistency": peer_status, "vlans": ""})

    dfs_group_section = _extract_section(lines, ["display dfs-group"])
    for line in dfs_group_section:
        match = _KV_LINE_RE.match(line)
        if match and match.group(1).strip().lower() in _HUAWEI_DFS_GROUP_FIELD_MAP:
            summary[_HUAWEI_DFS_GROUP_FIELD_MAP[match.group(1).strip().lower()]] = match.group(2).strip()

    for key, value in _parse_huawei_dfs_heartbeat(lines).items():
        summary.setdefault(key, value)

    dfs_member_section = _extract_section(lines, ["display dfs-group m-lag brief"])
    for line in dfs_member_section:
        match = _HUAWEI_MLAG_MEMBER_ROW_RE.match(line)
        if match:
            mlag_id, trunk_num, _mode, port_state, _status_col, consistency_col = match.groups()
            members.append({
                "id": mlag_id,
                "port": f"Eth-Trunk{trunk_num}",
                "status": port_state.strip().lower(),
                "consistency": consistency_col.strip(),
                "vlans": "",
            })

    return {"summary": summary, "members": members}


# =============================================================
# CHASSIS INVENTORY / STACK-VS-STANDALONE
# =============================================================
#
# Cisco 'show inventory' is a well-known, stable two-line-per-module
# format across IOS/IOS-XE/NX-OS. Stack membership comes from 'show
# switch' (Catalyst StackWise) — a single row means standalone, multiple
# rows means a stack. Huawei serials come from 'display device elabel
# brief', and stack membership from 'display stack' (S/L/E and H series)
# — a device with no stack table at all is treated the same as
# standalone, since a single-member device simply won't print one.

_CISCO_INVENTORY_NAME_RE = re.compile(r'NAME:\s*"([^"]*)",\s*DESCR:\s*"([^"]*)"', re.IGNORECASE)
# PID is genuinely blank on real hardware for some entries (e.g. an SFP
# with no PID EEPROM field programmed prints "PID:                , VID:
# , SN: ..." — confirmed on a real Catalyst 3650 backup), so this must
# tolerate an empty PID/VID the same way it already tolerates SN oddities
# — a required (\S+) here silently drops that module's whole row.
_CISCO_INVENTORY_PID_RE = re.compile(r'PID:\s*(\S*)\s*,\s*VID:\s*(\S*)\s*,\s*SN:\s*(\S+)', re.IGNORECASE)
# "Master" confirmed as a real Cisco StackWise role on 2 independent
# real Catalyst 2960/2960X devices (the old alternation only had
# Active/Standby/Member — none of which any real device here printed —
# so Cisco stack detection failed on every real capture).
_CISCO_STACK_ROW_RE = re.compile(r"^\*?(\d+)\s+(Active|Standby|Member|Master)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)", re.IGNORECASE)
# "display stack" real column order confirmed on 2 real 2-member S5735
# stacks: MemberID / Role / MAC / Priority / DeviceType / Description —
# Role comes BEFORE the MAC address, the reverse of what the old regex
# assumed, so it never matched a single real row.
_HUAWEI_STACK_ROW_RE = re.compile(r"^(\d+)\s+(Master|Standby|Slave)\s+([0-9a-fA-F-]{6,})", re.IGNORECASE)


def _parse_cisco_inventory_entries(lines: list[str]) -> list[dict]:
    """Parse every 'show inventory' NAME/DESCR/PID/SN entry — chassis,
    power supplies, stack ports, AND per-interface transceiver modules
    alike. Shared by parse_inventory() (which keeps all of them) and
    parse_transceivers() (which keeps only the interface-named ones)."""
    entries: list[dict] = []
    pending_name = None
    for raw_line in lines:
        stripped = raw_line.strip()
        match = _CISCO_INVENTORY_NAME_RE.match(stripped)
        if match:
            pending_name = {"slot": match.group(1), "description": match.group(2)}
            continue
        match = _CISCO_INVENTORY_PID_RE.match(stripped)
        if match and pending_name:
            pid, _vid, serial = match.groups()
            entries.append({"slot": pending_name["slot"], "description": pending_name["description"], "pid": pid, "serial": serial})
            pending_name = None
    return entries


def parse_inventory(lines: list[str]) -> dict:
    modules: list[dict] = _parse_cisco_inventory_entries(lines)
    stack_members: list[dict] = []

    # Real command is commonly typed abbreviated ("sh switch" — confirmed
    # on a real Catalyst 2960X backup) rather than spelled out in full;
    # without the alias here the section was never found at all on that
    # capture, so stack membership silently came back empty.
    switch_section = _extract_section(lines, ["show switch", "sh switch"])
    for line in switch_section:
        match = _CISCO_STACK_ROW_RE.match(line)
        if match:
            switch_num, role, mac, _priority, _version, state = match.groups()
            stack_members.append({"slot": switch_num, "role": role, "mac": mac, "state": state})

    # "display device elabel brief" real column layout confirmed on 2
    # real S5735 stacks (4 chassis total): SlotID / Sub / Type / SN /
    # P/N — 5 columns, not the 6 the old regex assumed, and in the wrong
    # order, so it never matched a single real row. Sub-component rows
    # (FAN/PWR) print with a BLANK SlotID (just leading whitespace,
    # stripped away by _extract_section) and hold their own Sub/Type/SN
    # — e.g. "PWR1  PAC80S12-CN  2102131835USS6318275  02131835" — so
    # this is a small state machine keyed off whether the first token is
    # numeric (a new chassis/member) rather than a single fixed-width
    # regex, tolerant of "--" placeholders (FAN rows have no serial).
    # The P/N column (last on both row shapes) is the real Huawei
    # equivalent of Cisco's PID — confirmed identical to "display device
    # elabel"'s own Item= field on the same real captures — and was
    # previously discarded entirely, leaving every Huawei row's PID
    # column blank in the UI/export.
    elabel_section = _extract_section(lines, ["display device elabel brief"])
    current_elabel_slot = None
    for line in elabel_section:
        low = line.lower()
        if low.startswith("slotid") or low.startswith("----") or low.startswith("equipment sn") or low.startswith("license esn"):
            continue
        tokens = line.split()
        if tokens[0].isdigit():
            if len(tokens) < 5:
                continue
            slot, _sub, board_type, serial, pn = tokens[0], tokens[1], tokens[2], tokens[3], tokens[4]
            current_elabel_slot = slot
            if serial and serial != "--":
                modules.append({"slot": slot, "description": board_type, "pid": pn if pn != "--" else "", "serial": serial})
        else:
            if len(tokens) < 3:
                continue
            sub, board_type, serial = tokens[0], tokens[1], tokens[2]
            pn = tokens[3] if len(tokens) > 3 else ""
            if serial and serial != "--":
                label = f"{current_elabel_slot} {sub}" if current_elabel_slot else sub
                modules.append({"slot": label, "description": board_type, "pid": pn if pn != "--" else "", "serial": serial})

    stack_section = _extract_section(lines, ["display stack"])
    for line in stack_section:
        match = _HUAWEI_STACK_ROW_RE.match(line)
        if match:
            slot, role, mac = match.groups()
            stack_members.append({"slot": slot, "role": role, "mac": mac, "state": ""})

    # ArubaOS-Switch has no 'show inventory' equivalent — verified
    # against a real 2540 capture, the chassis serial number and
    # software revision are instead two of the many fields on 'show
    # system' (a general status screen, not a dedicated inventory
    # table), so this is a light-touch grab of just those two fields
    # rather than a full table parse.
    system_section = _extract_section(lines, ["show system"])
    aruba_serial = None
    aruba_software = None
    for line in system_section:
        match = re.search(r"Serial Number\s*:\s*(\S+)", line, re.IGNORECASE)
        if match:
            aruba_serial = match.group(1)
        match = re.search(r"Software revision\s*:\s*(\S+)", line, re.IGNORECASE)
        if match:
            aruba_software = match.group(1)
    if aruba_serial:
        modules.append({"slot": "Chassis", "description": aruba_software or "", "pid": "", "serial": aruba_serial})

    if stack_members:
        mode = "Stack" if len(stack_members) > 1 else "Standalone"
    else:
        mode = "Standalone" if modules else ""

    return {
        "modules": modules,
        "stack": {
            "mode": mode,
            "member_count": len(stack_members) if stack_members else (1 if modules else 0),
            "members": stack_members,
        },
    }
