"""Parsers for Cisco ``show`` command output used by the Router Analyzer.

Each parser takes the output lines of one command (a ``Block.lines`` list)
and returns plain dicts.  They are written against real captures from
IOS 12.4 (3825), IOS-XE 15.x (ASR1002-X) and IOS-XE 17.9 SD-WAN (C8200)
and are deliberately column-offset driven where Cisco prints fixed-width
tables, because values such as ``administratively down`` contain spaces.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .ifnames import canon
from .netutil import is_ipv4

INT_RE = re.compile(r"-?\d+")


def _int(text: str | None, default: int | None = None) -> int | None:
    if text is None:
        return default
    match = INT_RE.search(text.replace(",", ""))
    return int(match.group()) if match else default


def _header_offsets(header: str, names: list[str]) -> list[tuple[str, int]] | None:
    positions = []
    for name in names:
        index = header.find(name)
        if index < 0:
            return None
        positions.append((name, index))
    return positions


def _slice_columns(line: str, offsets: list[tuple[str, int]]) -> dict[str, str]:
    row: dict[str, str] = {}
    for i, (name, start) in enumerate(offsets):
        end = offsets[i + 1][1] if i + 1 < len(offsets) else None
        row[name] = (line[start:end] if end is not None else line[start:]).strip()
    return row


# --------------------------------------------------------------------------
# show clock / show version
# --------------------------------------------------------------------------


def parse_clock(lines: Iterable[str]) -> str:
    for line in lines:
        text = line.strip().lstrip(".*")
        if re.match(r"\d{1,2}:\d{2}:\d{2}", text):
            return text
    return ""


def parse_clock_detail(lines: Iterable[str]) -> dict[str, Any]:
    """``show clock detail`` adds one line ``show clock`` does not: the time source. A
    leading '.' or '*' on the time line is IOS's own authoritative-time marker (its
    meaning is 'not yet fully synchronised' / 'not authoritative') — kept as seen rather
    than interpreted here, since 'show ntp associations' / 'show ntp status' give an
    unambiguous synchronisation state."""
    info: dict[str, Any] = {}
    for line in lines:
        stripped = line.strip()
        m = re.match(r"([.*]?)(\d{1,2}:\d{2}:\d{2}.*)$", stripped)
        if m and "time" not in info:
            info["marker"], info["time"] = m.group(1), m.group(2)
            continue
        m = re.match(r"Time source is (\S+)", stripped, re.I)
        if m:
            info["source"] = m.group(1)
    return info


_SSH_VERSION = re.compile(r"SSH (Enabled|Disabled)(?:\s*-\s*version\s+(\S+))?", re.I)
_SSH_TIMEOUT = re.compile(r"Authentication timeout:\s*(\d+)\s*secs?;\s*Authentication retries:\s*(\d+)", re.I)
_SSH_DH_BITS = re.compile(r"Minimum expected Diffie Hellman key size\s*:\s*(\d+)\s*bits", re.I)
_SSH_KEY_LINE = re.compile(r"^(ssh-\S+|ecdsa-\S+)\s")


def parse_ip_ssh(lines: list[str]) -> dict[str, Any]:
    info: dict[str, Any] = {"enabled": False, "version": "", "auth_timeout": None, "auth_retries": None, "dh_min_bits": None, "key_type": ""}
    for line in lines:
        text = line.strip()
        m = _SSH_VERSION.match(text)
        if m:
            info["enabled"] = m.group(1).lower() == "enabled"
            info["version"] = m.group(2) or ""
            continue
        m = _SSH_TIMEOUT.search(text)
        if m:
            info["auth_timeout"], info["auth_retries"] = int(m.group(1)), int(m.group(2))
            continue
        m = _SSH_DH_BITS.search(text)
        if m:
            info["dh_min_bits"] = int(m.group(1))
            continue
        m = _SSH_KEY_LINE.match(text)
        if m and not info["key_type"]:
            info["key_type"] = m.group(1)
    return info


def parse_version(lines: list[str]) -> dict[str, Any]:
    text = "\n".join(lines)
    info: dict[str, Any] = {}
    m = re.search(r"Cisco IOS XE Software, Version (\S+)", text)
    if m:
        info["os"] = "IOS-XE"
        info["version"] = m.group(1)
    m = re.search(r"Cisco IOS Software(?:, [^\n(]*)?\(([^)]+)\), Version ([^,\s]+)", text)
    if m:
        info.setdefault("os", "IOS")
        info["image_family"] = m.group(1)
        info.setdefault("version", m.group(2))
    m = re.search(r"^(\S+) uptime is (.+)$", text, re.MULTILINE)
    if m:
        info["hostname"] = m.group(1)
        info["uptime"] = m.group(2).strip()
    m = re.search(r"System image file is \"([^\"]+)\"", text)
    if m:
        info["image"] = m.group(1)
    m = re.search(r"System returned to ROM by (.+)", text)
    if m:
        info["last_reload"] = m.group(1).strip()
    m = re.search(r"^[Cc]isco (\S+) \(([^)]+)\) processor.*?with ([\d/K]+[KkMm]?) bytes of memory", text, re.MULTILINE)
    if m:
        info["model"] = m.group(1)
        info["cpu"] = m.group(2)
        info["memory"] = m.group(3)
    else:
        m = re.search(r"^[Cc]isco (\S+) .*processor", text, re.MULTILINE)
        if m:
            info["model"] = m.group(1)
    m = re.search(r"Processor board ID (\S+)", text)
    if m:
        info["serial"] = m.group(1)
    m = re.search(r"Configuration register is (\S+)", text)
    if m:
        info["config_register"] = m.group(1)
    rows = _license_rows(lines)
    if rows:
        info["license_table"] = rows
        info["license_info"] = "; ".join(f"{r['technology']} {r['type']}: {r['current']}" for r in rows)[:200]
    m = re.search(r"License Level: (\S+)", text)
    if m:
        info["license_level"] = m.group(1)
    # IOS-XE 16.x / 17.x extras: facts that explain performance, licensing and restarts
    m = re.search(r"^Cisco IOS Software \[([^\]]+)\]", text, re.MULTILINE)
    if m:
        info["release_name"] = m.group(1)
    m = re.search(r"^ROM:\s*(.+)$", text, re.MULTILINE)
    if m:
        info["rom"] = m.group(1).strip()
    m = re.search(r"^Uptime for this control processor is (.+)$", text, re.MULTILINE)
    if m:
        info["control_processor_uptime"] = m.group(1).strip()
    m = re.search(r"^System restarted at (.+)$", text, re.MULTILINE)
    if m:
        info["restarted_at"] = m.group(1).strip()
    m = re.search(r"^Last reload reason:\s*(.+)$", text, re.MULTILINE)
    if m:
        info["last_reload_reason"] = m.group(1).strip()
    m = re.search(r"^Router operating mode:\s*(.+)$", text, re.MULTILINE)
    if m:
        info["operating_mode"] = m.group(1).strip()
    m = re.search(r"current (?:crypto )?throughput level is (\d+) kbps", text)
    if m:
        info["crypto_throughput_kbps"] = int(m.group(1))
    m = re.search(r"^Smart Licensing Status:\s*(.+)$", text, re.MULTILINE)
    if m:
        info["smart_licensing"] = m.group(1).strip()
    m = re.search(r"^Router operating mode:\s*(.+)$", text, re.MULTILINE)
    if m:
        info["operating_mode"] = m.group(1).strip()
    m = re.search(r"^(\d+)K bytes of physical memory", text, re.MULTILINE)
    if m:
        info["physical_memory_kb"] = int(m.group(1))
    m = re.search(r"^(\d+)K bytes of (?:flash|Flash) memory at (\S+?):?\.?$", text, re.MULTILINE)
    if m:
        info["flash_kb"], info["flash_device"] = int(m.group(1)), m.group(2).rstrip(":.")
    m = re.search(r"^(\d+)K bytes of non-volatile configuration memory", text, re.MULTILINE)
    if m:
        info["nvram_kb"] = int(m.group(1))
    packaging = "install" if re.search(r"packages\.conf", info.get("image", "")) else ("bundle" if info.get("image", "").endswith(".bin") else "")
    if packaging:
        info["boot_mode"] = packaging
    return info


def _license_rows(lines: list[str]) -> list[dict[str, str]]:
    """Rows of the 'Technology Package License Information' table (IOS-XE 16/17 layout)."""
    rows: list[dict[str, str]] = []
    start = next((i for i, line in enumerate(lines) if "Technology Package License Information" in line), None)
    if start is None:
        return rows
    dashes = 0
    for line in lines[start + 1:]:
        if line.startswith("-----"):
            dashes += 1
            if dashes >= 3:
                break
            continue
        if dashes < 2 or not line.strip():
            if dashes >= 2 and rows:
                break
            continue
        m = re.match(r"^(.+?)\s{2,}(Perpetual|Subscription|EvalRightToUse|RightToUse|Permanent|Evaluation|Evaluation Right To Use)\s+(\S.*?)(?:\s{2,}(\S.*))?\s*$", line)
        if m:
            rows.append({"technology": m.group(1).strip(), "type": m.group(2).strip(), "current": m.group(3).strip(), "next_reboot": (m.group(4) or "").strip()})
            continue
        # 16.x ISR 4000 layout: "Technology  Technology-package Current  Type  Next reboot"
        m = re.match(r"^(\S+)\s+(\S+)\s+(Smart License|RightToUse|EvalRightToUse|Permanent|Evaluation)\s+(\S+)\s*$", line)
        if m:
            rows.append({"technology": m.group(1), "type": m.group(3), "current": m.group(2), "next_reboot": m.group(4)})
    return rows


# --------------------------------------------------------------------------
# Interfaces
# --------------------------------------------------------------------------


_IPBRIEF_ROW = re.compile(
    r"^(?P<interface>\S+)\s+(?P<ip>\S+)\s+(?P<ok>YES|NO|unset)\s+(?P<method>\S+)\s+"
    r"(?P<status>.+?)\s+(?P<protocol>up|down|deleted)(?:\s*\([A-Za-z ]+\))?\s*$",
    re.IGNORECASE,
)


def parse_ip_interface_brief(lines: list[str]) -> list[dict[str, str]]:
    """Rows of ``show ip interface brief``.

    Tokenised rather than sliced by header column: the Status column holds
    "administratively down" (two words) and a terminal copy, a pager or a
    masked fixture can shift the columns, but the order of the fields never
    changes.  The header-offset reading is kept as a fallback for a row the
    pattern does not accept.
    """
    rows: list[dict[str, str]] = []
    offsets = None
    seen_header = False
    for line in lines:
        if line.startswith("Interface") and "IP-Address" in line:
            offsets = _header_offsets(line, ["Interface", "IP-Address", "OK?", "Method", "Status", "Protocol"])
            seen_header = True
            continue
        if not seen_header or not line.strip():
            continue
        match = _IPBRIEF_ROW.match(line.strip())
        if match:
            rows.append({
                "interface": canon(match["interface"]),
                "raw": match["interface"],
                "ip": match["ip"],
                "ok": match["ok"],
                "method": match["method"],
                "status": match["status"].strip(),
                "protocol": match["protocol"],
            })
            continue
        if offsets is None:
            continue
        row = _slice_columns(line, offsets)
        if not row["Interface"]:
            continue
        rows.append({
            "interface": canon(row["Interface"]),
            "raw": row["Interface"],
            "ip": row["IP-Address"],
            "ok": row["OK?"],
            "method": row["Method"],
            "status": row["Status"],
            "protocol": row["Protocol"],
        })
    return rows


def parse_interface_description(lines: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    offsets = None
    for line in lines:
        if line.startswith("Interface") and "Description" in line:
            offsets = _header_offsets(line, ["Interface", "Status", "Protocol", "Description"])
            continue
        if offsets is None or not line.strip():
            continue
        row = _slice_columns(line, offsets)
        if not row["Interface"]:
            continue
        rows.append({
            "interface": canon(row["Interface"]),
            "raw": row["Interface"],
            "status": row["Status"],
            "protocol": row["Protocol"],
            "description": row["Description"],
        })
    return rows


_IF_HEAD = re.compile(r"^(?P<name>\S+) is (?P<status>.+?), line protocol is (?P<proto>\S+)(?: \((?P<proto_note>[^)]*)\))?\s*$")


def parse_show_interfaces(lines: list[str]) -> list[dict[str, Any]]:
    """Parse ``show interfaces`` into one dict per interface."""
    results: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in lines:
        head = _IF_HEAD.match(line)
        if head:
            current = {"interface": canon(head.group("name")), "raw": head.group("name"), "status": head.group("status"), "protocol": head.group("proto")}
            results.append(current)
            continue
        if current is None:
            continue
        text = line.strip()
        if not text:
            continue
        m = re.match(r"Hardware is (.+?)(?:, address is (\S+) \(bia (\S+)\))?$", text)
        if m:
            current["hardware"] = m.group(1).strip()
            if m.group(2):
                current["mac"] = m.group(2)
            continue
        if text.startswith("Description:"):
            current["description"] = text[len("Description:"):].strip()
        elif text.startswith("Internet address is"):
            current["ip"] = text.split("is", 1)[1].strip()
        elif text.startswith("Interface is unnumbered"):
            current["ip"] = text.replace("Interface is unnumbered.", "").strip()
        elif text.startswith("MTU "):
            m = re.match(r"MTU (\d+) bytes, BW (\d+) Kbit(?:/sec)?, DLY (\d+) usec", text)
            if m:
                current["mtu"] = int(m.group(1))
                current["bandwidth_kbps"] = int(m.group(2))
                current["delay_usec"] = int(m.group(3))
        elif text.startswith("reliability"):
            m = re.match(r"reliability (\d+)/255, txload (\d+)/255, rxload (\d+)/255", text)
            if m:
                current["reliability"] = f"{m.group(1)}/255"
                current["txload"] = int(m.group(2))
                current["rxload"] = int(m.group(3))
        elif text.startswith("Encapsulation"):
            m = re.match(r"Encapsulation ([^,]+)", text)
            if m:
                current["encapsulation"] = m.group(1).strip()
        elif text.startswith("Keepalive"):
            current["keepalive"] = text.replace("Keepalive", "").strip()
        elif re.match(r"(Full|Half|Auto|Unknown)[- ][Dd]uplex", text) or re.match(r"(Full|Half|Auto)-duplex", text):
            m = re.match(r"(Full|Half|Auto|Unknown)[- ][Dd]uplex, ([^,]+)(?:, (.*))?", text)
            if m:
                current["duplex"] = m.group(1).lower()
                current["speed"] = m.group(2).strip()
                extra = m.group(3) or ""
                mm = re.search(r"media type is (\S+)", extra)
                if mm:
                    current["media"] = mm.group(1)
        elif text.startswith("Last input"):
            m = re.match(r"Last input ([^,]+), output ([^,]+)", text)
            if m:
                current["last_input"] = m.group(1)
                current["last_output"] = m.group(2)
        elif text.startswith("Last clearing"):
            current["counters_cleared"] = text.split("counters", 1)[-1].strip()
        elif text.startswith("Input queue:"):
            m = re.match(r"Input queue: (\d+)/(\d+)/(\d+)/(\d+)", text)
            if m:
                current["input_queue_drops"] = int(m.group(3))
                current["input_queue_flushes"] = int(m.group(4))
            m = re.search(r"Total output drops: (\d+)", text)
            if m:
                current["output_drops"] = int(m.group(1))
        elif text.startswith("Queueing strategy"):
            current["queueing"] = text.split(":", 1)[1].strip()
        elif text.startswith("5 minute input rate"):
            m = re.match(r"5 minute input rate (\d+) bits/sec, (\d+) packets/sec", text)
            if m:
                current["in_bps"] = int(m.group(1))
                current["in_pps"] = int(m.group(2))
        elif text.startswith("5 minute output rate"):
            m = re.match(r"5 minute output rate (\d+) bits/sec, (\d+) packets/sec", text)
            if m:
                current["out_bps"] = int(m.group(1))
                current["out_pps"] = int(m.group(2))
        elif re.match(r"\d+ packets input", text):
            m = re.match(r"(\d+) packets input, (\d+) bytes", text)
            if m:
                current["in_packets"] = int(m.group(1))
                current["in_bytes"] = int(m.group(2))
        elif re.match(r"\d+ packets output", text):
            m = re.match(r"(\d+) packets output, (\d+) bytes", text)
            if m:
                current["out_packets"] = int(m.group(1))
                current["out_bytes"] = int(m.group(2))
        elif re.match(r"\d+ input errors", text):
            m = re.match(r"(\d+) input errors, (\d+) CRC, (\d+) frame, (\d+) overrun, (\d+) ignored", text)
            if m:
                current["input_errors"] = int(m.group(1))
                current["crc"] = int(m.group(2))
                current["frame"] = int(m.group(3))
                current["overrun"] = int(m.group(4))
                current["ignored"] = int(m.group(5))
        elif re.match(r"(?:Received \d+ broadcasts,\s*)?\d+ runts", text):
            m = re.search(r"(\d+) runts, (\d+) giants, (\d+) throttles", text)
            if m:
                current["runts"] = int(m.group(1))
                current["giants"] = int(m.group(2))
                current["throttles"] = int(m.group(3))
        elif re.match(r"\d+ output errors", text):
            m = re.match(r"(\d+) output errors, (\d+) collisions, (\d+) interface resets", text)
            if m:
                current["output_errors"] = int(m.group(1))
                current["collisions"] = int(m.group(2))
                current["resets"] = int(m.group(3))
        elif re.match(r"\d+ lost carrier", text):
            m = re.match(r"(\d+) lost carrier, (\d+) no carrier", text)
            if m:
                current["lost_carrier"] = int(m.group(1))
        elif re.match(r"\d+ unknown protocol drops", text):
            current["unknown_protocol_drops"] = _int(text)
        elif re.match(r"\d+ watchdog", text):
            m = re.match(r"(\d+) watchdog, (\d+) multicast", text)
            if m:
                current["watchdog"] = int(m.group(1))
        elif re.match(r"\d+ output buffer failures", text):
            m = re.match(r"(\d+) output buffer failures", text)
            if m:
                current["output_buffer_failures"] = int(m.group(1))
        elif text.startswith("Tunnel source"):
            current["tunnel"] = text
        elif text.startswith("Tunnel protocol"):
            current["tunnel_protocol"] = text.split("protocol/transport", 1)[-1].strip()
    for item in results:
        bw = item.get("bandwidth_kbps") or 0
        # A tunnel's BW is a routing-metric placeholder (often 100 kbit/s), not a capacity.
        if bw and not str(item.get("interface", "")).startswith("Tunnel"):
            item["in_util_pct"] = round(item.get("in_bps", 0) / (bw * 1000) * 100, 1)
            item["out_util_pct"] = round(item.get("out_bps", 0) / (bw * 1000) * 100, 1)
    return results


def parse_interfaces_summary(lines: list[str]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    header = None
    for line in lines:
        if re.search(r"^\s+Interface\s+IHQ", line):
            header = True
            continue
        if not header or line.startswith("-") or not line.strip():
            continue
        m = re.match(r"^(\*?)\s*(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", line)
        if not m:
            continue
        name = canon(m.group(2))
        rows[name] = {
            "up": bool(m.group(1)), "ihq": int(m.group(3)), "iqd": int(m.group(4)), "ohq": int(m.group(5)), "oqd": int(m.group(6)),
            "rxbs": int(m.group(7)), "rxps": int(m.group(8)), "txbs": int(m.group(9)), "txps": int(m.group(10)), "trtl": int(m.group(11)),
        }
    return rows


# --------------------------------------------------------------------------
# ARP, inventory
# --------------------------------------------------------------------------


def parse_arp(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        m = re.match(r"^Internet\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S*)\s*$", line)
        if m:
            rows.append({"address": m.group(1), "age": m.group(2), "mac": m.group(3), "type": m.group(4), "interface": canon(m.group(5)) if m.group(5) else ""})
    return rows


def parse_arp_summary(lines: list[str]) -> dict[str, Any]:
    """``show arp summary`` (IOS-XE) and the one-line ``show ip arp summary`` (classic IOS / Catalyst).

    IOS-XE prints ``Total number of <kind> ARP entries: N.`` for every kind, the learn limits and one
    ``interface   count`` row per interface.  Classic IOS prints ``12 IP ARP entries, with 0 of them incomplete``.
    """
    out: dict[str, Any] = {"total": None, "kinds": {}, "limit": None, "configured_limit": None, "threshold": None, "permit_threshold": None, "per_interface": []}
    in_table = False
    for line in lines:
        text = line.strip()
        if not text:
            continue
        m = re.match(r"^(\d+) IP ARP entries?, with (\d+) of them incomplete", text, re.I)
        if m:
            out["total"] = int(m.group(1))
            out["kinds"]["Incomplete"] = int(m.group(2))
            continue
        m = re.match(r"^Total number of entries in the ARP table:\s*(\d+)", text, re.I)
        if m:
            out["total"] = int(m.group(1))
            continue
        m = re.match(r"^Total number of (.+?) ARP entries?:\s*(\d+)", text, re.I)
        if m:
            out["kinds"][m.group(1).strip().title()] = int(m.group(2))
            continue
        m = re.match(r"^Maximum limit of Learn ARP entry\s*:\s*(\d+)", text, re.I)
        if m:
            out["limit"] = int(m.group(1))
            continue
        m = re.match(r"^Maximum configured Learn ARP entry limit\s*:\s*(\d+)", text, re.I)
        if m:
            out["configured_limit"] = int(m.group(1))
            continue
        m = re.match(r"^Learn ARP Entry Threshold is (\d+) and Permit Threshold is (\d+)", text, re.I)
        if m:
            out["threshold"], out["permit_threshold"] = int(m.group(1)), int(m.group(2))
            continue
        if re.match(r"^Interface\s+Entry Count", text, re.I):
            in_table = True
            continue
        if in_table:
            m = re.match(r"^(\S+)\s+(\d+)$", text)
            if m:
                out["per_interface"].append({"interface": canon(m.group(1)), "entries": int(m.group(2))})
    if out["total"] is None and not out["kinds"]:
        return {}
    return out


def parse_inventory(lines: list[str]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    pending: dict[str, str] | None = None
    for line in lines:
        m = re.match(r'^NAME:\s*"(.*?)",\s*DESCR:\s*"(.*?)"\s*$', line)
        if m:
            pending = {"name": m.group(1), "description": m.group(2), "pid": "", "vid": "", "serial": ""}
            items.append(pending)
            continue
        m = re.match(r"^PID:\s*(.*?)\s*,\s*VID:\s*(.*?)\s*,\s*SN:\s*(.*?)\s*$", line)
        if m and pending is not None:
            pending["pid"] = m.group(1).strip()
            pending["vid"] = m.group(2).strip()
            pending["serial"] = m.group(3).strip()
    return items


# --------------------------------------------------------------------------
# Access-list hit counters
# --------------------------------------------------------------------------


def parse_access_lists(lines: list[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    for line in lines:
        m = re.match(r"^(Standard|Extended|Reflexive|Compiled)?\s*(IP|IPv6)?\s*access list (\S+)\s*$", line)
        if m:
            current = {"kind": (m.group(1) or "").lower(), "family": "ipv6" if m.group(2) == "IPv6" else "ipv4", "entries": []}
            result[m.group(3)] = current
            continue
        if current is None:
            continue
        m = re.match(r"^\s+(\d+)\s+(.*?)\s*$", line)
        if m:
            text = m.group(2)
            hits = None
            h = re.search(r"\((\d+) match(?:es)?\)", text)
            if h:
                hits = int(h.group(1))
                text = text[:h.start()].strip()
            current["entries"].append({"seq": m.group(1), "text": text, "hits": hits})
    return result


# --------------------------------------------------------------------------
# show route-map / show ip cache flow
# --------------------------------------------------------------------------


def parse_route_map_stats(lines: list[str]) -> dict[tuple[str, int], dict[str, int]]:
    stats: dict[tuple[str, int], dict[str, int]] = {}
    key = None
    for line in lines:
        m = re.match(r"^route-map (\S+), (permit|deny), sequence (\d+)", line)
        if m:
            key = (m.group(1), int(m.group(3)))
            stats[key] = {"packets": 0, "bytes": 0}
            continue
        m = re.search(r"Policy routing matches: (\d+) packets, (\d+) bytes", line)
        if m and key:
            stats[key] = {"packets": int(m.group(1)), "bytes": int(m.group(2))}
    return stats


def parse_cache_flow(lines: list[str]) -> dict[str, Any]:
    info: dict[str, Any] = {"protocols": []}
    in_table = False
    for line in lines:
        m = re.search(r"IP Flow Switching Cache, (\d+) bytes", line)
        if m:
            info["cache_bytes"] = int(m.group(1))
        m = re.match(r"^\s+(\d+) active, (\d+) inactive, (\d+) added\s*$", line)
        if m and "active_flows" not in info:
            info["active_flows"] = int(m.group(1))
            info["inactive_flows"] = int(m.group(2))
            info["flows_added"] = int(m.group(3))
        m = re.search(r"IP packet size distribution \(([\w.]+) total packets\)", line)
        if m:
            info["total_packets"] = m.group(1)
        if line.startswith("Protocol") and "Total" in line:
            in_table = True
            continue
        if in_table:
            m = re.match(r"^(\S+)\s+(\d+)\s+([\d.]+)\s+(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*$", line)
            if m:
                info["protocols"].append({"protocol": m.group(1), "flows": int(m.group(2)), "flows_per_sec": float(m.group(3)), "pkts_per_flow": int(m.group(4)), "bytes_per_pkt": int(m.group(5))})
            elif line.startswith("SrcIf"):
                in_table = False
    return info


def parse_policy_map_interface(lines: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    interface = policy = direction = ""
    current: dict[str, Any] | None = None
    for line in lines:
        if line and not line.startswith(" "):
            interface = line.strip()
            continue
        text = line.strip()
        m = re.match(r"Service-policy (input|output): (\S+)", text)
        if m:
            direction, policy = m.group(1), m.group(2)
            continue
        m = re.match(r"Class-map: (.+?) \((match-\w+)\)", text)
        if m:
            current = {"interface": canon(interface), "direction": direction, "policy": policy, "class": m.group(1), "packets": 0, "bytes": 0, "drops": 0, "offered_bps": 0}
            rows.append(current)
            continue
        if current is None:
            continue
        m = re.match(r"(\d+) packets, (\d+) bytes", text)
        if m and current["packets"] == 0:
            current["packets"], current["bytes"] = int(m.group(1)), int(m.group(2))
        m = re.search(r"offered rate (\d+) bps", text)
        if m:
            current["offered_bps"] = int(m.group(1))
        m = re.search(r"\(pkts output/bytes output\) (\d+)/(\d+)", text)
        m2 = re.search(r"drops? (\d+)", text)
        if text.startswith("(total drops)") or text.startswith("Total drops") or "total drops" in text:
            d = re.search(r"(\d+)", text)
            if d:
                current["drops"] = int(d.group(1))
    return rows
