"""Runtime tables of a Huawei AC that the configuration does not hold: ``display radio all`` and ``display ap lldp neighbor brief``.

A capture is often a whole terminal log: the same command can appear several times (one per session), be typed partly (``dis curr | i capwap``) or
fail (``Error: Unrecognized command``).  Every parser here reads each table it finds, keeps one row per key (the last complete one) and ignores the rest.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

_RADIO_ROW = re.compile(r"^\s*(\d+)\s+(\S+)\s+(\d+)\s+(2\.4G|5G|6G)\s+(\S+)\s+(on|off)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", re.I)
_PROMPT = re.compile(r"^\s*[<\[][^<>\[\]]+[>\]]")
_BAND = {"2.4g": "2.4 GHz", "5g": "5 GHz", "6g": "6 GHz"}


def _number(value: str) -> int | None:
    match = re.match(r"^(\d+)", value or "")
    return int(match.group(1)) if match else None


def _sections(content: str, command: str):
    """The lines that follow each prompt line that holds ``command``, up to the next prompt."""
    lines = content.replace("\r\n", "\n").split("\n")
    start = None
    for index, line in enumerate(lines):
        if _PROMPT.match(line):
            if start is not None:
                yield lines[start:index]
                start = None
            if re.search(command, line, re.I):
                start = index + 1
    if start is not None:
        yield lines[start:]


def parse_radios(content: str) -> list[dict[str, Any]]:
    """One row per (AP, radio): band, Wi-Fi standard, state, channel and width, EIRP now / maximum, associated clients, channel utilisation, working mode."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for section in _sections(content, r"display\s+radio\s+all"):
        for line in section:
            match = _RADIO_ROW.match(line)
            if not match:
                continue
            ap_id, name, rf, band, standard, state, chan, eirp, clients, util, mode = match.groups()
            channel, _, width = chan.partition("/")
            eirp_now, _, eirp_max = eirp.partition("/")
            rows[(ap_id, rf)] = {
                "ap_id": ap_id, "ap": name, "radio": rf, "band": _BAND.get(band.lower(), band), "standard": standard, "on": state.lower() == "on",
                "channel": "" if channel in ("-", "") else channel, "width": "" if width in ("-", "") else width,
                "eirp_now": _number(eirp_now), "eirp_max": _number(eirp_max), "clients": _number(clients) or 0, "utilisation": _number(util), "work_mode": mode,
            }
    return list(rows.values())


def radio_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Totals for sizing and findings: radios and how many are on, clients per band, the busiest radios, the Wi-Fi standards in use."""
    on = [r for r in rows if r["on"]]
    per_band: Counter = Counter()
    clients_band: Counter = Counter()
    for r in rows:
        per_band[r["band"]] += 1
        clients_band[r["band"]] += r["clients"]
    busy = sorted((r for r in on if r["utilisation"] is not None), key=lambda r: -r["utilisation"])
    per_ap: dict[str, int] = {}
    for r in rows:
        per_ap[r["ap_id"]] = per_ap.get(r["ap_id"], 0) + r["clients"]
    return {
        "radios": len(rows), "radios_on": len(on), "by_band": dict(per_band), "clients_by_band": dict(clients_band), "clients": sum(r["clients"] for r in rows),
        "max_clients_per_ap": max(per_ap.values(), default=0), "max_utilisation": busy[0]["utilisation"] if busy else None,
        "standards": dict(Counter(r["standard"] for r in rows)), "busiest": busy[:10],
        "utilisation_over_50": sum(1 for r in on if (r["utilisation"] or 0) >= 50),
        "monitor_radios": sum(1 for r in rows if r["work_mode"].lower().startswith("monitor")),
    }


def parse_ap_uplinks(content: str) -> list[dict[str, Any]]:
    """``display ap lldp neighbor brief``: which switch and port each AP is cabled to (the controller sees it, the switch capture may not)."""
    out: dict[str, dict[str, Any]] = {}
    for section in _sections(content, r"display\s+ap\s+lldp\s+neighbor\s+brief"):
        header = next((l for l in section if l.strip().lower().startswith("hostname") and "neighbor" in l.lower()), None)
        if not header:
            continue
        for line in section[section.index(header) + 1:]:
            parts = line.split()
            if len(parts) < 6 or set(line.strip()) <= {"-"}:
                continue
            ttl = parts[-1]
            if not ttl.isdigit():
                continue
            name, switch, mgmt, local_intf, switch_port = parts[0], parts[1], parts[2], parts[3], " ".join(parts[4:-1])
            out[name] = {"ap": name, "switch": switch, "switch_ip": mgmt if re.match(r"\d+\.\d+\.\d+\.\d+$", mgmt) else "", "ap_port": local_intf, "switch_port": switch_port}
    return list(out.values())


def uplink_summary(uplinks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Access points per switch: the PoE ports the switch must carry."""
    per: dict[str, int] = {}
    for row in uplinks:
        per[row["switch"]] = per.get(row["switch"], 0) + 1
    return [{"switch": s, "aps": n} for s, n in sorted(per.items(), key=lambda kv: (-kv[1], kv[0]))]


def parse_lldp_names(content: str) -> dict[str, dict[str, str]]:
    """The full neighbour names of ``display lldp neighbor``: ``{local interface: {"name", "port", "ip"}}``.  The brief table cuts a long name with ``...``."""
    out: dict[str, dict[str, str]] = {}
    for section in _sections(content, r"display\s+lldp\s+neighbor\s*$"):
        local = ""
        for line in section:
            head = re.match(r"^(\S+) has \d+ neighbors?:", line.strip())
            if head:
                local = head.group(1)
                continue
            if not local:
                continue
            for key, pattern in (("name", r"System name\s*:\s*(\S.*?)\s*$"), ("port", r"Port ID\s*:\s*(\S.*?)\s*$"), ("ip", r"Management address\s*:\s*(\S+)\s*$")):
                found = re.match(pattern, line.strip())
                if found and not (key == "port" and "type" in line.lower()):
                    out.setdefault(local, {}).setdefault(key, found.group(1))
    return out


_AP_ROW = re.compile(r"^\s*(\d+)\s+([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})\s+(\S+)\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3}|-)\s+(\S+)\s+(\S+)")


def parse_ap_table(content: str) -> dict[str, dict[str, str]]:
    """``display ap all``: ``{AP name: {"ip", "model", "state", "group", "mac"}}``, one entry per AP however many times the table was printed."""
    out: dict[str, dict[str, str]] = {}
    for section in _sections(content, r"display\s+ap\s+all"):
        for line in section:
            match = _AP_ROW.match(line)
            if match:
                _, mac, name, group, ip, model, state = match.groups()
                out[name] = {"ip": "" if ip == "-" else ip, "model": model, "state": state, "group": group, "mac": mac}
    return out
