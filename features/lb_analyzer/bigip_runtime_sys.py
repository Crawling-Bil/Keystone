"""System, network and traffic ``show`` output of a BIG-IP (interfaces, ARP, trunks, LLDP, performance, license, provisioning, HA, SSL, iRules).

Layouts follow TMOS 17.1 as printed by ``tmsh show ...`` in an interactive session and were checked against captures of a BIG-IP DNS
pair and an LTM+ASM pair.  Every parser takes the text of one command (the ``| `` prefixes of nested objects are already removed by
``bigip_runtime.unpipe``) and returns plain lists / dicts, so a missing or empty command costs nothing.

* ``show net interface`` / ``show net trunk``  https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/net/net_interface.html
* ``show net arp``  https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/net/net_arp.html
* ``show sys performance all-stats``  https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_performance_all-stats.html
* ``show sys license``  https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_license.html
* ``show sys provision``  https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_provision.html
* ``show sys ha-status``  https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_ha-status.html
* ``show cm device`` / ``device-group``  https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/cm/cm_device.html
* ``show ltm profile client-ssl / server-ssl``, ``show ltm rule``  https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/ltm/ltm_profile_client-ssl.html
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

_SCALE = {"K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15}
_NUMBER = re.compile(r"^(?P<n>\d+(?:\.\d+)?)(?P<s>[KMGTP]?)$")
_DASH = re.compile(r"^\s*-{5,}\s*$")
_TWO = re.compile(r"\s{2,}")


def number(text: str) -> float | None:
    """'10.3M' -> 10300000.0, '1.9K' -> 1900.0, '41' -> 41.0; anything else None."""
    found = _NUMBER.match(str(text or "").strip().replace(",", ""))
    return float(found["n"]) * _SCALE.get(found["s"], 1) if found else None


def _pairs(lines: list[str]) -> dict[str, str]:
    """'Key    value' lines split at the first run of two or more spaces (a colon form 'Key : value' too)."""
    out: dict[str, str] = {}
    for line in lines:
        text = line.strip()
        if not text or _DASH.match(line):
            continue
        if " : " in text and not _TWO.search(text.split(" : ")[0]):
            key, _, value = text.partition(" : ")
        else:
            parts = _TWO.split(text, 1)
            key, value = (parts[0], parts[1]) if len(parts) == 2 else (parts[0], "")
        out.setdefault(key.strip(), value.strip())
    return out


def _blocks(text: str, header: re.Pattern[str]) -> list[tuple[str, list[str], dict[str, str]]]:
    """Objects that start at a header line (name, body lines, named groups of the header); a ruled line (-----) never belongs to an object."""
    out: list[tuple[str, list[str], dict[str, str]]] = []
    current: tuple[str, list[str], dict[str, str]] | None = None
    for line in text.splitlines():
        found = header.match(line.strip())
        if found:
            if current:
                out.append(current)
            groups = {k: v or "" for k, v in found.groupdict().items()}
            current = (groups.get("name", "").strip(), [], groups)
        elif current is not None and not _DASH.match(line):
            current[1].append(line)
    if current:
        out.append(current)
    return out


# ---------------------------------------------------------------------------------------------------------------- network

_IFACE = re.compile(r"^(?P<lead>\s*)(?P<name>\S+)\s+(?P<status>[A-Za-z\-]+)\s+(?P<bits_in>[\d.]+[KMGTP]?)\s+(?P<bits_out>[\d.]+[KMGTP]?)\s+(?P<pkts_in>[\d.]+[KMGTP]?)\s+"
                    r"(?P<pkts_out>[\d.]+[KMGTP]?)\s+(?P<drops>[\d.]+[KMGTP]?)\s+(?P<errors>[\d.]+[KMGTP]?)\s+(?P<media>\S+)\s*$")


def parse_interfaces(text: str) -> list[dict[str, Any]]:
    """``show net interface`` / ``show net trunk``: one row per port.  An indented row below a trunk is a member of that trunk."""
    out: list[dict[str, Any]] = []
    trunk = ""
    for line in text.splitlines():
        found = _IFACE.match(line)
        if not found:
            continue
        row = {k: found[k] for k in ("name", "status", "bits_in", "bits_out", "pkts_in", "pkts_out", "drops", "errors", "media")}
        member = bool(found["lead"]) and bool(trunk)
        if not member:
            trunk = found["name"]
        row["trunk"] = trunk if member else ""
        for key in ("drops", "errors"):
            row[key + "_n"] = number(row[key]) or 0
        out.append(row)
    return out


_ARP = re.compile(r"^(?P<name>\S+)\s+(?P<address>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})\s+(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|incomplete)\s+(?P<vlan>\S+)\s+(?P<expire>\d+)\s+(?P<status>\S+)\s*$")


def parse_arp(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        found = _ARP.match(line.strip())
        if found:
            out.append({"address": found["address"], "mac": found["mac"].lower(), "vlan": found["vlan"].rsplit("/", 1)[-1], "expire": int(found["expire"]), "status": found["status"]})
    return out


def parse_lldp(text: str) -> list[dict[str, Any]]:
    """``show net lldp-neighbors``: the columns are cut at the start of each header word, whatever columns this TMOS release prints."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("Net::") and index + 1 < len(lines):
            header = lines[index + 1]
            starts = [m.start() for m in re.finditer(r"\S+(?: \S+)*", header)]
            names = [re.sub(r"\W+", "_", header[s:(starts[i + 1] if i + 1 < len(starts) else len(header))].strip()).strip("_").lower() for i, s in enumerate(starts)]
            rows = []
            for row in lines[index + 2:]:
                if not row.strip() or _DASH.match(row) or row.lstrip().startswith(("Net::", "Sys::")):
                    continue
                cells = [row[s:(starts[i + 1] if i + 1 < len(starts) else len(row))].strip() for i, s in enumerate(starts)]
                rows.append(dict(zip(names, cells)))
            return rows
    return []


# ---------------------------------------------------------------------------------------------------------------- performance

_PERF_HEAD = re.compile(r"^(?P<group>[A-Za-z][A-Za-z0-9 ()/%\-]*?)\s+Current\s+Average\s+Max(?:\(since (?P<since>[^)]+)\))?\s*$")
_PERF_ROW = re.compile(r"^(?P<metric>[A-Za-z][A-Za-z0-9 /\-.]*?)\s{2,}(?P<current>[\d.]+[KMGTP]?)\s+(?P<average>[\d.]+[KMGTP]?)\s+(?P<maximum>[\d.]+[KMGTP]?)\s*$")
_UNIT = re.compile(r"\((?P<u>%|bits/sec|pkts/sec|/sec/?)\)")


def parse_performance(text: str) -> list[dict[str, Any]]:
    """``show sys performance all-stats``: one row per metric with current, average and maximum since the counters were reset."""
    out: list[dict[str, Any]] = []
    group, unit, since = "", "", ""
    for line in text.splitlines():
        head = _PERF_HEAD.match(line.strip())
        if head:
            group = re.sub(r"\([^)]*\)", "", head["group"]).strip()
            units = _UNIT.findall(head["group"])
            unit = units[-1].strip("/") if units else ""
            unit = "%" if unit == "%" else ("/sec" if unit in ("sec", "") and units else unit)
            since = head["since"] or since
            continue
        row = _PERF_ROW.match(line.strip())
        if row and group:
            out.append({"group": group, "metric": row["metric"].strip(), "unit": unit, "current": row["current"], "average": row["average"], "maximum": row["maximum"],
                        "current_n": number(row["current"]), "maximum_n": number(row["maximum"]), "since": since})
    return out


# ---------------------------------------------------------------------------------------------------------------- license / provision / HA

def _license_date(text: str) -> date | None:
    for fmt in ("%Y/%m/%d", "%Y%m%d", "%Y-%m-%d"):
        try:
            return datetime.strptime(text.strip(), fmt).date()
        except ValueError:
            continue
    return None


def parse_license(text: str) -> dict[str, Any]:
    """Licence facts without the registration key (a secret that must not travel into reports)."""
    head: list[str] = []
    bundles: list[dict[str, Any]] = []
    limited: list[dict[str, Any]] = []
    mode = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Sys::"):
            continue
        if stripped == "Active Modules":
            mode = "active"
            continue
        if stripped == "Time Limited Modules":
            mode = "limited"
            continue
        if not mode:
            head.append(line)
            continue
        indent = len(line) - len(line.lstrip())
        if mode == "active":
            if indent <= 2:
                name = re.sub(r"\s*\([^)]*\)\s*$", "", stripped)
                bundles.append({"name": name, "features": []})
            elif bundles:
                bundles[-1]["features"].append(stripped)
        elif "|" in stripped:
            parts = [p.strip() for p in stripped.split("|")]
            parts += [""] * (5 - len(parts))
            limited.append({"name": parts[0], "start": parts[2], "end": parts[3], "kind": parts[4], "end_date": _license_date(parts[3])})
    pairs = _pairs(head)
    return {"licensed_version": pairs.get("Licensed Version", ""), "licensed_on": pairs.get("Licensed On", ""), "service_check": pairs.get("Service Check Date", ""),
            "service_check_date": _license_date(pairs.get("Service Check Date", "")), "platform": pairs.get("Platform ID", ""), "serial": pairs.get("Appliance Serial Number", ""),
            "bundles": bundles, "limited": limited}


_PROVISION = re.compile(r"^(?P<module>[a-z][a-z0-9\-]*)\s+(?P<cpu>\d+)\s+(?P<memory>\d+)\s+(?P<host_memory>\d+)\s+(?P<disk>\d+)\s*$")


def parse_provision(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        found = _PROVISION.match(line.strip())
        if found:
            row = {"module": found["module"], **{k: int(found[k]) for k in ("cpu", "memory", "host_memory", "disk")}}
            row["provisioned"] = bool(row["cpu"] or row["memory"] or row["host_memory"])
            out.append(row)
    return out


_HA_ROW = re.compile(r"^(?P<feature>[a-z][a-z0-9\-]*)\s+(?P<key>\S+)\s+(?P<action>[a-z][a-z0-9\-]*)\s+(?P<fail>yes|no)\s*$")


def parse_ha_status(text: str) -> list[dict[str, Any]]:
    """``show sys ha-status``: the HA table; a row with Fail = yes is an HA condition that has triggered."""
    return [{"feature": m["feature"], "key": m["key"], "action": m["action"], "failed": m["fail"] == "yes"} for m in (_HA_ROW.match(line.strip()) for line in text.splitlines()) if m]


_FAILOVER_ROW = re.compile(r"^(?P<local>\S+)\s+(?P<remote>\S+)\s+(?P<packets>\d+)\s+(?P<transitions>\d+)\s+(?P<last>\d{4}-\w{3}-\d{2} \d\d:\d\d:\d\d)\s+(?P<status>\S+)\s*$")


def parse_failover_connections(text: str) -> list[dict[str, Any]]:
    return [{"local": m["local"], "remote": m["remote"], "packets": int(m["packets"]), "transitions": int(m["transitions"]), "last": m["last"], "status": m["status"]}
            for m in (_FAILOVER_ROW.match(line.strip()) for line in text.splitlines()) if m]


_CM_DEVICE = re.compile(r"^CentMgmt::Device:\s*(?P<name>\S.*)$")
_CM_GROUP = re.compile(r"^CM::Device-Group\s*$")


def parse_cm_devices(text: str) -> list[dict[str, Any]]:
    out = []
    for name, lines, _ in _blocks(text, _CM_DEVICE):
        pairs = _pairs(lines)
        out.append({"name": name, "hostname": pairs.get("Hostname", name), "mgmt_ip": pairs.get("Mgmt IP", ""), "configsync_ip": pairs.get("Configsync IP", ""), "mirror_ip": pairs.get("Mirroring IP", ""),
                    "failover_ip": pairs.get("Failover Unicast IP(s)", ""), "state": pairs.get("Device HA State", ""), "load": pairs.get("Device Current Load Factor", ""),
                    "delta": pairs.get("Time Delta to Local Device (sec)", "")})
    return out


def parse_cm_groups(text: str) -> list[dict[str, Any]]:
    out = []
    for _, lines, _g in _blocks(text, _CM_GROUP):
        pairs = _pairs(lines)
        if pairs.get("Group Name"):
            out.append({"group": pairs["Group Name"], "member": pairs.get("Member Name", ""), "since_sync": pairs.get("Time Since Last Sync (HH:MM:SS)", ""), "sync_type": pairs.get("Last Sync Type", ""),
                        "originator": pairs.get("CID Originator", "")})
    return out


# ---------------------------------------------------------------------------------------------------------------- LTM objects

_VADDR = re.compile(r"^Ltm::Virtual Address:\s*(?P<name>\S.*)$")
_RULE = re.compile(r"^Ltm::Rule Event:\s*(?P<name>\S.*)$")
_SSL = re.compile(r"^Ltm::(?P<kind>Client|Server)SSL Profile:\s*(?P<name>\S.*)$")


def _int(text: str) -> int | None:
    value = number(str(text or "").split()[0] if str(text or "").split() else "")
    return int(value) if value is not None else None


def parse_virtual_addresses(text: str) -> list[dict[str, Any]]:
    out = []
    for name, lines, _ in _blocks(text, _VADDR):
        pairs = _pairs(lines)
        out.append({"address": name.split()[0], "name": name, "availability": pairs.get("Availability", ""), "state": pairs.get("State", ""), "reason": pairs.get("Reason", ""),
                    "connections": _int(pairs.get("Current Connections", "")), "maximum": _int(pairs.get("Maximum Connections", "")), "total": pairs.get("Total Connections", ""),
                    "bits_in": pairs.get("Bits In", ""), "bits_out": pairs.get("Bits Out", "")})
    return out


def parse_rules(text: str) -> list[dict[str, Any]]:
    """``show ltm rule``: one row per rule event (an iRule with three events is three rows)."""
    out = []
    for name, lines, _ in _blocks(text, _RULE):
        rule, _, event = name.rpartition(":")
        pairs = _pairs(lines)
        out.append({"rule": rule.rsplit("/", 1)[-1] or name, "event": event if rule else "", "priority": pairs.get("Priority", ""), "total": _int(pairs.get("Total", "")) or 0,
                    "failures": _int(pairs.get("Failures", "")) or 0, "aborts": _int(pairs.get("Aborts", "")) or 0, "average": pairs.get("Average", ""), "maximum": pairs.get("Maximum", "")})
    return out


_LEGACY = ("SSL Protocol Version 2", "SSL Protocol Version 3", "TLS Protocol Version 1.0", "TLS Protocol Version 1.1", "DTLS Protocol Version 1")


def parse_ssl_profiles(text: str) -> list[dict[str, Any]]:
    """``show ltm profile client-ssl`` / ``server-ssl``: connection and handshake counters and the protocol versions that were negotiated."""
    out = []
    for name, lines, groups in _blocks(text, _SSL):
        kind = groups["kind"].lower()
        pairs = _pairs(lines)
        native = pairs.get("Native", "").split()
        protocols = {key: _int(value) or 0 for key, value in pairs.items() if "Protocol Version" in key}
        out.append({"name": name, "kind": kind, "virtual": pairs.get("Virtual Server Name", ""), "open": _int(native[0]) if len(native) > 0 else None, "maximum": native[1] if len(native) > 1 else "",
                    "total": native[2] if len(native) > 2 else "", "total_n": number(native[2]) if len(native) > 2 else None, "secure": pairs.get("Secure Handshakes", ""),
                    "insecure_accepted": _int(pairs.get("Insecure Handshakes Accepted", "")) or 0, "protocols": {k: v for k, v in protocols.items() if v}, "legacy": sum(protocols.get(k, 0) for k in _LEGACY)})
    return out
