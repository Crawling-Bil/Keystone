"""Health checks for Cisco NX-OS, Huawei VRP / YunShan OS and ArubaOS-Switch captures.

``health.py`` judges Cisco IOS / IOS XE. This module gives the other three platforms the same Health tab, built only on
output that real TAM captures contain:

* **Cisco NX-OS** (Nexus 9000 DMZ pair): ``show version`` (kernel uptime, last reset and its reason), ``show environment all``
  (fans, power supplies, temperature), ``show spanning-tree summary``, ``show port-channel summary``, ``show lacp neighbor``,
  ``show vpc``, ``show license usage``, and the running-config (SNMP, telnet, syslog, NTP, spanning-tree edge ports).
* **Huawei** (S5735-S V2 / S5755-H on YunShan OS V600R025): ``display version`` (uptime per stack member), ``display device``
  (slot / fan / power alarm table), ``display stp`` and ``display stp brief``, ``display eth-trunk``, and the configuration.
* **ArubaOS-Switch** (2540, YC.16.06): ``show system`` (uptime, CPU, memory), ``show flash``, ``show spanning-tree``, and the
  configuration (SNMP communities, SNTP, syslog).

The result has the same shape as ``health.build_health`` so the page renders it with the same code. A rule fires only on lines
that are in the capture. A command that is not in the capture is listed under ``capture.missing``; it never counts as healthy.
Nothing is guessed: no temperature, CPU or memory threshold is invented, the tables show the numbers the device printed.

Documentation each finding links to (opened and read, except the Huawei pages: support.huawei.com refuses automated access,
so those three URLs and titles come from Huawei's own search listing):
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text, huawei_live, licence_detail, nxos_extras, nxos_state, show_tables
from .finding_context import vlan_phrase
from .health import DOCS as _HEALTH_DOCS
from .health import (LACP_STATE_BITS, MEMBER_FLAGS, SEVERITY_ORDER, _config_blocks, _finding, _running_config,
                     _short, parse_etherchannel_flags, parse_stp_summary)

DOCS: dict[str, tuple[str, str]] = {
    "nxos_reload": ("Cisco - Troubleshoot Unexpected Reloads or Crashes on Nexus 9000",
                    "https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/221551-troubleshoot-unexpected-reloads-or-crash.html"),
    "nxos_vpc": ("Cisco - Understand and Configure Nexus 9000 vPC with Best Practices",
                 "https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html"),
    "nxos_lacp": ("Cisco - Troubleshoot Link Aggregation Control Protocol (LACP) on Nexus",
                  "https://www.cisco.com/c/en/us/support/docs/lan-switching/link-aggregation-control-protocol-lacp-8023ad/221051-troubleshoot-link-aggregation-control-pr.html"),
    "nxos_snmp": ("Cisco DevNet - Configuring SNMP (Nexus 3000 and 9000, release 7.x)", "https://developer.cisco.com/docs/nx-os-n3k-n9k-api-ref-7-x/configuring-snmp"),
    "huawei_bpdu": ("Huawei - What is BPDU Protection and How to Configure BPDU Protection?", "https://support.huawei.com/enterprise/mx/doc/EDOC1100090433"),
    "huawei_lacp": ("Huawei S310 V600R022C10 Configuration Guide - Eth-Trunk in LACP mode",
                    "https://support.huawei.com/enterprise/en/doc/EDOC1100306151/cb34a757/eth-trunk-in-lacp-mode"),
    "huawei_stp": ("Huawei - Checking Whether the Loop Prevention Protocol Flaps",
                   "https://info.support.huawei.com/network/ptmngsys/Web/tsrev_s/en/content/s/13_edesk_ping_packet_loss/edesk_ping_packet_loss_edesk002.html"),
    "huawei_baseline": ("Huawei CloudEngine S3700, S5700 and S6700 V600R025C00 Configuration Guide (every command of the Baseline Check Items for Security Configuration of Campus Switches is documented here)",
                        "https://support.huawei.com/enterprise/en/doc/EDOC1100333463"),
    "huawei_stack": ("Huawei CloudEngine S5700 and S6700 V600R024C10 Configuration Guide - Virtualization (S5735-S-V2 stack support)",
                     "https://support.huawei.cn/enterprise/en/doc/EDOC1100458710/ca59e588/s5735i-s-v2-stack-support"),
    "aruba_harden": ("HPE Aruba Networking - Protect your infrastructure by securing your switches using the ArubaOS-Switch Hardening Guide",
                     "https://community.networking.hpe.com/discussion/protect-your-infrastructure-by-securing-your-switches-using-the-arubaos-switch-hardening-guide"),
}


_ERROR_LINE = re.compile(r"^\s*(?:%|\^\s*$|invalid (?:input|command)|error:|incomplete command|ambiguous command|unrecognized command)", re.IGNORECASE)


def _run(clean: list[str], pattern: str, headers: tuple[str, ...] = (), score=len) -> list[str] | None:
    """Output of a command: found by its echo (``pattern``) or, when the echo was lost, by a header line of its table (``headers``).

    Returns None when the command is not in the capture and ``[]`` when it was run but printed nothing (Huawei prints nothing for
    ``display eth-trunk`` when no Eth-Trunk exists). A block that opens with the device's error message (``% Invalid command``,
    ``Error: Unrecognized command``) is the output of a command that did not run and is ignored. Of several runs the fullest one (by
    ``score``) wins, the later run on a tie.
    """
    best: list[str] | None = None
    best_score = -1
    ran_empty = False
    for _index, block in capture_text.find_blocks(clean, [pattern], headers):
        if not block:
            ran_empty = True
            continue
        if any(_ERROR_LINE.match(line) for line in block[:3]):
            continue
        value = score(block)
        if value >= best_score:
            best, best_score = block, value
    if best is None and ran_empty:
        return []
    return best


def _add(findings: list[dict[str, Any]], code: str, severity: str, title: str, text: str, *, where: str = "", doc: str = "") -> None:
    entry = _finding(code, severity, title, text, where=where)
    ref = DOCS.get(doc) or _HEALTH_DOCS.get(doc)
    if ref and ref[1]:
        entry["doc"] = {"title": ref[0], "url": ref[1]}
    findings.append(entry)


def _empty(scope: str, family: str) -> dict[str, Any]:
    return {
        "supported": True, "scope": scope, "family": family, "note": "", "findings": [], "counts": {}, "stp": {}, "lacp": [],
        "environment": {"sensors": [], "fans": [], "power_supplies": [], "problems": 0, "rows": []},
        "licence": {"smart_account": "", "virtual_account": "", "licenses": [], "detail": {}},
        "software": {}, "capture": {"missing": [], "config_found": False, "hints": {}},
    }


def _finish(health: dict[str, Any], findings: list[dict[str, Any]], missing: list[dict[str, str]], config_found: bool, hints: dict[str, str]) -> dict[str, Any]:
    findings.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["code"], item["where"]))
    health["findings"] = findings
    software = health.get("software") or {}
    if not any(value not in ("", None, [], {}) for key, value in software.items() if key != "display"):
        health["software"] = {}          # nothing was read: an empty card must not earn the Health tab
    if not health.get("stp"):
        health["stp"] = {}
    health["counts"] = {level: sum(1 for item in findings if item["severity"] == level) for level in SEVERITY_ORDER}
    health["capture"] = {"missing": missing, "config_found": config_found, "hints": hints}
    return health


def _days(text: str) -> int:
    """``1 year, 2 weeks, 3 days`` / ``409 day(s)`` -> whole days (years 365, weeks 7)."""
    total = 0
    for amount, unit in re.findall(r"(\d+)\s*(year|week|day)", text or "", re.IGNORECASE):
        total += int(amount) * {"year": 365, "week": 7, "day": 1}[unit.lower()]
    return total


def _env_row(kind: str, name: str, location: str, state: str, reading: str, problem: bool) -> dict[str, Any]:
    return {"type": kind, "name": name, "location": location, "state": state, "reading": reading, "problem": problem}


def _uptime_finding(findings: list[dict[str, Any]], uptime: str, days: int, reload_text: str, platform: str) -> None:
    if days >= 365:
        years = days / 365
        _add(findings, "SW-VER-001", "info", f"No reload for {days} days (about {years:.1f} years)",
             f"Uptime as printed: {uptime}. Last reload: {reload_text or 'not reported'}. A switch that has been up this long is still running the release it booted with; "
             f"compare it with the release the vendor currently recommends for this {platform} platform, and plan a maintenance window for the upgrade.")


# =====================================================================================================================
# Cisco NX-OS
# =====================================================================================================================

def parse_nxos_version(lines: list[str] | None) -> dict[str, Any]:
    """Kernel uptime, last reset (time, reason, service), NX-OS release and chassis from ``show version``."""
    info: dict[str, Any] = {}
    for line in lines or []:
        text = line.strip()
        match = re.match(r"^Kernel uptime is\s+(.+)$", text, re.IGNORECASE)
        if match:
            info["uptime"] = match.group(1).strip()
            info["uptime_days"] = _days(match.group(1))
        match = re.match(r"^Last reset(?: at \d+ usecs after)?\s*(.*)$", text, re.IGNORECASE)
        if match and match.group(1).strip():
            info["last_reload"] = match.group(1).strip()
        match = re.match(r"^Reason:\s*(.+)$", text, re.IGNORECASE)
        if match:
            info["last_reload_reason"] = match.group(1).strip()
        match = re.match(r"^Service:\s*(.+)$", text, re.IGNORECASE)
        if match:
            info["last_reset_service"] = match.group(1).strip()
        match = re.match(r"^NXOS:\s*version\s+(\S+)", text, re.IGNORECASE)
        if match:
            info["version"] = match.group(1)
        match = re.match(r"^cisco\s+(Nexus\S*\s+\S+)\s+(?:chassis|Switch)", text, re.IGNORECASE)
        if match:
            info["platform"] = match.group(1)
        match = re.match(r"^Processor Board ID\s+(\S+)", text, re.IGNORECASE)
        if match:
            info["serial"] = match.group(1)
    return info


_NXOS_FAN = re.compile(r"^(\S+)\s+(\S+)\s+(--|\S+)\s+(front-to-back|back-to-front|\S+)\s+(\S+(?: \S+)?)\s*$")
_NXOS_PSU = re.compile(r"^(\d+)\s+(\S+)\s+(?:(\d+(?:\.\d+)?)\s*W|--|N/A)\s+(?:(\d+(?:\.\d+)?)\s*W|--|N/A)\s+(?:(\d+(?:\.\d+)?)\s*W|--|N/A)\s+(\S+(?: \S+)?)\s*$")
_NXOS_TEMP = re.compile(r"^(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(-?\d+)\s+(\S+(?: \S+)?)\s*$")
_ENV_OK = {"ok", "good", "normal", "online", "present"}


_ENV_SECTION = re.compile(r"^(Fan|Power Supply|Temperature|Power Usage Summary):\s*$", re.IGNORECASE)
_ENV_SKIP = re.compile(r"^(Fan\s+Model\b|Supply\s+Model|Power\s*$|Module\s+Sensor|\(Watts|\(Celsius|Voltage:|Fan Zone|Fan Air|Actual|Total)", re.IGNORECASE)


def parse_nxos_environment(lines: list[str] | None) -> list[dict[str, Any]]:
    """Fan, power supply and temperature rows of ``show environment all`` in the page's environment row shape."""
    rows: list[dict[str, Any]] = []
    section = ""
    for line in lines or []:
        text = line.strip()
        if not text or re.match(r"^-{5,}", text):
            continue
        header = _ENV_SECTION.match(text)
        if header:
            section = header.group(1).lower()
            continue
        if _ENV_SKIP.match(text):
            continue
        if section == "fan":
            match = _NXOS_FAN.match(text)
            if match:
                name, model, _hw, airflow, state = match.groups()
                rows.append(_env_row("Fan", name, "", state, airflow + (f", {model}" if model != "--" else ""), state.lower() not in _ENV_OK))
        elif section == "power supply":
            match = _NXOS_PSU.match(text)
            if match:
                slot, model, out_w, in_w, cap_w, state = match.groups()
                reading = ", ".join(part for part in (f"output {out_w} W" if out_w else "", f"input {in_w} W" if in_w else "", f"capacity {cap_w} W" if cap_w else "") if part)
                rows.append(_env_row("Power supply", f"PSU {slot} {model}" if model != "--" else f"PSU {slot}", "", state, reading, state.lower() not in _ENV_OK))
        elif section == "temperature":
            match = _NXOS_TEMP.match(text)
            if match:
                module, sensor, major, minor, current, state = match.groups()
                rows.append(_env_row("Sensor", sensor, f"module {module}", state, f"{current} C (minor threshold {minor} C, major {major} C)", state.lower() not in _ENV_OK))
    return rows


def parse_nxos_lacp_neighbors(lines: list[str] | None) -> list[dict[str, Any]]:
    """``show lacp neighbor``: one row per member port with the partner's system, port number, flags and port state."""
    rows: list[dict[str, Any]] = []
    group = ""
    pending: dict[str, Any] | None = None
    for line in lines or []:
        text = line.strip()
        match = re.match(r"^(?:port-channel|Po)(\d+)\s+neighbors", text, re.IGNORECASE)
        if match:
            group, pending = match.group(1), None
            continue
        # the system ID and the port number run together in the real output: "32768,90-77-ee-3b-4b-a70x141"
        # NX-OS does not zero-pad the octets ("02-a7-39-9-ea-df") and may print no space before the port number
        match = re.match(r"^(\S+)\s+(\d+),((?:[0-9a-f]{1,2}-){5}[0-9a-f]{1,2})\s*(0x[0-9a-f]+)\s+(\d+)\s+([SFAP]+)\s*$", text, re.IGNORECASE)
        if match:
            port, _sys_priority, system_id, port_number, age, flags = match.groups()
            raw = "".join(octet.zfill(2) for octet in system_id.lower().split("-"))
            pending = {"group": group, "port": port, "flags": flags, "partner_id": f"{raw[0:4]}.{raw[4:8]}.{raw[8:12]}", "age": age, "partner_port": port_number,
                       "priority": "", "partner_key": "", "state": "", "state_bits": "", "healthy": False}
            continue
        match = re.match(r"^(\d+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s*$", text, re.IGNORECASE)
        if match and pending is not None:
            value = int(match.group(3), 16)
            pending.update({"priority": match.group(1), "partner_key": match.group(2), "state": match.group(3).lower(),
                            "state_bits": ", ".join(name for bit, name in enumerate(LACP_STATE_BITS) if value & (1 << bit)),
                            "healthy": (value & 0x3C) == 0x3C and not (value & 0xC0)})
            rows.append(pending)
            pending = None
    return rows


def parse_nxos_vpc(lines: list[str] | None) -> dict[str, Any]:
    """``show vpc`` / ``show vpc brief``: the domain fields, the peer-link row and one row per vPC."""
    out: dict[str, Any] = {"fields": {}, "peerlink": [], "vpcs": []}
    section = ""
    for line in lines or []:
        text = line.strip()
        if not text:
            continue
        if re.match(r"^vPC Peer-link status", text, re.IGNORECASE):
            section = "peerlink"
            continue
        if re.match(r"^vPC status", text, re.IGNORECASE):
            section = "vpcs"
            continue
        match = re.match(r"^(vPC domain id|Peer status|vPC keep-alive status|Configuration consistency status|Per-vlan consistency status|"
                         r"Type-2 consistency status|vPC role|Number of vPCs configured|Peer Gateway|Auto-recovery status|Delay-restore status|"
                         r"Dual Active Detection Status)\s*:\s*(.*?)\s*$", text, re.IGNORECASE)
        if match:
            out["fields"][match.group(1).lower()] = match.group(2)
            continue
        if section == "peerlink":
            match = re.match(r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S.*)?$", text)
            if match and not text.startswith("--"):
                out["peerlink"].append({"id": match.group(1), "port": match.group(2), "status": match.group(3).lower(), "vlans": (match.group(4) or "").strip()})
        elif section == "vpcs":
            match = re.match(r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S.*)?$", text)
            if match and not text.startswith("--"):
                out["vpcs"].append({"id": match.group(1), "port": match.group(2), "status": match.group(3).lower(), "consistency": match.group(4).lower(),
                                    "reason": match.group(5), "vlans": (match.group(6) or "").strip()})
    # A long Consistency / Reason text wraps onto a second line ("Not" / "Applicable"); the column-aware reader joins the pieces
    wrapped = nxos_extras.parse_vpc_status(lines or [])["members"]
    if wrapped:
        out["vpcs"] = [{"id": row["id"], "port": row["port"], "status": row["status"].lower(), "consistency": row["consistency"].lower(), "reason": row["reason"],
                        "vlans": "" if row["vlans"] == "-" else row["vlans"]} for row in wrapped]
    return out


def parse_nxos_vpc_consistency(lines: list[str] | None) -> list[dict[str, Any]]:
    """``show vpc consistency-parameters global``: Name / Type / Local Value / Peer Value, a fixed-width table whose long rows wrap.

    The columns are cut at the offsets of the header words. The same value wraps identically on both sides, so any physical line whose
    local and peer halves differ means the values differ; the difference is reported against the parameter the line belongs to.
    """
    local_at = peer_at = None
    name = kind = ""
    rows: list[dict[str, Any]] = []
    for raw in lines or []:
        header = re.match(r"^Name\s+Type\s+Local Value\s+Peer Value", raw)
        if header:
            local_at, peer_at = raw.index("Local Value"), raw.index("Peer Value")
            continue
        if local_at is None or not raw.strip() or re.match(r"^[-\s]{10,}$", raw):
            continue
        left, right = raw[local_at:peer_at].strip(), raw[peer_at:].strip()
        label = raw[:local_at].rstrip()
        match = re.match(r"^(.*?)\s{2,}([12-])\s*$", label)
        if match and not raw[:1].isspace() and match.group(1).strip():
            name, kind = match.group(1).strip(), match.group(2)
            rows.append({"name": name, "type": kind, "local": left, "peer": right, "match": left == right})
        elif rows and (left or right):
            rows[-1]["local"] = f"{rows[-1]['local']} {left}".strip()
            rows[-1]["peer"] = f"{rows[-1]['peer']} {right}".strip()
            rows[-1]["match"] = rows[-1]["match"] and left == right
    return rows


_NXOS_LICENCE = re.compile(r"^(\S+)\s+(Yes|No)\s+(\S+)\s+(Unused|In use|Grace\S*(?: \S+)*?|Expired|\S+)\s+(Never|-|\d{1,2}-\w{3}-\d{2,4}|\S+)(?:\s+(.*))?$", re.IGNORECASE)


def parse_nxos_licence_usage(lines: list[str] | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    started = False
    for line in lines or []:
        text = line.strip()
        if re.match(r"^Feature\s+Ins\s+Lic\s+Status", text, re.IGNORECASE):
            started = True
            continue
        if not started or not text or re.match(r"^-{5,}$", text) or re.match(r"^Count\s*$", text, re.IGNORECASE):
            continue
        match = _NXOS_LICENCE.match(text)
        if match:
            feature, installed, count, status, expiry, comments = match.groups()
            rows.append({"license": feature, "tag": f"installed: {installed}", "count": count if count != "-" else "", "status": status.strip(),
                         "expiry": expiry, "comments": (comments or "").strip()})
    return rows


def _nxos_rules(findings: list[dict[str, Any]], *, software: dict[str, Any], env: list[dict[str, Any]], flags: dict[str, dict[str, Any]], lacp: list[dict[str, Any]],
                lacp_captured: bool, vpc: dict[str, Any], consistency: list[dict[str, Any]], licences: list[dict[str, Any]], stp: dict[str, Any],
                top: list[str], blocks: dict[str, list[str]], interfaces: list[dict[str, Any]], config: bool) -> None:
    uptime_reload = " / ".join(part for part in (software.get("last_reload"), software.get("last_reload_reason")) if part)
    _uptime_finding(findings, software.get("uptime", ""), software.get("uptime_days") or 0, uptime_reload, "Nexus")
    reason = f"{software.get('last_reload_reason', '')} {software.get('last_reset_service', '')}"
    if re.search(r"HA policy|hap reset|panic|watchdog|crash|core dump", reason, re.IGNORECASE):
        _add(findings, "SW-RST-001", "medium", "Last reset was caused by a failed service, not by a reload command",
             f"`show version` says: Reason: {software.get('last_reload_reason', '')}; Service: {software.get('last_reset_service', '') or 'not reported'}"
             f"{'; at ' + software['last_reload'] if software.get('last_reload') else ''}. NX-OS resets the device when a process's high-availability policy says so. "
             "Check `show system reset-reason`, `show cores` and `show processes log` for the failed service.", doc="nxos_reload")
    for row in env:
        if not row["problem"]:
            continue
        code = {"Fan": "SW-ENV-002", "Power supply": "SW-ENV-003"}.get(row["type"], "SW-ENV-001")
        severity = "medium" if row["state"].lower() in ("absent",) or row["type"] == "Sensor" else "high"
        _add(findings, code, severity, f"{row['type']} {row['name']} is {row['state']}", f"{row['name']} {('(' + row['location'] + ') ') if row['location'] else ''}reports {row['state']}: {row['reading']}.",
             where=row["name"])

    admin_down = {_short(item["name"]) for item in interfaces if item.get("status") == "admin down"}
    link_state = {_short(item["name"]): f"{item['status']} ({item['status_detail']})" if item.get("status_detail") else str(item["status"]) for item in interfaces if item.get("status")}
    for name, info in flags.items():
        bundle_down = info["state"].upper().startswith(("SD", "RD"))
        for member in info["members"]:
            flag = member["flag"]
            if flag in ("P", "p"):
                continue
            if flag == "D" and (member["port"] in admin_down or bundle_down):
                continue
            meaning = MEMBER_FLAGS.get(flag, {"r": "module removed", "b": "BFD session wait", "S": "switched", "R": "routed", "U": "up"}.get(flag, "unknown flag"))
            severity = {"s": "high", "I": "medium", "H": "info", "D": "medium"}.get(flag, "low")
            _add(findings, "SW-LACP-001", severity, f"{name} member {member['port']} is {meaning} ({flag})",
                 f"`show port-channel summary` lists {member['port']} with flag ({flag}) = {meaning}. The bundle does not use this link."
                 + (f" The interface itself is {link_state[member['port']]}." if member["port"] in link_state else "")
                 + " Check the port's status, its channel-group configuration and `show lacp neighbor`.", where=member["port"], doc="nxos_lacp")
    if lacp_captured:
        for row in lacp:
            if row["partner_id"] == "0000.0000.0000":
                _add(findings, "SW-LACP-004", "high", f"No LACP partner answered on {row['port']}",
                     "The partner system ID is all zeros: this port has not received a usable LACPDU from the far end.", where=row["port"], doc="nxos_lacp")
            elif not row["healthy"]:
                _add(findings, "SW-LACP-003", "medium", f"LACP partner state {row['state']} on {row['port']}",
                     f"Partner flags set: {row['state_bits'] or 'none'}. A bundled link shows 0x3d (Activity, Aggregation, Synchronization, Collecting, Distributing).",
                     where=row["port"], doc="nxos_lacp")

    fields = vpc["fields"]
    if fields:
        checks = (("peer status", "peer adjacency formed ok", "SW-VPC-001", "high", "vPC peer adjacency is not formed"),
                  ("vpc keep-alive status", "peer is alive", "SW-VPC-002", "high", "vPC keep-alive is not alive"),
                  ("configuration consistency status", "success", "SW-VPC-003", "high", "vPC configuration is inconsistent"),
                  ("per-vlan consistency status", "success", "SW-VPC-003", "medium", "vPC per-VLAN consistency is not success"),
                  ("type-2 consistency status", "success", "SW-VPC-003", "medium", "vPC type-2 consistency is not success"))
        for key, healthy, code, severity, title in checks:
            value = fields.get(key)
            if value is not None and value.strip().lower() != healthy:
                _add(findings, code, severity, title, f"`show vpc` says: {key}: {value}. Expected '{healthy}'. Run `show vpc consistency-parameters` for the parameter that differs.", doc="nxos_vpc")
        for row in vpc["peerlink"]:
            if row["status"] != "up":
                _add(findings, "SW-VPC-001", "high", f"vPC peer-link {row['port']} is {row['status']}", "The peer-link carries the vPC control and data between the two switches; with it down the pair cannot forward as one.",
                     where=row["port"], doc="nxos_vpc")
        for row in vpc["vpcs"]:
            if row["status"] != "up" or row["consistency"] != "success":
                local_down = row["status"].endswith("*")
                title = (f"vPC {row['id']} ({row['port']}) is down on this switch and forwards over the peer-link" if local_down
                         else f"vPC {row['id']} ({row['port']}) is {row['status']}, consistency {row['consistency']}")
                _add(findings, "SW-VPC-004", "high" if row["status"] != "up" else "medium", title,
                     f"`show vpc` row for vPC {row['id']}: Status {row['status']}{' (the legend in the same output says: local vPC is down, forwarding via vPC peer-link)' if local_down else ''}, "
                     f"Consistency {row['consistency']}, Reason {row['reason']}. Check `show vpc consistency-parameters vpc {row['id']}`.", where=row["port"], doc="nxos_vpc")

    dual = fields.get("dual active detection status", "").strip()
    if dual and dual not in ("0", "-"):
        adjacency = fields.get("peer status", "").strip()
        keepalive = fields.get("vpc keep-alive status", "").strip()
        formed = "adjacency formed ok" in adjacency.lower() and "alive" in keepalive.lower() and "not" not in keepalive.lower()
        if formed:
            # Cisco's published examples print 0 on a healthy pair and none of the pages read defines the other values; the same output says the pair is
            # in contact, so this is a value to look at, not proof of a dual-active condition.
            _add(findings, "SW-VPC-005", "low", f"vPC role prints Dual Active Detection Status {dual} while the peer is in contact",
                 f"`show vpc role` says Dual Active Detection Status: {dual} (Cisco's examples of a healthy pair print 0; the pages read do not define other values). The same capture reports Peer status: {adjacency} "
                 f"and vPC keep-alive status: {keepalive}, so the two peers are talking and this is not by itself a dual-active condition. Check `show vpc` and the Logs tab for peer-link or keep-alive events.", doc="nxos_vpc")
        else:
            _add(findings, "SW-VPC-005", "high", "vPC dual-active condition reported",
                 f"`show vpc role` says Dual Active Detection Status: {dual} and the peer is not in contact (Peer status: {adjacency or 'not printed'}; keep-alive: {keepalive or 'not printed'}). "
                 "Both peers may be forwarding as primary; check the peer-link and the keep-alive path at once.", doc="nxos_vpc")
    for row in consistency:
        if row["match"]:
            continue
        type1 = row["type"] == "1"
        _add(findings, "SW-VPC-003", "high" if type1 else "medium", f"vPC {'type-1' if type1 else 'type-2'} parameter differs between the peers: {row['name']}",
             f"`show vpc consistency-parameters global`: local `{row['local'] or 'empty'}`, peer `{row['peer'] or 'empty'}`. "
             + ("A type-1 mismatch suspends the vPC VLANs." if type1 else "A type-2 mismatch can cause traffic problems without suspending the vPC."), where=row["name"], doc="nxos_vpc")

    for row in licences:
        if "grace" in f"{row['status']} {row['comments']}".lower() or row["status"].lower() == "expired":
            _add(findings, "SW-LIC-003", "medium", f"Licensed feature {row['license']} is {row['status']}",
                 f"`show license usage`: status {row['status']}, expiry {row['expiry']}, comments {row['comments'] or 'none'}. Install the licence before the grace period ends.", where=row["license"])

    if config:
        # `spanning-tree vlan N priority` / `root primary` set on purpose; the root is otherwise the lowest MAC address
        explicit = any(re.match(r"^spanning-tree (vlan \S+ (priority|root)|mst \S+ (priority|root))", line) for line in top)
        if stp.get("root_vlan_count") and not explicit:
            _add(findings, "SW-STP-001", "medium", f"Root bridge for {stp['root_vlan_count']} VLAN(s) with no spanning-tree priority configured",
                 f"`show spanning-tree summary` says this switch is root for {vlan_phrase(stp['root_for'], 160)}, but the configuration has no `spanning-tree vlan ... priority` or `root primary`.")
        edge = [name for name, lines in blocks.items() if any(re.match(r"^spanning-tree port type edge\b", l) for l in lines)]
        global_guard = any(re.match(r"^spanning-tree port type edge bpduguard default", line) for line in top)
        unguarded = [name for name in edge if "spanning-tree bpduguard enable" not in blocks[name]]
        if unguarded and not global_guard:
            _add(findings, "SW-STP-002", "medium", f"{len(unguarded)} edge port(s) without BPDU Guard",
                 f"`spanning-tree port type edge` is set on {', '.join(_short(n) for n in unguarded[:6])}{' ...' if len(unguarded) > 6 else ''} and neither the per-port "
                 "`spanning-tree bpduguard enable` nor `spanning-tree port type edge bpduguard default` is configured.")
        communities = [line for line in top if re.match(r"^snmp-server community\s", line)]
        rw = [line for line in communities if re.search(r"\sgroup\s+network-admin\b|\srw\b", line)]
        if communities:
            _add(findings, "SW-SNMP-001", "high" if rw else "low",
                 f"{len(communities)} SNMP v1/v2c community string(s)" + (f", {len(rw)} with read-write rights (role network-admin or rw)" if rw else ""),
                 "Community strings travel in clear text and are shared secrets. " + (f"{len(rw)} of them map to `group network-admin` or `rw`, so anyone who learns the string can change the switch over SNMP. "
                                                                                       if rw else "") + "Prefer SNMPv3 users (`snmp-server user ... auth sha ... priv ...`). String names are not shown here.", doc="nxos_snmp")
        md5_users = [line for line in top if re.match(r"^snmp-server user\s+\S+.*\bauth md5\b", line)]
        if md5_users:
            _add(findings, "SW-SNMP-004", "low", f"{len(md5_users)} SNMPv3 user(s) authenticate with MD5",
                 "MD5 is the weaker of the authentication hashes NX-OS offers for SNMPv3. Recreate these users with `auth sha`. User names are not shown here.", doc="nxos_snmp")
        if any(re.match(r"^feature telnet\b", line) for line in top):
            _add(findings, "SW-TEL-001", "high", "Telnet server is enabled", "`feature telnet` sends logins and commands in clear text. Use `feature ssh` and `no feature telnet`.")
        if not any(re.match(r"^logging server\b", line) for line in top):
            _add(findings, "SW-LOG-001", "low", "No remote syslog server", "Logs stay in the switch buffer and are lost on reload. Add `logging server <ip>` to a collector.")
        ntp = [line for line in top if re.match(r"^ntp (server|peer)\b", line)]
        if not ntp:
            _add(findings, "SW-NTP-001", "medium", "No NTP server", "Log timestamps and certificates depend on the clock. Add at least two `ntp server` lines.")
        elif len(ntp) == 1:
            _add(findings, "SW-NTP-001", "low", "Only one NTP server", "One source cannot be cross-checked; configure at least two.")


def build_nxos(clean: list[str], *, interfaces: list[dict[str, Any]], port_channels: list[dict[str, Any]]) -> dict[str, Any]:
    health = _empty("Cisco NX-OS", "nxos")
    version_lines = _run(clean, r"sh(?:ow)? ver(?:sion)?", (r"^Cisco Nexus Operating System",), lambda b: ("uptime" in parse_nxos_version(b)) * 100 + len(parse_nxos_version(b)))
    version = parse_nxos_version(version_lines)
    env_lines = _run(clean, r"sh(?:ow)? env(?:ironment)?(?: all)?", (r"^Fan:\s*$",), lambda b: len(parse_nxos_environment(b)))
    env = parse_nxos_environment(env_lines)
    stp_lines = _run(clean, show_tables.PATTERNS["stp_summary"][0], (r"^Switch is in \S+ mode",), lambda b: len(parse_stp_summary(b)))
    stp = parse_stp_summary(stp_lines)
    flags_lines = _run(clean, r"sh(?:ow)? (?:etherchannel|port-channel) summary", (), lambda b: len(parse_etherchannel_flags(b)))
    flags = parse_etherchannel_flags(flags_lines)
    lacp_lines = _run(clean, r"sh(?:ow)? lacp (?:\d+ )?neighbors?(?: detail)?", (), lambda b: len(parse_nxos_lacp_neighbors(b)))
    lacp = parse_nxos_lacp_neighbors(lacp_lines)
    vpc_lines = _run(clean, r"sh(?:ow)? vpc(?: brief)?", (r"^vPC domain id\s*:",), lambda b: len(parse_nxos_vpc(b)["fields"]))
    role_lines = _run(clean, r"sh(?:ow)? vpc role")
    keepalive_lines = _run(clean, r"sh(?:ow)? vpc peer-keepalive")
    vpc = parse_nxos_vpc((role_lines or []) + (keepalive_lines or []) + (vpc_lines or []))
    consistency = parse_nxos_vpc_consistency(_run(clean, r"sh(?:ow)? vpc consistency-parameters global", (), lambda b: len(parse_nxos_vpc_consistency(b))))
    licence_lines = _run(clean, show_tables.PATTERNS["lic_usage"][0], (r"^Feature\s+Ins\s+Lic\b",), lambda b: len(parse_nxos_licence_usage(b)))
    licences = parse_nxos_licence_usage(licence_lines)
    config = _running_config(clean)
    top, blocks = _config_blocks(config)

    findings: list[dict[str, Any]] = []
    _nxos_rules(findings, software=version, env=env, flags=flags, lacp=lacp, lacp_captured=bool(lacp), vpc=vpc, consistency=consistency, licences=licences, stp=stp, top=top,
                blocks=blocks, interfaces=interfaces, config=bool(config))

    lacp_by_port = {row["port"]: row for row in lacp}
    for item in port_channels:
        info = flags.get(item.get("name", ""))
        if info:
            item["member_states"] = [{"port": m["port"], "flag": m["flag"], "meaning": MEMBER_FLAGS.get(m["flag"], "")} for m in info["members"]]
        raw_members = item.get("members") or []
        names = [part.strip() for part in raw_members.split(",")] if isinstance(raw_members, str) else list(raw_members)
        partners = sorted({lacp_by_port[m]["partner_id"] for m in names if m in lacp_by_port})
        if partners:
            item["lacp_partner"] = ", ".join(partners)

    health["environment"]["rows"] = env
    health["environment"]["problems"] = sum(1 for row in env if row["problem"])
    health["lacp"] = lacp
    stp_display = {"mode": stp.get("mode", "—"), "root_bridge_for": stp.get("root_for", "—"), "portfast_default": stp.get("portfast_default", "—"),
                   "bpdu_guard_default": stp.get("bpduguard_default", "—"), "loopguard_default": stp.get("loopguard_default", "—"),
                   "bridge_assurance": stp.get("bridge_assurance", "—"), "vpc_peer_switch": stp.get("vpc_peer_switch", "—")} if stp else {}
    if stp:
        stp["display"] = stp_display
    health["stp"] = stp
    fields = vpc["fields"]
    software = dict(version)
    software["display"] = {} if not (version or fields) else {
        "uptime": version.get("uptime", "—"), "last_reload": version.get("last_reload", "—"), "last_reload_reason": version.get("last_reload_reason", "—"),
        "last_reset_service": version.get("last_reset_service", "—"), "nx_os_release": version.get("version", "—"), "platform": version.get("platform", "—"),
        "vpc_role": fields.get("vpc role", "—"), "vpc_peer": fields.get("peer status", "—"), "vpc_keep_alive": fields.get("vpc keep-alive status", "—"),
    }
    health["software"] = software
    in_use = [row for row in licences if row["status"].lower() not in ("unused",)]
    detail = licence_detail.build_licence_detail(clean)      # Smart Licensing Using Policy layout of NX-OS 10.x: entitlements, status, ACK dates
    health["licence"]["licenses"] = in_use
    detail["features_listed"] = len(licences)
    detail["captured"] = bool(licences) or detail["captured"]
    detail["note"] = (f"{len(licences)} features listed, {len(in_use)} in use" if licences else
                      f"{len(detail['entitlements'])} entitlement(s), {sum(1 for item in detail['entitlements'] if re.search(r'in use', item.get('status', ''), re.IGNORECASE))} in use" if detail["entitlements"] else "")
    health["licence"]["detail"] = detail
    for item in licence_detail.licence_findings(detail, report_doc="smart_slp_nxos"):
        _add(findings, item["code"], item["severity"], item["title"], item["text"], where=item["where"], doc=item["doc"])
    extras = nxos_extras.analyse(clean)
    state = nxos_state.analyse(clean)
    findings += extras["findings"] + state["findings"]
    health["extra_tables"] = extras["tables"] + state["tables"]
    health["extra_counts"] = {**extras["counts"], **state["counts"]}

    missing = []
    for label, found, adds in (("show version", version_lines, "uptime, the reason for the last reset"), ("show environment all", env_lines, "fan, power supply and temperature state"),
                               ("show spanning-tree summary", stp_lines, "root-bridge VLANs, edge-port defaults, bridge assurance"), ("show port-channel summary", flags_lines, "member state of every port-channel"),
                               ("show lacp neighbor", lacp_lines, "LACP partner and state per member"), ("show vpc", vpc_lines if vpc_lines is not None else role_lines if role_lines is not None else keepalive_lines, "vPC peer, keep-alive and consistency state"),
                               ("show license usage", licence_lines, "which licensed features are in use")):
        if found is None:
            missing.append({"command": label, "adds": adds})
    if not config:
        missing.insert(0, {"command": "show running-config", "adds": "SNMP, telnet, syslog, NTP and spanning-tree edge-port checks"})
    hints = {"lacp": "Not in this capture. Add show lacp neighbor.", "env": "Not in this capture. Add show environment all."}
    return _finish(health, findings, missing, bool(config), hints)


# =====================================================================================================================
# Huawei VRP / YunShan OS
# =====================================================================================================================

def parse_huawei_version(lines: list[str] | None) -> dict[str, Any]:
    """Uptime of the device and of each stack member, release, startup time, memory and flash from ``display version``."""
    info: dict[str, Any] = {"members": []}
    for line in lines or []:
        text = line.strip()
        match = re.match(r"^(?:HUAWEI|Huawei|Quidway)\s+(?:CloudEngine\s+)?(\S+)\s+uptime is\s+(.+)$", text)
        if match and "uptime" not in info:
            info["platform"] = match.group(1)
            info["uptime"] = match.group(2).strip()
            info["uptime_days"] = _days(match.group(2))
            continue
        match = re.match(r"^Version\s+(\S+)\s+\((\S+\s+\S+)\)", text)
        if match and "version" not in info:
            info["version"] = f"{match.group(1)} ({match.group(2)})"
            continue
        match = re.match(r"^VRP \(R\) software, Version\s+(\S+)\s+\((.+?)\)", text)
        if match and "version" not in info:
            info["version"] = f"{match.group(1)} ({match.group(2)})"
            continue
        match = re.match(r"^Patch Version\s*:\s*(\S+)", text, re.IGNORECASE)
        if match:
            info["patch"] = match.group(1)
            continue
        match = re.match(r"^(\S+)\((Master|Standby|Slave)\)\s+(\d+)\s*:\s*uptime is\s+(.+)$", text)
        if match:
            info["members"].append({"model": match.group(1), "role": match.group(2), "member": match.group(3), "uptime": match.group(4).strip(),
                                    "uptime_days": _days(match.group(4)), "startup": ""})
            continue
        match = re.match(r"^StartupTime\s+(\S+\s+\S+)", text)
        if match and info["members"]:
            info["members"][-1]["startup"] = match.group(1)
            continue
        match = re.match(r"^Memory\s+Size\s*:\s*(.+)$", text)
        if match and "memory" not in info:
            info["memory"] = match.group(1).strip()
        match = re.match(r"^Flash\s+Size\s*:\s*(.+)$", text)
        if match and "flash" not in info:
            info["flash"] = match.group(1).strip()
    return info


_HUAWEI_SLOT = re.compile(r"^(\d+)\s+(\S+)\s+(\S+)\s+(Present|Absent|\S+)\s+(On|Off|\S+)\s+(Registered|Unregistered|\S+)\s+(\S+)\s+(Master|Standby|Slave|NA|\S+)\s*$")
_HUAWEI_PART = re.compile(r"^\s+((?:FAN|PWR|PSU|MPU|LPU|SFU|CMU)\S*)\s+(\S+)\s+(Present|Absent|\S+)\s+(On|Off|\S+)\s+(Registered|Unregistered|\S+)\s+(\S+)\s+(\S+)\s*$")


def parse_huawei_device(lines: list[str] | None) -> list[dict[str, Any]]:
    """``display device``: stack members (slots) and their fans and power supplies, with online / power / registration / alarm state."""
    rows: list[dict[str, Any]] = []
    slot = ""
    started = False
    for raw in lines or []:
        if re.match(r"^Slot\s+Card\s+Type\s+Online\s+Power\s+Register\s+Alarm", raw.strip(), re.IGNORECASE):
            started = True
            continue
        if not started or re.match(r"^\s*-{5,}\s*$", raw):
            continue
        part = _HUAWEI_PART.match(raw)
        if part and raw[:1].isspace():
            name, kind_model, online, power, register, alarm, _primary = part.groups()
            kind = "Fan" if name.upper().startswith("FAN") else "Power supply" if name.upper().startswith(("PWR", "PSU")) else "Board"
            absent = online.lower() == "absent"
            problem = (not absent) and (online.lower() != "present" or alarm.lower() != "normal" or register.lower() != "registered" or power.lower() not in ("on", "-"))
            rows.append({"type": kind, "name": name, "location": f"slot {slot}", "state": "Absent" if absent else alarm,
                         "reading": f"{kind_model}, online {online}, power {power}, {register}", "problem": problem, "absent": absent})
            continue
        match = _HUAWEI_SLOT.match(raw.strip())
        if match:
            slot, card, model, online, power, register, alarm, role = match.groups()
            absent = online.lower() == "absent"
            problem = (not absent) and (online.lower() != "present" or alarm.lower() != "normal" or register.lower() != "registered")
            rows.append({"type": "Switch", "name": f"Slot {slot} {model}", "location": role if role != "NA" else "", "state": alarm,
                         "reading": f"online {online}, power {power}, {register}", "problem": problem, "absent": absent})
    return rows


def parse_huawei_stp(global_lines: list[str] | None, brief_lines: list[str] | None) -> dict[str, Any]:
    """``display stp`` (CIST globals) and ``display stp brief`` (role and state of every port, per VLAN under VBST)."""
    info: dict[str, Any] = {}
    for line in global_lines or []:
        text = line.strip()
        for key, pattern in (("mode", r"^Mode\s*:\s*(\S+)"), ("bridge", r"^CIST Bridge\s*:\s*(\S+)"), ("bpdu_protection", r"^BPDU-Protection\s*:\s*(\S+)"),
                             ("tc_received", r"^TC or TCN received\s*:\s*(\d+)"), ("tc_count", r"^Number of TC\s*:\s*(\d+)"), ("last_tc", r"^Time since last TC\s*:\s*(.+)$")):
            match = re.match(pattern, text, re.IGNORECASE)
            if match:
                info[key] = match.group(1).strip()
        match = re.match(r"^CIST Root/ERPC\s*:\s*(\S+)\s*/\s*(\d+)(?:\s*\((.*)\))?", text, re.IGNORECASE)
        if match:
            info["root"] = match.group(1)
            info["root_cost"] = match.group(2)
            info["is_root"] = "this bridge is the root" in (match.group(3) or "").lower()
    ports: list[dict[str, Any]] = []
    for line in brief_lines or []:
        match = re.match(r"^\s*(\d+)\s+(\S+)\s+(ROOT|DESI|ALTE|BACK|MAST|DISA|\S{4})\s+(forwarding|discarding|learning|\S+)\s+(none|bpdu|root|loop|\S+)\s+(\d+)\s+(enable|disable)\s*$", line, re.IGNORECASE)
        if match:
            instance, port, role, state, protection, cost, edged = match.groups()
            ports.append({"instance": instance, "port": port, "role": role.upper(), "state": state.lower(), "protection": protection.lower(), "cost": cost, "edged": edged.lower() == "enable"})
    info["ports"] = ports
    return info


def parse_huawei_eth_trunk(lines: list[str] | None) -> list[dict[str, Any]]:
    """``display eth-trunk``: one dict per trunk with its state, the local member table and (LACP) the partner table."""
    trunks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    side = ""
    for line in lines or []:
        text = line.strip()
        match = re.match(r"^Eth-Trunk(\d+)'s state information is:", text, re.IGNORECASE)
        if match:
            current = {"id": match.group(1), "mode": "", "status": "", "up_ports": None, "least_active": None, "members": [], "partner": {}}
            trunks.append(current)
            side = ""
            continue
        if current is None:
            continue
        if re.match(r"^Local:", text, re.IGNORECASE):
            side = "local"
            continue
        if re.match(r"^Partner:", text, re.IGNORECASE):
            side = "partner"
            continue
        match = re.search(r"Working Mode:\s*(\S+)", text)
        if match:
            current["mode"] = match.group(1)
        match = re.search(r"Operating Status:\s*(\S+)", text)
        if match:
            current["status"] = match.group(1).lower()
        match = re.search(r"Number Of Up Ports In Trunk:\s*(\d+)", text)
        if match:
            current["up_ports"] = int(match.group(1))
        match = re.search(r"Least Active-linknumber:\s*(\d+)", text)
        if match:
            current["least_active"] = int(match.group(1))
        if side == "local":
            match = re.match(r"^(\S+?)(?:\((?:r|h|rh|hr)\))?\s+(Selected|Unselect|Unselected)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([01]{8})\s+(\d+)\s*$", text)
            if match:
                port, status, port_type, priority, number, key, state, weight = match.groups()
                current["members"].append({"port": port, "status": status, "type": port_type, "priority": priority, "number": number, "key": key, "state": state})
                continue
            match = re.match(r"^(\S+)\s+(Up|Down)\s+(\d+)\s*$", text, re.IGNORECASE)      # manual (non-LACP) trunk: PortName Status Weight
            if match and match.group(1).lower() not in ("portname",):
                current["members"].append({"port": match.group(1), "status": match.group(2).capitalize(), "type": "", "priority": "", "number": "", "key": "", "state": ""})
        elif side == "partner":
            match = re.match(r"^(\S+?)(?:\((?:r|h|rh|hr)\))?\s+(\d+)\s+([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\s+(\d+)\s+(\d+)\s+(\d+)\s+([01]{8})\s*$", text, re.IGNORECASE)
            if match:
                port, sys_priority, system_id, port_priority, number, key, state = match.groups()
                current["partner"][port] = {"system_priority": sys_priority, "system_id": system_id.lower(), "port_priority": port_priority, "number": number, "key": key, "state": state}
    return trunks


def huawei_lacp_state(bits: str) -> tuple[bool, str]:
    """802.1AX actor state as Huawei prints it: eight 0/1 characters, bit 0 (Activity) first. Healthy = Synchronization + Collecting + Distributing, not Defaulted / Expired."""
    flags = [bit == "1" for bit in bits]
    if len(flags) != 8:
        return False, ""
    names = ", ".join(name for name, on in zip(LACP_STATE_BITS, flags) if on)
    return (flags[3] and flags[4] and flags[5] and not flags[6] and not flags[7]), names


def _huawei_lacp_rows(trunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for trunk in trunks:
        for member in trunk["members"]:
            partner = trunk["partner"].get(member["port"])
            if not partner:
                continue
            healthy, names = huawei_lacp_state(partner["state"])
            rows.append({"group": trunk["id"], "port": member["port"], "flags": member["status"], "priority": partner["port_priority"], "partner_id": partner["system_id"],
                         "age": "", "partner_key": partner["key"], "partner_port": partner["number"], "state": partner["state"], "state_bits": names, "healthy": healthy})
    return rows


def _huawei_rules(findings: list[dict[str, Any]], *, version: dict[str, Any], devices: list[dict[str, Any]], stp: dict[str, Any], trunks: list[dict[str, Any]],
                  top: list[str], config: bool, config_edged: int, link_state: dict[str, str], config_lines: list[str] | None = None) -> None:
    members = version.get("members") or []
    _uptime_finding(findings, version.get("uptime", ""), max([version.get("uptime_days") or 0] + [m["uptime_days"] for m in members]),
                    f"started {members[0]['startup']}" if members and members[0].get("startup") else "", "Huawei")
    for row in devices:
        if row["problem"]:
            code = {"Fan": "SW-ENV-002", "Power supply": "SW-ENV-003"}.get(row["type"], "SW-ENV-001")
            _add(findings, code, "high", f"{row['type']} {row['name']} reports {row['state']}", f"`display device`: {row['name']} ({row['location']}) {row['reading']}, alarm {row['state']}.", where=row["name"])
        elif row.get("absent") and row["type"] == "Power supply":
            _add(findings, "SW-ENV-004", "info", f"{row['name']} slot is empty", f"`display device` lists {row['name']} as Absent: no power supply redundancy in that slot.", where=row["name"])

    if stp:
        edged_ports = {p["port"] for p in stp.get("ports", []) if p["edged"]}
        enabled = str(stp.get("bpdu_protection", "")).lower() == "enabled"
        if stp.get("bpdu_protection") and not enabled and (edged_ports or config_edged):
            _add(findings, "SW-STP-004", "medium", "BPDU protection is off while edge ports exist",
                 f"`display stp` says BPDU-Protection: {stp['bpdu_protection']}, and {len(edged_ports) or config_edged} port(s) are edge ports. "
                 "With BPDU protection a port that receives a BPDU is shut down; without it a switch plugged into an edge port can take part in spanning tree. Enable it with `stp bpdu-protection`.", doc="huawei_bpdu")
        not_forwarding = [p for p in stp.get("ports", []) if p["state"] != "forwarding"]
        if not_forwarding:
            names = ", ".join(sorted({f"{p['port']} (VLAN/instance {p['instance']}, {p['role']}, {p['state']})" for p in not_forwarding})[:6])
            _add(findings, "SW-STP-005", "info", f"{len(not_forwarding)} spanning-tree port entr{'y is' if len(not_forwarding) == 1 else 'ies are'} not forwarding",
                 f"`display stp brief`: {names}. A discarding alternate or backup port is normal in a looped design; an unexpected one means a link is blocked.", doc="huawei_stp")
        tc = int(stp.get("tc_count") or 0)
        if tc:
            _add(findings, "SW-STP-006", "info", f"{tc} spanning-tree topology change(s) recorded", f"`display stp`: Number of TC {tc}; time since the last one: {stp.get('last_tc', 'not reported')}. "
                 "Repeated topology changes flush MAC tables and cause short outages; find the port that flaps.", doc="huawei_stp")

    for trunk in trunks:
        name = f"Eth-Trunk{trunk['id']}"
        if trunk["status"] and trunk["status"] != "up":
            _add(findings, "SW-LACP-006", "high", f"{name} is {trunk['status']}", f"`display eth-trunk`: Operating Status {trunk['status']}, {trunk['up_ports']} port(s) up.", where=name, doc="huawei_lacp")
        elif trunk["up_ports"] is not None and trunk["least_active"] is not None and trunk["up_ports"] < trunk["least_active"]:
            _add(findings, "SW-LACP-006", "high", f"{name} has fewer active links than its minimum",
                 f"`display eth-trunk`: {trunk['up_ports']} port(s) up, least active-linknumber {trunk['least_active']}.", where=name, doc="huawei_lacp")
        for member in trunk["members"]:
            partner = trunk["partner"].get(member["port"])
            status = member["status"].lower()
            if status in ("unselect", "unselected", "down"):
                detail = ""
                if partner and partner["system_id"] == "0000-0000-0000":
                    detail = (f" The partner system ID is 0000-0000-0000 and its port state is {partner['state']}: no LACPDU has been received from the far end on this port, "
                              "so either the link is down or the far end is not running LACP on it.")
                elif partner:
                    _healthy, names = huawei_lacp_state(partner["state"])
                    detail = f" The partner's port state is {partner['state']} ({names or 'no flags'}), partner port number {partner['number']}, key {partner['key']}."
                link = link_state.get(member["port"].lower())
                if link:
                    detail += f" The interface itself is {link}."
                _add(findings, "SW-LACP-001", "medium", f"{name} member {member['port']} is {member['status']}",
                     f"`display eth-trunk` lists {member['port']} as {member['status']}: it does not carry traffic for the trunk.{detail} Check the far end's LACP mode and that both ends bundle the same ports.",
                     where=member["port"], doc="huawei_lacp")

    if config:
        if any(re.match(r"^telnet(?: ipv6)? server enable\b", line) for line in top):
            _add(findings, "SW-TEL-001", "high", "Telnet server is enabled", "`telnet server enable` sends logins and commands in clear text. Use `stelnet server enable` (SSH) and `undo telnet server enable`.")
        if any(re.match(r"^ftp(?: ipv6)? server enable\b", line) for line in top):
            _add(findings, "SW-FTP-001", "medium", "FTP server is enabled", "`ftp server enable` sends credentials and files in clear text. Use `sftp server enable`.")
        if any(re.match(r"^http server enable\b", line) for line in top):
            _add(findings, "SW-HTTP-001", "medium", "Plain HTTP management server is enabled", "`http server enable` serves the web UI without encryption. Use `http secure-server enable` only.")
        version_lines = [line for line in top if re.match(r"^snmp-agent sys-info version\b", line)]
        if any(re.search(r"\b(v1|all)\b", line) for line in version_lines):
            _add(findings, "SW-SNMP-002", "medium", "SNMPv1 is enabled", f"`{version_lines[0]}` allows SNMPv1, which has no authentication beyond a community string. Allow `v2c v3` or `v3` only.")
        communities = [line for line in top if re.match(r"^snmp-agent community\s+(read|write)\b", line)]
        writers = [line for line in communities if re.match(r"^snmp-agent community write\b", line)]
        if communities:
            _add(findings, "SW-SNMP-001", "medium" if writers else "low", f"{len(communities)} SNMP v1/v2c community string(s)" + (f", {len(writers)} with write access" if writers else ""),
                 "Community strings are shared secrets. Prefer SNMPv3 users. String names are not shown here.")
        if any(re.match(r"^snmp-agent community complexity-check disable\b", line) for line in top):
            _add(findings, "SW-SNMP-003", "low", "SNMP community complexity check is disabled", "`snmp-agent community complexity-check disable` lets simple community strings be configured.")
        if not any(re.match(r"^info-center loghost\s+\d", line) for line in top):
            _add(findings, "SW-LOG-001", "low", "No remote syslog server", "Logs stay in the switch buffer and are lost on reload. Add `info-center loghost <ip>` to a collector.")
        ntp = [line for line in top if re.match(r"^ntp(?:-service)? (?:unicast-server|server|unicast-peer|peer)\b", line) and "source-interface" not in line and "disable" not in line]
        if not ntp:
            _add(findings, "SW-NTP-001", "medium", "No NTP server", "Log timestamps and certificates depend on the clock. Add at least two `ntp unicast-server` lines.")
        elif len(ntp) == 1:
            _add(findings, "SW-NTP-001", "low", "Only one NTP server", "One source cannot be cross-checked; configure at least two.")
        _huawei_baseline(findings, config_lines or [], top)
        _huawei_flow_and_source(findings, config_lines or [])


def _huawei_sections(config: list[str]) -> list[tuple[str, list[str]]]:
    """``display current-configuration`` as (top-level line, indented lines); ``#`` separators close a section."""
    sections: list[tuple[str, list[str]]] = []
    for raw in config:
        if not raw.strip() or raw.strip() == "#":
            sections.append(("", []))
            continue
        if raw[0].isspace():
            if sections:
                sections[-1][1].append(raw.strip())
        else:
            sections.append((raw.strip(), []))
    return [s for s in sections if s[0]]


def _huawei_flow_and_source(findings: list[dict[str, Any]], config: list[str]) -> None:
    """NetStream export and management source-interface checks on a Huawei ``display current-configuration``.

    Written from four real S5755-H24T4Y2CZ core stacks (Depo Makassar, Manado, Pekanbaru, Semarang). Commands are from the Huawei CloudEngine
    S300, S500, S2700, S5700 and S6700 V600R025C00 command reference: `netstream export ip source <ip>` (an address, not an interface),
    `netstream timeout ip active <seconds>` (default 1800), `ntp server source-interface <interface>` and `info-center loghost source <interface>`.
    """
    lines = [raw.strip() for raw in config if raw.strip()]
    addresses: set[str] = set()
    addressed_vlanifs: set[str] = set()
    current = ""
    for raw in config:
        if raw and not raw[0].isspace():
            current = raw.strip()
            continue
        found = re.match(r"^\s+ip address (\d+\.\d+\.\d+\.\d+)\s+\S+", raw)
        if found:
            addresses.add(found.group(1))
            vlanif = re.match(r"^interface (Vlanif\d+)$", current)
            if vlanif:
                addressed_vlanifs.add(vlanif.group(1).lower())

    for line in lines:
        found = re.match(r"^netstream export ip source (\d+\.\d+\.\d+\.\d+)\s*$", line)
        if found and addresses and found.group(1) not in addresses:
            _add(findings, "SW-NSF-001", "medium", "NetStream export source is not an address of this switch",
                 f"`{line}`: no interface of this configuration carries {found.group(1)}, so the collector receives records from a source address the switch does not own "
                 "(the usual cause is a Catalyst `source Vlan<N>` copied without its SVI). Set `netstream export ip source` to the management SVI address. "
                 "Source: V600R025C00 command reference, NetStream commands.", where=line)
        found = re.match(r"^netstream timeout ip active (\d+)\s*$", line)
        if found and int(found.group(1)) < 60:
            _add(findings, "SW-NSF-002", "low", f"NetStream active flow timeout is {found.group(1)} second(s)",
                 f"`{line}`: the unit is seconds (default 1800, V600R025C00 command reference), so every long flow is exported every {found.group(1)} s. "
                 "That multiplies the records the collector must take; use 60 s or more unless the collector needs one-second resolution.", where=line)
    for pattern, label in ((r"^ntp server source-interface (Vlanif\d+)\s*$", "NTP"), (r"^info-center loghost source (Vlanif\d+)\s*$", "syslog")):
        for line in lines:
            found = re.match(pattern, line)
            if found and any(re.match(r"^interface Vlanif\d+$", item) for item in lines) and found.group(1).lower() not in addressed_vlanifs:
                _add(findings, "SW-SRC-001", "medium", f"The {label} source interface {found.group(1)} has no IP address on this switch",
                     f"`{line}`: {found.group(1)} is missing or has no `ip address`, so {label} packets leave with another source address (or are not sent) and an ACL on the server side drops them. "
                     "Point the source at an addressed management Vlanif.", where=line)


def _huawei_baseline(findings: list[dict[str, Any]], config: list[str], top: list[str]) -> None:
    """Checks from Huawei's "Baseline Check Items for Security Configuration of Campus Switches" (V600R025C00, Mandatory and Optional workbooks).

    Only what the saved configuration can prove is reported: ``display current-configuration`` omits default values, so a setting whose default
    is already the recommended one is judged by an explicit ``undo`` / ``disable`` line, and a setting that needs an explicit command (VTY
    ``protocol inbound ssh``, an SNMP ACL) is judged by its absence.  Passwords and community strings are never printed.
    """
    sections = _huawei_sections(config)
    vty = [(head, body) for head, body in sections if re.match(r"^user-interface\s+vty\b", head)]
    console = [(head, body) for head, body in sections if re.match(r"^user-interface\s+(?:con|console)\b", head)]
    anywhere = [raw.strip() for raw in config if raw.strip()]
    telnet_on = any(re.match(r"^telnet(?: ipv6)? server enable\b", line) for line in top)

    def has(pattern: str) -> bool:
        return any(re.match(pattern, line) for line in anywhere)

    def doc() -> str:
        return "huawei_baseline"

    # --- VTY (mandatory: protocol inbound, idle timeout, authentication mode; optional: ACL)
    for head, body in vty:
        inbound = [line for line in body if line.startswith("protocol inbound")]
        mode = inbound[-1].split()[-1] if inbound else "all"
        if mode in ("telnet", "all"):
            sev = "high" if (inbound or telnet_on) else "low"
            _add(findings, "SW-VTY-001", sev, f"VTY lines accept {'Telnet' if mode == 'telnet' else 'any inbound protocol'}",
                 f"`{head}`: " + (f"`{inbound[-1]}`" if inbound else "no `protocol inbound` line, so the default (`all`) applies")
                 + ". Baseline check item \"Protocol used by VTY\" (Mandatory, risk Very high) recommends `protocol inbound ssh`.", where=head, doc=doc())
        timeouts = [line for line in body if line.startswith("idle-timeout")]
        if timeouts and re.match(r"^idle-timeout\s+0(?:\s+0)?$", timeouts[-1]):
            _add(findings, "SW-VTY-002", "medium", "VTY sessions never time out",
                 f"`{head}`: `{timeouts[-1]}` disables the idle timeout. Baseline check item \"Idle timeout period of VTY sessions\" (Mandatory, risk Very high) asks for a non-zero value (default 10 minutes).", where=head, doc=doc())
        auth = [line for line in body if line.startswith("authentication-mode")]
        if auth and auth[-1].split()[-1] != "aaa":
            _add(findings, "SW-VTY-003", "high", f"VTY login uses `{auth[-1]}` instead of AAA",
                 f"`{head}`: a shared line password (or no password) gives every administrator the same identity and no accounting. Baseline check item \"Authentication mode of VTY service\" (Mandatory, risk Very high) recommends `authentication-mode aaa`.", where=head, doc=doc())
    if vty and not any(line.startswith("acl") and "inbound" in line for _head, body in vty for line in body) and not has(r"^ssh server acl\b"):
        _add(findings, "SW-VTY-004", "medium", "Management access is not restricted by an ACL",
             "No `acl <n> inbound` under `user-interface vty` and no `ssh server acl`: any reachable address may attempt a login. Baseline check items \"SSH ACL configuration\" (Mandatory) and \"VTY acl configuration\" (Optional, risk High).", doc=doc())
    for head, body in console:
        auth = [line for line in body if line.startswith("authentication-mode")]
        if auth and auth[-1].split()[-1] != "aaa":
            _add(findings, "SW-CON-001", "medium", f"Console login uses `{auth[-1]}`", f"`{head}`: baseline check item \"Authentication configuration on CONSOLE port\" (Optional, risk Very high) recommends `authentication-mode aaa`.", where=head, doc=doc())

    # --- SSH / Telnet / FTP service switches
    if has(r"^ssh server compatible-ssh1x enable\b"):
        _add(findings, "SW-SSH-002", "high", "SSH protocol version 1 compatibility is enabled",
             "`ssh server compatible-ssh1x enable` lets SSHv1 clients connect; SSHv1 has known weaknesses. Remove it (baseline check item \"SSHv1 compatibility status\", Mandatory).", doc=doc())
    for pattern, label, code, item in (
        (r"^ssh server ip-block disable\b", "SSH", "SW-SSH-003", "IP block feature for SSH server"),
        (r"^telnet server ip-block disable\b", "Telnet", "SW-TEL-002", "Telnet IP block feature"),
        (r"^ftp server ip-block disable\b", "FTP", "SW-FTP-002", "FTP IP block feature"),
        (r"^http server ip-block disable\b", "HTTP", "SW-HTTP-002", "HTTP IP block feature"),
    ):
        if has(pattern):
            _add(findings, code, "medium", f"{label} server does not lock out repeated failed logins",
                 f"`{pattern[1:].split(chr(92))[0].strip()}` turns off the lock on a client IP address after repeated authentication failures. Baseline check item \"{item}\".", doc=doc())
    for pattern, label in ((r"^telnet(?: ipv6)? server-source all-interface\b", "Telnet"), (r"^ftp(?: ipv6)? server source all-interface\b", "FTP"),
                           (r"^ssh(?: ipv6)? server-source all-interface\b", "SSH"), (r"^snmp-agent(?: proxy)? protocol source-status(?: ipv6)? all-interface\b", "SNMP")):
        if has(pattern):
            _add(findings, "SW-MGT-001", "medium", f"{label} server listens on every interface",
                 f"The `all-interface` source setting opens the {label} service on every address of the switch, not only the management one. Bind it to a management interface instead (baseline check items \"All-interface listening on ...\", Optional, risk Very high / High).", doc=doc())
    if has(r"^ntp(?: ipv6)? server source-interface all enable\b"):
        _add(findings, "SW-NTP-003", "medium", "NTP server listens on all interfaces",
             "`ntp server source-interface all enable` lets any interface answer NTP requests. Baseline check item \"The NTP IPv4 server enable to listen to all interfaces\" (Optional, risk Very high) recommends `disable`.", doc=doc())

    # --- SNMP
    snmp_in_use = [line for line in top if re.match(r"^snmp-agent (?:community|usm-user|target-host|sys-info version)\b", line)]
    if snmp_in_use and not has(r"^snmp-agent acl\b") and not any(re.match(r"^snmp-agent (?:community|usm-user)\b", line) and re.search(r"\bacl\b", line) for line in anywhere):
        _add(findings, "SW-SNMP-005", "medium", "SNMP is not restricted by an ACL",
             "No `snmp-agent acl` and no `acl` option on any community or SNMPv3 user: any address that knows a community or user can query the switch. Baseline check item \"Snmp acl configuration\" (Mandatory, risk Very high).", doc=doc())
    for pattern, title, item in (
        (r"^snmp-agent blacklist user-block disable\b", "SNMP user blacklist is disabled", "SNMP user blacklist"),
        (r"^snmp-agent blacklist ip-block disable\b", "SNMP IP blacklist is disabled", "SNMP IP blacklist"),
        (r"^snmp-agent usm-user password complexity-check disable\b", "SNMPv3 user password complexity check is disabled", "SNMP usm-user password complexity check"),
    ):
        if has(pattern):
            _add(findings, "SW-SNMP-006", "medium", title, f"`{pattern[1:].split(chr(92))[0]}` weakens the SNMP login protection. Baseline check item \"{item}\" (Mandatory, risk High).", doc=doc())

    # --- AAA and local accounts
    if has(r"^undo local-aaa-user wrong-password\b"):
        _add(findings, "SW-AAA-101", "high", "Local account locking is disabled",
             "`undo local-aaa-user wrong-password` turns off the lock after repeated wrong passwords, so a local account can be guessed without limit. Baseline check item \"Local account locking function\" (Mandatory, risk Very high); default `retry-interval 5 retry-time 3 block-time 5`.", doc=doc())
    if has(r"^undo administrator remote authen-fail\b"):
        _add(findings, "SW-AAA-102", "high", "Account locking for administrators that fail remote authentication is disabled",
             "`undo administrator remote authen-fail` turns off the lock. Baseline check item \"Account locking function for administrators who fail remote authentication\" (Mandatory, risk Very high).", doc=doc())
    weak = [line for line in anywhere if re.match(r"^password complexity (?:two-of-kinds|three-of-kinds)\b", line)]
    if weak:
        _add(findings, "SW-AAA-103", "medium", "Local password complexity is lowered",
             f"`{weak[0]}`: the default and the recommendation are `four-of-kinds` (baseline check item \"Local account security enhancement function\", Mandatory, risk Very high).", doc=doc())
    if has(r"^undo password alert original\b"):
        _add(findings, "SW-AAA-104", "medium", "Users are not prompted to change the initial password",
             "`undo password alert original` removes the prompt (baseline check item \"Prompting users to change initial passwords\", Mandatory, risk Very high).", doc=doc())
    if has(r"^local-user .* password-force-change disable\b"):
        _add(findings, "SW-AAA-105", "medium", "Forced password change is disabled for a local user",
             "A `local-user ... password-force-change disable` line lets an account keep its initial password (Optional baseline item \"password-force-change function\", risk Very high).", doc=doc())
    risky = []
    for line in anywhere:
        match = re.match(r"^local-user\s+(\S+)\s+service-type\s+(.+)$", line)
        if match and re.search(r"\b(?:telnet|ftp)\b", match.group(2)):
            risky.append(f"{match.group(1)} ({match.group(2).strip()})")
    if risky:
        _add(findings, "SW-AAA-106", "medium", f"{len(risky)} local user(s) may log in over Telnet or FTP",
             "Service types: " + "; ".join(risky[:8]) + (f" and {len(risky) - 8} more" if len(risky) > 8 else "")
             + ". Baseline check item \"AAA Local User Service Type\" (Mandatory, risk Very high) recommends `terminal ssh http`.", doc=doc())


def _huawei_config(clean: list[str]) -> list[str]:
    block = _run(clean, r"dis(?:p(?:l(?:a(?:y)?)?)?)? cur(?:r(?:e(?:n(?:t(?:-(?:c(?:o(?:n(?:f(?:i(?:g(?:u(?:r(?:a(?:t(?:i(?:o(?:n)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?")
    if block and any(line.startswith(("sysname ", "interface ")) for line in block):
        return block
    if any(line.startswith("sysname ") for line in clean) and any(line.startswith("interface ") for line in clean):
        return clean
    return []


def build_huawei(clean: list[str], *, interfaces: list[dict[str, Any]], port_channels: list[dict[str, Any]]) -> dict[str, Any]:
    health = _empty("Huawei VRP / YunShan OS", "huawei")
    _d = r"dis(?:p(?:l(?:a(?:y)?)?)?)?"
    version_lines = _run(clean, rf"{_d} ver(?:s(?:i(?:o(?:n)?)?)?)?", (r"^Huawei YunShan OS\s*$", r"^VRP \(R\) software"),
                         lambda b: ("uptime" in parse_huawei_version(b)) * 100 + len(parse_huawei_version(b)["members"]))
    version = parse_huawei_version(version_lines)
    device_lines = _run(clean, rf"{_d} device", (r"^.+'s Device status:\s*$",), lambda b: len(parse_huawei_device(b)))
    devices = parse_huawei_device(device_lines)
    stp_lines = _run(clean, rf"{_d} stp", (r"^CIST Global Information:",))
    stp_brief = _run(clean, rf"{_d} stp b(?:r(?:i(?:e(?:f)?)?)?)?", (r"^\s*(?:VLANID|MSTID)\s+Port\s+Role\s+STP State",), lambda b: len(parse_huawei_stp(None, b)["ports"]))
    stp = parse_huawei_stp(stp_lines, stp_brief) if (stp_lines or stp_brief) else {}
    trunk_lines = _run(clean, rf"{_d} eth-trunk(?: \d+)?", (r"^Eth-Trunk\d+'s state information is:",), lambda b: len(parse_huawei_eth_trunk(b)))
    trunks = parse_huawei_eth_trunk(trunk_lines)
    config = _huawei_config(clean)
    top: list[str] = []
    config_edged = 0
    for raw in config:
        if raw and not raw[0].isspace():
            top.append(raw.strip())
        elif re.match(r"^\s+stp edged-port enable\b", raw):
            config_edged += 1

    live_commands = (
        ("stack", rf"{_d} stack", (r"^\s*MemberID\s+Role\s+MAC",), huawei_live.parse_stack),
        ("topology", rf"{_d} stack topology", (r"^\s*Stack Topology Type:",), huawei_live.parse_stack_topology),
        ("stack_configuration", rf"{_d} stack configuration", (r"^\s*Attribute Configuration:",), huawei_live.parse_stack_configuration),
        ("dual_active", rf"{_d} dual-active", (r"^\s*Stack domainID:",), huawei_live.parse_dual_active),
        ("stack_history", rf"{_d} stack troubleshooting history", (), huawei_live.parse_stack_history),
        ("stack_port_down", rf"{_d} stack-port link-state last-down-reason", (r"^\s*Stack-Port\s*:",), huawei_live.parse_stack_port_down),
        ("vlan_summary", rf"{_d} vlan summary", (r"^\s*Number of static VLAN",), huawei_live.parse_vlan_summary),
        ("vlan_table", rf"{_d} vlan", (r"^\s*The total number of vlans is",), huawei_live.parse_vlan_table),
        ("port_vlan", rf"{_d} port vlan", (r"^\s*Port\s+Link Type\s+PVID",), huawei_live.parse_port_vlan),
        ("lacp_brief", rf"{_d} lacp brief", (), huawei_live.parse_lacp_brief),
        ("arp_statistics", rf"{_d} arp statistics", (), huawei_live.parse_arp_statistics),
        ("licence", rf"{_d} license(?: verbose)?", (r"^\s*MainBoard:",), huawei_live.parse_license),
        ("stp_region", rf"{_d} stp region-configuration", (r"^\s*Operating configuration",), huawei_live.parse_stp_region),
    )
    live: dict[str, Any] = {}
    for key, pattern, headers, parser in live_commands:
        value = parser(_run(clean, pattern, headers) or [])
        if value:
            live[key] = value

    findings: list[dict[str, Any]] = []
    link_state = {str(item.get("name", "")).lower(): str(item.get("status", "")) for item in interfaces if item.get("status")}
    for code, severity, title, text, where, doc_key in huawei_live.rules(live) + huawei_live.trunk_rules(live, port_channels):
        _add(findings, code, severity, title, text, where=where, doc=doc_key)
    _huawei_rules(findings, version=version, devices=devices, stp=stp, trunks=trunks, top=top, config=bool(config), config_edged=config_edged, link_state=link_state,
                  config_lines=config)

    health["environment"]["rows"] = [{k: v for k, v in row.items() if k != "absent"} for row in devices]
    health["environment"]["problems"] = sum(1 for row in devices if row["problem"])
    health["lacp"] = _huawei_lacp_rows(trunks)
    health["live"] = live
    health["stack"] = {"display": huawei_live.stack_summary(live), "members": live.get("stack", []),
                       "ports": (live.get("topology") or {}).get("links", [])}
    if stp:
        ports = stp.get("ports", [])
        root = "this bridge (root)" if stp.get("is_root") else stp.get("root", "—")
        stp["display"] = {"mode": stp.get("mode", "—"), "bridge_id": stp.get("bridge", "—"), "root_bridge": root,
                          "bpdu_protection": stp.get("bpdu_protection", "—"), "topology_changes": stp.get("tc_count", "—"), "time_since_last_change": stp.get("last_tc", "—"),
                          "port_entries": f"{len(ports)} ({sum(1 for p in ports if p['state'] == 'forwarding')} forwarding, {sum(1 for p in ports if p['state'] != 'forwarding')} not)" if ports else "—"}
    health["stp"] = stp
    software = {k: v for k, v in version.items() if k != "members"}
    software["last_reload"] = version["members"][0]["startup"] if version.get("members") and version["members"][0].get("startup") else ""
    software["display"] = {"uptime": version.get("uptime", "—"), "startup_time": software["last_reload"] or "—", "release": version.get("version", "—"), "patch": version.get("patch", "—"),
                           "platform": version.get("platform", "—"), "memory": version.get("memory", "—"), "flash": version.get("flash", "—")}
    for member in version.get("members", []):
        software["display"][f"member_{member['member']}_{member['role'].lower()}"] = f"{member['model']}, uptime {member['uptime']}"
    health["software"] = software
    health["licence"]["detail"] = {"captured": False, "note": ""}

    missing = []
    for label, found, adds in (("display version", version_lines, "uptime per stack member, release and patch"), ("display device", device_lines, "slot, fan and power supply alarm state"),
                               ("display stp", stp_lines, "mode, root bridge, BPDU protection, topology changes"), ("display stp brief", stp_brief, "role and state of every spanning-tree port"),
                               ("display eth-trunk", trunk_lines, "state of every Eth-Trunk and its members")):
        if found is None:
            missing.append({"command": label, "adds": adds})
    if not config:
        missing.insert(0, {"command": "display current-configuration", "adds": "SNMP, telnet, FTP, syslog and NTP checks"})
    hints = {"lacp": "Not in this capture, or no Eth-Trunk exists. Add display eth-trunk.", "env": "Not in this capture. Add display device."}
    return _finish(health, findings, missing, bool(config), hints)


# =====================================================================================================================
# ArubaOS-Switch
# =====================================================================================================================

def _aruba_number(text: str) -> int | None:
    digits = re.sub(r"[^\d]", "", text or "")
    return int(digits) if digits else None


def _aruba_uptime_days(text: str) -> float:
    """``402 days`` / ``37 hours`` / ``12 mins`` / ``1 day 3 hours`` -> days as a number."""
    total = 0.0
    for amount, unit in re.findall(r"(\d+)\s*(day|hour|min|sec)", text or "", re.IGNORECASE):
        total += int(amount) * {"day": 1, "hour": 1 / 24, "min": 1 / 1440, "sec": 1 / 86400}[unit.lower()]
    return total


def parse_aruba_system(lines: list[str] | None) -> dict[str, Any]:
    """``show system``: two columns per line (``Up Time : 37 hours   Memory - Total : 361,771,520``)."""
    info: dict[str, Any] = {}
    for line in lines or []:
        match = re.search(r"Up Time\s*:\s*(.+?)(?:\s{2,}|$)", line)
        if match:
            info["uptime"] = match.group(1).strip()
            info["uptime_days"] = int(_aruba_uptime_days(info["uptime"]))
        match = re.search(r"CPU Util \(%\)\s*:\s*(\d+)", line)
        if match:
            info["cpu_percent"] = int(match.group(1))
            free = re.search(r"\bFree\s*:\s*([\d,]+)", line)       # the memory "Free" sits on the CPU line
            if free:
                info["memory_free"] = _aruba_number(free.group(1))
        match = re.search(r"Memory\s+-\s+Total\s*:\s*([\d,]+)", line)
        if match:
            info["memory_total"] = _aruba_number(match.group(1))
        match = re.search(r"Software revision\s*:\s*(\S+)", line)
        if match:
            info["version"] = match.group(1)
        match = re.search(r"ROM Version\s*:\s*(\S+)", line)
        if match:
            info["rom"] = match.group(1)
    if info.get("memory_total") and info.get("memory_free") is not None:
        info["memory_used_percent"] = round(100 * (info["memory_total"] - info["memory_free"]) / info["memory_total"])
    return info


def parse_aruba_flash(lines: list[str] | None) -> dict[str, Any]:
    info: dict[str, Any] = {}
    for line in lines or []:
        match = re.match(r"^(Primary|Secondary) Image\s*:\s*\d+\s+(\S+)\s+(\S+)", line.strip())
        if match:
            info[match.group(1).lower() + "_image"] = f"{match.group(3)} ({match.group(2)})"
        match = re.match(r"^Default Boot Image\s*:\s*(\S+)", line.strip())
        if match:
            info["default_boot"] = match.group(1)
    return info


def parse_aruba_stp(lines: list[str] | None) -> dict[str, Any]:
    info: dict[str, Any] = {}
    for line in lines or []:
        text = line.strip()
        match = re.match(r"^STP Enabled\s*:\s*(Yes|No)", text, re.IGNORECASE)
        if match:
            info["enabled"] = match.group(1).lower() == "yes"
        match = re.match(r"^(?:Force Version|Mode)\s*:\s*(\S+)", text, re.IGNORECASE)
        if match:
            info["mode"] = match.group(1)
        match = re.match(r"^Root\s+Priority\s*:\s*(\d+)", text, re.IGNORECASE)
        if match:
            info["root_priority"] = match.group(1)
    return info


def _aruba_rules(findings: list[dict[str, Any]], *, system: dict[str, Any], stp: dict[str, Any], top: list[str], config: bool) -> None:
    _uptime_finding(findings, system.get("uptime", ""), system.get("uptime_days") or 0, "", "ArubaOS-Switch")
    if stp.get("enabled") is False:
        _add(findings, "SW-STP-007", "medium", "Spanning tree is disabled",
             "`show spanning-tree` says STP Enabled: No. A cable looped between two ports of this switch (or two switches) is then not blocked and a broadcast storm follows; "
             "enable it with `spanning-tree` and set `spanning-tree bpdu-protection` on the edge ports.", doc="aruba_harden")
    if config:
        communities = [line for line in top if re.match(r'^snmp-server community\s+"?[^"\s]+"?', line)]
        unrestricted = [line for line in communities if re.search(r"\sunrestricted\s*$", line)]
        public = [line for line in communities if re.match(r'^snmp-server community\s+"?public"?(?:\s|$)', line, re.IGNORECASE)]
        if communities:
            severity = "high" if any(p in unrestricted for p in public) else ("medium" if unrestricted or public else "low")
            parts = []
            if public:
                parts.append('the default community "public" is configured' + (" with `unrestricted` access" if any(p in unrestricted for p in public) else ""))
            if unrestricted:
                parts.append(f"{len(unrestricted)} community string(s) are `unrestricted` (read-write)")
            _add(findings, "SW-SNMP-001", severity, f"{len(communities)} SNMP v1/v2c community string(s)" + (f", {len(unrestricted)} unrestricted" if unrestricted else ""),
                 ("; ".join(parts).capitalize() + ". " if parts else "") + "Community strings are shared secrets sent in clear text; `unrestricted` lets a holder change the configuration over SNMP. "
                 "Use SNMPv3 and restricted communities. Other string names are not shown here.", doc="aruba_harden")
        if not any(re.match(r"^(sntp server|timesync|ntp server)\b", line) for line in top):
            _add(findings, "SW-NTP-001", "medium", "No SNTP / NTP time source", "No `sntp server`, `ntp server` or `timesync` line: log timestamps depend on a clock nobody sets. Add `timesync sntp` and an `sntp server`.")
        if not any(re.match(r"^logging\s+\d", line) for line in top):
            _add(findings, "SW-LOG-001", "low", "No remote syslog server", "Logs stay in the switch buffer and are lost on reload. Add `logging <ip>` to a collector.")


def build_aruba(clean: list[str], *, interfaces: list[dict[str, Any]], port_channels: list[dict[str, Any]]) -> dict[str, Any]:
    health = _empty("ArubaOS-Switch", "aruba")
    system_lines = _run(clean, r"sh(?:ow)? system", (r"^\s*Status and Counters - General System Information",), lambda b: len(parse_aruba_system(b)))
    system = parse_aruba_system(system_lines)
    flash_lines = _run(clean, r"sh(?:ow)? flash(?: _detail)?", (r"^Image\s+Size \(bytes\)\s+Date\s+Version",))
    flash = parse_aruba_flash(flash_lines)
    stp_lines = _run(clean, show_tables.PATTERNS["stp"][0], (r"^\s*Multiple Spanning Tree \(MST\) Information|^\s*Spanning Tree Information",))
    stp = parse_aruba_stp(stp_lines)
    config = _running_config(clean)
    top = [line.strip() for line in config if line and not line[0].isspace() and not line.startswith(";")]

    findings: list[dict[str, Any]] = []
    _aruba_rules(findings, system=system, stp=stp, top=top, config=bool(config))

    if stp:
        health["stp"] = dict(stp, display={"spanning_tree": "enabled" if stp.get("enabled") else "disabled", "mode": stp.get("mode", "—"), "root_priority": stp.get("root_priority", "—")})
    software = {k: v for k, v in system.items() if k in ("uptime", "uptime_days", "version")}
    memory = f"{system['memory_used_percent']}% used of {system['memory_total']:,} bytes" if system.get("memory_used_percent") is not None else "—"
    software["display"] = {"uptime": system.get("uptime", "—"), "software_revision": system.get("version", "—"), "rom_version": system.get("rom", "—"),
                           "cpu_utilisation": f"{system['cpu_percent']}%" if "cpu_percent" in system else "—", "memory": memory,
                           "primary_image": flash.get("primary_image", "—"), "secondary_image": flash.get("secondary_image", "—"), "default_boot_image": flash.get("default_boot", "—")}
    health["software"] = software
    health["licence"]["detail"] = {"captured": False, "note": ""}

    missing = []
    for label, found, adds in (("show system", system_lines, "uptime, CPU and memory"), ("show flash", flash_lines, "primary and secondary image versions"),
                               ("show spanning-tree", stp_lines, "whether spanning tree is on and which mode")):
        if found is None:
            missing.append({"command": label, "adds": adds})
    if not config:
        missing.insert(0, {"command": "show running-config", "adds": "SNMP, SNTP and syslog checks"})
    hints = {"lacp": "Link-aggregation state is not read for ArubaOS-Switch yet.", "env": "Fan, power supply and temperature output is not read for ArubaOS-Switch yet."}
    return _finish(health, findings, missing, bool(config), hints)


# ---------------------------------------------------------------- entry point

def build(clean: list[str], family: str, *, interfaces: list[dict[str, Any]], port_channels: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Health for ``family`` ("nxos", "huawei", "aruba"); None for a family this module does not handle."""
    builders = {"nxos": build_nxos, "huawei": build_huawei, "aruba": build_aruba}
    builder = builders.get(family)
    return builder(clean, interfaces=interfaces, port_channels=port_channels) if builder else None
