"""Nexus show commands that no other module reads: system resources, vPC statistics, LACP counters and keys, port-channel load-balance /
traffic / usage.

Every layout here was read from real NX-OS 9000 captures (a vPC pair member and a standalone edge switch).  Each parser returns plain rows;
``analyse`` turns them into the extra tables the Single Device page appends to its Health, Port-Channel and vPC / M-LAG tabs, plus the few findings
the numbers justify.  A command that was not captured, or that the device rejected (``% Invalid command`` = the feature is not enabled), adds nothing.

Findings use only what the device itself says: the ``Current memory status`` line, error counters that are not zero, a vPC keep-alive that received
nothing.  No threshold of this module's own is applied to CPU or memory.

Sources (pages opened while writing this module):

* Cisco, Nexus Memory Issues (the memory line of ``show system resources`` and the alert thresholds):
  https://community.cisco.com/t5/networking-knowledge-base/nexus-memory-issues/ta-p/3124960
* Cisco, Understand and Configure Nexus 9000 vPC with Best Practices:
  https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html
* Cisco, Troubleshoot Link Aggregation Control Protocol (LACP) on Nexus:
  https://www.cisco.com/c/en/us/support/docs/lan-switching/link-aggregation-control-protocol-lacp-8023ad/221051-troubleshoot-link-aggregation-control-pr.html
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text

DOCS = {
    "memory": ("Cisco Community - Nexus Memory Issues", "https://community.cisco.com/t5/networking-knowledge-base/nexus-memory-issues/ta-p/3124960"),
    "vpc": ("Cisco - Understand and Configure Nexus 9000 vPC with Best Practices",
            "https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html"),
    "lacp": ("Cisco - Troubleshoot Link Aggregation Control Protocol (LACP) on Nexus",
             "https://www.cisco.com/c/en/us/support/docs/lan-switching/link-aggregation-control-protocol-lacp-8023ad/221051-troubleshoot-link-aggregation-control-pr.html"),
}

_ERROR = re.compile(r"^\s*(?:%|\^\s*$|invalid (?:input|command)|error:)", re.IGNORECASE)


def _runs(clean: list[str], pattern: str) -> list[list[str]]:
    """Output of every run of a command, without runs the device rejected."""
    out = []
    for block in capture_text.command_outputs(clean, [pattern]):
        if block and not any(_ERROR.match(line) for line in block[:3]):
            out.append(block)
    return out


def _fullest(clean: list[str], pattern: str, rows) -> list[str]:
    """The run of the command that gave the most rows (the same command may be pasted twice)."""
    best: list[str] = []
    best_rows = -1
    for block in _runs(clean, pattern):
        count = rows(block)
        if count > best_rows:
            best, best_rows = block, count
    return best


def _mac(text: str) -> str:
    """NX-OS prints LACP system ids without zero padding (``02-be-f3-a4-84-1``): ``02be.f3a4.8401``."""
    parts = [part.zfill(2) for part in re.split(r"[-:]", text.strip())]
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9a-fA-F]{2}", part) for part in parts):
        return text.strip()
    digits = "".join(parts).lower()
    return f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"


def _kib(value: int | None) -> str:
    if value is None:
        return "—"
    if value >= 1024 * 1024:
        return f"{value / 1024 / 1024:.2f} GiB"
    return f"{value / 1024:.0f} MiB"


# ------------------------------------------------------------------ show system resources

_LOAD = re.compile(r"Load average:\s*1 minute:\s*([\d.]+)\s+5 minutes:\s*([\d.]+)\s+15 minutes:\s*([\d.]+)", re.IGNORECASE)
_PROCESSES = re.compile(r"Processes\s*:\s*(\d+) total,\s*(\d+) running", re.IGNORECASE)
_CPU = re.compile(r"^(CPU\d*) states\s*:\s*([\d.]+)% user,\s*([\d.]+)% kernel,\s*([\d.]+)% idle", re.IGNORECASE)
_MEMORY = re.compile(r"Memory usage:\s*(\d+)K total,\s*(\d+)K used,\s*(\d+)K free", re.IGNORECASE)
_KERNEL = re.compile(r"Kernel (buffers|cached)\s*:\s*(\d+)K", re.IGNORECASE)


def parse_system_resources(lines: list[str]) -> dict[str, Any]:
    """Load, processes, CPU (total and per core) and memory of ``show system resources``; ``{}`` when nothing matched."""
    out: dict[str, Any] = {"cores": []}
    for raw in lines:
        text = raw.strip()
        found = _LOAD.search(text)
        if found:
            out["load"] = [float(found.group(i)) for i in (1, 2, 3)]
            continue
        found = _PROCESSES.search(text)
        if found:
            out["processes"] = {"total": int(found.group(1)), "running": int(found.group(2))}
            continue
        found = _CPU.match(text)
        if found:
            user, kernel, idle = (float(found.group(i)) for i in (2, 3, 4))
            row = {"name": found.group(1).upper(), "user": user, "kernel": kernel, "idle": idle, "busy": round(100 - idle, 2)}
            if row["name"] == "CPU":
                out["cpu"] = row
            else:
                out["cores"].append(row)
            continue
        found = _MEMORY.search(text)
        if found:
            total, used, free = (int(found.group(i)) for i in (1, 2, 3))
            out["memory"] = {"total_kb": total, "used_kb": used, "free_kb": free, "used_pct": round(100 * used / total, 1) if total else None}
            continue
        found = _KERNEL.match(text)
        if found:
            out.setdefault("kernel", {})[found.group(1).lower()] = int(found.group(2))
            continue
        found = re.match(r"Current memory status:\s*(.+)$", text, re.IGNORECASE)
        if found:
            out["memory_status"] = found.group(1).strip()
    return out if any(key in out for key in ("load", "cpu", "memory", "processes")) else {}


def resources_tables(data: dict[str, Any]) -> list[dict[str, Any]]:
    if not data:
        return []
    rows: list[dict[str, Any]] = []
    memory = data.get("memory")
    if memory:
        kernel = data.get("kernel") or {}
        extra = ", ".join(f"kernel {name} {_kib(kernel[name])}" for name in ("buffers", "cached") if name in kernel)
        rows.append({"metric": "Memory", "value": f"{_kib(memory['used_kb'])} used of {_kib(memory['total_kb'])} ({memory['used_pct']}%)",
                     "state": data.get("memory_status", ""), "detail": f"{_kib(memory['free_kb'])} free" + (f"; {extra}" if extra else "")})
    cpu = data.get("cpu")
    if cpu:
        rows.append({"metric": "CPU (all cores)", "value": f"{cpu['busy']:.1f}% busy ({cpu['user']:.1f}% user, {cpu['kernel']:.1f}% kernel)", "state": "", "detail": f"{cpu['idle']:.1f}% idle"})
    cores = data.get("cores") or []
    if cores:
        hottest = max(cores, key=lambda core: core["busy"])
        rows.append({"metric": "Busiest core", "value": f"{hottest['name']}: {hottest['busy']:.1f}% busy ({hottest['user']:.1f}% user, {hottest['kernel']:.1f}% kernel)", "state": "",
                     "detail": f"{len(cores)} cores in total; one sample, not an average"})
    if data.get("load"):
        one, five, fifteen = data["load"]
        rows.append({"metric": "Load average", "value": f"{one:.2f} / {five:.2f} / {fifteen:.2f}", "state": "", "detail": "1, 5 and 15 minutes" + (f"; {len(cores)} CPU cores" if cores else "")})
    if data.get("processes"):
        rows.append({"metric": "Processes", "value": f"{data['processes']['total']} total, {data['processes']['running']} running", "state": "", "detail": ""})
    tables = [{"tab": "health", "id": "nx-resources", "title": "CPU and memory", "hint": "From show system resources. A single sample taken when the command ran. State is the Current memory status line the switch prints.",
               "columns": [{"key": "metric", "label": "Metric"}, {"key": "value", "label": "Value"}, {"key": "state", "label": "State", "status": True}, {"key": "detail", "label": "Detail"}],
               "rows": rows}]
    if cores:
        tables.append({"tab": "health", "id": "nx-cores", "title": "CPU cores", "hint": "Share of each core's time since the last sample.",
                       "columns": [{"key": "name", "label": "Core"}, {"key": "user", "label": "User %"}, {"key": "kernel", "label": "Kernel %"}, {"key": "idle", "label": "Idle %"}, {"key": "busy", "label": "Busy %"}],
                       "rows": [{**core, "user": f"{core['user']:.2f}", "kernel": f"{core['kernel']:.2f}", "idle": f"{core['idle']:.2f}", "busy": f"{core['busy']:.2f}"} for core in cores]})
    return tables


# ------------------------------------------------------------------ show vpc statistics

_ERROR_COUNTERS = ("runts", "giants", "crc", "no buffer", "input error", "short frame", "overrun", "underrun", "ignored", "watchdog", "bad etype drop", "bad proto drop", "if down drop",
                   "input with dribble", "input discard", "stomped crc", "output error", "collision", "deferred", "late collision", "lost carrier", "no carrier", "babble", "output discard")


def parse_vpc_peer_link(lines: list[str]) -> dict[str, Any]:
    """``show vpc statistics peer-link`` prints the interface counters of the peer-link port-channel."""
    out: dict[str, Any] = {"errors": {}}
    five_minute = False
    for raw in lines:
        text = raw.strip()
        found = re.match(r"^(\S+) is (up|down|administratively down)", text)
        if found and "interface" not in out:
            out["interface"], out["state"] = found.group(1), found.group(2)
            continue
        found = re.match(r"^MTU (\d+) bytes, BW (\d+) Kbit", text)
        if found:
            out["mtu"], out["bandwidth_kbit"] = int(found.group(1)), int(found.group(2))
            continue
        found = re.match(r"^(full|half)-duplex,\s*(.+?)(?:,|$)", text)
        if found:
            out["speed"] = found.group(2).strip()
            continue
        found = re.match(r"^Members in this channel:\s*(.+)$", text)
        if found:
            out["members"] = [part.strip() for part in found.group(1).split(",") if part.strip()]
            continue
        found = re.match(r"^Load-Interval #(\d+):\s*(\d+) (second|minute)", text)
        if found:
            five_minute = found.group(3) == "minute"
            continue
        found = re.match(r"^input rate (\S+ \S+), (\d+) pps; output rate (\S+ \S+), (\d+) pps", text)
        if found and five_minute:
            out["rate_in"], out["rate_out"] = f"{found.group(1)} ({found.group(2)} pps)", f"{found.group(3)} ({found.group(4)} pps)"
            continue
        found = re.match(r"^(\d+) interface resets", text)
        if found:
            out["resets"] = int(found.group(1))
            continue
        found = re.match(r"^(\d+) input packets\s+(\d+) bytes", text)
        if found:
            out["rx_packets"] = int(found.group(1))
            continue
        found = re.match(r"^(\d+) output packets\s+(\d+) bytes", text)
        if found:
            out["tx_packets"] = int(found.group(1))
            continue
        for count, label in re.findall(r"(\d+) ([A-Za-z][A-Za-z ]*?)(?=\s{2,}|$)", text):
            if label.strip().lower() in _ERROR_COUNTERS and int(count):
                out["errors"][label.strip()] = out["errors"].get(label.strip(), 0) + int(count)
    return out if "interface" in out else {}


def parse_vpc_keepalive_statistics(lines: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for raw in lines:
        for key, pattern in (("tx", r"peer-keepalive tx count:\s*(\d+)"), ("rx", r"peer-keepalive rx count:\s*(\d+)"),
                             ("interval_ms", r"average interval for peer rx:\s*(\d+)"), ("state_changes", r"Count of peer state changes:\s*(\d+)")):
            found = re.search(pattern, raw, re.IGNORECASE)
            if found:
                out[key] = int(found.group(1))
    return out if {"tx", "rx"} <= set(out) else {}


# ------------------------------------------------------------------ port-channel commands

def parse_load_balance(lines: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    scope = ""
    for raw in lines:
        text = raw.strip()
        if re.match(r"^System config:", text, re.IGNORECASE):
            scope = "System"
            rows.append({"scope": scope, "non_ip": "", "ip": "", "rotate": ""})
            continue
        found = re.match(r"^(Module \d+):", text)
        if found:
            scope = found.group(1)
            rows.append({"scope": scope, "non_ip": "", "ip": "", "rotate": ""})
            continue
        if not rows:
            continue
        found = re.match(r"^Non-IP:\s*(.+)$", text)
        if found:
            rows[-1]["non_ip"] = found.group(1).strip()
            continue
        found = re.match(r"^IP:\s*(.+?)(?:\s+rotate\s+(\d+))?$", text)
        if found:
            rows[-1]["ip"], rows[-1]["rotate"] = found.group(1).strip(), found.group(2) or ""
    return [row for row in rows if row["non_ip"] or row["ip"]]


def parse_port_channel_usage(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    key = ""
    for raw in lines:
        text = raw.strip()
        found = re.match(r"^Total (\d+) port-channel numbers used", text, re.IGNORECASE)
        if found:
            out["total"] = found.group(1)
            continue
        found = re.match(r"^(Used|Unused)\s*:\s*(.*)$", text)
        if found:
            key = found.group(1).lower()
            out[key] = found.group(2).strip()
        elif key and text and not text.startswith("="):
            out[key] = f"{out[key]} {text}".strip()
    return out


_PERCENT = r"([\d.]+)%"


def parse_port_channel_traffic(lines: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in lines:
        found = re.match(rf"^\s*(\d+)\s+(\S+)\s+{_PERCENT}\s+{_PERCENT}\s+{_PERCENT}\s+{_PERCENT}\s+{_PERCENT}\s+{_PERCENT}\s*$", raw)
        if found:
            rows.append({"channel": int(found.group(1)), "member": found.group(2), "rx_ucast": found.group(3), "tx_ucast": found.group(4), "rx_mcast": found.group(5),
                         "tx_mcast": found.group(6), "rx_bcast": found.group(7), "tx_bcast": found.group(8)})
    sizes: dict[int, int] = {}
    for row in rows:
        sizes[row["channel"]] = sizes.get(row["channel"], 0) + 1
    for row in rows:
        row["members"] = sizes[row["channel"]]
    return rows


def parse_lacp_counters(lines: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    channel = ""
    for raw in lines:
        text = raw.strip()
        if re.fullmatch(r"port-channel\d+", text, re.IGNORECASE):
            channel = text
            continue
        found = re.match(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$", text)
        if found and channel:
            rows.append({"channel": channel, "member": found.group(1), "sent": int(found.group(2)), "received": int(found.group(3)), "marker_received": int(found.group(4)),
                         "marker_sent": int(found.group(5)), "errors": int(found.group(6))})
    return rows


def parse_lacp_port_channels(lines: list[str]) -> list[dict[str, Any]]:
    """``show lacp port-channel``: one block per bundle with the local and partner system id and the keys."""
    rows: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    partner_seen = False
    for raw in lines:
        text = raw.strip()
        if re.fullmatch(r"(?:port-channel|Po)\d+", text, re.IGNORECASE):
            number = re.sub(r"\D", "", text)
            cur = {"channel": f"Po{number}", "local": "", "partner": "", "admin_key": "", "oper_key": "", "partner_key": "", "aggregate": "", "members": []}
            rows.append(cur)
            partner_seen = False
            continue
        if cur is None:
            continue
        found = re.match(r"^(Local|Partner) System Identifier=0x([0-9a-fA-F]+),(\S+)$", text)
        if found:
            priority = int(found.group(2), 16)
            value = f"priority {priority} · {_mac(found.group(3))}"
            cur["local" if found.group(1) == "Local" else "partner"] = value
            partner_seen = found.group(1) == "Partner"
            continue
        found = re.match(r"^(Admin key|Operational key)=(\S+)$", text)
        if found:
            if found.group(1) == "Admin key":
                cur["admin_key"] = found.group(2)
            elif partner_seen:
                cur["partner_key"] = found.group(2)
            else:
                cur["oper_key"] = found.group(2)
            continue
        found = re.match(r"^Aggregate or individual=(\d+)$", text)
        if found:
            cur["aggregate"] = "aggregate" if found.group(1) == "1" else "individual"
            continue
        found = re.match(r"^Member Port List=(.*)$", text)
        if found:
            cur["members"] = found.group(1).split()
    return rows


# ------------------------------------------------------------------ show vpc (live state of the vPC / M-LAG tab)

_VPC_SUMMARY_FIELDS = {
    "vpc domain id": "domain_id", "peer status": "peer_status", "vpc keep-alive status": "keepalive_status", "configuration consistency status": "consistency_status",
    "per-vlan consistency status": "per_vlan_consistency", "type-2 consistency status": "type2_consistency", "vpc role": "role", "number of vpcs configured": "vpc_count",
    "peer gateway": "peer_gateway", "dual-active excluded vlans": "dual_active_excluded_vlans", "graceful consistency check": "graceful_consistency_check",
    "auto-recovery status": "auto_recovery", "delay-restore status": "delay_restore", "delay-restore svi status": "delay_restore_svi", "operational layer3 peer-router": "layer3_peer_router",
}


def parse_vpc_status(lines: list[str]) -> dict[str, Any]:
    """``show vpc`` / ``show vpc brief`` of NX-OS: the domain fields, the peer-link row and every vPC row.

    The vPC table is cut at the column offsets of its header, because a long Consistency or Reason text wraps onto a second line
    (``Not`` / ``Applicable``, ``Consistency Check Not`` / ``Performed``). A status of ``down*`` means the local vPC is down and traffic is
    forwarded over the peer-link (the legend of the command says so).
    """
    fields: dict[str, str] = {}
    peer_link: dict[str, str] = {}
    members: list[dict[str, Any]] = []
    section = ""
    columns: dict[str, int] = {}
    for raw in lines:
        text = raw.strip()
        if not text:
            continue
        found = re.match(r"^([A-Za-z][A-Za-z0-9 /\-]+?)\s*:\s*(.+)$", text)
        if found and found.group(1).strip().lower() in _VPC_SUMMARY_FIELDS and section == "":
            fields[_VPC_SUMMARY_FIELDS[found.group(1).strip().lower()]] = found.group(2).strip()
            continue
        if re.match(r"^vPC Peer-link status", text, re.IGNORECASE):
            section = "peerlink"
            continue
        if re.match(r"^vPC status", text, re.IGNORECASE):
            section = "vpcs"
            continue
        if text.startswith("Please check"):
            section = "end"
            continue
        if section == "peerlink":
            found = re.match(r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S.*)$", text)
            if found and not text.startswith("--"):
                peer_link = {"id": found.group(1), "port": found.group(2), "status": found.group(3), "vlans": found.group(4).strip()}
        elif section == "vpcs":
            if re.match(r"^Id\s+Port\s+Status\s+Consistency\s+Reason\s+Active vlans", text, re.IGNORECASE):
                columns = {name: raw.index(name) for name in ("Id", "Port", "Status", "Consistency", "Reason", "Active vlans")}
                continue
            if not columns or text.startswith("--"):
                continue
            starts = [columns[name] for name in ("Id", "Port", "Status", "Consistency", "Reason", "Active vlans")]

            def cut(index: int) -> str:
                end = starts[index + 1] if index + 1 < len(starts) else len(raw)
                return raw[starts[index]:end].strip() if starts[index] < len(raw) else ""
            if re.match(r"^\d+\s", text):
                members.append({"id": cut(0), "port": cut(1), "status": cut(2), "consistency": cut(3), "reason": cut(4), "vlans": cut(5)})
            elif members:
                members[-1]["consistency"] = f"{members[-1]['consistency']} {cut(3)}".strip()
                members[-1]["reason"] = f"{members[-1]['reason']} {cut(4)}".strip()
    return {"fields": fields, "peer_link": peer_link, "members": members}


def refine_vpc(vpc_mlag: dict[str, Any], clean: list[str]) -> dict[str, Any]:
    """Replace the vPC rows of the generic reader by the NX-OS reader's rows when the capture has a live ``show vpc``.

    The generic reader misses ``down*`` rows and the wrapped Consistency / Reason text, and it is fed the raw capture, where the
    pasted command list is found before the real output."""
    parsed = parse_vpc_status(_fullest(clean, r"sh(?:ow)? vpc(?: brief)?", lambda b: len(parse_vpc_status(b)["members"]) * 100 + len(parse_vpc_status(b)["fields"])))
    if not parsed["members"] and not parsed["fields"]:
        return vpc_mlag
    summary = dict(vpc_mlag.get("summary") or {})
    for key, value in parsed["fields"].items():
        summary[key] = value
    link = parsed["peer_link"]
    if link:
        summary["peer_link"] = link["port"]
        summary["peer_link_status"] = link["status"]
        summary["peer_link_vlans"] = link["vlans"]
    members: list[dict[str, Any]] = []
    for row in parsed["members"]:
        via_peer_link = row["status"].endswith("*")
        reason = row["reason"]
        consistency = row["consistency"]
        text = consistency if not reason or reason.lower() == consistency.lower() else f"{consistency} ({reason})"
        members.append({"id": row["id"], "port": row["port"], "status": row["status"].rstrip("*").lower(), "consistency": text,
                        "vlans": "" if row["vlans"] == "-" else row["vlans"], "via_peer_link": via_peer_link})
    down_via_link = sum(1 for row in members if row["via_peer_link"])
    if down_via_link:
        summary["vpcs_down_via_peer_link"] = f"{down_via_link} (the local vPC is down and traffic is forwarded over the peer-link)"
    return {"summary": summary, "members": members or list(vpc_mlag.get("members") or [])}


# ------------------------------------------------------------------ findings and tables

def _finding(code: str, severity: str, title: str, text: str, where: str, doc: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"code": code, "severity": severity, "level": "warning" if severity in ("high", "medium") else "info", "title": title, "text": text, "where": where}
    ref = DOCS.get(doc)
    if ref:
        entry["doc"] = {"title": ref[0], "url": ref[1]}
    return entry


def analyse(clean: list[str]) -> dict[str, Any]:
    """``{"tables": [...], "counts": {key: rows}, "findings": [...]}`` for the Nexus-only commands found in ``clean``."""
    tables: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    findings: list[dict[str, Any]] = []

    resources = parse_system_resources(_fullest(clean, r"sh(?:ow)? system resources", lambda b: len(parse_system_resources(b))))
    if resources:
        tables += resources_tables(resources)
        counts["sysres"] = 1 + len(resources.get("cores") or [])
        status = resources.get("memory_status", "")
        if status and status.upper() != "OK":
            memory = resources.get("memory") or {}
            findings.append(_finding(
                "SW-NX-MEM-001", "high" if re.search(r"severe|critical|major", status, re.IGNORECASE) else "medium", f"Memory status is {status}",
                f"`show system resources` says Current memory status: {status}" + (f" with {memory.get('used_pct')}% of memory used" if memory.get("used_pct") is not None else "")
                + ". NX-OS raises this status when memory use crosses its alert thresholds (the defaults are 85% minor, 90% critical and 95% severe on current releases and can be changed with system memory-thresholds). "
                "Check `show system internal memory-alert-log` and which process holds the memory (`show processes memory`).", "show system resources", "memory"))

    peer_link = parse_vpc_peer_link(_fullest(clean, r"sh(?:ow)? vpc statistics peer-link", lambda b: len(parse_vpc_peer_link(b))))
    if peer_link:
        errors = peer_link["errors"]
        rows = [{"interface": peer_link["interface"], "state": peer_link.get("state", ""), "members": ", ".join(peer_link.get("members") or []) or "—", "speed": peer_link.get("speed", "—"),
                 "mtu": peer_link.get("mtu", "—"), "rate_in": peer_link.get("rate_in", "—"), "rate_out": peer_link.get("rate_out", "—"),
                 "errors": ", ".join(f"{label} {count}" for label, count in errors.items()) or "none", "resets": peer_link.get("resets", "—")}]
        tables.append({"tab": "vpcmlag", "id": "nx-vpc-peerlink", "title": "vPC peer-link counters",
                       "hint": "From show vpc statistics peer-link: the interface counters of the peer-link port-channel. Rates are the 5-minute averages. Errors lists every error or discard counter that is not zero.",
                       "columns": [{"key": "interface", "label": "Peer-link"}, {"key": "state", "label": "State", "status": True}, {"key": "members", "label": "Members"}, {"key": "speed", "label": "Speed"},
                                   {"key": "mtu", "label": "MTU"}, {"key": "rate_in", "label": "Input (5 min)"}, {"key": "rate_out", "label": "Output (5 min)"},
                                   {"key": "errors", "label": "Errors / discards"}, {"key": "resets", "label": "Resets"}], "rows": rows})
        counts["vpc_link"] = 1
        if errors:
            findings.append(_finding(
                "SW-NX-VPC-010", "medium", f"vPC peer-link {peer_link['interface']} shows error or discard counters",
                "show vpc statistics peer-link: " + ", ".join(f"{label} {count}" for label, count in errors.items()) + ". The peer-link carries vPC control traffic and orphan-port traffic; "
                "errors on it (physical layer, MTU or buffer drops) put the vPC consistency checks and the hardware synchronisation of the two peers at risk. Check the member optics and cabling with `show interface counters errors`.",
                peer_link["interface"], "vpc"))

    keepalive = parse_vpc_keepalive_statistics(_fullest(clean, r"sh(?:ow)? vpc statistics peer-keepalive", lambda b: len(parse_vpc_keepalive_statistics(b))))
    if keepalive:
        tables.append({"tab": "vpcmlag", "id": "nx-vpc-keepalive", "title": "vPC peer-keepalive statistics",
                       "hint": "From show vpc statistics peer-keepalive. The keep-alive messages travel outside the peer-link, over the keep-alive link or the management VRF.",
                       "columns": [{"key": "tx", "label": "Sent"}, {"key": "rx", "label": "Received"}, {"key": "interval", "label": "Average interval for peer rx (ms)"}, {"key": "changes", "label": "Peer state changes"}],
                       "rows": [{"tx": keepalive["tx"], "rx": keepalive["rx"], "interval": keepalive.get("interval_ms", "—"), "changes": keepalive.get("state_changes", "—")}]})
        counts["vpc_ka"] = 1
        if keepalive["tx"] and not keepalive["rx"]:
            findings.append(_finding("SW-NX-VPC-011", "high", "vPC keep-alive: messages are sent but none were received",
                                     f"show vpc statistics peer-keepalive: {keepalive['tx']} sent, 0 received. The peer does not answer on the keep-alive link; with the peer-link also down both peers would act as primary.",
                                     "peer-keepalive", "vpc"))
        elif keepalive.get("state_changes"):
            findings.append(_finding("SW-NX-VPC-012", "low", f"vPC peer state changed {keepalive['state_changes']} time(s)",
                                     f"show vpc statistics peer-keepalive: Count of peer state changes {keepalive['state_changes']} since the statistics were last cleared or the switch booted. "
                                     "Each change is a keep-alive loss or recovery; the Logs tab shows when they happened.", "peer-keepalive", "vpc"))

    balance = parse_load_balance(_fullest(clean, r"sh(?:ow)? port-channel load-balance", lambda b: len(parse_load_balance(b))))
    if balance:
        tables.append({"tab": "portchannels", "id": "nx-pc-balance", "title": "Port-channel load balancing",
                       "hint": "From show port-channel load-balance: which header fields choose the member link of a bundle. Each end of a bundle chooses for its own outgoing traffic.",
                       "columns": [{"key": "scope", "label": "Scope"}, {"key": "non_ip", "label": "Non-IP traffic"}, {"key": "ip", "label": "IP traffic"}, {"key": "rotate", "label": "Rotate"}], "rows": balance})
        counts["pc_balance"] = len(balance)

    usage = parse_port_channel_usage(_fullest(clean, r"sh(?:ow)? port-channel usage", lambda b: len(parse_port_channel_usage(b))))
    if usage.get("total"):
        tables.append({"tab": "portchannels", "id": "nx-pc-usage", "title": "Port-channel numbers in use",
                       "hint": "From show port-channel usage.", "columns": [{"key": "total", "label": "Port-channels"}, {"key": "used", "label": "Numbers in use"}],
                       "rows": [{"total": usage["total"], "used": usage.get("used", "")}]})
        counts["pc_usage"] = 1

    traffic = parse_port_channel_traffic(_fullest(clean, r"sh(?:ow)? port-channel traffic", lambda b: len(parse_port_channel_traffic(b))))
    if traffic:
        tables.append({"tab": "portchannels", "id": "nx-pc-traffic", "title": "Traffic share per member",
                       "hint": "From show port-channel traffic: each member's share of its bundle's traffic since the member counters were last cleared. A bundle with one member always shows 100%.",
                       "columns": [{"key": "channel", "label": "Port-channel"}, {"key": "member", "label": "Member"}, {"key": "members", "label": "Members"}, {"key": "rx_ucast", "label": "Rx unicast"},
                                   {"key": "tx_ucast", "label": "Tx unicast"}, {"key": "rx_mcast", "label": "Rx multicast"}, {"key": "tx_mcast", "label": "Tx multicast"},
                                   {"key": "rx_bcast", "label": "Rx broadcast"}, {"key": "tx_bcast", "label": "Tx broadcast"}], "rows": traffic})
        counts["pc_traffic"] = len(traffic)

    lacp = parse_lacp_counters(_fullest(clean, r"sh(?:ow)? lacp counters", lambda b: len(parse_lacp_counters(b))))
    if lacp:
        tables.append({"tab": "portchannels", "id": "nx-lacp-counters", "title": "LACP counters",
                       "hint": "From show lacp counters: LACPDUs sent and received per member since the counters were last cleared. A member that sends but never receives has a silent partner. The two ends may use different LACP rates, so sent and received need not be equal.",
                       "columns": [{"key": "channel", "label": "Port-channel"}, {"key": "member", "label": "Member"}, {"key": "sent", "label": "LACPDUs sent"}, {"key": "received", "label": "LACPDUs received"},
                                   {"key": "marker_received", "label": "Marker received"}, {"key": "marker_sent", "label": "Marker response sent"}, {"key": "errors", "label": "Packet errors"}], "rows": lacp})
        counts["lacp_counters"] = len(lacp)
        bad = [row for row in lacp if row["errors"]]
        if bad:
            findings.append(_finding("SW-NX-LACP-010", "medium", f"LACP packet errors on {len(bad)} member port(s)",
                                     "show lacp counters: " + ", ".join(f"{row['member']} {row['errors']}" for row in bad[:8]) + (" ..." if len(bad) > 8 else "")
                                     + ". A packet error is an LACPDU the switch could not accept. Check the partner's LACP configuration and the cabling.", ", ".join(row["member"] for row in bad[:4]), "lacp"))
        silent = [row for row in lacp if row["sent"] >= 100 and row["received"] == 0]
        if silent:
            findings.append(_finding("SW-NX-LACP-011", "high", f"{len(silent)} LACP member port(s) send LACPDUs but receive none",
                                     "show lacp counters: " + ", ".join(f"{row['member']} sent {row['sent']}, received 0" for row in silent[:8])
                                     + ". The partner is not sending LACPDUs on these links (not in LACP mode, wrong port, or a one-way link), so the port cannot join the bundle.",
                                     ", ".join(row["member"] for row in silent[:4]), "lacp"))

    keys = parse_lacp_port_channels(_fullest(clean, r"sh(?:ow)? lacp port-channel(?: \S+)?", lambda b: len(parse_lacp_port_channels(b))))
    if keys:
        tables.append({"tab": "portchannels", "id": "nx-lacp-keys", "title": "LACP system ids and keys",
                       "hint": "From show lacp port-channel: the local and partner system id (priority and MAC) and the operational keys of every bundle. Ports bundle only when their keys match.",
                       "columns": [{"key": "channel", "label": "Port-channel"}, {"key": "local", "label": "Local system"}, {"key": "partner", "label": "Partner system"}, {"key": "admin_key", "label": "Admin key"},
                                   {"key": "oper_key", "label": "Operational key"}, {"key": "partner_key", "label": "Partner key"}, {"key": "aggregate", "label": "Mode"}, {"key": "members_text", "label": "Members"}],
                       "rows": [{**row, "members_text": ", ".join(row["members"]) or "—"} for row in keys]})
        counts["lacp_keys"] = len(keys)
    return {"tables": tables, "counts": counts, "findings": findings}
