"""Live state of a Cisco IOS / IOS XE router or switch: CPU, memory, interface queue drops, BGP neighbors, route counts.

The Switch Analyzer used to list these commands as "recognised but not parsed":

* ``show processes cpu sorted``     - CPU load now (5 s / 1 min / 5 min) and the busiest processes
* ``show processes memory sorted``  - the memory pools (Processor, lsmpi_io ...) and the processes that hold the most
* ``show interfaces summary``       - input / output queue drops and throttles per interface
* ``show ip bgp summary``           - the BGP neighbors, their state and the prefixes they sent
* ``show ip route summary``         - routes per source (connected, static, ospf, bgp ...)

``analyse(clean)`` returns ``{"tables": [...], "counts": {...}, "findings": [...]}`` in the shape ``nxos_state.analyse`` uses, so the
Health tab shows them the same way.  Every rule says what the counter means and what it does not.
References: https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-aggregation-services-routers/212646-troubleshoot-high-cpu-on-asr1000-series.html
(CPU), https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xe-17/225227-troubleshoot-memory-issues-in-ios-xe.html (memory),
https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-ios-xe-sd-wan/224129-troubleshoot-interface-packet-drops-in.html (IQD / OQD),
https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/220604-understand-basic-bgp-troubleshoot.html (BGP states).
"""

from __future__ import annotations

import re
from typing import Any

from .nxos_state import _fullest, _runs

DOCS = {
    "cpu": ("Cisco - Troubleshoot High CPU on ASR1000 Series Router (show processes cpu sorted, platform and process view)",
            "https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-aggregation-services-routers/212646-troubleshoot-high-cpu-on-asr1000-series.html"),
    "memory": ("Cisco - Troubleshoot Memory Issues in IOS XE", "https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xe-17/225227-troubleshoot-memory-issues-in-ios-xe.html"),
    "drops": ("Cisco - Troubleshoot Interface Packet Drops in IOS XE Routers", "https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-ios-xe-sd-wan/224129-troubleshoot-interface-packet-drops-in.html"),
    "bgp": ("Cisco - Understand Basic BGP Troubleshoot", "https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/220604-understand-basic-bgp-troubleshoot.html"),
}

CPU_HIGH = 80          # five-minute average, percent
MEMORY_HIGH = 90       # Processor pool used, percent
MEMORY_WATCH = 80
DROPS_MEDIUM = 1000    # drops on one interface since the counters were cleared
TOP = 5

_NEIGHBOR_DOWN = ("idle", "active", "connect", "opensent", "openconfirm")


def _finding(code: str, severity: str, title: str, text: str, where: str, doc: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"code": code, "severity": severity, "level": "warning" if severity in ("high", "medium") else "info", "title": title, "text": text, "where": where}
    ref = DOCS.get(doc)
    if ref:
        entry["doc"] = {"title": ref[0], "url": ref[1]}
    return entry


def _table(table_id: str, title: str, hint: str, columns: list[tuple[str, str]], rows: list[dict[str, Any]], status: str = "") -> dict[str, Any]:
    return {"tab": "health", "id": table_id, "title": title, "hint": hint,
            "columns": [{"key": key, "label": label, **({"status": True} if key == status else {})} for key, label in columns], "rows": rows}


# ------------------------------------------------------------------ show processes cpu sorted

_CPU_HEAD = re.compile(r"CPU utilization for five seconds:\s*(\d+)%(?:/(\d+)%)?;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%", re.IGNORECASE)
_CPU_ROW = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)%\s+(\d+)\s+(.+?)\s*$")


def parse_cpu(lines: list[str]) -> dict[str, Any]:
    """``CPU utilization for five seconds: 15%/2%; one minute: 13%; five minutes: 7%`` and the process rows (the first ones are the busiest)."""
    info: dict[str, Any] = {}
    top: list[dict[str, Any]] = []
    for line in lines:
        head = _CPU_HEAD.search(line)
        if head:
            info = {"five_sec": int(head[1]), "interrupt": int(head[2] or 0), "one_min": int(head[3]), "five_min": int(head[4])}
            continue
        row = _CPU_ROW.match(line)
        if row and info:
            top.append({"pid": int(row[1]), "process": row[9], "five_sec": float(row[5]), "one_min": float(row[6]), "five_min": float(row[7])})
    if info:
        info["top"] = sorted(top, key=lambda item: (-item["five_min"], -item["one_min"], -item["five_sec"]))[:TOP]
    return info


# ------------------------------------------------------------------ show processes memory sorted

_POOL = re.compile(r"^\s*(.+?)\s+Pool\s+Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)", re.IGNORECASE)
_MEM_ROW = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$")


def parse_memory(lines: list[str]) -> dict[str, Any]:
    pools: list[dict[str, Any]] = []
    holders: list[dict[str, Any]] = []
    for line in lines:
        pool = _POOL.match(line)
        if pool:
            total, used, free = int(pool[2]), int(pool[3]), int(pool[4])
            pools.append({"pool": pool[1].strip(), "total": total, "used": used, "free": free, "used_pct": round(100.0 * used / total, 1) if total else 0.0})
            continue
        row = _MEM_ROW.match(line)
        if row and pools:
            holders.append({"pid": int(row[1]), "process": row[8], "holding": int(row[5])})
    if not pools:
        return {}
    return {"pools": pools, "top": sorted(holders, key=lambda item: -item["holding"])[:TOP]}


def megabytes(value: int) -> str:
    return f"{value / 1048576:.1f} MB" if value >= 1048576 else f"{value / 1024:.0f} KB" if value >= 1024 else f"{value} B"


# ------------------------------------------------------------------ show interfaces summary

_IFSUM = re.compile(r"^(\*?)\s*(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")


def parse_interfaces_summary(lines: list[str]) -> list[dict[str, Any]]:
    """One row per interface: the ``*`` in front means the interface is up; IHQ / IQD / OHQ / OQD are queue sizes and drops, TRTL the throttle count."""
    rows: list[dict[str, Any]] = []
    started = False
    for line in lines:
        if re.match(r"^\s*Interface\s+IHQ\s+IQD", line):
            started = True
            continue
        if not started:
            continue
        match = _IFSUM.match(line.rstrip())
        if match:
            rows.append({"interface": match[2], "up": bool(match[1]), "ihq": int(match[3]), "iqd": int(match[4]), "ohq": int(match[5]), "oqd": int(match[6]),
                         "rxbs": int(match[7]), "rxps": int(match[8]), "txbs": int(match[9]), "txps": int(match[10]), "trtl": int(match[11])})
    return rows


# ------------------------------------------------------------------ show ip bgp summary

_BGP_ID = re.compile(r"BGP router identifier\s+(\S+),\s*local AS number\s+(\d+)", re.IGNORECASE)
_BGP_ROW = re.compile(r"^(\S+)\s+(\d)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+?)\s*$")


def parse_bgp_summary(lines: list[str]) -> dict[str, Any]:
    """``show ip bgp summary`` (IOS XE, NX-OS layout): router id, local AS and one row per neighbor.

    A neighbor row whose address is too long for the column is printed on its own line with the numbers on the next one; both are joined."""
    info: dict[str, Any] = {"router_id": "", "local_as": "", "neighbors": []}
    started = False
    pending = ""
    for line in lines:
        text = line.rstrip()
        match = _BGP_ID.search(text)
        if match:
            info["router_id"], info["local_as"] = match[1], match[2]
            continue
        if re.match(r"^\s*Neighbor\s+V\s+AS", text):
            started = True
            continue
        if not started or not text.strip():
            continue
        if pending:
            text = pending + " " + text.strip()
            pending = ""
        row = _BGP_ROW.match(text.strip())
        if not row:
            if re.match(r"^\S+$", text.strip()):
                pending = text.strip()
            continue
        state = row[10].strip()
        established = bool(re.fullmatch(r"\d+", state))
        info["neighbors"].append({"neighbor": row[1], "version": int(row[2]), "as": row[3], "msg_rcvd": int(row[4]), "msg_sent": int(row[5]), "up_down": row[9],
                                  "state": "Established" if established else state, "prefixes": int(state) if established else None})
    return info if info["neighbors"] or info["router_id"] else {}


def bgp_neighbor_problem(row: dict[str, Any]) -> str:
    """'' for an Established neighbor, otherwise how the neighbor is not up: 'admin' (shut down on purpose), 'never' (never came up) or 'down'."""
    state = row["state"].lower()
    if state == "established":
        return ""
    if "admin" in state:
        return "admin"
    if any(state.startswith(word) for word in _NEIGHBOR_DOWN):
        return "never" if row["up_down"].lower() == "never" else "down"
    return "down"


# ------------------------------------------------------------------ show ip route summary



def parse_route_summary(lines: list[str]) -> dict[str, Any]:
    """``show ip route summary``: ``IP routing table name is default (0x0)`` and one row per route source with its networks / subnets / memory."""
    info: dict[str, Any] = {"table": "", "sources": []}
    for line in lines:
        head = re.match(r"^IP routing table name is\s+(\S+)", line.strip())
        if head:
            info["table"] = head[1]
            continue
        row = re.match(r"^(connected|static|application|omp|internal|ospf\s+\S+|bgp\s+\S+|eigrp\s+\S+|isis(?:\s+\S+)?|rip|mobile|odr|nhrp|lisp|vrrp|Total)\s+(.*)$", line.strip(), re.IGNORECASE)
        if not row or not info["table"]:
            continue
        numbers = [int(item) for item in row[2].split() if item.isdigit()]
        if len(numbers) >= 5:              # networks, subnets, replicates, overhead, memory
            info["sources"].append({"source": row[1], "networks": numbers[0], "subnets": numbers[1], "memory": numbers[4]})
        elif len(numbers) == 2:            # `internal`: networks and memory only
            info["sources"].append({"source": row[1], "networks": numbers[0], "subnets": 0, "memory": numbers[1]})
    return info if info["sources"] else {}


# ------------------------------------------------------------------ findings and tables

ALL_PARTS = ("cpu", "memory", "queues", "bgp", "routes")


def analyse(clean: list[str], parts: tuple[str, ...] = ALL_PARTS) -> dict[str, Any]:
    """``parts`` limits the work to some readers (a NX-OS capture only wants ``bgp``: its other commands have their own readers)."""
    tables: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    findings: list[dict[str, Any]] = []

    cpu = parse_cpu(_fullest(clean, r"sh(?:ow)? proc(?:esses)? cpu sorted(?: \S+)?", lambda b: len(parse_cpu(b).get("top", [])))) if "cpu" in parts else {}
    if cpu:
        counts["cpu_processes"] = len(cpu["top"])
        tables.append(_table("ios-cpu", "CPU: busiest processes",
                             f"From show processes cpu sorted. The router reports {cpu['five_sec']}% for five seconds ({cpu['interrupt']}% of it at interrupt level), {cpu['one_min']}% for one minute and {cpu['five_min']}% for five minutes. "
                             "A process list can add up to less than the total: the rest is interrupt level (packet forwarding in software).",
                             [("process", "Process"), ("pid", "PID"), ("five_sec", "5 s %"), ("one_min", "1 min %"), ("five_min", "5 min %")], cpu["top"]))
        if cpu["five_min"] >= CPU_HIGH:
            busiest = ", ".join(f"{item['process']} ({item['five_min']}%)" for item in cpu["top"][:3])
            findings.append(_finding("SW-IOS-001", "high", f"CPU averages {cpu['five_min']}% over five minutes",
                                     f"show processes cpu sorted: five seconds {cpu['five_sec']}%/{cpu['interrupt']}%, one minute {cpu['one_min']}%, five minutes {cpu['five_min']}%. Busiest by five-minute average: {busiest}. "
                                     "Interrupt level close to the total means packets are punted or process-switched; a single process near the total points at that process (a routing protocol re-converging, a loop, a flood of management traffic).",
                                     "show processes cpu sorted", "cpu"))

    memory = parse_memory(_fullest(clean, r"sh(?:ow)? proc(?:esses)? memory sorted(?: \S+)?", lambda b: len(parse_memory(b).get("pools", [])))) if "memory" in parts else {}
    if memory:
        counts["memory_pools"] = len(memory["pools"])
        tables.append(_table("ios-memory", "Memory pools", "From show processes memory sorted. Used is the memory allocated from the pool; the processor pool is the one that matters for the control plane.",
                             [("pool", "Pool"), ("total_text", "Total"), ("used_text", "Used"), ("free_text", "Free"), ("used_pct", "Used %")],
                             [dict(pool, total_text=megabytes(pool["total"]), used_text=megabytes(pool["used"]), free_text=megabytes(pool["free"])) for pool in memory["pools"]]))
        tables.append(_table("ios-memory-top", "Memory: largest holders", "From show processes memory sorted: the processes that hold the most memory now (Holding column).",
                             [("process", "Process"), ("pid", "PID"), ("holding_text", "Holding")], [dict(item, holding_text=megabytes(item["holding"])) for item in memory["top"]]))
        processor = next((pool for pool in memory["pools"] if pool["pool"].lower().startswith("processor")), None)
        if processor and processor["used_pct"] >= MEMORY_WATCH:
            high = processor["used_pct"] >= MEMORY_HIGH
            findings.append(_finding("SW-IOS-002", "high" if high else "medium", f"Processor memory is {processor['used_pct']}% used",
                                     f"show processes memory sorted: {megabytes(processor['used'])} of {megabytes(processor['total'])} used, {megabytes(processor['free'])} free. Largest holder: "
                                     + (f"{memory['top'][0]['process']} ({megabytes(memory['top'][0]['holding'])}). " if memory["top"] else "")
                                     + "A pool that stays near full after a reload keeps shrinking when routes or sessions grow; compare with the same output taken an hour later, and a growing holder is a leak candidate.",
                                     "show processes memory sorted", "memory"))

    summary = parse_interfaces_summary(_fullest(clean, r"sh(?:ow)? int(?:erfaces?)? summary", lambda b: len(parse_interfaces_summary(b)))) if "queues" in parts else []
    if summary:
        dropping = sorted((row for row in summary if row["iqd"] or row["oqd"] or row["trtl"]), key=lambda row: -(row["iqd"] + row["oqd"]))
        counts["interface_queues"] = len(summary)
        if dropping:
            tables.append(_table("ios-queues", "Interfaces with queue drops or throttles",
                                 "From show interfaces summary. IQD / OQD count the packets dropped from the input / output queue since the counters were last cleared (the counters are cumulative, not a rate); TRTL is the throttle count.",
                                 [("interface", "Interface"), ("state", "State"), ("iqd", "IQD"), ("oqd", "OQD"), ("trtl", "TRTL"), ("ihq", "IHQ"), ("ohq", "OHQ")],
                                 [dict(row, state="up" if row["up"] else "down") for row in dropping], "state"))
            heavy = [row for row in dropping if row["iqd"] + row["oqd"] >= DROPS_MEDIUM]
            if heavy:
                shown = "; ".join(f"{row['interface']} IQD {row['iqd']} / OQD {row['oqd']}" for row in heavy[:6])
                findings.append(_finding("SW-IOS-003", "medium", f"{len(heavy)} interface(s) dropped {DROPS_MEDIUM} packets or more in the queues",
                                         f"show interfaces summary: {shown}. Output queue drops mean the interface was offered more than it can send (a policer or shaper, congestion, a speed or duplex mismatch downstream); "
                                         "input queue drops mean the router could not take packets off the interface fast enough. The counters are cumulative since the last `clear counters`, so read "
                                         "`show interfaces <name>` for the time since the last clearing and whether the drops are still growing.",
                                         "show interfaces summary", "drops"))

    bgp = parse_bgp_summary(_fullest(clean, r"sh(?:ow)? ip bgp(?: ipv4 unicast)? summary", lambda b: len(parse_bgp_summary(b).get("neighbors", [])))) if "bgp" in parts else {}
    if bgp and bgp["neighbors"]:
        counts["bgp_neighbors"] = len(bgp["neighbors"])
        tables.append(_table("ios-bgp", "BGP neighbors", f"From show ip bgp summary: local AS {bgp['local_as']}, router id {bgp['router_id']}. State/PfxRcd is the number of prefixes received when the session is Established, otherwise the state.",
                             [("neighbor", "Neighbor"), ("as", "AS"), ("state", "State"), ("prefixes", "Prefixes received"), ("up_down", "Up/Down"), ("msg_rcvd", "Msgs in"), ("msg_sent", "Msgs out")],
                             bgp["neighbors"], "state"))
        down = [row for row in bgp["neighbors"] if bgp_neighbor_problem(row) in ("down", "never")]
        if down:
            findings.append(_finding("SW-IOS-004", "medium", f"{len(down)} BGP neighbor(s) are configured but not Established",
                                     "show ip bgp summary: " + "; ".join(f"{row['neighbor']} AS {row['as']} {row['state']}" + (", never came up" if bgp_neighbor_problem(row) == "never" else f", last up/down {row['up_down']}") for row in down[:6])
                                     + ". Idle means the router has no session in progress to that neighbor: typical causes are no route to the neighbor address, a session that was reset and is waiting out its retry timer, or a configuration mismatch "
                                     "(remote AS, update-source, authentication); an Idle neighbor that has never been up is most often a wrong or unreachable address, or a neighbor that is not configured on the other side. "
                                     "Active and Connect mean the TCP session does not complete (routing to the peer, or an ACL or firewall on TCP port 179).",
                                     "show ip bgp summary", "bgp"))
        admin = [row for row in bgp["neighbors"] if bgp_neighbor_problem(row) == "admin"]
        if admin:
            findings.append(_finding("SW-IOS-005", "low", f"{len(admin)} BGP neighbor(s) are administratively shut down",
                                     "show ip bgp summary: " + ", ".join(f"{row['neighbor']} AS {row['as']}" for row in admin[:6])
                                     + " show Idle (Admin): the neighbor is configured with `shutdown`. Fine for a decommissioned peer; remove the neighbor statements that are no longer needed so that a later `no shutdown` does not bring back an old policy.",
                                     "show ip bgp summary", "bgp"))

    routes = parse_route_summary(_fullest(clean, r"sh(?:ow)? ip route(?: vrf \S+)? summary", lambda b: len(parse_route_summary(b).get("sources", [])))) if "routes" in parts else {}
    if routes:
        counts["route_summary"] = len(routes["sources"])
        tables.append(_table("ios-routes", "Route summary", f"From show ip route summary, routing table {routes['table']}: networks and subnets per route source. The total is what the routing table holds now.",
                             [("source", "Source"), ("networks", "Networks"), ("subnets", "Subnets"), ("memory", "Memory (bytes)")], routes["sources"]))
    return {"tables": tables, "counts": counts, "findings": findings}
