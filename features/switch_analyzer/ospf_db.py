"""OSPF interface summary and link-state database, read from ``show ip ospf interface brief`` and ``show ip ospf database``.

``ospf_live.py`` reads the neighbours; this module reads the other two views an engineer opens first:

* ``show ip ospf interface brief [vrf all]`` -- one row per OSPF interface.  NX-OS 9000 prints ``OSPF Process ID <n> VRF <vrf>``, ``Total number of interface: <n>``
  and ``Interface  ID  Area  Cost  State  Neighbors  Status``.  The IOS / IOS XE layout (``Interface  PID  Area  IP Address/Mask  Cost  State  Nbrs F/C``) follows the published
  syntax and has no capture behind it; it is read too.
* ``show ip ospf database`` -- the link-state database summary: one table per LSA type (Router, Network, Summary Network, Summary ASBR, AS External, NSSA External,
  Opaque) and area, each row ``Link ID  ADV Router  Age  Seq#  Checksum [Link Count | Tag]``.  A real capture holds ~19,000 rows (almost all AS External), so only the
  per-type totals and the Router LSAs (one per router) are kept, never one row per LSA.

A terminal pager spoils this command more than any other (a long output): ``--More--`` followed by its help screen, and ``...skipping N lines`` where a key press made the pager
jump over lines.  Both are counted, and the capture is called incomplete when any line was skipped.  ``terminal length 0`` (NX-OS and IOS) turns the pager off.

Judged here: an interface that is down, a LSA that has not been refreshed in time, a Full neighbour with no Router LSA, a database that is incomplete.  Everything else is shown.

Sources (pages opened while writing this module):

* Cisco, Cisco Nexus 9000 Series NX-API CLI Reference, OSPF Commands (``show ip ospf interface brief vrf all``):
  https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/ospf-commands/
* Cisco, Cisco Nexus 3500 Series NX-API CLI Reference, OSPF Commands (``show ip ospf database`` with the Link ID / ADV Router / Age / Seq# / Checksum columns; the same NX-OS syntax):
  https://developer.cisco.com/docs/nexus-3500-series-nx-api-cli-reference/latest/ospf-commands
* IETF, RFC 2328 OSPF Version 2, Appendix B Architectural Constants (``LSRefreshTime`` 30 minutes, ``MaxAge`` 1 hour); an originator re-floods its LSA every 30 minutes,
  and a LSA that reaches ``MaxAge`` is flushed: https://datatracker.ietf.org/doc/html/rfc2328#appendix-B
* Cisco, Cisco Nexus 9000 NX-OS Unicast Routing Configuration Guide, Configuring OSPFv2 (9.x guide):
  https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/9-x/unicast/configuration/guide/l3_cli_nxos/l3_ospf.html
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text
from .live_state import interface_key

DOCS = {
    "commands": ("Cisco - Nexus 9000 NX-API CLI Reference, OSPF Commands", "https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/ospf-commands/"),
    "database": ("Cisco - Nexus 3500 NX-API CLI Reference, OSPF Commands (show ip ospf database)", "https://developer.cisco.com/docs/nexus-3500-series-nx-api-cli-reference/latest/ospf-commands"),
    "rfc": ("IETF - RFC 2328 OSPF Version 2, Appendix B Architectural Constants", "https://datatracker.ietf.org/doc/html/rfc2328#appendix-B"),
    "guide": ("Cisco - Nexus 9000 NX-OS Unicast Routing Configuration Guide, Configuring OSPFv2",
              "https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/9-x/unicast/configuration/guide/l3_cli_nxos/l3_ospf.html"),
}

PATTERN_INTERFACE = (r"sh(?:ow)? ip ospf interface brief(?: vrf \S+)?",)
PATTERN_DATABASE = (r"sh(?:ow)? ip ospf(?: \S+)? database(?: vrf \S+)?",)

LSA_REFRESH = 1800      # RFC 2328 Appendix B: LSRefreshTime (seconds)
MAX_AGE = 3600          # RFC 2328 Appendix B: MaxAge (seconds)
STALE_AFTER = LSA_REFRESH + 600     # an originator re-floods at 1800 s; ten more minutes without a refresh is not timer jitter

_PROCESS = re.compile(r"^\s*OSPF Process ID (\S+?)(?:\s+VRF\s+(\S+?))?\s*$")
_TOTAL = re.compile(r"^\s*Total number of interface:\s*(\d+)")
_HEADER_NX = re.compile(r"^\s*Interface\s+ID\s+Area\s+Cost\s+State\s+Neighbors\s+Status\s*$")
_ROW_NX = re.compile(r"^\s*(\S+)\s+(\d+)\s+(\d{1,3}(?:\.\d{1,3}){3}|\d+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s*$")
_HEADER_IOS = re.compile(r"^\s*Interface\s+PID\s+Area\s+IP Address/Mask\s+Cost\s+State\s+Nbrs F/C\s*$")
_ROW_IOS = re.compile(r"^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+(\d+)\s+(\S+)\s+(\d+)/(\d+)\s*$")

_ROUTER_HEAD = re.compile(r"^\s*OSPF Router with ID \((\S+)\) \(Process ID (\S+?)(?:\s+VRF\s+(\S+?))?\)\s*$")
_LSA_HEAD = re.compile(r"^\s*((?:Type-\d+ )?[A-Za-z0-9 \-]*Link States)(?:\s*\(Area\s+(\S+?)\))?\s*$")
_LSA_ROW = re.compile(r"^\s*(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(0x[0-9A-Fa-f]{4,8})\s+(0x[0-9A-Fa-f]{4,8})(?:\s+(\d+))?\s*$")
_SKIP = re.compile(r"^\s*\.\.\.skipping (one|\d+) lines?\s*$")
_PAGER_HELP = re.compile(r"^\s*\.\.\.pager help screen removed|Most commands optionally preceded by integer argument k", re.IGNORECASE)

LSA_TYPES = {"router": "Router (1)", "network": "Network (2)", "summary": "Summary network (3)", "asbr-summary": "Summary ASBR (4)", "external": "AS external (5)",
             "nssa-external": "NSSA external (7)", "opaque": "Opaque", "other": "Other"}
_ORDER = list(LSA_TYPES)


def _kind(title: str) -> str:
    text = title.lower()
    if text.startswith("router"):
        return "router"
    if "asb" in text:
        return "asbr-summary"
    if text.startswith("summary"):
        return "summary"
    if text.startswith("net"):
        return "network"
    if "type-7" in text or "nssa" in text:
        return "nssa-external"
    if "external" in text:
        return "external"
    if "opaque" in text or re.search(r"type-(?:9|10|11)\b", text):
        return "opaque"
    return "other"


def parse_interfaces(lines: list[str]) -> tuple[list[dict[str, Any]], dict[tuple[str, str], int]]:
    """Rows of one ``show ip ospf interface brief`` output and the ``Total number of interface`` of every process / VRF."""
    rows: list[dict[str, Any]] = []
    totals: dict[tuple[str, str], int] = {}
    process, vrf, layout = "", "", ""
    for raw in lines:
        found = _PROCESS.match(raw)
        if found:
            process, vrf = found.group(1), found.group(2) or ""
            continue
        found = _TOTAL.match(raw)
        if found:
            totals[(process, vrf)] = int(found.group(1))
            continue
        if _HEADER_NX.match(raw):
            layout = "nx"
            continue
        if _HEADER_IOS.match(raw):
            layout = "ios"
            continue
        if layout == "nx":
            found = _ROW_NX.match(raw)
            if found:
                rows.append({"process": process, "vrf": vrf, "interface": found.group(1), "id": found.group(2), "area": found.group(3), "cost": found.group(4),
                             "state": found.group(5).upper(), "neighbors": int(found.group(6)), "status": found.group(7).lower(), "address": ""})
        elif layout == "ios":
            found = _ROW_IOS.match(raw)
            if found:
                state = found.group(6).upper()
                rows.append({"process": found.group(2), "vrf": vrf, "interface": found.group(1), "id": "", "area": found.group(3), "cost": found.group(5), "state": state,
                             "neighbors": int(found.group(8)), "full": int(found.group(7)), "status": "down" if state == "DOWN" else "up", "address": found.group(4)})
    return rows, totals


def parse_database(lines: list[str]) -> dict[str, Any]:
    """Totals per process / VRF / area / LSA type, every Router LSA, and what the terminal pager did to the output."""
    processes: dict[tuple[str, str], str] = {}
    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    routers: list[dict[str, Any]] = []
    process, vrf, kind, area = "", "", "", ""
    skipped = skip_events = pager_help = 0
    rows = 0
    for raw in lines:
        found = _SKIP.match(raw)
        if found:
            skip_events += 1
            skipped += 1 if found.group(1) == "one" else int(found.group(1))
            kind = ""       # the lines after a cut may belong to another section than the ones before it: read nothing until the next section header
            continue
        if _PAGER_HELP.search(raw):
            pager_help += 1
            kind = ""
            continue
        found = _ROUTER_HEAD.match(raw)
        if found:
            process, vrf = found.group(2), found.group(3) or ""
            processes[(process, vrf)] = found.group(1)
            kind = ""
            continue
        found = _LSA_HEAD.match(raw)
        if found:
            kind, area = _kind(found.group(1)), found.group(2) or ""
            continue
        found = _LSA_ROW.match(raw)
        if found and kind:
            rows += 1
            link_id, adv, age, seq = found.group(1), found.group(2), int(found.group(3)), found.group(4)
            group = groups.setdefault((process, vrf, area, kind), {"process": process, "vrf": vrf, "area": area, "kind": kind, "count": 0, "advs": set(), "oldest": 0,
                                                                  "over_refresh": 0, "stale": 0, "maxage": 0, "oldest_adv": ""})
            group["count"] += 1
            group["advs"].add(adv)
            if age > group["oldest"]:
                group["oldest"], group["oldest_adv"] = age, adv
            group["over_refresh"] += age > LSA_REFRESH
            group["stale"] += age > STALE_AFTER
            group["maxage"] += age >= MAX_AGE
            if kind == "router":
                routers.append({"process": process, "vrf": vrf, "area": area, "router": adv, "age": age, "seq": seq, "links": int(found.group(6)) if found.group(6) else None})
    summary = []
    for key in sorted(groups, key=lambda k: (k[0], k[1], k[2] == "", _area_key(k[2]), _ORDER.index(k[3]))):
        item = dict(groups[key])
        item["advs"] = len(item["advs"])
        summary.append(item)
    return {"processes": [{"process": p, "vrf": v, "router_id": rid} for (p, v), rid in processes.items()], "lsdb": summary, "routers": routers,
            "skipped": skipped, "skip_events": skip_events, "pager_help": pager_help, "rows": rows}


def read(clean: list[str], host: str | None = None) -> dict[str, Any]:
    """``{"interfaces": [...], "interface_totals": {...}, "database": {...}}`` from the commands of the capture (``host``: see ``fhrp_live.read``)."""
    def keep(index: int) -> bool:
        return host is None or capture_text.prompt_host(clean[index]) in (None, host)

    interfaces: list[dict[str, Any]] = []
    totals: dict[tuple[str, str], int] = {}
    for index, block in capture_text.find_blocks(clean, PATTERN_INTERFACE):
        if not keep(index) or not block or re.match(r"^\s*(?:%|\^\s*$)", block[0]):
            continue
        rows, found = parse_interfaces(block)
        if len(rows) >= len(interfaces):
            interfaces, totals = rows, found
    database: dict[str, Any] = {"processes": [], "lsdb": [], "routers": [], "skipped": 0, "skip_events": 0, "pager_help": 0, "rows": 0}
    for index, block in capture_text.find_blocks(clean, PATTERN_DATABASE):
        if not keep(index) or not block or re.match(r"^\s*(?:%|\^\s*$)", block[0]):
            continue
        parsed = parse_database(block)
        if parsed["rows"] >= database["rows"]:
            database = parsed
    return {"interfaces": interfaces, "interface_totals": totals, "database": database}


def _area_key(area: str) -> str:
    """``0`` and ``0.0.0.0`` are the same area (IOS prints the first, NX-OS the second)."""
    if re.fullmatch(r"\d+", area or ""):
        value = int(area)
        return ".".join(str((value >> shift) & 255) for shift in (24, 16, 8, 0))
    return area or ""


def incomplete(view: dict[str, Any]) -> bool:
    return bool(view["database"]["skipped"])


def notes(view: dict[str, Any]) -> list[dict[str, str]]:
    """Capture notes: the pager cut the database output."""
    database = view["database"]
    if not database["skipped"] and not database["pager_help"]:
        return []
    parts = []
    if database["skipped"]:
        parts.append(f"{database['skipped']} line{'s' if database['skipped'] != 1 else ''} were never printed ({database['skip_events']} '...skipping' marker{'s' if database['skip_events'] != 1 else ''})")
    if database["pager_help"]:
        parts.append("the pager's help screen is in the output")
    return [{"level": "warning", "text": "The terminal pager cut the 'show ip ospf database' output: " + " and ".join(parts) + ". The LSA counts below are lower than the device holds and "
             "the LSDB comparison and the neighbour-in-database check are switched off. Run 'terminal length 0' first and capture the command again."}]


def checks(view: dict[str, Any], neighbors: list[dict[str, str]]) -> list[str]:
    """Places where the interface summary and the neighbour table disagree."""
    out = []
    counted: dict[tuple[str, str], int] = {}
    for row in view["interfaces"]:
        key = (row["process"], row["vrf"])
        counted[key] = counted.get(key, 0) + 1
    for key, reported in view["interface_totals"].items():
        if counted.get(key, 0) != reported:
            out.append(f"show ip ospf interface brief says {reported} interface(s) for process {key[0]}" + (f", VRF {key[1]}" if key[1] else "") + f", the table lists {counted.get(key, 0)}")
    if view["interfaces"] and neighbors and all("neighbors" in row for row in view["interfaces"]):
        by_interface: dict[tuple[str, str, str], int] = {}
        for row in neighbors:
            key = (row["process"], row["vrf"], interface_key(row["interface"]))
            by_interface[key] = by_interface.get(key, 0) + 1
        for row in view["interfaces"]:
            if "full" in row:       # the IOS layout counts Full neighbours (F/C), not all of them
                continue
            seen = by_interface.get((row["process"], row["vrf"], interface_key(row["interface"])), 0)
            if seen != row["neighbors"]:
                out.append(f"{row['interface']} (process {row['process']}): show ip ospf interface brief counts {row['neighbors']} neighbour(s), show ip ospf neighbors lists {seen}")
    return out


def findings(view: dict[str, Any], neighbors: list[dict[str, str]]) -> list[dict[str, Any]]:
    from features.analyzer_core.findings import finding

    out: list[dict[str, Any]] = []
    down = [row for row in view["interfaces"] if row["state"] == "DOWN" or row["status"] == "down"]
    if down:
        names = ", ".join(f"{row['interface']} (area {row['area']})" for row in down[:8]) + (f" and {len(down) - 8} more" if len(down) > 8 else "")
        out.append(finding(
            "SW-OSPF-002", "low", "Routing", f"{len(down)} OSPF interface{'s are' if len(down) != 1 else ' is'} down",
            obj=names,
            detail="OSPF is configured on these interfaces but they are down, so no adjacency can form on them and the networks behind them are not advertised.",
            recommendation="If the port is meant to be in service, check its link state (`show interface <name>`); if it is retired, remove it from OSPF (`no ip router ospf <process> area <area>` on NX-OS) so the configuration matches the network.",
            reference=DOCS["guide"][1]))
    database = view["database"]
    if database["lsdb"]:
        late = [dict(item, stale=item["stale"] - item["maxage"]) for item in database["lsdb"] if item["stale"] - item["maxage"] > 0]
        if late and not incomplete(view):
            total = sum(item["stale"] for item in late)
            worst = max(late, key=lambda item: item["oldest"])
            where = ", ".join(f"{LSA_TYPES[item['kind']]}{' area ' + item['area'] if item['area'] else ''}: {item['stale']}" for item in late[:5])
            out.append(finding(
                "SW-OSPF-004", "low", "Routing", f"{total} OSPF LSA{'s are' if total != 1 else ' is'} older than {STALE_AFTER // 60} minutes",
                obj=f"process {worst['process']}" + (f", VRF {worst['vrf']}" if worst["vrf"] else ""),
                detail=(f"An originating router re-floods its LSAs every {LSA_REFRESH // 60} minutes (LSRefreshTime), so an age above {STALE_AFTER // 60} minutes means the refresh did not arrive; "
                        f"at {MAX_AGE // 60} minutes (MaxAge) the LSA is flushed. Oldest: {worst['oldest']} s from {worst['oldest_adv']}. Counts: {where}."),
                recommendation="Check whether the originating router is still alive and reachable (`show ip ospf neighbors`, `ping`), and whether LSA flooding is blocked on the path.",
                reference=DOCS["rfc"][1]))
        aged = [item for item in database["lsdb"] if item["maxage"]]
        if aged and not incomplete(view):
            total = sum(item["maxage"] for item in aged)
            where = ", ".join(f"{LSA_TYPES[item['kind']]}{' area ' + item['area'] if item['area'] else ''} in process {item['process']}: {item['maxage']}" for item in aged[:5])
            out.append(finding(
                "SW-OSPF-005", "medium", "Routing", f"{total} OSPF LSA{'s are' if total != 1 else ' is'} at MaxAge ({MAX_AGE} s) in the database",
                obj=where,
                detail=("An LSA at MaxAge has been flushed (its originator withdrew it, or it aged out) and is only kept until every neighbour has acknowledged the flush, "
                        "so it normally disappears within seconds. One still listed means a neighbour in that area is not acknowledging, or the topology behind it is flapping."),
                recommendation="Capture `show ip ospf database` again after a minute: if the LSA is still there, look for a neighbour of that area that is not Full (`show ip ospf neighbors`) and for a "
                               "MTU or link problem towards it (`show interface`, `show ip ospf interface`).",
                reference="https://datatracker.ietf.org/doc/html/rfc2328#section-14"))
    if database["routers"] and not incomplete(view):
        by_area: dict[tuple[str, str, str], set[str]] = {}
        for item in database["routers"]:
            by_area.setdefault((item["process"], item["vrf"], _area_key(item["area"])), set()).add(item["router"])
        area_of = {(row["process"], row["vrf"], interface_key(row["interface"])): _area_key(row["area"]) for row in view["interfaces"]}
        missing = []
        for row in neighbors:
            if row["state"].upper() != "FULL":
                continue
            area = area_of.get((row["process"], row["vrf"], interface_key(row["interface"])))
            if area is not None and row["neighbor_id"] not in by_area.get((row["process"], row["vrf"], area), set()):
                missing.append(f"{row['neighbor_id']} on {row['interface']}")
        if missing:
            out.append(finding(
                "SW-OSPF-003", "low", "Routing", f"{len(missing)} Full OSPF neighbour{'s have' if len(missing) != 1 else ' has'} no Router LSA in the database",
                obj=", ".join(missing[:6]) + (f" and {len(missing) - 6} more" if len(missing) > 6 else ""),
                detail="A neighbour that reached Full has synchronised its database with this router, so its Router LSA must be in the area's database. The two commands were captured at different moments, "
                       "so a neighbour that was just flushed or restarted shows up here too.",
                recommendation="Capture `show ip ospf neighbors` and `show ip ospf database` again within the same minute; if the LSA is still missing, compare the router IDs (`show ip ospf`) of both ends.",
                reference=DOCS["rfc"][1]))
    return out


_STATE_TONES = {"dr": "ok", "bdr": "ok", "drother": "ok", "p2p": "ok", "ptp": "ok", "loopback": "ok", "loop": "ok", "waiting": "warn", "wait": "warn", "down": "bad", "unknown": "warn"}


def tables(view: dict[str, Any], neighbors: list[dict[str, str]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    interfaces, database = view["interfaces"], view["database"]
    if interfaces:
        columns = [{"key": "process", "label": "Process"}, {"key": "vrf", "label": "VRF"}, {"key": "interface", "label": "Interface"}, {"key": "id", "label": "ID"},
                   {"key": "area", "label": "Area"}, {"key": "address", "label": "Address"}, {"key": "cost", "label": "Cost"},
                   {"key": "state", "label": "State", "status": True, "tones": _STATE_TONES}, {"key": "neighbors", "label": "Neighbours"},
                   {"key": "status", "label": "Status", "status": True, "tones": {"up": "ok", "down": "bad"}}]
        for key in ("vrf", "id", "address"):
            if not any(row.get(key) for row in interfaces):
                columns = [column for column in columns if column["key"] != key]
        up = sum(1 for row in interfaces if row["status"] == "up")
        out.append({"tab": "routing", "id": "ospf-interfaces", "title": "OSPF interfaces (show ip ospf interface brief)",
                    "hint": f"{len(interfaces)} interfaces, {up} up. State is the interface's role on its segment (DR, BDR, DROTHER, P2P). An up interface with 0 neighbours is either alone on its segment or passive: "
                            "the brief view does not say which.",
                    "columns": columns, "rows": [dict(row, id=row["id"] or "—", address=row["address"] or "—", vrf=row["vrf"] or "—") for row in interfaces]})
    if database["processes"] or database["lsdb"]:
        by_process: dict[tuple[str, str], dict[str, Any]] = {}
        for item in database["processes"]:
            by_process[(item["process"], item["vrf"])] = {"process": item["process"], "vrf": item["vrf"] or "—", "router_id": item["router_id"]}
        for key, row in by_process.items():
            row.update({"areas": "", "interfaces": "—", "neighbors": "—", "router": 0, "network": 0, "summary": 0, "asbr": 0, "external": 0, "total": 0})
            areas = sorted({_area_key(item["area"]) for item in database["lsdb"] if (item["process"], item["vrf"]) == key and item["area"]})
            row["areas"] = ", ".join(areas) or "—"
            mine = [r for r in interfaces if (r["process"], r["vrf"]) == key]
            if mine:
                row["interfaces"] = f"{sum(1 for r in mine if r['status'] == 'up')} up / {len(mine)}"
            theirs = [n for n in neighbors if (n["process"], n["vrf"]) == key]
            if theirs:
                row["neighbors"] = f"{sum(1 for n in theirs if n['state'].upper() == 'FULL')} Full / {len(theirs)}"
            for item in database["lsdb"]:
                if (item["process"], item["vrf"]) != key:
                    continue
                name = {"router": "router", "network": "network", "summary": "summary", "asbr-summary": "asbr", "external": "external", "nssa-external": "external"}.get(item["kind"])
                if name:
                    row[name] += item["count"]
                row["total"] += item["count"]
        rows = list(by_process.values())
        columns = [{"key": "process", "label": "Process"}, {"key": "vrf", "label": "VRF"}, {"key": "router_id", "label": "Router ID"}, {"key": "areas", "label": "Areas"},
                   {"key": "interfaces", "label": "Interfaces"}, {"key": "neighbors", "label": "Neighbours"}, {"key": "router", "label": "Router LSAs"},
                   {"key": "network", "label": "Network LSAs"}, {"key": "summary", "label": "Summary LSAs"}, {"key": "asbr", "label": "ASBR LSAs"},
                   {"key": "external", "label": "External LSAs"}, {"key": "total", "label": "All LSAs"}]
        if not any(row["vrf"] != "—" for row in rows):
            columns = [column for column in columns if column["key"] != "vrf"]
        hint = "One row per OSPF process: its router ID, the areas it holds, and the link-state database totals."
        if incomplete(view):
            hint += f" The pager skipped {database['skipped']} lines of the database output, so the LSA totals are lower than the device holds."
        out.append({"tab": "routing", "id": "ospf-overview", "title": "OSPF processes (show ip ospf database)", "hint": hint, "columns": columns, "rows": rows})
        columns = [{"key": "process", "label": "Process"}, {"key": "vrf", "label": "VRF"}, {"key": "area", "label": "Area"}, {"key": "type", "label": "LSA type"}, {"key": "count", "label": "LSAs"},
                   {"key": "advs", "label": "Advertising routers"}, {"key": "oldest", "label": "Oldest age (s)"},
                   {"key": "stale", "label": f"Older than {STALE_AFTER // 60} min"}]
        if not any(item["vrf"] for item in database["lsdb"]):
            columns = [column for column in columns if column["key"] != "vrf"]
        rows = [{"process": item["process"], "vrf": item["vrf"] or "—", "area": item["area"] or "AS-wide", "type": LSA_TYPES[item["kind"]], "count": item["count"], "advs": item["advs"],
                 "oldest": item["oldest"], "stale": str(item["stale"])} for item in database["lsdb"]]
        out.append({"tab": "routing", "id": "ospf-lsdb", "title": "OSPF link-state database by type", "hint": (
            f"A router re-floods its own LSAs every {LSA_REFRESH // 60} minutes and an LSA is flushed at {MAX_AGE // 60} minutes (RFC 2328 Appendix B), so an age above "
            f"{STALE_AFTER // 60} minutes is flagged. AS external LSAs are not tied to an area."), "columns": columns, "rows": rows})
    routers = database["routers"]
    if routers:
        own = {(item["process"], item["vrf"]): item["router_id"] for item in database["processes"]}
        full = {(n["process"], n["vrf"], n["neighbor_id"]) for n in neighbors if n["state"].upper() == "FULL"}
        rows = []
        for item in sorted(routers, key=lambda r: (r["process"], r["vrf"], _area_key(r["area"]), tuple(int(x) for x in r["router"].split(".")))):
            seen = "this router" if own.get((item["process"], item["vrf"])) == item["router"] else ("Full neighbour" if (item["process"], item["vrf"], item["router"]) in full else "")
            rows.append({"process": item["process"], "vrf": item["vrf"] or "—", "area": item["area"], "router": item["router"], "seen": seen or "—", "age": item["age"],
                         "links": item["links"] if item["links"] is not None else "—", "seq": item["seq"]})
        columns = [{"key": "process", "label": "Process"}, {"key": "vrf", "label": "VRF"}, {"key": "area", "label": "Area"}, {"key": "router", "label": "Advertising router"},
                   {"key": "seen", "label": "Seen as"}, {"key": "links", "label": "Links"}, {"key": "age", "label": "Age (s)"}, {"key": "seq", "label": "Sequence"}]
        if not any(row["vrf"] != "—" for row in rows):
            columns = [column for column in columns if column["key"] != "vrf"]
        out.append({"tab": "routing", "id": "ospf-routers", "title": "OSPF routers in the database (Router LSAs)",
                    "hint": f"{len(rows)} routers advertise a Router LSA, one per router and area. Links is the number of links the router lists; Seen as marks this router and its Full neighbours.",
                    "columns": columns, "rows": rows})
    return out


def counts(view: dict[str, Any]) -> dict[str, int]:
    """``result["extras"]`` entries: rows each parser produced (read by the Coverage tab)."""
    return {"ospf_intf": len(view["interfaces"]), "ospf_db": view["database"]["rows"]}


def pair_check(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Two routers of one area hold the same link-state database: compare the LSA totals per process, area and type and the routers each side lists."""
    la, lb = (a or {}).get("database", {}).get("lsdb") or [], (b or {}).get("database", {}).get("lsdb") or []
    if not la or not lb:
        return {"rows": [], "counts": {}, "incomplete": []}
    cut = [name for name, side in (("A", a), ("B", b)) if incomplete(side)]
    key = lambda item: (item["process"], item["vrf"], _area_key(item["area"]), item["kind"])  # noqa: E731
    map_a, map_b = {key(i): i for i in la}, {key(i): i for i in lb}
    routers_a = {(r["process"], r["vrf"], _area_key(r["area"])): set() for r in a["database"]["routers"]}
    routers_b = {(r["process"], r["vrf"], _area_key(r["area"])): set() for r in b["database"]["routers"]}
    for side, store in ((a, routers_a), (b, routers_b)):
        for r in side["database"]["routers"]:
            store[(r["process"], r["vrf"], _area_key(r["area"]))].add(r["router"])
    rows, summary = [], {}
    for k in sorted(set(map_a) | set(map_b), key=lambda k: (k[0], k[1], k[2] == "", k[2], _ORDER.index(k[3]))):
        ia, ib = map_a.get(k), map_b.get(k)
        ca, cb = (ia or {}).get("count", 0), (ib or {}).get("count", 0)
        reason = ""
        if (ia is None or ib is None) and ("A" if ia is None else "B") in cut:
            verdict, reason = "Check", f"the database of {'A' if ia is None else 'B'} is incomplete (pager), so a missing section proves nothing"
        elif ia is None or ib is None:
            verdict, reason = ("Only on A" if ib is None else "Only on B"), "the area or LSA type exists in one database only"
        elif ca == cb:
            verdict = "Same"
        elif cut:
            verdict, reason = "Check", f"the database of {' and '.join(cut)} is incomplete (pager), so the counts cannot be compared"
        else:
            verdict, reason = "Differs", f"{abs(ca - cb)} LSA{'s' if abs(ca - cb) != 1 else ''} more on {'A' if ca > cb else 'B'}"
        if k[3] == "router" and ia and ib:
            only_a = routers_a.get(k[:3], set()) - routers_b.get(k[:3], set())
            only_b = routers_b.get(k[:3], set()) - routers_a.get(k[:3], set())
            if (only_a or only_b) and not cut:
                reason = "; ".join(filter(None, [reason, "only A lists " + ", ".join(sorted(only_a)[:4]) if only_a else "", "only B lists " + ", ".join(sorted(only_b)[:4]) if only_b else ""]))
        summary[verdict] = summary.get(verdict, 0) + 1
        rows.append({"process": k[0], "vrf": k[1] or "—", "area": (ia or ib)["area"] or "AS-wide", "type": LSA_TYPES[k[3]], "a_count": ca if ia else "—", "b_count": cb if ib else "—",
                     "a_oldest": ia["oldest"] if ia else "—", "b_oldest": ib["oldest"] if ib else "—", "verdict": verdict, "reason": reason or "same number of LSAs on both"})
    return {"rows": rows, "counts": summary, "incomplete": cut}


VERDICT_TONES = {"same": "ok", "differs": "bad", "check": "warn", "only on a": "warn", "only on b": "warn"}
