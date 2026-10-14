"""Live OSPF neighbours read from ``show ip ospf neighbors`` and ``show ip ospf neighbors summary``.

The Routing tab already shows the OSPF *configuration* (``l3.py``).  This module reads what the device says now:

* ``show ip ospf neighbors [vrf all]`` -- one row per adjacency: ``Neighbor ID  Pri  State  Up Time  Address  Interface``.  NX-OS 9000 prints an
  ``OSPF Process ID <n> VRF <vrf>`` line and ``Total number of neighbors: <n>`` above every table and ``Up Time`` as the fourth column; IOS / IOS XE and the Nexus
  7000 print ``Dead Time`` there and no process line.  Both layouts are read.
* ``show ip ospf neighbors summary [vrf all]`` (NX-OS) -- per process and interface, how many neighbours are in each state.

Read from the layout of a real Nexus 9000 capture (a vPC pair with two OSPF processes).  Nothing is judged except an adjacency that has not reached Full
(on a broadcast network two routers that are neither DR nor BDR legitimately stay in 2-Way, so that state is shown but never flagged).

Sources (pages opened while writing this module):

* IETF, RFC 2328 OSPF Version 2, section 10.1 Neighbor states (Down, Attempt, Init, 2-Way, ExStart, Exchange, Loading, Full):
  https://datatracker.ietf.org/doc/html/rfc2328#section-10.1
* Cisco, Troubleshoot OSPF Neighbors Stuck in Exstart/Exchange State (an MTU mismatch is the most common cause):
  https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/13684-12.html
* Cisco, Nexus 7000 OSPF Adjacency Issues Troubleshoot (``show ip ospf neighbor`` and its ``Dead Time`` column on NX-OS):
  https://www.cisco.com/c/en/us/support/docs/switches/nexus-7000-series-switches/116422-technote-ospf-00.html
* Cisco, Cisco Nexus 9000 Series NX-API CLI Reference, OSPF Commands (``show ip ospf neighbors summary vrf all``, ``show ip ospf interface brief vrf all``):
  https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/ospf-commands/
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text
from .live_state import interface_key

DOCS = {
    "rfc": ("IETF - RFC 2328 OSPF Version 2, 10.1 Neighbor states", "https://datatracker.ietf.org/doc/html/rfc2328#section-10.1"),
    "exstart": ("Cisco - Troubleshoot OSPF Neighbors Stuck in Exstart/Exchange State", "https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/13684-12.html"),
    "nexus": ("Cisco - Nexus 7000 OSPF Adjacency Issues Troubleshoot", "https://www.cisco.com/c/en/us/support/docs/switches/nexus-7000-series-switches/116422-technote-ospf-00.html"),
    "commands": ("Cisco - Nexus 9000 NX-API CLI Reference, OSPF Commands", "https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/ospf-commands/"),
}

PATTERN_NEIGHBORS = (r"sh(?:ow)? ip ospf nei(?:ghbors?)?(?: vrf \S+)?",)
PATTERN_SUMMARY = (r"sh(?:ow)? ip ospf nei(?:ghbors?)? summary(?: vrf \S+)?",)

_PROCESS = re.compile(r"^\s*OSPF Process ID (\S+?)(?:\s+VRF\s+(\S+?))?\s*(?:,\s*Neighbor Summary)?\s*$")
_TOTAL = re.compile(r"^\s*Total number of neighbors:\s*(\d+)")
_HEADER = re.compile(r"^\s*Neighbor ID\s+Pri\s+State\s+(Up Time|Dead Time)\s+Address\s+Interface\s*$")
_ROW = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+([A-Z0-9]+)(?:/\s*(\S+))?\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s*$")
_SUMMARY_HEADER = re.compile(r"^\s*Interface\s+Down\s+Attempt\s+Init\s+TwoWay\s+ExStart\s+Exchange\s+Loading\s+Full\s+Total\s*$")
_SUMMARY_ROW = re.compile(r"^\s*(\S+)\s+((?:\d+\s+){8}\d+)\s*$")
_STATES = ("down", "attempt", "init", "twoway", "exstart", "exchange", "loading", "full")

# RFC 2328 10.1, in the words of the RFC's own one-line definitions
STATE_MEANING = {
    "DOWN": "no recent information has been received from the neighbour",
    "ATTEMPT": "no recent information has been received from the neighbour; the router is trying to reach it (non-broadcast networks only)",
    "INIT": "a Hello was seen from the neighbour, but bidirectional communication is not established (this router is not listed in the neighbour's Hello)",
    "EXSTART": "the first step of creating an adjacency: deciding who is master and the initial sequence number of the database exchange",
    "EXCHANGE": "the router is sending Database Description packets that describe its whole link-state database",
    "LOADING": "Link State Request packets are sent to the neighbour for advertisements that are missing or out of date",
}


def parse_neighbors(lines: list[str]) -> list[dict[str, str]]:
    """Every adjacency row of one ``show ip ospf neighbors`` output, with the process and VRF printed above its table (empty on IOS)."""
    rows: list[dict[str, str]] = []
    process, vrf, time_kind = "", "", "up"
    for raw in lines:
        found = _PROCESS.match(raw)
        if found and "Neighbor Summary" not in raw:
            process, vrf = found.group(1), found.group(2) or ""
            continue
        found = _HEADER.match(raw)
        if found:
            time_kind = "up" if found.group(1) == "Up Time" else "dead"
            continue
        found = _ROW.match(raw)
        if found:
            rows.append({"process": process, "vrf": vrf, "neighbor_id": found.group(1), "priority": found.group(2), "state": found.group(3), "role": "" if found.group(4) in (None, "-") else found.group(4),
                         "time": found.group(5), "time_kind": time_kind, "address": found.group(6), "interface": found.group(7)})
    return rows


def parse_reported_totals(lines: list[str]) -> dict[tuple[str, str], int]:
    """``Total number of neighbors: n`` per (process, VRF)."""
    totals: dict[tuple[str, str], int] = {}
    key = ("", "")
    for raw in lines:
        found = _PROCESS.match(raw)
        if found and "Neighbor Summary" not in raw:
            key = (found.group(1), found.group(2) or "")
            continue
        found = _TOTAL.match(raw)
        if found:
            totals[key] = int(found.group(1))
    return totals


def parse_summary(lines: list[str]) -> list[dict[str, Any]]:
    """``show ip ospf neighbors summary``: per process and interface, the neighbour count of each state (the ``Total`` row first)."""
    rows: list[dict[str, Any]] = []
    process, vrf, in_table = "", "", False
    for raw in lines:
        found = _PROCESS.match(raw)
        if found:
            process, vrf, in_table = found.group(1), found.group(2) or "", False
            continue
        if _SUMMARY_HEADER.match(raw):
            in_table = True
            continue
        if not in_table:
            continue
        found = _SUMMARY_ROW.match(raw)
        if found:
            numbers = [int(value) for value in found.group(2).split()]
            row: dict[str, Any] = {"process": process, "vrf": vrf, "interface": "All interfaces" if found.group(1).lower() == "total" else found.group(1)}
            row.update(dict(zip(_STATES, numbers[:8])))
            row["total"] = numbers[8]
            rows.append(row)
    return rows


def read(clean: list[str], host: str | None = None) -> dict[str, Any]:
    """``{"neighbors": [...], "summary": [...], "reported": {(process, vrf): n}}`` from every OSPF neighbour command of the capture (``host``: see ``fhrp_live.read``)."""
    def keep(index: int) -> bool:
        return host is None or capture_text.prompt_host(clean[index]) in (None, host)

    neighbors: list[dict[str, str]] = []
    reported: dict[tuple[str, str], int] = {}
    for index, block in capture_text.find_blocks(clean, PATTERN_NEIGHBORS):
        if not keep(index) or not block or re.match(r"^\s*(?:%|\^\s*$)", block[0]):
            continue
        rows = parse_neighbors(block)
        if len(rows) >= len(neighbors):       # the same command run twice: the later, fuller copy is the one read
            neighbors, reported = rows, parse_reported_totals(block)
    summary: list[dict[str, Any]] = []
    for index, block in capture_text.find_blocks(clean, PATTERN_SUMMARY):
        if not keep(index) or not block or re.match(r"^\s*(?:%|\^\s*$)", block[0]):
            continue
        rows = parse_summary(block)
        if len(rows) >= len(summary):
            summary = rows
    return {"neighbors": neighbors, "summary": summary, "reported": reported}


def _is_full(row: dict[str, str]) -> bool:
    return row["state"].upper() == "FULL"


def findings(neighbors: list[dict[str, str]]) -> list[dict[str, Any]]:
    """An adjacency that is neither Full nor a legitimate 2-Way between two DROTHER routers."""
    from features.analyzer_core.findings import finding

    out = []
    for row in neighbors:
        state = row["state"].upper()
        if state == "FULL" or (state == "2WAY" and row["role"].upper() == "DROTHER"):
            continue
        meaning = STATE_MEANING.get(state, "")
        if state == "2WAY":
            meaning = "two-way communication exists, but no adjacency was formed; on a broadcast network that is normal only between two routers that are neither DR nor BDR"
        where = f"{row['neighbor_id']} on {row['interface']}" + (f" (process {row['process']}" + (f", VRF {row['vrf']}" if row["vrf"] else "") + ")" if row["process"] else "")
        out.append(finding(
            "SW-OSPF-001", "high", "Routing", f"OSPF neighbour is {row['state']}, not Full",
            obj=where,
            detail=f"The neighbour has not reached Full: {meaning}. Routes through it are not exchanged until the adjacency completes.",
            recommendation=("Check that the MTU is the same on both ends of the link (`show interface <name>`), the most common reason for a neighbour that stays in ExStart / Exchange; "
                            "then compare the hello / dead timers, area, authentication and the router IDs of the two routers (`show ip ospf interface <name>`)."),
            reference=DOCS["exstart"][1] if state in {"EXSTART", "EXCHANGE"} else DOCS["rfc"][1]))
    return out


def tables(view: dict[str, Any]) -> list[dict[str, Any]]:
    """The two tables of the Routing tab."""
    out: list[dict[str, Any]] = []
    neighbors = view["neighbors"]
    if neighbors:
        kind = "Dead time" if any(row["time_kind"] == "dead" for row in neighbors) else "Up time"
        columns = [{"key": "process", "label": "Process"}, {"key": "vrf", "label": "VRF"}, {"key": "neighbor_id", "label": "Neighbor ID"}, {"key": "priority", "label": "Pri"},
                   {"key": "state", "label": "State", "status": True,
                    "tones": {"full": "ok", "2way": "mute", "init": "bad", "exstart": "bad", "exchange": "bad", "loading": "warn", "down": "bad", "attempt": "bad"}},
                   {"key": "role", "label": "Role"}, {"key": "time", "label": kind}, {"key": "address", "label": "Address"}, {"key": "interface", "label": "Interface"}]
        if not any(row["process"] for row in neighbors):
            columns = [column for column in columns if column["key"] != "process"]
        if not any(row["vrf"] for row in neighbors):
            columns = [column for column in columns if column["key"] != "vrf"]
        rows = [dict(row, role=row["role"] or "—", state=row["state"].upper(), process=row["process"] or "—", vrf=row["vrf"] or "—") for row in neighbors]
        full = sum(1 for row in neighbors if _is_full(row))
        hint = (f"{len(neighbors)} adjacenc{'y' if len(neighbors) == 1 else 'ies'} from the device, {full} Full. Role is the neighbour's role on the segment (DR, BDR, DROTHER). "
                "Two DROTHER routers stay in 2-Way by design; any other state short of Full is flagged on the Findings tab.")
        out.append({"tab": "routing", "id": "ospf-neighbors", "title": "OSPF neighbours (show ip ospf neighbors)", "hint": hint, "columns": columns, "rows": rows})
    summary = view["summary"]
    if summary:
        used = [state for state in _STATES if state in {"full"} or any(row[state] for row in summary)]
        labels = {"down": "Down", "attempt": "Attempt", "init": "Init", "twoway": "2-Way", "exstart": "ExStart", "exchange": "Exchange", "loading": "Loading", "full": "Full"}
        columns = [{"key": "process", "label": "Process"}, {"key": "vrf", "label": "VRF"}, {"key": "interface", "label": "Interface"}]
        columns += [{"key": state, "label": labels[state]} for state in used] + [{"key": "total", "label": "Total"}]
        if not any(row["vrf"] for row in summary):
            columns = [column for column in columns if column["key"] != "vrf"]
        out.append({"tab": "routing", "id": "ospf-neighbor-summary", "title": "OSPF neighbours per interface (show ip ospf neighbors summary)",
                    "hint": "How many neighbours each interface has in every state, per OSPF process. The first row of a process is its total.",
                    "columns": columns, "rows": [dict(row) for row in summary]})
    return out


def checks(view: dict[str, Any]) -> list[str]:
    """Places where the commands of one capture disagree (a neighbour table shorter than the device said, the summary against the list)."""
    out = []
    counted: dict[tuple[str, str], int] = {}
    for row in view["neighbors"]:
        key = (row["process"], row["vrf"])
        counted[key] = counted.get(key, 0) + 1
    for key, reported in view["reported"].items():
        if counted.get(key, 0) != reported:
            label = f"process {key[0]}" + (f", VRF {key[1]}" if key[1] else "") if key[0] else "the neighbour table"
            out.append(f"show ip ospf neighbors says {reported} neighbour(s) for {label}, the table lists {counted.get(key, 0)}")
    totals = {(row["process"], row["vrf"]): row["total"] for row in view["summary"] if row["interface"] == "All interfaces"}
    for key, total in totals.items():
        if key in counted and counted[key] != total:
            out.append(f"show ip ospf neighbors summary says {total} neighbour(s) for process {key[0]}, show ip ospf neighbors lists {counted[key]}")
    return out


def by_interface(neighbors: list[dict[str, str]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in neighbors:
        key = interface_key(row["interface"])
        out[key] = out.get(key, 0) + 1
    return out
