"""Spanning-tree ports in an *inconsistent* (blocked-by-protection) state, from ``show spanning-tree inconsistentports`` (IOS / IOS XE).

The Spanning Tree protection features (root guard, loop guard, BPDU guard on a trunk, PVID / port-type mismatch) do not drop a port; they put it in a
``*_INC`` state in which it forwards nothing for that VLAN until the cause is gone.  The command lists every such port with the reason.  An empty table
and ``Number of inconsistent ports (segments) in the system : 0`` is the all-clear; the layout of the empty case was read from Catalyst 9300 / Nexus
captures of ours, the row layout follows the Cisco command reference (one row per VLAN and port: ``VLAN0010  GigabitEthernet1/0/1  Root Inconsistent``).

Source: Cisco IOS XE, Spanning Tree Protocol configuration guide, "Spanning-tree protection" / ``show spanning-tree inconsistentports``:
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/lyr2/b_179_lyr2_9300_cg/configuring_spanning_tree_protocol.html
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text

PATTERN = (r"sh(?:ow)? spanning-tree inconsistentports",)
DOC = "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/lyr2/b_179_lyr2_9300_cg/configuring_spanning_tree_protocol.html"
_ROW = re.compile(r"^(?P<instance>(?:VLAN|MST)\d+)\s+(?P<port>\S+)\s+(?P<reason>\S.*?)\s*$", re.IGNORECASE)
_COUNT = re.compile(r"Number of inconsistent ports \(segments\) in the system\s*:\s*(?P<n>\d+)", re.IGNORECASE)


def read(clean: list[str], host: str | None = None) -> dict[str, Any]:
    """``{"captured": bool, "count": int | None, "ports": [{"instance", "port", "reason"}]}``."""
    view: dict[str, Any] = {"captured": False, "count": None, "ports": []}
    for index, block in capture_text.find_blocks(clean, PATTERN):
        if host is not None and capture_text.prompt_host(clean[index]) not in (None, host):
            continue
        if not block or re.match(r"^\s*(?:%|\^|invalid\b)", block[0], re.IGNORECASE):
            continue
        ports = []
        count = None
        for line in block:
            match = _COUNT.search(line)
            if match:
                count = int(match.group("n"))
                continue
            match = _ROW.match(line.strip())
            if match:
                ports.append({"instance": match.group("instance").upper(), "port": match.group("port"), "reason": match.group("reason")})
        if count is not None or ports:
            view = {"captured": True, "count": count if count is not None else len(ports), "ports": ports}
    return view


def findings(view: dict[str, Any]) -> list[dict[str, Any]]:
    from features.analyzer_core.findings import finding

    if not view.get("count"):
        return []
    ports = view.get("ports") or []
    shown = ", ".join(f"{item['port']} ({item['instance']}: {item['reason']})" for item in ports[:6]) + (" ..." if len(ports) > 6 else "")
    return [finding(
        "SW-STP-102", "high", "Spanning tree", f"{view['count']} port(s) are blocked by a spanning-tree protection (inconsistent state)",
        obj="spanning-tree inconsistentports",
        detail="The device lists these ports as inconsistent, so they forward nothing for the VLAN until the cause is removed" + (": " + shown if shown else "") + ".",
        recommendation="Read the reason per port: Root Inconsistent (a neighbour sends a superior BPDU on a root-guard port), Loop Inconsistent (BPDUs stopped on a loop-guard port), "
                       "Type / PVID Inconsistent (trunk or native-VLAN mismatch). Fix the neighbour or the port configuration; the port recovers by itself.",
        reference=DOC)]


def counts(view: dict[str, Any]) -> dict[str, int]:
    return {"stp_inconsistent": 1 if view.get("captured") else 0}
