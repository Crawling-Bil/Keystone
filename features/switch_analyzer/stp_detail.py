"""``show spanning-tree``: one block per STP instance (per VLAN for PVST / rapid-PVST, ``MST0`` ... for MST).

Each instance prints the root bridge, this bridge, and a port table::

    VLAN0010
      Spanning tree enabled protocol rstp
      Root ID    Priority    32778
                 Address     0249.620c.b000
                 Cost        19
                 Port        4 (FastEthernet0/4)
      Bridge ID  Priority    32778  (priority 32768 sys-id-ext 10)
                 Address     0279.4ed4.ac00
    Interface           Role Sts Cost      Prio.Nbr Type
    Fa0/4               Root FWD 19        128.4    P2p

``Sts`` ``BKN*`` together with ``*TYPE_Inc`` / ``*ROOT_Inc`` / ``*LOOP_Inc`` / ``*PVID_Inc`` is a port the switch
put in a broken (inconsistent) state: Cisco's Root Guard, Loop Guard, BPDU type and PVID inconsistency protection.
This is the same condition that logs ``%SPANTREE-2-*_INCONSIST`` (see ``logs.py``).

Role and state names are those of the Catalyst Layer 2 guide, "Configuring Spanning Tree Protocol":
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/lyr2/b_1712_lyr2_9300_cg/configuring_spanning_tree_protocol.html
"""
from __future__ import annotations

import re
from typing import Any

from . import show_tables

ROLES = {"root": "Root port", "desg": "Designated", "altn": "Alternate", "back": "Backup", "mstr": "Master", "dis": "Disabled", "boun": "Boundary"}
STATES = {"fwd": "Forwarding", "blk": "Blocking", "lrn": "Learning", "lis": "Listening", "bkn": "Broken (inconsistent)", "dis": "Disabled"}
INCONSISTENT = {"TYPE": "Type inconsistent (trunk / access mismatch with the neighbour)", "ROOT": "Root inconsistent (Root Guard)",
                "LOOP": "Loop inconsistent (Loop Guard)", "PVID": "PVID inconsistent (native VLAN mismatch)", "BA": "Bridge Assurance inconsistent"}

_INSTANCE = re.compile(r"^(VLAN\d+|MST\d+)\s*$", re.IGNORECASE)
_PORT_ROW = re.compile(
    r"^(?P<name>\S+)\s+(?P<role>Root|Desg|Altn|Back|Mstr|Dis|Boun)\s+(?P<state>FWD|BLK|LRN|LIS|BKN|DIS)(?P<flag>\*?)\s*"
    r"(?P<cost>\d+)\s+(?P<prio>\d+)\.(?P<number>\d+)\s*(?P<rest>.*)$", re.IGNORECASE)


def _instance(name: str) -> dict[str, Any]:
    vlan = re.match(r"VLAN0*(\d+)$", name, re.IGNORECASE)
    return {"id": name.upper(), "vlan": int(vlan.group(1)) if vlan else None, "protocol": "", "is_root": False,
            "root_priority": None, "root_address": "", "root_cost": None, "root_port": "",
            "bridge_priority": None, "bridge_address": "", "hello": None, "max_age": None, "forward_delay": None,
            "ports": [], "root_ports": 0, "blocking": 0, "inconsistent": 0}


def parse_spanning_tree(lines: list[str]) -> dict[str, Any]:
    instances: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    note = ""
    current: dict[str, Any] | None = None
    side = ""            # "root" | "bridge": which block the Address / Hello lines belong to
    in_ports = False
    for line in lines:
        text = line.strip()
        if not text:
            continue
        if re.match(r"^No spanning tree instance exists", text, re.IGNORECASE):
            note = "No spanning tree instance exists."
            continue
        match = _INSTANCE.match(text) if not line[:1].isspace() else None
        if match:
            name = match.group(1).upper()
            if name not in instances:
                instances[name] = _instance(name)
                order.append(name)
            else:                       # the same instance printed twice: the later copy replaces the earlier one
                instances[name] = _instance(name)
            current, side, in_ports = instances[name], "", False
            continue
        if current is None:
            continue
        match = re.match(r"^Spanning tree enabled protocol (\S+)", text, re.IGNORECASE)
        if match:
            current["protocol"] = match.group(1).lower()
            continue
        match = re.match(r"^Root ID\s+Priority\s+(\d+)", text, re.IGNORECASE)
        if match:
            current["root_priority"], side, in_ports = int(match.group(1)), "root", False
            continue
        match = re.match(r"^Bridge ID\s+Priority\s+(\d+)", text, re.IGNORECASE)
        if match:
            current["bridge_priority"], side, in_ports = int(match.group(1)), "bridge", False
            continue
        if re.match(r"^This bridge is the root", text, re.IGNORECASE):
            current["is_root"] = True
            continue
        if re.match(r"^Interface\s+Role\s+Sts\s+Cost", text, re.IGNORECASE):
            in_ports, side = True, ""
            continue
        if in_ports:
            match = _PORT_ROW.match(text)
            if match:
                rest = match.group("rest").strip()
                flags = re.findall(r"\*([A-Z]+)_Inc", rest)
                role, state = match.group("role").lower(), match.group("state").lower()
                current["ports"].append({
                    "instance": current["id"], "interface": match.group("name"), "role": match.group("role").title(), "role_name": ROLES.get(role, ""),
                    "state": match.group("state").upper(), "state_name": STATES.get(state, ""), "cost": int(match.group("cost")),
                    "priority": int(match.group("prio")), "port_number": int(match.group("number")), "type": re.sub(r"\s*\*[A-Z]+_Inc", "", rest).strip(),
                    "inconsistent": ", ".join(INCONSISTENT.get(flag, flag) for flag in flags) if flags or match.group("flag") else "",
                    "broken": state == "bkn" or bool(flags),
                })
            continue
        if side:
            match = re.match(r"^Address\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", text, re.IGNORECASE)
            if match:
                current[f"{side}_address"] = match.group(1).lower()
                continue
            match = re.match(r"^Cost\s+(\d+)", text, re.IGNORECASE)
            if match and side == "root":
                current["root_cost"] = int(match.group(1))
                continue
            match = re.match(r"^Port\s+(\d+)\s+\((.+?)\)", text, re.IGNORECASE)
            if match and side == "root":
                current["root_port"] = match.group(2)
                continue
            match = re.match(r"^Hello Time\s+(\d+)\s*sec\s+Max Age\s+(\d+)\s*sec\s+Forward Delay\s+(\d+)\s*sec", text, re.IGNORECASE)
            if match and side == "bridge":
                current["hello"], current["max_age"], current["forward_delay"] = (int(match.group(i)) for i in (1, 2, 3))
    result = [instances[name] for name in order]
    for item in result:
        # This bridge is the root when its address is also the root address (a root switch prints no Root ID Cost / Port).
        if item["root_address"] and item["root_address"] == item["bridge_address"]:
            item["is_root"] = True
        item["root_ports"] = sum(1 for port in item["ports"] if port["role"] == "Root")
        item["blocking"] = sum(1 for port in item["ports"] if port["state"] in ("BLK", "BKN"))
        item["inconsistent"] = sum(1 for port in item["ports"] if port["broken"])
    return {"instances": result, "note": note}


def parse_aruba_summary(lines: list[str]) -> dict[str, str]:
    """ArubaOS-Switch ``show spanning-tree`` heads with ``Multiple Spanning Tree (MST) Information`` and a
    ``Key : value`` list ("STP Enabled : No"). Only that list is read; the per-port table is not parsed."""
    if not any(re.match(r"^\s*Multiple Spanning Tree", line, re.IGNORECASE) for line in lines):
        return {}
    out: dict[str, str] = {}
    for line in lines:
        match = re.match(r"^\s*([A-Za-z][A-Za-z0-9 .\-]*?)\s*:\s*(\S.*?)\s*$", line)
        if match and match.group(1) not in out:
            out[match.group(1)] = match.group(2)
    return out


def build_spanning_tree(clean: list[str]) -> dict[str, Any]:
    """Merge every ``show spanning-tree`` / ``... vlan N`` / ``... active`` run in the capture (by instance)."""
    found = show_tables.blocks(clean, "stp")
    merged: dict[str, dict[str, Any]] = {}
    note = ""
    for block in found:
        parsed = parse_spanning_tree(block)
        note = parsed["note"] or note
        for item in parsed["instances"]:
            old = merged.get(item["id"])
            if old is None or len(item["ports"]) >= len(old["ports"]):
                merged[item["id"]] = item
    summary: dict[str, str] = {}
    for block in found:
        summary = parse_aruba_summary(block) or summary
    if summary and not merged:
        note = f"ArubaOS-Switch layout: STP Enabled {summary.get('STP Enabled', '?')}. Only the summary list is read."
    instances = sorted(merged.values(), key=lambda item: (item["vlan"] is None, item["vlan"] or 0, item["id"]))
    ports = [port for item in instances for port in item["ports"]]
    roots = sorted({item["root_address"] for item in instances if item["root_address"]})
    return {
        "captured": bool(found),
        "enabled": bool(instances) or summary.get("STP Enabled", "").lower().startswith("y"),
        "note": note if not instances else "",
        "summary": summary,
        "protocol": next((item["protocol"] for item in instances if item["protocol"]), ""),
        "instances": instances,
        "ports": ports,
        "root_for": [item["id"] for item in instances if item["is_root"]],
        "root_bridges": len(roots),
        "blocking": sum(1 for port in ports if port["state"] in ("BLK", "BKN")),
        "broken": [port for port in ports if port["broken"]],
    }
