"""FortiOS ``get`` / ``diagnose`` output that complements the configuration.

These parsers follow the documented FortiOS output formats.  They have not
been run against a captured FortiGate yet, so the service lists whichever of
them produced data in the result's warnings (see ``service.UNVALIDATED``).
Everything is optional: the analysis works from the configuration alone.
"""

from __future__ import annotations

import re
from typing import Any

from ..analyzer_core import capture as cap

_KV = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9 /_\-\.\(\)]*?):\s*(?P<value>.*)$")
_ROUTE = re.compile(
    r"^(?P<code>[A-Z][A-Z0-9*]*(?:\s[A-Z0-9*]+)?)\s+(?P<prefix>\d+\.\d+\.\d+\.\d+/\d+)\s+"
    r"(?:\[(?P<dist>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<via>\S+?)(?:\s+\([^)]*\))?,\s*(?P<intf>[^,\s]+)|is directly connected,\s*(?P<cintf>\S+))"
)
_BGP_NEIGHBOR = re.compile(r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<ver>\d)\s+(?P<asn>\d+)\s+(?P<rcvd>\d+)\s+(?P<sent>\d+)\s+(?P<tblver>\d+)\s+(?P<inq>\d+)\s+(?P<outq>\d+)\s+(?P<updown>\S+)\s+(?P<state>\S+)\s*$")
_IPSEC = re.compile(r"^'(?P<name>[^']+)'\s+(?P<remote>\S+?)(?::\d+)?\s+selectors\(total,up\):\s*(?P<total>\d+)/(?P<up>\d+)")
_ROUTE_CODES = {"K": "kernel", "C": "connected", "S": "static", "R": "RIP", "B": "BGP", "O": "OSPF", "I": "IS-IS", "IA": "OSPF inter area"}

COMMANDS = (
    ("get system status", "Model, serial, FortiOS build, operation mode, VDOM and HA state, system time."),
    ("get router info routing-table all", "Installed routes by protocol and the default route."),
    ("get router info bgp summary", "BGP neighbour state and prefixes received."),
    ("get vpn ipsec tunnel summary", "IPsec tunnels with selectors up / total."),
    ("get system ha status", "HA cluster members, primary and sync state."),
    ("get system performance status", "CPU, memory and session load at capture time."),
)


def parse_status(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        match = _KV.match(line)
        if match and match["value"].strip():
            out.setdefault(match["key"].strip(), match["value"].strip())
    version = out.get("Version", "")
    model = re.match(r"(?P<model>Forti[A-Za-z]+-[A-Za-z0-9\-]+)\s+v(?P<ver>\d+\.\d+\.\d+),build(?P<build>\d+)", version)
    if model:
        out["_model"], out["_version"], out["_build"] = model["model"], model["ver"], model["build"]
    return out


def parse_routes(text: str) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    vrf = "0"
    for line in text.splitlines():
        vrf_match = re.match(r"Routing table for VRF=(\d+)", line)
        if vrf_match:
            vrf = vrf_match[1]
            continue
        match = _ROUTE.match(line.strip())
        if not match:
            continue
        code = match["code"].replace("*", "").strip()
        routes.append({
            "vrf": vrf, "protocol": _ROUTE_CODES.get(code.split()[0], code), "code": match["code"], "prefix": match["prefix"], "distance": int(match["dist"]) if match["dist"] else 0, "metric": int(match["metric"]) if match["metric"] else 0,
            "next_hop": match["via"] or "", "interface": match["intf"] or match["cintf"] or "", "default": match["prefix"] == "0.0.0.0/0" or "*" in match["code"],
        })
    return routes


def parse_bgp_summary(text: str) -> dict[str, Any]:
    neighbors = []
    header = re.search(r"BGP router identifier (\S+?),\s*local AS number (\d+)", text)
    for line in text.splitlines():
        match = _BGP_NEIGHBOR.match(line.strip())
        if not match:
            continue
        state = match["state"]
        established = state.isdigit()
        neighbors.append({"ip": match["ip"], "remote_as": match["asn"], "up_down": match["updown"], "state": "Established" if established else state, "prefixes": int(state) if established else 0,
                          "msg_rcvd": int(match["rcvd"]), "msg_sent": int(match["sent"])})
    return {"router_id": header[1] if header else "", "local_as": header[2] if header else "", "neighbors": neighbors}


def parse_ipsec_summary(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        match = _IPSEC.match(line.strip())
        if match:
            total, up = int(match["total"]), int(match["up"])
            out.append({"name": match["name"], "remote": match["remote"], "selectors": total, "up": up, "state": "up" if total and up == total else ("partial" if up else "down")})
    return out


def parse_ha(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"members": []}
    for line in text.splitlines():
        match = _KV.match(line)
        if match and match["key"].strip() in ("HA Health Status", "Mode", "Model", "Primary", "Group Name"):
            out[match["key"].strip()] = match["value"].strip()
        member = re.match(r"^(?:Primary|Secondary|Master|Slave)\s*:\s*(?P<host>\S+),\s*(?P<serial>\S+),\s*HA cluster index\s*=\s*(?P<index>\d+)", line.strip())
        if member:
            out["members"].append({"role": line.strip().split(":")[0], "host": member["host"], "serial": member["serial"], "index": member["index"]})
    return out


def gather(content: str) -> dict[str, Any]:
    capture = cap.split_capture(content, [cap.FORTI_PROMPT])
    data: dict[str, Any] = {"capture": capture, "hostname": capture.hostname()}

    def block_text(*templates: str) -> str:
        block = capture.first(*templates)
        return block.text if block else ""

    status = block_text("get system status")
    if status:
        data["status"] = parse_status(status)
    routes = block_text("get router info routing-table all", "get router info routing-table database", "get router info routing-table details")
    if routes:
        data["routes"] = parse_routes(routes)
    bgp = block_text("get router info bgp summary")
    if bgp:
        data["bgp"] = parse_bgp_summary(bgp)
    ipsec = block_text("get vpn ipsec tunnel summary", "get vpn ipsec tunnel details")
    if ipsec:
        data["ipsec"] = parse_ipsec_summary(ipsec)
    ha = block_text("get system ha status", "diagnose sys ha status")
    if ha:
        data["ha"] = parse_ha(ha)
    return data
