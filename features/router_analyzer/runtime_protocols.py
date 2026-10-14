"""``show ip protocols``: one record per routing protocol the router runs.

Read from a real ASR1002-X capture (OSPF as an ASBR with redistribution, BGP with a route-map on every neighbor).  A router that runs
no routing protocol prints only ``*** IP Routing is NSF aware ***``.

The age in "Routing Information Sources" is the time since the last update *from that source*: on a stable network it grows for years
(real capture: OSPF sources at ``6y49w``), so it is shown as printed and never judged.
"""

from __future__ import annotations

import re
from typing import Any

_HEAD = re.compile(r'^Routing Protocol is "([^"]+)"\s*$')
_SOURCE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\S+)\s*$")
_NETWORK_OSPF = re.compile(r"^(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+area\s+(\S+)\s*$")
_AREAS = re.compile(r"(\d+)\.\s*(\d+) normal (\d+) stub (\d+) nssa")
_REDIST_LINE = re.compile(r"^(\S+(?: \d+)?)\s+(?:with\s+)?(.*)$")
_NEIGHBOR_COLUMNS = {"FiltIn": "filter_in", "FiltOut": "filter_out", "DistIn": "distance_in", "DistOut": "distance_out", "Weight": "weight", "RouteMap": "route_map"}


def _redistribution(entry: str) -> dict[str, str]:
    """``bgp 64512 with metric mapped to 10, includes subnets in redistribution`` -> source ``bgp 64512``, detail; ``ospf 172 (internal)``."""
    text = entry.strip().rstrip(",")
    inner = re.fullmatch(r"(\S+(?: \d+)?)\s+\((.+)\)", text)
    if inner:
        return {"source": inner.group(1), "detail": inner.group(2)}
    with_detail = re.match(r"^(\S+(?: \d+)?)\s+with\s+(.*)$", text)
    if with_detail:
        return {"source": with_detail.group(1), "detail": with_detail.group(2).replace(" in redistribution", "")}
    return {"source": text, "detail": ""}


def _neighbor_columns(header: str) -> list[tuple[str, int, int]]:
    return [(_NEIGHBOR_COLUMNS[m.group(0)], m.start(), m.end()) for m in re.finditer(r"\S+", header) if m.group(0) in _NEIGHBOR_COLUMNS]


def _neighbor(line: str, columns: list[tuple[str, int, int]]) -> dict[str, str] | None:
    tokens = [(m.group(0), m.start(), m.end()) for m in re.finditer(r"\S+", line)]
    if not tokens or not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", tokens[0][0]):
        return None
    row = {"address": tokens[0][0], "filter_in": "", "filter_out": "", "distance_in": "", "distance_out": "", "weight": "", "route_map": ""}
    route_map_start = next((start for key, start, _end in columns if key == "route_map"), None)
    for value, start, end in tokens[1:]:
        if route_map_start is not None and start >= route_map_start - 1 and not value.isdigit():
            row["route_map"] = value
            continue
        # the numbers are printed right-aligned under their column title
        key = next((k for k, _s, e in columns if e == end), None) or next((k for k, s, e in columns if s <= start < e), None)
        if key:
            row[key] = value
        elif route_map_start is not None and start >= route_map_start:
            row["route_map"] = value
    return row


def parse_ip_protocols(lines: list[str]) -> list[dict[str, Any]]:
    """Protocol records: name, router id, role, areas, redistribution, networks, passive interfaces, information sources, BGP neighbor policy."""
    protocols: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    mode = ""
    columns: list[tuple[str, int, int]] = []
    for raw in lines:
        text = raw.strip()
        head = _HEAD.match(text)
        if head:
            name = head.group(1)
            words = name.split()
            cur = {"name": name, "kind": words[0], "id": " ".join(words[1:]), "router_id": "", "asbr": False, "areas": "", "max_paths": None, "redistribute": [], "networks": [], "passive": [], "sources": [],
                   "neighbors": [], "distance": "", "incoming_filter": "", "outgoing_filter": "", "notes": []}
            protocols.append(cur)
            mode = ""
            continue
        if cur is None:
            continue
        if not text:
            mode = ""
            continue
        if text.startswith("Router ID "):
            cur["router_id"] = text.split(None, 2)[2]
            mode = ""
        elif "autonomous system boundary router" in text:
            cur["asbr"] = True
            mode = ""
        elif text.startswith("Number of areas in this router is"):
            body = text.split(" is ", 1)[1].strip()
            found = _AREAS.search(body)
            cur["areas"] = f"{found.group(1)} ({found.group(2)} normal, {found.group(3)} stub, {found.group(4)} nssa)" if found else body
            mode = ""
        elif text.startswith("Maximum path:"):
            digits = text.split(":", 1)[1].strip()
            cur["max_paths"] = int(digits) if digits.isdigit() else None
            mode = ""
        elif text.startswith("Redistributing External Routes from"):
            mode = "redistribute"
        elif text.startswith("Redistributing:"):
            cur["redistribute"] = [_redistribution(part) for part in re.split(r",\s*(?![^()]*\))", text.split(":", 1)[1]) if part.strip()]
            mode = ""
        elif text.startswith("Routing for Networks"):
            mode = "networks"
        elif text.startswith("Passive Interface"):
            mode = "passive"
        elif text.startswith("Routing Information Sources"):
            mode = "sources"
        elif text.startswith("Neighbor(s):"):
            mode = "neighbors"
            columns = []
        elif text.startswith("Distance:"):
            cur["distance"] = text.split(":", 1)[1].strip()
            mode = ""
        elif text.startswith("Outgoing update filter list"):
            cur["outgoing_filter"] = text.rsplit(" is ", 1)[-1]
        elif text.startswith("Incoming update filter list"):
            cur["incoming_filter"] = text.rsplit(" is ", 1)[-1]
        elif mode == "redistribute":
            cur["redistribute"].append(_redistribution(text))
        elif mode == "networks":
            ospf = _NETWORK_OSPF.match(text)
            if ospf:
                cur["networks"].append({"network": ospf.group(1), "wildcard": ospf.group(2), "area": ospf.group(3)})
            elif re.fullmatch(r"\S+(?:\s+\S+)?", text):
                parts = text.split()
                cur["networks"].append({"network": parts[0], "wildcard": parts[1] if len(parts) > 1 else "", "area": ""})
        elif mode == "passive":
            cur["passive"].extend(text.split())
        elif mode == "sources":
            source = _SOURCE.match(text)
            if source:
                cur["sources"].append({"gateway": source.group(1), "distance": int(source.group(2)), "last_update": source.group(3)})
        elif mode == "neighbors":
            if text.startswith("Address"):
                columns = _neighbor_columns(raw)
                continue
            row = _neighbor(raw, columns)
            if row:
                cur["neighbors"].append(row)
        else:
            cur["notes"].append(text)
    return protocols
