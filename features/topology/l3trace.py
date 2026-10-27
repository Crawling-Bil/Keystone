"""Path trace over the L3 model: where does a device send a packet to an address, hop by hop, according to its routing table.

This is routing intent, not measured traffic: at each device the connected subnets and the routes read from the capture are searched for
the longest prefix that contains the destination, the next hop is mapped to the device that owns that address, and the walk continues
there.  Only the best routes a capture holds are known (a ``show ip route`` lists the winners), equal-cost alternatives are reported but
only the first is followed, and the walk stops at a device nobody captured.  Policy routing, ACLs, NAT, PBR and SD-WAN data policy are not
evaluated.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .l3engine import L3Model

MAX_HOPS = 16


def _vrf(value: str) -> str:
    return value if value and value.lower() not in ("global", "default") else "global"


def trace_data(graph, model: L3Model, ids: dict[int, str]) -> dict[str, Any]:
    """Everything ``trace`` needs, as plain JSON (written next to the export so the page can ask for traces later)."""
    devices: dict[str, Any] = {}
    owners: dict[str, list[str]] = {}
    for key, node in graph.nodes.items():
        if not node.captured or not (node.l3 or node.l3facts.get("routes")):
            continue
        interfaces = [{"name": r["name"], "ip": r["ip"], "plen": r.get("prefix_len"), "vrf": _vrf(str(r.get("vrf", ""))), "shutdown": bool(r.get("shutdown"))} for r in node.l3 if r.get("ip") and r.get("prefix_len")]
        routes = [{"vrf": _vrf(str(r.get("vrf", ""))), "protocol": r.get("protocol", ""), "next_hop": r.get("next_hop", ""), "interface": r.get("interface", ""), "prefixes": list(r.get("prefixes", [])), "default": bool(r.get("default"))}
                  for r in node.l3facts.get("routes", [])]
        devices[key] = {"name": node.hostname, "interfaces": interfaces, "routes": routes}
        for row in interfaces:
            owners.setdefault(row["ip"], [key, row["name"], row["vrf"]])
    via: dict[str, str] = {}
    pairs: dict[str, list[str]] = {}
    for edge in model.edges:
        ident = ids[id(edge)]
        for route in edge.routes:
            via[f"{route['device']}|{route['next_hop']}"] = ident
        if edge.kind in ("p2p", "peering", "tunnel", "overlay"):
            pairs.setdefault("|".join(sorted((edge.a, edge.b))), []).append(ident)
        elif edge.kind == "segment":
            pairs.setdefault(f"seg|{edge.b}", []).append(ident)
    seg_of = {edge.a: edge.b for edge in model.edges if edge.kind == "segment"}
    segments: dict[str, list[str]] = {}
    for edge in model.edges:
        if edge.kind == "segment":
            segments.setdefault(edge.subnet, []).append(f"{edge.a}|{ids[id(edge)]}")
    return {"devices": devices, "owners": owners, "via": via, "pairs": pairs, "segments": segments, "seg_of": seg_of}


def _resolve(data: dict[str, Any], source: str) -> str | None:
    low = source.strip().lower()
    for key, dev in data["devices"].items():
        if low in (key.lower(), dev["name"].lower()):
            return key
    try:
        ip = str(ipaddress.ip_address(low))
    except ValueError:
        return None
    owner = data["owners"].get(ip)
    return owner[0] if owner else None


def _lpm(rows: list[tuple[Any, dict[str, Any]]], dst: Any) -> list[tuple[Any, dict[str, Any]]]:
    best = -1
    out: list[tuple[Any, dict[str, Any]]] = []
    for network, row in rows:
        if dst in network:
            if network.prefixlen > best:
                best, out = network.prefixlen, [(network, row)]
            elif network.prefixlen == best:
                out.append((network, row))
    return out


def trace(data: dict[str, Any], source: str, destination: str, vrf: str = "") -> dict[str, Any]:
    """Hops from ``source`` (hostname or one of its addresses) to ``destination``; ``edge_ids`` are the L3 lines the path uses."""
    try:
        dst = ipaddress.ip_address(destination.strip())
    except ValueError:
        return {"ok": False, "error": "The destination is not an IP address."}
    start = _resolve(data, source)
    if start is None:
        return {"ok": False, "error": "The source is not a captured device or one of its addresses."}
    here, table = start, _vrf(vrf)
    hops: list[dict[str, Any]] = []
    edge_ids: list[str] = []
    seen: set[tuple[str, str]] = set()
    message = ""
    arrived = False
    for _ in range(MAX_HOPS):
        dev = data["devices"][here]
        if (here, table) in seen:
            message = f"Loop: the packet comes back to {dev['name']}."
            hops.append({"device": dev["name"], "vrf": table, "action": message, "edges": []})
            break
        seen.add((here, table))
        owner = data["owners"].get(str(dst))
        if owner and owner[0] == here:
            hops.append({"device": dev["name"], "vrf": table, "action": f"{dst} is an address of this device ({owner[1]}).", "edges": []})
            arrived, message = True, f"Arrived at {dev['name']}."
            break
        connected = [(ipaddress.ip_interface(f"{r['ip']}/{r['plen']}").network, r) for r in dev["interfaces"] if r["vrf"] == table and not r["shutdown"]]
        routed = [(ipaddress.ip_network(p, strict=False), r) for r in dev["routes"] if r["vrf"] == table for p in r["prefixes"]]
        conn = _lpm(connected, dst)
        rte = _lpm(routed, dst)
        if conn and (not rte or conn[0][0].prefixlen >= rte[0][0].prefixlen):
            network, row = conn[0]
            held = data["owners"].get(str(dst))
            if held and held[0] != here and held[2] == table:
                pair = data["pairs"].get("|".join(sorted((here, held[0]))), [])
                seg = [i.split("|")[1] for s, members in data["segments"].items() if ipaddress.ip_network(s) == network for i in members if i.split("|")[0] in (here, held[0])]
                ids = pair[:1] or seg
                edge_ids += ids
                hops.append({"device": dev["name"], "vrf": table, "action": f"{dst} is in the connected subnet {network} ({row['name']}); {data['devices'][held[0]]['name']} owns it.", "edges": ids})
                here = held[0]
                continue
            hops.append({"device": dev["name"], "vrf": table, "action": f"{dst} is in the connected subnet {network} ({row['name']}); it is delivered on the LAN (a host or a device nobody captured).", "edges": []})
            arrived, message = True, f"Delivered into {network} on {dev['name']} {row['name']}."
            break
        if not rte:
            hops.append({"device": dev["name"], "vrf": table, "action": f"No route to {dst} in the routing table of VRF {table}.", "edges": []})
            message = f"{dev['name']} has no route to {dst}."
            break
        network, row = rte[0]
        extra = f" ({len(rte) - 1} equal-cost alternative(s) exist; the first is followed)" if len(rte) > 1 else ""
        label = f"{network} via {row['next_hop']} ({row['protocol']})" + (f" out {row['interface']}" if row["interface"] else "")
        ident = data["via"].get(f"{here}|{row['next_hop']}", "")
        held = data["owners"].get(row["next_hop"])
        if ident:
            edge_ids.append(ident)
        if held and held[0] != here:
            hops.append({"device": dev["name"], "vrf": table, "action": f"Route {label}; the next hop belongs to {data['devices'][held[0]]['name']}.{extra}", "edges": [ident] if ident else []})
            here = held[0]
            continue
        hops.append({"device": dev["name"], "vrf": table, "action": f"Route {label}; the next hop is not a captured device, so the trace ends there.{extra}", "edges": [ident] if ident else []})
        message = f"The packet leaves the captured network through {row['next_hop']}."
        break
    else:
        message = f"Stopped after {MAX_HOPS} hops."
    return {"ok": True, "arrived": arrived, "message": message, "hops": hops, "edge_ids": list(dict.fromkeys(i for i in edge_ids if i)), "vrf": table}
