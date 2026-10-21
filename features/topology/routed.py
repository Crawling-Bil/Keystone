"""Routed point-to-point links inferred from interface addresses (/30 and /31 networks shared by two devices)."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any

from .graph import Connection, Graph, Link


def _interfaces(graph: Graph):
    for key, node in graph.nodes.items():
        if not node.captured:
            continue
        for row in node.l3:
            vrf = row["vrf"].lower()
            if row["shutdown"] or "mgmt" in vrf or "management" in vrf or row["name"].lower().startswith(("lo", "mgmt", "nve", "tu")):
                continue
            try:
                interface = ipaddress.ip_interface(f"{row['ip']}/{int(row['prefix_len'])}")
            except ValueError:
                continue
            yield key, row, interface


def infer_routed(graph: Graph) -> list[dict[str, Any]]:
    """Add routed links; returns facts for findings (mask mismatches)."""
    by_net: dict[tuple[str, Any], list[tuple[str, dict, Any]]] = defaultdict(list)
    all_ifaces = list(_interfaces(graph))
    for key, row, interface in all_ifaces:
        if interface.network.prefixlen >= 30:
            by_net[(row["vrf"], interface.network)].append((key, row, interface))
    issues: list[dict[str, Any]] = []
    by_ip: dict[str, str] = {}
    for key, node in graph.nodes.items():
        for ip in node.ips | ({node.mgmt_ip} if node.mgmt_ip else set()):
            by_ip.setdefault(ip, key)
    existing: dict[frozenset, list[Connection]] = defaultdict(list)
    for conn in graph.connections:
        existing[frozenset((conn.a, conn.b))].append(conn)
    for (vrf, network), members in sorted(by_net.items(), key=lambda item: str(item[0][1])):
        nodes = {m[0] for m in members}
        subnet = str(network)
        if len(members) == 1:
            # the other end is not captured: it still counts when some known device advertises that address
            a, row_a, if_a = members[0]
            peers = [str(host) for host in network.hosts() if host != if_a.ip] if network.prefixlen == 30 else [str(h) for h in network if h != if_a.ip]
            b = next((by_ip[p] for p in peers if p in by_ip and by_ip[p] != a), "")
            if not b:
                continue
            peer_ip = next(p for p in peers if by_ip.get(p) == b)
            row_b, if_b = {"name": ""}, ipaddress.ip_interface(f"{peer_ip}/{network.prefixlen}")
        elif len(members) == 2 and len(nodes) == 2:
            (a, row_a, if_a), (b, row_b, if_b) = sorted(members, key=lambda m: m[0])
        else:
            continue
        match = None
        for conn in existing.get(frozenset((a, b)), []):
            near_a, near_b = (conn.a_po, conn.b_po) if conn.a == a else (conn.b_po, conn.a_po)
            ports_a = {l.a_port if l.a == a else l.b_port for l in conn.links}
            ports_b = {l.b_port if l.b == b else l.a_port for l in conn.links}
            if (row_a["name"] and row_a["name"] in ports_a | {near_a}) or (row_b["name"] and row_b["name"] in ports_b | {near_b}):
                match = conn
                break
        if match is not None:
            match.subnet = subnet
            match.ip_a, match.ip_b = (str(if_a.ip), str(if_b.ip)) if match.a == a else (str(if_b.ip), str(if_a.ip))
            continue
        link = Link(a, row_a["name"], b, row_b["name"], "inferred", {"L3"}, f"{subnet}: {if_a.ip} <-> {if_b.ip}")
        conn = Connection(a, b, [link], kind="routed", subnet=subnet, ip_a=str(if_a.ip), ip_b=str(if_b.ip))
        graph.links.append(link)
        graph.connections.append(conn)
        existing[frozenset((a, b))].append(conn)
    # TOPO-012: an address inside another device's /30 or /31 with a different mask
    small = [(k, r, i) for k, r, i in all_ifaces if i.network.prefixlen >= 30]
    for k1, r1, i1 in small:
        for k2, r2, i2 in all_ifaces:
            if k1 != k2 and r1["vrf"] == r2["vrf"] and i2.ip in i1.network and i2.network.prefixlen != i1.network.prefixlen and str(i1.ip) < str(i2.ip):
                issues.append({"type": "mask-mismatch", "a": k1, "a_if": f"{r1['name']} {i1}", "b": k2, "b_if": f"{r2['name']} {i2}"})
    return issues
