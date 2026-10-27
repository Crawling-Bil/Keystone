"""The logical IP view: which devices share a subnet, and every interface address of a device in a table under the picture.

The physical view answers "which cable goes where".  This view answers "how does an IP packet get from A to B": two devices that
own addresses in the same subnet are joined by one line labelled with the interface and address at each end (``Gi0/0/0
192.168.161.238/29``), and a subnet shared by more than two devices (a VLAN with several SVIs, a LAN segment) is drawn as one
yellow oval that every member connects to.  Loopbacks and /32 addresses are not links; they are listed in the tables.

Under the picture each device with two or more interface addresses gets a table: interface, description, address/prefix, VRF, state.
A device that nobody captured (a provider router named by a port description, an access point) takes part when an ARP table gave
its address and that address falls inside a captured interface's subnet.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any

from .extract import Device
from .graph import Connection, Graph, Link
from .layout import MARGIN, NODE_H, NODE_W, layered
from .names import port_sort_key
from .roles import ROLE_LABEL
from .scene import ROW_H, Page, TableBox, _route, table_columns
from .labelplace import place_labels

MAX_SEGMENT_LINES = 24
MERGE_PAIR_OVER = 3       # more than this many subnets shared by the same two devices are drawn as one line
TABLE_CHUNK = 40
TABLE_GAP = 26
VIEW_NAME = "IP view"
_MGMT = ("mgmt", "management", "oob")


def _skip_interface(row: dict[str, Any]) -> bool:
    vrf, name = str(row.get("vrf", "")).lower(), str(row.get("name", "")).lower()
    return bool(row.get("shutdown")) or any(w in vrf for w in _MGMT) or name.startswith(("mgmt", "vmanage", "nvi"))


def _networks(graph: Graph) -> dict[tuple[str, Any], list[tuple[str, dict[str, Any], Any]]]:
    nets: dict[tuple[str, Any], list[tuple[str, dict[str, Any], Any]]] = defaultdict(list)
    for key, node in graph.nodes.items():
        if not node.captured or key in graph.hidden_nodes:
            continue
        for row in node.l3:
            if _skip_interface(row) or str(row.get("kind", "")).lower() == "loopback" or str(row.get("name", "")).lower().startswith(("lo", "loopback")):
                continue
            try:
                interface = ipaddress.ip_interface(f"{row['ip']}/{int(row['prefix_len'])}")
            except (ValueError, KeyError, TypeError):
                continue
            if interface.network.prefixlen >= 32:
                continue
            nets[("", interface.network)].append((key, row, interface))     # VRF names are local to a device: the subnet decides
    return nets


def _far_port(graph: Graph, key: str, other: str) -> str:
    for link in graph.links:
        if link.a == other and link.b == key and link.b_port == "":
            return link.a_port
        if link.b == other and link.a == key and link.a_port == "":
            return link.b_port
    return ""


def _uncaptured_members(graph: Graph, network: Any, taken: set[str]) -> list[tuple[str, dict[str, Any], Any]]:
    out = []
    for key, node in graph.nodes.items():
        if node.captured or key in taken or key in graph.hidden_nodes or node.role_hint in ("host", "phone", "server", "segment"):
            continue
        for ip in sorted(node.ips | ({node.mgmt_ip} if node.mgmt_ip else set())):
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if address in network:
                row = {"name": "", "ip": ip, "prefix_len": network.prefixlen, "vrf": "", "description": ""}
                out.append((key, row, ipaddress.ip_interface(f"{ip}/{network.prefixlen}")))
                break
    return out


def _segment_node(network: Any, vrf: str, members: list[tuple[str, dict[str, Any], Any]]) -> Device:
    vlan = next((str(r["name"]) for _, r, _ in members if str(r.get("kind", "")).lower() == "svi" or str(r.get("name", "")).lower().startswith(("vlan", "vl"))), "")
    description = next((str(r.get("description", "")) for _, r, _ in members if r.get("description")), "")
    label = " · ".join(x for x in (vlan.upper().replace("VLAN", "VLAN ") if vlan else "", f"VRF {vrf}" if vrf else "", description[:24]) if x)
    node = Device(key=f"SEG:{vrf}:{network}", hostname=str(network), captured=False, role_hint="segment", model=label)
    shown = min(len(members), MAX_SEGMENT_LINES)
    node.mgmt_ip = f"{len(members)} devices" if shown == len(members) else f"{len(members)} devices ({shown} drawn)"
    return node


def _interface_tables(graph: Graph, keys: list[str]) -> list[TableBox]:
    tables: list[TableBox] = []
    for key in sorted(keys, key=lambda k: graph.nodes[k].hostname):
        node = graph.nodes[key]
        rows = []
        for row in node.l3:
            description = str(row.get("description", "")) or node.descriptions.get(row["name"], "")
            state = "admin down" if row.get("shutdown") else str(row.get("status", "")) or ""
            rows.append([row["name"], description, f"{row['ip']}/{row['prefix_len']}", str(row.get("vrf", "")) or "-", state])
            for extra in row.get("secondary") or []:
                rows.append([row["name"], "secondary", str(extra), str(row.get("vrf", "")) or "-", state])
        if len(rows) < 2:
            continue
        rows.sort(key=lambda r: port_sort_key(r[0]))
        chunks = [rows[i:i + TABLE_CHUNK] for i in range(0, len(rows), TABLE_CHUNK)]
        for n, chunk in enumerate(chunks, 1):
            suffix = f" ({n}/{len(chunks)})" if len(chunks) > 1 else ""
            tables.append(TableBox(f"{node.hostname} · {ROLE_LABEL.get(node.role_hint, node.role_hint)} · {len(rows)} interface address(es){suffix}",
                                   ["Interface", "Description", "IP address / prefix", "VRF", "State"], chunk))
    return tables


def _place_tables(page: Page, tables: list[TableBox], top: float) -> None:
    limit = max(page.width, 1500.0)
    x, y, row_h = float(MARGIN), top, 0.0
    for table in tables:
        table.w = max(sum(table_columns(table)) + 12, len(table.title) * 7.2 + 20)
        table.h = 52 + len(table.rows) * ROW_H + 4
        if x > MARGIN and x + table.w > limit:
            x, y, row_h = float(MARGIN), y + row_h + TABLE_GAP, 0.0
        table.x, table.y = x, y
        x += table.w + TABLE_GAP
        row_h = max(row_h, table.h)
        page.width = max(page.width, table.x + table.w + MARGIN)
    if tables:
        page.height = y + row_h + MARGIN


def ip_page(graph: Graph, curved: bool = False) -> Page | None:
    """The IP view of the whole network, or None when no captured device owns a routed interface address."""
    nets = _networks(graph)
    conns: list[Connection] = []
    links: list[Link] = []
    nodes: dict[str, Device] = {}
    pairs: dict[tuple[str, str], list[Connection]] = defaultdict(list)
    for (vrf, network), members in sorted(nets.items(), key=lambda item: (item[0][0], int(item[0][1].network_address), item[0][1].prefixlen)):
        devices = {m[0] for m in members}
        members = members + _uncaptured_members(graph, network, devices)
        by_device: dict[str, tuple[str, dict[str, Any], Any]] = {}
        for member in members:
            by_device.setdefault(member[0], member)
        if len(by_device) < 2:
            continue
        ordered = sorted(by_device.values(), key=lambda m: (graph.nodes[m[0]].role_hint in ("host", "phone"), m[0]))
        if len(ordered) == 2:
            (a, row_a, if_a), (b, row_b, if_b) = ordered
            name_b = row_b["name"] or _far_port(graph, b, a)
            link = Link(a, row_a["name"], b, name_b, "confirmed", {"L3"}, f"{network}: {if_a.ip} <-> {if_b.ip}")
            links.append(link)
            conn = Connection(a, b, [link], kind="l3", subnet=str(network), ip_a=str(if_a.ip), ip_b=str(if_b.ip))
            conns.append(conn)
            pairs[(a, b)].append(conn)
        else:
            segment = _segment_node(network, vrf, ordered)
            nodes[segment.key] = segment
            for key, row, interface in ordered[:MAX_SEGMENT_LINES]:
                link = Link(key, row["name"], segment.key, "", "confirmed", {"L3"}, f"{network}: {interface.ip}")
                links.append(link)
                conns.append(Connection(key, segment.key, [link], kind="l3seg", subnet=str(network), ip_a=str(interface.ip)))
        for key, _, _ in ordered:
            nodes[key] = graph.nodes[key]
    for key, node in graph.nodes.items():                       # captured devices with an address but no shared subnet still belong on the page
        if node.captured and key not in nodes and key not in graph.hidden_nodes and any(not _skip_interface(r) for r in node.l3):
            nodes[key] = node
    for (a, b), group in pairs.items():                         # an SVI pair sharing dozens of VLANs is one line, not dozens
        if len(group) > MERGE_PAIR_OVER:
            first = group[0]
            first.links = [c.links[0] for c in group]
            first.subnet = first.ip_a = first.ip_b = ""
            for extra in group[1:]:
                conns.remove(extra)
    if not conns:
        return None
    sub = Graph(nodes=nodes, links=links, connections=conns, hidden_kinds=set())
    placed, width, height = layered(sub, list(nodes))
    page = Page(VIEW_NAME, placed, set(), [], conns, {}, width, height, view="ip", graph=sub, curved=curved)
    _route(page)
    place_labels(page, sub, True)
    tables = _interface_tables(graph, [k for k in nodes if k in graph.nodes and graph.nodes[k].captured])
    page.tables = tables
    _place_tables(page, tables, height + 20)
    return page
