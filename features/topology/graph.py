"""Node resolution and link pairing.

Each captured device reports half-edges ("on my port X I see device Y port Z"). A link is *confirmed* when both
ends agree, *single-sided* when only one end reports it (the peer was not captured, or does not run the protocol),
and a *conflict* when the peer's own table says that port faces somebody else. Identity is resolved in this order:
serial number, management/interface IP, short hostname (domain and '(SERIAL)' suffix removed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .extract import Device, HalfEdge
from .names import canon_port, is_ip, port_sort_key, short_host, split_platform

STATE_RANK = {"inferred": 0, "confirmed": 1, "single": 2, "conflict": 3}


@dataclass
class Link:
    a: str
    a_port: str
    b: str
    b_port: str
    state: str
    protocols: set[str] = field(default_factory=set)
    note: str = ""
    native_vlan: str = ""
    duplex: str = ""
    seen_native_a: str = ""     # native (CDP) / port (LLDP) VLAN that end A advertises about itself, as read in B's neighbor table
    seen_native_b: str = ""     # the same for end B, read in A's neighbor table
    a_ip: str = ""              # address/prefix of a routed port at end A (L2 views show it next to the port name)
    b_ip: str = ""

    def swap(self) -> None:
        """Turn the link around (a becomes b) and keep the per-end facts with their end."""
        self.a, self.a_port, self.b, self.b_port = self.b, self.b_port, self.a, self.a_port
        self.seen_native_a, self.seen_native_b = self.seen_native_b, self.seen_native_a
        self.a_ip, self.b_ip = self.b_ip, self.a_ip


@dataclass
class Connection:
    """One line in the diagram: a single link, a port-channel (several links), or unbundled parallel links."""

    a: str
    b: str
    links: list[Link]
    a_po: str = ""
    b_po: str = ""
    kind: str = "link"          # link | bundle | parallel | peer-link | rollup | routed | host
    vpc_id: str = ""
    multi_chassis: bool = False
    subnet: str = ""            # routed point-to-point network, when the two ends share one
    ip_a: str = ""
    ip_b: str = ""
    po_ip_a: str = ""           # address/prefix of the port-channel at end A / B, when it is a routed bundle
    po_ip_b: str = ""
    l3: dict[str, Any] = field(default_factory=dict)    # layer-3 views: what this line stands for (kind, state, vrf, evidence, routes), see l3page

    @property
    def state(self) -> str:
        return max((link.state for link in self.links), key=lambda s: STATE_RANK[s])

    @property
    def protocols(self) -> set[str]:
        return set().union(*(link.protocols for link in self.links))


@dataclass
class Graph:
    nodes: dict[str, Device] = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    issues: list[dict[str, Any]] = field(default_factory=list)   # raw facts for findings.py
    vpc_pairs: list[tuple[str, str, str]] = field(default_factory=list)  # (node, node, domain)
    hosts: list[dict[str, Any]] = field(default_factory=list)            # end hosts learned from MAC / ARP tables
    hidden_kinds: set[str] = field(default_factory=set)                  # connection kinds kept in the tables but left out of the picture
    hidden_nodes: set[str] = field(default_factory=set)                  # nodes left out of the pictures (option "exclude end points"); tables keep them
    f5_hosts: list[dict[str, Any]] = field(default_factory=list)         # hosts read from a BIG-IP ARP table (f5neighbors), added to hosts after the MAC tables
    group_aps: bool = False                                              # access points drawn one by one are framed per switch even when ``group_endpoints`` is off
    group_endpoints: bool = False                                        # option "group end points under the same switch": the layout frames them per switch
    rolled_roles: dict[str, str] = field(default_factory=dict)           # endpoint nodes folded into a rollup box -> their role
    chassis_units: dict[str, list[str]] = field(default_factory=dict)    # firewall chassis name -> the node keys of its VDOMs / vsys


def link_ratings(graph: "Graph", link: Link) -> tuple[int, int]:
    """Rated speed in Mbit/s of both ends of a link (0 = unknown): the transceiver or port-name rating, not the negotiated rate."""
    a, b = graph.nodes.get(link.a), graph.nodes.get(link.b)
    return (a.speeds.get(link.a_port, 0) if a else 0, b.speeds.get(link.b_port, 0) if b else 0)


def link_speeds(graph: "Graph", link: Link) -> tuple[int, int]:
    """Speed in Mbit/s of both ends (0 = unknown): what the port runs at (``show interface status`` / ``show interface``, link up),
    and the rating when the capture holds no operational speed."""
    a, b = graph.nodes.get(link.a), graph.nodes.get(link.b)
    rated = link_ratings(graph, link)
    return (a.actual_speeds.get(link.a_port, 0) if a else 0) or rated[0], (b.actual_speeds.get(link.b_port, 0) if b else 0) or rated[1]


def link_speed(graph: "Graph", link: Link) -> int:
    """What the link can carry: the lower of the two known ends, else the one known end."""
    known = [s for s in link_speeds(graph, link) if s]
    return min(known) if known else 0


def connection_speeds(graph: "Graph", conn: Connection) -> list[int]:
    return [link_speed(graph, link) for link in conn.links]


def _unique_keys(devices: list[Device], graph: Graph) -> None:
    seen: dict[str, Device] = {}
    for device in devices:
        base = device.hostname or "UNKNOWN"
        key = base
        if key in seen:
            if seen[key].serials and device.serials and seen[key].serials & device.serials:
                graph.issues.append({"type": "duplicate-capture", "node": key, "files": [seen[key].source, device.source]})
                continue
            graph.issues.append({"type": "same-hostname", "node": key, "files": [seen[key].source, device.source]})
            n = 2
            while f"{base}#{n}" in seen:
                n += 1
            key = f"{base}#{n}"
        device.key = key
        seen[key] = device
        graph.nodes[key] = device
        if device.chassis:
            graph.chassis_units.setdefault(device.chassis, []).append(key)


def pick_unit(graph: Graph, key: str, port: str = "") -> str:
    """A firewall chassis is drawn as one node per VDOM / vsys, and a neighbor knows only the chassis name and the port: the node that owns ``port``.
    Without a port (or one nobody owns) the first node of the chassis stands for it."""
    node = graph.nodes.get(key)
    if node is None or not node.chassis:
        return key
    units = graph.chassis_units.get(node.chassis) or [key]
    if len(units) > 1 and port:
        want = canon_port(port)
        for unit in units:
            if want in graph.nodes[unit].unit_ports:
                return unit
        if "." in want:                                  # port5.100: the VLAN sub-interface belongs to the VDOM of its parent port
            return pick_unit(graph, key, want.split(".")[0])
    return key


def _indexes(graph: Graph):
    by_serial: dict[str, str] = {}
    by_mac: dict[str, str] = {}
    by_ip: dict[str, str] = {}
    by_host: dict[str, str] = {}
    for key, device in graph.nodes.items():
        for serial in device.serials:
            by_serial.setdefault(serial, key)
        for mac in device.macs:
            by_mac.setdefault(mac, key)
        for ip in device.ips | ({device.mgmt_ip} if device.mgmt_ip else set()):
            by_ip.setdefault(ip, key)
        by_host.setdefault(device.hostname, key)
        if device.chassis:
            by_host.setdefault(device.chassis, key)
    return by_serial, by_ip, by_host, by_mac


def _stub_for(graph: Graph, half: HalfEdge, by_serial, by_ip, by_host, by_mac) -> str:
    host = short_host(half.remote_name)
    key = host or half.remote_ip or half.remote_serial
    if half.remote_chassis and half.remote_chassis in by_mac and by_mac[half.remote_chassis] in graph.nodes:
        key = by_mac[half.remote_chassis]        # the same unnamed device already seen under another name
    existing = graph.nodes.get(key)
    if existing is None:
        model, version, vendor = split_platform(half.remote_platform)
        stub = Device(key=key, hostname=host or key, fqdn=half.remote_name, captured=False, model=model, os_version=version, vendor=vendor,
                      mgmt_ip=half.remote_ip, caps=half.remote_caps)
        if half.remote_serial:
            stub.serials.add(half.remote_serial)
        if half.remote_ip:
            stub.ips.add(half.remote_ip)
        graph.nodes[key] = stub
    else:
        existing.mgmt_ip = existing.mgmt_ip or half.remote_ip
        if not existing.model:
            existing.model, existing.os_version, existing.vendor = split_platform(half.remote_platform)
        existing.caps = existing.caps or half.remote_caps
        if half.remote_serial:
            existing.serials.add(half.remote_serial)
    if half.remote_chassis:
        graph.nodes[key].macs.add(half.remote_chassis)
    for index, value in ((by_serial, half.remote_serial), (by_ip, half.remote_ip), (by_host, host), (by_mac, half.remote_chassis)):
        if value:
            index.setdefault(value, key)
    return key


def _resolve(graph: Graph, half: HalfEdge, indexes) -> str:
    by_serial, by_ip, by_host, by_mac = indexes
    if half.remote_serial and half.remote_serial in by_serial:
        return pick_unit(graph, by_serial[half.remote_serial], half.remote_port)
    if half.remote_chassis and half.remote_chassis in by_mac:
        return pick_unit(graph, by_mac[half.remote_chassis], half.remote_port)
    host = short_host(half.remote_name)
    if host in by_host:
        return pick_unit(graph, by_host[host], half.remote_port)
    if half.remote_ip and half.remote_ip in by_ip:
        return by_ip[half.remote_ip]
    if is_ip(host) and host in by_ip:
        return by_ip[host]
    return _stub_for(graph, half, by_serial, by_ip, by_host, by_mac)


def build(devices: list[Device]) -> Graph:
    graph = Graph()
    _unique_keys(devices, graph)
    indexes = _indexes(graph)
    captured = list(graph.nodes)
    halves: dict[tuple[str, str], list[tuple[HalfEdge, str]]] = {}
    for key in captured:
        for half in graph.nodes[key].halves:
            remote = _resolve(graph, half, indexes)
            if remote == key:
                continue
            halves.setdefault((key, half.local_port), []).append((half, remote))
    graph.issues += _protocol_disagreements(halves)

    done: set[frozenset] = set()
    for (node, port), entries in sorted(halves.items(), key=lambda item: (item[0][0], port_sort_key(item[0][1]))):
        for half, remote in entries:
            rport = half.remote_port
            end_a, end_b = (node, port), (remote, rport)
            marker = frozenset({end_a, end_b}) if rport else frozenset({end_a, (remote, "?" + node + port)})
            if marker in done:
                continue
            reverse = None
            if rport:
                for rhalf, rremote in halves.get((remote, rport), []):
                    if rremote == node:
                        reverse = rhalf
                        break
            else:
                for (rnode, rp), rentries in halves.items():
                    if rnode == remote and any(r == node and rh.remote_port == port for rh, r in rentries):
                        reverse, rport = rentries[0][0], rp
                        break
            if reverse is not None:
                state, note = "confirmed", ""
            elif graph.nodes[remote].captured and rport and (remote, rport) in halves:
                other = halves[(remote, rport)][0][1]
                state, note = "conflict", f"{remote} {rport} reports {other}, not {node}"
                graph.issues.append({"type": "conflict", "a": node, "a_port": port, "b": remote, "b_port": rport, "other": other})
            else:
                why = "peer is captured but shows no neighbor on that port" if graph.nodes[remote].captured else "peer not captured"
                state, note = "single", why
            done.add(marker)
            if reverse is not None:
                done.add(frozenset({end_a, (remote, rport)}))
            link = Link(node, port, remote, rport, state, set(half.protocols) | (set(reverse.protocols) if reverse else set()),
                        note, half.native_vlan, half.duplex,
                        seen_native_a=reverse.native_vlan if reverse else "", seen_native_b=half.native_vlan)
            graph.links.append(link)
    _connections(graph)
    return graph


def _protocol_disagreements(halves) -> list[dict[str, Any]]:
    issues = []
    for (node, port), entries in halves.items():
        if len(entries) > 1:
            by_proto: dict[str, set[str]] = {}
            for half, remote in entries:
                for proto in half.protocols:
                    by_proto.setdefault(proto, set()).add(remote)
            if len(by_proto) > 1 and len({frozenset(v) for v in by_proto.values()}) > 1:
                issues.append({"type": "proto-disagree", "node": node, "port": port,
                               "detail": {p: sorted(v) for p, v in by_proto.items()}})
    return issues


def _connections(graph: Graph) -> None:
    groups: dict[tuple, list[Link]] = {}
    for link in graph.links:
        a, b = graph.nodes[link.a], graph.nodes[link.b]
        a_po, b_po = a.bundle_of.get(link.a_port, ""), b.bundle_of.get(link.b_port, "")
        ordered = (link.a, link.b) if link.a <= link.b else (link.b, link.a)
        flipped = ordered[0] != link.a
        key = ordered + ((b_po, a_po) if flipped else (a_po, b_po))
        groups.setdefault(key, []).append(link)
    # peer-link / vpc detection
    for key, links in groups.items():
        first = links[0]
        node_a, node_b = graph.nodes[key[0]], graph.nodes[key[1]]
        po_a, po_b = key[2], key[3]
        conn = Connection(key[0], key[1], sorted(links, key=lambda l: port_sort_key(l.a_port)), po_a, po_b)
        if key[0] != first.a:   # normalise port orientation to match (a, b) of the connection
            for link in conn.links:
                link.swap()
        conn.kind = "bundle" if (po_a or po_b) else ("parallel" if len(links) > 1 else "link")
        if conn.kind == "link" and any(p.lower().startswith("mgmt") for l in links for p in (l.a_port, l.b_port)):
            conn.kind = "mgmt"                                    # out-of-band management port: drawn thin and dotted, or hidden on request
        if node_a.vpc_domain and node_a.vpc_domain == node_b.vpc_domain and po_a and po_a == node_a.vpc_peer_link:
            conn.kind = "peer-link"
            graph.vpc_pairs.append((key[0], key[1], node_a.vpc_domain))
        graph.connections.append(conn)
    # multi-chassis bundles: the same Po on one device whose members reach two different peers
    by_po: dict[tuple[str, str], list[Connection]] = {}
    for conn in graph.connections:
        for node, po in ((conn.a, conn.a_po), (conn.b, conn.b_po)):
            if po:
                by_po.setdefault((node, po), []).append(conn)
    for (node, po), conns in by_po.items():
        if len({c.b if c.a == node else c.a for c in conns}) > 1:
            for conn in conns:
                conn.multi_chassis = True
    for conn in graph.connections:
        for node, po in ((conn.a, conn.a_po), (conn.b, conn.b_po)):
            vid = graph.nodes[node].vpc_ids.get(po, "")
            if vid:
                conn.vpc_id = vid
