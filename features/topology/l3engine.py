"""The layer-3 model of the network: which device talks to which, over what, and with what evidence.

One ``L3Edge`` is one thing a reader can point at: a routed point-to-point link, a shared segment (VLAN interfaces, a LAN), a tunnel,
an SD-WAN overlay, a routing adjacency between devices that are not on the same subnet, or the first hop towards a gateway nobody
captured.  Every edge keeps the sentences that prove it (``evidence``), whether the proof shows the link working (``state``), and
the routes whose next hop is reached over it.

The model describes routing intent: where a device sends traffic according to its routing table and interface state.  It does not
measure traffic.

Sources, all read from the captures: interface addresses (``Device.l3``), interface state, routes, OSPF / EIGRP / BGP neighbors,
tunnel interfaces and SD-WAN BFD sessions (``Device.l3facts``).
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .extract import Device
from .graph import Graph
from .l3cloud import classify, cloud_node
from .l3focus import MORE_KEY, Focus
from .names import canon_port

_MGMT = ("mgmt", "management", "oob")
UP, DOWN, CONFIGURED = "up", "down", "configured"


@dataclass
class L3Edge:
    kind: str                                    # p2p | segment | tunnel | overlay | peering | gateway
    a: str
    b: str
    a_if: str = ""
    b_if: str = ""
    a_ip: str = ""
    b_ip: str = ""
    subnet: str = ""
    vrf: str = ""
    state: str = CONFIGURED                       # up: something shows it working; down: something shows it broken; configured: configuration only
    evidence: list[str] = field(default_factory=list)
    routes: list[dict[str, Any]] = field(default_factory=list)     # {device, protocol, vrf, next_hop, count, prefixes, default}
    colours: list[str] = field(default_factory=list)               # SD-WAN: "private1 > mpls" per session
    sessions: tuple[int, int] = (0, 0)                             # SD-WAN: sessions up, sessions total
    sites: int = 0                                                 # SD-WAN summary edge: how many remote sites it stands for (they are not drawn)
    members: list["L3Edge"] = field(default_factory=list)          # a grouped line (uncaptured next-hop routers) stands for these edges
    ident: str = ""                                                # set for grouped lines (L3-G01); every other edge gets its ID from l3page.edge_ids

    def add(self, text: str) -> None:
        if text and text not in self.evidence:
            self.evidence.append(text)


@dataclass
class L3Model:
    edges: list[L3Edge] = field(default_factory=list)
    nodes: dict[str, Device] = field(default_factory=dict)         # segments, clouds and uncaptured peers the edges point at
    unresolved: list[dict[str, Any]] = field(default_factory=list)  # next hops and neighbors that no capture explains
    hidden: dict[str, dict[str, Any]] = field(default_factory=dict)  # SD-WAN remote sites that are not drawn (see l3focus): system IP -> {site_id, sessions, up, hubs, colours}
    focus: Focus = field(default_factory=Focus)
    grouped: list[L3Edge] = field(default_factory=list)            # display lines that replace several gateway edges (see group_gateways)

    def drawn(self) -> list[L3Edge]:
        """The lines of the picture: every edge, with the members of a group replaced by the group's line."""
        inside = {id(m) for g in self.grouped for m in g.members}
        return [e for e in self.edges if id(e) not in inside] + self.grouped


def _skip(row: dict[str, Any]) -> bool:
    """Shut-down interfaces and management interfaces (management VRF, mgmt / vmanage names, a description that says management) are not L3 links."""
    vrf, name, text = str(row.get("vrf", "")).lower(), str(row.get("name", "")).lower(), str(row.get("description", "")).lower()
    return bool(row.get("shutdown")) or any(w in vrf for w in _MGMT) or name.startswith(("mgmt", "vmanage", "nvi")) or any(w in text for w in ("management", "mgmt", "oob"))


def _inside(address: str, network: Any) -> bool:
    try:
        return ipaddress.ip_address(address) in network
    except ValueError:
        return False


def _mgmt(row: dict[str, Any]) -> bool:
    """A management interface (not a shut-down one): the routes that use it serve the device's own management traffic, not the network's."""
    return not row.get("shutdown") and _skip(row)


def _iface(row: dict[str, Any]) -> ipaddress.IPv4Interface | None:
    try:
        return ipaddress.ip_interface(f"{row['ip']}/{int(row['prefix_len'])}")
    except (KeyError, ValueError, TypeError):
        return None


def _status_ok(status: str) -> str:
    """up / down / '' (unknown) from 'up/up', 'down/down', 'admin down'."""
    low = status.lower()
    if low in ("up/up", "up"):
        return UP
    if low.startswith(("down", "admin", "up/down")):
        return DOWN
    return ""


class _Index:
    """Who owns an address, and which connected subnet it falls in."""

    def __init__(self, graph: Graph) -> None:
        self.owner: dict[str, tuple[str, str, str]] = {}                # ip -> (node, interface, vrf)
        self.system: dict[str, str] = {}                                # SD-WAN system-ip -> node
        self.mgmt: dict[str, list[Any]] = defaultdict(list)             # node -> networks of its management interfaces
        self.vip: dict[str, list[tuple[str, str]]] = defaultdict(list)  # HSRP / VRRP virtual address -> [(node, interface)] of the devices that run the group
        self.subnets: dict[str, list[tuple[Any, str, dict[str, Any]]]] = defaultdict(list)     # node -> [(network, interface name, row)]
        for key, node in graph.nodes.items():
            if not node.captured or key in graph.hidden_nodes:
                continue
            for row in node.l3:
                interface = _iface(row)
                if interface is None:
                    continue
                self.owner.setdefault(str(interface.ip), (key, str(row["name"]), str(row.get("vrf", ""))))
                for extra in row.get("secondary") or []:
                    self.owner.setdefault(str(extra).split("/")[0], (key, str(row["name"]), str(row.get("vrf", ""))))
                if not _skip(row) and interface.network.prefixlen < 32:
                    self.subnets[key].append((interface.network, str(row["name"]), row))
                elif _mgmt(row) and interface.network.prefixlen < 32:
                    self.mgmt[key].append(interface.network)
            for ip in node.ips | ({node.mgmt_ip} if node.mgmt_ip else set()):
                self.owner.setdefault(ip.split("/")[0], (key, "", ""))
            for group in node.l3facts.get("fhrp", []) or []:
                if group.get("virtual_ip"):
                    self.vip[str(group["virtual_ip"])].append((key, str(group.get("interface", ""))))
            system = str(node.l3facts.get("system_ip", ""))
            if system:
                self.system[system] = key
                self.owner.setdefault(system, (key, "system-ip", ""))

    def on_mgmt(self, node: str, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in self.mgmt.get(node, []))

    def connected(self, node: str, ip: str) -> tuple[Any, str, dict[str, Any]] | None:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best = None
        for network, name, row in self.subnets.get(node, []):
            if address in network and (best is None or network.prefixlen > best[0].prefixlen):
                best = (network, name, row)
        return best


def _edge_key(edge: L3Edge) -> tuple:
    return (edge.kind, tuple(sorted((edge.a, edge.b))), edge.subnet if edge.kind in ("p2p", "segment") else "", edge.vrf if edge.kind == "gateway" else "")


class _Builder:
    def __init__(self, graph: Graph, hints: dict[str, Any] | None, focus: Focus | None = None) -> None:
        self.graph = graph
        self.index = _Index(graph)
        self.focus = focus or Focus()
        self.model = L3Model(focus=self.focus)
        self.edges: dict[tuple, L3Edge] = {}
        self.hints = hints or {}
        self.clouds: dict[str, Device] = {}

    # ------------------------------------------------------------------ helpers
    def edge(self, edge: L3Edge) -> L3Edge:
        key = _edge_key(edge)
        have = self.edges.get(key)
        if have is None:
            self.edges[key] = edge
            self.model.edges.append(edge)
            return edge
        for text in edge.evidence:
            have.add(text)
        return have

    def cloud(self, node: str, interface: str, ip: str, vrf: str = "", peer: bool = False) -> tuple[str, list[str]]:
        cloud, reasons = cloud_node(self.graph, node, interface, ip, self.hints, peer)
        self.model.nodes.setdefault(cloud.key, cloud)
        return cloud.key, reasons

    def _state(self, *pairs: tuple[str, str]) -> str:
        seen = [_status_ok(self.graph.nodes[n].l3facts.get("state", {}).get(i, "") or next((r.get("status", "") for r in self.graph.nodes[n].l3 if r["name"] == i), "")) for n, i in pairs if n in self.graph.nodes]
        if DOWN in seen:
            return DOWN
        return UP if seen and all(s == UP for s in seen) else CONFIGURED

    # ------------------------------------------------------------------ connected subnets: point-to-point links and shared segments
    def subnets(self) -> None:
        groups: dict[Any, list[tuple[str, str, dict[str, Any], Any]]] = defaultdict(list)
        for key, entries in self.index.subnets.items():
            for network, name, row in entries:
                groups[network].append((key, name, row, _iface(row)))
        for network, members in sorted(groups.items(), key=lambda item: (int(item[0].network_address), item[0].prefixlen)):
            first: dict[str, tuple[str, str, dict[str, Any], Any]] = {}
            for member in members:
                first.setdefault(member[0], member)
            if len(first) < 2:
                continue
            ordered = sorted(first.values(), key=lambda m: m[0])
            vrfs = sorted({str(m[2].get("vrf", "")) for m in ordered})
            if len(ordered) == 2:
                (a, a_if, a_row, a_ip), (b, b_if, b_row, b_ip) = ordered
                edge = L3Edge("p2p", a, b, a_if, b_if, str(a_ip.ip), str(b_ip.ip), str(network), vrfs[0], self._state((a, a_if), (b, b_if)))
                edge.add(f"{a} {a_if} {a_ip.ip} and {b} {b_if} {b_ip.ip} share {network}")
                self.edge(edge)
            else:
                vips = sorted({v for v, holders in self.index.vip.items() for h in holders if _inside(v, network)})
                seg = Device(key=f"SEG:{network}", hostname=str(network), captured=False, role_hint="segment", model=" · ".join(x for x in ((ordered[0][1].upper() if ordered[0][1].lower().startswith("vlan") else ""), f"VRF {vrfs[0]}" if vrfs[0] else "", f"virtual {vips[0]}" if vips else "") if x),
                             mgmt_ip=f"{len(ordered)} devices")
                self.model.nodes[seg.key] = seg
                for key, name, row, interface in ordered:
                    edge = L3Edge("segment", key, seg.key, name, "", str(interface.ip), "", str(network), vrfs[0], self._state((key, name)))
                    edge.add(f"{key} {name} {interface.ip} is on {network}, shared by {len(ordered)} devices")
                    self.edge(edge)

    # ------------------------------------------------------------------ routing neighbors
    def neighbors(self) -> None:
        for key, node in self.graph.nodes.items():
            if not node.captured:
                continue
            for row in node.l3facts.get("neighbors", []):
                address, protocol = str(row.get("address", "")), str(row.get("protocol", ""))
                if not address:
                    continue
                state = str(row.get("state", ""))
                healthy = state.upper().startswith(("FULL", "2WAY")) or state.lower() in ("established", "up") or (protocol == "bgp" and state[:1].isdigit())    # 2-WAY is the normal state between two DROTHER routers on a LAN (RFC 2328 section 10.1)
                unproven = state.lower() in ("configured", "")                     # configuration only (a FortiGate backup has no neighbor table)
                owner = self.index.owner.get(address)
                label = f"{protocol.upper()} neighbor {address} {state}".strip()
                if owner and owner[0] != key:
                    near = self.index.connected(key, address)
                    other = owner[0]
                    if near:
                        for edge in self.edges.values():
                            if edge.kind in ("p2p", "segment") and edge.subnet == str(near[0]) and {edge.a, edge.b} & {key} and (edge.kind == "segment" or other in (edge.a, edge.b)):
                                edge.add(label)
                                if healthy and edge.state != DOWN:
                                    edge.state = UP
                                elif not healthy and not unproven and protocol != "bgp":
                                    edge.state = DOWN
                    else:
                        peer = L3Edge("peering", key, other, near[1] if near else "", owner[1], "", address, "", str(row.get("vrf", "")), UP if healthy else (CONFIGURED if unproven else DOWN))
                        peer.add(label + f" ({protocol.upper()} session between addresses that are not on one subnet)")
                        self.edge(peer)
                elif not owner:
                    near = self.index.connected(key, address)
                    if near:
                        gw, why = self.cloud(key, near[1], address)
                        edge = self.edge(L3Edge("gateway", key, gw, near[1], "", near[2].get("ip", ""), address, str(near[0]), str(near[2].get("vrf", "")), UP if healthy else self._state((key, near[1]))))
                        edge.add(label)
                        for text in why:
                            edge.add(text)
                    else:
                        self.model.unresolved.append({"device": key, "what": f"{protocol} neighbor", "address": address})

    # ------------------------------------------------------------------ tunnels
    def tunnels(self) -> None:
        for key, node in self.graph.nodes.items():
            if not node.captured:
                continue
            for tunnel in node.l3facts.get("tunnels", []):
                destination = tunnel.get("destination", "")
                if not destination or tunnel.get("mode") == "sdwan":
                    continue
                owner = self.index.owner.get(destination)
                state = self._state((key, tunnel["name"]))
                why: list[str] = []
                other = owner[0] if owner and owner[0] != key else None
                if other is None:
                    source = str(tunnel.get("source") or "")
                    held = self.index.owner.get(source)
                    via = held[1] if held and held[0] == key else (canon_port(source) if source and not source[0].isdigit() else "")
                    other, why = self.cloud(key, via or tunnel["name"], destination, peer=True)
                edge = L3Edge("tunnel", key, other, tunnel["name"], owner[1] if owner else "", tunnel.get("ip", "").split("/")[0], destination, "", tunnel.get("vrf", ""), state)
                edge.add(f"{key} {tunnel['name']} ({tunnel.get('mode') or 'tunnel'}) from {tunnel.get('source') or '?'} to {destination}")
                for text in why:
                    edge.add(text)
                self.edge(edge)

    # ------------------------------------------------------------------ SD-WAN overlay
    def _site_of(self, key: str) -> tuple[str, str, str]:
        node = self.graph.nodes[key]
        return str(node.l3facts.get("system_ip", "")), str(node.l3facts.get("site_id", "")), node.hostname

    def _hide(self, hub: str, remote: str, session: dict[str, Any]) -> None:
        item = self.model.hidden.setdefault(remote, {"site_id": str(session.get("site_id", "")), "sessions": 0, "up": 0, "hubs": {}, "colours": set()})
        item["sessions"] += 1
        up = str(session.get("state", "")).lower() == "up"
        item["up"] += 1 if up else 0
        per_hub = item["hubs"].setdefault(hub, [0, 0])
        per_hub[1] += 1
        per_hub[0] += 1 if up else 0
        item["colours"].add(f"{session.get('local_color', '?')} > {session.get('remote_color', '?')}")

    def _more_edges(self) -> None:
        """One summary cloud for every remote site that is not drawn, joined to each hub that has sessions to them."""
        if not self.model.hidden:
            return
        hubs: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        colours: set[str] = set()
        for item in self.model.hidden.values():
            colours |= item["colours"]
            for hub, (up, total) in item["hubs"].items():
                hubs[hub][0] += up
                hubs[hub][1] += total
        count = len(self.model.hidden)
        cloud = Device(key=MORE_KEY, hostname=f"+{count} SD-WAN site{'s' if count != 1 else ''}", captured=False, role_hint="cloud", model="not drawn", mgmt_ip="BFD tables")
        self.model.nodes[MORE_KEY] = cloud
        reason = "only the captured sites are drawn" if not self.focus.narrowed else "only the sites typed in the list are drawn"
        for hub, (up, total) in sorted(hubs.items()):
            edge = L3Edge("overlay", hub, MORE_KEY, state=UP if up else DOWN)
            edge.sessions = (up, total)
            edge.sites = len([1 for item in self.model.hidden.values() if hub in item["hubs"]])
            edge.colours = sorted(colours)
            edge.add(f"SD-WAN BFD: {self.graph.nodes[hub].hostname} has {total} session(s) to {edge.sites} other site(s), {up} up; they are not drawn ({reason})")
            self.edges[("overlay", tuple(sorted((hub, MORE_KEY))), "", "")] = edge
            self.model.edges.append(edge)

    def overlay(self) -> None:
        pairs: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = defaultdict(list)
        for key, node in self.graph.nodes.items():
            if not node.captured:
                continue
            local = self._site_of(key)
            for session in node.l3facts.get("overlay", []):
                remote = session.get("system_ip", "")
                if not remote:
                    continue
                other = self.index.system.get(remote)
                host = self.graph.nodes[other].hostname if other else ""
                if not self.focus.draws(remote, str(session.get("site_id", "")), host, other is not None, local):
                    self._hide(key, remote, session)
                    continue
                if other is None:
                    ghost = Device(key=f"SDWAN:{remote}", hostname=f"SD-WAN {remote}", captured=False, role_hint="router", model=f"site {session.get('site_id', '')}".strip(), mgmt_ip=remote)
                    self.model.nodes.setdefault(ghost.key, ghost)
                    other = ghost.key
                if other != key:
                    pairs[tuple(sorted((key, other)))].append((key, session))
        for (a, b), sessions in pairs.items():
            up = sum(1 for _, s in sessions if str(s.get("state", "")).lower() == "up")
            edge = L3Edge("overlay", a, b, "", "", "", "", "", "", UP if up else DOWN)
            edge.sessions = (up, len(sessions))
            edge.colours = sorted({f"{s.get('local_color', '?')} > {s.get('remote_color', '?')}" for _, s in sessions})
            edge.add(f"SD-WAN BFD: {up} of {len(sessions)} sessions up ({', '.join(edge.colours)})")
            self.edge(edge)

    # ------------------------------------------------------------------ access links to the provider
    def access_links(self) -> None:
        """A routed interface that nothing in the captures connects, but whose description, VRF, neighbor name, SD-WAN colour or a typed hint says it faces a provider."""
        used = {(e.a, e.a_if) for e in self.edges.values()} | {(e.b, e.b_if) for e in self.edges.values()}
        for key, node in self.graph.nodes.items():
            if not node.captured or key in self.graph.hidden_nodes:
                continue
            for row in node.l3:
                interface = _iface(row)
                name = str(row["name"])
                if interface is None or _skip(row) or (key, name) in used or str(row.get("kind", "")).lower() in ("loopback", "tunnel") or interface.network.prefixlen >= 32:
                    continue
                found = classify(self.graph, key, name, str(interface.ip), self.hints)
                if found is None:
                    continue
                gateway = next((r["next_hop"] for r in node.l3facts.get("routes", []) if r.get("next_hop") and self.index.connected(key, r["next_hop"]) and self.index.connected(key, r["next_hop"])[0] == interface.network), "")
                cloud, why = self.cloud(key, name, gateway or str(interface.ip))
                edge = self.edge(L3Edge("gateway", key, cloud, name, "", str(interface.ip), gateway, str(interface.network), str(row.get("vrf", "")), self._state((key, name))))
                edge.add(f"{key} {name} {interface.ip}/{interface.network.prefixlen} has no captured device on its subnet")
                for text in why:
                    edge.add(text)

    # ------------------------------------------------------------------ routes
    def routes(self) -> None:
        for key, node in self.graph.nodes.items():
            if not node.captured:
                continue
            for route in node.l3facts.get("routes", []):
                hop = str(route.get("next_hop", ""))
                if not hop[:1].isdigit() or self.index.on_mgmt(key, hop):
                    continue                                        # 'directly connected', or a route that serves the management interface
                owner = self.index.owner.get(hop) or ((self.index.system[hop], "", "") if hop in self.index.system else None)
                shared = ""
                if owner is None and hop in self.index.vip:
                    holders = [h for h in self.index.vip[hop] if h[0] != key]
                    if not holders:
                        continue                                    # the device's own virtual address
                    owner = (holders[0][0], holders[0][1], "")
                    shared = " and ".join(sorted({self.graph.nodes[h[0]].hostname for h in self.index.vip[hop]}))
                target = None
                if owner and owner[0] != key:
                    target = self._edge_to(key, owner[0], hop, route)
                    if shared and target is not None:
                        target.add(f"next hop {hop} is the HSRP/VRRP virtual address shared by {shared}")
                elif not owner:
                    near = self.index.connected(key, hop)
                    if near:
                        gw, why = self.cloud(key, near[1], hop)
                        target = self.edge(L3Edge("gateway", key, gw, near[1], "", near[2].get("ip", ""), hop, str(near[0]), str(near[2].get("vrf", "")), self._state((key, near[1]))))
                        for text in why:
                            target.add(text)
                    elif route.get("protocol") == "omp" and hop:
                        if f"SDWAN:{hop}" in self.model.nodes or self.focus.draws(hop, "", "", False, self._site_of(key)):
                            ghost = Device(key=f"SDWAN:{hop}", hostname=f"SD-WAN {hop}", captured=False, role_hint="router", mgmt_ip=hop)
                            self.model.nodes.setdefault(ghost.key, ghost)
                            target = self.edge(L3Edge("overlay", key, ghost.key, state=UP))
                        else:
                            target = self.edges.get(("overlay", tuple(sorted((key, MORE_KEY))), "", ""))     # routes to a site that is not drawn count on the summary line
                    else:
                        self.model.unresolved.append({"device": key, "what": f"next hop of {route.get('count', 0)} {route.get('protocol', '')} route(s)", "address": hop})
                if target is not None:
                    target.routes.append({"device": key, "protocol": route.get("protocol", ""), "vrf": route.get("vrf", ""), "next_hop": hop, "count": route.get("count", 0),
                                          "prefixes": list(route.get("prefixes", [])), "default": bool(route.get("default"))})

    def _edge_to(self, key: str, other: str, hop: str, route: dict[str, Any]) -> L3Edge | None:
        """The edge between two captured devices that carries a next hop: the shared subnet containing it, else the overlay, tunnel or peering."""
        near = self.index.connected(key, hop)
        for edge in self.edges.values():
            if {edge.a, edge.b} == {key, other} and edge.kind in ("p2p", "segment") and near and edge.subnet == str(near[0]):
                return edge
        for edge in self.edges.values():
            if edge.kind == "segment" and near and edge.subnet == str(near[0]) and key in (edge.a, edge.b):
                return edge
        for kind in (("overlay",) if route.get("protocol") == "omp" else ("tunnel", "peering", "overlay")):
            for edge in self.edges.values():
                if edge.kind == kind and {edge.a, edge.b} == {key, other}:
                    return edge
        edge = L3Edge("peering", key, other, near[1] if near else "", "", "", hop, "", str(route.get("vrf", "")), CONFIGURED)
        edge.add(f"{key} routes through {hop}, an address of {other} that is not on a shared subnet")
        return self.edge(edge)


GROUP_OVER = 6          # more uncaptured next-hop routers than this on a page are drawn as one node per VRF
PARALLEL_OVER = 2       # more shared subnets than this between the same two devices (an HSRP pair with twenty VLAN interfaces) are drawn as one line


def _group_state(members: list[L3Edge]) -> str:
    """A group is broken only when every member is; one working member makes it work (the label says how many are down)."""
    if all(m.state == DOWN for m in members):
        return DOWN
    return UP if any(m.state == UP for m in members) else CONFIGURED


def group_parallel(model: L3Model, graph: Graph) -> None:
    """Draw the many direct links between the same two devices in the same VRF as one line.

    Two distribution switches that both own a VLAN interface in twenty VLANs share twenty subnets; the picture needs one line with the
    count, not twenty arcs.  The members stay in the tables, in the trace and in the click panel.
    """
    pairs: dict[tuple[str, str, str], list[L3Edge]] = defaultdict(list)
    for e in model.edges:
        if e.kind == "p2p":
            pairs[(min(e.a, e.b), max(e.a, e.b), e.vrf)].append(e)
    start = len(model.grouped)
    for n, ((a, b, vrf), members) in enumerate(sorted((k, v) for k, v in pairs.items() if len(v) > PARALLEL_OVER), start + 1):
        ifaces = sorted({m.a_if if m.a == a else m.b_if for m in members})
        far = sorted({m.b_if if m.a == a else m.a_if for m in members})
        state = _group_state(members)
        line = L3Edge("p2p", a, b, f"{len(ifaces)} interfaces", f"{len(far)} interfaces", "", "", "", vrf, state, members=members)
        line.ident = f"L3-G{n:02d}"
        broken = [m for m in members if m.state == DOWN]
        if broken:
            line.add(f"{len(broken)} of {len(members)} shared subnets show a broken state: " + ", ".join(m.subnet or m.a_if for m in broken[:12]))
        for m in members[:60]:
            line.add(m.evidence[0] if m.evidence else f"{m.a} {m.a_if} and {m.b} {m.b_if} share {m.subnet}")
        line.routes = [r for m in members for r in m.routes]
        model.grouped.append(line)


SEGMENT_OVER = 4        # more shared subnets than this with the very same devices on them (three switches with thirty VLAN interfaces each) are drawn as one node


def _subnet_range(subnets: list[str]) -> str:
    """'10.20.0.0/24 ... 10.20.29.0/24' for a long list, the plain list for a short one (the full list stays in the tables)."""
    ordered = sorted(subnets, key=lambda t: (int(ipaddress.ip_network(t, strict=False).network_address), t))
    return ", ".join(ordered) if len(ordered) <= 3 else f"{ordered[0]} ... {ordered[-1]}"


def group_segments(model: L3Model, graph: Graph) -> None:
    """Draw the shared subnets that have the same devices on them (and the same VRF) as one node with one line per device.

    Three distribution switches that own thirty VLAN interfaces each would put thirty ellipses and ninety lines on the page, all with the same three
    ends; the picture needs one node that says "30 shared subnets".  The members stay in the tables, in the trace and in the click panel.
    """
    on: dict[str, list[L3Edge]] = defaultdict(list)
    for e in model.edges:
        if e.kind == "segment" and e.b in model.nodes:
            on[e.b].append(e)
    clusters: dict[tuple[frozenset, str], list[str]] = defaultdict(list)
    for seg, edges in on.items():
        clusters[(frozenset(e.a for e in edges), edges[0].vrf)].append(seg)
    for (devices, vrf), segs in sorted(clusters.items(), key=lambda item: (sorted(item[0][0]), item[0][1], sorted(item[1]))):
        if len(segs) <= SEGMENT_OVER:
            continue
        n = len(model.grouped) + 1
        key = f"SEGG:{vrf or 'global'}:{'|'.join(sorted(devices))}"
        networks = [on[seg][0].subnet for seg in segs]
        model.nodes[key] = Device(key=key, hostname=f"{len(segs)} shared subnets", captured=False, role_hint="segment",
                                  model=" · ".join(x for x in (_subnet_range(networks), f"VRF {vrf}" if vrf else "") if x), mgmt_ip=f"{len(devices)} devices")
        for device in sorted(devices):
            members = [e for seg in segs for e in on[seg] if e.a == device]
            ifaces = sorted({m.a_if for m in members if m.a_if})
            line = L3Edge("segment", device, key, f"{len(ifaces)} interfaces" if len(ifaces) > 1 else (ifaces[0] if ifaces else ""), "", "", "", "", vrf, _group_state(members), members=members)
            line.ident = f"L3-G{n:02d}"
            n += 1
            broken = [m for m in members if m.state == DOWN]
            if broken:
                line.add(f"{len(broken)} of {len(members)} shared subnets show a broken state: " + ", ".join(m.subnet or m.a_if for m in broken[:12]))
            for m in members[:60]:
                line.add(m.evidence[0] if m.evidence else f"{device} {m.a_if} is on {m.subnet}")
            line.routes = [r for m in members for r in m.routes]
            model.grouped.append(line)


def group_gateways(model: L3Model, graph: Graph) -> None:
    """Replace the first-hop edges that end at an uncaptured router (``GW:`` nodes) by one line per (device, VRF) to one node per VRF.

    A distribution switch with twenty VLAN interfaces whose next hops are routers nobody captured would otherwise put twenty grey boxes on
    the page.  The member edges stay in the tables, in the trace and in the click panel; only the picture is simplified.
    """
    gws = [e for e in model.edges if e.kind == "gateway" and e.b.startswith("GW:")]
    if len({e.b for e in gws}) <= GROUP_OVER:
        return
    per_vrf: dict[str, set[str]] = defaultdict(set)
    for e in gws:
        per_vrf[e.vrf].add(e.b)
    for vrf, keys in per_vrf.items():
        key = f"GWG:{vrf or 'global'}"
        model.nodes[key] = Device(key=key, hostname=f"{len(keys)} next-hop router{'s' if len(keys) != 1 else ''} not captured", captured=False, role_hint="router",
                                  model=f"VRF {vrf}" if vrf else "global table", mgmt_ip="from the routing tables")
    groups: dict[tuple[str, str], list[L3Edge]] = defaultdict(list)
    for e in gws:
        groups[(e.a, e.vrf)].append(e)
    for n, ((device, vrf), members) in enumerate(sorted(groups.items()), len(model.grouped) + 1):
        ifaces = sorted({m.a_if for m in members if m.a_if})
        state = _group_state(members)
        line = L3Edge("gateway", device, f"GWG:{vrf or 'global'}", ifaces[0] if len(ifaces) == 1 else f"{len(ifaces)} interfaces", "", "", "", "", vrf, state, members=members)
        line.ident = f"L3-G{n:02d}"
        for m in members[:60]:
            line.add(f"{graph.nodes[device].hostname} {m.a_if} -> next hop {m.b_ip}: " + (m.evidence[0] if m.evidence else "first hop"))
        line.routes = [r for m in members for r in m.routes]
        model.grouped.append(line)


def build(graph: Graph, hints: dict[str, Any] | None = None, focus: Focus | None = None, group: bool = True) -> L3Model:
    """The L3 model of every captured device in the graph (``hints``: provider hints typed by the user, see l3cloud; ``focus``: which SD-WAN sites are drawn, see l3focus)."""
    b = _Builder(graph, hints, focus)
    b.subnets()
    b.neighbors()
    b.tunnels()
    b.overlay()
    b._more_edges()
    b.routes()
    b.access_links()
    if group:
        group_parallel(b.model, graph)
        group_gateways(b.model, graph)
        group_segments(b.model, graph)
    return b.model
