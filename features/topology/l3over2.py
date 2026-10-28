"""L3 over L2: which cables carry each layer-3 link.

The L2 page already shows every cable.  This view keeps those cables (same devices, same places) and draws the L3 links of the L3 model
on top of them as curved arcs in the colour of their VRF.  A cable that carries at least one L3 link is drawn thick in that colour; a
cable that carries none stays thin and grey.  Click a cable or an arc to see what rides on what.

How an L3 link is mapped to cables (``underlay``):

* a routed port or a routed port-channel: the cable (or bundle) at that port;
* a VLAN interface (SVI): the shortest chain of captured cables between the two devices (VLAN membership of trunks is not read, so this is
  the shortest path, not proof that the VLAN is allowed on every hop);
* a shared segment: the chains between its members;
* an SD-WAN overlay: the access ports that carry the transport colours on both devices, because the overlay is built over them;
* a gateway or provider access link: the port that faces the gateway.

A link with no cable in the captures (the far end is an uncaptured modem, CDP is off) is listed with an empty underlay and says so.
"""

from __future__ import annotations

import dataclasses
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from .graph import Connection, Graph
from .l3engine import L3Edge, L3Model
from .layout import MARGIN, NODE_H, NODE_W, Placed
from .labelplace import place_labels
from .satellites import Extra, place as place_satellites
from .scene import Page, _clips, _curve, _route
from .names import canon_port

MAX_HOPS = 6
MAX_SEGMENT_MEMBERS = 8
GREY = "#B8B8B8"
EXTRA_GAP = 240.0          # room above the physical devices for provider clouds, segments and remote SD-WAN sites
ROW_STEP = 170.0           # one more row of those when they would not fit in the width of the devices
MAX_ROWS = 4


@dataclass
class Under:
    conns: list[int] = field(default_factory=list)       # indexes into graph.connections
    note: str = ""


def _port_index(graph: Graph) -> dict[tuple[str, str], int]:
    index: dict[tuple[str, str], int] = {}
    for n, conn in enumerate(graph.connections):
        if conn.kind in graph.hidden_kinds:
            continue
        for link in conn.links:
            index.setdefault((conn.a, link.a_port), n)
            index.setdefault((conn.b, link.b_port), n)
        for po in (conn.a_po.split("/") if conn.a_po else []):
            index.setdefault((conn.a, po), n)
        for po in (conn.b_po.split("/") if conn.b_po else []):
            index.setdefault((conn.b, po), n)
    return index


def _adjacency(graph: Graph) -> dict[str, list[tuple[str, int]]]:
    adj: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for n, conn in enumerate(graph.connections):
        if conn.kind in graph.hidden_kinds or conn.kind in ("host", "rollup"):
            continue
        adj[conn.a].append((conn.b, n))
        adj[conn.b].append((conn.a, n))
    return adj


def _path(adj: dict[str, list[tuple[str, int]]], a: str, b: str) -> list[int] | None:
    """Shortest chain of connections from a to b (at most MAX_HOPS), or None."""
    if a == b:
        return []
    seen = {a}
    queue: deque[tuple[str, list[int]]] = deque([(a, [])])
    while queue:
        node, chain = queue.popleft()
        if len(chain) >= MAX_HOPS:
            continue
        for other, n in adj.get(node, []):
            if other in seen:
                continue
            if other == b:
                return chain + [n]
            seen.add(other)
            queue.append((other, chain + [n]))
    return None


def _parents(graph: Graph) -> dict[tuple[str, str], str]:
    """(device, interface) -> the interface that carries it, for sub-interfaces that name their parent (a FortiGate VLAN interface ``vlan100`` on ``agg-core``)."""
    return {(key, str(row["name"])): str(row["parent"]) for key, node in graph.nodes.items() for row in node.l3 if row.get("parent")}


def _lookup(index: dict[tuple[str, str], int], node: str, interface: str, parents: dict[tuple[str, str], str] | None = None) -> int | None:
    """The connection at a port; a sub-interface (Gi0/0/1.100, or one that names its parent) uses the cable of its parent port."""
    if not interface:
        return None
    seen: set[str] = set()
    while interface and interface not in seen:
        seen.add(interface)
        for name in (interface, interface.split(".")[0]):
            if (node, name) in index:
                return index[(node, name)]
        interface = (parents or {}).get((node, interface), "")
    return None


def conn_text(graph: Graph, n: int) -> str:
    conn = graph.connections[n]
    link = conn.links[0]
    a, b = graph.nodes[conn.a].hostname, graph.nodes[conn.b].hostname
    ports = f"{conn.a_po or link.a_port} - {conn.b_po or link.b_port}"
    return f"{a} {ports} {b}" + (f" ({len(conn.links)} links)" if len(conn.links) > 1 else "")


def underlay(graph: Graph, model: L3Model) -> dict[int, Under]:
    """``id(edge)`` of every L3 edge -> the cables that carry it."""
    index, adj, parents = _port_index(graph), _adjacency(graph), _parents(graph)
    out: dict[int, Under] = {}
    members: dict[str, list[L3Edge]] = defaultdict(list)
    for edge in model.edges:
        if edge.kind == "segment":
            members[edge.b].append(edge)
    for edge in model.edges:
        chain: list[int] = []
        note = ""
        if edge.kind in ("p2p", "peering", "tunnel") and edge.a in graph.nodes and edge.b in graph.nodes:
            ca, cb = _lookup(index, edge.a, edge.a_if, parents), _lookup(index, edge.b, edge.b_if, parents)
            direct = [n for n in (ca, cb) if n is not None and {graph.connections[n].a, graph.connections[n].b} == {edge.a, edge.b}]
            if direct:
                chain = sorted(set(direct))
            else:
                found = _path(adj, edge.a, edge.b)
                chain = found or []
                note = "" if found else "no chain of captured cables joins these devices"
        elif edge.kind == "segment" and edge.a in graph.nodes:
            for other in members[edge.b][:MAX_SEGMENT_MEMBERS]:
                if other.a != edge.a and other.a in graph.nodes:
                    chain += _path(adj, edge.a, other.a) or []
            chain = sorted(set(chain))
        elif edge.kind == "overlay":
            for node in (edge.a, edge.b):
                if node in graph.nodes:
                    for port in (graph.nodes[node].l3facts.get("wan_colour") or {}):
                        n = _lookup(index, node, port, parents)
                        if n is not None:
                            chain.append(n)
            chain = sorted(set(chain))
            note = "" if chain else "the transport ports have no captured cable (the far end of the access link is not a captured device)"
        elif edge.kind == "gateway" and edge.a in graph.nodes:
            n = _lookup(index, edge.a, edge.a_if, parents)
            chain = [n] if n is not None else []
            note = "" if chain else "the access port has no CDP / LLDP neighbor in the captures"
        if chain and not note:
            note = "carried on " + "; ".join(conn_text(graph, n) for n in chain[:6]) + (" ..." if len(chain) > 6 else "")
        out[id(edge)] = Under(chain, note)
    return out


def _spread(keys: list[str], want: dict[str, float], gap: float = 230.0) -> dict[str, float]:
    """x for each extra node: as close as possible to ``want``, never closer than ``gap`` to its neighbor."""
    order = sorted(keys, key=lambda k: want[k])
    xs: dict[str, float] = {}
    last = None
    for k in order:
        x = want[k] if last is None else max(want[k], last + gap)
        xs[k] = x
        last = x
    return xs


def _rows(keys: list[str], want: dict[str, float], width: float, gap: float = 230.0) -> tuple[dict[str, tuple[float, int]], int]:
    """(x, row) for each extra node.  One row while the nodes fit in the width of the devices; otherwise up to MAX_ROWS rows, neighbours in x order go to different rows so every node stays near the devices it joins."""
    per_row = max(6, int(width // gap))
    rows = min(MAX_ROWS, max(1, -(-len(keys) // per_row)))
    order = sorted(keys, key=lambda k: want[k])
    out: dict[str, tuple[float, int]] = {}
    for r in range(rows):
        part = [k for i, k in enumerate(order) if i % rows == r]
        out.update({k: (x, r) for k, x in _spread(part, want, gap).items()})
    return out, rows


def _guess_to_uncaptured_router(graph: Graph, conn: Connection) -> bool:
    """A cable that only an ARP entry or a port description suggests, to a router nobody captured.  It carries no L3 link of this page, so it only adds a
    long grey line; the table of links keeps it."""
    if any(link.state != "inferred" for link in conn.links):
        return False
    far = [graph.nodes[k] for k in (conn.a, conn.b) if k in graph.nodes and not graph.nodes[k].captured]
    return any(node.role_hint == "router" for node in far)


def _bow_candidates(bow: float) -> list[float]:
    """The planned bow first, then the other side, then wider ones on both sides (a straight line is not an arc of the L3 over L2 pages)."""
    size = abs(bow)
    sign = 1 if bow >= 0 else -1
    out = [bow, -bow]
    for extra in (40, 80):
        out += [sign * (size + extra), -sign * (size + extra)]
    return out


def _touches(points: list[tuple[float, float]], a: tuple[float, float], b: tuple[float, float], box: tuple[float, float, float, float]) -> bool:
    """Does the polyline a - points - b run through the rectangle?"""
    path = [a, *points, b]
    return any(_clips(box, p, q) for p, q in zip(path, path[1:]))


def l3over2_page(graph: Graph, phys: Page, model: L3Model, colours: dict[str, str], ids: dict[int, str], names: dict[str, str], curved: bool = True) -> Page | None:
    """One L3-over-L2 page for one physical page, or None when no L3 link touches its devices."""
    from .l3page import edge_colour, to_connection
    under = underlay(graph, model)
    for line in model.grouped:                      # a grouped line rides on every cable its members ride on
        chain = sorted({n for m in line.members for n in under[id(m)].conns})
        under[id(line)] = Under(chain, ("carried on " + "; ".join(conn_text(graph, n) for n in chain[:6]) + (" ..." if len(chain) > 6 else "")) if chain else "")
    drawn = model.drawn()
    shown = [e for e in drawn if (e.a in phys.nodes) or (e.b in phys.nodes)]
    shown = [e for e in shown if (e.a in phys.nodes or e.a in model.nodes) and (e.b in phys.nodes or e.b in model.nodes)]
    if not shown:
        return None
    extras = {k for e in shown for k in (e.a, e.b) if k not in phys.nodes}
    ends: dict[str, list[str]] = {k: [] for k in extras}
    for e in shown:
        for k, other in ((e.a, e.b), (e.b, e.a)):
            if k in extras and other in phys.nodes:
                ends[k].append(other)
    spots = place_satellites({k: (p.x, p.y) for k, p in phys.nodes.items()},
                             [Extra(k, ends[k], above=(model.nodes[k].role_hint if k in model.nodes else "") in ("cloud", "router")) for k in sorted(extras)])
    xs = [p.x for p in phys.nodes.values()] + [x for x, _ in spots.values()]
    ys = [p.y for p in phys.nodes.values()] + [y for _, y in spots.values()]
    shift_x = max(0.0, MARGIN + 60 - min(xs, default=0.0))                 # an extra put left of / above everything moves the page, not off it
    shift_y = max(0.0, MARGIN - min(ys, default=0.0))
    dy = shift_y
    nodes = {k: Placed(p.x + shift_x, p.y + shift_y, p.tier, p.box) for k, p in phys.nodes.items()}
    for key, (x, y) in spots.items():
        nodes[key] = Placed(x + shift_x, y + shift_y, -1)
    physical = {id(c): n for n, c in enumerate(graph.connections)}
    carries: dict[int, list[tuple[str, str]]] = defaultdict(list)
    for e in shown:
        for n in under[id(e)].conns:
            carries[n].append((ids[id(e)], edge_colour({"state": e.state, "kind": e.kind, "vrf": e.vrf}, colours)))
    conns: list[Connection] = []
    kept_index: dict[int, int] = {}                  # index in the physical page -> index here (a guessed cable to a router nobody captured may be left out)
    for old_index, conn in enumerate(phys.connections):
        originals = phys.bundled.get(old_index) or [conn]              # a site bundle of the Overview stands for several cables: they carry what its cables carry
        numbers = [physical[id(c)] for c in originals if id(c) in physical]
        rides = list(dict.fromkeys(r for n in numbers for r in carries.get(n, [])))
        if not rides and all(_guess_to_uncaptured_router(graph, c) for c in originals):
            continue
        kept_index[old_index] = len(conns)
        look = {"role": "under", "colour": rides[0][1] if rides else GREY, "width": 5 if rides else 1.5, "carries": [r[0] for r in rides]}
        if rides:
            look["id"] = rides[0][0]
            cables = conn_text(graph, numbers[0]) if len(originals) == 1 else f"{len(originals)} cables between two sites"
            look["meaning"] = f"{cables} carries " + ", ".join(r[0] for r in rides) + "."
        conns.append(dataclasses.replace(conn, l3=look))
    l3conns: list[Connection] = []
    rank: dict[frozenset, int] = defaultdict(int)
    bows: dict[frozenset, list[float]] = {}
    for e in shown:
        c = to_connection(e, colours, ids[id(e)], names, ids)
        c.l3["over2"] = True
        c.l3["under"] = under[id(e)].note
        if under[id(e)].note:
            c.l3["meaning"] += " " + under[id(e)].note[0].upper() + under[id(e)].note[1:] + "."
        l3conns.append(c)
    sub_nodes = {k: graph.nodes[k] for k in phys.nodes}
    sub_nodes.update({k: model.nodes[k] for k in extras})
    sub = Graph(nodes=sub_nodes, links=graph.links, connections=conns + l3conns, hidden_kinds=graph.hidden_kinds, vpc_pairs=graph.vpc_pairs)
    width = max(phys.width + shift_x, max((p.x for p in nodes.values()), default=0) + NODE_W + MARGIN)
    height = max(phys.height + dy, max((p.y for p in nodes.values()), default=0) + NODE_H + 80 + MARGIN)
    page = Page(phys.name + " · L3 over L2", nodes, set(phys.ghosts), [(t, x + shift_x, y + dy, w, h) for t, x, y, w, h in phys.boxes], conns + l3conns, {}, width, height,
                view="l3over2", graph=sub, curved=True)
    page.end_boxes = [(t, x + shift_x, y + dy, w, h) for t, x, y, w, h in phys.end_boxes]
    page.routes = {kept_index[i]: [(x + shift_x, y + dy) for x, y in pts] for i, pts in phys.routes.items() if i in kept_index}      # the devices moved down by dy, so did every bend point
    page.comb_source = {kept_index[i]: key for i, key in phys.comb_source.items() if i in kept_index}
    for k, c in enumerate(l3conns, len(conns)):
        a, b = nodes[c.a], nodes[c.b]
        pa, pb = (a.x + NODE_W / 2, a.y + NODE_H / 2), (b.x + NODE_W / 2, b.y + NODE_H / 2)
        pair = frozenset((c.a, c.b))
        r = rank[pair]
        rank[pair] += 1
        bow = (60 + 34 * (r // 2)) * (1 if r % 2 == 0 else -1)
        dx, dyy = pb[0] - pa[0], pb[1] - pa[1]
        length = (dx * dx + dyy * dyy) ** 0.5 or 1.0
        obstacles = [(p.x - 6, p.y - 6, p.x + NODE_W + 6, p.y + NODE_H + 56) for key, p in nodes.items() if key not in (c.a, c.b)]
        taken = bows.setdefault(pair, [])
        route = None
        for candidate in _bow_candidates(bow):                       # the arc takes the first bow that leaves every other device (and its caption) alone and is not a sibling's
            if any(abs(candidate - other) < 24 for other in taken):
                continue
            mid = ((pa[0] + pb[0]) / 2 - dyy / length * candidate, (pa[1] + pb[1]) / 2 + dx / length * candidate)
            points = _curve(pa, mid, pb)
            if not any(_touches(points, pa, pb, box) for box in obstacles):
                route, bow = points, candidate
                break
        if route is None:
            mid = ((pa[0] + pb[0]) / 2 - dyy / length * bow, (pa[1] + pb[1]) / 2 + dx / length * bow)
            route = _curve(pa, mid, pb)
        taken.append(bow)
        page.routes[k] = route
    place_labels(page, sub, True)
    touching = {id(e) for e in shown} | {id(m) for e in shown for m in e.members}
    page.l3 = {"model": model, "edges": [(ids[id(e)], e) for e in shown], "all": [(ids[id(e)], e) for e in model.edges + model.grouped if id(e) in touching], "names": {**names}, "colours": colours,
               "under": {ids[id(e)]: under[id(e)].note for e in model.edges + model.grouped if id(e) in touching}}
    return page
