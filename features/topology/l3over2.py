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
import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from .graph import Connection, Graph
from .l3engine import L3Edge, L3Model
from .layout import ENDPOINT_ROLES, MARGIN, NODE_H, NODE_W, Placed
from .labelplace import place_labels
from .satellites import Extra, place as place_satellites
from .scene import Page, _arrange_groups, _box_of, _centre, _clips, _connections_for, _curve, _route, bundle_sites, zone_boxes
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


def _bow_candidates(bow: float, wide: bool = False) -> list[float]:
    """The planned bow first, then the other side, then wider ones on both sides (a straight line is not an arc of the L3 over L2 pages).  ``wide``: a page with zone boxes also tries
    the bows that go round a box, which are much wider."""
    size = abs(bow)
    sign = 1 if bow >= 0 else -1
    out = [bow, -bow]
    for extra in (40, 80) + ((160, 260, 380) if wide else ()):
        out += [sign * (size + extra), -sign * (size + extra)]
    return out


def _touches(points: list[tuple[float, float]], a: tuple[float, float], b: tuple[float, float], box: tuple[float, float, float, float]) -> bool:
    """Does the polyline a - points - b run through the rectangle?"""
    path = [a, *points, b]
    return any(_clips(box, p, q) for p, q in zip(path, path[1:]))


MESH_BOW = 30.0           # planned bow of an arc over a straight mesh cable (the ordinary one is 60)
ARC_ROOM = 260.0          # how far outside the page an arc may swing to get round devices


def _long_bows(length: float, bow: float, taken: list[float]) -> list[float]:
    """Wider bows for a long line: a line across half the page needs a bow of a fraction of its length to clear the devices between its ends (the fixed bows reach 380 px)."""
    sign = 1 if bow >= 0 else -1
    out: list[float] = []
    for share in (0.12, 0.2, 0.3, 0.42):
        size = share * length
        if size > 380:
            out += [sign * size, -sign * size]
    return out


BAND_ROW = 170.0          # height of one row of provider clouds in the WAN band
BAND_AIR = 150.0          # free space above and below the clouds in the band
BAND_SPACING = 250.0      # least distance between two clouds of a row (the label of one never touches the next)
BAND_MAX_ROW = 5          # more clouds than this are set out in two rows
BAND_HIT = 400.0          # what a line through a device costs, in px of length


def _gap_page(phys: Page, g0: float, g1: float, rows: int) -> tuple[Page, float]:
    """``phys`` with the free strip (g0, g1) between two rows of boxes opened to hold ``rows`` rows of clouds: everything at or below the middle of the strip moves down."""
    need = rows * BAND_ROW + 2 * BAND_AIR
    grow = max(0.0, need - (g1 - g0))
    split = (g0 + g1) / 2
    move = lambda y: y + grow if y >= split else y                                   # noqa: E731
    nodes = {k: dataclasses.replace(p, y=move(p.y + NODE_H / 2) - NODE_H / 2) for k, p in phys.nodes.items()}
    boxes = [(t, x, move(y), w, h) for t, x, y, w, h in phys.boxes]
    end_boxes = [(t, x, move(y), w, h) for t, x, y, w, h in phys.end_boxes]
    centers = [(t, x, move(y), w, h) for t, x, y, w, h in phys.centers]
    routes = {i: [(x, move(y)) for x, y in pts] for i, pts in phys.routes.items()}
    zones = [(t, kind, x, move(y), w, h) for t, kind, x, y, w, h in phys.zones]
    return dataclasses.replace(phys, nodes=nodes, boxes=boxes, end_boxes=end_boxes, centers=centers, routes=routes, zones=zones, height=phys.height + grow), grow


def _band_cost(page: Page, placed: dict[str, tuple[float, float]], ends: dict[str, list[str]]) -> float:
    """Length of the straight lines from the clouds to their devices, plus ``BAND_HIT`` for every device (icon and caption) a line runs through on its way."""
    total = 0.0
    for cloud, (cx, cy) in placed.items():
        a = (cx + NODE_W / 2, cy + NODE_H / 2)
        for end in ends[cloud]:
            node = page.nodes.get(end)
            if node is None:
                continue
            b = (node.x + NODE_W / 2, node.y + NODE_H / 2)
            total += math.dist(a, b)
            for key, other in page.nodes.items():
                if key != end and key not in placed and _clips((other.x - 20, other.y - 20, other.x + NODE_W + 20, other.y + NODE_H + 70), a, b):
                    total += BAND_HIT
    return total


def _open_wan_band(phys: Page, ends: dict[str, list[str]]) -> tuple[Page, dict[str, tuple[float, float]]]:
    """Provider clouds that serve devices of several site boxes go between rows of boxes, not above the topmost one.

    A cloud above the page has a line to every site, and the line of a site at the bottom runs over the boxes in between.  The overview's boxes are in rows; every free
    strip between two rows is tried (the lower rows move down until it holds the clouds, one or two rows of them, each cloud at the mean x of its devices), the page with the
    clouds above everything is tried too, and the one where the lines are shortest and run through the fewest devices is kept (``_band_cost``).  Returns the page copy
    with the moved devices, boxes and bend points, and the places of the clouds; an empty dict when the clouds belong above the page."""
    if len(phys.boxes) < 3 or not ends:
        return phys, {}
    centre = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in phys.nodes.items()}
    boxes_of = {k: _box_of(phys, c) for k, c in centre.items()}
    multi = {c: [e for e in es if e in phys.nodes] for c, es in ends.items()}
    multi = {c: es for c, es in multi.items() if len({boxes_of[e] for e in es if boxes_of.get(e) is not None}) >= 2}
    if not multi:
        return phys, {}
    spans = sorted((y, y + h) for _, _, y, _, h in phys.boxes)
    merged: list[list[float]] = []
    for lo, hi in spans:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    gaps = [(merged[i][1], merged[i + 1][0]) for i in range(len(merged) - 1)]
    if not gaps:
        return phys, {}
    rows = 1 if len(multi) <= BAND_MAX_ROW else 2
    order = sorted(multi, key=lambda c: (sum(centre[e][0] for e in multi[c]) / len(multi[c]), c))      # two clouds with the same mean x keep a fixed order, not the order of a set
    best: tuple[float, Page, dict[str, tuple[float, float]]] | None = None
    top = min(y for lo, hi in merged for y in (lo,))
    above = {c: (sum(centre[e][0] for e in multi[c]) / len(multi[c]) - NODE_W / 2, top - 250.0) for c in order}        # the clouds above the page, where the satellites would put them
    best = (_band_cost(phys, above, multi), phys, {})
    for g0, g1 in gaps:
        moved, _ = _gap_page(phys, g0, g1, rows)
        placed: dict[str, tuple[float, float]] = {}
        last = [-1e9] * rows
        for n, cloud in enumerate(order):
            row = n % rows
            want = sum(centre[e][0] for e in multi[cloud]) / len(multi[cloud]) - NODE_W / 2
            x = max(want, last[row] + BAND_SPACING)
            last[row] = x
            placed[cloud] = (x, g0 + BAND_AIR + row * BAND_ROW)
        cost = _band_cost(moved, placed, multi)
        if cost < best[0]:
            best = (cost, moved, placed)
    return best[1], best[2]


FRAME_TITLE = 38.0        # the strip at the top of a site box that holds its title
FRAME_AIR = 22.0          # free space between a provider cloud lifted out of a box and the box
CAPTION_H = 60.0          # what hangs under a cloud: its gateway address and the caption


def _clear_frames(phys: Page, spots: dict[str, tuple[float, float]], ends: dict[str, list[str]], keep: set[str]) -> dict[str, tuple[float, float]]:
    """A provider cloud (or any device nobody captured) that serves the devices of one site box and sits across the top edge of that box, or on its title, goes up out of the box:
    its icon and caption lie wholly above the frame.  A cloud wholly inside the frame, or wholly outside it, stays where it is; so does a cloud that serves several boxes."""
    moved: dict[str, tuple[float, float]] = {}
    for key, (x, y) in spots.items():
        if key in keep or key not in ends:
            continue
        boxes = {_box_of(phys, (phys.nodes[o].x + NODE_W / 2, phys.nodes[o].y + NODE_H / 2)) for o in ends[key] if o in phys.nodes}
        if len(boxes) != 1 or None in boxes:
            continue
        _, bx, by, bw, bh = phys.boxes[next(iter(boxes))]
        top, bottom = y, y + NODE_H + CAPTION_H
        across = top < by < bottom                                           # the top edge of the frame runs through the cloud or its caption
        on_title = by <= top < by + FRAME_TITLE and x < bx + bw and x + NODE_W > bx
        if across or on_title:
            moved[key] = _off_neighbours((x, by - FRAME_AIR - NODE_H - CAPTION_H), key, {**spots, **moved})
    return moved


LIFT_STEP = 40.0          # a node lifted out of a box slides sideways in steps of this many px until its caption clears the others
LIFT_REACH = 14           # ... up to this many steps to either side


def _off_neighbours(point: tuple[float, float], key: str, where: dict[str, tuple[float, float]]) -> tuple[float, float]:
    """The place of a node moved up out of a box, slid sideways when the captions (a cell of ``CELL_W``) of the nodes already there would overlap its own: lifting changed only its height,
    so a neighbour that was clear before may now stand just beside it."""
    from .satellites import CELL_W

    def clear(x: float, y: float) -> bool:
        return all(abs(x - ox) >= CELL_W or abs(y - oy) >= NODE_H + CAPTION_H for other, (ox, oy) in where.items() if other != key)

    if clear(*point):
        return point
    for n in range(1, LIFT_REACH + 1):
        for sign in (1, -1):
            if clear(point[0] + sign * n * LIFT_STEP, point[1]):
                return (point[0] + sign * n * LIFT_STEP, point[1])
    return point


ZONE_AIR = 24.0           # free space between a segment or global node moved off a zone box and the box
ZONE_CAPTION = 56.0       # what hangs under such a node: its name


def _in_zone_of(zones: list[tuple[str, str, float, float, float, float]], point: tuple[float, float]) -> int | None:
    for i, (_, _, x, y, w, h) in enumerate(zones):
        if x <= point[0] <= x + w and y <= point[1] <= y + h:
            return i
    return None


def _clear_zone_edges(phys: Page, spots: dict[str, tuple[float, float]], ends: dict[str, list[str]], keep: set[str]) -> dict[str, tuple[float, float]]:
    """A shared subnet, a global-route node or any other extra of the L3 over L2 page that stands across the edge of a zone box (half in, half out) is moved to the nearest place wholly
    outside that box, or wholly inside it when every device it joins is in that box.  A node wholly inside or wholly outside every box stays; so does one that has no free place."""
    zones = phys.zones
    if not zones:
        return {}
    moved: dict[str, tuple[float, float]] = {}
    taken = [(p.x - 10, p.y - 10, p.x + NODE_W + 10, p.y + NODE_H + ZONE_CAPTION) for p in phys.nodes.values()]
    taken += [(x - 10, y - 10, x + NODE_W + 10, y + NODE_H + ZONE_CAPTION) for k, (x, y) in spots.items() if k in keep]

    def rect(x: float, y: float) -> tuple[float, float, float, float]:
        return (x, y, x + NODE_W, y + NODE_H + ZONE_CAPTION)

    def meets(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> bool:
        return a[0] < b[2] and a[2] > b[0] and a[1] < b[3] and a[3] > b[1]

    def straddles(r: tuple[float, float, float, float]) -> bool:
        for _, _, zx, zy, zw, zh in zones:
            z = (zx, zy, zx + zw, zy + zh)
            if meets(r, z) and not (r[0] >= z[0] and r[2] <= z[2] and r[1] >= z[1] and r[3] <= z[3]):
                return True
        return False

    for key in sorted(spots):
        x, y = spots[key]
        if key in keep or key not in ends or not straddles(rect(x, y)):
            continue
        homes = {_in_zone_of(zones, (phys.nodes[o].x + NODE_W / 2, phys.nodes[o].y + NODE_H / 2)) for o in ends[key] if o in phys.nodes}
        options: list[tuple[float, float]] = []
        for i, (_, _, zx, zy, zw, zh) in enumerate(zones):
            if not meets(rect(x, y), (zx, zy, zx + zw, zy + zh)):
                continue
            options += [(zx - NODE_W - ZONE_AIR, y), (zx + zw + ZONE_AIR, y), (x, zy - NODE_H - ZONE_CAPTION - ZONE_AIR), (x, zy + zh + ZONE_AIR)]
            if homes == {i}:
                options.append((min(max(x, zx + 14), zx + zw - NODE_W - 14), min(max(y, zy + 58), zy + zh - NODE_H - ZONE_CAPTION - 14)))
        best: tuple[float, tuple[float, float]] | None = None
        for ox, oy in options:
            r = rect(ox, oy)
            if straddles(r) or any(meets(r, t) for t in taken):
                continue
            distance = math.dist((x, y), (ox, oy))
            if best is None or distance < best[0]:
                best = (distance, (ox, oy))
        if best is not None:
            moved[key] = best[1]
            taken.append((best[1][0] - 10, best[1][1] - 10, best[1][0] + NODE_W + 10, best[1][1] + NODE_H + ZONE_CAPTION))
    return moved


def l3over2_page(graph: Graph, phys: Page, model: L3Model, colours: dict[str, str], ids: dict[int, str], names: dict[str, str], curved: bool = True,
                 only: set[int] | None = None, name: str = "", lift_clouds: bool = False) -> Page | None:
    """One L3-over-L2 page for one physical page, or None when no L3 link touches its devices.  ``only``: the ids (``id(edge)``) of the L3 links to draw, all others are left out.
    ``lift_clouds``: a cloud of one site that stands across the top edge of its box goes up out of the box (the page of the links between sites, whose boxes are tight)."""
    from .l3page import edge_colour, to_connection
    under = underlay(graph, model)
    for line in model.grouped:                      # a grouped line rides on every cable its members ride on
        chain = sorted({n for m in line.members for n in under[id(m)].conns})
        under[id(line)] = Under(chain, ("carried on " + "; ".join(conn_text(graph, n) for n in chain[:6]) + (" ..." if len(chain) > 6 else "")) if chain else "")
    drawn = model.drawn()
    shown = [e for e in drawn if (e.a in phys.nodes) or (e.b in phys.nodes)]
    shown = [e for e in shown if (e.a in phys.nodes or e.a in model.nodes) and (e.b in phys.nodes or e.b in model.nodes)]
    if only is not None:
        shown = [e for e in shown if id(e) in only]
    if not shown:
        return None
    extras = {k for e in shown for k in (e.a, e.b) if k not in phys.nodes}
    ends: dict[str, list[str]] = {k: [] for k in extras}
    for e in shown:
        for k, other in ((e.a, e.b), (e.b, e.a)):
            if k in extras and other in phys.nodes:
                ends[k].append(other)
    phys, in_band = _open_wan_band(phys, {k: v for k, v in ends.items() if k in model.nodes and model.nodes[k].role_hint == "cloud"})
    fixed = {k: (p.x, p.y) for k, p in phys.nodes.items()}
    fixed.update(in_band)                                                  # the clouds of the band are in the way of the other extras
    cables = [[_centre(phys.nodes[c.a]), *[(float(x), float(y)) for x, y in (phys.routes.get(i) or [])], _centre(phys.nodes[c.b])]
              for i, c in enumerate(phys.connections) if c.a in phys.nodes and c.b in phys.nodes and c.a != c.b]          # a subnet or a cloud icon does not stand on a cable
    spots = place_satellites(fixed, [Extra(k, ends[k], above=(model.nodes[k].role_hint if k in model.nodes else "") in ("cloud", "router")) for k in sorted(extras - set(in_band))], cables)
    spots.update(in_band)
    if lift_clouds:
        spots.update(_clear_frames(phys, spots, ends, set(in_band)))
    spots.update(_clear_zone_edges(phys, spots, ends, set(in_band)))
    xs = [p.x for p in phys.nodes.values()] + [x for x, _ in spots.values()]
    ys = [p.y for p in phys.nodes.values()] + [y for _, y in spots.values()]
    shift_x = max(0.0, MARGIN + 60 - min(xs, default=0.0))                 # an extra put left of / above everything moves the page, not off it
    shift_y = max(0.0, MARGIN - min(ys, default=0.0))
    dy = shift_y
    nodes = {k: Placed(p.x + shift_x, p.y + shift_y, p.tier, p.box, p.depth, p.zone, p.zone_id) for k, p in phys.nodes.items()}
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
        if not rides and (only is not None or all(_guess_to_uncaptured_router(graph, c) for c in originals)):         # the page of the links between sites keeps only the cables that carry one
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
    page = Page(name or phys.name + " · L3 over L2", nodes, set(phys.ghosts), [(t, x + shift_x, y + dy, w, h) for t, x, y, w, h in phys.boxes], conns + l3conns, {}, width, height,
                view="l3over2", graph=sub, curved=True)
    page.end_boxes = [(t, x + shift_x, y + dy, w, h) for t, x, y, w, h in phys.end_boxes]
    page.zones = zone_boxes(graph, page) if getattr(graph, "zone_boxes", True) else []           # the zones of the physical page, from where its icons stand now
    page.zone_note = phys.zone_note if not page.zones else ""
    page.routes = {kept_index[i]: [(x + shift_x, y + dy) for x, y in pts] for i, pts in phys.routes.items() if i in kept_index}      # the devices moved down by dy, so did every bend point
    page.comb_source = {kept_index[i]: key for i, key in phys.comb_source.items() if i in kept_index}
    page.bus = {kept_index[i] for i in phys.bus if i in kept_index}
    page.mesh = {kept_index[i] for i in phys.mesh if i in kept_index}
    meshed = {frozenset((conns[i].a, conns[i].b)) for i in page.mesh}                  # pairs whose cable is a straight mesh line: their arc rides close beside it
    for k, c in enumerate(l3conns, len(conns)):
        a, b = nodes[c.a], nodes[c.b]
        pa, pb = (a.x + NODE_W / 2, a.y + NODE_H / 2), (b.x + NODE_W / 2, b.y + NODE_H / 2)
        pair = frozenset((c.a, c.b))
        r = rank[pair]
        rank[pair] += 1
        bow = ((MESH_BOW if pair in meshed else 60) + 34 * (r // 2)) * (1 if r % 2 == 0 else -1)
        dx, dyy = pb[0] - pa[0], pb[1] - pa[1]
        length = (dx * dx + dyy * dyy) ** 0.5 or 1.0
        obstacles = [(p.x - 6, p.y - 6, p.x + NODE_W + 6, p.y + NODE_H + 56) for key, p in nodes.items() if key not in (c.a, c.b)]
        taken = bows.setdefault(pair, [])
        route = None
        foreign = [(zx, zy, zx + zw, zy + zh) for _, _, zx, zy, zw, zh in page.zones
                   if not (zx <= pa[0] <= zx + zw and zy <= pa[1] <= zy + zh) and not (zx <= pb[0] <= zx + zw and zy <= pb[1] <= zy + zh)]       # a zone box that holds neither end: an arc through it is avoidable
        best_cuts: int | None = None
        hit_bow = bow
        hit_route: tuple[int, int, float, list[tuple[float, float]]] | None = None      # the arc that runs through the fewest devices when none runs through none
        for candidate in _bow_candidates(bow, wide=bool(foreign)) + _long_bows(length, bow, taken):    # the arc takes the first bow that leaves every other device (and its caption) alone, is not a sibling's and cuts no zone box that it need not: with zones, the one that cuts fewest
            if any(abs(candidate - other) < 24 for other in taken):
                continue
            mid = ((pa[0] + pb[0]) / 2 - dyy / length * candidate, (pa[1] + pb[1]) / 2 + dx / length * candidate)
            points = _curve(pa, mid, pb)
            hits = sum(1 for box in obstacles if _touches(points, pa, pb, box))
            if hits:
                if not (-ARC_ROOM <= mid[0] <= width + ARC_ROOM and -ARC_ROOM <= mid[1] <= height + ARC_ROOM):
                    continue                                          # an arc that is only a way out of the page is no better than the line
                key_hits = (hits, sum(1 for box in foreign if _touches(points, pa, pb, box)), abs(candidate))
                if hit_route is None or key_hits < hit_route[:3]:
                    hit_route = (*key_hits, points)
                    hit_bow = candidate
                continue
            cuts = sum(1 for box in foreign if _touches(points, pa, pb, box))
            if best_cuts is None or cuts < best_cuts:
                route, bow, best_cuts = points, candidate, cuts
            if cuts == 0:
                break
        if route is None and hit_route is not None:
            route, bow = hit_route[3], hit_bow                          # no arc is free of devices: the one that crosses the fewest, not the planned one that may cross many
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


SITES_MIN_DEVICES = 40      # an Overview of at least this many icons gets the "between sites" page too ...
SITES_MIN_SHRINK = 0.75     # ... when the devices that carry a link between sites are at most this share of them (otherwise it would be the same picture)


def sites_page(graph: Graph, phys: Page, model: L3Model, colours: dict[str, str], ids: dict[int, str], names: dict[str, str], curved: bool = True) -> Page | None:
    """The L3-over-L2 Overview of a large network, read at the level of sites: only the L3 links that leave a site, on the devices that carry them.

    On an Overview of a hundred devices the L3 links inside a site (the gateway of every VLAN, every point-to-point between core and distribution) are most of the arcs, and
    they run across the other sites' boxes.  An engineer who reads the WAN needs the other links: site to site, site to provider, site to a remote peer.  Here the site boxes
    keep their order, but hold only the devices at the end of such a link (the box title says how many of the site's devices that is); the links inside a site stay on the
    site pages and on the full L3-over-L2 page.  None when the Overview is small or the links between sites touch most of its devices (the full page is then as readable)."""
    if len(phys.boxes) < 2 or len(phys.nodes) < SITES_MIN_DEVICES:
        return None
    where = {key: _box_of(phys, _centre(placed)) for key, placed in phys.nodes.items()}
    reach: dict[str, set[Any]] = defaultdict(set)                 # the sites on each side of a shared segment: one site only, and it is not a link between sites
    for edge in model.drawn():
        for end, other in ((edge.a, edge.b), (edge.b, edge.a)):
            if end in phys.nodes and other not in phys.nodes:
                reach[other].add(where[end])
    between: set[int] = set()
    keep: set[str] = set()
    for edge in model.drawn():
        a_in, b_in = edge.a in phys.nodes, edge.b in phys.nodes
        if a_in and b_in:
            if where[edge.a] is not None and where[edge.a] == where[edge.b]:
                continue
            keep |= {edge.a, edge.b}
        elif a_in != b_in:
            far = edge.b if a_in else edge.a
            if far in graph.nodes or (model.nodes[far].role_hint == "segment" and len(reach[far]) < 2):         # a captured device that is not on this page; a VLAN of one site
                continue
            keep.add(edge.a if a_in else edge.b)
        else:
            continue
        between.add(id(edge))
    if not between or len(keep) > SITES_MIN_SHRINK * len(phys.nodes):
        return None
    title_of = {key: (phys.boxes[i][0] if i is not None else "Other devices") for key, i in where.items()}
    groups: dict[str, list[str]] = defaultdict(list)
    for key in sorted(keep):
        groups[title_of[key]].append(key)
    sizes = {title: sum(1 for k, t in title_of.items() if t == title and graph.nodes[k].captured and graph.nodes[k].role_hint not in ENDPOINT_ROLES) for title in set(title_of.values())}
    total = Counter(title_of.values())
    small = dataclasses.replace(graph, nodes={k: graph.nodes[k] for k in keep}, connections=[c for c in graph.connections if c.a in keep and c.b in keep])
    nodes, boxes, width, height = _arrange_groups(small, dict(groups), sizes)
    base = Page("Sites", nodes, set(), [(f"{t} · {len(groups[t])} of {total[t]} devices", x, y, w, h) for t, x, y, w, h in boxes], [], {}, width, height)
    base.curved = curved
    base.connections = _connections_for(small, set(nodes))
    bundle_sites(small, base)
    _route(base)
    return l3over2_page(graph, base, model, colours, ids, names, curved, only=between, name="Sites · L3 over L2", lift_clouds=True)
