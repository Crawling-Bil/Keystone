"""Turn a Graph into drawable pages: node coordinates, group boxes, and routed lines for each page."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .graph import Connection, Graph
from .layout import BOX_HALF, BOX_MIN, MARGIN, NODE_H, NODE_W, X_STEP, Y_STEP, Placed, groups_of, layered

PAGE_ROW_WIDTH = 3200
BOX_PAD = 60
TITLE_H = 40
Layout = dict[str, dict[str, tuple[float, float]]]


@dataclass
class PairBox:
    """The frame drawn around the two switches of a vPC / MLAG pair in the logical view."""

    key: str
    title: str
    members: tuple[str, str]
    x: float
    y: float
    w: float
    h: float

    @property
    def centre(self) -> tuple[float, float]:
        return self.x + self.w / 2, self.y + self.h / 2


@dataclass
class TableBox:
    """A text table under the IP view: the interfaces of one device with description and address."""

    title: str
    header: list[str]
    rows: list[list[str]]
    x: float = 0
    y: float = 0
    w: float = 0
    h: float = 0


@dataclass
class Shape:
    """A free-form box on a page that is not a device: the virtual servers, pools, pool members and nodes of the F5 map (see ``f5page``)."""

    ident: str                  # unique on the page
    kind: str                   # external | pool | member | node
    x: float
    y: float
    w: float
    h: float
    lines: list[str] = field(default_factory=list)   # label rows, the first one bold
    status: str = ""            # F5 object status (available, unverified, unknown, unavailable, offline, disabled, forced down, parent disabled) or ""
    attrs: dict[str, str] = field(default_factory=dict)   # what the box stands for: written as attributes of the draw.io cell and as the tooltip of the preview


@dataclass
class ShapeEdge:
    """A line between two shapes, or between a shape and a device of the page (``node:KEY``)."""

    a: str
    b: str
    status: str = ""
    points: list[tuple[float, float]] = field(default_factory=list)     # the whole path from the first shape to the second (empty: a straight line)


ROW_H = 17


def table_columns(table: TableBox) -> list[float]:
    """Width in px of every column of a table: the longest cell at 10 px text, between 56 and 260."""
    widths = []
    for i, name in enumerate(table.header):
        longest = max([len(name)] + [len(str(row[i])) for row in table.rows if i < len(row)])
        widths.append(min(260.0, max(56.0, longest * 5.8 + 14)))
    return widths


@dataclass
class Page:
    name: str
    nodes: dict[str, Placed] = field(default_factory=dict)
    ghosts: set[str] = field(default_factory=set)
    boxes: list[tuple[str, float, float, float, float]] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    routes: dict[int, list[tuple[float, float]]] = field(default_factory=dict)   # connection index -> waypoints
    width: float = 0
    height: float = 0
    kept: int = 0
    pair_boxes: dict[str, PairBox] = field(default_factory=dict)    # logical view only
    view: str = "physical"                                           # physical | logical | ip
    label_pos: dict[tuple[int, str], tuple[float, float, float]] = field(default_factory=dict)   # (connection index, a|b|mid) -> x, y, share of the line
    tables: list["TableBox"] = field(default_factory=list)           # IP view: interface tables under the diagram
    l3: dict[str, Any] = field(default_factory=dict)                  # L3 pages: the model, the edges by id and the VRF colours
    curved: bool = False                                              # lines that must go around a device are drawn as smooth curves, not bent lines
    legend_extra: list[tuple[str, str]] = field(default_factory=list)  # (colour, text) rows added to the legend (one per VRF)
    graph: Any = None                                                # IP view: the small graph that holds this page's own nodes and lines
    end_boxes: list[tuple[str, float, float, float, float]] = field(default_factory=list)   # "group end points": (switch name, x, y, w, h) of the frame round the end points of one switch
    shapes: list["Shape"] = field(default_factory=list)              # F5 map: virtual servers, pools, members, nodes
    shape_edges: list["ShapeEdge"] = field(default_factory=list)
    comb_source: dict[int, str] = field(default_factory=dict)       # connection index -> the switch end of a comb line (its port label stands on the drop beside that switch)


def _connections_for(graph: Graph, keys: set[str]) -> list[Connection]:
    return [c for c in graph.connections if c.a in keys and c.b in keys and c.kind not in graph.hidden_kinds]


def _apply_saved(page: Page, saved: dict[str, tuple[float, float]]) -> None:
    """Put nodes the user already placed back where they were; slide new nodes off the saved ones."""
    kept = {key: pos for key, pos in saved.items() if key in page.nodes}
    page.kept = len(kept)
    if not kept:
        return
    taken = [(x, y) for x, y in kept.values()]
    for key, placed in page.nodes.items():
        if key in kept:
            placed.x, placed.y = kept[key]
    for key, placed in page.nodes.items():
        if key in kept:
            continue
        step = 0
        while any(abs(placed.x - x) < X_STEP * 0.7 and abs(placed.y - y) < Y_STEP * 0.7 for x, y in taken) and step < 60:
            step += 1
            placed.y += Y_STEP * 0.5
            if step % 6 == 0:
                placed.y -= Y_STEP * 3
                placed.x += X_STEP * 0.5
        taken.append((placed.x, placed.y))


def endpoint_boxes(graph: Graph, page: Page) -> list[tuple[str, float, float, float, float]]:
    """The frame round the end points of each switch, from where the icons really are (so a layout kept from an earlier file keeps its frames too).
    Title = host name of the switch; the frame covers the icons, their labels and a strip for the title."""
    members: dict[str, list[Placed]] = defaultdict(list)
    for key, placed in page.nodes.items():
        if placed.box:
            members[placed.box].append(placed)
    out = []
    for parent, group in sorted(members.items()):
        if len(group) < BOX_MIN:
            continue
        x0 = min(p.x for p in group) + NODE_W / 2 - BOX_HALF
        x1 = max(p.x for p in group) + NODE_W / 2 + BOX_HALF
        y0 = min(p.y for p in group) - 46
        y1 = max(p.y for p in group) + NODE_H + 62
        node = graph.nodes.get(parent)
        out.append((node.hostname if node else parent, x0, y0, x1 - x0, y1 - y0))
    return out


def _frames(page: Page) -> dict[str, tuple[tuple[float, float, float, float], set[str]]]:
    """{owner switch: (rectangle of its frame of end points, the keys of the end points)}: the same rectangles as ``endpoint_boxes``, found by the owner's key."""
    members: dict[str, list[str]] = defaultdict(list)
    for key, placed in page.nodes.items():
        if placed.box:
            members[placed.box].append(key)
    out = {}
    for parent, keys in members.items():
        if len(keys) < BOX_MIN:
            continue
        group = [page.nodes[k] for k in keys]
        out[parent] = ((min(p.x for p in group) + NODE_W / 2 - BOX_HALF, min(p.y for p in group) - 46,
                        max(p.x for p in group) + NODE_W / 2 + BOX_HALF, max(p.y for p in group) + NODE_H + 62), set(keys))
    return out


def _bounds(page: Page) -> None:
    if not page.nodes:
        return
    xs = [p.x for p in page.nodes.values()]
    ys = [p.y for p in page.nodes.values()]
    page.width = max(xs) + NODE_W + MARGIN - min(0, min(xs))
    page.height = max(ys) + NODE_H + 80 + MARGIN - min(0, min(ys))


def _group_boxes(graph: Graph, page: Page, groups: dict[str, list[str]]) -> None:
    page.boxes = []
    for name, keys in sorted(groups.items()):
        placed = [page.nodes[k] for k in keys if k in page.nodes]
        if placed:
            x0, y0 = min(p.x for p in placed) - BOX_PAD, min(p.y for p in placed) - BOX_PAD - TITLE_H
            x1, y1 = max(p.x for p in placed) + NODE_W + BOX_PAD, max(p.y for p in placed) + NODE_H + BOX_PAD + 50
            page.boxes.append((name, x0, y0, x1 - x0, y1 - y0))


HUB_DOMINANCE = 2.0       # a site this many times larger than all the others together keeps them in one column beside it (see ``_side_stack``)


def _side_stack(hub: str, side: list[str], weight: dict[str, dict[str, int]]) -> list[str]:
    """The small sites beside a very large one, top to bottom: the one linked most to the big site first, then each next one the site linked most to the one
    before it (the lines between neighbours stay short and never run past a third box); "Other devices" last."""
    rest = [n for n in side if n != "Other devices"]
    order: list[str] = []
    while rest:
        last = order[-1] if order else hub
        pick = max(rest, key=lambda n: (weight[last].get(n, 0), weight[hub].get(n, 0), [-ord(c) for c in n]))
        order.append(pick)
        rest.remove(pick)
    return order + [n for n in side if n == "Other devices"]


def _arrange_groups(graph: Graph, groups: dict[str, list[str]]) -> tuple[dict[str, Placed], list[tuple[str, float, float, float, float]], float, float]:
    """Boxes of the groups on one page: the group with the most lines to other groups sits in the middle cell of a square grid, the groups it is
    linked to most come next around it, the rest further out ("Other devices" last).  A cell is as wide as the widest box of its column and
    as high as the tallest of its row, so boxes never overlap."""
    layouts: dict[str, tuple[dict[str, Placed], float, float]] = {}
    for name, keys in groups.items():
        placed, width, height = layered(graph, keys, 0, 0)
        layouts[name] = (placed, width + BOX_PAD, height + TITLE_H + BOX_PAD)
    owner = {key: name for name, keys in groups.items() for key in keys}
    weight: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds:
            continue
        a, b = owner.get(conn.a), owner.get(conn.b)
        if a and b and a != b:
            weight[a][b] += 1
            weight[b][a] += 1
    degree = {name: sum(weight[name].values()) for name in groups}
    hub = max((n for n in groups if n != "Other devices"), key=lambda n: (degree[n], len(groups[n]), n), default=next(iter(groups)))
    ranked = [hub] + sorted((n for n in groups if n != hub), key=lambda n: (n == "Other devices", -weight[hub].get(n, 0), -degree[n], n))
    count = len(ranked)
    area = {n: layouts[n][1] * layouts[n][2] for n in groups}
    big = max(groups, key=lambda n: (area[n], n))                  # the largest site, whichever site has the most lines
    side = [n for n in ranked if n != big]
    if len(side) >= 2 and area[big] >= HUB_DOMINANCE * sum(area[n] for n in side):
        hub = big
        stack = _side_stack(hub, side, weight)
        nodes: dict[str, Placed] = {}
        boxes: list[tuple[str, float, float, float, float]] = []
        x_side = layouts[hub][1] + BOX_PAD
        y = 0.0
        spots = {hub: (0.0, 0.0)}
        for name in stack:
            spots[name] = (x_side, y)
            y += layouts[name][2] + BOX_PAD
        for name in sorted(groups):
            placed, box_w, box_h = layouts[name]
            bx, by = spots[name]
            for key, p in placed.items():
                nodes[key] = Placed(p.x + bx + BOX_PAD, p.y + by + BOX_PAD + TITLE_H, p.tier, p.box)
            boxes.append((name, bx, by, box_w, box_h))
        wide = x_side + max(layouts[n][1] for n in stack)
        return nodes, boxes, max(wide - BOX_PAD, 0.0), max(max(layouts[hub][2], y - BOX_PAD), 0.0) + BOX_PAD
    cols = max(1, math.ceil(math.sqrt(count)))
    cols += 1 - cols % 2                                   # an odd number of columns and rows: there is a middle cell
    rows = max(1, math.ceil(count / cols))
    rows += 1 - rows % 2
    centre_r, centre_c = rows // 2, cols // 2
    cells = sorted(((r, c) for r in range(rows) for c in range(cols)), key=lambda rc: ((rc[0] - centre_r) ** 2 + (rc[1] - centre_c) ** 2, abs(rc[1] - centre_c), rc))[:count]
    cell_of = dict(zip(ranked, cells))
    col_w = {c: max((layouts[n][1] for n, (_, cc) in cell_of.items() if cc == c), default=0.0) for c in range(cols)}
    row_h = {r: max((layouts[n][2] for n, (rr, _) in cell_of.items() if rr == r), default=0.0) for r in range(rows)}
    col_x, row_y, x, y = {}, {}, 0.0, 0.0
    for c in range(cols):
        col_x[c] = x
        x += col_w[c] + (BOX_PAD if col_w[c] else 0)
    for r in range(rows):
        row_y[r] = y
        y += row_h[r] + (BOX_PAD if row_h[r] else 0)
    nodes: dict[str, Placed] = {}
    boxes: list[tuple[str, float, float, float, float]] = []
    for name in sorted(groups):
        placed, box_w, box_h = layouts[name]
        r, c = cell_of[name]
        bx, by = col_x[c] + (col_w[c] - box_w) / 2, row_y[r]
        for key, p in placed.items():
            nodes[key] = Placed(p.x + bx + BOX_PAD, p.y + by + BOX_PAD + TITLE_H, p.tier, p.box)
        boxes.append((name, bx, by, box_w, box_h))
    return nodes, boxes, max(x - BOX_PAD, 0.0), max(y - BOX_PAD, 0.0) + BOX_PAD


def build_pages(graph: Graph, group_mode: str = "none", layout: Layout | None = None, curved: bool = False) -> list[Page]:
    groups = groups_of(graph, group_mode)
    overview = Page("Overview")
    if len(groups) == 1:
        placed, width, height = layered(graph, groups["All devices"] if "All devices" in groups else list(graph.nodes))
        overview.nodes, overview.width, overview.height = placed, width, height
    else:
        overview.nodes, overview.boxes, overview.width, overview.height = _arrange_groups(graph, groups)
    saved = layout or {}
    if saved.get("Overview") or (saved and len(saved) == 1):
        _apply_saved(overview, saved.get("Overview") or next(iter(saved.values())))
        _bounds(overview)
        if len(groups) > 1:
            _group_boxes(graph, overview, groups)
    overview.connections = _connections_for(graph, set(overview.nodes))
    pages = [overview]
    if len(groups) > 1:
        for name, keys in sorted(groups.items()):
            keyset = set(keys)
            ghosts = {c.b if c.a in keyset else c.a for c in graph.connections
                      if (c.a in keyset) != (c.b in keyset) and c.kind not in graph.hidden_kinds
                      and c.a not in graph.hidden_nodes and c.b not in graph.hidden_nodes}
            shown = list(keyset | ghosts)
            placed, width, height = layered(graph, shown)
            page = Page(name, placed, ghosts, [], [], {}, width, height)
            if saved.get(name):
                _apply_saved(page, saved[name])
                _bounds(page)
            page.connections = _connections_for(graph, set(shown))
            pages.append(page)
    for page in pages:
        page.curved = curved
        page.end_boxes = endpoint_boxes(graph, page)
        _route(page)
    return pages


# ---- line routing -------------------------------------------------------------------------------------------------

def _centre(placed: Placed) -> tuple[float, float]:
    return placed.x + NODE_W / 2, placed.y + NODE_H / 2


def _hits(p: tuple[float, float], q: tuple[float, float], obstacles: list[tuple[float, float, float, float]]) -> bool:
    """Does the segment p-q cross one of the boxes (x0, y0, x1, y1)?"""
    length = max(abs(q[0] - p[0]), abs(q[1] - p[1]))
    steps = max(int(length // 12), 2)
    for i in range(1, steps):
        x = p[0] + (q[0] - p[0]) * i / steps
        y = p[1] + (q[1] - p[1]) * i / steps
        for x0, y0, x1, y1 in obstacles:
            if x0 < x < x1 and y0 < y < y1:
                return True
    return False


# ---- lines between site boxes (Overview with groups) ----------------------------------------------------------------

LANES = 5               # parallel lanes a bundle of lines between two boxes is spread over
LANE_STEP = 7.0         # px between two lanes
BOX_CLEAR = 14.0        # first lane's distance from a box it goes around
BEND_COST = 30.0        # a route prefers to be a little longer over one more bend


def _clips(rect: tuple[float, float, float, float], a: tuple[float, float], b: tuple[float, float]) -> bool:
    """Does the segment a-b pass through the inside of the rectangle (x0, y0, x1, y1)?  (Liang-Barsky)"""
    x0, y0, x1, y1 = rect
    (ax, ay), (bx, by) = a, b
    dx, dy = bx - ax, by - ay
    t0, t1 = 0.0, 1.0
    for p, q in ((-dx, ax - x0), (dx, x1 - ax), (-dy, ay - y0), (dy, y1 - ay)):
        if p == 0:
            if q <= 0:
                return False
        else:
            t = q / p
            if p < 0:
                t0 = max(t0, t)
            else:
                t1 = min(t1, t)
            if t0 >= t1:
                return False
    return True


def _box_of(page: Page, point: tuple[float, float]) -> int | None:
    """Index in ``page.boxes`` of the smallest group box that holds the point."""
    best, area = None, 0.0
    for i, (_, x, y, w, h) in enumerate(page.boxes):
        if x <= point[0] <= x + w and y <= point[1] <= y + h and (best is None or w * h < area):
            best, area = i, w * h
    return best


def _route_around_boxes(page: Page, centres: dict[str, tuple[float, float]]) -> set[int]:
    """Lines between two group boxes that would cross a third box go around it: the shortest path over the corners of the boxes, a little off
    their edges, with a lane per line so that a bundle between two boxes fans out instead of lying on one line.  Returns the indexes routed."""
    import heapq
    if len(page.boxes) < 3:
        return set()
    rects = [(x, y, x + w, y + h) for _, x, y, w, h in page.boxes]
    box_index = {key: _box_of(page, c) for key, c in centres.items() if key in page.nodes}
    members: dict[int, list[str]] = defaultdict(list)
    for key, i in box_index.items():
        if i is not None:
            members[i].append(key)
    node_rect = {k: (p.x - 8, p.y - 8, p.x + NODE_W + 8, p.y + NODE_H + 52) for k, p in page.nodes.items()}
    lane_of: dict[tuple[int, int], int] = defaultdict(int)
    graphs: dict[float, tuple[list[tuple[float, float]], list[list[tuple[int, float]]]]] = {}

    def corner_graph(margin: float):
        if margin not in graphs:
            points = []
            for x0, y0, x1, y1 in rects:
                points += [(x0 - margin, y0 - margin), (x1 + margin, y0 - margin), (x0 - margin, y1 + margin), (x1 + margin, y1 + margin)]
            adjacency: list[list[tuple[int, float]]] = [[] for _ in points]
            for i in range(len(points)):
                for j in range(i + 1, len(points)):
                    if not any(_clips(r, points[i], points[j]) for r in rects):
                        d = math.dist(points[i], points[j])
                        adjacency[i].append((j, d))
                        adjacency[j].append((i, d))
            graphs[margin] = (points, adjacency)
        return graphs[margin]

    routed: set[int] = set()
    for index, conn in enumerate(page.connections):
        if conn.a not in box_index or conn.b not in box_index:
            continue
        ga, gb = box_index[conn.a], box_index[conn.b]
        if ga is None or gb is None or ga == gb:
            continue
        a, b = centres[conn.a], centres[conn.b]
        foreign = [r for i, r in enumerate(rects) if i not in (ga, gb)]
        if not any(_clips(r, a, b) for r in foreign):
            continue
        pair = (min(ga, gb), max(ga, gb))
        lane = lane_of[pair] % LANES
        lane_of[pair] += 1
        points, adjacency = corner_graph(BOX_CLEAR + LANE_STEP * lane)
        near = [node_rect[k] for g in (ga, gb) for k in members[g] if k not in (conn.a, conn.b)]
        obstacles = foreign + near
        n = len(points)
        start, goal = n, n + 1
        extra: dict[int, list[tuple[int, float]]] = {start: [], goal: []}
        for end, ident in ((a, start), (b, goal)):
            for j, q in enumerate(points):
                if not any(_clips(r, end, q) for r in obstacles):
                    d = math.dist(end, q)
                    extra[ident].append((j, d))
                    extra.setdefault(j, []).append((ident, d))
        if not any(_clips(r, a, b) for r in obstacles):
            extra[start].append((goal, math.dist(a, b)))
        best = {start: 0.0}
        came: dict[int, int] = {}
        queue = [(0.0, start)]
        while queue:
            cost, u = heapq.heappop(queue)
            if u == goal:
                break
            if cost > best.get(u, 1e18):
                continue
            for v, d in (adjacency[u] if u < n else []) + extra.get(u, []):
                step = cost + d + (BEND_COST if u != start and v != goal else 0.0)
                if step < best.get(v, 1e18):
                    best[v] = step
                    came[v] = u
                    heapq.heappush(queue, (step, v))
        if goal not in came:
            continue
        path, node = [], came[goal]
        while node != start:
            path.append(points[node])
            node = came[node]
        path.reverse()
        if path:
            page.routes[index] = path
            routed.add(index)
    return routed


# ---- lines to the end points of one switch (a comb instead of a fan) ---------------------------------------------------

COMB_STEP = 12.0         # px between two lines that drop beside the same switch
COMB_STEP_MIN = 4.0      # ... and no closer than this when a switch has very many lines
COMB_LANE_MIN = 2.0      # no lane closer than this
COMB_CLEAR = 62.0        # the first line drops this far from the centre of its switch: beside the icon and the text under it
COMB_EXIT = 5.0          # px between two lines that leave the side of the icon
COMB_LANE = 6.0          # px between two horizontal runs of the comb above a frame
COMB_CHANNEL = 5.0       # px between two lines that share the vertical channel beside one column of end points
COMB_OUTER = 64.0        # a line that takes the strip on the far side of its column runs this far from the column's centre: clear of the names, and well apart from the line that ends in the next column


def _route_comb(page: Page, centres: dict[str, tuple[float, float]], boxes: dict[str, tuple[float, float, float, float]], skip: set[int]) -> set[int]:
    """Lines from a switch to the end points in a frame (option "group end points") run as a comb: down from the switch, along a lane just above the
    frame, then down the free channel beside the column of the end point and into it.  The farther the end point, the farther out and the higher
    the lane, so the lines never cross each other.  Straight lines (end point right below) and lines that would hit a device stay as they are."""
    members: dict[str, list[str]] = defaultdict(list)
    for key, placed in page.nodes.items():
        if placed.box and placed.box in page.nodes:
            members[placed.box].append(key)
    frames: dict[str, tuple[float, float, float, float]] = {}
    pitch: dict[str, float] = {}
    for parent, keys in members.items():
        if len(keys) < BOX_MIN:
            continue
        xs = sorted({round(page.nodes[k].x) for k in keys})
        gaps = [b - a for a, b in zip(xs, xs[1:]) if b - a > 20]
        pitch[parent] = min(gaps) if gaps else X_STEP
        frames[parent] = (min(page.nodes[k].x for k in keys) + NODE_W / 2 - BOX_HALF, min(page.nodes[k].y for k in keys) - 46,
                          max(page.nodes[k].x for k in keys) + NODE_W / 2 + BOX_HALF, max(page.nodes[k].y for k in keys) + NODE_H + 62)
    if not frames:
        return set()
    # which lines: (frame parent, source key, target key, index)
    lines: dict[str, dict[str, list[tuple[int, str]]]] = defaultdict(lambda: defaultdict(list))
    for index, conn in enumerate(page.connections):
        if index in skip or conn.a not in page.nodes or conn.b not in page.nodes:
            continue
        pa, pb = page.nodes[conn.a].box, page.nodes[conn.b].box
        if pa in frames and pb != pa:
            target, source, parent = conn.a, conn.b, pa
        elif pb in frames and pa != pb:
            target, source, parent = conn.b, conn.a, pb
        else:
            continue
        if page.nodes[source].box in frames:
            continue                                                  # end point to end point of another frame: leave it
        lines[parent][source].append((index, target))
    done: set[int] = set()
    centred: set[int] = set()
    for parent, by_source in lines.items():
        x0, y0, x1, y1 = frames[parent]
        step = pitch[parent]
        top = y0 - 14.0                                               # lowest lane
        lane = 0
        # the source that is lowest on the page takes the lowest lanes (its lines are the shortest)
        for source, group in sorted(by_source.items(), key=lambda kv: -centres[kv[0]][1]):
            sx, sy = centres[source]
            lane_step = min(COMB_LANE, (top - sy - NODE_H - 54) / (len(group) + 1))
            if lane_step < COMB_LANE_MIN:
                continue                                              # frame too close below the switch for a comb
            sides = {-1: [], 0: [], 1: []}
            for index, target in group:
                dx = centres[target][0] - sx
                sides[-1 if dx < -6 else 1 if dx > 6 else 0].append((abs(dx), index, target))
            for index, target in group:                               # an end point right below the switch: the first row keeps its straight line, the rows below it take a strip beside the column
                if abs(centres[target][0] - sx) > 6:
                    continue
                tx, ty = centres[target]
                if any(abs(centres[m][0] - tx) < 10 and centres[m][1] < ty - 10 for m in members[parent]):
                    side = -1 if len(sides[-1]) <= len(sides[1]) else 1
                    sides[side].append((0.0, index, target))
                    centred.add(index)
            for side in (-1, 1):
                cands = []                                            # (index, target, inner channel x, outer channel x); None for a first-row end point (the lane ends right above it)
                for _, index, target in sides[side]:
                    tx, ty = centres[target]
                    column = [m for m in members[parent] if abs(centres[m][0] - tx) < 10]
                    if not any(centres[m][1] < ty - 10 for m in column):
                        cands.append((index, target, None, None))
                        continue
                    above = sum(1 for m in column if centres[m][1] < ty - 10 and any(m == t for _, _, t in sides[side]))
                    k = max(above - 1, 0)                                  # the rows above use the channel too: each line sits a little further in (to the switch) / out (away from it)
                    if index in centred:
                        cands.append((index, target, float(k), None))        # right below the switch: it drops beside the column on its own side (the deeper the row, the farther out)
                    else:
                        cands.append((index, target, tx - side * (step / 2 + COMB_CHANNEL * k), tx + side * (COMB_OUTER + COMB_CHANNEL * k)))
                limit = _comb_wall(boxes, source, sx, sy, top, side) - 6.0         # the drops stay between the switch and the first device beside it
                if limit < COMB_CLEAR + 2.0:
                    continue                                          # a device stands right beside the switch: no room for drops
                entries, drop = _comb_order(cands, centres, sx, side, centred, limit)
                count = len(entries)
                exit_step = min(COMB_EXIT, 28.0 / max(count, 1))
                for rank, (reach, index, target, chan) in enumerate(entries):
                    tx, ty = centres[target]
                    if reach - 6 < COMB_CLEAR:
                        continue                                      # right beside the switch: no room for a drop, the line stays as it is
                    off = sx + side * min(COMB_CLEAR + drop * rank, reach - 6, limit)       # never beyond the far end of the lane: a lane runs outwards only
                    y = top - lane_step * (lane + rank)
                    leave = sy + 6 + (count - 1 - rank) * exit_step      # below the middle line of the icon (a link to the next switch leaves there); the farther line leaves higher
                    head = [(sx + side * NODE_W / 2, leave), (off, leave)]
                    path = head + ([(off, ty)] if index in centred else [(off, y), (tx, y)] if chan is None else [(off, y), (chan, y), (chan, ty)])
                    if _comb_free(path, centres[source], (tx, ty), boxes, {source, target}):
                        page.routes[index] = path if page.connections[index].a == source else path[::-1]     # a route runs from the line's first end to its second
                        page.comb_source[index] = source
                        done.add(index)
                lane += count
    return done


def _comb_order(cands: list[tuple[int, str, float | None, float | None]], centres: dict[str, tuple[float, float]], sx: float, side: int, centred: set[int], limit: float = 1e9) -> tuple[list[tuple[float, int, str, float | None]], float]:
    """The lines of one side of a switch, nearest first (lowest lane, least outward: no two lines cross), and the px between two drops.  A line drops at
    ``COMB_CLEAR + drop * rank`` and its lane then runs outwards to the strip or the end point, so that distance must be smaller than its reach; the drops
    are pulled together before a line takes the strip on the far side of its column (which makes it turn back)."""
    outer: set[int] = set()
    top_drop = max(COMB_STEP_MIN, min(COMB_STEP, 360.0 / max(len(cands), 1)))
    room = (limit - COMB_CLEAR) / max(len(cands) - 1, 1)               # px per drop that fit between the switch and the first device beside it
    floor = COMB_STEP_MIN if room >= COMB_STEP_MIN else max(2.0, room)
    top_drop = max(floor, min(top_drop, room))
    while True:
        entries = []
        for index, target, inner, far in cands:
            tx = centres[target][0]
            chan = far if index in outer and far is not None else inner
            if index in centred:
                entries.append((float("inf"), index, target, None))        # right below the switch: nearest of all, the deeper row the farther out
                continue
            entries.append((side * ((tx if chan is None else chan) - sx), index, target, chan))      # how far out, signed: a strip on the other side of the switch is no strip for this side
        order = {index: inner for index, _, inner, _ in cands}
        entries.sort(key=lambda e: (e[1] not in centred, order[e[1]] if e[1] in centred else e[0], e[1]))
        drop = top_drop
        while True:
            bad = [e for rank, e in enumerate(entries) if e[1] not in centred and e[0] - 6 < COMB_CLEAR + drop * rank]
            if not bad or drop <= floor:
                break
            drop = max(floor, drop - 1.0)
        movable = [e for e in bad if e[3] is not None and e[1] not in outer and next(c for c in cands if c[0] == e[1])[3] is not None]
        if not movable:
            return entries, drop
        outer.add(movable[0][1])


def _comb_wall(boxes: dict[str, tuple[float, float, float, float]], source: str, sx: float, sy: float, top: float, side: int) -> float:
    """How far beside a switch (px from its centre) the first device on that side stands in the band between the switch and the lanes."""
    wall = 1e9
    for key, (x0, y0, x1, y1) in boxes.items():
        if key == source or y1 < sy + NODE_H / 2 or y0 > top:
            continue
        edge = side * ((x0 if side > 0 else x1) - sx)
        if edge > NODE_W / 2:
            wall = min(wall, edge)
    return wall


def _comb_free(path: list[tuple[float, float]], start: tuple[float, float], end: tuple[float, float], boxes: dict[str, tuple[float, float, float, float]], ends: set[str]) -> bool:
    """No device (except the two ends) lies on the line start -> path -> end."""
    points = [start, *path, end]
    for key, rect in boxes.items():
        if key in ends:
            continue
        if any(_clips(rect, p, q) for p, q in zip(points, points[1:])):
            return False
    return True


def _detour(a: tuple[float, float], b: tuple[float, float], d: tuple[float, float], n: tuple[float, float], spread: float, bridge: bool, lifts: list[float],
            others: list[tuple[float, float, float, float]]) -> list[tuple[float, float]] | None:
    """The first of the ``lifts`` (px sideways from the straight line) that gets a line from a to b round every obstacle: two corners over them (a bridge) or one bend."""
    (dx, dy), (nx, ny) = d, n
    length = (dx * dx + dy * dy) ** 0.5 or 1.0
    mid = ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2)
    for lift in lifts:
        if bridge:
            t = BRIDGE_END / length
            path = [(a[0] + dx * t + nx * lift, a[1] + dy * t + ny * lift), (b[0] - dx * t + nx * lift, b[1] - dy * t + ny * lift)]
            if all(not _hits(p, q, others) for p, q in zip([a, *path], [*path, b])):
                return path
            continue
        point = (mid[0] + nx * (spread + lift), mid[1] + ny * (spread + lift))
        if not _hits(a, point, others) and not _hits(point, b, others):
            return [point]
    return None


def _route(page: Page) -> None:
    """Straight lines unless they would cross a device or lie on top of a sibling line; then bend them once."""
    centres = {k: _centre(p) for k, p in page.nodes.items()}
    centres.update({k: box.centre for k, box in page.pair_boxes.items()})
    boxes = {k: (p.x - 8, p.y - 8, p.x + NODE_W + 8, p.y + NODE_H + 52) for k, p in page.nodes.items()}
    inside = {member: key for key, box in page.pair_boxes.items() for member in box.members}
    siblings: dict[frozenset, list[int]] = {}
    for index, conn in enumerate(page.connections):
        siblings.setdefault(frozenset((conn.a, conn.b)), []).append(index)
    frames = _frames(page)
    around = _route_around_boxes(page, centres) if page.boxes else set()
    around |= _route_comb(page, centres, boxes, around)          # a curved page keeps its comb too: the corners are rounded when drawn (svg, draw.io `rounded=1`)
    for index, conn in enumerate(page.connections):
        if conn.a not in centres or conn.b not in centres or index in around:
            continue
        a, b = centres[conn.a], centres[conn.b]
        ends = {conn.a, conn.b}
        for end in (conn.a, conn.b):                       # a line to a frame also leaves its two switches alone
            if end in page.pair_boxes:
                ends.update(page.pair_boxes[end].members)
            elif end in inside:
                ends.add(inside[end])
        others = [box for key, box in boxes.items() if key not in ends]
        others += [(box.x, box.y, box.x + box.w, box.y + box.h) for key, box in page.pair_boxes.items() if key not in ends]
        crossing = [rect for owner, (rect, kids) in frames.items() if owner not in ends and not (kids & ends)]
        others += crossing                                                  # a line that is not one of the frame's own goes round it
        wide = [460, -460, 620, -620] if crossing else []                  # a frame is wide: the lanes beside it may need to lie farther out
        group = siblings[frozenset((conn.a, conn.b))]
        spread = (group.index(index) - (len(group) - 1) / 2) * 34 if len(group) > 1 else 0.0
        dx, dy = b[0] - a[0], b[1] - a[1]
        length = (dx * dx + dy * dy) ** 0.5 or 1.0
        nx, ny = -dy / length, dx / length                      # unit normal
        mid = ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2)
        if not spread and not _hits(a, b, others):
            continue
        bridge = not page.curved and not spread and length > 3 * BRIDGE_END          # a blocked line between two devices of one row goes over them like a bridge, not as a peak
        lifts = [0.0] if spread and not _hits(a, b, others) else [0.0, 70, -70, 140, -140, 220, -220, 320, -320, *wide]
        found = _detour(a, b, (dx, dy), (nx, ny), spread, bridge, lifts, others)
        if found is None and crossing:                                      # no way round a frame: keep to the devices, a line grazing a frame is better than one through its middle
            plain = [rect for rect in others if rect not in crossing]
            if not spread and not _hits(a, b, plain):
                continue
            found = _detour(a, b, (dx, dy), (nx, ny), spread, bridge, [0.0, 70, -70, 140, -140, 220, -220, 320, -320], plain)
        if found is None:
            if bridge:
                t = BRIDGE_END / length
                found = [(a[0] + dx * t + nx * 70, a[1] + dy * t + ny * 70), (b[0] - dx * t + nx * 70, b[1] - dy * t + ny * 70)]
            else:
                found = [(mid[0] + nx * (spread + 70), mid[1] + ny * (spread + 70))]
        page.routes[index] = found
    _untangle_approaches(page, centres)
    _separate_lanes(page, centres)
    if page.curved:
        curve_routes(page)


LANE_NUDGE = 6.0         # px a comb lane moves up when it would lie on the lane of another switch


def _separate_lanes(page: Page, centres: dict[str, tuple[float, float]]) -> None:
    """The lanes of one switch's comb are set per switch, so a lane that runs beyond its own frame (a switch that stands far from its frame, a far strip) can lie on
    the lane of the next switch at the same height.  The later line moves its lane up by ``LANE_NUDGE`` steps until no other switch's run lies on it."""
    runs: list[tuple[int, str, int, float, float, float]] = []                 # (line, source, index of the run's first point, y, x from, x to)
    for index, route in sorted(page.routes.items()):
        source = page.comb_source.get(index)
        if source is None or len(route) < 4:
            continue
        for k in range(len(route) - 1):
            (x0, y0), (x1, y1) = route[k], route[k + 1]
            if abs(y0 - y1) < 0.5 and abs(x0 - x1) > 6 and y0 > centres[source][1] + NODE_H / 2 + 30:          # a run below the text under the switch: a lane, not the leave
                runs.append((index, source, k, y0, min(x0, x1), max(x0, x1)))
    def clash(run: tuple[int, str, int, float, float, float], y: float) -> bool:
        return any(o[0] != run[0] and o[1] != run[1] and abs(o[3] - y) < 2.0 and min(o[5], run[5]) - max(o[4], run[4]) > 6 for o in runs)
    for n, run in enumerate(runs):
        if not clash(run, run[3]):
            continue
        index, source, k, y, x0, x1 = run
        floor = centres[source][1] + NODE_H / 2 + 54                         # below the text under the switch
        for step in range(1, 9):
            lane = y - LANE_NUDGE * step
            if lane < floor:
                break
            if not clash(run, lane):
                route = list(page.routes[index])
                route[k], route[k + 1] = (route[k][0], lane), (route[k + 1][0], lane)
                page.routes[index] = route
                runs[n] = (index, source, k, lane, x0, x1)
                break


APPROACH_STEP = 14.0      # px sideways between two lines that would arrive at one device along the same straight run


def _untangle_approaches(page: Page, centres: dict[str, tuple[float, float]]) -> None:
    """Two lines of different switches that both end in one device (an access point heard by two switches, a host on two uplinks) may arrive along the same
    vertical or horizontal run.  The comb line of the device's own frame keeps the run; every other one moves its last corner sideways by ``APPROACH_STEP``
    (alternately left and right), so the final stretch is a slight slant instead of a second line on top of the first."""
    arrivals: dict[tuple[str, str, int], list[tuple[int, int]]] = defaultdict(list)       # (device, axis, rounded position) -> [(line, end 0/1)]
    for index, route in page.routes.items():
        if len(route) < 2 or index >= len(page.connections):
            continue
        conn = page.connections[index]
        for end, (device, corner, before) in enumerate(((conn.a, route[0], route[1]), (conn.b, route[-1], route[-2]))):
            centre = centres.get(device)
            if centre is None:
                continue
            if abs(corner[0] - centre[0]) < 0.5 and abs(corner[1] - centre[1]) > 6 and abs(before[1] - corner[1]) < 0.5:         # vertical arrival after a horizontal run
                arrivals[(device, "x", round(centre[0]))].append((index, end))
            elif abs(corner[1] - centre[1]) < 0.5 and abs(corner[0] - centre[0]) > 6 and abs(before[0] - corner[0]) < 0.5:       # horizontal arrival after a vertical run
                arrivals[(device, "y", round(centre[1]))].append((index, end))
    for (device, axis, _), lines in sorted(arrivals.items()):
        lines.sort(key=lambda le: (le[0] not in page.comb_source, le[0]))          # the frame's own comb line first: it keeps the run
        if len(lines) < 2:
            continue
        for rank, (index, end) in enumerate(lines[1:], start=1):
            shift = APPROACH_STEP * ((rank + 1) // 2) * (1 if rank % 2 else -1)
            route = list(page.routes[index])
            at = 0 if end == 0 else len(route) - 1
            x, y = route[at]
            route[at] = (x + shift, y) if axis == "x" else (x, y + shift)
            page.routes[index] = route


BRIDGE_END = 60.0     # px along the line from a device to the first corner of a bridge over the devices between two others


CURVE_POINTS = 16      # points sampled along a curve (the SVG preview and the label placement follow them; draw.io gets every 4th and smooths them)


def _curve(a: tuple[float, float], via: tuple[float, float], b: tuple[float, float]) -> list[tuple[float, float]]:
    """Points of the quadratic Bezier from a to b that passes through ``via`` in its middle (control point 2*via - (a+b)/2)."""
    cx, cy = 2 * via[0] - (a[0] + b[0]) / 2, 2 * via[1] - (a[1] + b[1]) / 2
    out = []
    for i in range(1, CURVE_POINTS + 1):
        t = i / (CURVE_POINTS + 1)
        out.append(((1 - t) ** 2 * a[0] + 2 * (1 - t) * t * cx + t * t * b[0], (1 - t) ** 2 * a[1] + 2 * (1 - t) * t * cy + t * t * b[1]))
    return out


def curve_routes(page: Page) -> None:
    """Round the single bend of every routed line into a smooth curve; a line that was straight stays straight."""
    centres = {k: _centre(p) for k, p in page.nodes.items()}
    centres.update({k: box.centre for k, box in page.pair_boxes.items()})
    for index, points in list(page.routes.items()):
        conn = page.connections[index]
        if len(points) == 1 and conn.a in centres and conn.b in centres:
            page.routes[index] = _curve(centres[conn.a], points[0], centres[conn.b])
