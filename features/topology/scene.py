"""Turn a Graph into drawable pages: node coordinates, group boxes, and routed lines for each page."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .graph import Connection, Graph
from .layout import MARGIN, NODE_H, NODE_W, X_STEP, Y_STEP, Placed, groups_of, layered

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
    graph: Any = None                                                # IP view: the small graph that holds this page's own nodes and lines


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
            nodes[key] = Placed(p.x + bx + BOX_PAD, p.y + by + BOX_PAD + TITLE_H, p.tier)
        boxes.append((name, bx, by, box_w, box_h))
    return nodes, boxes, max(x - BOX_PAD, 0.0), max(y - BOX_PAD, 0.0) + BOX_PAD


def build_pages(graph: Graph, group_mode: str = "none", layout: Layout | None = None) -> list[Page]:
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


def _route(page: Page) -> None:
    """Straight lines unless they would cross a device or lie on top of a sibling line; then bend them once."""
    centres = {k: _centre(p) for k, p in page.nodes.items()}
    centres.update({k: box.centre for k, box in page.pair_boxes.items()})
    boxes = {k: (p.x - 8, p.y - 8, p.x + NODE_W + 8, p.y + NODE_H + 52) for k, p in page.nodes.items()}
    inside = {member: key for key, box in page.pair_boxes.items() for member in box.members}
    siblings: dict[frozenset, list[int]] = {}
    for index, conn in enumerate(page.connections):
        siblings.setdefault(frozenset((conn.a, conn.b)), []).append(index)
    for index, conn in enumerate(page.connections):
        if conn.a not in centres or conn.b not in centres:
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
        group = siblings[frozenset((conn.a, conn.b))]
        spread = (group.index(index) - (len(group) - 1) / 2) * 34 if len(group) > 1 else 0.0
        dx, dy = b[0] - a[0], b[1] - a[1]
        length = (dx * dx + dy * dy) ** 0.5 or 1.0
        nx, ny = -dy / length, dx / length                      # unit normal
        mid = ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2)
        if not spread and not _hits(a, b, others):
            continue
        for lift in ([0.0] if spread and not _hits(a, b, others) else [0.0, 70, -70, 140, -140, 220, -220, 320, -320]):
            point = (mid[0] + nx * (spread + lift), mid[1] + ny * (spread + lift))
            if not _hits(a, point, others) and not _hits(point, b, others):
                page.routes[index] = [point]
                break
        else:
            page.routes[index] = [(mid[0] + nx * (spread + 70), mid[1] + ny * (spread + 70))]
