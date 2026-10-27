"""Place the port and bundle labels of a page so that they do not sit on a device, on a hostname or on each other.

The first drawings put every port label at 22 % of its line.  With ten lines leaving one switch the labels landed on top of each
other and on the three text lines under the icon.  Here each label tries a list of distances along its own line and takes the first
spot that is free; the result is stored on the page (``page.label_pos``) and read by both the SVG preview and the draw.io writer,
so the two agree.
"""

from __future__ import annotations

from . import labels
from .graph import Graph
from .layout import NODE_H, NODE_W
from .scene import Page

CHAR_W = 5.4          # width of one character at font-size 10
LABEL_H = 13
END_DISTANCES = (62, 82, 102, 124, 148, 174, 202, 232, 264)
MID_FRACTIONS = (0.5, 0.42, 0.58, 0.35, 0.65, 0.28, 0.72, 0.2, 0.8, 0.14, 0.86)
SHIFTS = (0, 13, -13, 26, -26)
MID_SHIFTS = SHIFTS + (40, -40, 56, -56, 72)       # a centre label may stand further off its line (two devices side by side: the arc runs under their captions)
WIDE_FRACTIONS = tuple(f / 25 for f in range(2, 24))      # second search: every 4 % of the line
WIDE_SHIFTS = (0, 14, -14, 28, -28, 42, -42, 56, -56, 70, -70, 84, -84, 100, -100, 130, -130, 160, -160)
CELL = 120.0          # grid cell of the line index used to find the lines a label would sit on

Rect = tuple[float, float, float, float]


def _size(text: str, mid: bool = False) -> tuple[float, float]:
    lines = labels.wrap_centre(text) if mid else [text]
    return max(len(line) for line in lines) * CHAR_W + 8, LABEL_H * len(lines) - (len(lines) - 1) * 2


def _node_boxes(page: Page, graph: Graph) -> list[Rect]:
    boxes: list[Rect] = []
    for key, pos in page.nodes.items():
        boxes.append((pos.x - 2, pos.y - 2, pos.x + NODE_W + 2, pos.y + NODE_H + 2))
        node = graph.nodes[key]
        lines = [line for line in labels.node_lines(node) if line]
        if lines:
            half = max(len(line[:34]) for line in lines) * 6.6 / 2
            cx = pos.x + NODE_W / 2
            boxes.append((cx - half, pos.y + NODE_H + 3, cx + half, pos.y + NODE_H + 18 + 14 * len(lines)))
    for frame in page.pair_boxes.values():              # the frame title strip
        boxes.append((frame.x, frame.y, frame.x + frame.w, frame.y + 24))
    return boxes


def _hit(rect: Rect, others: list[Rect]) -> int:
    x0, y0, x1, y1 = rect
    return sum(1 for a, b, c, d in others if x0 < c and x1 > a and y0 < d and y1 > b)


def _clips(rect: Rect, a: tuple[float, float], b: tuple[float, float]) -> bool:
    """True when the segment a-b passes through the rectangle (Liang-Barsky clipping)."""
    x0, y0, x1, y1 = rect
    (ax, ay), (bx, by) = a, b
    dx, dy = bx - ax, by - ay
    t0, t1 = 0.0, 1.0
    for p, q in ((-dx, ax - x0), (dx, x1 - ax), (-dy, ay - y0), (dy, y1 - ay)):
        if p == 0:
            if q < 0:
                return False
            continue
        r = q / p
        if p < 0:
            if r > t1:
                return False
            t0 = max(t0, r)
        else:
            if r < t0:
                return False
            t1 = min(t1, r)
    return True


class _LineIndex:
    """The drawn lines in a coarse grid, so a label can count how many OTHER lines run under it."""

    def __init__(self) -> None:
        self.cells: dict[tuple[int, int], list[tuple[int, tuple[float, float], tuple[float, float]]]] = {}

    def add(self, owner: int, points: list[tuple[float, float]]) -> None:
        for a, b in zip(points, points[1:]):
            for cx in range(int(min(a[0], b[0]) // CELL), int(max(a[0], b[0]) // CELL) + 1):
                for cy in range(int(min(a[1], b[1]) // CELL), int(max(a[1], b[1]) // CELL) + 1):
                    self.cells.setdefault((cx, cy), []).append((owner, a, b))

    def crossed(self, rect: Rect, own: int) -> int:
        seen: set[int] = set()
        x0, y0, x1, y1 = rect
        for cx in range(int(x0 // CELL), int(x1 // CELL) + 1):
            for cy in range(int(y0 // CELL), int(y1 // CELL) + 1):
                for owner, a, b in self.cells.get((cx, cy), ()):
                    if owner != own and owner not in seen and _clips(rect, a, b):
                        seen.add(owner)
        return len(seen)


def _polyline(page: Page, index: int, conn) -> list[tuple[float, float]] | None:
    centres = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}
    centres.update({k: box.centre for k, box in page.pair_boxes.items()})
    if conn.a not in centres or conn.b not in centres:
        return None
    return [centres[conn.a], *page.routes.get(index, []), centres[conn.b]]


def _at(points: list[tuple[float, float]], distance: float) -> tuple[float, float, float, float]:
    """(x, y, normal_x, normal_y) at ``distance`` along the polyline."""
    left = distance
    for (x1, y1), (x2, y2) in zip(points, points[1:]):
        length = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
        if length and left <= length:
            f = left / length
            return x1 + (x2 - x1) * f, y1 + (y2 - y1) * f, -(y2 - y1) / length, (x2 - x1) / length
        left -= length
    (x1, y1), (x2, y2) = points[-2], points[-1]
    length = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5 or 1.0
    return x2, y2, -(y2 - y1) / length, (x2 - x1) / length


DROP_STEP = 5.0       # px between two tried heights on a drop


def _on_the_drop(page: Page, index: int, slot: str, points: list[tuple[float, float]], w: float, h: float, blocked: list[Rect]) -> tuple[float, float, float] | None:
    """The spot for the label of the switch end of a comb line: on the vertical run beside the switch (the drop), the first height that no other label or
    device covers.  The lines of a comb are a few px apart, so a label beside the line would belong to its neighbour; on its own drop it is clearly the line's."""
    conn = page.connections[index]
    source = page.comb_source.get(index)
    if source is None or (conn.a if slot == "a" else conn.b) != source:
        return None
    run = points if slot == "a" else points[::-1]                     # from the switch outwards: centre, icon edge, beside the icon, the drop ...
    if len(run) < 4 or abs(run[2][0] - run[3][0]) > 0.5:
        return None
    (x, y0), (_, y1) = run[2], run[3]
    top, bottom = min(y0, y1) + h / 2 + 4, max(y0, y1) - h / 2 - 3
    if bottom < top:
        return None
    walked = sum(((q[0] - p[0]) ** 2 + (q[1] - p[1]) ** 2) ** 0.5 for p, q in zip(run[:2], run[1:3]))
    y = top
    while y <= bottom:
        rect = (x - w / 2, y - h / 2, x + w / 2, y + h / 2)
        if not _hit(rect, blocked):
            along = walked + abs(y - y0)
            return x, y, along if slot == "a" else sum(((q[0] - p[0]) ** 2 + (q[1] - p[1]) ** 2) ** 0.5 for p, q in zip(points, points[1:])) - along
        y += DROP_STEP
    return None


def place_labels(page: Page, graph: Graph, show_ports: bool = True) -> None:
    page.label_pos = {}
    obstacles = _node_boxes(page, graph)
    taken: list[Rect] = []
    lines = _LineIndex()
    for index, conn in enumerate(page.connections):
        drawn = _polyline(page, index, conn)
        if drawn:
            lines.add(index, drawn)
    jobs: list[tuple[int, list[tuple[float, float]], float, str, str]] = []
    for index, conn in enumerate(page.connections):
        points = _polyline(page, index, conn)
        if not points:
            continue
        total = sum(((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5 for (x1, y1), (x2, y2) in zip(points, points[1:])) or 1.0
        items: list[tuple[str, str]] = []
        if show_ports and not (page.view == "logical" and conn.kind == "peer-link"):
            a_text, b_text = labels.end_texts(conn)
            items += [("a", a_text), ("b", b_text)]
        middle = labels.center_text(conn, graph)
        if middle:
            items.append(("mid", middle))
        for slot, text in items:
            if text:
                jobs.append((index, points, total, slot, text))
    for index, points, total, slot, text in jobs:
        w, h = _size(text, slot == "mid")
        spot = _on_the_drop(page, index, slot, points, w, h, obstacles + taken) if slot in ("a", "b") else None
        if spot is not None:                                  # a comb line: the port at the switch is written on the line's own drop, one band below the one before
            page.label_pos[(index, slot)] = (spot[0], spot[1], spot[2] / total)
            taken.append((spot[0] - w / 2 - 1, spot[1] - h / 2 - 1, spot[0] + w / 2 + 1, spot[1] + h / 2 + 1))
            continue
        if slot == "mid":
            distances = [total * f for f in MID_FRACTIONS]
        else:
            distances = [d for d in END_DISTANCES if d <= total * 0.62] or [total * 0.3]
        best: tuple[int, float, float, float] | None = None
        for distance in distances:
            along = distance if slot in ("a", "mid") else total - distance
            x, y, nx, ny = _at(points, along)
            for shift in (MID_SHIFTS if slot == "mid" else SHIFTS):
                cx, cy = x + nx * shift, y + ny * shift
                rect = (cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2)
                score = _hit(rect, obstacles) * 6 + _hit(rect, taken) * 4 + lines.crossed(rect, index) + (1 if shift else 0) + (1 if abs(shift) > 26 else 0)
                if best is None or score < best[0]:
                    best = (score, cx, cy, along / total)
                if score == 0:
                    break
            if best and best[0] == 0:
                break
        if best is not None and best[0] >= 4 and slot in ("a", "b", "mid"):          # still on a device, a text or another label: search the whole line with wider shifts
            for fraction in WIDE_FRACTIONS:
                along = total * fraction if slot != "b" else total * (1 - fraction)
                if slot != "mid" and fraction > 0.7:
                    continue
                x, y, nx, ny = _at(points, along)
                for shift in WIDE_SHIFTS:
                    cx, cy = x + nx * shift, y + ny * shift
                    rect = (cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2)
                    score = _hit(rect, obstacles) * 6 + _hit(rect, taken) * 4 + lines.crossed(rect, index) + abs(shift) // 28 + (1 if shift else 0)
                    if score < best[0]:
                        best = (score, cx, cy, (total * fraction if slot != "b" else total * (1 - fraction)) / total)
                if best[0] < 4:
                    break
        if best is None:
            continue
        _, cx, cy, t = best
        page.label_pos[(index, slot)] = (cx, cy, t)
        taken.append((cx - w / 2 - 1, cy - h / 2 - 1, cx + w / 2 + 1, cy + h / 2 + 1))
