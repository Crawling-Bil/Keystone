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

CHAR_W = 5.7          # width of one character at font-size 10
LABEL_H = 13
END_DISTANCES = (62, 82, 102, 124, 148, 174, 202, 232, 264)
MID_FRACTIONS = (0.5, 0.42, 0.58, 0.35, 0.65)

Rect = tuple[float, float, float, float]


def _size(text: str) -> tuple[float, float]:
    return len(text) * CHAR_W + 8, LABEL_H


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


def place_labels(page: Page, graph: Graph, show_ports: bool = True) -> None:
    page.label_pos = {}
    obstacles = _node_boxes(page, graph)
    taken: list[Rect] = []
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
            if not text:
                continue
            w, h = _size(text)
            if slot == "mid":
                distances = [total * f for f in MID_FRACTIONS]
            else:
                distances = [d for d in END_DISTANCES if d <= total * 0.62] or [total * 0.3]
            best: tuple[int, float, float, float] | None = None
            for distance in distances:
                along = distance if slot in ("a", "mid") else total - distance
                x, y, nx, ny = _at(points, along)
                for shift in (0, 13, -13):
                    cx, cy = x + nx * shift, y + ny * shift
                    rect = (cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2)
                    score = _hit(rect, obstacles) * 3 + _hit(rect, taken) * 2 + (1 if shift else 0)
                    if best is None or score < best[0]:
                        best = (score, cx, cy, along / total)
                    if score == 0:
                        break
                if best and best[0] == 0:
                    break
            if best is None:
                continue
            _, cx, cy, t = best
            page.label_pos[(index, slot)] = (cx, cy, t)
            taken.append((cx - w / 2 - 1, cy - h / 2 - 1, cx + w / 2 + 1, cy + h / 2 + 1))
