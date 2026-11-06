"""How good is a page's layout?  Three numbers per page, computed from where the icons stand and which cables join them (every line taken the way it is drawn: the straight segment between the two icon
centres, or, for a line that the layout routed around a group box or into a comb, the bent path over its waypoints):

* ``crossings``: places where two lines cross (lines that meet at a device do not count);
* ``through``: line-and-icon pairs where a line runs across the icon of a device it does not belong to;
* ``length``: total length of the lines, in pixels.

``cost`` joins them so that two layouts of the same page can be compared (a crossing costs 1, a line through an icon 5, every 1,000 px of line 1).  The numbers are written to
run-settings.txt, and the tests use them as a guard: a layout rule must not make a page worse on the same cables.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

NODE_W, NODE_H = 76, 76
CELL = 400                     # px of the grid that limits the pairs of lines that are compared
THROUGH_WEIGHT = 5
LENGTH_UNIT = 1000.0
MAX_LINES = 6000              # a page with more lines than this is scored on its first MAX_LINES lines (the Overview of a very large estate)

Segment = tuple[float, float, float, float]


def _ccw(ax: float, ay: float, bx: float, by: float, cx: float, cy: float) -> float:
    return (bx - ax) * (cy - ay) - (by - ay) * (cx - ax)


def crosses(p: Segment, q: Segment) -> bool:
    """Proper crossing of two segments (touching ends and collinear overlaps do not count)."""
    d1, d2 = _ccw(*p, q[0], q[1]), _ccw(*p, q[2], q[3])
    d3, d4 = _ccw(*q, p[0], p[1]), _ccw(*q, p[2], p[3])
    return ((d1 > 0) != (d2 > 0)) and ((d3 > 0) != (d4 > 0)) and 0 not in (d1, d2, d3, d4)


def runs_through(segment: Segment, rect: tuple[float, float, float, float]) -> bool:
    """Does the segment cross the inside of the rectangle (x0, y0, x1, y1)?  Liang-Barsky clipping."""
    x0, y0, x1, y1 = segment
    left, top, right, bottom = rect
    dx, dy = x1 - x0, y1 - y0
    t0, t1 = 0.0, 1.0
    for p, q in ((-dx, x0 - left), (dx, right - x0), (-dy, y0 - top), (dy, bottom - y0)):
        if p == 0:
            if q < 0:
                return False
            continue
        t = q / p
        if p < 0:
            if t > t1:
                return False
            t0 = max(t0, t)
        else:
            if t < t0:
                return False
            t1 = min(t1, t)
    return t1 - t0 > 1e-9


def _polyline(page: Any, conn: Any, index: int, centre: dict[str, tuple[float, float]]) -> list[tuple[float, float]]:
    """The points of one line as it is drawn: from the centre of one icon over the waypoints that ``scene`` routed (a line that goes around a group box, a comb line)
    to the centre of the other.  A line without waypoints is the straight segment."""
    middle = (getattr(page, "routes", None) or {}).get(index) or ()
    return [centre[conn.a], *[(float(x), float(y)) for x, y in middle], centre[conn.b]]


def score_page(page: Any) -> dict[str, float]:
    """``crossings``, ``through``, ``length`` and ``cost`` of one page (a scene.Page).  A line that the layout routed around boxes is scored on its bent path."""
    centre = {key: (p.x + NODE_W / 2, p.y + NODE_H / 2) for key, p in page.nodes.items()}
    lines: list[tuple[str, str, list[Segment]]] = []
    for index, conn in enumerate(page.connections):
        if conn.a in centre and conn.b in centre and conn.a != conn.b:
            points = _polyline(page, conn, index, centre)
            lines.append((conn.a, conn.b, [(x0, y0, x1, y1) for (x0, y0), (x1, y1) in zip(points, points[1:])]))
    lines = lines[:MAX_LINES]
    length = sum(((s[2] - s[0]) ** 2 + (s[3] - s[1]) ** 2) ** 0.5 for _, _, segments in lines for s in segments)
    cells: dict[tuple[int, int], list[tuple[int, int]]] = defaultdict(list)
    for index, (_, _, segments) in enumerate(lines):
        for n, s in enumerate(segments):
            for cx in range(int(min(s[0], s[2]) // CELL), int(max(s[0], s[2]) // CELL) + 1):
                for cy in range(int(min(s[1], s[3]) // CELL), int(max(s[1], s[3]) // CELL) + 1):
                    cells[(cx, cy)].append((index, n))
    seen: set[tuple[tuple[int, int], tuple[int, int]]] = set()
    crossings = 0
    for members in cells.values():
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                if a[0] == b[0] or (a, b) in seen:
                    continue
                seen.add((a, b))
                ends = {lines[a[0]][0], lines[a[0]][1]}
                if lines[b[0]][0] in ends or lines[b[0]][1] in ends:
                    continue
                if crosses(lines[a[0]][2][a[1]], lines[b[0]][2][b[1]]):
                    crossings += 1
    where: dict[tuple[int, int], list[str]] = defaultdict(list)
    for key, (x, y) in centre.items():
        where[(int(x // CELL), int(y // CELL))].append(key)
    through = 0
    for a, b, segments in lines:                                 # only the icons in the cells that the bounding box of the line touches are tested
        hit: set[str] = set()
        for s in segments:
            for cx in range(int((min(s[0], s[2]) - NODE_W) // CELL), int((max(s[0], s[2]) + NODE_W) // CELL) + 1):
                for cy in range(int((min(s[1], s[3]) - NODE_W) // CELL), int((max(s[1], s[3]) + NODE_W) // CELL) + 1):
                    for key in where.get((cx, cy), ()):
                        if key in hit or key in (a, b):
                            continue
                        x, y = centre[key]
                        if runs_through(s, (x - NODE_W / 2 + 4, y - NODE_H / 2 + 4, x + NODE_W / 2 - 4, y + NODE_H / 2 - 4)):
                            hit.add(key)
        through += len(hit)
    return {"crossings": crossings, "through": through, "length": round(length), "cost": round(crossings + THROUGH_WEIGHT * through + length / LENGTH_UNIT, 1)}


def score_pages(pages: list[Any]) -> list[dict[str, Any]]:
    """One row per page: its name, the number of devices and the score."""
    return [{"page": page.name, "devices": len(page.nodes), **score_page(page)} for page in pages]
