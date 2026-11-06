"""Where the name of an end-point frame is written, so that no line runs through the text.

The frame round the end points of one switch has its name in the top strip.  Lines that serve the end points inside enter the frame from above, and
lines of other links may cross the strip, so the name at the top-left corner is sometimes struck through by a line.  The strip is 46 px high above
the first icon: wide enough for the name to slide sideways until it sits in a gap between two lines.

The same spot is used by the SVG and by the draw.io file, so both pictures agree.
"""

from __future__ import annotations

from . import labels
from .layout import NODE_H, NODE_W

TITLE_LEFT = 10.0              # px from the left border of the frame to the first letter, when nothing is in the way
CHAR_W = 6.9                   # px per letter of a 12 px bold title (Helvetica/Arial)
TITLE_PAD = 4.0                # px of clear space asked for on both sides of the text
TITLE_TOP = 8.0                # the text occupies this band (px below the top border of the frame) ...
TITLE_BOTTOM = 26.0            # ... down to here
SLIDE = 8.0                    # px per step when the name slides along the strip


def title_width(title: str) -> float:
    return CHAR_W * len(title) + 2 * TITLE_PAD


def page_segments(page) -> list[tuple[float, float, float, float]]:
    """Every straight piece of every line on ``page``: from the centre of one end, along its route, to the centre of the other."""
    centre = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}
    centre.update({k: frame.centre for k, frame in page.pair_boxes.items()})
    out = []
    for index, conn in enumerate(page.connections):
        if conn.a not in centre or conn.b not in centre:
            continue
        points = [centre[conn.a], *(page.routes.get(index) or []), centre[conn.b]]
        out += [(a[0], a[1], b[0], b[1]) for a, b in zip(points, points[1:])]
    return out


LABEL_CHAR_W = 5.6             # px per letter of a 10 px port label
LABEL_ROW_H = 13.0


def page_label_rects(page, graph=None) -> list[tuple[float, float, float, float]]:
    """The boxes of the port labels of ``page`` (where ``labelplace`` put them): the name of a frame slides away from them as well as from the lines."""
    out = []
    for (index, slot), (x, y, _) in page.label_pos.items():
        if index >= len(page.connections):
            continue
        conn = page.connections[index]
        if slot == "mid":
            text = labels.center_text(conn, graph) if graph is not None else ""
            rows = labels.wrap_centre(text) if text else []
        else:
            a_text, b_text = labels.end_texts(conn)
            rows = [a_text if slot == "a" else b_text]
        rows = [row for row in rows if row]
        if not rows:
            continue
        w = max(len(row) for row in rows) * LABEL_CHAR_W + 4
        h = LABEL_ROW_H * len(rows)
        out.append((x - w / 2, y + 3.5 - h / 2 - 2, x + w / 2, y + 3.5 + h / 2 + 2))
    return out


def _hits(segment: tuple[float, float, float, float], left: float, top: float, right: float, bottom: float) -> bool:
    """True when the segment passes through the rectangle (Liang-Barsky clipping)."""
    x1, y1, x2, y2 = segment
    t0, t1 = 0.0, 1.0
    dx, dy = x2 - x1, y2 - y1
    for p, q in ((-dx, x1 - left), (dx, right - x1), (-dy, y1 - top), (dy, bottom - y1)):
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
    return t0 <= t1


def end_title_spot(page, box: tuple[str, float, float, float, float], segments: list[tuple[float, float, float, float]] | None = None,
                   rects: list[tuple[float, float, float, float]] | None = None) -> float:
    """Distance from the left border of the frame to the first letter of its name: the left-most spot (sliding right in small steps) where no
    line crosses the text and no port label (``rects``) stands on it; when every spot is blocked, the one with the fewest lines and labels on it."""
    title, x, y, w, h = box
    segments = page_segments(page) if segments is None else segments
    width = title_width(title)
    last = w - width - TITLE_LEFT + TITLE_PAD
    best, best_hits = TITLE_LEFT, None
    dx = TITLE_LEFT
    while True:
        left, right = x + dx - TITLE_PAD, x + dx - TITLE_PAD + width
        hits = sum(1 for s in segments if _hits(s, left, y + TITLE_TOP, right, y + TITLE_BOTTOM))
        hits += sum(1 for a, b, c, d in rects or () if a < right and c > left and b < y + TITLE_BOTTOM and d > y + TITLE_TOP)
        if best_hits is None or hits < best_hits:
            best, best_hits = dx, hits
        if hits == 0 or dx >= last:
            break
        dx = min(dx + SLIDE, last)
    return best
