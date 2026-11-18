"""Where the name of an end-point frame is written, so that no line runs through the text.

The frame round the end points of one switch has its name in the top strip.  Lines that serve the end points inside enter the frame from above, and
lines of other links may cross the strip, so the name at the top-left corner is sometimes struck through by a line.  The strip is 46 px high above
the first icon: wide enough for the name to slide sideways until it sits in a gap between two lines.

The same spot is used by the SVG and by the draw.io file, so both pictures agree.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import labels
from .textwidth import text_width
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


def _width(text: str, char_w: float, size: float | None, spacing: float) -> float:
    """Width of a title: measured letter by letter at the type size when ``size`` is given, else ``char_w`` px a letter."""
    return (text_width(text, size) + spacing * len(text) if size else char_w * len(text)) + 2 * TITLE_PAD


def _search(page, box, segments, rects, text: str, char_w: float, left_edge: float, top: float, bottom: float, size: float | None = None, spacing: float = 0.0) -> tuple[float, int]:
    """(distance from the left border to the first letter, lines and labels still on the text): the left-most spot, sliding right in small steps, where nothing is on the text;
    when every spot is blocked, the one with the fewest."""
    _title, x, y, w, h = box
    width = _width(text, char_w, size, spacing)
    last = max(w - width - left_edge + TITLE_PAD, left_edge)
    best, best_hits = left_edge, None
    dx = left_edge
    while True:
        left, right = x + dx - TITLE_PAD, x + dx - TITLE_PAD + width
        hits = sum(1 for s in segments if _hits(s, left, y + top, right, y + bottom))
        hits += sum(1 for a, b, c, d in rects or () if a < right and c > left and b < y + bottom and d > y + top)
        if best_hits is None or hits < best_hits:
            best, best_hits = dx, hits
        if hits == 0 or dx >= last:
            break
        dx = min(dx + SLIDE, last)
    return best, best_hits or 0


def end_title_spot(page, box: tuple[str, float, float, float, float], segments: list[tuple[float, float, float, float]] | None = None,
                   rects: list[tuple[float, float, float, float]] | None = None, char_w: float = CHAR_W, left_edge: float = TITLE_LEFT,
                   top: float = TITLE_TOP, bottom: float = TITLE_BOTTOM) -> float:
    """Distance from the left border of the frame to the first letter of its name: the left-most spot (sliding right in small steps) where no
    line crosses the text and no port label (``rects``) stands on it; when every spot is blocked, the one with the fewest lines and labels on it.
    The other arguments say how big the name is (``char_w`` px per letter), where it starts and which band below the top border it occupies: the zone boxes and the frame round the
    centre use the same search with their own type size."""
    segments = page_segments(page) if segments is None else segments
    return _search(page, box, segments, rects, box[0], char_w, left_edge, top, bottom)[0]


@dataclass(frozen=True)
class Fitted:
    """What a frame title came to: the text to write, where it starts, and how many lines or labels still stand on it (0 = clean)."""
    text: str
    spot: float
    hits: int


def short_variants(title: str) -> list[str]:
    """The title and its shorter forms, longest first: 'CORE · 2 units · twin units' -> 'CORE · 2 units' -> 'CORE'.  A title without the dot separator has no shorter form."""
    parts = [p for p in title.split(" \u00b7 ") if p]
    return [" \u00b7 ".join(parts[:n]) for n in range(len(parts), 0, -1)] or [title]


def fit_title(page, box: tuple, segments: list, rects: list, char_w: float, left_edge: float, top: float, bottom: float, shorten: bool = False, size: float | None = None, spacing: float = 0.0) -> Fitted:
    """The best way to write a frame title: slide it along the strip to a clean gap; when no gap is wide enough and ``shorten`` is set, try its shorter forms (the full name stays
    in the tooltip); when nothing is clean, the full title at the spot with the fewest hits (the caller then draws it on top of the lines with a white halo, ``Fitted.hits`` > 0)."""
    title = box[0]
    first = _search(page, box, segments, rects, title, char_w, left_edge, top, bottom, size, spacing)
    if first[1] == 0 or not shorten:
        return Fitted(title, first[0], first[1])
    for text in short_variants(title)[1:]:
        spot, hits = _search(page, box, segments, rects, text, char_w, left_edge, top, bottom, size, spacing)
        if hits == 0:
            return Fitted(text, spot, 0)
    return Fitted(title, first[0], first[1])


ZONE_CHAR_W = 9.6              # a 15 px bold title with letter spacing
ZONE_LEFT = 16.0
CENTRE_CHAR_W = 6.6            # an 11 px bold title
CENTRE_LEFT = 10.0


def zone_title(page, zone: tuple, segments: list, rects: list) -> Fitted:
    """The zone name, fitted (see ``fit_title``)."""
    title, _kind, x, y, w, h = zone
    return fit_title(page, (title, x, y, w, h), segments, rects, ZONE_CHAR_W, ZONE_LEFT, 8.0, 34.0, size=15.0, spacing=0.5)


def centre_title(page, frame: tuple, segments: list, rects: list) -> Fitted:
    """The name of the frame round the centre of the network, fitted: its shorter forms are tried when the long one finds no clean gap between the lines."""
    return fit_title(page, frame, segments, rects, CENTRE_CHAR_W, CENTRE_LEFT, 4.0, 24.0, shorten=True, size=11.0)


def end_title(page, box: tuple, segments: list, rects: list) -> Fitted:
    """The name of an end-point frame, fitted."""
    return fit_title(page, box, segments, rects, CHAR_W, TITLE_LEFT, TITLE_TOP, TITLE_BOTTOM, size=12.0)


def zone_title_spot(page, zone: tuple, segments: list, rects: list) -> float:
    """Where the name of a zone box starts (px from its left border): it slides along the top strip to a gap between the lines that enter the box there."""
    title, _kind, x, y, w, h = zone
    return end_title_spot(page, (title, x, y, w, h), segments, rects, ZONE_CHAR_W, ZONE_LEFT, 8.0, 34.0)


def centre_title_spot(page, frame: tuple, segments: list, rects: list) -> float:
    """The same for the frame round the centre of the network (the core pair)."""
    return end_title_spot(page, frame, segments, rects, CENTRE_CHAR_W, CENTRE_LEFT, 4.0, 24.0)
