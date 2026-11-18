"""Line shape "Orthogonal": every cable leaves its device straight up or down, runs sideways in the free strip between two rows of devices, and arrives straight (right angles only,
the way a drawing by hand or a wiring diagram is made).

A line between two devices that stand in different rows takes the free strip (the gap between two rows) that costs least: fewest devices crossed, then the shortest way.  Lines that
want the same strip are spread over lanes (``LANE`` px apart), so that two cables never lie on one track and a reader can follow each one.  Two devices in one row, with
others between them, are joined over the row.  Lines that the layout already routed as a comb or a fan (the uplinks of one switch) keep their shape: they have right angles already.
"""

from __future__ import annotations

from collections import defaultdict

from .layout import NODE_H, NODE_W
from .scene import Page, _centre, _hits

LANE = 10.0                     # px between two lines that run in the same strip
OVER_ROW = 34.0                 # a line over a row of devices runs this far above their icons
BAND = NODE_H + 52              # an icon with its name, model and address under it


def _strips(page: Page) -> list[float]:
    """The y of the free strips: the middle of the space between two rows of devices (rows found from the y of the icons, a row ends where the next starts)."""
    tops = sorted({round(p.y) for p in page.nodes.values()})
    out: list[float] = []
    rows: list[list[int]] = []
    for y in tops:
        if rows and y - rows[-1][-1] < NODE_H // 2:
            rows[-1].append(y)
        else:
            rows.append([y])
    for upper, lower in zip(rows, rows[1:]):
        bottom, top = upper[-1] + BAND, lower[0]
        if top - bottom >= 30:
            out.append((bottom + top) / 2)
        else:
            out.append((upper[-1] + NODE_H + lower[0]) / 2)
    return out


PORT_SPAN = 56.0                # the lines that leave one side of an icon share this width (they stay under the icon's body)
PORT_STEP = 16.0                # ... at most this far apart
STUB = 30.0                     # a line starts under the icon: it reaches this far from the icon's centre before it turns, so the sideways step is hidden by the icon


def _slots(count: int) -> list[float]:
    if count <= 1:
        return [0.0] * count
    step = min(PORT_STEP, PORT_SPAN / (count - 1))
    return [(i - (count - 1) / 2) * step for i in range(count)]


def orthogonalize(page: Page) -> None:
    """Replace the route of every line of the page by one with right angles (``page.routes``); the lines of a comb stay as they are."""
    if not page.nodes or not page.connections:
        return
    strips = _strips(page)
    boxes = {k: (p.x - 4, p.y - 4, p.x + NODE_W + 4, p.y + NODE_H + 4) for k, p in page.nodes.items()}
    centres = {k: _centre(p) for k, p in page.nodes.items()}
    plans: dict[int, tuple[str, str, int, int, float]] = {}                   # line -> (kind, ..., side at a, side at b, strip)
    ports: dict[tuple[str, int], list[tuple[float, int, bool]]] = defaultdict(list)       # (device, side: -1 up, +1 down) -> [(x of the other end, line, is a)]
    siblings: dict[frozenset, list[int]] = defaultdict(list)
    for index, conn in enumerate(page.connections):
        siblings[frozenset((conn.a, conn.b))].append(index)
    for index, conn in enumerate(page.connections):
        if index in page.comb_source or conn.a == conn.b or conn.a not in centres or conn.b not in centres:
            continue
        a, b = centres[conn.a], centres[conn.b]
        others = [rect for key, rect in boxes.items() if key not in (conn.a, conn.b)]
        if abs(a[1] - b[1]) < NODE_H / 2:                                  # one row: straight sideways when nothing stands between, else over the row
            if abs(a[1] - b[1]) < 2 and not _hits(a, b, others):
                plans[index] = ("row", "", 0, 0, 0.0)
                continue
            plans[index] = ("over", "", -1, -1, round(min(a[1], b[1]) - NODE_H / 2))
        else:
            top, bottom = (conn.a, conn.b) if a[1] < b[1] else (conn.b, conn.a)
            ct, cb = centres[top], centres[bottom]
            candidates = [s for s in strips if ct[1] + NODE_H / 2 <= s <= cb[1] - NODE_H / 2 + 1] or [(ct[1] + cb[1]) / 2]
            best = min(candidates, key=lambda strip: (sum(1 for p, q in ((ct, (ct[0], strip)), ((ct[0], strip), (cb[0], strip)), ((cb[0], strip), cb)) if _hits(p, q, others)) * 1000
                                                      + abs(strip - ct[1]) + abs(strip - cb[1])))
            down_a = a[1] < b[1]
            plans[index] = ("elbow", "", 1 if down_a else -1, -1 if down_a else 1, best)
        _, _, side_a, side_b, _ = plans[index]
        ports[(conn.a, side_a)].append((b[0], index, True))
        ports[(conn.b, side_b)].append((a[0], index, False))
    offset: dict[tuple[int, bool], float] = {}
    for (_, _), entries in ports.items():
        entries.sort(key=lambda e: (e[0], e[1]))
        for (_, index, is_a), x in zip(entries, _slots(len(entries))):
            offset[(index, is_a)] = x
    used: list[tuple[float, float, float]] = []                                  # (y, from x, to x) of the runs placed so far, whatever strip they belong to
    order = sorted(plans, key=lambda i: _length(page, centres, i), reverse=True)        # the long lines take their lanes first
    for index in order:
        conn = page.connections[index]
        kind, _, side_a, side_b, strip = plans[index]
        (ax, ay), (bx, by) = centres[conn.a], centres[conn.b]
        if kind == "row":
            group = siblings[frozenset((conn.a, conn.b))]
            spread = (group.index(index) - (len(group) - 1) / 2) * LANE if len(group) > 1 else 0.0
            page.routes[index] = [(ax + (STUB if bx > ax else -STUB), ay + spread), (bx - (STUB if bx > ax else -STUB), by + spread)] if spread else []
            continue
        xa, xb = ax + offset.get((index, True), 0.0), bx + offset.get((index, False), 0.0)
        base = strip - OVER_ROW if kind == "over" else strip
        y = _lane(used, base, xa, xb, -1 if kind == "over" else 0)
        page.routes[index] = [(xa, ay + side_a * STUB), (xa, y), (xb, y), (xb, by + side_b * STUB)]
        used.append((y, min(xa, xb), max(xa, xb)))


def _length(page: Page, centres: dict[str, tuple[float, float]], index: int) -> float:
    conn = page.connections[index]
    if conn.a not in centres or conn.b not in centres:
        return 0.0
    (x1, y1), (x2, y2) = centres[conn.a], centres[conn.b]
    return abs(x1 - x2) + abs(y1 - y2)


def _lane(used: list[tuple[float, float, float]], base: float, x0: float, x1: float, direction: int = 0) -> float:
    """The y of the run of a line from x0 to x1 that wants the track ``base``: the first track (the middle, then 1 above, 1 below, 2 above ...; only above when ``direction`` is -1) that no run
    over the same stretch of x lies on, whatever strip that run was planned for."""
    lo, hi = (x0, x1) if x0 <= x1 else (x1, x0)
    runs = [(y, a, b) for y, a, b in used if min(hi, b) - max(lo, a) > 4]
    lane = 0
    while True:
        step = ((lane + 1) // 2) * LANE
        y = base + (-step if direction < 0 else (step if lane % 2 else -step))
        if all(abs(y - ry) >= LANE - 1 for ry, _, _ in runs):
            return y
        lane += 1
