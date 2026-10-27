"""Place the nodes that belong to no cable (provider clouds, shared subnets, gateways nobody captured, remote SD-WAN sites) around the devices they join.

The L3 over L2 page keeps the physical positions.  An extra node goes as near as possible to the centre of the devices it is linked to, on a free spot:
a provider or Internet cloud above them, anything else beside them.  A spot is free when the icon, its label and a margin overlap no other node.
Nodes are placed one after the other, the best connected first, so a hub's satellites gather round it like the points of a star.
"""

from __future__ import annotations

from dataclasses import dataclass

from .layout import NODE_H, NODE_W
from .scene import _clips

CELL_W = 250.0            # room one node takes: label width included
CELL_H = 175.0            # icon, up to three label lines, and a margin
STEP_X = 125.0            # the spots tried lie on this grid round the wanted point
STEP_Y = 88.0
REACH = 14                # spots tried on each side of the wanted point
ABOVE = 250.0             # a cloud sits this far above the highest device it serves
SWAP_MAX = 36              # up to this many extras are improved by exchanging spots (more would take too long)
SWAP_PASSES = 4
HIT_COST = 400.0           # one line through another node costs as much as this many pixels of line
SIDE = 300.0              # a satellite sits this far to the side of the device it serves


@dataclass
class Extra:
    key: str
    ends: list[str]            # keys of the placed devices it is linked to (repeated for several links)
    above: bool = False        # provider / Internet cloud: above its devices


def _rect(x: float, y: float) -> tuple[float, float, float, float]:
    """Top-left corner of an icon -> the space it needs."""
    return x - (CELL_W - NODE_W) / 2, y - 12, x + NODE_W + (CELL_W - NODE_W) / 2, y + CELL_H - 12


def _free(rect: tuple[float, float, float, float], taken: list[tuple[float, float, float, float]]) -> bool:
    return not any(rect[0] < t[2] and t[0] < rect[2] and rect[1] < t[3] and t[1] < rect[3] for t in taken)


def place(fixed: dict[str, tuple[float, float]], extras: list[Extra]) -> dict[str, tuple[float, float]]:
    """{extra key: (x, y)} (top-left of the icon) for every extra; ``fixed`` holds the top-left of the devices already on the page."""
    taken = [_rect(x, y) for x, y in fixed.values()]
    centre_x = (min(x for x, _ in fixed.values()) + max(x for x, _ in fixed.values())) / 2 if fixed else 0.0
    out: dict[str, tuple[float, float]] = {}
    order = sorted(extras, key=lambda e: (not e.above, -len(set(e.ends)), -len(e.ends), e.key))
    for extra in order:
        ends = [fixed[k] for k in extra.ends if k in fixed] + [out[k] for k in extra.ends if k in out]
        if not ends:
            ends = [(centre_x, 0.0)]
        mx = sum(x for x, _ in ends) / len(ends)
        my = sum(y for _, y in ends) / len(ends)
        single = len(set(extra.ends)) <= 1
        if extra.above:
            want = (mx, min(y for _, y in ends) - ABOVE)
        elif single:
            want = (mx + (SIDE if mx >= centre_x else -SIDE), my)          # the satellite of one device goes to the side that faces away from the middle of the page
        else:
            want = (mx, my)                                                # a subnet shared by several devices sits in the middle of them
        best: tuple[float, tuple[float, float]] | None = None
        for i in range(-REACH, REACH + 1):
            for j in range(-REACH, REACH + 1):
                x, y = want[0] + i * STEP_X, want[1] + j * STEP_Y
                cost = abs(x - want[0]) + 1.6 * abs(y - want[1])
                if extra.above and y > min(p[1] for p in ends) - CELL_H * 0.8:
                    cost += 4000.0                                        # a provider goes over the devices it serves, not beside them
                if best is not None and cost >= best[0]:
                    continue
                if _free(_rect(x, y), taken):
                    best = (cost, (x, y))
        if best is None:                                                  # no free spot in reach (a very crowded page): the column above everything
            best = (0.0, (want[0], min(min(y for _, y in fixed.values()), min((y for _, y in out.values()), default=0.0)) - CELL_H * (len(out) % 5 + 1)))
        out[extra.key] = best[1]
        taken.append(_rect(*best[1]))
    if 2 <= len(extras) <= SWAP_MAX:
        _swap(fixed, extras, out)
    return out


def _centre(point: tuple[float, float]) -> tuple[float, float]:
    return point[0] + NODE_W / 2, point[1] + NODE_H / 2


def _plan_cost(fixed: dict[str, tuple[float, float]], extras: list[Extra], out: dict[str, tuple[float, float]]) -> float:
    """Total length of the lines from every extra to the devices it joins, plus a heavy charge for every line that runs through another node (icon and caption)."""
    where = {**fixed, **out}
    boxes = {k: (x - 6, y - 6, x + NODE_W + 6, y + NODE_H + 56) for k, (x, y) in where.items()}
    total = 0.0
    for extra in extras:
        a = _centre(out[extra.key])
        for end in set(extra.ends):
            if end not in where or end == extra.key:
                continue
            b = _centre(where[end])
            total += ((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2) ** 0.5
            for key, box in boxes.items():
                if key not in (extra.key, end) and _clips(box, a, b):
                    total += HIT_COST
    return total


def _swap(fixed: dict[str, tuple[float, float]], extras: list[Extra], out: dict[str, tuple[float, float]]) -> None:
    """Greedy first placement puts the best connected node nearest to its wished spot, which can leave a later node's line running through an earlier one.
    Two extras of the same kind exchange their spots (every spot has the same size) when that shortens the lines and frees them of nodes; repeated until nothing improves."""
    keys = sorted(out)
    kind = {e.key: e.above for e in extras}
    best = _plan_cost(fixed, extras, out)
    for _ in range(SWAP_PASSES):
        improved = False
        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                if kind.get(a) != kind.get(b):
                    continue
                out[a], out[b] = out[b], out[a]
                cost = _plan_cost(fixed, extras, out)
                if cost < best - 1.0:
                    best, improved = cost, True
                else:
                    out[a], out[b] = out[b], out[a]
        if not improved:
            break
