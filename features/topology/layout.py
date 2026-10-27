"""Layered layout: one row per tier, nodes of a tier in natural name order (A-Z, 0-9) left to right, what hangs off one device grouped under it and uplink-only devices over what they serve, vPC / stack peers side by side."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .graph import Graph
from .roles import tier_of

NODE_W, NODE_H = 76, 76          # icon size (as in the sample diagrams)
X_STEP, Y_STEP = 230, 250        # label room between icons
X_MAX = 300                      # widest step a long hostname may ask for
SUB_STEP = 175                   # distance between the staggered lines of one long row of endpoints
WRAP_MIN = 12                    # a row of endpoints shorter than this is never cut
COMB_EXTRA_MAX = 420            # most extra height a row gap gets for the lanes of a comb to a frame of end points
Y_EXTRA_MAX = 260              # most extra height a row gap gets for its lines
MARGIN = 80
AUTO_MIN_DEVICES = 30            # grouping "auto": fewer devices than this stay on one diagram
AUTO_MAX_SITE = 40               # ... a site (group) should not hold more devices than one readable page
AUTO_MAX_SITES = 40              # ... and the overview should not hold more boxes than this
ENDPOINT_ROLES = ("ap", "phone", "host", "server")
BOX_MIN = 2                      # fewer end points under one switch than this are not framed (a frame round one icon says nothing)
BOX_COLS_MAX = 6                 # most icons in one line of a frame
BOX_HALF = 123                   # a frame reaches this far (label room + padding) beyond the centre of its outermost icon
BOX_GAP = 44                     # free space between two frames of one row
STAR_MIN_ROUTERS = 3             # a page holding at least this many routers / firewalls / load balancers is laid out as a star (see ``star_applicable``)
STAR_MAX_TIER = 2.0              # rows down to the aggregation switches are ordered by the star sweeps; access switches and end points follow their uplinks
STAR_SWEEPS = 10                 # up and down barycenter passes
STAR_SCORE_EDGES = 400            # more lines than this: the sweeps are scored once instead of after every pass
STAR_PERM_MAX = 6                 # the main row of a star (at most this many devices) is also tried in every order; the rows around it follow each order
STAR_PERM_EDGES = 160             # ... on pages with at most this many lines
STAR_DROP = 0.62                 # a device that a longer same-row link would run over is lowered by this share of SUB_STEP
DROP_CLEAR = 62.0                # the comb of a switch (scene._route_comb): first drop this far from the centre of the switch ...
DROP_STEP = 12.0                 # ... then this many px between two drops (at most) ...
DROP_STEP_MIN = 4.0              # ... at least this many ...
DROP_SPAN = 360.0                # ... and the drops of one side together take at most this much
DROP_ROOM = 48.0                 # half an icon plus air between the last drop and the icon of the next device
PREFIX_WORDS = {"prefix1": 1, "prefix2": 2, "prefix3": 3}     # grouping modes and how many leading hostname words name the group


@dataclass
class Placed:
    x: float
    y: float
    tier: int
    box: str = ""            # end points drawn under a switch with "group end points": the key of that switch (the page draws one labelled frame per switch)


def natural_key(name: str, tie: str = "") -> tuple:
    """Sort key for hostnames: case-insensitive, letters (A-Z) before numbers (0-9) at the same position, digit runs compare as numbers (SW-2 before SW-10)."""
    parts = re.findall(r"\d+|\D", name.upper())            # one character per non-digit, one number per digit run
    return tuple((1, int(p), "") if p.isdigit() else (0, 0, p) for p in parts), tie


def layered(graph: Graph, keys: list[str], x0: float = 0, y0: float = 0, tiers: dict[str, float] | None = None) -> tuple[dict[str, Placed], float, float]:
    """Place ``keys`` (a subset of graph nodes). Returns positions plus the width and height used.  ``tiers`` overrides the row of single nodes (the L3 pages lift provider clouds above the routers)."""
    members = set(keys)
    tier_value = _tier_values(graph, keys)
    tier_value.update({k: v for k, v in (tiers or {}).items() if k in tier_value})
    star = star_applicable(graph, keys)
    if star:                                                            # routers seen only by their neighbours sit in the outside row, with the providers
        for key in keys:
            node = graph.nodes[key]
            if node.role_hint == "router" and not node.captured and tier_value[key] == 0.0:
                tier_value[key] = -1.0
    else:
        tier_value.update(uplink_routers(graph, keys, tier_value))
    framed = box_groups(graph, keys, tier_value)
    tiers: dict[float, list[str]] = {}
    for key in keys:
        tiers.setdefault(tier_value[key], []).append(key)
    order = sorted(tiers)
    rows = {tier: sorted(tiers[tier], key=lambda k: _name_key(graph, k)) for tier in order}      # natural name order first
    neighbours: dict[str, set[str]] = {k: set() for k in keys}
    for conn in graph.connections:
        if conn.a in members and conn.b in members and conn.kind not in graph.hidden_kinds:
            neighbours[conn.a].add(conn.b)
            neighbours[conn.b].add(conn.a)
    pairs = {frozenset((a, b)) for a, b, _ in graph.vpc_pairs}
    core = max((len(rows[t]) for t in order if t < 4), default=0)
    parts = {tier: _parts(len(rows[tier]), tier, core) for tier in order}
    xstep = _x_step(graph, keys)
    framed_tiers = {tier_value[k] for kids in framed.values() for k in kids}
    for tier in framed_tiers:
        parts[tier] = 1                                                 # a row with frames is set out in a grid per frame, not dealt out over staggered lines
    slots: dict[str, int] = {}                                          # line inside its row of every end point of a frame
    pairs = pairs | (ha_pairs(graph, keys) if star else set())
    spot = _arrange(graph, rows, order, neighbours, pairs, parts, framed, xstep, slots, star)      # x of every node, in icon steps
    for tier in framed_tiers | {tier_value[k] for k in slots if k in tier_value and tier_value[k] <= STAR_MAX_TIER and star}:
        parts[tier] = max((slots.get(k, 0) for k in rows[tier]), default=0) + 1
    owner = {k: parent for parent, kids in framed.items() for k in kids}
    gaps = _gaps(graph, keys, order, rows)
    lo, hi = min(spot.values(), default=0), max(spot.values(), default=0)
    side = 40.0 if framed else 0.0                                      # room for the frames beyond the outermost icons
    placed: dict[str, Placed] = {}
    y = y0 + MARGIN
    for line, tier in enumerate(order):
        lines = parts[tier]
        for i, key in enumerate(rows[tier]):
            placed[key] = Placed(x0 + MARGIN + side + (spot[key] - lo) * xstep, y + (slots[key] if key in slots else i % lines) * SUB_STEP, tier, owner.get(key, ""))
        y += (lines - 1) * SUB_STEP + gaps[line]
    last_gap = gaps[-1] if gaps else Y_STEP
    width = MARGIN * 2 + side * 2 + (hi - lo) * xstep + NODE_W
    height = (y - last_gap) - y0 + NODE_H + 40 + MARGIN
    return placed, width, height


def uplink_routers(graph: Graph, keys: list[str], tier_value: dict[str, float]) -> dict[str, float]:
    """A router that nobody captured, linked to a router of its own row and to nothing below it, is an uplink of that router (the next router towards the
    provider, as WANR1 and WANR2 are for the router of a branch): it goes one row up, so the picture reads from the uplink down to the LAN.  Used on a page
    that is not laid out as a star (a star lifts these routers itself); the main router stays in its row."""
    members = set(keys)
    near: dict[str, set[str]] = {key: set() for key in keys}
    for conn in graph.connections:
        if conn.a in members and conn.b in members and conn.kind not in graph.hidden_kinds:
            near[conn.a].add(conn.b)
            near[conn.b].add(conn.a)
    lifted: dict[str, float] = {}
    for key in keys:
        node = graph.nodes[key]
        if node.role_hint != "router" or node.captured or not near[key]:
            continue
        row = tier_value[key]
        beside = [m for m in near[key] if tier_value[m] == row and graph.nodes[m].role_hint in ROUTERISH]
        below = [m for m in near[key] if tier_value[m] > row]
        if beside and not below and any(graph.nodes[m].captured for m in beside):
            lifted[key] = row - 1.0
    return lifted


def _name_key(graph: Graph, key: str) -> tuple:
    return natural_key(graph.nodes[key].hostname if key in graph.nodes else key, key)


def _parts(count: int, tier: float, core: int) -> int:
    """A long row of endpoints (a hundred access points) is dealt out over several staggered lines (every n-th device on one line)
    so the picture does not grow ten metres wide; the order along x stays the order of the row."""
    if tier < 4 or count <= WRAP_MIN:
        return 1
    cap = max(WRAP_MIN, int(core * 1.3) + 1)
    return 1 if count <= cap else -(-count // cap)


ISOLATED_EXTRA = 1.0           # icon steps of extra room between the linked devices of a row and the devices that have no link at all


def _isolated_last(row: list[str], neighbours: dict[str, set[str]]) -> list[str]:
    """A device with no link to anything on the page stays out of the row's connected devices: it goes to the end, so it never stands between two devices that are
    linked (their line would have to go round it) and reads as "not connected" rather than as part of the chain."""
    linked = [k for k in row if neighbours.get(k)]
    return linked + [k for k in row if not neighbours.get(k)] if 0 < len(linked) < len(row) else row


def _cluster_row(row: list[str], neighbours: dict[str, set[str]], want: dict[str, float], pairs: set[frozenset]) -> list[str]:
    """Devices of one row that are linked to each other stand side by side, and a device that has nothing to do with them does not stand between them (the line
    would have to go round it).  The row is cut into runs of devices that hang from the same place above (the same wished x, or none); inside a run every
    group of devices linked to each other (links inside the row) keeps its own order and moves together, the groups stand in the order of their first device."""
    out: list[str] = []
    i = 0
    while i < len(row):
        j = i + 1
        while j < len(row) and ((want.get(row[j]) is None) == (want.get(row[i]) is None)) and (want.get(row[i]) is None or abs(want[row[j]] - want[row[i]]) < 0.01):
            j += 1
        run = row[i:j]
        i = j
        seen: set[str] = set()
        groups: list[list[str]] = []
        for key in run:
            if key in seen:
                continue
            group, todo = [], [key]
            while todo:
                k = todo.pop()
                if k in seen:
                    continue
                seen.add(k)
                group.append(k)
                todo.extend(n for n in neighbours.get(k, ()) if n in run and n not in seen)
            groups.append(sorted(group, key=run.index))
        out.extend(k for group in groups for k in group)
    return out


def _isolated_gaps(row: list[str], neighbours: dict[str, set[str]], gaps: list[float]) -> list[float]:
    """``gaps`` (least distance between neighbours of a row) with ``ISOLATED_EXTRA`` more before the first device that has no link at all."""
    out = list(gaps)
    for i, (a, b) in enumerate(zip(row, row[1:])):
        if neighbours.get(a) and not neighbours.get(b):
            out[i] += ISOLATED_EXTRA
    return out


def _arrange(graph: Graph, rows: dict[float, list[str]], order: list[float], neighbours: dict[str, set[str]],
             pairs: set[frozenset], parts: dict[float, int], framed: dict[str, list[str]] | None = None, xstep: float = X_STEP,
             slots: dict[str, float] | None = None, star: bool = False) -> dict[str, float]:
    """Order every row and give every node its x (in icon steps).
    1. Bottom-up: devices whose only link goes down (an uplink-only router or firewall) sit over what they serve, several of them side by side
       (router A, B, C over the core they serve; the routers of core 1 never mix with those of core 2).
    2. Top-down: what hangs off one device (switch, access point, phone, PC, a collapsed node) stays together right under it,
       in name order; the children of switch A never mix with those of switch B. Devices with several uplinks keep natural name
       order and are centred between their uplinks.
    Positions follow the anchors as closely as the icon spacing allows, so a child really sits below its parent."""
    spot: dict[str, float] = {}
    def uniform(row: list[str], gap: float) -> dict[str, float]:
        return {k: (i - (len(row) - 1) / 2) * gap for i, k in enumerate(row)}
    for tier in order:
        spot.update(uniform(rows[tier], 1 / parts[tier]))
    for index in range(len(order) - 2, -1, -1):                       # 1. bottom-up
        tier = order[index]
        known = {k for t in order[index + 1:] for k in rows[t]}
        rows[tier] = _isolated_last(_keep_pairs_together(_reorder(graph, rows[tier], neighbours, spot, known, stubs_only=True)[0], pairs), neighbours)
        spot.update(uniform(rows[tier], 1 / parts[tier]))
    def top_down(index: int) -> None:
        tier = order[index]
        gap = 1 / parts[tier]
        want: dict[str, float] = {}
        if index:
            known = {k for t in order[:index] for k in rows[t]}
            row, want = _reorder(graph, rows[tier], neighbours, spot, known, gap)
            rows[tier] = _keep_pairs_together(row, pairs)
        rows[tier] = _isolated_last(_cluster_row(rows[tier], neighbours, want, pairs), neighbours)
        if framed and slots is not None and any(k in kids for kids in framed.values() for k in rows[tier]):
            spot.update(_spread_framed(rows[tier], want, framed, xstep, slots))
        else:
            spot.update(_spread(rows[tier], want, gap, _isolated_gaps(rows[tier], neighbours, [gap] * max(len(rows[tier]) - 1, 0))))

    for index in range(len(order)):                                   # 2. top-down
        top_down(index)

    def centre_owners() -> None:
        """3. A frame of end points is much wider than an icon, so the frames of a row are packed apart from the switches they belong to.  The switches of a row
        move over their frames (the lines of a comb are then short and run on both sides), the devices that have no frame follow, and a switch whose frame lies
        more than one row below (a core over its access switches) keeps a channel free in the rows between, as wide as its drops, so that none of its lines
        runs through another switch or over the lines of that switch.  The frames stay where they are (one pass, nothing is iterated, so the page cannot drift)."""
        index_of = {k: i for i, tier in enumerate(order) for k in rows[tier]}
        reach = {parent: drop_reach(len(kids)) for parent, kids in framed.items()}
        centre = {parent: sum(spot[k] for k in kids) / len(kids) for parent, kids in framed.items()}
        shifted: set[str] = set()
        for parent, kids in framed.items():
            cols = frame_columns(len(kids))
            if cols % 2 == 0 and len(kids) > cols:                          # an even grid has no middle column: the switch stands over one of the two middle ones, so that column drops
                centre[parent] += 0.5 if spot[parent] >= centre[parent] else -0.5          # straight and beside itself instead of every line of it hooking round the gap between the two
                shifted.add(parent)
        kid_rows = {index_of[k] for kids in framed.values() for k in kids}
        first = None
        changed: set[int] = set()
        for index, tier in enumerate(order):
            if star and tier <= STAR_MAX_TIER:                              # the rows of a star keep the order of the sweeps
                continue
            row = rows[tier]
            owners = [k for k in row if k in framed]
            passing = [p for p, kids in framed.items() if index_of[p] < index < index_of[kids[0]]]
            if not (owners and (len(row) > 1 or shifted.intersection(owners))) and not passing:
                continue
            want: dict[str, float] = {}
            for key in row:
                if key in framed:
                    want[key] = centre[key]
                elif not owners:
                    want[key] = spot[key]
            items = list(row)
            for parent in sorted(passing, key=lambda p: spot[p]):              # the channel of a core stands where the core stands, between the devices on either side of it
                mark = "\0" + parent
                at = sum(1 for k in items if (want.get(k, spot[k]) if not k.startswith("\0") else spot[k[1:]]) < spot[parent])
                while 0 < at < len(items) and frozenset((items[at - 1], items[at])) in pairs:
                    at += 1
                items.insert(at, mark)
                want[mark] = spot[parent]
                reach[mark] = reach[parent]
            got = _spread(items, want, 1.0, _isolated_gaps(items, neighbours, _owner_gaps(items, reach, xstep)))
            spot.update({k: x for k, x in got.items() if not k.startswith("\0")})
            first = index if first is None else first
            changed.add(index)
        if first is not None:
            for below in range(first + 1, len(order)):                         # what hangs between the rows follows; the frames and the rows of end points stay
                if below not in kid_rows and below not in changed:             # a row that was centred keeps its places
                    top_down(below)

    if star and slots is not None:
        upper = [i for i, tier in enumerate(order) if tier <= STAR_MAX_TIER]
        if upper:
            _star_sweeps(rows, order, neighbours, pairs, spot, max(upper))
            for index in range(max(upper) + 1, len(order)):          # what hangs below follows the new order of the rows above
                top_down(index)
            _lower_in_the_way(rows, order, neighbours, spot, max(upper), slots)
            _stack_ha_pairs(rows, order, pairs, spot, max(upper), slots)
    if framed and slots is not None:
        centre_owners()
    return spot


def drop_reach(lines: int) -> float:
    """px from the centre of a switch to the outermost drop of its comb to ``lines`` end points (half of them on each side, a few more on the busier one)."""
    per_side = -(-lines // 2) + 1
    step = max(DROP_STEP_MIN, min(DROP_STEP, DROP_SPAN / per_side))
    return DROP_CLEAR + step * (per_side - 1)


def _owner_gaps(row: list[str], reach: dict[str, float], xstep: float) -> list[float]:
    """Least distance (in icon steps) between neighbours of one row: one step, more when the drops of the lines of a switch to its frame have to pass the next device."""
    return [max(1.0, (max(reach.get(a, 0.0), reach.get(b, 0.0)) + DROP_ROOM) / xstep) for a, b in zip(row, row[1:])]


def _reorder(graph: Graph, row: list[str], neighbours: dict[str, set[str]], spot: dict[str, float], known: set[str],
             gap: float = 1.0, stubs_only: bool = False) -> tuple[list[str], dict[str, float]]:
    """One row against the rows already placed (``known``). A device with exactly one neighbour there and none beside it is a child
    of that neighbour: the children of one parent form one block under it, in name order. The others keep the order they have and
    are only moved right where their neighbours sit to the right of the devices before them. Returns the new row and the x each
    device would like. With ``stubs_only`` (the bottom-up pass) only a device whose single link goes to a placed device counts as a
    child, so a core with several links keeps its natural place in the row."""
    beside = set(row)
    kids: dict[str, list[str]] = {}
    free: list[str] = []
    for key in row:
        refs = [n for n in neighbours[key] if n in known]
        if len(refs) == 1 and not (neighbours[key] & beside) and (not stubs_only or len(neighbours[key]) == 1):
            kids.setdefault(refs[0], []).append(key)
        else:
            free.append(key)
    units: list[tuple[float, int, object, list[str]]] = []
    anchor = float("-inf")
    for i, key in enumerate(free):
        refs = [spot[n] for n in neighbours[key] if n in known]
        if refs and not stubs_only:
            anchor = max(anchor, sum(refs) / len(refs))
        units.append((anchor, 0, i, [key]))
    for parent, group in kids.items():
        units.append((spot[parent], 1, _name_key(graph, parent), sorted(group, key=lambda k: _name_key(graph, k))))
    units.sort(key=lambda u: (u[0], u[1], u[2]))
    new = [key for unit in units for key in unit[3]]
    want: dict[str, float] = {}
    for parent, group in kids.items():
        for j, key in enumerate(sorted(group, key=lambda k: _name_key(graph, k))):
            want[key] = spot[parent] + (j - (len(group) - 1) / 2) * gap
    for key in free:
        refs = [spot[n] for n in neighbours[key] if n in known]
        if refs and not stubs_only:
            want[key] = sum(refs) / len(refs)
    return new, want


def _spread(row: list[str], want: dict[str, float], gap: float, gaps: list[float] | None = None) -> dict[str, float]:
    """x of every device of a row: as near to the wanted x as possible, never closer than ``gap`` to the one before it (``gaps[i]`` is the least distance
    between ``row[i]`` and ``row[i + 1]`` when the pairs differ; isotonic regression on x - offset, so the order never changes)."""
    n = len(row)
    wished: list[float | None] = [want.get(k) for k in row]
    steps = gaps if gaps is not None else [gap] * max(n - 1, 0)
    offset = [0.0]
    for step in steps:
        offset.append(offset[-1] + step)
    if all(w is None for w in wished):
        return {k: offset[i] - offset[-1] / 2 for i, k in enumerate(row)}
    for i in range(1, n):                                             # a device with no wish follows the one before it
        if wished[i] is None and wished[i - 1] is not None:
            wished[i] = wished[i - 1] + steps[i - 1]
    for i in range(n - 2, -1, -1):
        if wished[i] is None and wished[i + 1] is not None:
            wished[i] = wished[i + 1] - steps[i]
    blocks: list[list[float]] = []                                    # [sum, count] of runs that must share one level
    for i, w in enumerate(wished):
        blocks.append([w - offset[i], 1])                             # type: ignore[operator]
        while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
            total, count = blocks.pop()
            blocks[-1][0] += total
            blocks[-1][1] += count
    out: dict[str, float] = {}
    i = 0
    for total, count in blocks:
        for _ in range(int(count)):
            out[row[i]] = total / count + offset[i]
            i += 1
    return out


ROUTERISH = ("router", "firewall", "loadbalancer")


def star_applicable(graph: Graph, keys: list[str]) -> bool:
    """A page whose devices are mostly routers, firewalls and load balancers (at least ``STAR_MIN_ROUTERS``, two of them captured) is laid out as a star:
    the rows are ordered so that no line crosses another where the picture allows it.  A page of switches keeps the layout it always had."""
    nodes = [graph.nodes[k] for k in keys]
    routerish = [n for n in nodes if n.role_hint in ROUTERISH]
    return len(routerish) >= STAR_MIN_ROUTERS and sum(1 for n in routerish if n.captured) >= 2


def ha_pairs(graph: Graph, keys: list[str]) -> set[frozenset]:
    """Firewalls (and load balancers) that are the two units of one HA pair: linked to each other, or the same model and the same neighbours."""
    members = set(keys)
    near: dict[str, set[str]] = {k: set() for k in keys}
    for conn in graph.connections:
        if conn.a in members and conn.b in members and conn.kind not in graph.hidden_kinds:
            near[conn.a].add(conn.b)
            near[conn.b].add(conn.a)
    pairs: set[frozenset] = set()
    units = [k for k in keys if graph.nodes[k].role_hint in ("firewall", "loadbalancer")]
    for i, a in enumerate(units):
        for b in units[i + 1:]:
            na, nb = graph.nodes[a], graph.nodes[b]
            if na.role_hint != nb.role_hint:
                continue
            same_model = bool(na.model) and na.model == nb.model
            if b in near[a] and same_model:
                pairs.add(frozenset((a, b)))
            elif same_model and len(near[a] - {b}) >= 2 and near[a] - {b} == near[b] - {a}:
                pairs.add(frozenset((a, b)))
    return pairs


def _crossings(rows: dict[float, list[str]], order: list[float], neighbours: dict[str, set[str]], spot: dict[str, float]) -> tuple[int, float]:
    """(crossings, total length) of the straight lines between the node positions: x = spot, y = index of the row."""
    where = {k: (spot[k], i) for i, t in enumerate(order) for k in rows[t]}
    edges = [(where[a], where[b]) for a in where for b in neighbours[a] if a < b and b in where]

    def turn(p, q, r):
        return (q[0] - p[0]) * (r[1] - p[1]) - (q[1] - p[1]) * (r[0] - p[0])

    crossing = 0
    for i, (p, q) in enumerate(edges):
        for r, t in edges[i + 1:]:
            if p in (r, t) or q in (r, t):
                continue
            if turn(p, q, r) * turn(p, q, t) < 0 and turn(r, t, p) * turn(r, t, q) < 0:
                crossing += 1
    by_row: dict[int, list[float]] = {}
    for x, line in where.values():
        by_row.setdefault(line, []).append(x)
    for p, q in edges:                                                  # a line between two devices of one row that runs over the devices between them
        if p[1] == q[1]:
            lo, hi = sorted((p[0], q[0]))
            crossing += sum(1 for x in by_row[p[1]] if lo < x < hi)
    length = sum(abs(p[0] - q[0]) + 1.5 * abs(p[1] - q[1]) for p, q in edges)
    return crossing, length


def _star_sweeps(rows: dict[float, list[str]], order: list[float], neighbours: dict[str, set[str]], pairs: set[frozenset], spot: dict[str, float], last: int) -> None:
    """Order the rows 0..``last`` so that devices that talk to each other stand next to each other and lines cross as little as possible:
    barycenter passes down and up (a device goes to the mean x of its neighbours in the row above, then below; neighbours in its own row count too),
    the best order found is kept.  What is linked to the same devices on both sides ends up between them, so a hub sits in the middle of its neighbours."""
    row_of = {k: i for i, t in enumerate(order) for k in rows[t]}
    best = ({t: list(rows[t]) for t in order}, dict(spot), _crossings(rows, order, neighbours, spot))
    big = sum(len(v) for v in neighbours.values()) // 2 > STAR_SCORE_EDGES          # counting crossings is quadratic: on a very large page only the last pass is scored
    for sweep in range(STAR_SWEEPS if not big else 4):
        down = sweep % 2 == 0
        for i in (range(0, last + 1) if down else range(last, -1, -1)):
            tier = order[i]
            row = rows[tier]
            want: dict[str, float] = {}
            for k in row:
                refs = [spot[n] for n in neighbours[k] if n in row_of and ((row_of[n] < i) if down else (row_of[n] > i))]
                refs += [spot[n] for n in neighbours[k] if n != k and row_of.get(n) == i]
                want[k] = sum(refs) / len(refs) if refs else spot[k]
            index = {k: j for j, k in enumerate(row)}
            row = _keep_pairs_together(sorted(row, key=lambda k: (round(want[k], 6), index[k])), pairs)
            rows[tier] = row
            spot.update(_spread(row, want, 1.0))
        if big and sweep < 3:
            continue
        score = _crossings(rows, order, neighbours, spot)
        if score < best[2]:
            best = ({t: list(rows[t]) for t in order}, dict(spot), score)
    if sum(len(v) for v in neighbours.values()) // 2 <= STAR_PERM_EDGES:
        best = _star_orders(rows, order, neighbours, pairs, spot, last, best, row_of)
    for t in order:
        rows[t] = best[0][t]
    spot.update(best[1])


def _star_orders(rows: dict[float, list[str]], order: list[float], neighbours: dict[str, set[str]], pairs: set[frozenset], spot: dict[str, float], last: int,
                 best: tuple, row_of: dict[str, int]) -> tuple:
    """The barycenter sweeps can stop in a local optimum (a router that talks to both others ends at the edge of its row, so a line runs over the router
    between them).  The main row of the star (the row with the most captured devices, at most ``STAR_PERM_MAX`` devices) is therefore also tried in every order
    (a mirror image counts once, the one with the busiest device on the left); for each order the rows above and below it are placed by barycenter passes around the fixed row.  The best of everything wins."""
    main = max((i for i in range(last + 1) if 2 <= len(rows[order[i]]) <= STAR_PERM_MAX), key=lambda i: (len(rows[order[i]]), -i), default=None)
    if main is None:
        return best
    import itertools
    main_row = sorted(best[0][order[main]], key=natural_key)

    def lead(key: str) -> tuple:
        return -len(neighbours[key]), natural_key(key)

    trial_rows = {t: list(best[0][t]) for t in order}
    for perm in itertools.permutations(main_row):
        if lead(perm[-1]) < lead(perm[0]) or _split_pair(perm, pairs):          # the mirror image of an order is the same picture: only the one with the busiest device (then the first name) on the left
            continue
        rows_t = {t: list(v) for t, v in trial_rows.items()}
        rows_t[order[main]] = list(perm)
        spot_t = dict(best[1])
        spot_t.update(_spread(rows_t[order[main]], {k: float(j) - (len(perm) - 1) / 2 for j, k in enumerate(perm)}, 1.0))
        for sweep in range(4):
            down = sweep % 2 == 0
            for i in (range(0, last + 1) if down else range(last, -1, -1)):
                if i == main:
                    continue
                tier = order[i]
                row = rows_t[tier]
                want: dict[str, float] = {}
                for k in row:
                    refs = [spot_t[n] for n in neighbours[k] if n in row_of and ((row_of[n] < i) if down else (row_of[n] > i))]
                    refs += [spot_t[n] for n in neighbours[k] if n != k and row_of.get(n) == i]
                    want[k] = sum(refs) / len(refs) if refs else spot_t[k]
                index = {k: j for j, k in enumerate(row)}
                row = _keep_pairs_together(sorted(row, key=lambda k: (round(want[k], 6), index[k])), pairs)
                rows_t[tier] = row
                spot_t.update(_spread(row, want, 1.0))
        score = _crossings(rows_t, order, neighbours, spot_t)
        if score < best[2]:
            best = (rows_t, spot_t, score)
    return best


def _split_pair(perm: tuple[str, ...], pairs: set[frozenset]) -> bool:
    """An order in which the two units of an HA pair are not next to each other."""
    place = {k: j for j, k in enumerate(perm)}
    return any(len(pair) == 2 and all(k in place for k in pair) and abs(place[tuple(pair)[0]] - place[tuple(pair)[1]]) != 1 for pair in pairs)


def _lower_in_the_way(rows: dict[float, list[str]], order: list[float], neighbours: dict[str, set[str]], spot: dict[str, float], last: int,
                      slots: dict[str, float]) -> None:
    """Two routers of one row that are linked but not next to each other: the line would run over the devices between them.  Each device of the row gets
    one of two heights (the second is ``STAR_DROP`` of a step lower) so that as few long lines as possible run over an icon: a line between two devices
    of the upper height passes above a lowered device between them; three routers that all talk to each other form a triangle.  Found by flipping one
    device at a time while that helps."""
    for i in range(last + 1):
        row = rows[order[i]]
        place = {k: j for j, k in enumerate(row)}
        long_links = [(place[a], place[b]) for a in row for b in neighbours[a] if b in place and place[b] - place[a] > 1]
        if not long_links:
            continue
        low = [False] * len(row)

        def obstructed(levels: list[bool]) -> int:
            hits = 0
            for lo, hi in long_links:
                for m in range(lo + 1, hi):
                    if levels[lo] != levels[hi] or levels[m] == levels[lo]:
                        hits += 1
            return hits

        cost = obstructed(low)
        for _ in range(3 * len(row)):
            improved = False
            for j in range(len(row)):
                low[j] = not low[j]
                trial = obstructed(low)
                if trial < cost:
                    cost, improved = trial, True
                else:
                    low[j] = not low[j]
            if not improved or cost == 0:
                break
        if any(low):
            for k, is_low in zip(row, low):
                slots[k] = STAR_DROP if is_low else 0.0


def _stack_ha_pairs(rows: dict[float, list[str]], order: list[float], pairs: set[frozenset], spot: dict[str, float], last: int, slots: dict[str, float]) -> None:
    """An HA pair that stands at the left or right end of a row of four or more (beside the main devices, not above or below them) is stacked:
    one unit over the other, so the row stays narrow.  Between the main devices it stays side by side."""
    for i in range(last + 1):
        row = rows[order[i]]
        if len(row) < 4:
            continue
        for first, second in ((row[0], row[1]), (row[-2], row[-1])):
            if frozenset((first, second)) in pairs and slots.get(first, 0.0) == 0.0 and slots.get(second, 0.0) == 0.0:
                centre = (spot[first] + spot[second]) / 2
                spot[first], spot[second] = centre - 0.3, centre + 0.3          # a little off the vertical, so the line to the lower unit clears the upper one
                for k in row:
                    slots.setdefault(k, 0.0)
                slots[second] = 1.0


def framed_roles(graph: Graph) -> tuple[str, ...]:
    """The roles of the end points that are framed per switch: all of them with the option "group end points", only the access points when that option is off
    but the access points are drawn one by one (not collapsed), none otherwise."""
    if getattr(graph, "group_endpoints", False):
        return ENDPOINT_ROLES
    return ("ap",) if getattr(graph, "group_aps", False) else ()


def box_groups(graph: Graph, keys: list[str], tier_value: dict[str, float]) -> dict[str, list[str]]:
    """Option "group end points under the same switch" (and, always, the access points drawn one by one): {switch: its end points, in name order} for every switch with at least ``BOX_MIN`` end points
    (access point, phone, host, server nobody captured) whose only link goes to that switch.  An end point on two switches, or behind another end
    point, is not framed.  The switch must be in a row above its end points, so the frame sits under it."""
    roles = framed_roles(graph)
    if not roles:
        return {}
    members = set(keys)
    near: dict[str, set[str]] = {key: set() for key in keys}
    for conn in graph.connections:
        if conn.a in members and conn.b in members and conn.kind not in graph.hidden_kinds:
            near[conn.a].add(conn.b)
            near[conn.b].add(conn.a)
    groups: dict[str, list[str]] = {}
    for key in keys:
        node = graph.nodes[key]
        if node.captured or node.role_hint not in roles or len(near[key]) != 1:
            continue
        parent = next(iter(near[key]))
        if graph.nodes[parent].role_hint in ENDPOINT_ROLES or tier_value[parent] >= tier_value[key]:
            continue
        groups.setdefault(parent, []).append(key)
    return {parent: sorted(kids, key=lambda k: _name_key(graph, k)) for parent, kids in groups.items() if len(kids) >= BOX_MIN}


def frame_columns(count: int) -> int:
    """Icons per line inside one frame: up to three side by side, then a grid that is about as wide as it is high (at most ``BOX_COLS_MAX``)."""
    return count if count <= 3 else min(BOX_COLS_MAX, math.ceil(math.sqrt(count)))


def _spread_framed(row: list[str], want: dict[str, float], framed: dict[str, list[str]], xstep: float, slots: dict[str, int]) -> dict[str, float]:
    """x (in icon steps) of a row that holds frames of end points.  A frame is a unit as wide as its grid; it is put as near as possible to the switch above it,
    never closer than ``BOX_GAP`` to the unit before it (same least-squares order-keeping fit as ``_spread``).  Fills ``slots`` with the line of each icon in its frame."""
    owner = {k: parent for parent, kids in framed.items() for k in kids}
    units: list[tuple[list[str], float, float | None, bool]] = []          # members, half width in steps, wished x, is a frame
    i = 0
    while i < len(row):
        parent = owner.get(row[i])
        if parent is None:
            units.append(([row[i]], 0.5, want.get(row[i]), False))
            i += 1
            continue
        j = i
        while j < len(row) and owner.get(row[j]) == parent:
            j += 1
        members = row[i:j]
        cols = frame_columns(len(members))
        wishes = [want[k] for k in members if k in want]
        units.append((members, ((cols - 1) * xstep / 2 + BOX_HALF) / xstep, sum(wishes) / len(wishes) if wishes else None, True))
        i = j
    offsets = [0.0]
    for (_, left, _, left_frame), (_, right, _, right_frame) in zip(units, units[1:]):
        offsets.append(offsets[-1] + left + right + (BOX_GAP / xstep if left_frame or right_frame else 0.0))
    wished = [u[2] for u in units]
    if all(w is None for w in wished):
        centres = [o - offsets[-1] / 2 for o in offsets]
    else:
        for n in range(1, len(units)):
            if wished[n] is None and wished[n - 1] is not None:
                wished[n] = wished[n - 1] + offsets[n] - offsets[n - 1]
        for n in range(len(units) - 2, -1, -1):
            if wished[n] is None and wished[n + 1] is not None:
                wished[n] = wished[n + 1] - (offsets[n + 1] - offsets[n])
        level = _isotonic([w - o for w, o in zip(wished, offsets)])        # type: ignore[operator]
        centres = [lv + o for lv, o in zip(level, offsets)]
    out: dict[str, float] = {}
    for (members, _, _, is_frame), centre in zip(units, centres):
        if not is_frame:
            out[members[0]] = centre
            slots[members[0]] = 0
            continue
        cols = frame_columns(len(members))
        lines = -(-len(members) // cols)
        for n, key in enumerate(members):
            line, column = divmod(n, cols)
            on_line = cols if line < lines - 1 else len(members) - cols * (lines - 1)
            out[key] = centre + column - (on_line - 1) / 2                  # a short last line is centred under the others
            slots[key] = line
    return out


def _isotonic(values: list[float]) -> list[float]:
    """Closest non-decreasing sequence in the least-squares sense (pool adjacent violators)."""
    blocks: list[list[float]] = []
    for value in values:
        blocks.append([value, 1])
        while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
            total, count = blocks.pop()
            blocks[-1][0] += total
            blocks[-1][1] += count
    out: list[float] = []
    for total, count in blocks:
        out.extend([total / count] * int(count))
    return out


def _x_step(graph: Graph, keys: list[str]) -> float:
    """Room between two icons of one row: the longest hostname, model or address under an icon decides (12 pt bold, about 7 px a letter)."""
    longest = max((max(len(graph.nodes[k].hostname), len(graph.nodes[k].model or ""), len(graph.nodes[k].mgmt_ip or "")) for k in keys), default=12)
    return min(X_MAX, max(X_STEP, 7.0 * min(longest, 34) + 44))


def _gaps(graph: Graph, keys: list[str], order: list[float], rows: dict[float, list[str]]) -> list[float]:
    """Height of every row: more lines between two rows means more room for the port labels on them."""
    members = set(keys)
    line_of = {key: i for i, tier in enumerate(order) for key in rows[tier]}
    crossing = [0] * max(len(order), 1)
    for conn in graph.connections:
        if conn.a in members and conn.b in members and conn.kind not in graph.hidden_kinds:
            lo, hi = sorted((line_of[conn.a], line_of[conn.b]))
            for i in range(lo, hi):
                crossing[i] += 1
    comb = [0.0] * max(len(order), 1)                           # lanes of the comb above a frame of end points: 6 px per line of one switch
    roles = framed_roles(graph)
    if roles:
        lanes: dict[tuple[int, str], int] = {}
        for conn in graph.connections:
            if conn.a in members and conn.b in members and conn.kind not in graph.hidden_kinds:
                for top, low in ((conn.a, conn.b), (conn.b, conn.a)):
                    node = graph.nodes[low]
                    if not node.captured and node.role_hint in roles and line_of[top] < line_of[low]:
                        lanes[(line_of[low] - 1, top)] = lanes.get((line_of[low] - 1, top), 0) + 1
        for (i, _), count in lanes.items():
            comb[i] = max(comb[i], min(COMB_EXTRA_MAX, 4.0 * count - 20))
    return [Y_STEP + min(Y_EXTRA_MAX, max(0, count - 8) * 7) + max(0.0, extra) for count, extra in zip(crossing, comb)]


def _tier_values(graph: Graph, keys: list[str]) -> dict[str, float]:
    """Row of every node: the tier of its role, except that a device nobody captured which hangs only off devices of its own
    tier goes half a row lower (a switch behind an access pair is below that pair, not beside it)."""
    members = set(keys)
    value = {key: float(tier_of(graph.nodes[key].role_hint)) for key in keys}
    near: dict[str, set[str]] = {key: set() for key in keys}
    for conn in graph.connections:
        if conn.a in members and conn.b in members and conn.kind not in graph.hidden_kinds:
            near[conn.a].add(conn.b)
            near[conn.b].add(conn.a)
    pairs = {frozenset((a, b)) for a, b, _ in graph.vpc_pairs}
    for key in keys:                                          # a shared subnet (IP view) sits half a row below the devices it joins
        if graph.nodes[key].role_hint == "segment":
            members = [value[m] for m in near[key] if m in value and graph.nodes[m].role_hint != "segment"]
            value[key] = (max(members) + 0.5) if members else value[key]
    value.update(mesh_tiers(graph, keys, value, near, pairs))
    for key in keys:
        node = graph.nodes[key]
        if node.role_hint == "segment":
            continue
        base = value[key]
        if node.captured or base >= 4 or not near[key]:
            continue
        if node.vendor == "F5" and node.role_hint == "loadbalancer":
            continue                                          # the HA peer of a BIG-IP (assumed from its sync VLAN) stands beside it, not under it
        peers = [m for m in near[key] if graph.nodes[m].role_hint not in ("ap", "phone", "host", "server")]
        if peers and all(value[m] >= base for m in peers) and any(value[m] == base and frozenset((key, m)) not in pairs for m in peers):
            if any(value[n] < base for m in peers for n in near[m] if n != key):
                value[key] = base + 0.5
    return value


MESH_ROLES = {"router", "firewall", "loadbalancer", "core", "aggregation", "switch", "access", "wlc", "fabric"}
MESH_MAX_ROW = 80                # a row with more devices than this is not searched for meshes


def _stem(hostname: str) -> str:
    return re.sub(r"\d+", "", hostname.upper())


def _twins(graph: Graph, a: str, b: str, peers: set[frozenset]) -> bool:
    """Two devices that are the two units of one pair: vPC / MLAG / stack peers, or the same model under names that differ only in their numbers (HQCORENX1, HQCORENX2)."""
    if frozenset((a, b)) in peers:
        return True
    na, nb = graph.nodes[a], graph.nodes[b]
    return bool(na.model) and na.model == nb.model and na.hostname != nb.hostname and _stem(na.hostname) == _stem(nb.hostname)


def find_meshes(graph: Graph, keys: list[str], value: dict[str, float], near: dict[str, set[str]]) -> list[tuple[tuple[str, str], tuple[str, str]]]:
    """Squares of four network devices of one row in which every device of one side is linked to both devices of the other side (a pair of core switches
    cross-connected with a pair of edge switches; four Nexus or Catalyst in a full mesh).  Returns ``(side, side)`` for every group of linked devices of that row
    that holds one square, or one square whose two sides are both pairs (vPC / MLAG peers, or the same model under names that differ in their number): a
    metro switch linked to the same two edge switches does not change the picture.  When two spines serve six leaves there are many squares and none of them is
    the picture, so those rows stay as they are.  A square of four fully linked devices can be cut into two sides three ways; the cut that keeps the pairs together is taken."""
    members = {k for k in keys if graph.nodes[k].role_hint in MESH_ROLES}
    rows: dict[float, list[str]] = {}
    for key in members:
        rows.setdefault(value[key], []).append(key)
    peers = {frozenset((a, b)) for a, b, _ in graph.vpc_pairs}
    found: list[tuple[tuple[str, str], tuple[str, str]]] = []
    for row in rows.values():
        if len(row) < 4 or len(row) > MESH_MAX_ROW:
            continue
        side = set(row)
        link = {k: near[k] & side for k in row}
        seen: set[str] = set()
        for start in sorted(row):
            if start in seen or not link[start]:
                continue
            group, todo = set(), [start]
            while todo:
                cur = todo.pop()
                if cur in group:
                    continue
                group.add(cur)
                todo.extend(link[cur] - group)
            seen |= group
            squares: dict[frozenset, tuple[tuple[str, str], tuple[str, str], int]] = {}
            ordered = sorted(group)
            for i, a in enumerate(ordered):
                for b in ordered[i + 1:]:
                    common = sorted((link[a] & link[b]) - {a, b})
                    for j, c in enumerate(common):
                        for d in common[j + 1:]:
                            four = frozenset((a, b, c, d))
                            # (a, b) | (c, d): the cross lines a-c a-d b-c b-d all exist; pairs on a side and lines inside a side count for the cut
                            inner = 3 * _twins(graph, a, b, peers) + 3 * _twins(graph, c, d, peers) + (b in link[a]) + (d in link[c])
                            if four not in squares or inner > squares[four][2]:
                                squares[four] = ((a, b), (c, d), inner)
            if len(squares) > 1:
                squares = {f: q for f, q in squares.items() if q[2] >= 6}              # both sides are pairs
            if len(squares) == 1:
                (first, second, _), = squares.values()
                found.append((first, second))
    return found


def mesh_tiers(graph: Graph, keys: list[str], value: dict[str, float], near: dict[str, set[str]], pairs: set[frozenset]) -> dict[str, float]:
    """Rows of the devices of every square found by ``find_meshes``: the side that has more lines upward (then fewer downward, then the one nobody captured,
    then the first name) stays in the row, the other side goes half a row lower, so the four stand as a box with the lines between the sides running straight
    down and across.  A seen-only device that hangs only off the lower side (a metro switch) goes below it."""
    out: dict[str, float] = {}
    for first, second in find_meshes(graph, keys, value, near):
        row = value[first[0]]

        def rank(side: tuple[str, str]) -> tuple:
            up = sum(1 for k in side for m in near[k] if value[m] < row and graph.nodes[m].role_hint not in ENDPOINT_ROLES)
            down = sum(1 for k in side for m in near[k] if value[m] > row)
            return -up, down, sum(1 for k in side if graph.nodes[k].captured), natural_key(min(side))
        top, bottom = sorted((first, second), key=rank)
        for key in bottom:
            out[key] = row + 0.5
        mesh = set(first) | set(second)
        for key in keys:
            node = graph.nodes[key]
            if key in mesh or node.captured or value[key] != row or node.role_hint in ENDPOINT_ROLES or node.role_hint == "segment":
                continue
            if near[key] and near[key] <= set(bottom) | {m for m in near[key] if value[m] > row}:
                if near[key] & set(bottom):
                    out[key] = row + 1.0
    return out


def _keep_pairs_together(row: list[str], pairs: set[frozenset]) -> list[str]:
    out: list[str] = []
    for key in row:
        if key in out:
            continue
        out.append(key)
        for other in row:
            if other not in out and frozenset((key, other)) in pairs:
                out.append(other)
    return out


def groups_of(graph: Graph, mode: str, follow: bool = True) -> dict[str, list[str]]:
    """Group node keys by 'none' | 'prefix1' | 'prefix2' | 'prefix3' (leading hostname words).  A device nobody captured whose name matches no site (an IP phone
    SEP0C2724547E0D, a PC, an access point named after another floor, a switch behind a distribution switch) follows the site of the devices it is linked to, so the
    Overview shows it under its own switch and not in one box "Other devices" far from the cable; with ``follow=False`` it stays in "Other devices" (the
    count the "auto" grouping uses to size the sites, which are sized by their network devices, not by their phones)."""
    visible = [key for key in graph.nodes if key not in graph.hidden_nodes]
    if mode not in PREFIX_WORDS:
        return {"All devices": visible}
    take = PREFIX_WORDS[mode]
    groups: dict[str, list[str]] = {}
    for key, node in graph.nodes.items():
        if key in graph.hidden_nodes:
            continue
        if "::" in key and key.split("::")[0] in graph.nodes:     # rolled-up endpoints follow their parent
            node = graph.nodes[key.split("::")[0]]
        host = node.chassis or node.hostname                 # the VDOMs / vsys / vCMP guests of one box share its name: "DRFGFW1 [DR-OL-FG]" is not a site "DRFGFW1 [DR"
        parts = host.replace("_", "-").split("-")
        name = "-".join(parts[:take]) if len(parts) > take else host
        groups.setdefault(name, []).append(key)
    # a "site" made only of devices that nobody captured (a firewall, a server, a stray MAC name) is not a site
    other = [k for name, keys in list(groups.items()) if all(not graph.nodes[k].captured for k in keys) for k in groups.pop(name)]
    if other:
        groups.setdefault("Other devices", []).extend(other)
        if follow:
            _follow_neighbours(graph, groups)
    return groups


FOLLOW_PASSES = 4                # a phone behind a seen-only switch behind a distribution switch needs two passes


def _follow_neighbours(graph: Graph, groups: dict[str, list[str]]) -> None:
    """Move devices of "Other devices" into the one site their cables lead to: every visible line of the device goes to devices of that single site (devices that are
    still in "Other devices" do not count against it, they may follow in the next pass).  A device linked to two sites, or to nothing, stays where it is."""
    owner = {key: name for name, keys in groups.items() for key in keys}
    near: dict[str, set[str]] = {key: set() for key in owner}
    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds or conn.a not in owner or conn.b not in owner:
            continue
        near[conn.a].add(conn.b)
        near[conn.b].add(conn.a)
    for _ in range(FOLLOW_PASSES):
        moved: dict[str, str] = {}
        for key in groups.get("Other devices", []):
            sites = {owner[m] for m in near[key]} - {"Other devices"}
            if len(sites) == 1:
                moved[key] = next(iter(sites))
        if not moved:
            break
        for key, name in moved.items():
            owner[key] = name
            groups[name].append(key)
        groups["Other devices"] = [k for k in groups["Other devices"] if k not in moved]
    if not groups.get("Other devices"):
        groups.pop("Other devices", None)


def auto_mode(graph: Graph) -> str:
    """Pick the grouping for the "auto" option: ``none`` for a small network, otherwise the shortest hostname prefix (1, 2 or 3 words) whose
    sites each fit on a page, with at least two sites that hold two or more devices.  When no prefix gives readable sites the diagram stays whole."""
    visible = [key for key in graph.nodes if key not in graph.hidden_nodes]
    if len(visible) < AUTO_MIN_DEVICES:
        return "none"
    fallback: tuple[int, str] | None = None
    for mode in ("prefix1", "prefix2", "prefix3"):
        groups = groups_of(graph, mode, follow=False)
        named = {name: keys for name, keys in groups.items() if name != "Other devices"}
        multi = [keys for keys in named.values() if len(keys) >= 2]
        if len(multi) < 2 or len(groups) > AUTO_MAX_SITES:
            continue
        biggest = max(len(keys) for keys in named.values())
        if biggest <= AUTO_MAX_SITE:
            return mode
        if fallback is None or biggest < fallback[0]:
            fallback = (biggest, mode)
    return fallback[1] if fallback else "none"
