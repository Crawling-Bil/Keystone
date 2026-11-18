"""The page laid out as blocks round the core: external zones on top, the core in the middle, internal zones under it, tall zones (a DMZ with its own WAN and servers) at the sides.

``zones.plan`` finds the blocks; each block is laid out by ``layered`` as a small page of its own (its head pair on the side that faces the core, its switches and end points
below it, in the frames and rows the rest of the engine already makes), and the blocks are set out in bands.  Inside a band the blocks stand side by side in the order that keeps the
lines between blocks short; the outer bands are aligned on the side that faces the core, so the head of every block is the nearest to it.  The page is then the picture a person
draws by hand for such a network (core in the centre, the way out above, the users and servers below, a box round each zone), see ``zones.py``.
"""

from __future__ import annotations

from collections import defaultdict

from . import layout as L
from .graph import Graph
from .zones import Zone, ZonePlan, block_rows, centres_on, plan

GAP_X = 150.0                      # free space between two blocks of one band (the lines of the blocks run through it)
GAP_Y = 110.0                      # ... and between two bands (the lines between the blocks, and their port names)
PAD = 60.0                         # round the box of a block (``scene.BOX_PAD``)
TITLE = 40.0                       # the strip for the title of a block (``scene.TITLE_H``)
SIDE_GAP = 260.0                   # a tall block stands this far from the centre column: the lines of the core run between them
INSIDE_SHARE = 0.5                 # a tall block stands in the row of the core when the blocks of one side take at most this share of the width of the widest band
CORE_TITLE = "CORE"


HEAD_GAP = 2.2 * L.NODE_W          # the units of a head pair stand at least this far apart (centre to centre): side by side, with room for the name of the peer link between them; longer names ask for more (``L.caption_width``)


def _pack_heads(graph: Graph, placed: dict[str, L.Placed], zone: Zone) -> None:
    """The two units of the head of a block (an aggregation pair) stand side by side in the middle of the block, not at the two ends of the row of switches below them: every switch below
    is cabled to both, so a pair far apart makes every one of those cables cross the cables of its neighbours (K2,n); a pair together makes them a fan."""
    heads = sorted((k for k in zone.head if k in placed), key=lambda k: placed[k].x)
    if len(heads) < 2:
        return
    y = placed[heads[0]].y
    if any(abs(placed[k].y - y) > 1 for k in heads) or any(k not in heads and abs(p.y - y) < L.NODE_H for k, p in placed.items()):
        return                                                       # the heads are not alone in their row: the layout keeps what it found
    middle = sum(placed[k].x for k in heads) / len(heads)
    widths = [L.caption_width(graph, k) for k in heads]
    offsets = [0.0]
    for i in range(1, len(heads)):                                   # each neighbour needs half of its own caption and half of the other's, plus a clear margin, never less than HEAD_GAP
        offsets.append(offsets[-1] + max(HEAD_GAP, (widths[i - 1] + widths[i]) / 2 + L.CAPTION_MARGIN))
    shift = middle - (offsets[0] + offsets[-1]) / 2
    for k, off in zip(heads, offsets):
        p = placed[k]
        placed[k] = L.Placed(shift + off, p.y, p.tier, p.box, p.depth, p.zone, p.zone_id)


def _block(graph: Graph, zone: Zone, ghosts: set[str], ghost_side: dict[str, int] | None):
    keys = zone.keys
    placed, width, height = L.layered(graph, sorted(keys), 0, 0, ghosts=ghosts & keys, ghost_side=ghost_side, forced=block_rows(graph, zone))
    if zone.kind == "internal":
        _pack_heads(graph, placed, zone)
    return placed, width + PAD, height + TITLE + PAD


def _links(graph: Graph, owner: dict[str, str]) -> dict[str, dict[str, int]]:
    weight: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds:
            continue
        a, b = owner.get(conn.a), owner.get(conn.b)
        if a and b and a != b:
            weight[a][b] += 1
            weight[b][a] += 1
    return weight


def _order(blocks: list[Zone], size: dict[str, tuple[float, float]], weight, centre_x: dict[str, float], key_of: dict[str, str]) -> list[Zone]:
    """The blocks of one band left to right: first by name, then three passes that put each block at the mean x of the blocks (and the sides) it is cabled to."""
    order = sorted(blocks, key=lambda z: sorted(key_of[k] for k in z.head or z.members)[0] if (z.head or z.members) else "")
    if len(order) < 2:
        return order
    for _ in range(3):
        x = 0.0
        pos: dict[str, float] = dict(centre_x)
        for z in order:
            pos[z.key] = x + size[z.key][0] / 2
            x += size[z.key][0] + GAP_X
        total = x - GAP_X
        pos["core"] = total / 2                                      # the core stands in the middle of the band
        want: dict[str, float] = {}
        for z in order:
            links = {o: w for o, w in weight.get(z.key, {}).items() if o in pos and o not in {b.key for b in blocks}}
            weight_sum = sum(links.values())
            want[z.key] = sum(pos[o] * w for o, w in links.items()) / weight_sum if weight_sum else pos[z.key]
        order = sorted(order, key=lambda z: (want[z.key], z.key))
    return order


def _fit_inside(side: list[Zone], size: dict[str, tuple[float, float]], free: float) -> list[Zone]:
    """The tall blocks of one side that stand in the row of the core (beside it, at its height) because the bands above and below are wide enough to leave the room: the lines to the core
    stay short.  The rest stand in the columns at the sides of the page."""
    taken: list[Zone] = []
    used = 0.0
    for z in side:
        need = size[z.key][0] + GAP_X
        if used + need > free:
            break
        taken.append(z)
        used += need
    return taken


def _core_start(graph, layouts, spots, size, core_row, centre_zone, zones, x_centre, width_c, row_w, inside_left) -> float:
    """Where the row of the core starts so that the core stands above the middle of the heads it is cabled to (the head pairs of the blocks above and below), as far as the row fits in the page."""
    offset = 0.0
    for z in core_row:
        if z is centre_zone:
            break
        offset += size[z.key][0] + GAP_X
    heads: list[float] = []
    placed_x = {k: p.x + spots[z.key][0] for z in zones if z.key in spots for k, p in layouts[z.key][0].items()}
    core_keys = centre_zone.members
    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds:
            continue
        for mine, other in ((conn.a, conn.b), (conn.b, conn.a)):
            if mine in core_keys and other in placed_x and other not in core_keys:
                heads.append(placed_x[other])
    middle = sum(heads) / len(heads) + PAD if heads else x_centre + width_c / 2
    start = middle - offset - size[centre_zone.key][0] / 2
    return max(x_centre, min(start, x_centre + width_c - row_w))


def _crossings(graph: Graph, placed: dict[str, L.Placed], owner: dict[str, str]) -> float:
    """A quick count for the choice between two orders of the blocks: the crossings (and five times the lines through an icon) of the lines between two blocks, each line taken as the
    straight segment between its two icons, against all lines."""
    centre = {k: (p.x + L.NODE_W / 2, p.y + L.NODE_H / 2) for k, p in placed.items()}
    segs = []
    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds or conn.a == conn.b or conn.a not in centre or conn.b not in centre:
            continue
        a, b = centre[conn.a], centre[conn.b]
        segs.append((a, b, conn.a, conn.b, owner.get(conn.a) != owner.get(conn.b)))
    cost = 0.0
    inter = [s for s in segs if s[4]]
    for s in inter:
        (x1, y1), (x2, y2) = s[0], s[1]
        lo_x, hi_x, lo_y, hi_y = min(x1, x2), max(x1, x2), min(y1, y2), max(y1, y2)
        for k, p in placed.items():                               # through an icon
            if k in (s[2], s[3]):
                continue
            if p.x < hi_x and p.x + L.NODE_W > lo_x and p.y < hi_y and p.y + L.NODE_H > lo_y and _hits_rect(s[0], s[1], p.x, p.y):
                cost += 5
    for i, s in enumerate(inter):
        for t in segs:
            if t is s or (t[4] and id(t) < id(s)) or {s[2], s[3]} & {t[2], t[3]}:
                continue
            if _cross(s[0], s[1], t[0], t[1]):
                cost += 1
    return cost


def _cross(p1, p2, p3, p4) -> bool:
    d1 = (p4[0] - p3[0]) * (p1[1] - p3[1]) - (p4[1] - p3[1]) * (p1[0] - p3[0])
    d2 = (p4[0] - p3[0]) * (p2[1] - p3[1]) - (p4[1] - p3[1]) * (p2[0] - p3[0])
    d3 = (p2[0] - p1[0]) * (p3[1] - p1[1]) - (p2[1] - p1[1]) * (p3[0] - p1[0])
    d4 = (p2[0] - p1[0]) * (p4[1] - p1[1]) - (p2[1] - p1[1]) * (p4[0] - p1[0])
    return d1 * d2 < 0 and d3 * d4 < 0


def _hits_rect(a, b, x: float, y: float) -> bool:
    x1, y1, x2, y2 = x + 6, y + 6, x + L.NODE_W - 6, y + L.NODE_H - 6
    for p, q in (((x1, y1), (x2, y1)), ((x2, y1), (x2, y2)), ((x2, y2), (x1, y2)), ((x1, y2), (x1, y1))):
        if _cross(a, b, p, q):
            return True
    return x1 < a[0] < x2 and y1 < a[1] < y2


MOVES = 60                         # the most orders of the blocks that are tried


def _split_by_centre(graph: Graph, keys: list[str], ghosts: set[str], centres: list[frozenset]) -> list[list[str]]:
    """The devices of a page that has two centres (a data center and its recovery site drawn on one diagram), one list per centre: every device goes with the centre it is nearest to (hops
    over the cables; a tie goes to the centre that has more cables to it, then to the first by name).  Devices of other sites stay with the centre they are cabled to."""
    members = set(keys)
    near: dict[str, set[str]] = {k: set() for k in members}
    for conn in graph.connections:
        if conn.kind not in graph.hidden_kinds and conn.a in members and conn.b in members and conn.a != conn.b:
            near[conn.a].add(conn.b)
            near[conn.b].add(conn.a)
    owner: dict[str, int] = {}
    frontier: list[str] = []
    for i, centre in enumerate(centres):
        for k in centre:
            owner[k] = i
            frontier.append(k)
    while frontier:
        votes: dict[str, dict[int, int]] = {}
        for k in frontier:
            for m in near[k]:
                if m not in owner:
                    votes.setdefault(m, {}).setdefault(owner[k], 0)
                    votes[m][owner[k]] += 1
        frontier = []
        for m in sorted(votes, key=lambda x: graph.nodes[x].hostname):
            owner[m] = sorted(votes[m], key=lambda i: (-votes[m][i], i))[0]
            frontier.append(m)
    out: list[list[str]] = [[] for _ in centres]
    for k in sorted(members, key=lambda x: graph.nodes[x].hostname):
        out[owner.get(k, 0)].append(k)
    return out


def _layered_many(graph: Graph, keys: list[str], x0: float, y0: float, ghosts: set[str], ghost_side: dict[str, int] | None,
                  centres: list[frozenset]) -> tuple[dict[str, L.Placed], float, float] | None:
    """Two or more centres on one page: each centre with its own zones is laid out as a page of its own (the biggest first, on the left), and the pages stand side by side; the cables between
    them (the interconnect) run across the gap."""
    centres = sorted(centres, key=lambda c: (-len(c), sorted(graph.nodes[k].hostname for k in c)[0]))
    parts = _split_by_centre(graph, keys, ghosts, centres)
    sizes = {i: len(part) for i, part in enumerate(parts)}
    order = sorted(range(len(parts)), key=lambda i: (-sizes[i], i))
    placed: dict[str, L.Placed] = {}
    x = x0
    height = 0.0
    any_zone = False
    for i in order:
        part = [k for k in parts[i]]
        sub_ghosts = ghosts & set(part)
        got = layered_zoned(graph, part, x, y0, sub_ghosts, ghost_side)
        if got is None:
            got = L.layered(graph, part, x, y0, ghosts=sub_ghosts, ghost_side=ghost_side)
        else:
            any_zone = True
        sub, width, h = got
        for key, p in sub.items():
            if p.zone_id:
                kind, _, rest = p.zone_id.partition(":")
                placed[key] = L.Placed(p.x, p.y, p.tier, p.box, p.depth, p.zone, f"{kind}:c{i}/{rest}")
            else:
                placed[key] = p
        x += width + MANY_GAP
        height = max(height, h)
    if not any_zone:
        return None
    return placed, x - MANY_GAP - x0, height


MANY_GAP = 420.0                   # free space between the pages of two centres (the interconnect and its port names run through it)


def layered_zoned(graph: Graph, keys: list[str], x0: float = 0, y0: float = 0, ghosts: set[str] | None = None,
                  ghost_side: dict[str, int] | None = None) -> tuple[dict[str, L.Placed], float, float] | None:
    ghosts = set(ghosts or ())
    centres = centres_on(graph, set(keys) - ghosts)
    if len(centres) >= 2:
        return _layered_many(graph, keys, x0, y0, ghosts, ghost_side, centres)
    found: ZonePlan | None = plan(graph, keys, ghosts, ghost_side)
    if found is None:
        return None
    centre_zone = Zone(key="core", head=found.centre, members=set(found.centre), ends=set(found.centre_ends), kind="core", title=CORE_TITLE)
    zones = [centre_zone] + found.zones
    owner = {k: z.key for z in zones for k in z.keys}
    key_of = {k: graph.nodes[k].hostname for k in owner}
    layouts: dict[str, tuple[dict[str, L.Placed], float, float]] = {}
    for z in zones:
        layouts[z.key] = _block(graph, z, set() if z.kind == "ghost" else ghosts, ghost_side)
    size = {k: (v[1], v[2]) for k, v in layouts.items()}
    weight = _links(graph, owner)
    top = [z for z in found.zones if z.kind == "external"]
    bottom = [z for z in found.zones if z.kind == "internal"]
    tall = [z for z in found.zones if z.kind == "tall"]
    foreign = [z for z in found.zones if z.kind == "ghost"]
    beside = [z for z in found.zones if z.kind in ("management", "other")]
    tall.sort(key=lambda z: (-weight["core"].get(z.key, 0), z.key))
    left: list[Zone] = []
    right: list[Zone] = []
    left_w = right_w = 0.0
    for z in tall:                                                  # the side with less width takes the next one
        if left_w <= right_w:
            left.append(z)
            left_w += size[z.key][0] + GAP_X
        else:
            right.append(z)
            right_w += size[z.key][0] + GAP_X
    mgmt = [z for z in beside if z.kind == "management"]
    other = [z for z in beside if z.kind == "other"]
    side_x = {z.key: -1e6 for z in left} | {z.key: 1e6 for z in right}
    centre_x = {"core": 0.0, **side_x}
    top = _order(top, size, weight, centre_x, key_of)
    bottom = _order(bottom, size, weight, centre_x, key_of)

    def assemble(top: list[Zone], bottom: list[Zone], left: list[Zone], right: list[Zone]):
        def row_width(items: list[Zone]) -> float:
            return sum(size[z.key][0] for z in items) + GAP_X * max(len(items) - 1, 0)
        bands_w = max(row_width(top), row_width(bottom), row_width(mgmt + [centre_zone] + other))
        inside_left, inside_right = _fit_inside(left, size, INSIDE_SHARE * bands_w), _fit_inside(right, size, INSIDE_SHARE * bands_w)
        left = [z for z in left if z not in inside_left]
        right = [z for z in right if z not in inside_right]
        core_row = inside_left + mgmt + [centre_zone] + other + inside_right
        width_c = max(bands_w, row_width(core_row))
        h_top = max((size[z.key][1] for z in top), default=0.0)
        h_core = max(size[z.key][1] for z in core_row)
        h_bottom = max((size[z.key][1] for z in bottom), default=0.0)
        y_core = h_top + (GAP_Y if top else 0.0)
        y_bottom = y_core + h_core + (GAP_Y if bottom else 0.0)
        left = [z for z in foreign if z.side < 0] + left             # the other site stands outside everything, on its side of the picture of all sites
        right = right + [z for z in foreign if z.side >= 0]
        left_cols = sum(size[z.key][0] for z in left) + GAP_X * max(len(left) - 1, 0)
        x_centre = (left_cols + SIDE_GAP if left else 0.0)
        spots: dict[str, tuple[float, float]] = {}
        x = 0.0
        def column_y(z: Zone) -> float:
            """A tall zone in a column at the side stands at the height of the core row (its lines to the core run level and short), not at the top of the page; a zone of another site keeps the top (its devices are lined up with ours afterwards)."""
            return 0.0 if z.kind == "ghost" else max(0.0, y_core + (h_core - size[z.key][1]) / 2)

        for z in left:
            spots[z.key] = (x, column_y(z))
            x += size[z.key][0] + GAP_X

        def band(items: list[Zone], y: float, align: str, h_band: float, start: float | None = None) -> None:
            start = x_centre + (width_c - row_width(items)) / 2 if start is None else start
            for z in items:
                h = size[z.key][1]
                spots[z.key] = (start, y + ((h_band - h) if align == "bottom" else 0.0))
                start += size[z.key][0] + GAP_X
        band(top, 0.0, "bottom", h_top)
        band(bottom, y_bottom, "top", h_bottom)
        band(core_row, y_core, "middle", h_core, _core_start(graph, layouts, spots, size, core_row, centre_zone, found.zones, x_centre, width_c, row_width(core_row), inside_left))
        x = x_centre + width_c + SIDE_GAP if right else x_centre + width_c
        for z in right:
            spots[z.key] = (x, column_y(z))
            x += size[z.key][0] + GAP_X
        placed: dict[str, L.Placed] = {}
        title_of = {z.key: z.title for z in zones}
        for z in zones:
            p_map, w, h = layouts[z.key]
            bx, by = spots[z.key]
            if z.key == "core":
                by += (h_core - h) / 2
            for key, p in p_map.items():
                placed[key] = L.Placed(p.x + bx + PAD + x0, p.y + by + PAD + TITLE + y0, p.tier, p.box, p.depth, title_of[z.key], f"{z.kind}:{z.key}")
        width = max(spots[z.key][0] + size[z.key][0] for z in zones) + PAD
        height = max(spots[z.key][1] + size[z.key][1] for z in zones) + PAD
        for z in foreign:                                           # the other site stands in the rows of the devices of this site that it is cabled to (its edge pair beside our edge pair)
            _align_ghosts(graph, z, placed, {k for g in foreign for k in g.keys}, y0)
            height = max(height, max(placed[k].y for k in z.keys) + L.NODE_H + 40 + PAD - y0)
        return placed, width, height

    state = (top, bottom, left, right)
    best = assemble(*state)
    best_cost = _crossings(graph, best[0], {k: z for k, z in owner.items()})
    tries = 0
    improved = True
    while improved and tries < MOVES and best_cost > 0:
        improved = False
        for candidate in _neighbours(state):
            tries += 1
            trial = assemble(*candidate)
            cost = _crossings(graph, trial[0], owner) + 0.00001 * trial[1] * 0 + 0.0
            if cost < best_cost:
                best, best_cost, state, improved = trial, cost, candidate, True
                break
            if tries >= MOVES:
                break
    return best


def _neighbours(state):
    """The orders one step away: two neighbours of a band swapped, a tall block on the other side."""
    top, bottom, left, right = state
    for index, band in enumerate((top, bottom)):
        for i in range(len(band) - 1):
            swapped = list(band)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            yield (swapped, bottom, left, right) if index == 0 else (top, swapped, left, right)
    for z in left:
        yield (top, bottom, [x for x in left if x is not z], right + [z])
    for z in right:
        yield (top, bottom, left + [z], [x for x in right if x is not z])


def _align_ghosts(graph: Graph, zone: Zone, placed: dict[str, L.Placed], foreign: set[str], y0: float) -> float:
    """Move the block of another site up or down until its devices that are cabled to this site stand at the mean height of the devices they are cabled to.  Returns the shift."""
    here: list[float] = []
    there: list[float] = []
    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds:
            continue
        for ghost, local in ((conn.a, conn.b), (conn.b, conn.a)):
            if ghost in zone.keys and local in placed and local not in foreign:
                here.append(placed[ghost].y)
                there.append(placed[local].y)
    if not here:
        return 0.0
    shift = sum(there) / len(there) - sum(here) / len(here)
    floor = y0 + PAD + TITLE
    top = min(placed[k].y for k in zone.keys)
    if top + shift < floor:
        shift = floor - top
    for k in zone.keys:
        p = placed[k]
        placed[k] = L.Placed(p.x, p.y + shift, p.tier, p.box, p.depth, p.zone, p.zone_id)
    return shift

