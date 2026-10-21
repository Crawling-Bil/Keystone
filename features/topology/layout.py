"""Layered layout: one row per tier, nodes of a tier in natural name order (A-Z, 0-9) left to right, what hangs off one device grouped under it and uplink-only devices over what they serve, vPC / stack peers side by side."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .graph import Graph
from .roles import tier_of

NODE_W, NODE_H = 76, 76          # icon size (as in the sample diagrams)
X_STEP, Y_STEP = 230, 250        # label room between icons
X_MAX = 300                      # widest step a long hostname may ask for
SUB_STEP = 175                   # distance between the staggered lines of one long row of endpoints
WRAP_MIN = 12                    # a row of endpoints shorter than this is never cut
Y_EXTRA_MAX = 260              # most extra height a row gap gets for its lines
MARGIN = 80
PREFIX_WORDS = {"prefix1": 1, "prefix2": 2, "prefix3": 3}     # grouping modes and how many leading hostname words name the group


@dataclass
class Placed:
    x: float
    y: float
    tier: int


def natural_key(name: str, tie: str = "") -> tuple:
    """Sort key for hostnames: case-insensitive, letters (A-Z) before numbers (0-9) at the same position, digit runs compare as numbers (SW-2 before SW-10)."""
    parts = re.findall(r"\d+|\D", name.upper())            # one character per non-digit, one number per digit run
    return tuple((1, int(p), "") if p.isdigit() else (0, 0, p) for p in parts), tie


def layered(graph: Graph, keys: list[str], x0: float = 0, y0: float = 0) -> tuple[dict[str, Placed], float, float]:
    """Place ``keys`` (a subset of graph nodes). Returns positions plus the width and height used."""
    members = set(keys)
    tier_value = _tier_values(graph, keys)
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
    spot = _arrange(graph, rows, order, neighbours, pairs, parts)      # x of every node, in icon steps
    xstep = _x_step(graph, keys)
    gaps = _gaps(graph, keys, order, rows)
    lo, hi = min(spot.values(), default=0), max(spot.values(), default=0)
    placed: dict[str, Placed] = {}
    y = y0 + MARGIN
    for line, tier in enumerate(order):
        lines = parts[tier]
        for i, key in enumerate(rows[tier]):
            placed[key] = Placed(x0 + MARGIN + (spot[key] - lo) * xstep, y + (i % lines) * SUB_STEP, tier)
        y += (lines - 1) * SUB_STEP + gaps[line]
    last_gap = gaps[-1] if gaps else Y_STEP
    width = MARGIN * 2 + (hi - lo) * xstep + NODE_W
    height = (y - last_gap) - y0 + NODE_H + 40 + MARGIN
    return placed, width, height


def _name_key(graph: Graph, key: str) -> tuple:
    return natural_key(graph.nodes[key].hostname if key in graph.nodes else key, key)


def _parts(count: int, tier: float, core: int) -> int:
    """A long row of endpoints (a hundred access points) is dealt out over several staggered lines (every n-th device on one line)
    so the picture does not grow ten metres wide; the order along x stays the order of the row."""
    if tier < 4 or count <= WRAP_MIN:
        return 1
    cap = max(WRAP_MIN, int(core * 1.3) + 1)
    return 1 if count <= cap else -(-count // cap)


def _arrange(graph: Graph, rows: dict[float, list[str]], order: list[float], neighbours: dict[str, set[str]],
             pairs: set[frozenset], parts: dict[float, int]) -> dict[str, float]:
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
        rows[tier] = _keep_pairs_together(_reorder(graph, rows[tier], neighbours, spot, known, stubs_only=True)[0], pairs)
        spot.update(uniform(rows[tier], 1 / parts[tier]))
    for index, tier in enumerate(order):                              # 2. top-down
        gap = 1 / parts[tier]
        want: dict[str, float] = {}
        if index:
            known = {k for t in order[:index] for k in rows[t]}
            row, want = _reorder(graph, rows[tier], neighbours, spot, known, gap)
            rows[tier] = _keep_pairs_together(row, pairs)
        spot.update(_spread(rows[tier], want, gap))
    return spot


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


def _spread(row: list[str], want: dict[str, float], gap: float) -> dict[str, float]:
    """x of every device of a row: as near to the wanted x as possible, never closer than ``gap`` to the one before it
    (isotonic regression on x - i*gap, so the order never changes)."""
    n = len(row)
    wished: list[float | None] = [want.get(k) for k in row]
    if all(w is None for w in wished):
        return {k: (i - (n - 1) / 2) * gap for i, k in enumerate(row)}
    for i in range(1, n):                                             # a device with no wish follows the one before it
        if wished[i] is None and wished[i - 1] is not None:
            wished[i] = wished[i - 1] + gap
    for i in range(n - 2, -1, -1):
        if wished[i] is None and wished[i + 1] is not None:
            wished[i] = wished[i + 1] - gap
    blocks: list[list[float]] = []                                    # [sum, count] of runs that must share one level
    for i, w in enumerate(wished):
        blocks.append([w - i * gap, 1])                               # type: ignore[operator]
        while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
            total, count = blocks.pop()
            blocks[-1][0] += total
            blocks[-1][1] += count
    out: dict[str, float] = {}
    i = 0
    for total, count in blocks:
        for _ in range(int(count)):
            out[row[i]] = total / count + i * gap
            i += 1
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
    return [Y_STEP + min(Y_EXTRA_MAX, max(0, count - 8) * 7) for count in crossing]


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
    for key in keys:
        node = graph.nodes[key]
        if node.role_hint == "segment":
            continue
        base = value[key]
        if node.captured or base >= 4 or not near[key]:
            continue
        peers = [m for m in near[key] if graph.nodes[m].role_hint not in ("ap", "phone", "host", "server")]
        if peers and all(value[m] >= base for m in peers) and any(value[m] == base and frozenset((key, m)) not in pairs for m in peers):
            if any(value[n] < base for m in peers for n in near[m] if n != key):
                value[key] = base + 0.5
    return value


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


def groups_of(graph: Graph, mode: str) -> dict[str, list[str]]:
    """Group node keys by 'none' | 'prefix1' | 'prefix2' | 'prefix3' (leading hostname words)."""
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
        parts = node.hostname.replace("_", "-").split("-")
        name = "-".join(parts[:take]) if len(parts) > take else node.hostname
        groups.setdefault(name, []).append(key)
    # a "site" made only of devices that nobody captured (a firewall, a server, a stray MAC name) is not a site
    other = [k for name, keys in list(groups.items()) if all(not graph.nodes[k].captured for k in keys) for k in groups.pop(name)]
    if other:
        groups.setdefault("Other devices", []).extend(other)
    return groups
