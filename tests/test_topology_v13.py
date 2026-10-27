"""Topology Builder 1.3: switches stand over their frames of end points so the lines of one switch never run on the lines of another, a very large site keeps the small
ones in one column, lines keep out of frames that are not theirs, and the page width stays bounded.  Synthetic captures only."""

from __future__ import annotations

import random
from collections import defaultdict

from features.topology import scene
from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.layout import NODE_H, NODE_W
from features.topology.scene import _arrange_groups, _detour, _frames, build_pages


def _graph(rng: random.Random) -> Graph:
    """One core, 2 to 6 access switches under it with 0 to 45 end points each, and sometimes end points on the core itself."""
    nodes = {"CORE": Device(key="CORE", hostname="CORE", captured=True, role_hint="core")}
    conns = []
    for s in range(rng.choice([2, 3, 4, 5, 6])):
        sw = f"SW-{s}"
        nodes[sw] = Device(key=sw, hostname=sw, captured=True, role_hint="access")
        conns.append(Connection("CORE", sw, [Link("CORE", f"Po{s}", sw, "Po1", "confirmed", {"CDP"}, "")]))
        for i in range(rng.choice([0, 1, 2, 4, 10, 25, 45])):
            key = f"{sw}-E{i}"
            nodes[key] = Device(key=key, hostname=key, captured=False, role_hint=rng.choice(["ap", "phone", "pc"]))
            conns.append(Connection(sw, key, [Link(sw, f"Gi1/0/{i}", key, "Gi0", "confirmed", {"CDP"}, "")]))
    for i in range(rng.choice([0, 0, 5, 30])):
        key = f"CORE-E{i}"
        nodes[key] = Device(key=key, hostname=key, captured=False, role_hint="pc")
        conns.append(Connection("CORE", key, [Link("CORE", f"Gi2/0/{i}", key, "Gi0", "confirmed", {"CDP"}, "")]))
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set(), group_endpoints=True)


def _segments(page, graph):
    """(line index, source switch, from, to) of every segment of every routed line, from the device centre to the device centre."""
    centre = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}
    out = []
    for index, conn in enumerate(page.connections):
        route = page.routes.get(index)
        if not route or len(route) < 4:
            continue
        source = conn.a if "-E" not in conn.a and graph.nodes[conn.a].captured else conn.b
        points = [centre[conn.a], *route, centre[conn.b]]
        out += [(index, source, p, q) for p, q in zip(points, points[1:])]
    return out


def _overlaps(segments) -> int:
    """Collinear stretches (longer than 6 px) shared by segments of two different switches."""
    count = 0
    for n, (i, si, p, q) in enumerate(segments):
        for j, sj, r, s in segments[n + 1:]:
            if si == sj or i == j:
                continue
            if abs(p[0] - q[0]) < .5 and abs(r[0] - s[0]) < .5 and abs(p[0] - r[0]) < 2.0:
                lo, hi = max(min(p[1], q[1]), min(r[1], s[1])), min(max(p[1], q[1]), max(r[1], s[1]))
            elif abs(p[1] - q[1]) < .5 and abs(r[1] - s[1]) < .5 and abs(p[1] - r[1]) < 2.0:
                lo, hi = max(min(p[0], q[0]), min(r[0], s[0])), min(max(p[0], q[0]), max(r[0], s[0]))
            else:
                continue
            count += hi - lo > 6
    return count


def _in_foreign_frames(page, graph, segments) -> int:
    count = 0
    for _, source, p, q in segments:
        for name, x, y, w, h in page.end_boxes:
            if name == source or graph.nodes[source].hostname in name:
                continue
            if max(p[0], q[0]) > x + 2 and min(p[0], q[0]) < x + w - 2 and max(p[1], q[1]) > y + 2 and min(p[1], q[1]) < y + h - 2:
                count += 1
                break
    return count


def test_lines_of_different_switches_never_run_on_each_other_and_never_cross_a_foreign_frame():
    pages = 0
    for seed in range(24):
        graph = _graph(random.Random(seed))
        for page in build_pages(graph):
            segments = _segments(page, graph)
            assert _overlaps(segments) == 0, (seed, page.name)
            assert _in_foreign_frames(page, graph, segments) == 0, (seed, page.name)
            pages += bool(segments)
    assert pages >= 20


def test_a_switch_stands_over_the_middle_of_its_frame_of_end_points_or_since_1_4_over_one_of_the_two_middle_columns_of_an_even_grid():
    seen = middle = 0
    for seed in range(24):
        graph = _graph(random.Random(seed))
        page = build_pages(graph)[0]
        for owner, (rect, kids) in _frames(page).items():
            if owner not in page.nodes:
                continue
            top = min(page.nodes[k].y for k in kids)
            xs = sorted(round(page.nodes[k].x, 1) for k in kids if page.nodes[k].y == top)                       # the first line of the grid: full columns
            pitch = min((b - a for a, b in zip(xs, xs[1:])), default=0.0)
            off = abs(page.nodes[owner].x + NODE_W / 2 - (rect[0] + rect[2]) / 2)
            assert off < 1.0 or abs(off - pitch / 2) < 1.0, (seed, owner, off, pitch)
            seen += 1
            if off >= 1.0:                                                # the switch stands exactly over a column, so that column has no hooks
                assert any(abs(page.nodes[k].x - page.nodes[owner].x) < 1.0 for k in kids), (seed, owner)
                middle += 1
    assert seen >= 30 and middle >= 5


def test_the_page_width_is_set_by_its_widest_row_and_does_not_drift_with_the_centring():
    for seed in range(24):
        page = build_pages(_graph(random.Random(seed)))[0]
        rows: dict[int, int] = defaultdict(int)
        for placed in page.nodes.values():
            rows[round(placed.y)] += 1
        frames = sum(rect[2] - rect[0] for rect, _ in _frames(page).values())
        assert page.width <= 250 * max(rows.values()) + frames + 2000, (seed, page.width)


def test_the_same_capture_gives_the_same_pages_every_time():
    def shape(graph):
        return [(page.name, round(page.width), round(page.height), sorted((k, round(p.x), round(p.y)) for k, p in page.nodes.items()),
                 sorted((i, [(round(x), round(y)) for x, y in r]) for i, r in page.routes.items())) for page in build_pages(graph)]
    assert shape(_graph(random.Random(5))) == shape(_graph(random.Random(5)))


def _site(prefix: str, count: int) -> dict[str, Device]:
    return {f"{prefix}-SW{i}": Device(key=f"{prefix}-SW{i}", hostname=f"{prefix}-SW{i}", captured=True, role_hint="access") for i in range(count)}


def _sites_graph(links: dict[tuple[str, str], int], sizes: dict[str, int]) -> tuple[Graph, dict[str, list[str]]]:
    nodes: dict[str, Device] = {}
    groups = {}
    for name, count in sizes.items():
        found = _site(name, count)
        nodes.update(found)
        groups[name] = list(found)
    conns = []
    for (a, b), n in links.items():
        for i in range(n):
            x, y = f"{a}-SW{i}", f"{b}-SW{i}"
            conns.append(Connection(x, y, [Link(x, f"Gi0/{i}", y, "Gi0/1", "confirmed", {"CDP"}, "")]))
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set()), groups


def test_a_very_large_site_keeps_the_small_ones_in_one_column_ordered_by_their_links():
    graph, groups = _sites_graph({("BIG", "S1"): 1, ("BIG", "S2"): 3, ("BIG", "S3"): 2, ("S2", "S3"): 1}, {"BIG": 20, "S1": 1, "S2": 2, "S3": 2})
    nodes, boxes, width, height = _arrange_groups(graph, groups)
    where = {name: (x, y, w, h) for name, x, y, w, h in boxes}
    assert where["BIG"][:2] == (0.0, 0.0)
    column = {where[n][0] for n in ("S1", "S2", "S3")}
    assert len(column) == 1 and min(column) >= where["BIG"][2]                                # one column, right of the big site
    order = sorted(("S1", "S2", "S3"), key=lambda n: where[n][1])
    assert order[0] == "S2" and order[1] == "S3"                                              # the most linked to BIG first, then the one linked most to it
    for a, b in zip(order, order[1:]):
        assert where[a][1] + where[a][3] <= where[b][1]                                       # no overlap
    assert width >= max(where[n][0] + where[n][2] for n in order) - 200 and height >= where[order[-1]][1] + where[order[-1]][3] - 200
    assert len(nodes) == 25


def test_sites_of_similar_size_stay_in_the_grid_round_the_busiest_one():
    graph, groups = _sites_graph({("A", "B"): 2, ("A", "C"): 1, ("A", "D"): 1, ("A", "E"): 1}, {"A": 3, "B": 3, "C": 3, "D": 3, "E": 3})
    _, boxes, _, _ = _arrange_groups(graph, groups)
    where = {name: (x, y) for name, x, y, _, _ in boxes}
    assert len({y for _, y in where.values()}) > 1 and len({x for x, _ in where.values()}) > 1


def test_a_detour_goes_round_an_obstacle_with_the_first_lift_that_clears_it_and_gives_up_when_none_does():
    a, b = (0.0, 0.0), (1000.0, 0.0)
    block = [(400.0, -40.0, 600.0, 40.0)]
    found = _detour(a, b, (1.0, 0.0), (0.0, 1.0), 0.0, True, [0.0, 70, -70, 140, -140], block)
    assert found is not None and len(found) == 2 and abs(found[0][1]) in (70.0, 140.0) and found[0][1] == found[1][1]
    assert not any(scene._hits(p, q, block) for p, q in zip([a, *found], [*found, b]))
    wall = [(400.0, -5000.0, 600.0, 5000.0)]
    assert _detour(a, b, (1.0, 0.0), (0.0, 1.0), 0.0, True, [0.0, 70, -70, 140, -140], wall) is None


def test_the_version_is_at_least_1_3():
    from core.modules import TOOLS
    assert tuple(int(n) for n in next(t for t in TOOLS if t.key == "topology").version.split(".")) >= (1, 3)
