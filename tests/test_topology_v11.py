"""Topology Builder 1.1: comb lines keep their direction (no more triangles in draw.io), never turn back on their lane, and reach the rows below a switch."""

from __future__ import annotations

import math
import random
import xml.etree.ElementTree as ET

from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.layout import NODE_H, NODE_W


def _graph(flip, count: int = 18, switches: int = 1, with_core: bool = True) -> Graph:
    """Access switches under one core, each with ``count`` access points; ``flip(i)`` writes the line of end point i as end point -> switch."""
    nodes = {"CORE": Device(key="CORE", hostname="CORE", captured=True, role_hint="core")}
    conns = []
    for s in range(switches):
        sw = f"SW-{s}"
        nodes[sw] = Device(key=sw, hostname=sw, captured=True, role_hint="access")
        conns.append(Connection("CORE", sw, [Link("CORE", f"Po{s}", sw, "Po1", "confirmed", {"CDP"}, "")]))
        for i in range(count):
            key = f"{sw}-E{i + 1}"
            nodes[key] = Device(key=key, hostname=key, captured=False, role_hint="ap")
            if flip(i):
                conns.append(Connection(key, sw, [Link(key, "Gi0", sw, f"Gi1/0/{i + 1}", "confirmed", {"CDP"}, "")]))
            else:
                conns.append(Connection(sw, key, [Link(sw, f"Gi1/0/{i + 1}", key, "Gi0", "confirmed", {"CDP"}, "")]))
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set(), group_endpoints=True)


def _centres(page) -> dict[str, tuple[float, float]]:
    return {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}


def _combed(page):
    """(index, connection, switch key, path from the switch to the end point) for every line the comb routed."""
    centres = _centres(page)
    for index, conn in enumerate(page.connections):
        route = page.routes.get(index)
        if not route or len(route) < 3 or "-E" not in conn.a + conn.b:
            continue
        switch = conn.b if "-E" in conn.a else conn.a
        full = [centres[conn.a], *route, centres[conn.b]]
        yield index, conn, switch, (full if switch == conn.a else full[::-1])


def test_a_route_runs_from_the_first_end_of_its_line_to_the_second_end_whichever_way_the_line_is_written():
    from features.topology.scene import build_pages
    for flip in (lambda i: False, lambda i: True, lambda i: i % 2 == 0, lambda i: i % 3 == 0):
        page = build_pages(_graph(flip, count=22))[0]
        centres = _centres(page)
        seen = 0
        for _, conn, switch, path in _combed(page):
            seen += 1
            route = path[1:-1]
            assert math.dist(route[0], centres[switch]) < math.dist(route[-1], centres[switch]), conn
        assert seen >= 15


def test_the_first_waypoint_of_a_line_written_end_point_first_lies_beside_the_end_point_in_drawio():
    """The triangle: a line written 'access point - switch' was stored switch -> access point, so draw.io drew it to the far lane and back."""
    from features.topology.drawio import to_drawio
    from features.topology.scene import build_pages
    graph = _graph(lambda i: True, count=20)
    pages = build_pages(graph)
    root = ET.fromstring(to_drawio(graph, pages=pages))
    centre = {}
    for obj in root.iter("object"):
        geo = obj.find("mxCell/mxGeometry")
        if geo is not None and geo.get("width"):
            centre[obj.get("id")] = (float(geo.get("x")) + float(geo.get("width")) / 2, float(geo.get("y")) + float(geo.get("height")) / 2)
    checked = 0
    for cell in root.iter("mxCell"):
        if cell.get("edge") != "1" or cell.get("source") not in centre or cell.get("target") not in centre:
            continue
        points = [(float(p.get("x")), float(p.get("y"))) for p in cell.iter("mxPoint")]
        if len(points) < 4:
            continue
        checked += 1
        source = centre[cell.get("source")]
        assert math.dist(points[0], source) < math.dist(points[-1], source), cell.get("source")
    assert checked >= 10


def test_no_comb_line_goes_back_up_or_turns_back_on_its_lane():
    from features.topology.scene import build_pages
    for seed in range(40):
        rng = random.Random(seed)
        graph = _graph(lambda i, r=rng: r.random() < 0.5, count=rng.randint(3, 40), switches=rng.choice([1, 2, 3]))
        for page in build_pages(graph):
            for _, conn, _, path in _combed(page):
                assert all(b[1] >= a[1] - 1 for a, b in zip(path, path[1:])), (seed, conn)             # never up
                runs = [b[0] - a[0] for a, b in zip(path[:-1], path[1:-1]) if abs(b[0] - a[0]) > 1]       # sideways moves up to the end point's own stub
                assert all(u * v > 0 for u, v in zip(runs, runs[1:])), (seed, conn)                       # always the same way



def test_an_end_point_in_the_rows_below_the_first_one_under_a_switch_gets_its_own_drop_and_a_short_stub():
    from features.topology.scene import build_pages
    page = build_pages(_graph(lambda i: i % 2 == 0, count=17))[0]
    sx = _centres(page)["SW-0"][0]
    below = [(conn, path) for _, conn, _, path in _combed(page) if abs(path[-1][0] - sx) < 6]
    assert below, "the rows under the switch use a drop of their own"
    for conn, path in below:
        assert len(path) == 5                                           # switch, icon edge, beside the icon, the drop, the end point
        assert all(abs(a[0] - b[0]) < 0.5 or abs(a[1] - b[1]) < 0.5 for a, b in zip(path[1:], path[2:]))
        assert 56 <= abs(path[-2][0] - sx) <= 120                       # clear of the names, close to the column


def test_two_stubs_on_one_row_beside_one_gap_never_look_like_one_line():
    """Two end points side by side must not be joined by two stubs that meet in the gap between them: it would read as a link between the two."""
    from features.topology.scene import build_pages
    for flip in (lambda i: False, lambda i: i % 2 == 0):
        page = build_pages(_graph(flip, count=26))[0]
        rows: dict[int, list[tuple[float, float]]] = {}
        for _, _, _, path in _combed(page):
            if len(path) >= 5 and abs(path[-2][1] - path[-1][1]) < 0.5:
                rows.setdefault(round(path[-1][1]), []).append((min(path[-2][0], path[-1][0]), max(path[-2][0], path[-1][0])))      # the stub into the end point
        assert rows
        for y, stubs in rows.items():
            for n, (a0, a1) in enumerate(stubs):
                for b0, b1 in stubs[n + 1:]:
                    assert not (a0 < b1 and b0 < a1), (y, (a0, a1), (b0, b1))                   # no two stubs on one row overlap
                    assert min(abs(a1 - b0), abs(b1 - a0)) >= 20, (y, (a0, a1), (b0, b1))       # and a clear gap lies between two stubs


def test_a_line_never_crosses_back_over_the_centre_of_its_switch():
    from features.topology.scene import build_pages
    page = build_pages(_graph(lambda i: False, count=9))[0]
    sx = _centres(page)["SW-0"][0]
    for _, conn, _, path in _combed(page):
        side = 1 if path[1][0] > sx else -1
        assert all(side * (p[0] - sx) >= -6 for p in path[1:]), conn
