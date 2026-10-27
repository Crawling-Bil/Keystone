"""Topology Builder 1.4: no end-point line hooks round its column, lines of two switches into one device do not share their last run, the read captures stay cached.
Synthetic captures only."""

from __future__ import annotations

import random

from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.layout import NODE_H, NODE_W
from features.topology.scene import build_pages
from tests.test_topology_v13 import _graph, _segments, _overlaps


def test_no_end_point_line_of_a_random_frame_hooks_round_the_outside_of_its_column():
    lines = 0
    for seed in range(24):
        graph = _graph(random.Random(seed))
        for page in build_pages(graph):
            centre = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}
            for index, conn in enumerate(page.connections):
                route = page.routes.get(index)
                if not route or len(route) < 4 or "-E" not in conn.a + conn.b:
                    continue
                switch, end = (conn.a, conn.b) if "-E" in conn.b else (conn.b, conn.a)
                dx = centre[end][0] - centre[switch][0]
                if abs(dx) < 6:
                    continue
                lines += 1
                side = 1 if dx > 0 else -1
                assert not any(side * (x - centre[end][0]) > 20 for x, _ in route), (seed, conn.a, conn.b)
    assert lines >= 300


def _dual_homed(count: int = 12) -> Graph:
    """Two access switches under one core, each with a frame of end points, and one access point that both switches report."""
    nodes = {"CORE": Device(key="CORE", hostname="CORE", captured=True, role_hint="core")}
    conns = []
    for s in range(2):
        sw = f"SW-{s}"
        nodes[sw] = Device(key=sw, hostname=sw, captured=True, role_hint="access")
        conns.append(Connection("CORE", sw, [Link("CORE", f"Po{s}", sw, "Po1", "confirmed", {"CDP"}, "")]))
        for i in range(count):
            key = f"{sw}-E{i}"
            nodes[key] = Device(key=key, hostname=key, captured=False, role_hint="ap")
            conns.append(Connection(sw, key, [Link(sw, f"Gi1/0/{i}", key, "Gi0", "confirmed", {"CDP"}, "")]))
    conns.append(Connection("SW-1", "SW-0-E0", [Link("SW-1", "Gi1/0/40", "SW-0-E0", "Gi1", "confirmed", {"CDP"}, "")]))
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set(), group_endpoints=True)


def test_two_switches_that_both_see_one_access_point_do_not_share_the_last_stretch_of_their_lines():
    graph = _dual_homed()
    page = build_pages(graph)[0]
    assert _overlaps(_segments(page, graph)) == 0


def test_a_second_line_that_arrives_along_the_run_of_the_first_moves_its_last_corner_sideways():
    from features.topology.layout import Placed
    from features.topology.scene import APPROACH_STEP, Page, _centre, _untangle_approaches
    page = Page("T", {"A": Placed(0, 0, 0.0, ""), "B": Placed(1000, 0, 0.0, ""), "E": Placed(500 - NODE_W / 2, 600, 1.0, "")})
    page.connections = [Connection("A", "E", [Link("A", "1", "E", "1", "confirmed", {"CDP"}, "")]), Connection("B", "E", [Link("B", "1", "E", "2", "confirmed", {"CDP"}, "")])]
    x = 500.0
    page.routes = {0: [(100.0, 300.0), (x, 300.0)], 1: [(900.0, 300.0), (x, 300.0)]}
    page.comb_source = {0: "A"}
    centres = {k: _centre(p) for k, p in page.nodes.items()}
    _untangle_approaches(page, centres)
    assert page.routes[0][-1] == (x, 300.0)                                   # the comb line (or, failing that, the first) keeps the run
    assert page.routes[1][-1] == (x + APPROACH_STEP, 300.0) and page.routes[1][0] == (900.0, 300.0)


def test_the_captures_of_a_big_run_stay_cached_so_that_a_second_build_does_not_read_them_again():
    from features.topology import service
    assert service.CACHE_FILES >= 200


def test_the_version_is_at_least_1_4():
    from core.modules import TOOLS
    assert tuple(int(n) for n in next(t for t in TOOLS if t.key == "topology").version.split(".")) >= (1, 4)
