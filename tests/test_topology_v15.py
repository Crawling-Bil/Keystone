"""Topology Builder 1.5: access points framed under their switch whatever the end-point option says, devices with no link stand apart from the linked ones,
linked devices of a row stand side by side, comb lanes of two switches never lie on each other.  Synthetic captures only."""

from __future__ import annotations

from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.layout import NODE_W, box_groups, framed_roles
from features.topology.scene import Page, build_pages


def _link(a: str, b: str, port: str = "Gi1") -> Connection:
    return Connection(a, b, [Link(a, port, b, "Gi0", "confirmed", {"CDP"}, "")])


def _switch_with(roles: dict[str, int], group_endpoints: bool, group_aps: bool) -> Graph:
    """One core, one access switch and ``roles[role]`` uncaptured end points of each role under the access switch."""
    nodes = {"CORE": Device(key="CORE", hostname="CORE", captured=True, role_hint="core"), "SW": Device(key="SW", hostname="SW", captured=True, role_hint="access")}
    conns = [_link("CORE", "SW", "Po1")]
    for role, count in roles.items():
        for i in range(count):
            key = f"{role.upper()}-{i + 1}"
            nodes[key] = Device(key=key, hostname=key, captured=False, role_hint=role)
            conns.append(_link("SW", key, f"Gi1/0/{len(nodes)}"))
    graph = Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set())
    graph.group_endpoints, graph.group_aps = group_endpoints, group_aps
    return graph


def test_access_points_drawn_one_by_one_are_framed_even_when_the_end_point_option_is_off():
    graph = _switch_with({"ap": 6, "phone": 5}, group_endpoints=False, group_aps=True)
    assert framed_roles(graph) == ("ap",)
    page = build_pages(graph)[0]
    assert [b[0] for b in page.end_boxes] == ["SW"]
    framed = {k for k, p in page.nodes.items() if p.box}
    assert framed == {f"AP-{i}" for i in range(1, 7)}                           # the phones stay unframed


def test_nothing_is_framed_when_both_options_are_off_and_everything_when_the_end_point_option_is_on():
    assert build_pages(_switch_with({"ap": 6, "phone": 5}, False, False))[0].end_boxes == []
    page = build_pages(_switch_with({"ap": 6, "phone": 5}, True, True))[0]
    assert {k for k, p in page.nodes.items() if p.box} == {f"AP-{i}" for i in range(1, 7)} | {f"PHONE-{i}" for i in range(1, 6)}


def test_the_service_frames_access_points_unless_they_are_collapsed():
    from features.topology import service
    from tests.topology_samples import nxos_capture
    files = [("SW-1.txt", nxos_capture("SW-1", "FDO00000001", "10.0.0.1", []))]
    for collapse_aps, expect in ((False, True), (True, False)):
        graph = service.build_topology(files, collapse_endpoints=False, collapse_aps=collapse_aps, group_endpoints=False)["graph"]
        assert graph.group_aps is expect and graph.group_endpoints is False


def _row(names: list[str], links: list[tuple[str, str]]) -> Graph:
    nodes = {"CORE": Device(key="CORE", hostname="CORE", captured=True, role_hint="core")}
    conns = []
    for name in names:
        nodes[name] = Device(key=name, hostname=name, captured=True, role_hint="access")
        conns.append(_link("CORE", name, f"Gi/{name}"))
    conns += [_link(a, b, "Gi9") for a, b in links]
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set())


def test_a_switch_with_no_link_at_all_stands_at_the_end_of_its_row_and_not_between_two_linked_ones():
    graph = _row(["SW-A", "SW-M", "SW-Z"], [("SW-A", "SW-Z")])
    del graph.nodes["CORE"]                                                      # nothing above: the three switches share a row and SW-M is linked to nothing
    graph.connections = [c for c in graph.connections if "CORE" not in (c.a, c.b)]
    page = build_pages(graph)[0]
    order = sorted(page.nodes, key=lambda k: page.nodes[k].x)
    assert order == ["SW-A", "SW-Z", "SW-M"]
    assert page.nodes["SW-M"].x - page.nodes["SW-Z"].x > 1.5 * (page.nodes["SW-Z"].x - page.nodes["SW-A"].x)       # and a little apart
    assert not page.routes                                                       # the link A - Z is a straight line: nothing stands in its way


def test_devices_of_a_row_that_are_linked_to_each_other_stand_side_by_side():
    graph = _row([f"SW-{i}" for i in range(1, 7)], [("SW-1", "SW-5"), ("SW-2", "SW-6")])
    page = build_pages(graph)[0]
    order = sorted((k for k in page.nodes if k != "CORE"), key=lambda k: page.nodes[k].x)
    assert order == ["SW-1", "SW-5", "SW-2", "SW-6", "SW-3", "SW-4"]
    side = [i for i, c in enumerate(page.connections) if c.a.startswith("SW") and c.b.startswith("SW")]
    assert all(i not in page.routes for i in side)                               # no line has to go over a device


def test_two_comb_lanes_of_different_switches_at_one_height_are_moved_apart():
    from features.topology.layout import Placed
    from features.topology.scene import LANE_NUDGE, _centre, _separate_lanes
    page = Page("T", {"A": Placed(0, 0, 0.0, ""), "B": Placed(900, 0, 0.0, ""), "E1": Placed(100, 500, 1.0, "A"), "E2": Placed(500, 500, 1.0, "B")})
    page.connections = [_link("A", "E1"), _link("B", "E2")]
    page.routes = {0: [(80.0, 6.0), (110.0, 6.0), (110.0, 400.0), (400.0, 400.0), (400.0, 450.0)], 1: [(860.0, 6.0), (800.0, 6.0), (800.0, 400.0), (200.0, 400.0), (200.0, 450.0)]}
    page.comb_source = {0: "A", 1: "B"}
    _separate_lanes(page, {k: _centre(p) for k, p in page.nodes.items()})
    y0 = {i: next(y for (x0, y), (x1, y1) in zip(r, r[1:]) if y == y1 and abs(x0 - x1) > 100) for i, r in page.routes.items()}
    assert abs(y0[0] - y0[1]) >= LANE_NUDGE - 0.1
    assert all(abs(a[0] - b[0]) < 0.5 or abs(a[1] - b[1]) < 0.5 for r in page.routes.values() for a, b in zip(r, r[1:]))      # still orthogonal
