"""Topology Builder v49: neighbours that a switch lists on a port they are not plugged into (CDP flooded through a switch that does not speak CDP),
the name of an end-point frame kept off the lines, comb lines further apart, and two lines of different cables never laid over each other.
Synthetic data only: invented names, no real capture."""

from __future__ import annotations

import types

import pytest

from features.topology import scene, titles
from features.topology.extract import Device, mac_in_name
from features.topology.findings import build_findings
from features.topology.graph import Connection, Graph, Link, _connections
from features.topology.layout import NODE_H, NODE_W
from features.topology.scene import build_pages
from features.topology.through import apply


def _device(key: str, role: str, captured: bool = True) -> Device:
    return Device(key=key, hostname=key, captured=captured, role_hint=role)


def _graph(lldp_anchor: bool = True, aps: int = 3, ap_elsewhere: bool = False, anchor_role: str = "access", second_anchor: bool = False) -> Graph:
    """CISCO-SW sees, on Gi1/0/1, the switch HW-SW (LLDP and CDP) and ``aps`` access points that only HW-SW can reach (CDP only)."""
    nodes = {"CISCO-SW": _device("CISCO-SW", "core"), "HW-SW": _device("HW-SW", anchor_role, captured=False)}
    links = [Link("CISCO-SW", "Gi1/0/1", "HW-SW", "XGE0/0/1", "single", {"LLDP"} if lldp_anchor else {"CDP"}, "")]
    for n in range(aps):
        key = f"AP-{n}"
        nodes[key] = _device(key, "ap", captured=False)
        links.append(Link("CISCO-SW", "Gi1/0/1", key, "Eth0", "single", {"CDP"}, ""))
    if second_anchor:
        nodes["OTHER-SW"] = _device("OTHER-SW", "access", captured=False)
        links.append(Link("CISCO-SW", "Gi1/0/1", "OTHER-SW", "Gi0/1", "single", {"CDP"}, ""))
    if ap_elsewhere:
        links.append(Link("HW-SW", "GE0/0/5", "AP-0", "Eth0", "single", {"LLDP"}, ""))
    graph = Graph(nodes=nodes, links=links, hidden_kinds=set())
    _connections(graph)
    return graph


def _pairs(graph: Graph) -> set[frozenset]:
    return {frozenset((link.a, link.b)) for link in graph.links}


def test_end_points_that_only_cdp_reported_on_a_port_facing_a_switch_are_attached_to_that_switch():
    graph = _graph()
    issues = apply(graph)
    assert _pairs(graph) == {frozenset(("CISCO-SW", "HW-SW")), *(frozenset(("HW-SW", f"AP-{n}")) for n in range(3))}
    moved = [l for l in graph.links if l.note.startswith("seen through HW-SW")]
    assert len(moved) == 3 and all(l.state == "single" and "HW-SW" in (l.a, l.b) and "captured but" not in l.note for l in moved)
    assert issues == [{"type": "seen-through", "node": "CISCO-SW", "anchor": "HW-SW", "ports": ["Gi1/0/1"], "rehomed": ["AP-0", "AP-1", "AP-2"], "dropped": []}]
    assert all(len(c.links) == 1 for c in graph.connections)                       # connections were rebuilt


def test_an_end_point_that_is_plugged_in_somewhere_else_keeps_that_cable_and_loses_the_line_through_the_port():
    graph = _graph(ap_elsewhere=True)
    issues = apply(graph)
    assert frozenset(("CISCO-SW", "AP-0")) not in _pairs(graph) and frozenset(("HW-SW", "AP-0")) in _pairs(graph)
    assert issues[0]["dropped"] == ["AP-0"] and issues[0]["rehomed"] == ["AP-1", "AP-2"]
    assert not any(l.note.startswith("seen through") and "AP-0" in (l.a, l.b) for l in graph.links)


def test_without_lldp_the_one_network_device_on_the_port_is_the_real_neighbor():
    graph = _graph(lldp_anchor=False)
    apply(graph)
    assert frozenset(("HW-SW", "AP-1")) in _pairs(graph) and frozenset(("CISCO-SW", "AP-1")) not in _pairs(graph)


def test_two_network_devices_on_a_port_without_lldp_are_left_alone():
    graph = _graph(lldp_anchor=False, second_anchor=True)
    before = _pairs(graph)
    assert apply(graph) == [] and _pairs(graph) == before


def test_a_port_with_a_single_neighbor_or_only_network_devices_is_left_alone():
    graph = _graph(aps=0)
    assert apply(graph) == []
    graph = _graph(aps=0, second_anchor=True, lldp_anchor=False)
    assert apply(graph) == []


def test_an_access_point_cannot_be_the_real_neighbor_of_a_port_that_also_lists_a_switch():
    graph = _graph(anchor_role="ap")
    assert apply(graph) == []


def test_the_lldp_neighbor_wins_even_when_cdp_lists_another_switch_on_the_same_port():
    """A Cisco switch above a Huawei switch above another Cisco switch: CDP names the far switch on the near port, LLDP names the cable."""
    graph = _graph(aps=0, second_anchor=True)
    graph.links[0].protocols = {"LLDP", "CDP"}
    issues = apply(graph)
    assert frozenset(("HW-SW", "OTHER-SW")) in _pairs(graph) and frozenset(("CISCO-SW", "OTHER-SW")) not in _pairs(graph)
    assert issues and issues[0]["rehomed"] == ["OTHER-SW"]


def test_the_findings_say_what_was_seen_through_and_the_shared_name_rule_does_not_count_it_as_cables():
    graph = _graph(aps=8)
    graph.issues += apply(graph)
    rows = {f["id"]: f for f in build_findings(graph)}
    assert rows["TOPO-046"]["severity"] == "info" and rows["TOPO-046"]["devices"] == ["CISCO-SW", "HW-SW"]
    assert "8 neighbor(s) seen through HW-SW" in rows["TOPO-046"]["title"] and rows["TOPO-046"]["reference"].startswith("https://community.cisco.com/")
    assert "TOPO-045" not in rows                                                  # eight end points hang under one switch, not on eight cables of a shared name


@pytest.mark.parametrize("name,expected", [("NPOINT069F81027403", "069f81027403"), ("APAABBCCDDEEFF", "aabbccddeeff"), ("LAB-SW1", ""), ("069f.8102.7403", "")])
def test_a_name_that_ends_in_a_chassis_mac_gives_that_mac(name, expected):
    assert mac_in_name(name).lower().replace(".", "") == expected


def test_a_device_listed_under_its_mac_and_under_a_name_that_ends_in_that_mac_is_one_device():
    from features.topology.extract import HalfEdge
    from features.topology.graph import build

    def device(host: str, halves: list) -> Device:
        dev = _device(host, "core")
        dev.halves = halves
        return dev

    half_a = HalfEdge(local_port="Gi1/0/1", remote_name="NPOINT069F81027403", remote_port="Eth0", protocols={"CDP"})
    half_b = HalfEdge(local_port="Gi1/0/2", remote_name="069f.8102.7403", remote_port="Eth0", protocols={"LLDP"}, remote_chassis="069f81027403")
    graph = build([device("SW-A", [half_a]), device("SW-B", [half_b])])
    names = {n.hostname for n in graph.nodes.values() if not n.captured}
    assert len(names) == 1


# ---- the name of an end-point frame ---------------------------------------------------------------------------------------------------------------------------

def _page(routes: list[list[tuple[float, float]]], nodes: dict[str, tuple[float, float]]) -> types.SimpleNamespace:
    keys = list(nodes)
    conns = [types.SimpleNamespace(a=keys[0], b=keys[1]) for _ in routes]
    return types.SimpleNamespace(nodes={k: types.SimpleNamespace(x=x, y=y) for k, (x, y) in nodes.items()}, connections=conns, routes=dict(enumerate(routes)), pair_boxes={})


def test_the_frame_title_stays_at_the_corner_when_no_line_crosses_it():
    page = _page([[(500.0, 300.0), (500.0, 600.0)]], {"S": (400, 0), "E": (400, 900)})
    assert titles.end_title_spot(page, ("SW-A", 100.0, 200.0, 400.0, 300.0)) == titles.TITLE_LEFT


def test_the_frame_title_slides_to_a_gap_between_lines():
    lines = [[(120.0, 230.0), (120.0, 600.0)], [(200.0, 230.0), (200.0, 600.0)]]
    page = _page(lines, {"S": (0, 0), "E": (0, 900)})
    box = ("SW-A", 100.0, 200.0, 400.0, 300.0)
    spot = titles.end_title_spot(page, box)
    assert spot > titles.TITLE_LEFT
    left, right = 100.0 + spot - titles.TITLE_PAD, 100.0 + spot - titles.TITLE_PAD + titles.title_width("SW-A")
    assert not any(left <= x <= right for x in (120.0, 200.0))


def test_a_frame_title_that_cannot_avoid_every_line_takes_the_spot_with_the_fewest():
    lines = [[(x, 230.0), (x, 600.0)] for x in range(110, 190, 6)]                 # a wall of lines over a narrow frame
    page = _page(lines, {"S": (0, 0), "E": (0, 900)})
    spot = titles.end_title_spot(page, ("A-LONG-SWITCH-NAME-01", 100.0, 200.0, 120.0, 300.0))
    assert titles.TITLE_LEFT <= spot <= 120.0


def test_svg_and_drawio_write_the_title_at_the_spot_the_engine_chose(monkeypatch):
    from features.topology import drawio as drawio_module
    from features.topology import svg as svg_module

    graph = _comb_graph(6)
    pages = build_pages(graph)
    page = pages[0]
    assert page.end_boxes
    monkeypatch.setattr(svg_module, "end_title_spot", lambda page, box, segments=None, rects=None: 37.0)
    monkeypatch.setattr(drawio_module, "end_title_spot", lambda page, box, segments=None, rects=None: 37.0)
    markup = svg_module.to_svg(page, graph)
    xml = drawio_module.to_drawio(graph, pages=pages)
    for title, x, y, w, h in page.end_boxes:
        assert f'<text x="{x + 37:.0f}" y="{y + 20:.0f}"' in markup
    assert xml.count("spacingLeft=37;") == len(page.end_boxes)


def test_the_title_spot_is_ten_pixels_in_when_no_line_is_near_on_a_real_page():
    graph = _comb_graph(6)
    page = build_pages(graph)[0]
    spots = [titles.end_title_spot(page, box) for box in page.end_boxes]
    assert spots and all(titles.TITLE_LEFT <= s <= box[3] for s, box in zip(spots, page.end_boxes))


# ---- lines ----------------------------------------------------------------------------------------------------------------------------------------------------------

def _comb_graph(ends: int, switches: int = 2) -> Graph:
    nodes = {"CORE": _device("CORE", "core")}
    conns = []
    for s in range(switches):
        sw = f"SW-{s}"
        nodes[sw] = _device(sw, "access")
        conns.append(Connection("CORE", sw, [Link("CORE", f"Po{s}", sw, "Po1", "confirmed", {"CDP"}, "")]))
        for i in range(ends):
            key = f"{sw}-E{i}"
            nodes[key] = _device(key, "ap", captured=False)
            conns.append(Connection(sw, key, [Link(sw, f"Gi1/0/{i}", key, "Gi0", "confirmed", {"CDP"}, "")]))
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set(), group_endpoints=True)


def test_the_lanes_of_a_comb_are_further_apart_than_before():
    assert scene.COMB_LANE >= 8.0 and scene.COMB_CHANNEL >= 8.0 and scene.COMB_CHANNEL_MIN >= 5.0
    page = build_pages(_comb_graph(8, switches=2))[0]
    lanes = sorted({round(route[2][1]) for index, route in page.routes.items() if index in page.comb_source and len(route) >= 4 and abs(route[2][1] - route[3][1]) < 1})
    assert len(lanes) >= 3 and all(b - a >= 8 for a, b in zip(lanes, lanes[1:])), lanes


def test_a_side_with_very_many_lines_leaves_along_more_of_the_icon():
    page = build_pages(_comb_graph(24, switches=1))[0]
    leave = [route[0][1] for index, route in page.routes.items() if index in page.comb_source and route]
    sy = page.nodes["SW-0"].y + NODE_H / 2
    assert max(leave) <= sy + 36 and min(leave) < sy + 6 and len(set(round(v, 1) for v in leave)) >= len(leave) // 2


def test_no_two_different_cables_lie_on_each_other_outside_the_icons_on_the_demo_pages():
    from features.topology import demo, service

    def runs(page):
        centre = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}
        found = []
        for index, conn in enumerate(page.connections):
            if conn.a not in centre or conn.b not in centre:
                continue
            pts = [centre[conn.a], *(page.routes.get(index) or []), centre[conn.b]]
            icons = [(centre[k][0] - NODE_W / 2 + 2, centre[k][1] - NODE_H / 2 + 2, centre[k][0] + NODE_W / 2 - 2, centre[k][1] + NODE_H / 2 - 2) for k in (conn.a, conn.b)]
            for p, q in zip(pts, pts[1:]):
                if abs(p[0] - q[0]) < 0.5 or abs(p[1] - q[1]) < 0.5:
                    vertical = abs(p[0] - q[0]) < 0.5
                    fixed = p[0] if vertical else p[1]
                    lo, hi = sorted((p[1], q[1]) if vertical else (p[0], q[0]))
                    # drop the part inside the own icons
                    for l, t, r, b in icons:
                        a0, a1 = (t, b) if vertical else (l, r)
                        if l - 1 < (fixed if vertical else lo) < r + 1 or True:
                            inside = (l <= fixed <= r) if vertical else (t <= fixed <= b)
                            if inside:
                                if lo < a1 and hi > a0:
                                    lo, hi = (max(lo, a1), hi) if lo >= a0 else (lo, min(hi, a0))
                    if hi - lo > 8:
                        found.append((index, vertical, fixed, lo, hi))
        return found

    total = 0
    names = [f["name"] for f in next(s for s in demo.list_sets() if s["id"] == "multisite")["files"]]
    files = [(n, demo.read_file("multisite", n).decode("utf-8")) for n in names]
    for built in (service.build_topology(files, group="auto", view="all", collapse_endpoints=False, include_hosts=False, group_endpoints=True, collapse_aps=False),):
        for page in built["pages"]:
            segs = runs(page)
            for i, a in enumerate(segs):
                for b in segs[i + 1:]:
                    if a[0] != b[0] and a[1] == b[1] and abs(a[2] - b[2]) < 2.0:
                        total += max(0.0, min(a[4], b[4]) - max(a[3], b[3]))
    assert total < 40, total


# ---- the whole pipeline -----------------------------------------------------------------------------------------------------------------------------------------

def _captured(host: str, halves: list) -> Device:
    dev = Device(key=host, hostname=host, captured=True)
    dev.halves = halves
    return dev


def _half(port: str, name: str, remote_port: str, protocols: set[str], platform: str = "", caps: str = "", descr: str = "") -> "HalfEdge":
    from features.topology.extract import HalfEdge
    return HalfEdge(local_port=port, remote_name=name, remote_port=remote_port, protocols=protocols, remote_platform=platform, remote_caps=caps, remote_descr=descr)


def test_the_service_draws_the_access_points_under_the_switch_they_are_plugged_into_not_under_the_one_above():
    """CORE-SW lists two access points on its uplink to HW-SW (CDP flooded through HW-SW); HW-SW lists them on their own ports (LLDP)."""
    from features.topology.service import build_topology

    ap = dict(platform="AIR-AP2802I-E-K9", caps="Trans-Bridge IGMP", descr="Cisco AP Software")
    core = _captured("CORE-SW", [_half("Gi1/0/1", "HW-SW", "XGE0/0/1", {"LLDP", "CDP"}, caps="Switch IGMP"),
                                 _half("Gi1/0/1", "AP-1", "Eth0", {"CDP"}, **ap), _half("Gi1/0/1", "AP-2", "Eth0", {"CDP"}, **ap)])
    hw = _captured("HW-SW", [_half("XGE0/0/1", "CORE-SW", "Gi1/0/1", {"LLDP"}, caps="Switch IGMP"),
                             _half("GE0/0/1", "AP-1", "Eth0", {"LLDP"}, **ap), _half("GE0/0/2", "AP-2", "Eth0", {"LLDP"}, **ap)])
    built = build_topology([], devices=[core, hw], group="auto", view="physical", group_endpoints=True)
    graph = built["graph"]
    ends = {frozenset((c.a, c.b)) for c in graph.connections}
    assert all(frozenset(("CORE-SW", ap_name)) not in ends for ap_name in ("AP-1", "AP-2"))
    assert frozenset(("HW-SW", "AP-1")) in ends and frozenset(("HW-SW", "AP-2")) in ends
    assert not any(f["id"] == "TOPO-011" for f in built["findings"])


def test_two_cables_from_one_hub_to_two_boxes_that_go_round_the_same_box_do_not_share_a_run():
    """Both lines leave the hub for the top corners of the tall box in the middle; with one lane they ran side by side on the same 230 px."""
    boxes = [("L", 0, 0, 200, 200), ("M", 300, -500, 200, 1200), ("R", 600, -100, 200, 150), ("S", 600, -320, 200, 150)]
    places = {"H1": (50, 50), "R1": (650, -60), "S1": (650, -280)}
    page = types.SimpleNamespace(boxes=boxes, nodes={k: types.SimpleNamespace(x=x, y=y) for k, (x, y) in places.items()},
                                 connections=[types.SimpleNamespace(a="H1", b="R1"), types.SimpleNamespace(a="H1", b="S1")], routes={})
    centres = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}
    assert scene._route_around_boxes(page, centres) == {0, 1}

    def legs(index: int) -> set:
        points = [centres[page.connections[index].a], *page.routes[index], centres[page.connections[index].b]]
        return {tuple(sorted((tuple(map(round, p)), tuple(map(round, q))))) for p, q in zip(points, points[1:])}

    assert not legs(0) & legs(1)
    first, second = page.routes[0], page.routes[1]
    assert abs(first[0][1] - second[0][1]) >= scene.LANE_STEP - 1              # the second line runs one lane further out
