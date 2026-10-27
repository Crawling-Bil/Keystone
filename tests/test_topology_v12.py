"""Topology Builder 1.2: the comb on dense frames and curved pages, labels on their drops, bridges instead of V peaks, F5 map lines that stay clear of the boxes."""

from __future__ import annotations

import math
import xml.etree.ElementTree as ET

from features.topology import f5page
from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.labelplace import place_labels
from features.topology.layout import NODE_H, NODE_W
from features.topology.scene import build_pages
from tests.test_topology_v07_f5 import _graph as _f5_graph, _tree
from tests.test_topology_v11 import _centres, _combed, _graph as _comb_graph


def _two_switches(count: int = 24) -> Graph:
    """The A02 case: two access switches side by side under one core, each with a frame of end points."""
    return _comb_graph(lambda i: i % 2 == 0, count=count, switches=2)


def test_every_end_point_line_of_two_neighbouring_switches_is_a_comb_line_that_stays_clear_of_every_device():
    page = build_pages(_two_switches())[0]
    centres = _centres(page)
    end_lines = [i for i, c in enumerate(page.connections) if "-E" in c.a + c.b]
    assert len(end_lines) == 48
    boxes = {k: (c[0] - NODE_W / 2, c[1] - NODE_H / 2, c[0] + NODE_W / 2, c[1] + NODE_H / 2) for k, c in centres.items()}
    combed = [i for i in end_lines if i in page.comb_source]
    assert len(combed) >= 44                                                      # a handful of straight lines (end point right under the switch) may stay
    for _, conn, switch, path in _combed(page):
        for a, b in zip(path[1:], path[2:]):
            for key, (x0, y0, x1, y1) in boxes.items():
                if key in (conn.a, conn.b):
                    continue
                inside = max(a[0], b[0]) > x0 + 1 and min(a[0], b[0]) < x1 - 1 and max(a[1], b[1]) > y0 + 1 and min(a[1], b[1]) < y1 - 1
                assert not inside, (conn, key)
        assert all(abs(a[0] - b[0]) < 0.5 or abs(a[1] - b[1]) < 0.5 for a, b in zip(path[1:], path[2:])), conn      # orthogonal: no diagonal and no V


def test_the_drops_of_the_left_switch_stop_before_the_first_device_beside_it():
    page = build_pages(_two_switches())[0]
    centres = _centres(page)
    left, right = sorted(("SW-0", "SW-1"), key=lambda k: centres[k][0])
    for _, conn, switch, path in _combed(page):
        if switch != left:
            continue
        drop = path[2][0]
        side = 1 if drop > centres[left][0] else -1
        if side > 0:
            assert drop < centres[right][0] - NODE_W / 2 + 1, conn


def test_the_port_label_at_the_switch_of_a_comb_line_lies_on_the_drop_of_that_line():
    graph = _two_switches(20)
    page = build_pages(graph)[0]
    place_labels(page, graph)
    seen = 0
    for index, conn, switch, path in _combed(page):
        slot = "a" if conn.a == switch else "b"
        spot = page.label_pos.get((index, slot))
        if spot is None or index not in page.comb_source:
            continue
        run = path[2:4]
        if abs(run[0][0] - run[1][0]) > 0.5:
            continue
        seen += 1
        assert abs(spot[0] - run[0][0]) < 0.5, conn                              # on the drop's x
        assert min(run[0][1], run[1][1]) <= spot[1] <= max(run[0][1], run[1][1]), conn
    assert seen >= 15


def test_two_port_labels_of_one_switch_never_overlap_each_other():
    graph = _comb_graph(lambda i: False, count=30)
    page = build_pages(graph)[0]
    place_labels(page, graph)
    boxes = []
    for (index, slot), (x, y, _) in page.label_pos.items():
        if index in page.comb_source:
            boxes.append((x - 14, y - 5, x + 14, y + 5))                          # the shortest port text is about 28 x 10 px
    assert len(boxes) >= 20
    for n, a in enumerate(boxes):
        for b in boxes[n + 1:]:
            assert a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1], (a, b)


def test_a_curved_page_keeps_the_comb_and_draws_it_with_rounded_corners_in_svg_and_drawio():
    from features.topology.drawio import to_drawio
    from features.topology.svg import to_svg
    graph = _comb_graph(lambda i: i % 2 == 0, count=20)
    pages = build_pages(graph, "none", None, True)
    page = pages[0]
    assert page.curved and len(page.comb_source) >= 15
    root = ET.fromstring(to_drawio(graph, pages=pages))
    multi = [c for c in root.iter("mxCell") if c.get("edge") == "1" and len(list(c.iter("mxPoint"))) >= 4]
    assert len(multi) >= 12
    assert all("rounded=1" in c.get("style", "") for c in multi)
    assert "<path" in to_svg(page, graph) and 'stroke-linejoin="round"' in to_svg(page, graph)


def test_a_curved_page_with_several_switches_has_no_line_that_goes_back_up():
    graph = _two_switches(18)
    page = build_pages(graph, "none", None, True)[0]
    for _, conn, _, path in _combed(page):
        assert all(b[1] >= a[1] - 1 for a, b in zip(path, path[1:])), conn


def test_a_link_blocked_by_a_device_in_the_same_row_is_a_flat_bridge_not_a_v_peak():
    from tests.test_topology_l3engine import _crossing_graph
    from features.topology.scene import _route
    graph, page = _crossing_graph()
    _route(page)
    (x1, y1), (x2, y2) = page.routes[0]
    assert abs(y1 - y2) < 0.5 and x1 < x2


def _f5_edges(virtuals: int):
    page = f5page.page_for(_f5_graph(_tree(virtuals, pools=7, members=3)), "LB1")
    boxes = {s.ident: s for s in page.shapes if s.kind in ("external", "member", "node")}
    return page, boxes


def test_the_lines_of_the_big_ip_map_top_blocks_run_through_no_box_but_their_own():
    for n in (26, 60, 90):
        page, boxes = _f5_edges(n)
        lanes = [e for e in page.shape_edges if e.points]
        assert len(lanes) >= (n - 16) // 2
        for edge in lanes:
            own = boxes.get(edge.a if edge.a in boxes else edge.b)
            pts = edge.points
            for a, b in zip(pts, pts[1:]):
                assert abs(a[0] - b[0]) < 0.5 or abs(a[1] - b[1]) < 0.5, (n, edge.a)           # lanes are orthogonal
                for ident, s in boxes.items():
                    if own is not None and ident == own.ident:
                        continue
                    inside = max(a[0], b[0]) > s.x + 1 and min(a[0], b[0]) < s.x + s.w - 1 and max(a[1], b[1]) > s.y + 1 and min(a[1], b[1]) < s.y + s.h - 1
                    assert not inside, (n, edge.a, ident)


def test_the_lines_of_the_top_blocks_of_one_side_never_cross_each_other():
    page, _ = _f5_edges(90)
    lanes = [e.points for e in page.shape_edges if e.points]

    def cross(p, q, r, s):
        horizontal, vertical = (p, q), (r, s)
        if abs(p[1] - q[1]) > 0.5:
            horizontal, vertical = vertical, horizontal
        (hx0, hy), (hx1, _) = horizontal
        (vx, vy0), (_, vy1) = vertical
        if abs(horizontal[0][1] - horizontal[1][1]) > 0.5 or abs(vertical[0][0] - vertical[1][0]) > 0.5:
            return False                                                                          # parallel segments: overlap is not a crossing
        return min(hx0, hx1) + 0.5 < vx < max(hx0, hx1) - 0.5 and min(vy0, vy1) + 0.5 < hy < max(vy0, vy1) - 0.5

    crossings = 0
    for n, a in enumerate(lanes):
        for b in lanes[n + 1:]:
            for p, q in zip(a, a[1:]):
                for r, s in zip(b, b[1:]):
                    crossings += cross(p, q, r, s)
    assert crossings == 0


def test_a_long_name_in_the_big_ip_map_is_cut_with_an_ellipsis_and_stays_in_its_box():
    from features.topology.svg import _fit
    long = "vs_" + "x" * 80
    cut = _fit(long, 20)
    assert len(cut) == 20 and cut.endswith("…") and _fit("vs_short", 20) == "vs_short"


def test_the_f5_map_lane_points_reach_drawio_as_waypoints():
    from features.topology.drawio import to_drawio
    graph = _f5_graph(_tree(60, pools=7, members=3))
    page = f5page.page_for(graph, "LB1")
    root = ET.fromstring(to_drawio(graph, pages=[page]))
    waypoints = [len(list(c.iter("mxPoint"))) for c in root.iter("mxCell") if c.get("edge") == "1"]
    assert max(waypoints) >= 4


def test_the_version_is_at_least_1_2():
    from core.modules import TOOLS
    assert tuple(int(n) for n in next(t for t in TOOLS if t.key == "topology").version.split(".")) >= (1, 2)
