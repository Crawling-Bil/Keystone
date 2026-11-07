"""Topology Builder 1.7: lines that lie on each other are lifted apart, a tall frame gets room for its lines, a busy switch lets its lines leave one by one, access points that are
cabled to one switch and only guessed on another stand in the frame of the first, frame names keep off port labels.  Synthetic captures only (invented names)."""

from __future__ import annotations

import math
import random

import pytest

from features.topology import layout, scene, titles
from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.layout import NODE_H, NODE_W
from features.topology.scene import build_pages


def _fan(hosts: int, role: str = "host", switches: int = 1) -> Graph:
    """One core over ``switches`` access switches, each with ``hosts`` end points that nobody captured."""
    nodes = {"CORE": Device(key="CORE", hostname="CORE", captured=True, role_hint="core")}
    conns = []
    for s in range(switches):
        sw = f"SW-{s}"
        nodes[sw] = Device(key=sw, hostname=sw, captured=True, role_hint="access")
        conns.append(Connection("CORE", sw, [Link("CORE", f"Po{s}", sw, "Po1", "confirmed", {"CDP"}, "")]))
        for i in range(hosts):
            key = f"{sw}-H{i:02d}"
            nodes[key] = Device(key=key, hostname=key, captured=False, role_hint=role)
            conns.append(Connection(sw, key, [Link(sw, f"Gi1/0/{i + 1}", key, "Gi0", "confirmed", {"LLDP"}, "")]))
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set(), group_endpoints=True)


def _centres(page):
    return {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}


def _runs(page):
    """Every straight piece of every line: (line index, from, to), from the centre of one icon over the waypoints to the centre of the other."""
    centre = _centres(page)
    out = []
    for index, conn in enumerate(page.connections):
        if conn.a not in centre or conn.b not in centre:
            continue
        points = [centre[conn.a], *(page.routes.get(index) or []), centre[conn.b]]
        out += [(index, p, q) for p, q in zip(points, points[1:])]
    return out


def _same_track(page, eps: float = 3.0, minimum: float = 8.0) -> float:
    """px of straight pieces of two different lines that lie within ``eps`` px of each other, side by side (the part under an icon is left out)."""
    centre = _centres(page)
    icons = [(x - NODE_W / 2, y - NODE_H / 2, x + NODE_W / 2, y + NODE_H / 2) for x, y in centre.values()]

    def outside(lo: float, hi: float, fixed: float, vertical: bool) -> float:
        length = hi - lo
        for r in icons:
            if (r[0] < fixed < r[2]) if vertical else (r[1] < fixed < r[3]):
                a, b = (r[1], r[3]) if vertical else (r[0], r[2])
                length -= max(0.0, min(hi, b) - max(lo, a))
        return length

    runs = _runs(page)
    total = 0.0
    for n, (i, p, q) in enumerate(runs):
        for j, r, s in runs[n + 1:]:
            if i == j:
                continue
            if abs(p[0] - q[0]) < .5 and abs(r[0] - s[0]) < .5 and abs(p[0] - r[0]) < eps:
                lo, hi = max(min(p[1], q[1]), min(r[1], s[1])), min(max(p[1], q[1]), max(r[1], s[1]))
                vertical = True
            elif abs(p[1] - q[1]) < .5 and abs(r[1] - s[1]) < .5 and abs(p[1] - r[1]) < eps:
                lo, hi = max(min(p[0], q[0]), min(r[0], s[0])), min(max(p[0], q[0]), max(r[0], s[0]))
                vertical = False
            else:
                continue
            if hi - lo > minimum:
                total += max(0.0, outside(lo, hi, p[0] if vertical else p[1], vertical))
    return total


# ---- a tall frame gets room for its lines ----------------------------------------------------------------------------------------------------

def test_a_short_frame_keeps_one_step_between_its_columns_and_a_tall_one_gets_more():
    assert layout.frame_pitch(4) == 1.0
    assert layout.frame_pitch(12) == 1.0
    assert 1.2 < layout.frame_pitch(54) <= layout.FRAME_PITCH_MAX
    pitches = [layout.frame_pitch(n) for n in range(2, 120)]
    assert all(1.0 <= p <= layout.FRAME_PITCH_MAX for p in pitches)
    assert pitches[-1] > pitches[0]


def test_the_columns_of_a_tall_frame_stand_further_apart_than_those_of_a_short_one():
    def pitch(hosts: int) -> float:
        page = build_pages(_fan(hosts))[0]
        xs = sorted({round(p.x) for k, p in page.nodes.items() if "-H" in k})
        return min(b - a for a, b in zip(xs, xs[1:]) if b - a > 20)
    assert pitch(54) > pitch(12) * 1.15


def test_the_lines_of_one_switch_into_a_tall_frame_do_not_lie_on_each_other():
    for hosts in (30, 54):
        page = build_pages(_fan(hosts))[0]
        assert _same_track(page) == 0, hosts


@pytest.mark.parametrize("seed", range(10))
def test_random_frames_have_no_lines_on_each_other_outside_the_icons(seed):
    from tests.test_topology_v13 import _graph
    page = build_pages(_graph(random.Random(seed)))[0]
    assert _same_track(page, eps=2.0) == 0, seed


def test_the_row_gap_over_a_frame_holds_the_lanes_of_its_comb():
    """The room between a switch and its frame is wide enough for every line to have a lane of 7 px or more."""
    page = build_pages(_fan(54))[0]
    centre = _centres(page)
    lanes = set()
    for index, route in page.routes.items():
        if index in page.comb_source:
            for (x0, y0), (x1, y1) in zip(route, route[1:]):
                if abs(y0 - y1) < .5 and abs(x0 - x1) > 20 and y0 > centre["SW-0"][1] + NODE_H / 2 + 30:          # a run below the text under the switch: a lane, not a head
                    lanes.add(round(y0))
    lanes = sorted(lanes)
    assert len(lanes) >= 30
    assert min(b - a for a, b in zip(lanes, lanes[1:])) >= 6.5
    assert centre["SW-0"][1] < min(lanes)


# ---- a busy switch lets its lines leave one by one ---------------------------------------------------------------------------------------------

def _heads(page, source: str) -> dict[int, list[float]]:
    sx, _ = _centres(page)[source]
    heads: dict[int, list[float]] = {-1: [], 1: []}
    for index, route in page.routes.items():
        if page.comb_source.get(index) != source or len(route) < 3:
            continue
        first = route[0] if page.connections[index].a == source else route[-1]
        if abs(first[0] - sx) >= NODE_W / 2 - 1:                         # starts at the side of the icon
            heads[-1 if first[0] < sx else 1].append(first[1])
    return heads


def test_the_lines_that_leave_one_side_of_a_busy_switch_start_four_px_apart():
    page = build_pages(_fan(54))[0]
    heads = _heads(page, "SW-0")
    assert max(len(v) for v in heads.values()) >= 20
    for ys in heads.values():
        ys.sort()
        assert all(b - a >= 4.0 - 0.01 for a, b in zip(ys, ys[1:]))


def test_a_switch_with_a_few_lines_keeps_its_seven_px_between_heads():
    page = build_pages(_fan(4))[0]
    for ys in _heads(page, "SW-0").values():
        ys.sort()
        assert all(b - a <= scene.COMB_EXIT + 0.01 for a, b in zip(ys, ys[1:]))


# ---- the channels of a core stay where the core stands --------------------------------------------------------------------------------------

def test_a_device_in_a_row_between_a_core_and_its_frame_gives_way_to_the_channel():
    items = ["\0CORE", "X", "Y", "Z"]
    got = {"\0CORE": -0.5, "X": 0.0, "Y": 1.0, "Z": 2.0}
    layout._pin_channels(items, got, [1.0, 1.0, 1.0], {"\0CORE": 0.0})
    assert got["\0CORE"] == 0.0
    assert got["X"] >= 1.0 and got["Y"] >= got["X"] + 1.0 and got["Z"] >= got["Y"] + 1.0


def test_two_cores_pin_their_channels_and_press_the_devices_between_them_together():
    items = ["\0A", "X", "Y", "Z", "\0B"]
    got = {"\0A": -1.0, "X": 0.0, "Y": 1.0, "Z": 2.0, "\0B": 3.0}
    layout._pin_channels(items, got, [1.05, 1.0, 1.0, 2.0], {"\0A": 0.0, "\0B": 4.5})
    assert got["\0A"] == 0.0 and got["\0B"] == 4.5
    assert got["X"] > 0.0 and got["Z"] < 4.5
    xs = [got[k] for k in items]
    assert all(b - a >= layout.PIN_GAP_MIN - 1e-9 for a, b in zip(xs, xs[1:]))


def test_channels_that_are_too_close_for_the_devices_between_them_leave_the_row_as_it_was():
    items = ["\0A", "X", "Y", "\0B"]
    got = {"\0A": -1.0, "X": 0.0, "Y": 1.0, "\0B": 2.0}
    before = dict(got)
    layout._pin_channels(items, got, [1.0, 1.0, 1.0], {"\0A": 0.0, "\0B": 1.0})
    assert got == before


# ---- one cable that is read and another that is only guessed ----------------------------------------------------------------------------

def _two_switches(second_kind: str, second_state: str) -> Graph:
    nodes = {"CORE": Device(key="CORE", hostname="CORE", captured=True, role_hint="core")}
    conns = []
    for s in range(2):
        sw = f"SW-{s}"
        nodes[sw] = Device(key=sw, hostname=sw, captured=True, role_hint="access")
        conns.append(Connection("CORE", sw, [Link("CORE", f"Po{s}", sw, "Po1", "confirmed", {"CDP"}, "")]))
        for i in range(3):
            key = f"{sw}-AP{i}"
            nodes[key] = Device(key=key, hostname=key, captured=False, role_hint="ap")
            conns.append(Connection(sw, key, [Link(sw, f"Gi1/0/{i + 1}", key, "Gi0", "confirmed", {"CDP"}, "")]))
    conns.append(Connection("SW-1", "SW-0-AP0", [Link("SW-1", "Gi1/0/40", "SW-0-AP0", "Gi0", second_state, {"DESC"}, "")], kind=second_kind))
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set(), group_endpoints=True)


def _frame_of(page, key):
    p = page.nodes[key]
    x, y = p.x + NODE_W / 2, p.y + NODE_H / 2
    return [t for t, bx, by, bw, bh in page.end_boxes if bx <= x <= bx + bw and by <= y <= by + bh]


def test_an_access_point_with_one_read_cable_and_one_inferred_stands_in_the_frame_of_the_read_one():
    page = build_pages(_two_switches("inferred", "inferred"))[0]
    assert _frame_of(page, "SW-0-AP0") == ["SW-0"]
    assert _frame_of(page, "SW-0-AP1") == ["SW-0"]
    assert _frame_of(page, "SW-1-AP0") == ["SW-1"]


def test_an_access_point_that_two_switches_both_report_stays_outside_the_frames():
    page = build_pages(_two_switches("link", "confirmed"))[0]
    assert _frame_of(page, "SW-0-AP0") == []


def test_every_access_point_of_one_switch_is_in_its_frame_even_with_a_guessed_second_cable():
    graph = _two_switches("inferred", "inferred")
    graph.group_endpoints = False
    graph.group_aps = True
    page = build_pages(graph)[0]
    assert all(_frame_of(page, f"SW-0-AP{i}") == ["SW-0"] for i in range(3))


# ---- frame names keep off port labels ------------------------------------------------------------------------------------------------------

def test_the_name_of_a_frame_slides_away_from_a_port_label():
    page = scene.Page("T")
    box = ("A-LONG-SWITCH-NAME-01", 100.0, 100.0, 700.0, 300.0)
    assert titles.end_title_spot(page, box, [], []) == titles.TITLE_LEFT
    label = (100 + 120.0 - 10, 100 + 6.0, 100 + 120.0 + 10, 100 + 22.0)                   # a port label right above the first column
    spot = titles.end_title_spot(page, box, [], [label])
    assert spot > titles.TITLE_LEFT
    left = box[1] + spot - titles.TITLE_PAD
    assert left >= label[2] or left + titles.title_width(box[0]) <= label[0]


def test_port_labels_keep_off_the_default_place_of_a_frame_name():
    from features.topology import labelplace
    graph = _fan(8, role="ap")
    graph.nodes["SW-0"].hostname = "A-SWITCH-WITH-A-LONG-NAME-01"
    page = build_pages(graph)[0]
    labelplace.place_labels(page, graph)
    assert page.end_boxes
    for rect in titles.page_label_rects(page, graph):
        for title, x, y, w, h in page.end_boxes:
            box = (x + 4, y + 6, x + titles.TITLE_LEFT + titles.title_width(title), y + 28)
            assert not (rect[0] < box[2] and box[0] < rect[2] and rect[1] < box[3] and box[1] < rect[3])


# ---- the version and the room between rows -----------------------------------------------------------------------------------------------

def test_the_version_is_at_least_1_7():
    from core.modules import TOOLS
    version = next(t for t in TOOLS if t.key == "topology").version
    assert tuple(int(part) for part in version.split(".")) >= (1, 7)
    from features.topology.service import _tool_version
    assert _tool_version() == version


def test_the_row_gap_grows_with_the_number_of_lines_to_a_frame_and_stays_within_its_cap():
    gaps = []
    for hosts in (4, 12, 30, 54):
        graph = _fan(hosts)
        keys = list(graph.nodes)
        tiers = layout._tier_values(graph, keys)
        order = sorted(set(tiers.values()))
        rows = {t: [k for k in keys if tiers[k] == t] for t in order}
        gaps.append(max(layout._gaps(graph, keys, order, rows)))
    assert gaps == sorted(gaps) and gaps[-1] > gaps[0] + 100
    assert math.isfinite(gaps[-1]) and gaps[-1] <= layout.Y_STEP + layout.Y_EXTRA_MAX + layout.COMB_EXTRA_MAX

# ---- two lines on one track are lifted apart -------------------------------------------------------------------------------------------------

def _stage(page, routes: dict[int, list[tuple[float, float]]]):
    centre = _centres(page)
    boxes = {k: (p.x - 8, p.y - 8, p.x + NODE_W + 8, p.y + NODE_H + 52) for k, p in page.nodes.items()}
    page.routes = dict(routes)
    page.comb_source = {}
    return centre, boxes


def test_two_lines_that_share_a_vertical_run_are_lifted_apart():
    page = build_pages(_fan(4))[0]
    far = max(p.y for p in page.nodes.values()) + 400
    centre, boxes = _stage(page, {0: [(-300.0, 100.0), (-300.0, far)], 1: [(-300.0, 120.0), (-300.0, far - 20)]})
    scene._lift_apart(page, centre, boxes)
    xs = {i: page.routes[i][0][0] for i in (0, 1)}
    assert abs(xs[0] - xs[1]) >= scene.LIFT_STEP - 0.01
    assert all(page.routes[i][0][0] == page.routes[i][1][0] for i in (0, 1))          # each run is still straight
    assert xs[0] == -300.0                                                           # the earlier line keeps its place


def test_two_lines_that_share_a_horizontal_run_are_lifted_apart():
    page = build_pages(_fan(4))[0]
    far = max(p.x for p in page.nodes.values()) + 400
    centre, boxes = _stage(page, {0: [(far, -300.0), (far + 300, -300.0)], 1: [(far + 20, -300.0), (far + 250, -300.0)]})
    scene._lift_apart(page, centre, boxes)
    assert abs(page.routes[0][0][1] - page.routes[1][0][1]) >= scene.LIFT_STEP - 0.01


def test_lines_that_only_touch_end_to_end_or_are_far_apart_stay_where_they_are():
    page = build_pages(_fan(4))[0]
    far = max(p.y for p in page.nodes.values()) + 400
    routes = {0: [(-300.0, 100.0), (-300.0, 200.0)], 1: [(-300.0, 205.0), (-300.0, far)], 2: [(-250.0, 100.0), (-250.0, far)]}
    centre, boxes = _stage(page, routes)
    scene._lift_apart(page, centre, boxes)
    assert page.routes == routes


def test_a_lifted_line_never_moves_onto_a_device():
    page = build_pages(_fan(4))[0]
    node = page.nodes["SW-0-H03"]
    left = node.x - 8 - 2                                                            # 2 px outside the clearance box of the end point: a step to the right would run through it
    centre, boxes = _stage(page, {0: [(left, node.y - 100), (left, node.y + 300)], 1: [(left, node.y - 90), (left, node.y + 290)]})
    scene._lift_apart(page, centre, boxes)
    assert page.routes[0][0][0] == left
    moved = page.routes[1][0][0]
    assert moved < left and left - moved >= scene.LIFT_STEP                          # the second went to the free side
    conn = page.connections[1]
    assert scene._comb_free(page.routes[1], centre[conn.a], centre[conn.b], boxes, {conn.a, conn.b})

# ---- a guessed second cable into a frame finds a free way in -----------------------------------------------------------------------------------

def _guessed_cable_page():
    page = build_pages(_fan(6, switches=2))[0]
    page.connections.append(Connection("SW-1", "SW-0-H05", [Link("SW-1", "Gi1/0/48", "SW-0-H05", "Gi0", "inferred", {"ARP"}, "")], kind="inferred"))
    page.routes.pop(len(page.connections) - 1, None)
    return page, len(page.connections) - 1


def test_a_guessed_cable_enters_the_frame_by_the_strip_beside_its_end_point():
    page, index = _guessed_cable_page()
    centre = _centres(page)
    boxes = {k: (p.x - 8, p.y - 8, p.x + NODE_W + 8, p.y + NODE_H + 52) for k, p in page.nodes.items()}
    done = scene._route_into_frames(page, centre, boxes, set())
    assert index in done
    route = page.routes[index]
    assert route[0][0] != centre["SW-0-H05"][0] and abs(route[0][0] - centre["SW-0-H05"][0]) < layout.X_STEP          # the strip next to the column, not the column itself
    assert scene._comb_free(route, centre["SW-1"], centre["SW-0-H05"], boxes, {"SW-1", "SW-0-H05"})


def test_when_the_first_strip_is_blocked_the_cable_tries_another_way_in(monkeypatch):
    page, index = _guessed_cable_page()
    centre = _centres(page)
    boxes = {k: (p.x - 8, p.y - 8, p.x + NODE_W + 8, p.y + NODE_H + 52) for k, p in page.nodes.items()}
    real = scene._comb_free
    calls = []

    def blocked_once(path, start, end, rects, ends):
        calls.append(list(path))
        return False if len(calls) <= 2 * len(scene.DROP_OFFSETS) + 1 else real(path, start, end, rects, ends)          # every way in by the first strip (the straight one and the elbows) is blocked
    monkeypatch.setattr(scene, "_comb_free", blocked_once)
    done = scene._route_into_frames(page, centre, boxes, set())
    first = 2 * len(scene.DROP_OFFSETS) + 1
    assert index in done and len(calls) > first
    assert calls[0][-1][0] != calls[first][-1][0]                                      # the next try is at another strip
    assert page.routes[index] != calls[0] and page.routes[index] != calls[0][::-1]


def test_a_line_that_cannot_get_round_the_devices_takes_the_way_through_the_fewest():
    box = lambda x, y: (x, y, x + 80, y + 80)
    wall = [box(-40 + 100 * i, 160) for i in range(5)]                                 # a long row of devices between the two ends
    a, b = (200.0, 0.0), (200.0, 400.0)
    d = (b[0] - a[0], b[1] - a[1])
    n = (-d[1] / 400.0, d[0] / 400.0)
    path = scene._detour_least(a, b, d, n, 0.0, False, [0.0, 70.0, -70.0], wall)
    count = len(set().union(*(scene._hit_boxes(p, q, wall) for p, q in zip([a, *path], [*path, b]))))
    straight = len(scene._hit_boxes(a, b, wall))
    assert straight >= 1 and count <= straight
    assert scene._detour_least(a, b, d, n, 0.0, False, [], wall) is None


def _graph_with_guessed_cable() -> Graph:
    graph = _fan(6, switches=2)
    graph.connections.append(Connection("SW-1", "SW-0-H05", [Link("SW-1", "Gi1/0/48", "SW-0-H05", "Gi0", "inferred", {"ARP"}, "")], kind="inferred"))
    return graph


def test_a_guessed_cable_is_no_comb_line_of_the_switch_that_only_guesses():
    graph = _graph_with_guessed_cable()
    page = build_pages(graph)[0]
    index = len(page.connections) - 1
    assert page.connections[index].kind == "inferred"
    assert index not in page.comb_source


def test_a_line_that_no_detour_frees_still_takes_the_way_through_the_fewest_devices(monkeypatch):
    import dataclasses
    graph = _fan(0, switches=3)
    graph.connections.append(Connection("SW-0", "SW-2", [Link("SW-0", "Gi1/0/47", "SW-2", "Gi1/0/47", "confirmed", {"LLDP"}, "")]))
    page = build_pages(graph)[0]
    for key, x in (("SW-0", 80.0), ("SW-1", 310.0), ("SW-2", 540.0)):                         # the switch between the two ends of the cable
        page.nodes[key] = dataclasses.replace(page.nodes[key], x=x)
    page.routes.clear()
    seen = []
    real = scene._detour_least
    monkeypatch.setattr(scene, "_detour", lambda *args, **kwargs: None)
    monkeypatch.setattr(scene, "_detour_least", lambda *args, **kwargs: seen.append(1) or real(*args, **kwargs))
    scene._route(page)
    assert seen
    index = len(page.connections) - 1
    assert page.routes[index]                                                            # the line was bent, not left to run over the middle switch
