"""Topology v3.0: a full mesh is drawn as straight lines, a line to a child at the side leaves the side of its parent, a frame of end points stays whole with the switches
under its switch in a row of their own, a site box holds its zone boxes, a floor with no core still gets its zone, the name of a zone slides away from the lines.

Everything is built from small synthetic networks (names ``YY-``, ``YA-``, ``YF-``); no customer data.  The rules are about roles, cables and positions, not names of a site.

Standards for the shape: Cisco Campus LAN and Wireless LAN Design Guide https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html ;
Cisco Massively Scalable Data Center (a leaf cabled to every spine) https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/white-paper-c11-743245.html
"""

from __future__ import annotations

import sys
from pathlib import Path

from features.topology import layout, roles, scene, titles
from features.topology.extract import Device, HalfEdge
from features.topology.graph import build

sys.path.insert(0, str(Path(__file__).parent))
from test_topology_v23 import _dev, _farm


def _agg_mesh(page, graph):
    """The lines between an aggregation switch and a top-of-rack switch: (index, parent, child)."""
    out = []
    for i, conn in enumerate(page.connections):
        names = {graph.nodes[conn.a].hostname: conn.a, graph.nodes[conn.b].hostname: conn.b}
        parent = next((k for n, k in names.items() if n.startswith("ZZ-AGG")), None)
        child = next((k for n, k in names.items() if n.startswith("ZZ-TOR")), None)
        if parent and child:
            out.append((i, parent, child))
    return out


def _farm_page(tors=8):
    graph = _farm("ZZ", tors=tors)
    graph.group_endpoints = True
    return graph, scene.build_pages(graph)[0]


# ---- a full mesh is a set of straight lines ------------------------------------------------------------------------------------------------------------

def test_the_links_of_a_full_mesh_are_straight_lines_and_not_a_bus():
    graph, page = _farm_page(8)
    lines = _agg_mesh(page, graph)
    assert len(lines) == 16
    assert not any(i in page.bus for i, _, _ in lines)                          # no lanes, no loops round the pair
    assert all(i in page.mesh for i, _, _ in lines)
    assert not any(page.routes.get(i) for i, _, _ in lines)                     # a straight line has no bend point


def test_the_old_bus_is_still_there_behind_the_switch(monkeypatch):
    monkeypatch.setattr(scene, "MESH_STRAIGHT", False)
    graph, page = _farm_page(8)
    lines = _agg_mesh(page, graph)
    assert sum(1 for i, _, _ in lines if i in page.bus) == 16 and not page.mesh


def test_a_straight_mesh_line_never_runs_through_another_icon():
    graph, page = _farm_page(8)
    boxes = {k: (p.x, p.y, p.x + scene.NODE_W, p.y + scene.NODE_H) for k, p in page.nodes.items()}
    pair = {k for k in page.nodes if graph.nodes[k].hostname.startswith("ZZ-AGG")}                 # the other switch of the pair may stand on the way to the far switches: the line passes behind it
    for i, parent, child in _agg_mesh(page, graph):
        a, b = scene._centre(page.nodes[parent]), scene._centre(page.nodes[child])
        for key, (x0, y0, x1, y1) in boxes.items():
            if key not in pair | {child}:
                assert not titles._hits((a[0], a[1], b[0], b[1]), x0 + 4, y0 + 4, x1 - 4, y1 - 4), (graph.nodes[parent].hostname, graph.nodes[child].hostname, key)


def test_l3_over_l2_keeps_the_straight_mesh_of_its_physical_page():
    from features.topology import l3over2
    graph, phys = _farm_page(8)
    assert phys.mesh
    pages = l3over2.build_l3_pages(graph, [phys]) if hasattr(l3over2, "build_l3_pages") else None
    if pages:
        assert pages[0].mesh


# ---- a line to a child at the side leaves the side of its parent -------------------------------------------------------------------------------------

def _two_children_far_below():
    """A core with two access switches far under it, one far left and one far right (nothing else): the lines must not start at the bottom of the icon and cross."""
    devices = [_dev("YY-CORE1", "C9300-24T", ["YY-ACC1", "YY-ACC2"]), _dev("YY-ACC1", "C9300-24T", ["YY-CORE1"], hosts=2), _dev("YY-ACC2", "C9300-24T", ["YY-CORE1"], hosts=2)]
    graph = build(devices)
    roles.classify(graph)
    return graph


def test_no_route_of_a_page_starts_inside_the_box_of_its_parent_after_the_side_exits():
    page = scene.build_pages(_two_children_far_below())[0]
    for i, conn in enumerate(page.connections):
        for key in (conn.a, conn.b):
            placed = page.nodes[key]
            for x, y in page.routes.get(i) or ():
                assert not (placed.x + 4 < x < placed.x + scene.NODE_W - 4 and placed.y + 4 < y < placed.y + scene.NODE_H - 4)


def test_route_sides_moves_a_steep_line_to_the_side_and_leaves_a_flat_one(monkeypatch):
    graph = _two_children_far_below()
    page = scene.Page("t")
    page.nodes = {"a": layout.Placed(400.0, 0.0, 0, ""), "b": layout.Placed(0.0, 400.0, 1, ""), "c": layout.Placed(800.0, 400.0, 1, ""), "d": layout.Placed(900.0, 20.0, 0, "")}
    conns = []
    for a, b in (("a", "b"), ("a", "c"), ("a", "d")):
        conn = next(iter(graph.connections))
        import copy
        clone = copy.copy(conn)
        clone.a, clone.b = a, b
        conns.append(clone)
    page.connections = conns
    centres = {k: scene._centre(p) for k, p in page.nodes.items()}
    boxes = {k: (p.x - 8, p.y - 8, p.x + scene.NODE_W + 8, p.y + scene.NODE_H + 52) for k, p in page.nodes.items()}
    scene._route_sides(page, centres, boxes, set())
    assert page.routes.get(0) and page.routes.get(1)                            # the two steep lines got a bend point
    assert page.routes[0][0][0] <= page.nodes["a"].x and page.routes[1][0][0] >= page.nodes["a"].x + scene.NODE_W         # the bend stands at the left / right side of the parent's icon
    assert not page.routes.get(2)                                               # the flat line to the device beside it stays as it is


# ---- end points of one switch: one frame, the switches under it in a row of their own ----------------------------------------------------------------------

def _frame_with_child(name="YF-WLC1", under="YF-ACC1"):
    """An access switch with six end points under a core, and a controller cabled to ``under`` (the access switch or the core)."""
    core = _dev("YF-CORE1", "C9500-24Y4C", ["YF-ACC1"])
    acc = _dev("YF-ACC1", "C9300-48P", ["YF-CORE1"], hosts=6)
    (core if under == "YF-CORE1" else acc).halves.append(HalfEdge(local_port="Gi1/0/48", remote_name=name, remote_port="Gi1", protocols={"LLDP"}))
    wlc = Device(key=name, hostname=name, captured=True, role_hint="wlc", model="C9800-L",
                 halves=[HalfEdge(local_port="Gi1", remote_name=under, remote_port="Gi1/0/48", protocols={"LLDP"})])
    graph = build([core, acc, wlc])
    roles.classify(graph)
    graph.group_endpoints = True
    return graph


def _one_row(graph, keys=None):
    """The row of the page where the controller and the end points all stand (a zone block gives its devices rows by hops: ``forced``)."""
    keys = keys or list(graph.nodes)
    forced = {k: 3.0 for k in keys if k != "YF-CORE1" and k != "YF-ACC1"}
    forced.update({"YF-CORE1": 1.0, "YF-ACC1": 2.0})
    return layout.layered(graph, keys, forced=forced)[0]


def test_a_device_that_is_not_an_end_point_never_stands_between_the_members_of_a_frame(monkeypatch):
    graph = _frame_with_child("YF-WLC1", under="YF-CORE1")                      # a controller of the core stands in the row of the frame
    monkeypatch.setattr(layout, "_cluster_row", lambda row, *a, **k: [row[0], "YF-WLC1", *[r for r in row[1:] if r != "YF-WLC1"]] if "YF-WLC1" in row else row)      # the sweeps once put it in the middle of the frame
    seen = []
    spread = layout._spread_framed
    monkeypatch.setattr(layout, "_spread_framed", lambda row, *a, **k: (seen.append(list(row)), spread(row, *a, **k))[1])
    placed = _one_row(graph)
    row = next(r for r in seen if "YF-WLC1" in r)
    at = [i for i, k in enumerate(row) if k.startswith("HOST")]
    assert len(at) == 6 and at == list(range(at[0], at[0] + 6))                 # the six end points stand side by side in the row given to the frame fit
    members = [p.x for p in placed.values() if p.box]
    assert not (min(members) < placed["YF-WLC1"].x < max(members) and abs(placed["YF-WLC1"].y - next(p.y for p in placed.values() if p.box)) < 1)


def test_the_switch_under_a_switch_with_a_frame_has_a_row_between_the_switch_and_its_frame():
    placed = _one_row(_frame_with_child())
    acc, wlc = placed["YF-ACC1"], placed["YF-WLC1"]
    kid = next(p for p in placed.values() if p.box)
    assert acc.y < wlc.y < kid.y                                              # the controller has a row of its own, the frame is under it


def test_frames_whole_closes_up_the_members_of_one_frame():
    owner = {"e1": "s", "e2": "s", "e3": "s"}
    assert layout._frames_whole(["e1", "x", "e2", "y", "e3"], owner) == ["e1", "e2", "e3", "x", "y"]
    assert layout._frames_whole(["x", "y"], owner) == ["x", "y"]


# ---- the box of a site holds its zone boxes ------------------------------------------------------------------------------------------------------------

def test_a_site_box_grows_to_hold_the_zone_boxes_whose_middle_is_inside():
    page = scene.Page("t")
    page.boxes = [("YS-1", 100.0, 100.0, 400.0, 300.0)]
    page.zones = [("CORE", "core", 80.0, 150.0, 200.0, 200.0), ("LAN / USER", "internal", 300.0, 150.0, 240.0, 330.0), ("OUTSIDE", "internal", 900.0, 900.0, 100.0, 100.0)]
    scene._hold_zones(page)
    _, x, y, w, h = page.boxes[0]
    for _, _, zx, zy, zw, zh in page.zones[:2]:
        assert x <= zx and y <= zy and x + w >= zx + zw and y + h >= zy + zh
    assert x + w < 900                                                          # the zone of another place does not pull the box
    assert page.width >= x + w and page.height >= y + h


def test_a_site_box_without_zones_is_not_changed():
    page = scene.Page("t")
    page.boxes = [("YS-1", 100.0, 100.0, 400.0, 300.0)]
    scene._hold_zones(page)
    assert page.boxes == [("YS-1", 100.0, 100.0, 400.0, 300.0)]


def _demo_pages(group="auto"):
    from features.topology import demo, service
    from features.topology.corpus import BUILD
    files = [(f["name"], demo.read_file("multisite", f["name"]).decode("utf-8")) for f in next(i for i in demo.list_sets() if i["id"] == "multisite")["files"]]
    return service.build_topology(files, **{**BUILD, "group": group})


def test_no_zone_box_of_the_demo_overview_crosses_the_frame_of_its_site():
    overview = _demo_pages()["pages"][0]
    assert overview.boxes and overview.zones
    for name, x, y, w, h in overview.boxes:
        for _, _, zx, zy, zw, zh in overview.zones:
            if x <= zx + zw / 2 <= x + w and y <= zy + zh / 2 <= y + h:
                assert x <= zx and y <= zy and x + w >= zx + zw and y + h >= zy + zh, name


def test_build_pages_grows_the_site_boxes_round_zone_boxes_that_are_wider_than_the_icons(monkeypatch):
    real = scene.zone_boxes
    monkeypatch.setattr(scene, "zone_boxes", lambda graph, page: [(t, k, x - 300, y, w + 600, h) for t, k, x, y, w, h in real(graph, page)])         # zones that reach far beyond their icons (wide frames, long captions)
    overview = scene.build_pages(_floors(3), "prefix2")[0]
    assert overview.boxes and overview.zones
    held = 0
    for name, x, y, w, h in overview.boxes:
        for _, _, zx, zy, zw, zh in overview.zones:
            if x <= zx + zw / 2 <= x + w and y <= zy + zh / 2 <= y + h:
                held += 1
                assert x <= zx and y <= zy and x + w >= zx + zw and y + h >= zy + zh, name
    assert held >= 3
    assert overview.width >= max(x + w for _, x, _, w, _ in overview.boxes)


def test_the_demo_pages_have_lines_that_leave_the_side_of_a_core_icon():
    pages = _demo_pages()["pages"]
    sides = 0
    for page in pages[1:]:
        for i, conn in enumerate(page.connections):
            route = page.routes.get(i)
            for key in (conn.a, conn.b):
                placed = page.nodes.get(key)
                if route and len(route) == 1 and placed and (abs(route[0][0] - placed.x) < 1 or abs(route[0][0] - (placed.x + scene.NODE_W)) < 1):
                    sides += 1
    assert sides >= 1


# ---- a floor with no core of its own gets its zone on the Overview too -----------------------------------------------------------------------------------

def _floors(count=4):
    """A core pair at the top and ``count`` floors, each a distribution switch with two access switches and end points: the floors have no core of their own."""
    devices = [_dev("YA-CORE1", "C9500-24Y4C", ["YA-CORE2"] + [f"YA{n}-DS1" for n in range(1, count + 1)]),
               _dev("YA-CORE2", "C9500-24Y4C", ["YA-CORE1"] + [f"YA{n}-DS1" for n in range(1, count + 1)])]
    for n in range(1, count + 1):
        devices.append(_dev(f"YA{n}-DS1", "C9300-48P", ["YA-CORE1", "YA-CORE2", f"YA{n}-AS1", f"YA{n}-AS2"]))
        devices += [_dev(f"YA{n}-AS{m}", "C9200-24P", [f"YA{n}-DS1"], hosts=3) for m in (1, 2)]
    graph = build(devices)
    roles.classify(graph)
    return graph


def test_every_floor_of_a_grouped_overview_has_its_zone_boxes():
    overview = scene.build_pages(_floors(4), "prefix2")[0]
    floors = [box for box in overview.boxes if box[0].startswith("YA") and box[0] != "YA-CORE"]
    assert len(floors) >= 4
    for name, x, y, w, h in floors:
        zones = [z for z in overview.zones if x <= z[2] + z[4] / 2 <= x + w and y <= z[3] + z[5] / 2 <= y + h]
        assert zones, name                                                      # no floor stays without a zone box because it has no core of its own


# ---- the name of a zone slides away from the lines that enter its box ----------------------------------------------------------------------------------

def test_the_name_of_a_zone_slides_to_a_gap_between_the_lines():
    page = scene.Page("t")
    zone = ("CORE", "core", 0.0, 0.0, 600.0, 300.0)
    left = titles.zone_title_spot(page, zone, [], [])
    assert left == titles.ZONE_LEFT                                           # nothing in the way: the corner
    through = [(left + 10, -50.0, left + 12, 120.0)]                          # a line that enters the box through the name
    moved = titles.zone_title_spot(page, zone, through, [])
    assert moved > left
    assert not titles._hits(through[0], moved - titles.TITLE_PAD, 8.0, moved + titles.ZONE_CHAR_W * 4 + titles.TITLE_PAD, 34.0)


def test_the_name_of_a_zone_keeps_the_corner_when_every_spot_is_blocked_equally():
    page = scene.Page("t")
    zone = ("A VERY LONG ZONE NAME THAT FILLS THE BOX", "core", 0.0, 0.0, 300.0, 300.0)
    spot = titles.zone_title_spot(page, zone, [], [])
    assert spot == titles.ZONE_LEFT


# ---- the L3 arc over a straight mesh cable rides close beside it ----------------------------------------------------------------------------------

def _mesh_arc_bows(monkeypatch, bow):
    from features.topology import demo, l3over2, service
    from features.topology.corpus import BUILD
    monkeypatch.setattr(l3over2, "MESH_BOW", bow)
    item = next(i for i in demo.list_sets() if i["id"] == "dcdrc")
    files = [(f["name"], demo.read_file("dcdrc", f["name"]).decode("utf-8")) for f in item["files"]]
    page = next(p for p in service.build_topology(files, **{**BUILD, "group": item.get("group", "none")})["l3_pages"] if p.name.startswith("HQ-DC") and p.mesh)
    pairs = {frozenset((page.connections[i].a, page.connections[i].b)) for i in page.mesh}
    out = []
    for k, c in enumerate(page.connections):
        if c.l3 and c.l3.get("over2") and c.l3.get("role") != "under" and frozenset((c.a, c.b)) in pairs:
            a, b = scene._centre(page.nodes[c.a]), scene._centre(page.nodes[c.b])
            length = ((b[0] - a[0]) ** 2 + (b[1] - a[1]) ** 2) ** 0.5 or 1.0
            out.append(max(abs((p[0] - a[0]) * (b[1] - a[1]) - (p[1] - a[1]) * (b[0] - a[0])) / length for p in page.routes[k]))
    return out


def test_an_arc_over_a_straight_mesh_cable_bows_less_than_an_ordinary_one(monkeypatch):
    near, far = _mesh_arc_bows(monkeypatch, 30.0), _mesh_arc_bows(monkeypatch, 60.0)
    assert near and len(near) == len(far)
    assert sum(near) < sum(far) - 20          # the planned bow of every free arc is half; arcs that had to swing round an icon are the same in both
    assert min(near) >= 20                    # still beside the cable, not on it


# ---- draw.io: a side exit is a fixed exit point of the icon, not a bend that stays behind when the icon is moved ---------------------------------------------

def test_side_exit_reads_a_bend_on_the_side_of_an_icon():
    from features.topology import drawio
    icon = (100.0, 200.0, 210.0, 68.0)
    assert drawio.side_exit([(310.0, 220.0)], icon) == (1.0, 20 / 68)
    assert drawio.side_exit([(100.0, 234.0)], icon) == (0.0, 0.5)
    assert drawio.side_exit([(310.0, 300.0)], icon) is None            # below the icon: not on its side
    assert drawio.side_exit([(200.0, 220.0)], icon) is None            # inside the icon's width: a bend of another kind
    assert drawio.side_exit([(310.0, 220.0), (320.0, 250.0)], icon) is None   # two bends: a comb or a detour
    assert drawio.side_exit(None, icon) is None and drawio.side_exit([(310.0, 220.0)], None) is None


def test_the_drawio_file_pins_the_side_exits_and_drops_their_bend():
    import re
    from features.topology import demo, service
    from features.topology.corpus import BUILD
    item = next(i for i in demo.list_sets() if i["id"] == "dcdrc")
    files = [(f["name"], demo.read_file("dcdrc", f["name"]).decode("utf-8")) for f in item["files"]]
    xml = service.build_topology(files, **{**BUILD, "group": item.get("group", "none")})["drawio"]
    xml = xml if isinstance(xml, str) else xml.decode("utf-8")
    pinned = re.findall(r'<mxCell style="[^"]*(?:exit|entry)X=([01]);(?:exit|entry)Y=([0-9.]+);[^"]*"[^>]*edge="1"[^>]*>(.*?)</mxCell>', xml, flags=re.S)
    assert pinned, "the demo has lines that leave the side of an icon"
    for side, fraction, body in pinned:
        assert 0.0 <= float(fraction) <= 1.0
        assert 'as="points"' not in body                                # the pinned point is the bend: no second one


# ---- a label that is still on another label after the two searches gets a third, denser one -------------------------------------------------------

def _label_clashes(page, graph):
    from features.topology import labelplace as L, labels
    rects = []
    for (i, slot), (cx, cy, _t) in page.label_pos.items():
        conn = page.connections[i]
        a, b = labels.end_texts(conn)
        text = {"a": a, "b": b, "mid": labels.center_text(conn, graph)}[slot]
        w, h = L._size(text, slot == "mid")
        rects.append((cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2))
    on_label = sum(1 for n, r in enumerate(rects) if any(m != n and not (r[2] <= q[0] or q[2] <= r[0] or r[3] <= q[1] or q[3] <= r[1]) for m, q in enumerate(rects)))
    on_icon = sum(1 for r in rects if any(not (r[2] <= o[0] or o[2] <= r[0] or r[3] <= o[1] or o[3] <= r[1]) for o in L._node_boxes(page, graph)))
    return on_label, on_icon


def test_the_dense_label_search_clears_labels_that_stood_on_labels_and_icons(monkeypatch):
    from features.topology import demo, labelplace, service
    from features.topology.corpus import BUILD
    item = next(i for i in demo.list_sets() if i["id"] == "dcdrc")
    files = [(f["name"], demo.read_file("dcdrc", f["name"]).decode("utf-8")) for f in item["files"]]
    page = next(p for p in service.build_topology(files, **{**BUILD, "group": item.get("group", "none")})["l3_pages"] if p.name.startswith("HQ-DC") and p.mesh)
    with_search = _label_clashes(page, page.graph)
    monkeypatch.setattr(labelplace, "DENSE_BUDGET", 0)
    labelplace.place_labels(page, page.graph, True)
    without = _label_clashes(page, page.graph)
    assert with_search[1] == 0 and without[1] > 0
    assert with_search[0] < without[0]
