"""Topology Builder 1.0: comb lines to end points, Palo Alto high availability, descriptions that name a far port, ports described twice."""

from __future__ import annotations

from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from tests.test_topology_v07 import _endpoint_graph


# ----------------------------------------------------------------------------------------------------------------- comb lines to end points
def _comb_graph():
    graph = _endpoint_graph({"SW-A": 12, "SW-B": 5})
    graph.nodes["SW-D"] = Device(key="SW-D", hostname="SW-D", captured=True, role_hint="access")
    graph.connections.append(Connection("SW-A", "SW-D", [Link("SW-A", "Eth1/40", "SW-D", "Eth1/1", "confirmed", {"CDP"}, "")]))
    return graph


def _segments(route):
    return list(zip(route, route[1:]))


def _cross(s, t) -> bool:
    """Two axis-parallel segments cross in their insides (a shared lane or a touch at an end is not a crossing)."""
    (a, b), (c, d) = s, t
    horizontal, vertical = (s, t) if abs(a[1] - b[1]) < 0.5 else (t, s)
    if abs(horizontal[0][1] - horizontal[1][1]) > 0.5 or abs(vertical[0][0] - vertical[1][0]) > 0.5:
        return False
    hx0, hx1 = sorted((horizontal[0][0], horizontal[1][0]))
    vy0, vy1 = sorted((vertical[0][1], vertical[1][1]))
    x, y = vertical[0][0], horizontal[0][1]
    return hx0 + 0.5 < x < hx1 - 0.5 and vy0 + 0.5 < y < vy1 - 0.5


def test_lines_to_the_end_points_of_a_frame_run_as_a_comb_without_crossings():
    from features.topology.scene import build_pages
    page = build_pages(_comb_graph())[0]
    combed = {i: page.routes[i] for i, c in enumerate(page.connections) if c.a == "SW-A" and c.b.startswith("SW-A-PH") and i in page.routes}
    assert len(combed) == 11                                                    # the end point right under the switch (middle column, first row) keeps its straight line
    for route in combed.values():
        assert len(route) >= 3
        assert all(abs(p[0] - q[0]) < 0.5 or abs(p[1] - q[1]) < 0.5 for p, q in _segments(route)[1:])          # after the leave, only horizontal and vertical runs
    items = list(combed.items())
    for n, (i, one) in enumerate(items):
        for j, other in items[n + 1:]:
            assert not any(_cross(s, t) for s in _segments(one)[1:] for t in _segments(other)[1:]), (i, j)


def test_a_comb_lane_lies_above_the_frame_and_the_line_ends_on_its_end_point():
    from features.topology.layout import NODE_H, NODE_W
    from features.topology.scene import build_pages
    page = build_pages(_comb_graph())[0]
    box = next(b for b in page.end_boxes if b[0] == "SW-A")
    for i, conn in enumerate(page.connections):
        if conn.a == "SW-A" and conn.b.startswith("SW-A-PH") and i in page.routes:
            route = page.routes[i]
            if abs(page.nodes[conn.b].x - page.nodes["SW-A"].x) < 6:             # the middle column drops beside itself instead of taking a lane
                continue
            assert min(y for _, y in route[2:]) < box[2]                       # the lane is above the frame's top edge
            target = page.nodes[conn.b]
            assert route[-1][1] <= target.y + NODE_H / 2 + 1 and abs(route[-1][0] - (target.x + NODE_W / 2)) < 130


def test_the_layout_leaves_room_for_the_lanes_of_a_big_frame():
    from features.topology.scene import build_pages
    page = build_pages(_comb_graph())[0]
    sw, box = page.nodes["SW-A"], next(b for b in page.end_boxes if b[0] == "SW-A")
    assert box[2] - (sw.y + 76 + 54) >= 6 * 12 / 2                              # the gap from the text under the switch to the frame


def test_a_curved_page_keeps_the_comb_and_curves_only_the_single_bends():
    """1.0 skipped the comb on curved pages; 1.2 keeps it (the corners are rounded when drawn), lines that bend once are still curves."""
    from features.topology.scene import CURVE_POINTS, build_pages
    page = build_pages(_comb_graph(), curved=True)[0]
    assert page.comb_source
    assert all(len(page.routes[i]) >= 3 for i in page.comb_source)
    assert all(len(route) in (CURVE_POINTS, *(len(page.routes[i]) for i in page.comb_source)) for route in page.routes.values())


def test_the_comb_reaches_drawio_as_waypoints():
    import xml.etree.ElementTree as ET
    from features.topology.drawio import to_drawio
    from features.topology.scene import build_pages
    graph = _comb_graph()
    pages = build_pages(graph)
    waypoints = [len(list(c.iter("mxPoint"))) for c in ET.fromstring(to_drawio(graph, pages=pages)).iter("mxCell") if c.get("edge") == "1"]
    assert max(waypoints) >= 4


def test_a_second_switch_below_the_first_does_not_make_lines_cross_in_its_own_lanes():
    from features.topology.scene import build_pages
    graph = _endpoint_graph({"SW-1": 9})
    graph.nodes["SW-3"] = Device(key="SW-3", hostname="SW-3", captured=True, role_hint="access")
    graph.connections.append(Connection("SW-1", "SW-3", [Link("SW-1", "Gi1/0/1", "SW-3", "Gi1/0/1", "confirmed", {"CDP"}, "")]))
    for i in range(4):
        key = f"SW-3-PH{i + 1}"
        graph.nodes[key] = Device(key=key, hostname=key, captured=False, role_hint="phone")
        graph.connections.append(Connection("SW-3", key, [Link("SW-3", f"Eth1/{i + 2}", key, "Port1", "confirmed", {"CDP"}, "")]))
    page = build_pages(graph)[0]
    for source in ("SW-1", "SW-3"):
        mine = [page.routes[i] for i, c in enumerate(page.connections) if c.a == source and "-PH" in c.b and i in page.routes and len(page.routes[i]) >= 4]
        assert mine
        for n, one in enumerate(mine):
            for other in mine[n + 1:]:
                assert not any(_cross(s, t) for s in _segments(one)[1:] for t in _segments(other)[1:])


# ----------------------------------------------------------------------------------------------------------------- Palo Alto high availability
def _pan_unit(host: str, own: str, peer: str, priority: int, extra: str = "") -> str:
    return f"""set deviceconfig system hostname {host}
set deviceconfig high-availability enabled yes
set deviceconfig high-availability group group-id 7
set deviceconfig high-availability group peer-ip {peer}
set deviceconfig high-availability group mode active-passive
set deviceconfig high-availability group election-option device-priority {priority}
set deviceconfig high-availability group election-option preemptive yes
set deviceconfig high-availability interface ha1 port ethernet1/7
set deviceconfig high-availability interface ha1 ip-address {own}
set deviceconfig high-availability interface ha2 port ethernet1/8
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.1/30
{extra}"""


def _build(files):
    from features.topology.service import build_topology
    return build_topology(files, view="physical")


def test_pan_high_availability_settings_are_read_in_set_format_and_in_xml():
    from features.topology import panosdev
    (device,) = panosdev.read_units(_pan_unit("FWA", "10.255.0.1", "10.255.0.2", 90), "fwa.txt")
    ha = device.l3facts["pan_ha"]
    assert ha["mode"] == "active-passive" and ha["group"] == "7" and ha["peer_ip"] == "10.255.0.2" and ha["own_ip"] == "10.255.0.1" and ha["priority"] == 90
    assert ("HA1", "Eth1/7") in ha["ports"] and ("HA2", "Eth1/8") in ha["ports"] and device.l3facts["ha"] == "active-passive"
    xml = """<config><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>FWX</hostname></system>
<high-availability><enabled>yes</enabled><group><group-id>7</group-id><peer-ip>10.255.0.1</peer-ip><mode><active-passive/></mode>
<election-option><device-priority>110</device-priority><preemptive>yes</preemptive></election-option></group>
<interface><ha1><port>ethernet1/7</port><ip-address>10.255.0.2</ip-address></ha1><ha2><port>ethernet1/8</port></ha2></interface></high-availability></deviceconfig>
<network><interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.5/30"/></ip></layer3></entry></ethernet></interface></network></entry></devices></config>"""
    (other,) = panosdev.read_units(xml, "fwx.xml")
    assert other.l3facts["pan_ha"]["peer_ip"] == "10.255.0.1" and other.l3facts["pan_ha"]["priority"] == 110 and other.l3facts["pan_ha"]["mode"] == "active-passive"


def test_two_uploaded_units_of_a_pair_are_joined_port_to_port_once():
    result = _build([("fwa.txt", _pan_unit("FWA", "10.255.0.1", "10.255.0.2", 90)), ("fwb.txt", _pan_unit("FWB", "10.255.0.2", "10.255.0.1", 100))])
    graph = result["graph"]
    ha = [l for l in graph.links if "HA" in l.protocols]
    assert len(ha) == 2 and {(l.a_port, l.b_port) for l in ha} == {("Eth1/7", "Eth1/7"), ("Eth1/8", "Eth1/8")}
    assert not [k for k in graph.nodes if k.startswith("HAPEER-")]


def test_one_uploaded_unit_gets_a_grey_peer_named_by_its_ha1_address():
    graph = _build([("fwa.txt", _pan_unit("FWA", "10.255.0.1", "10.255.0.2", 90))])["graph"]
    peers = [n for k, n in graph.nodes.items() if k.startswith("HAPEER-")]
    assert len(peers) == 1 and not peers[0].captured and peers[0].role_hint == "firewall" and "10.255.0.2" in peers[0].model
    assert len([l for l in graph.links if "HA" in l.protocols]) == 2


def test_the_ha_port_of_a_firewall_with_no_ha_settings_is_not_invented():
    text = _pan_unit("FWA", "10.255.0.1", "10.255.0.2", 90).replace("enabled yes", "enabled no")
    graph = _build([("fwa.txt", text)])["graph"]
    assert not [l for l in graph.links if "HA" in l.protocols]


def test_an_aggregate_group_defined_in_the_template_is_still_a_bundle():
    text = "set deviceconfig system hostname FWT\nset network interface ethernet ethernet1/1 aggregate-group ae1\nset network interface ethernet ethernet1/2 aggregate-group ae1\n"
    from features.topology import panosdev
    (device,) = panosdev.read_units(text, "fwt.txt")
    assert device.bundles == {"ae1": ["Eth1/1", "Eth1/2"]} and "template" in device.bundle_info["ae1"]["description"]


def test_a_panorama_style_firewall_is_still_a_firewall_not_a_switch():
    graph = _build([("fwa.txt", _pan_unit("FWA", "10.255.0.1", "10.255.0.2", 90))])["graph"]
    assert graph.nodes["FWA"].role_hint == "firewall"


# ----------------------------------------------------------------------------------------------------------------- descriptions that name a port
def test_port_hint_reads_the_far_port_out_of_a_description():
    from features.topology.inferred import port_hint
    assert port_hint("Connection to CORE-2 - Port Eth1/17") == "Eth1/17"
    assert port_hint("uplink to CORE-2") == ""


def test_a_port_described_as_facing_two_devices_is_reported_once_and_both_lines_stay():
    from features.topology.findings import build_findings
    from features.topology.inferred import infer_neighbors
    nodes = {n: Device(key=n, hostname=n, captured=True, ips={f"10.0.0.{i}"}) for i, n in enumerate(("SW-A1", "SW-C3", "SW-D4"), 1)}
    nodes["SW-A1"].descriptions = {"Eth1/1": "to SW-C3 Eth1/9"}
    nodes["SW-C3"].descriptions = {"Eth1/9": "to SW-D4"}
    graph = Graph(nodes=nodes, links=[], connections=[], hidden_kinds=set())
    facts = infer_neighbors(graph)
    twice = [f for f in facts if f["type"] == "port-claimed-twice"]
    assert len(twice) == 1 and twice[0]["a"] == "SW-C3" and {twice[0]["first"], twice[0]["second"]} == {"SW-A1", "SW-D4"}
    graph.issues += facts
    assert "TOPO-029" in {row["id"] for row in build_findings(graph)}


# ----------------------------------------------------------------------------------------------------------------- labels
def test_two_wide_labels_on_two_close_short_lines_do_not_sit_on_each_other():
    from features.topology import labelplace, labels
    from features.topology.layout import Placed
    from features.topology.scene import Page
    nodes = {k: Device(key=k, hostname=k, role_hint="router") for k in "abcd"}
    first = Connection("a", "b", [Link("a", "Gi0/1", "b", "Gi0/1", "confirmed")], kind="routed", subnet="26 next hops not captured · OSPF 7871 prefixes, static default + 534 prefixes")
    second = Connection("c", "d", [Link("c", "Gi0/2", "d", "Gi0/2", "confirmed")], kind="routed", subnet="26 next hops not captured · OSPF 7890 prefixes, static default + 513 prefixes")
    graph = Graph(nodes=nodes, links=[first.links[0], second.links[0]], connections=[first, second])
    placed = {"a": Placed(0, 0, 0), "b": Placed(0, 250, 0), "c": Placed(60, 0, 0), "d": Placed(60, 250, 0)}
    page = Page("t", placed, set(), [], [first, second], {}, 600, 500, view="physical", graph=graph)
    labelplace.place_labels(page, graph, True)
    rects = []
    for index in (0, 1):
        cx, cy, _ = page.label_pos[(index, "mid")]
        w, h = labelplace._size(labels.center_text(page.connections[index], graph), mid=True)
        rects.append((cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2))
    assert not labelplace._hit(rects[0], [rects[1]])


# ----------------------------------------------------------------------------------------------------------------- satellites and L3 arcs
def test_two_satellites_on_crossed_spots_exchange_them():
    from features.topology.satellites import Extra, _swap
    fixed = {"A": (0.0, 500.0), "B": (800.0, 500.0)}
    extras = [Extra("e1", ["A"], above=True), Extra("e2", ["B"], above=True)]
    out = {"e1": (800.0, 0.0), "e2": (0.0, 0.0)}
    _swap(fixed, extras, out)
    assert out["e1"] == (0.0, 0.0) and out["e2"] == (800.0, 0.0)


def test_a_satellite_of_another_kind_is_not_exchanged():
    from features.topology.satellites import Extra, _swap
    fixed = {"A": (0.0, 500.0), "B": (800.0, 500.0)}
    extras = [Extra("e1", ["A"], above=True), Extra("e2", ["B"], above=False)]
    out = {"e1": (800.0, 0.0), "e2": (0.0, 0.0)}
    _swap(fixed, extras, out)
    assert out == {"e1": (800.0, 0.0), "e2": (0.0, 0.0)}


def test_the_bow_candidates_try_the_planned_bow_first_and_both_sides():
    from features.topology.l3over2 import _bow_candidates
    assert _bow_candidates(60)[:2] == [60, -60] and _bow_candidates(-94)[:2] == [-94, 94]
    assert len(set(_bow_candidates(60))) == len(_bow_candidates(60))
