"""Topology v2.5: blocks that hold nearly everything are split, a hub with its own users is a zone, aggregation pairs draw a bus, L3 arcs and extras respect zone boxes, long lines go to the helper.

Everything is built from small synthetic networks (names ``QB-``, ``HB-``, ``ZZ-``, ``NN-``); no customer data.  The rules are about roles, functions and cables, not names of a site.

Standards for the shape: Cisco Campus LAN and Wireless LAN Design Guide https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html ;
Cisco Massively Scalable Data Center (a leaf cabled to both spines) https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/white-paper-c11-743245.html
"""

from __future__ import annotations

import types
import sys
from pathlib import Path
from collections import defaultdict

import pytest

from features.topology import layout, l3over2, roles, scene, service, zones
from features.topology.graph import build

sys.path.insert(0, str(Path(__file__).parent))
from test_topology_v23 import _dev, _farm


@pytest.fixture(autouse=True)
def _old_bus(monkeypatch):
    """These tests are about the bus (lanes) and the zone style of the lines; v3.0 draws a full mesh as straight lines instead (``scene.MESH_STRAIGHT``), the bus is kept behind the switch."""
    from features.topology import scene as _scene
    monkeypatch.setattr(_scene, "MESH_STRAIGHT", False)


# ---- synthetic networks -------------------------------------------------------------------------------------------------------------------------------

def _wan_heavy():
    """A core pair, one edge switch cabled to the core and to two WAN routers, eight branch switches (two hosts each) cabled to both routers, one distribution switch."""
    core = ["QB-CORE1", "QB-CORE2"]
    routers = ["QB-WAN1", "QB-WAN2"]
    branches = [f"QB-BR{i}" for i in range(1, 9)]
    devices = [_dev(c, "N9K-C93180YC-FX3", [x for x in core if x != c] + ["QB-EDGE1", "QB-DIST1"]) for c in core]
    devices.append(_dev("QB-EDGE1", "C9300-24T", core + routers, function="edge"))
    devices += [_dev(r, "ASR1002-X", ["QB-EDGE1"] + branches, role="router", function="wan") for r in routers]
    devices += [_dev(b, "C9300-24T", routers, hosts=2) for b in branches]
    devices.append(_dev("QB-DIST1", "C9300-48P", core, hosts=3))
    graph = build(devices)
    roles.classify(graph)
    return graph


def _edge_block(routers: int = 8, switches: int = 3):
    """A core pair, one edge switch cabled to the core, to ``routers`` WAN routers and to ``switches`` branch switches (everything of the way out hangs from it), one distribution switch with one access switch."""
    core = ["QB-CORE1", "QB-CORE2"]
    wan = [f"QB-WAN{i}" for i in range(1, routers + 1)]
    bsw = [f"QB-BSW{i}" for i in range(1, switches + 1)]
    devices = [_dev(c, "N9K-C93180YC-FX3", [x for x in core if x != c] + ["QB-EDGE1", "QB-DIST1"]) for c in core]
    devices.append(_dev("QB-EDGE1", "C9300-24T", core + wan + bsw, function="edge"))
    devices += [_dev(r, "ASR1002-X", ["QB-EDGE1"], role="router", function="wan") for r in wan]
    devices += [_dev(b, "C9300-24T", ["QB-EDGE1"]) for b in bsw]
    devices += [_dev("QB-DIST1", "C9300-48P", core + ["QB-ACC1"]), _dev("QB-ACC1", "C9300-48P", ["QB-DIST1"])]
    graph = build(devices)
    roles.classify(graph)
    return graph


def _hub(own_hosts: int, closet_hosts: int = 3, closets: int = 6):
    """A core pair over one distribution hub that has ``closets`` closet switches and ``own_hosts`` end points of its own."""
    core = ["HB-CORE1", "HB-CORE2"]
    names = [f"HB-CL{i}" for i in range(1, closets + 1)]
    devices = [_dev(c, "N9K-C93180YC-FX3", [x for x in core if x != c] + ["HB-HUB1"]) for c in core]
    devices.append(_dev("HB-HUB1", "C9300-48P", core + names, hosts=own_hosts))
    devices += [_dev(c, "C9200-24P", ["HB-HUB1"], hosts=closet_hosts) for c in names]
    graph = build(devices)
    roles.classify(graph)
    graph.group_endpoints = True
    return graph


def _flat():
    """A core pair and seven access switches without end points: one block that holds everything."""
    core = ["NN-CORE1", "NN-CORE2"]
    access = [f"NN-ACC{i}" for i in range(1, 8)]
    devices = [_dev(c, "N9K-C93180YC-FX3", [x for x in core if x != c] + access) for c in core]
    devices += [_dev(a, "C9300-24T", core) for a in access]
    graph = build(devices)
    roles.classify(graph)
    return graph


def _names(graph, zone):
    return sorted(graph.nodes[k].hostname for k in zone.members)


# ---- a block that holds nearly everything is split --------------------------------------------------------------------------------------------------

def test_the_routers_of_a_big_way_out_block_become_a_way_out_zone_of_their_own():
    graph = _edge_block()
    why: list[str] = []
    plan = zones.plan(graph, list(graph.nodes), why=why)
    assert plan is not None and not why
    by_names = {tuple(_names(graph, z)): z for z in plan.zones}
    wan = tuple(f"QB-WAN{i}" for i in range(1, 9))
    assert wan in by_names and by_names[wan].kind == "external"
    edge = next(z for z in plan.zones if "QB-EDGE1" in _names(graph, z))
    assert _names(graph, edge) == ["QB-BSW1", "QB-BSW2", "QB-BSW3", "QB-EDGE1"]          # the head keeps the switches below it
    assert not set(by_names[wan].members) & set(edge.members)
    assert max(len(z.members) for z in plan.zones) <= zones.BIGGEST_SHARE * sum(len(z.members) for z in plan.zones) + 1e-9


def test_a_branch_block_whose_switches_have_few_end_points_each_is_not_a_hub():
    graph = _wan_heavy()
    why: list[str] = []
    assert zones.plan(graph, list(graph.nodes), why=why) is None                 # nine of twelve devices in one internal block, no switch with a crowd of its own: the page keeps its rows
    assert why and "one block holds nearly all" in why[0]


def test_switches_cabled_to_the_wan_routers_are_titled_as_a_branch_not_as_a_lan(monkeypatch):
    graph = _wan_heavy()
    monkeypatch.setattr(zones, "BIGGEST_SHARE", 1.0)                                  # let the page gate pass: the question here is the title
    plan = zones.plan(graph, list(graph.nodes))
    branch = next(z for z in plan.zones if "QB-BR1" in _names(graph, z))
    assert branch.title == "BRANCH SWITCHES"
    lan = next(z for z in plan.zones if _names(graph, z) == ["QB-DIST1"])
    assert lan.title != "BRANCH SWITCHES"                                              # a switch under the core is not a branch


def test_a_block_without_routers_is_not_split_and_a_page_of_one_flat_block_has_no_zones():
    graph = _flat()
    why: list[str] = []
    assert zones.plan(graph, list(graph.nodes), why=why) is None
    assert why and "one block holds nearly all" in why[0]


# ---- a hub with a crowd of its own end points is a zone ----------------------------------------------------------------------------------------------

def test_a_hub_with_twelve_or_more_own_end_points_is_zoned_and_one_with_few_is_not():
    many = _hub(own_hosts=14)
    plan = zones.plan(many, list(many.nodes))
    assert plan is not None and any(z.kind == "internal" and len(z.ends) >= zones.HUB_ENDS for z in plan.zones)
    few = _hub(own_hosts=1, closet_hosts=1)
    why: list[str] = []
    assert zones.plan(few, list(few.nodes), why=why) is None and why


def test_the_hub_stands_over_its_own_frame_with_half_of_the_closets_on_each_side():
    graph = _hub(own_hosts=14)
    page = scene.build_pages(graph)[0]
    hub = page.nodes[next(k for k in graph.nodes if graph.nodes[k].hostname == "HB-HUB1")]
    closets = sorted((page.nodes[k].x, graph.nodes[k].hostname) for k in graph.nodes if graph.nodes[k].hostname.startswith("HB-CL"))
    left = [name for x, name in closets if x < hub.x]
    right = [name for x, name in closets if x > hub.x]
    assert len(left) == len(right) == 3
    assert page.end_boxes and len(page.zones) >= 1


def test_the_kid_order_puts_the_frame_between_two_halves_of_the_closets_only_with_a_frame():
    graph = _hub(own_hosts=14)
    hub = next(k for k in graph.nodes if graph.nodes[k].hostname == "HB-HUB1")
    kids = [k for k in graph.nodes if k != hub and not graph.nodes[k].hostname.startswith("HB-CORE")]
    order = layout._kid_order(graph, kids)
    ends = [i for i, k in enumerate(order) if not graph.nodes[k].captured]
    assert ends and ends == list(range(ends[0], ends[-1] + 1))                   # one block
    assert 0 < ends[0] and ends[-1] < len(order) - 1                             # with closets on both sides
    plain = _hub(own_hosts=0, closet_hosts=0)
    plain_kids = [k for k in plain.nodes if plain.nodes[k].hostname.startswith("HB-CL")]
    assert layout._kid_order(plain, plain_kids) == sorted(plain_kids, key=lambda k: layout._name_key(plain, k))      # nothing to frame: the plain name order


# ---- the bus of an aggregation pair ------------------------------------------------------------------------------------------------------------------

def _agg_bus(graph, page):
    """The bus lines between an aggregation switch and a top-of-rack switch: (index, parent, child)."""
    out = []
    for i in page.bus:
        conn = page.connections[i]
        names = {graph.nodes[conn.a].hostname: conn.a, graph.nodes[conn.b].hostname: conn.b}
        parent = next((k for n, k in names.items() if n.startswith("ZZ-AGG")), None)
        child = next((k for n, k in names.items() if n.startswith("ZZ-TOR")), None)
        if parent and child:
            out.append((i, parent, child))
    return out


def _farm_page(tors: int, bus: bool = True):
    graph = _farm("ZZ", tors=tors)
    graph.group_endpoints = True
    return graph, scene.build_pages(graph)[0]


def test_a_pair_cabled_to_eight_switches_draws_its_links_as_a_bus_and_a_pair_with_one_switch_does_not():
    graph, big = _farm_page(8)
    assert len(_agg_bus(graph, big)) == 16
    assert all(i in big.routes for i in big.bus)
    graph, small = _farm_page(1)
    assert not _agg_bus(graph, small)


def test_the_lines_of_one_bus_share_their_lane_and_the_two_drops_into_a_switch_stand_apart():
    graph, page = _farm_page(8)
    outer: dict[str, set[float]] = defaultdict(set)
    drops: dict[str, list[float]] = defaultdict(list)
    for i, parent, child in _agg_bus(graph, page):
        conn = page.connections[i]
        route = page.routes[i] if parent == conn.a else page.routes[i][::-1]
        outer[parent].add(round(route[0][1]))
        drops[child].append(route[-1][0])
    for ys in outer.values():
        assert len(ys) == 2                                                    # a lane for the lines that leave the outer side and one for the inner side: never one lane per line
    assert all(len(xs) == 2 and abs(xs[0] - xs[1]) >= 4 for xs in drops.values())


def test_a_second_cable_to_the_same_switch_is_a_second_drop_of_the_bus():
    import copy
    graph, page = _farm_page(8)
    lines = _agg_bus(graph, page)
    index, parent, child = lines[0]
    page.connections.append(copy.copy(page.connections[index]))                    # a second, separate cable between the same two switches
    extra = len(page.connections) - 1
    page.bus.clear()
    page.routes.clear()
    centres = {k: scene._centre(p) for k, p in page.nodes.items()}
    boxes = {k: (p.x - 8, p.y - 8, p.x + scene.NODE_W + 8, p.y + scene.NODE_H + 52) for k, p in page.nodes.items()}
    done = scene._route_bus(page, centres, boxes, set())
    assert index in done and extra in done
    conn = page.connections[index]
    ends = {i: (page.routes[i] if graph.nodes[conn.a].hostname.startswith("ZZ-AGG") else page.routes[i][::-1])[-1][0] for i in (index, extra)}
    assert abs(ends[index] - ends[extra]) >= scene.BUS_DROP - 0.5                  # the two cables drop side by side, not on one line


def test_the_lines_of_two_different_parents_never_lie_on_one_track():
    graph, page = _farm_page(8)
    runs = []
    for i, parent, _ in _agg_bus(graph, page):
        route = page.routes[i]
        for (x0, y0), (x1, y1) in zip(route, route[1:]):
            if abs(y0 - y1) < 0.5 and abs(x0 - x1) > 8:
                runs.append((parent, y0, min(x0, x1), max(x0, x1)))
    for n, (pa, ya, la, ha) in enumerate(runs):
        for pb, yb, lb, hb in runs[n + 1:]:
            if pa != pb and abs(ya - yb) < 2.5:
                assert min(ha, hb) - max(la, lb) <= 2.0, (pa, pb, ya, yb)


def test_the_bus_lines_are_not_lifted_apart_and_cross_less_than_the_lines_they_replace(monkeypatch):
    from features.topology import corpus
    _, with_bus = _farm_page(8)
    monkeypatch.setattr(scene, "_route_bus", lambda *a, **k: set())
    _, without = _farm_page(8)
    assert not without.bus
    assert corpus.overlay(with_bus)[0] <= corpus.overlay(without)[0]
    from features.topology.layoutscore import score_page
    assert score_page(with_bus)["crossings"] < score_page(without)["crossings"]


def test_a_line_that_would_run_through_a_device_keeps_its_ordinary_route():
    import dataclasses
    graph, page = _farm_page(8)
    parents = sorted((k for k in page.nodes if graph.nodes[k].hostname.startswith("ZZ-AGG")), key=lambda k: page.nodes[k].x)
    ay = page.nodes[parents[0]].y
    lane_y = ay + scene.NODE_H / 2 + 6
    blocker = next(k for k in page.nodes if graph.nodes[k].hostname.startswith("ZZ-TOR"))
    left_x = page.nodes[parents[0]].x - 400
    page.nodes[blocker] = dataclasses.replace(page.nodes[blocker], x=left_x, y=lane_y - scene.NODE_H / 2)       # a device on the lane that runs left from the first parent
    page.bus.clear()
    page.routes.clear()
    centres = {k: scene._centre(p) for k, p in page.nodes.items()}
    boxes = {k: (p.x - 8, p.y - 8, p.x + scene.NODE_W + 8, p.y + scene.NODE_H + 52) for k, p in page.nodes.items()}
    done = scene._route_bus(page, centres, boxes, set())
    for index in done:
        conn = page.connections[index]
        route = page.routes[index]
        assert scene._comb_free(route, centres[conn.a], centres[conn.b], boxes, {conn.a, conn.b})
        assert index in page.bus


def _aggregation_files(tors: int = 10):
    """Captures (IOS XE, invented names) of an aggregation pair with a routed link between them and ``tors`` top-of-rack switches, each cabled to both."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from topology_samples import iosxe_capture
    names = [f"TOR{i}" for i in range(1, tors + 1)]
    files = {}
    for name, ip, other, mine, peer_ip in (("AGG1", "10.0.0.1", "AGG2", "10.9.0.1", "10.0.0.2"), ("AGG2", "10.0.0.2", "AGG1", "10.9.0.2", "10.0.0.1")):
        config = f"interface GigabitEthernet1/0/48\n no switchport\n description to-{other}\n ip address {mine} 255.255.255.252\n!\n"
        neighbours = [(other, peer_ip, "C9500", "GigabitEthernet1/0/48", "GigabitEthernet1/0/48")]
        neighbours += [(t, f"10.0.1.{i + 1}", "C9300L", f"GigabitEthernet1/0/{i + 1}", f"GigabitEthernet1/0/{1 if name == 'AGG1' else 2}") for i, t in enumerate(names)]
        files[name.lower() + ".txt"] = iosxe_capture(name, f"FOC{name}", ip, neighbours, config_extra=config)
    for i, t in enumerate(names):
        neighbours = [("AGG1", "10.0.0.1", "C9500", "GigabitEthernet1/0/1", f"GigabitEthernet1/0/{i + 1}"), ("AGG2", "10.0.0.2", "C9500", "GigabitEthernet1/0/2", f"GigabitEthernet1/0/{i + 1}")]
        files[t.lower() + ".txt"] = iosxe_capture(t, f"FOCT{i}", f"10.0.1.{i + 1}", neighbours)
    return files


def test_the_l3_over_l2_page_keeps_the_bus_of_its_physical_page():
    result = service.build_topology(list(_aggregation_files().items()), view="l3over2", group="none", group_endpoints=True)
    physical, over = result["pages"][0], result["l3_pages"][0]
    assert len(physical.bus) == 16 and len(over.bus) == 16
    assert all(i < len(over.connections) and i in over.routes for i in over.bus)
    from features.topology import corpus
    assert corpus.overlay(over)[0] <= 600                                           # the bus shares its lanes on purpose; nothing else lies on a bus


def test_the_route_and_ip_pages_have_no_bus():
    result = service.build_topology(list(_aggregation_files().items()), view="all", group="none", group_endpoints=True)
    others = [p for key in ("l3_extra_pages", "ip_pages") for p in result.get(key) or []]
    assert others and all(not p.bus for p in others)
    assert result["pages"][0].bus                                                    # the physical page of the same run has one


def _slant_page(second_ends=("C", "D")):
    page = scene.Page("t", {}, set())
    page.connections = [types.SimpleNamespace(a="A", b="B"), types.SimpleNamespace(a=second_ends[0], b=second_ends[1])]
    page.routes = {0: [(0.0, 0.0), (500.0, 150.0)], 1: [(0.0, 1.0), (500.0, 151.0)]}              # two bridges that lie on one slanted track
    centres = {k: (0.0, 0.0) for k in "ABCD"}
    return page, centres


def _across(route_a, route_b):
    (x0, y0), (x1, y1) = route_a
    length = ((x1 - x0) ** 2 + (y1 - y0) ** 2) ** 0.5
    px, py = route_b[0]
    return abs((px - x0) * (y1 - y0) - (py - y0) * (x1 - x0)) / length


def test_two_slanted_runs_of_different_lines_that_lie_on_one_track_are_moved_apart():
    page, centres = _slant_page()
    scene._lift_slants(page, centres, {})
    assert _across(page.routes[0], page.routes[1]) >= scene.SLANT_SAME
    assert page.routes[0] == [(0.0, 0.0), (500.0, 150.0)]                                        # the first line keeps its place


def test_slanted_runs_of_lines_that_share_an_end_stay_where_they_are():
    page, centres = _slant_page(("A", "D"))
    scene._lift_slants(page, centres, {})
    assert page.routes[1] == [(0.0, 1.0), (500.0, 151.0)]


# ---- L3 over L2: arcs and extras respect zone boxes --------------------------------------------------------------------------------------------------

def test_the_wide_bows_are_tried_only_when_a_page_has_zone_boxes():
    plain = l3over2._bow_candidates(60.0)
    wide = l3over2._bow_candidates(60.0, wide=True)
    assert plain == wide[:len(plain)] and len(wide) == len(plain) + 6
    assert max(abs(b) for b in wide) >= 60 + 380


def _phys(zone_rects, nodes):
    return types.SimpleNamespace(zones=zone_rects, nodes={k: types.SimpleNamespace(x=x, y=y) for k, (x, y) in nodes.items()})


def test_an_extra_across_the_edge_of_a_zone_box_moves_wholly_outside_or_inside():
    zone = ("BOX", "internal", 100.0, 100.0, 600.0, 400.0)
    phys = _phys([zone], {"A": (150.0, 150.0), "B": (300.0, 150.0)})
    straddling = (zone[2] + zone[4] - 40.0, 250.0)                               # half in, half out through the right edge
    moved = l3over2._clear_zone_edges(phys, {"S": straddling}, {"S": ["A", "B"]}, set())
    assert "S" in moved
    x, y = moved["S"]
    inside = zone[2] <= x and x + layout.NODE_W <= zone[2] + zone[4]
    outside = x >= zone[2] + zone[4] or x + layout.NODE_W <= zone[2]
    assert inside or outside
    still = l3over2._clear_zone_edges(phys, {"S": (300.0, 300.0)}, {"S": ["A", "B"]}, set())
    assert still == {}                                                           # wholly inside: stays


def test_an_extra_that_belongs_to_one_zone_goes_inside_it_and_one_of_two_zones_goes_outside_both():
    left = ("L", "internal", 50.0, 100.0, 300.0, 400.0)
    right = ("R", "internal", 600.0, 100.0, 300.0, 400.0)
    phys = _phys([left, right], {"A": (80.0, 150.0), "B": (640.0, 150.0)})
    moved = l3over2._clear_zone_edges(phys, {"S": (320.0, 250.0)}, {"S": ["A", "B"]}, set())
    if "S" in moved:
        x, y = moved["S"]
        for _, _, zx, zy, zw, zh in (left, right):
            r = (x, y, x + layout.NODE_W, y + layout.NODE_H)
            overlaps = r[0] < zx + zw and r[2] > zx and r[1] < zy + zh and r[3] > zy
            inside = r[0] >= zx and r[2] <= zx + zw and r[1] >= zy and r[3] <= zy + zh
            assert not overlaps or inside


# ---- a long line sends the capture to the helper, whatever its size ----------------------------------------------------------------------------------

def test_a_capture_with_a_long_line_is_read_in_the_helper_and_a_short_one_is_not():
    short = "hostname NN-SW1\n" + "interface Gi1/0/1\n description uplink\n" * 100
    assert not service._needs_helper(short)
    long_line = short + "x" * service.ISOLATE_LONG_LINE + "\n"
    assert service._needs_helper(long_line)
    assert service._needs_helper("a\n" * (service.ISOLATE_MIN_CHARS // 2 + 1))
    assert service.ISOLATE_LONG_LINE <= 5_000


def test_the_history_limits_can_be_set_from_the_environment_and_stay_in_range(monkeypatch):
    import app
    monkeypatch.setenv("NES_TOPOLOGY_MAX_AGE_DAYS", "90")
    assert app._env_number("NES_TOPOLOGY_MAX_AGE_DAYS", 30, 1, 3650) == 90
    monkeypatch.setenv("NES_TOPOLOGY_MAX_AGE_DAYS", "0")
    assert app._env_number("NES_TOPOLOGY_MAX_AGE_DAYS", 30, 1, 3650) == 1
    monkeypatch.setenv("NES_TOPOLOGY_MAX_AGE_DAYS", "100000")
    assert app._env_number("NES_TOPOLOGY_MAX_AGE_DAYS", 30, 1, 3650) == 3650
    monkeypatch.setenv("NES_TOPOLOGY_MAX_AGE_DAYS", "abc")
    assert app._env_number("NES_TOPOLOGY_MAX_AGE_DAYS", 30, 1, 3650) == 30
    monkeypatch.delenv("NES_TOPOLOGY_MAX_AGE_DAYS")
    assert app._env_number("NES_TOPOLOGY_MAX_AGE_DAYS", 30, 1, 3650) == 30


# ---- peer-link members are paired by what the configuration says -------------------------------------------------------------------------------------

def _keepalive_pair(descriptions_a=None, descriptions_b=None, members_a=("XGE1/0/47", "XGE1/0/48"), members_b=("XGE1/0/45", "XGE1/0/46")):
    from test_topology_config_pairs import _tor
    a = _tor("PL-AGG1", domain="140", vendor="Cisco", model="N9K-C93180YC-FX", members=list(members_a), keepalive="10.0.0.2", ips={"10.0.0.1"})
    b = _tor("PL-AGG2", domain="140", vendor="Cisco", model="N9K-C93240YC-FX2", members=list(members_b), keepalive="10.0.0.1", ips={"10.0.0.2"})
    a.descriptions, b.descriptions = dict(descriptions_a or {}), dict(descriptions_b or {})
    graph = build([a, b])
    (conn,) = [c for c in graph.connections if c.kind == "peer-link"]
    return conn


def test_peer_link_members_that_name_each_other_in_their_descriptions_are_paired_by_it():
    conn = _keepalive_pair({"XGE1/0/48": "peer-link to PL-AGG2"}, {"XGE1/0/46": "peer-link to PL-AGG1"})
    pairs = {(l.a_port, l.b_port): l for l in conn.links}
    assert ("XGE1/0/48", "XGE1/0/46") in pairs and ("XGE1/0/47", "XGE1/0/45") in pairs
    assert "descriptions name each other" in pairs[("XGE1/0/48", "XGE1/0/46")].note


def test_peer_link_members_without_evidence_are_paired_in_order_and_the_note_says_it_is_a_guess():
    conn = _keepalive_pair()
    assert [(l.a_port, l.b_port) for l in conn.links] == [("XGE1/0/47", "XGE1/0/45"), ("XGE1/0/48", "XGE1/0/46")]
    assert all("guess" in l.note for l in conn.links)


def test_members_with_the_same_port_name_on_both_switches_are_paired_by_name():
    conn = _keepalive_pair(members_a=("XGE1/0/47", "XGE1/0/48"), members_b=("XGE1/0/48", "XGE1/0/47"))
    assert sorted((l.a_port, l.b_port) for l in conn.links) == [("XGE1/0/47", "XGE1/0/47"), ("XGE1/0/48", "XGE1/0/48")]
    assert all("guess" not in l.note for l in conn.links)


# ---- the management switch from its cabling -----------------------------------------------------------------------------------------------------------

def _plain_dc(far_port="Gi1/0/9", own_port="Gi1/0/{n}", skip=()):
    """The data center of ``test_topology_functions._dc`` with one change: the switch N06 reaches every other device over a plain port, with no management port and no description at all."""
    from test_topology_functions import _graph
    spec = {"N01": ("ISR4451-X", {}), "N02": ("C8200L-1N-4T", {}), "N03": ("C9500-48Y4C", {}), "N05": ("C9200L-48T-4X", {}), "N06": ("Built-in", {}),
            "N07": ("N9K-C93180YC-FX", {}), "N08": ("N9K-C93180YC-FX", {}), "N10": ("C9200L-24T-4G", {}), "N11": ("C9200L-24T-4G", {})}
    links = [("N01", "Gi0/0/1", "N03", "Twe1/0/1"), ("N03", "Twe1/0/2", "N07", "Eth1/1"), ("N03", "Twe1/0/3", "N08", "Eth1/1"), ("N07", "Eth1/47", "N08", "Eth1/47"),
             ("N05", "Gi1/0/41", "N01", "Gi0/0/2"), ("N05", "Gi1/0/42", "N02", "Gi0/0/2"), ("N05", "Gi1/0/47", "N03", "Twe1/0/47")]
    for rack in ("N10", "N11"):
        links += [(rack, "Gi1/0/25", "N07", f"Eth1/{rack[-2:]}"), (rack, "Gi1/0/26", "N08", f"Eth1/{rack[-2:]}")]
    for n, other in enumerate(("N01", "N02", "N03", "N05", "N07", "N08"), 1):
        if other not in skip:
            links.append(("N06", own_port.format(n=n), other, far_port))
    graph = _graph(spec, links, pairs=[("N07", "N08")])
    roles.classify(graph)
    return graph


def test_a_switch_with_single_gigabit_cables_to_every_tier_is_the_management_switch_without_any_mgmt_word():
    node = _plain_dc().nodes["N06"]
    assert node.function == "management" and "single 1 Gbit links" in node.function_why
    assert getattr(node, "hier_depth", None) is None                                                 # and it is no step of the hierarchy


def test_faster_cables_or_too_few_neighbours_are_no_management_switch():
    assert _plain_dc(own_port="Te1/0/{n}").nodes["N06"].function != "management"                     # 10 Gbit ports on the switch: a data switch
    assert _plain_dc(far_port="Te1/0/9").nodes["N06"].function != "management"                       # 10 Gbit ports on the other end
    assert _plain_dc(skip=("N01", "N02")).nodes["N06"].function != "management"                      # four neighbours


def test_a_management_switch_keeps_its_row_under_the_tiers_when_the_rows_are_counted_from_the_outside(monkeypatch):
    from features.topology import layout
    graph = _plain_dc()
    monkeypatch.setattr(layout, "star_applicable", lambda *_: True)                                   # the page of a site with several routers: rows counted in hops from the outside
    placed, _w, _h = layout.layered(graph, list(graph.nodes))
    assert placed["N05"].y < placed["N07"].y                                                           # the edge switch is above the aggregation pair: the rows were counted from the outside
    assert placed["N06"].y > placed["N07"].y and placed["N06"].tier == 2.5                             # and the management switch is under the lowest row it is cabled to (the aggregation pair)
    monkeypatch.setattr(layout, "MGMT_SPAN", 0)
    again, _w, _h = layout.layered(graph, list(graph.nodes))
    assert again["N06"].y < placed["N06"].y and again["N06"].tier == 1.0                               # mutation check: without the rule it stands in the hop row of the edge


# ---- the reading budget ---------------------------------------------------------------------------------------------------------------------------------

def _plain_files(count=4):
    from features.topology import demo
    return [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / "before").glob("*.txt"))][:count]


def test_after_one_slow_capture_the_rest_of_the_run_is_read_in_the_helper(monkeypatch):
    """Nothing in the text of a capture says it is slow (a short file can hold a layout the reader handles badly): once one has taken long, the others can be stopped."""
    from features.topology import isolate
    files = _plain_files(4)
    seen = []

    class Fake:
        def call(self, func, args, limit):
            seen.append(args[0])
            return isolate.OK, func(*args)

        def __exit__(self, *a):
            pass

    monkeypatch.setattr(isolate, "Isolated", Fake)
    monkeypatch.setattr(service, "READ_SLOW_SECONDS", -1.0)                                       # every capture counts as slow: the second one is already read in the helper
    service._CACHE.clear()
    devices, skipped = service.read_devices(files)
    assert len(seen) == len(files) - 1 and not skipped and len(devices) >= len(files) - 1
    assert seen == [name for name, _ in files[1:]]


def test_a_fast_run_never_starts_the_helper(monkeypatch):
    from features.topology import isolate

    def boom(*_):
        raise AssertionError("the helper was started")

    monkeypatch.setattr(isolate, "Isolated", boom)
    service._CACHE.clear()
    devices, _ = service.read_devices(_plain_files(3))
    assert devices


def test_the_program_starts_the_helper_process_safely_when_it_is_packed():
    """The helper starts the program again (start method ``spawn``): the entry point needs the main guard and ``freeze_support`` once packed into an .exe.
    Python: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.freeze_support"""
    source = (Path(__file__).resolve().parent.parent / "run.py").read_text(encoding="utf-8")
    guard = source.index('if __name__ == "__main__":')
    assert "multiprocessing.freeze_support()" in source[guard:] and source.index("main()", guard) > guard


# ---- zone-aware L3 over L2 pages, end to end ---------------------------------------------------------------------------------------------------------------

def _multisite_l3():
    from features.topology import demo
    files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / "multisite").glob("*.txt"))]
    result = service.build_topology(files, view="l3over2", group="auto", group_endpoints=True)
    phys = next(p for p in result["pages"] if p.name == "HQ")
    return phys, next(p for p in result["l3_pages"] if p.name == "HQ · L3 over L2")


def _rect_state(node, zone):
    _t, _k, x, y, w, h = zone
    if not (node.x < x + w and x < node.x + layout.NODE_W and node.y < y + h and y < node.y + layout.NODE_H):
        return "outside"
    return "inside" if x <= node.x and node.x + layout.NODE_W <= x + w and y <= node.y and node.y + layout.NODE_H <= y + h else "across"


def test_the_l3_over_l2_page_of_a_zoned_site_keeps_the_zones_and_no_extra_stands_across_a_zone_edge():
    """End to end on the multi-site demo.  The demo does not put an extra across an edge even without the clearing, so this is a regression guard; the rule itself has its mutation-checked unit tests above (``_clear_zone_edges``)."""
    phys, over = _multisite_l3()
    assert {t for t, *_ in phys.zones} <= {t for t, *_ in over.zones} and len(phys.zones) >= 3        # the zone boxes of the cable page are on the routed page as well (which adds the core's own box)
    extras = [k for k in over.nodes if k not in phys.nodes]
    assert extras                                                                                       # clouds and shared subnets were added
    assert not [k for k in extras for z in over.zones if _rect_state(over.nodes[k], z) == "across"]    # none is half in a zone box and half out


# ---- Aruba CX VSX as a pair ------------------------------------------------------------------------------------------------------------------------------

def _vsx_capture(name, other, role, peer, source, lldp=True, isl_state="In-Sync"):
    """An AOS-CX capture of one VSX member: the ``vsx`` block, the ISL (lag 256, two ports), one multi-chassis LAG, ``show vsx status`` and, when ``lldp``, the other member on both ISL ports."""
    lines = [f"{name}# show version", "AOS-CX", "Version      : FL.10.13.1000", "", f"{name}# show system", f"Hostname               : {name}", "Product Name           : JL700A 8325-32C Switch", "",
             f"{name}# show running-config", "!Version AOS-CX FL.10.13.1000", f"hostname {name}", "vsx", "    system-mac 02:00:00:00:10:01", "    inter-switch-link lag 256", f"    role {role}",
             f"    keepalive peer {peer} source {source} vrf KA", "interface lag 256", "    no shutdown", "    no routing", "    lacp mode active", "interface lag 10 multi-chassis", "    no shutdown",
             "    no routing", "    lacp mode active", "interface 1/1/49", "    no shutdown", "    lag 256", "interface 1/1/50", "    no shutdown", "    lag 256", ""]
    if lldp:
        lines += [f"{name}# show lldp neighbor-info detail", "LLDP Neighbor Information", "=========================", "", "Total Neighbor Entries          : 2", ""]
        for port in ("1/1/49", "1/1/50"):
            lines += [f"Port                           : {port}", "Neighbor Entries               : 1", f"Neighbor Chassis-Name          : {other}", "Neighbor Chassis-Description   : 8325",
                      "Neighbor Chassis-ID            : 0a:1b:00:00:09:09", "Chassis Capabilities Available : Bridge, Router", "Chassis Capabilities Enabled   : Bridge, Router",
                      f"Neighbor Port-ID               : {port}", "Neighbor Port-Desc             : ", "Neighbor Port VLAN ID          : 1", "TTL                            : 120",
                      f"Neighbor System-Name           : {other}", "Neighbor System-Description    : 8325", "-" * 79]
    lines += [f"{name}# show vsx status", "VSX Operational State", "---------------------", f"  ISL channel             : {isl_state}", "  ISL mgmt channel        : operational",
              "  Config Sync Status      : In-Sync", "", "Attribute           Local               Peer", "------------        --------            --------", f"Device Role         {role}             " + ("secondary" if role == "primary" else "primary"), "",
              f"{name}# show vsx status keepalive", "Keepalive State       : Keepalive-Established", ""]
    return "\n".join(lines)


def _vsx_pair(lldp=True, isl_state="In-Sync"):
    files = [("cx1.txt", _vsx_capture("DC-CX1", "DC-CX2", "primary", "10.255.0.2", "10.255.0.1", lldp, isl_state)),
             ("cx2.txt", _vsx_capture("DC-CX2", "DC-CX1", "secondary", "10.255.0.1", "10.255.0.2", lldp, isl_state))]
    return service.build_topology(files, group="none", view="physical")


def test_the_vsx_block_is_read_into_the_pair_fields():
    from features.topology import vsx
    found = vsx.read(_vsx_capture("A", "B", "primary", "10.255.0.2", "10.255.0.1"))
    assert (found["system_mac"], found["isl"], found["role"], found["peer"], found["source"], found["vrf"], found["multi_chassis"]) == ("02:00:00:00:10:01", "256", "primary", "10.255.0.2", "10.255.0.1", "KA", [10])
    assert found["state"]["isl channel"] == "In-Sync" and found["state"]["keepalive state"] == "Keepalive-Established"
    assert vsx.read("hostname x\ninterface 1/1/1\n   no shutdown\n")["system_mac"] == ""                                # a capture without VSX
    assert vsx.read("vsx\n   role primary\n")["isl"] == ""                                                            # a block without an ISL is not a pair


def test_two_vsx_members_with_lldp_are_one_pair_with_a_confirmed_peer_link():
    graph = _vsx_pair(lldp=True)["graph"]
    assert graph.vpc_pairs == [("DC-CX1", "DC-CX2", "02:00:00:00:10:01")]
    peer = next(c for c in graph.connections if c.kind == "peer-link")
    assert {l.state for l in peer.links} == {"confirmed"} and len(peer.links) == 2
    one = graph.nodes["DC-CX1"]
    assert (one.pair_kind, one.vpc_role, one.vpc_peer_link, one.vpc_ids) == ("VSX", "primary", "Po256", {"Po10": "10"})


def test_two_vsx_members_without_lldp_are_paired_from_the_keepalive_addresses_and_say_inferred():
    graph = _vsx_pair(lldp=False)["graph"]
    assert graph.vpc_pairs == [("DC-CX1", "DC-CX2", "02:00:00:00:10:01")]                                            # each keepalive peer is the source address of the other
    peer = next(c for c in graph.connections if c.kind == "peer-link")
    assert {l.state for l in peer.links} == {"inferred"} and "peer-link read from the configuration" in peer.links[0].note


def test_a_vsx_pair_with_an_isl_out_of_sync_is_reported_with_the_aruba_page():
    healthy = _vsx_pair()
    assert not [f for f in healthy["findings"] if f["id"] == "TOPO-019"]
    rows = [f for f in _vsx_pair(isl_state="Out-Sync")["findings"] if f["id"] == "TOPO-019"]
    assert rows and "ISL channel Out-Sync" in rows[0]["detail"] and "show vsx status" in rows[0]["recommendation"]
    assert rows[0]["reference"].startswith("https://arubanetworking.hpe.com/techdocs/VSG/")


def test_a_vsx_member_alone_is_listed_as_a_pair_without_its_peer():
    files = [("cx1.txt", _vsx_capture("DC-CX1", "DC-CX2", "primary", "10.255.0.2", "10.255.0.1", False))]
    rows = [f for f in service.build_topology(files, group="none", view="physical")["findings"] if f["id"] == "TOPO-021"]
    assert rows and "VSX" in rows[0]["recommendation"]


def test_a_vpc_domain_already_read_is_not_overwritten_by_vsx():
    from features.topology import vsx
    device = types.SimpleNamespace(vpc_domain="140", vpc_ids={}, ips=set(), bundles={}, pair_kind="", vpc_role="", vpc_peer_link="", vpc_keepalive="", vpc_health={})
    assert vsx.apply(device, _vsx_capture("A", "B", "primary", "10.255.0.2", "10.255.0.1")) is False and device.vpc_domain == "140" and device.pair_kind == ""


# ---- the firewall zone map and the cables that go round a firewall -----------------------------------------------------------------------------------------

def _fw_net(legs, cables=(("S1", "Gi1/0/48", "S2", "Gi1/0/48"),), allowed=None, native=None, routers=(), fw_names=("FW1",)):
    """One firewall FW1 with ``legs`` = [(interface, zone, vlan or None, switch, switch port)] and switches S1, S2 joined by ``cables``.  ``allowed``: {(switch, port): trunk list};
    ``native``: {(switch, port): VLAN}; ``routers``: names of routers that stand between the switches instead of a cable."""
    from features.topology.extract import Device
    from features.topology.graph import Connection, Graph, Link
    nodes = {"FW1": Device(key="FW1", hostname="FW1", captured=True, role_hint="firewall", vendor="Palo Alto Networks")}
    for name in ("S1", "S2"):
        nodes[name] = Device(key=name, hostname=name, captured=True, role_hint="core")
    for name in routers:
        nodes[name] = Device(key=name, hostname=name, captured=True, role_hint="router")
    links = []
    for i, (iface, zone, vlan, switch, port) in enumerate(legs):
        parent = iface.split(".")[0]
        if vlan:
            nodes["FW1"].fw_ifaces.append({"name": iface, "zone": zone, "parent": parent, "vlan": vlan, "type": "layer3"})
        else:
            nodes["FW1"].fw_ifaces.append({"name": iface, "zone": zone, "parent": "", "vlan": None, "type": "ethernet"})
        links.append(("FW1", parent, switch, port))
    links += list(cables)
    for r in routers:
        links += [("S1", "Gi1/0/40", r, "Gi0/0"), ("S2", "Gi1/0/40", r, "Gi0/1")]
    conns, seen = [], {}
    for a, pa, b, pb in links:
        link = Link(a, pa, b, pb, "confirmed", {"LLDP"}, "")
        key = (a, b)
        if key in seen:
            seen[key].links.append(link)
            continue
        conn = Connection(a, b, [link])
        seen[key] = conn
        conns.append(conn)
    for (sw, port), text in (allowed or {}).items():
        nodes[sw].port_allowed[port] = text
    for (sw, port), vlan in (native or {}).items():
        nodes[sw].port_native[port] = str(vlan)
    graph = Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set())
    return graph


def _bypasses(graph):
    from features.topology import fwzones
    return fwzones.bypasses(graph)


TRUNK_LEGS = [("ethernet1/1.10", "TRUST", 10, "S1", "Gi1/0/1"), ("ethernet1/2.10", "DMZ", 10, "S2", "Gi1/0/1")]


def test_the_map_lists_the_cable_the_neighbor_and_the_zone_of_every_firewall_interface():
    from features.topology import fwzones
    graph = _fw_net([("ethernet1/1", "TRUST", None, "S1", "Gi1/0/1"), ("ethernet1/2", "DMZ", None, "S2", "Gi1/0/1")], cables=())
    rows = fwzones.zone_map(graph)
    assert [(r["firewall_zone"], r["interface"], r["neighbor"], r["neighbor_port"]) for r in rows] == [("DMZ", "ethernet1/2", "S2", "Gi1/0/1"), ("TRUST", "ethernet1/1", "S1", "Gi1/0/1")]
    assert all(r["evidence"] == "LLDP" for r in rows)


def test_a_vlan_sub_interface_uses_the_cable_of_its_parent_port():
    from features.topology import fwzones
    rows = fwzones.zone_map(_fw_net(TRUNK_LEGS, cables=()))
    assert {(r["firewall_zone"], r["vlan"], r["cable"], r["neighbor"]) for r in rows} == {("TRUST", 10, "ethernet1/1", "S1"), ("DMZ", 10, "ethernet1/2", "S2")}


def test_two_zones_on_the_same_vlan_joined_by_a_trunk_are_a_firm_bypass():
    found = _bypasses(_fw_net(TRUNK_LEGS))
    assert len(found) == 1 and found[0]["certain"] and found[0]["vlan"] == 10 and {found[0]["zone_a"], found[0]["zone_b"]} == {"TRUST", "DMZ"}
    assert found[0]["firewall"] == "FW1" and "S1" in found[0]["through"]


def test_zones_on_different_vlans_do_not_bypass_each_other_even_over_one_trunk():
    legs = [("ethernet1/1.10", "TRUST", 10, "S1", "Gi1/0/1"), ("ethernet1/2.20", "DMZ", 20, "S2", "Gi1/0/1")]
    assert _bypasses(_fw_net(legs)) == []


def test_a_trunk_that_does_not_carry_the_vlan_ends_the_path():
    graph = _fw_net(TRUNK_LEGS, allowed={("S1", "Gi1/0/48"): "20-30", ("S2", "Gi1/0/48"): "20-30"})
    assert _bypasses(graph) == []
    open_graph = _fw_net(TRUNK_LEGS, allowed={("S1", "Gi1/0/48"): "1-4094", ("S2", "Gi1/0/48"): "1-4094"})
    assert len(_bypasses(open_graph)) == 1


def test_a_router_between_the_switches_ends_the_path():
    assert _bypasses(_fw_net(TRUNK_LEGS, cables=(), routers=("R1",))) == []                                   # traffic is routed there on purpose


def test_two_legs_of_one_zone_are_no_bypass():
    legs = [("ethernet1/1.10", "TRUST", 10, "S1", "Gi1/0/1"), ("ethernet1/2.10", "TRUST", 10, "S2", "Gi1/0/1")]
    assert _bypasses(_fw_net(legs)) == []


def test_untagged_legs_use_the_native_vlan_of_the_switch_port_and_say_possible_when_it_is_not_printed():
    legs = [("ethernet1/1", "TRUST", None, "S1", "Gi1/0/1"), ("ethernet1/2", "DMZ", None, "S2", "Gi1/0/1")]
    apart = _bypasses(_fw_net(legs, native={("S1", "Gi1/0/1"): 10, ("S2", "Gi1/0/1"): 20}))
    assert apart == []                                                                                         # two access VLANs: separated by the switch
    same = _bypasses(_fw_net(legs, native={("S1", "Gi1/0/1"): 10, ("S2", "Gi1/0/1"): 10}))
    assert len(same) == 1 and same[0]["certain"]
    unknown = _bypasses(_fw_net(legs))
    assert len(unknown) == 1 and not unknown[0]["certain"]


def test_the_findings_split_firm_paths_from_possible_ones_and_name_the_vendor_page():
    from features.topology import findings
    firm = [r for r in findings._bypass_findings(_fw_net(TRUNK_LEGS)) if r["id"] == "TOPO-059"]
    assert len(firm) == 1 and firm[0]["severity"] == "high" and "FW1" in firm[0]["devices"] and "Palo Alto" not in firm[0]["title"]
    assert firm[0]["reference"].startswith("https://docs.paloaltonetworks.com/")
    legs = [("ethernet1/1", "TRUST", None, "S1", "Gi1/0/1"), ("ethernet1/2", "DMZ", None, "S2", "Gi1/0/1")]
    possible = findings._bypass_findings(_fw_net(legs))
    assert [r["id"] for r in possible] == ["TOPO-060"] and possible[0]["severity"] == "info"
    assert findings._bypass_findings(_fw_net(TRUNK_LEGS, cables=())) == []


def test_the_run_returns_the_firewall_zone_map_with_the_zone_of_the_drawing_and_the_demo_has_no_bypass():
    from features.topology import demo
    files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / "multisite").glob("*.txt"))]
    result = service.build_topology(files, view="physical", group="auto", group_endpoints=True)
    rows = result["fw_zone_map"]
    assert rows and {"firewall", "firewall_zone", "interface", "vlan", "cable", "neighbor", "drawing_zone", "evidence"} <= set(rows[0])
    assert {r["firewall"] for r in rows} >= {"HQ-FGLAN1", "HQ-PADC1"}                                       # FortiGate and PAN-OS firewalls both
    assert any(r["drawing_zone"] == "CORE" for r in rows)                                                    # the zone of the drawing the far device stands in
    assert not [r for r in rows if r["interface"] in ("port1", "port2") and r["firewall_zone"] == r["interface"] and r["neighbor"] == ""]
    assert result["fw_bypass"] == [] and not [f for f in result["findings"] if f["id"] in ("TOPO-059", "TOPO-060")]


def test_a_member_of_an_aggregate_is_not_a_zone_of_its_own():
    from features.topology import fwzones
    graph = _fw_net(TRUNK_LEGS)
    graph.nodes["FW1"].bundle_of["ethernet1/1"] = "ae1"                                                    # the port that carries the TRUST sub-interface is a member of ae1
    graph.nodes["FW1"].fw_ifaces.append({"name": "ethernet1/1", "zone": "SPARE", "parent": "", "vlan": None, "type": "ethernet"})
    assert "SPARE" not in {r["firewall_zone"] for r in fwzones.zone_map(graph)}


# ---- the F5 table tied to the network ---------------------------------------------------------------------------------------------------------------------

F5_MAP = '''
ltm pool /Common/web_pool {
    members {
        /Common/198.51.100.20:80 {
            address 198.51.100.20
        }
        /Common/10.77.0.5:80 {
            address 10.77.0.5
        }
    }
    monitor /Common/http
}
ltm pool /Common/one_arm_pool {
    members {
        /Common/192.0.2.30:8080 {
            address 192.0.2.30
        }
    }
}
ltm virtual /Common/web_vs {
    destination /Common/192.0.2.50:443
    pool /Common/web_pool
    ip-protocol tcp
}
ltm virtual /Common/oa_vs {
    destination /Common/192.0.2.51:8080
    pool /Common/one_arm_pool
    ip-protocol tcp
}
'''


def _f5_net():
    """A BIG-IP (client VLAN on port 1.1, server VLAN on trunk trk1) cabled to switch S1 (1.1) and S2 (1.2 of the trunk)."""
    from features.topology import bigipdev
    from features.topology.extract import Device
    from features.topology.graph import Connection, Graph, Link
    from test_topology_bigip import _config
    f5 = bigipdev.read(_config() + F5_MAP, "lab-lb1.conf")
    f5.captured = True
    nodes = {f5.hostname: f5, "S1": Device(key="S1", hostname="S1", captured=True, role_hint="core"), "S2": Device(key="S2", hostname="S2", captured=True, role_hint="access")}
    for key, node in nodes.items():
        node.key = key
    one = Connection(f5.hostname, "S1", [Link(f5.hostname, "1.1", "S1", "Gi1/0/1", "confirmed", {"LLDP"}, "")])
    two = Connection(f5.hostname, "S2", [Link(f5.hostname, "1.2", "S2", "Gi1/0/1", "confirmed", {"LLDP"}, "")], "trk1", "")
    graph = Graph(nodes=nodes, links=[l for c in (one, two) for l in c.links], connections=[one, two], hidden_kinds=set())
    return graph


def test_the_f5_table_puts_every_member_on_a_vlan_a_cable_and_a_neighbor():
    from features.topology import f5zones
    table = {(r["virtual_server"], r["member"]): r for r in f5zones.rows(_f5_net())}
    web = table[("web_vs", "198.51.100.20:80")]
    assert (web["virtual_vlan"], web["member_vlan"], web["virtual_neighbors"], web["member_neighbors"]) == ("client", "server", "S1", "S2")
    assert web["deployment"].startswith("two-armed")
    assert table[("web_vs", "10.77.0.5:80")]["deployment"].startswith("routed") and table[("web_vs", "10.77.0.5:80")]["member_vlan"] == ""         # no self IP holds 10.77.0.5
    assert table[("oa_vs", "192.0.2.30:8080")]["deployment"].startswith("one-armed")                                                          # the virtual address and the member are on the client VLAN


def test_the_f5_table_carries_the_zone_of_the_neighbor_in_the_drawing():
    from features.topology import f5zones
    graph = _f5_net()
    placed = types.SimpleNamespace(zone="SERVER FARM")
    page = types.SimpleNamespace(nodes={"S2": placed, "S1": types.SimpleNamespace(zone="CORE")})
    rows = {r["member"]: r for r in f5zones.rows(graph, [page])}
    assert rows["198.51.100.20:80"]["member_zone"] == "SERVER FARM" and rows["198.51.100.20:80"]["virtual_zone"] == "CORE"
    assert f5zones.rows(graph) and all(r["member_zone"] == "" for r in f5zones.rows(graph))                                                      # no pages, no zones


def test_a_run_without_a_bigip_has_an_empty_f5_table():
    from features.topology import demo
    files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / "after").glob("*.txt"))]
    assert service.build_topology(files, view="physical", group="none")["f5_table"] == []


# ---- SD-WAN transport findings ----------------------------------------------------------------------------------------------------------------------------

def _sdwan_net(sessions_a, sessions_b=()):
    from features.topology.extract import Device
    from features.topology.graph import Graph
    nodes = {}
    for key, sessions in (("EDGE-A", sessions_a), ("EDGE-B", sessions_b)):
        node = Device(key=key, hostname=key, captured=True, role_hint="router")
        node.l3facts = {"overlay": sessions, "system_ip": "10.0.0.1" if key == "EDGE-A" else "10.0.0.2", "site_id": "100"}
        nodes[key] = node
    return Graph(nodes=nodes, links=[], connections=[], hidden_kinds=set())


def _bfd(system, site, local, remote, state="up"):
    return {"system_ip": system, "site_id": site, "local_color": local, "remote_color": remote, "state": state}


def test_bfd_sessions_that_are_down_are_listed_per_site_with_the_colours():
    from features.topology import findings
    graph = _sdwan_net([_bfd("10.0.1.1", "200", "mpls", "mpls"), _bfd("10.0.1.1", "200", "biz-internet", "biz-internet", "down"), _bfd("10.0.1.2", "300", "mpls", "mpls"), _bfd("10.0.1.2", "300", "biz-internet", "biz-internet")])
    rows = {r["id"]: r for r in findings._sdwan_findings(graph)}
    assert "TOPO-061" in rows and "site 200" in rows["TOPO-061"]["detail"] and "biz-internet > biz-internet" in rows["TOPO-061"]["detail"] and "site 300" not in rows["TOPO-061"]["detail"]
    assert rows["TOPO-061"]["reference"].startswith("https://www.cisco.com/c/en/us/td/docs/solutions/CVD/SDWAN/")


def test_a_site_reached_over_one_colour_is_reported_and_two_colours_are_not():
    from features.topology import findings
    two = _sdwan_net([_bfd("10.0.1.1", "200", "mpls", "mpls"), _bfd("10.0.1.1", "200", "biz-internet", "biz-internet"), _bfd("10.0.1.2", "300", "mpls", "mpls"), _bfd("10.0.1.2", "300", "biz-internet", "biz-internet")])
    assert findings._sdwan_findings(two) == []
    one = _sdwan_net([_bfd("10.0.1.1", "200", "mpls", "mpls"), _bfd("10.0.1.2", "300", "mpls", "mpls"), _bfd("10.0.1.2", "300", "biz-internet", "biz-internet")])
    rows = findings._sdwan_findings(one)
    assert [r["id"] for r in rows] == ["TOPO-062"] and "site 200" in rows[0]["detail"] and "site 300" not in rows[0]["detail"]


def test_a_run_without_an_overlay_has_no_sdwan_findings():
    from features.topology import findings
    assert findings._sdwan_findings(_sdwan_net([])) == []


# ---- the changes since an earlier run, marked on the drawing -----------------------------------------------------------------------------------------------

def _run_of(setid, **more):
    from features.topology import demo
    files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / setid).glob("*.txt"))]
    return service.build_topology(files, view="physical", group="none", **more)


def _loaded(result):
    from features.topology import diff
    from features.topology.service import to_json
    return diff.load_run(to_json(result["graph"], result["findings"], result["devices"], result["settings"]).encode("utf-8"))


def test_the_marks_name_new_changed_and_gone_devices_and_links():
    from features.topology import diffmark
    dev = lambda name, **kw: {"device": name, "captured": "yes", "role": "core", "model": "X", **kw}                                              # noqa: E731
    lnk = lambda a, pa, b, pb, **kw: {"device_a": a, "port_a": pa, "device_b": b, "port_b": pb, "state": "confirmed", **kw}                     # noqa: E731
    before = {"devices": [dev("A"), dev("B"), dev("C"), dev("OLD")], "links": [lnk("A", "1", "B", "1"), lnk("A", "2", "C", "1"), lnk("B", "2", "C", "2"), lnk("A", "9", "OLD", "1")]}
    after = {"devices": [dev("A"), dev("B", model="Y"), dev("C"), dev("NEW")], "links": [lnk("A", "1", "B", "1"), lnk("A", "2", "C", "1", state="single"), lnk("A", "5", "NEW", "1")]}
    marks = diffmark.collect(before, after, "run 1")
    assert marks.devices == {"B": "changed", "NEW": "added"} and marks.gone == ["OLD"]
    assert marks.links == {frozenset(("A", "C")): "changed", frozenset(("A", "NEW")): "added"}
    assert marks.removed_links == [("B", "C")]                                                                 # A-OLD left with its device: only links between devices still drawn are listed


def test_a_run_with_no_difference_gets_no_marks_and_the_same_picture():
    from features.topology import diffmark
    first = _run_of("before")
    marks = diffmark.collect(_loaded(first), _loaded(_run_of("before")))
    assert marks.empty
    plain = first["svgs"][0]["svg"]
    again = _run_of("before", compare_with=_loaded(first))["svgs"][0]["svg"]
    assert plain == again and "diff-note" not in again


def test_the_new_diagram_carries_the_marks_and_nothing_moves():
    earlier = _loaded(_run_of("before"))
    marked = _run_of("after", compare_with=earlier, compare_label="the earlier run (before.json)")
    plain = _run_of("after")
    assert {k: (p.x, p.y) for k, p in marked["pages"][0].nodes.items()} == {k: (p.x, p.y) for k, p in plain["pages"][0].nodes.items()}      # the layout is the one without marks
    svg = marked["svgs"][0]["svg"]
    assert "diff-note" in svg and "Changes since the earlier run (before.json)" in svg
    assert marked["marks"].devices or marked["marks"].links
    assert ("diff-added" in svg) == bool([1 for v in list(marked["marks"].devices.values()) + list(marked["marks"].links.values()) if v == "added"])
    height = lambda text: float(text.split('viewBox="')[1].split('"')[0].split()[3])                                                          # noqa: E731
    assert height(svg) == height(plain["svgs"][0]["svg"]) + 64                                                                                 # the note band is below the picture


# ---- the control evidence page -----------------------------------------------------------------------------------------------------------------------------

def test_the_new_findings_are_tagged_with_the_controls_they_are_evidence_for():
    from features.topology import evidence
    ids = {(f, c) for f, c, _ in evidence.controls_for("TOPO-059")}
    assert (evidence.PCI, "1.4.1") in ids and (evidence.NIST, "SC-7") in ids and (evidence.ISO, "A.8.22") in ids
    assert evidence.controls_for("TOPO-060") == evidence.controls_for("TOPO-059")
    assert (evidence.NIST, "CP-8(2)") in {(f, c) for f, c, _ in evidence.controls_for("TOPO-061")} and evidence.controls_for("TOPO-062") == evidence.controls_for("TOPO-061")


def test_the_control_page_groups_by_framework_escapes_text_and_says_it_is_no_assessment():
    from features.topology import evidence
    rows = evidence.control_rows([{"id": "TOPO-059", "severity": "high", "title": "zone <script>alert(1)</script> joined", "devices": ["FW1", "S1"]}], "Bank <b>DC</b>")
    page = evidence.control_page(rows, "Bank <b>DC</b>", "2026-11-10 10:00", 3)
    assert "<script>" not in page and "&lt;script&gt;" in page and "Bank &lt;b&gt;DC&lt;/b&gt;" in page
    assert evidence.PCI in page and "1.4.1" in page and "FW1, S1" in page and evidence.DISCLAIMER in page
    assert page.index(evidence.CIS) < page.index(evidence.NIST) < page.index(evidence.PCI) < page.index(evidence.ISO)       # the order of the frameworks is fixed
    assert "3 capture(s)" in page and "<script" not in page.lower().replace("&lt;script", "")


def test_the_pack_holds_the_control_evidence_page(tmp_path):
    import zipfile
    from features.topology import demo, routes
    files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / "after").glob("*.txt"))]
    result = service.build_topology(files, view="physical", group="none")
    tables = routes._write_run(tmp_path, result, "Demo", inputs=files)
    assert b"control evidence" in tables["pack"]["audit/control-evidence.html"]
    names = zipfile.ZipFile(tmp_path / "keystone-topology-pack.zip").namelist()
    assert any(n.endswith("audit/control-evidence.html") for n in names) and any(n.endswith("audit/controls.csv") for n in names)
    assert any(n.endswith("/topology.vsdx") for n in names) and (tmp_path / "topology.vsdx").read_bytes()[:2] == b"PK"        # the Visio drawing is saved with the run and in the pack


# ---- the Visio file ---------------------------------------------------------------------------------------------------------------------------------------

def test_the_vsdx_is_a_package_with_a_page_per_diagram_a_box_per_device_and_a_line_per_cable():
    import io
    import re
    import zipfile
    from xml.etree import ElementTree as ET
    from features.topology.vsdx import to_vsdx
    result = _run_of("after")
    page = result["pages"][0]
    archive = zipfile.ZipFile(io.BytesIO(to_vsdx(result["pages"], result["graph"], "speed")))
    names = set(archive.namelist())
    assert {"[Content_Types].xml", "_rels/.rels", "visio/document.xml", "visio/pages/pages.xml", "visio/pages/page1.xml", "visio/pages/_rels/pages.xml.rels"} <= names
    for name in names:
        ET.fromstring(archive.read(name))                                                                  # every part is well-formed XML
    xml = archive.read("visio/pages/page1.xml").decode("utf-8")
    shapes = len(re.findall(r"<Shape ", xml))
    assert shapes >= len(page.nodes) * 2 + len(page.connections)                                           # a box and a label for every device, a line for every cable
    for node in page.nodes:
        assert result["graph"].nodes[node].hostname in xml                                                 # the host name is on the page
    assert "Overview" in archive.read("visio/pages/pages.xml").decode("utf-8")


def test_a_text_with_markup_cannot_break_out_of_the_visio_xml():
    import io
    import zipfile
    from xml.etree import ElementTree as ET
    from features.topology.vsdx import to_vsdx
    result = _run_of("after")
    graph = result["graph"]
    first = next(iter(result["pages"][0].nodes))
    graph.nodes[first].hostname = 'X"><Shape ID="999"/>&<b>'
    archive = zipfile.ZipFile(io.BytesIO(to_vsdx(result["pages"], graph)))
    root = ET.fromstring(archive.read("visio/pages/page1.xml"))
    assert not [e for e in root.iter() if e.get("ID") == "999"]                                            # no shape was added by the host name


def test_libreoffice_opens_the_vsdx(tmp_path):
    import shutil
    import subprocess
    from features.topology.vsdx import to_vsdx
    office = shutil.which("soffice") or shutil.which("libreoffice")
    if not office:
        pytest.skip("LibreOffice is not installed")
    result = _run_of("after")
    (tmp_path / "t.vsdx").write_bytes(to_vsdx(result["pages"], result["graph"]))
    done = subprocess.run([office, "--headless", "--convert-to", "pdf", "--outdir", str(tmp_path), str(tmp_path / "t.vsdx")], capture_output=True, timeout=180)
    pdf = tmp_path / "t.pdf"
    assert pdf.is_file() and pdf.stat().st_size > 2000, done.stderr


def test_the_leftover_scan_reads_inside_the_visio_file_like_the_workbook():
    from features.topology import demo, routes
    from features.topology.vsdx import to_vsdx
    result = _run_of("after")
    graph = result["graph"]
    name = next(iter(result["pages"][0].nodes))
    graph.nodes[name].hostname = "SECRET-HOST-77"
    data = to_vsdx(result["pages"], graph)
    assert b"SECRET-HOST-77" not in data                                                                      # compressed: a plain search of the bytes finds nothing
    assert "SECRET-HOST-77" in routes._pack_texts({"topology.vsdx": data})["topology.vsdx"]                    # unpacked: the scan finds it
