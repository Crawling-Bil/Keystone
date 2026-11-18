"""Topology v2.8: a saved run keeps its firewall interfaces, devices with two uplinks stand at the middle of them, lines into another zone slant out and drop.

Everything is built from small synthetic networks (names ``YY-``) and from the demo sets; no customer data.

Standards for the shape: Cisco Campus LAN and Wireless LAN Design Guide https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html ;
Cisco Massively Scalable Data Center (dual-homed leaf, spine pair) https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/white-paper-c11-743245.html
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from features.topology import demo, layout, roles, scene, service
from features.topology.corpus import BUILD
from features.topology.graph import build
from features.topology.state import device_from_state, device_to_state, devices_to_state, read_state

from test_topology_v23 import _dev


@pytest.fixture(autouse=True)
def _old_bus(monkeypatch):
    """These tests are about the bus (lanes) and the zone style of the lines; v3.0 draws a full mesh as straight lines instead (``scene.MESH_STRAIGHT``), the bus is kept behind the switch."""
    from features.topology import scene as _scene
    monkeypatch.setattr(_scene, "MESH_STRAIGHT", False)


def _demo_files(set_id: str):
    item = next(i for i in demo.list_sets() if i["id"] == set_id)
    return item, [(f["name"], demo.read_file(set_id, f["name"]).decode("utf-8")) for f in item["files"]]


# ---- a saved run keeps what a firewall knows about its interfaces ---------------------------------------------------------------------------------------------

def test_the_interfaces_and_zones_of_a_firewall_survive_a_saved_run():
    """fw_ifaces is a list of dicts: it was read back as the text of each dict, and the zone check of a reopened run failed on it."""
    item, files = _demo_files("dcdrc")
    built = service.build_topology(files, **{**BUILD, "group": item.get("group", "none")})
    firewalls = [d for d in built["devices"] if d.captured and d.fw_ifaces]
    assert firewalls, "the demo set must hold a firewall with interfaces"
    for device in firewalls:
        back = device_from_state(json.loads(json.dumps(device_to_state(device))))
        assert back.fw_ifaces == device.fw_ifaces
        assert all(isinstance(row, dict) for row in back.fw_ifaces)


def test_every_field_of_a_device_comes_back_from_a_saved_run():
    """The general rule behind the test above: a field that changes in a round trip is a field that a reopened run reads wrongly (tuples come back as lists, which is the same data)."""
    def plain(value):
        if isinstance(value, dict):
            return {k: plain(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [plain(v) for v in value]
        if isinstance(value, set):
            return sorted(plain(v) for v in value)
        return value
    for set_id in ("dcdrc", "multisite"):
        item, files = _demo_files(set_id)
        built = service.build_topology(files, **{**BUILD, "group": item.get("group", "none")})
        for device in built["devices"]:
            if not device.captured:
                continue
            back = device_from_state(json.loads(json.dumps(device_to_state(device))))
            for field in dataclasses.fields(device):
                if field.name in ("key", "carried", "role_hint", "captured"):
                    continue
                assert plain(getattr(back, field.name)) == plain(getattr(device, field.name)), f"{device.hostname}.{field.name}"


@pytest.mark.parametrize("set_id", [item["id"] for item in demo.list_sets()])
def test_a_saved_run_builds_again_with_the_same_roles_and_firewall_zone_map(set_id):
    """A reopened run (Add to a previous run) is the same network: a PAN-OS firewall came back as an aggregation switch (the role of a firewall was not saved) and its zone map lost 16 of 44 rows."""
    item, files = _demo_files(set_id)
    options = {**BUILD, "group": item.get("group", "none")}
    first = service.build_topology(files, **options)
    saved = json.dumps({"state": devices_to_state(first["devices"])}).encode()
    again = service.build_topology([], devices=read_state(saved), **options)
    assert {n.hostname: n.role_hint for n in again["graph"].nodes.values()} == {n.hostname: n.role_hint for n in first["graph"].nodes.values()}
    assert again["fw_zone_map"] == first["fw_zone_map"]
    assert again["fw_bypass"] == first["fw_bypass"]


def test_only_the_roles_that_a_reader_knows_are_saved():
    item, files = _demo_files("dcdrc")
    built = service.build_topology(files, **{**BUILD, "group": item.get("group", "none")})
    saved = {d.hostname: device_to_state(d) for d in built["devices"] if d.captured}
    assert any(s.get("role_hint") == "firewall" for s in saved.values())
    assert all(s.get("role_hint", "firewall") in ("firewall", "loadbalancer") for s in saved.values()), "a switch or router role is worked out again from the name, the model and the cables"


# ---- a device with two uplinks stands at the middle of them -----------------------------------------------------------------------------------------------------

def _dual_net():
    """A core pair over four distribution switches, each with one closet under it.  Two more closets are cabled to two distribution switches each: YY-ZA to the last two, YY-ZB
    to the first two.  By name ZA comes first and ZB second; by their uplinks it is the other way round."""
    core = ["YY-CORE1", "YY-CORE2"]
    devices = [_dev(c, "N9K-C93180YC-FX3", [x for x in core if x != c] + [f"YY-D{i}" for i in range(1, 5)]) for c in core]
    devices += [_dev(f"YY-D{i}", "C9500-24Y4C", core + [f"YY-A{i}"] + (["YY-ZB"] if i <= 2 else ["YY-ZA"])) for i in range(1, 5)]
    devices += [_dev(f"YY-A{i}", "C9300-24T", [f"YY-D{i}"], hosts=2) for i in range(1, 5)]
    devices += [_dev("YY-ZA", "C9300-24T", ["YY-D3", "YY-D4"], hosts=2), _dev("YY-ZB", "C9300-24T", ["YY-D1", "YY-D2"], hosts=2)]
    graph = build(devices)
    roles.classify(graph)
    return graph


def _x(placed, graph, name):
    return next(p.x for k, p in placed.items() if graph.nodes[k].hostname == name)


def test_a_closet_with_two_uplinks_stands_under_the_middle_of_them_not_after_the_closet_that_comes_before_it_by_name():
    graph = _dual_net()
    placed, _, _ = layout.layered(graph, list(graph.nodes))
    assert _x(placed, graph, "YY-ZB") < _x(placed, graph, "YY-ZA")
    left = (_x(placed, graph, "YY-D1") + _x(placed, graph, "YY-D2")) / 2
    right = (_x(placed, graph, "YY-D3") + _x(placed, graph, "YY-D4")) / 2
    assert abs(_x(placed, graph, "YY-ZB") - left) < abs(_x(placed, graph, "YY-ZB") - right)
    assert abs(_x(placed, graph, "YY-ZA") - right) < abs(_x(placed, graph, "YY-ZA") - left)


def test_the_route_and_ip_pages_keep_the_old_order():
    """Mutation check of the switch: with ``middle`` off (the logical pages) the closets keep the order of their names."""
    graph = _dual_net()
    placed, _, _ = layout.layered(graph, list(graph.nodes), middle=False)
    assert _x(placed, graph, "YY-ZB") > _x(placed, graph, "YY-ZA")


# ---- lines into another zone ----------------------------------------------------------------------------------------------------------------------------------

def _hq_page():
    item, files = _demo_files("multisite")
    built = service.build_topology(files, **{**BUILD, "group": item.get("group", "none")})
    return next(p for p in built["pages"] if p.name == "HQ")


def _cross_zone(page):
    return [(i, c) for i, c in enumerate(page.connections) if page.nodes.get(c.a) and page.nodes.get(c.b) and page.nodes[c.a].zone_id and page.nodes[c.b].zone_id and page.nodes[c.a].zone_id != page.nodes[c.b].zone_id]


def test_a_line_from_the_core_into_another_zone_slants_out_and_drops_straight_into_the_child():
    page = _hq_page()
    drops = []
    for index, conn in _cross_zone(page):
        route = page.routes.get(index)
        if route and len(route) >= 2 and abs(route[-2][0] - route[-1][0]) < 0.01 and abs(route[-1][1] - route[-2][1]) > 100:
            drops.append(index)
    assert len(drops) >= 3, "the core of the demo site is cabled into its user zone and its server zone: those lines drop"
    assert not [i for i, _ in _cross_zone(page) if i in page.bus], "no lane along the row of the core into another zone"


def test_the_zone_style_is_what_removes_the_lanes(monkeypatch):
    """Mutation check: when the zone style is never accepted, the lines into another zone go back to the bus (the lanes along the row of the core)."""
    monkeypatch.setattr(scene, "ZONE_LINE_SLACK", 0.0)
    monkeypatch.setattr(scene, "ZONE_LINE_PLUS", -10 ** 6)
    page = _hq_page()
    assert [i for i, _ in _cross_zone(page) if i in page.bus], "without the zone style the bus lines of the demo core run into the other zones"


def test_the_zone_style_goes_back_to_the_bus_when_it_puts_a_line_through_an_icon(monkeypatch):
    """Mutation check of the guard: when the zone style scores one more line through an icon than the bus style, the page keeps the bus."""
    real = scene.score_page

    def worse_without_bus(page):
        score = dict(real(page))
        if not page.bus:
            score["through"] += 1
        return score
    monkeypatch.setattr(scene, "score_page", worse_without_bus)
    page = _hq_page()
    assert [i for i, _ in _cross_zone(page) if i in page.bus]


def test_the_zone_style_never_adds_a_line_through_an_icon():
    from features.topology.layoutscore import score_page
    item, files = _demo_files("multisite")
    built = service.build_topology(files, **{**BUILD, "group": item.get("group", "none")})
    for page in [p for p in built["pages"] if p.name in ("HQ", "BAL", "MED")] + [p for p in built["l3_pages"] if p.name in ("HQ · L3 over L2", "Overview · L3 over L2")]:
        assert score_page(page)["through"] == 0, page.name


# ---- subnet and cloud icons keep off cable lines ----------------------------------------------------------------------------------------------------------------

def test_a_subnet_icon_does_not_stand_on_a_cable_line():
    from features.topology.layout import NODE_H, NODE_W
    from features.topology.satellites import Extra, place
    from features.topology.scene import _clips
    fixed = {"A": (0.0, 0.0), "B": (1000.0, 600.0)}                                  # two devices far apart, one cable between them
    cable = [[(NODE_W / 2, NODE_H / 2), (1000.0 + NODE_W / 2, 600.0 + NODE_H / 2)]]
    extras = [Extra("SEG", ["A", "B"])]
    free = place(fixed, extras)["SEG"]                                                # as before: the middle of the two, which is on their line
    kept = place(fixed, extras, cable)["SEG"]
    box = lambda x, y: (x, y, x + NODE_W, y + NODE_H)
    assert _clips(box(*free), *cable[0]), "without the lines the subnet stands in the middle, on the cable"
    assert not _clips(box(*kept), *cable[0]), "with the lines it stands beside the cable"


def test_a_page_with_no_spot_clear_of_the_cables_is_placed_as_before():
    from features.topology.satellites import Extra, place
    fixed = {"A": (0.0, 0.0), "B": (1000.0, 0.0)}
    wall = [[(x, -5000.0), (x, 5000.0)] for x in range(-5000, 6000, 40)]               # a cable every 40 px: no icon fits between two of them
    got = place(fixed, [Extra("SEG", ["A", "B"])], wall)
    assert set(got) == {"SEG"}
