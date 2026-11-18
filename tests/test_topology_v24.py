"""Topology v2.4: zones per way out, children under their own parent, floors with zones.

Everything is built from small synthetic networks (names ``YY-``, ``QQ-``, ``FL-``); no customer data.  The rules are about roles, functions and cables, not names of a site.

Standards for the shape: Cisco Campus LAN and Wireless LAN Design Guide https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html ;
Cisco Massively Scalable Data Center (spine/leaf and the pair of border leaves) https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/white-paper-c11-743245.html
"""

from __future__ import annotations

import pytest

from features.topology import hosts, layout, roles, service, zones
from features.topology.extract import Device
from features.topology.graph import build

from test_topology_v23 import _dev


# ---- synthetic networks -------------------------------------------------------------------------------------------------------------------------------

def _edge_net(outs=(("YY-RTW1", "wan"), ("YY-RTW2", "wan"), ("YY-INET1", "internet"), ("YY-PTNR1", "partner")), leaf: bool = True, accs: int = 0):
    """A core pair, an aggregation pair with two top-of-rack switches, an edge switch cabled to the core and to the routers ``outs`` (each a way out: the function is told by the name words, see functions.py),
    optionally a captured router behind the internet router (an ISP gateway) and ``accs`` access switches cabled to the core only."""
    core = ["YY-CORE1", "YY-CORE2"]
    names = [n for n, _ in outs]
    devices = [_dev(c, "N9K-C93180YC-FX3", [x for x in core if x != c] + ["YY-AGG1", "YY-AGG2", "YY-EDGE1"] + [f"YY-ACC{i}" for i in range(1, accs + 1)]) for c in core]
    devices += [_dev("YY-AGG1", "C9500-24Y4C", core + ["YY-AGG2", "YY-TOR1", "YY-TOR2"]), _dev("YY-AGG2", "C9500-24Y4C", core + ["YY-AGG1", "YY-TOR1", "YY-TOR2"])]
    devices += [_dev(t, "C9300-24T", ["YY-AGG1", "YY-AGG2"], hosts=2) for t in ("YY-TOR1", "YY-TOR2")]
    devices += [_dev(f"YY-ACC{i}", "C9300-24T", core) for i in range(1, accs + 1)]
    devices.append(_dev("YY-EDGE1", "C9300-24T", core + names, function="edge"))
    inet = next((n for n in names if "INET" in n), None)
    devices += [_dev(n, "ASR1002-X", ["YY-EDGE1"] + (["YY-GWX"] if leaf and n == inet else []), role="router", function=f) for n, f in outs]
    if leaf and inet:
        devices.append(_dev("YY-GWX", "ISR4331", [inet], role="router"))
    graph = build(devices)
    roles.classify(graph)
    return graph


def _zone_of(plan, graph, hostname):
    return next(z for z in plan.zones if any(graph.nodes[k].hostname == hostname for k in z.members))


def _names(graph, zone):
    return sorted(graph.nodes[k].hostname for k in zone.members)


# ---- every way out is a zone of its own -----------------------------------------------------------------------------------------------------------------

def test_a_hub_edge_switch_stands_alone_and_each_way_out_is_a_zone_with_its_own_routers():
    graph = _edge_net()
    plan = zones.plan(graph, list(graph.nodes))
    assert _names(graph, _zone_of(plan, graph, "YY-EDGE1")) == ["YY-EDGE1"]
    assert _names(graph, _zone_of(plan, graph, "YY-RTW1")) == ["YY-RTW1", "YY-RTW2"]
    assert _names(graph, _zone_of(plan, graph, "YY-INET1")) == ["YY-GWX", "YY-INET1"]          # the router behind the internet router goes with it
    assert _names(graph, _zone_of(plan, graph, "YY-PTNR1")) == ["YY-PTNR1"]
    titles = {z.title for z in plan.zones if z.kind == "external"}
    assert {"EDGE", "WAN / BRANCH", "INTERNET / PUBLIC", "EXTRANET / 3RD PARTY"} <= titles


MOSTLY_WAN = (("YY-RTW1", "wan"), ("YY-RTW2", "wan"), ("YY-RTW3", "wan"), ("YY-INET1", "internet"))


def test_an_edge_switch_that_serves_mostly_one_way_out_keeps_it_and_the_other_way_out_is_apart():
    graph = _edge_net(outs=MOSTLY_WAN, leaf=False)
    plan = zones.plan(graph, list(graph.nodes))
    assert _zone_of(plan, graph, "YY-EDGE1") is _zone_of(plan, graph, "YY-RTW1")
    assert _zone_of(plan, graph, "YY-RTW3").title == "WAN / BRANCH"
    assert _names(graph, _zone_of(plan, graph, "YY-INET1")) == ["YY-INET1"]
    assert 0.75 >= zones.DEDICATED_SHARE


def test_the_share_that_makes_an_edge_switch_dedicated_is_what_decides(monkeypatch):
    """Mutation check: with a share nobody reaches, the same edge switch is a hub and stands alone."""
    monkeypatch.setattr(zones, "DEDICATED_SHARE", 1.01)
    graph = _edge_net(outs=MOSTLY_WAN, leaf=False)
    plan = zones.plan(graph, list(graph.nodes))
    assert _names(graph, _zone_of(plan, graph, "YY-EDGE1")) == ["YY-EDGE1"]


def test_a_zone_is_titled_by_its_way_out_not_by_a_word_in_a_device_name():
    """A router named PUBLIC in a WAN zone does not make it the internet."""
    outs = (("YY-RTW1", "wan"), ("YY-PUBLICW", "wan"), ("YY-INET1", "internet"))
    graph = _edge_net(outs=outs, leaf=False)
    plan = zones.plan(graph, list(graph.nodes))
    zone = _zone_of(plan, graph, "YY-PUBLICW")
    assert zone is _zone_of(plan, graph, "YY-RTW1")
    assert zone.title == "WAN / BRANCH"
    assert _zone_of(plan, graph, "YY-INET1").title == "INTERNET / PUBLIC"


def test_access_switches_that_hang_from_the_core_alone_share_one_lan_zone():
    graph = _edge_net(accs=2)
    plan = zones.plan(graph, list(graph.nodes))
    lan = _zone_of(plan, graph, "YY-ACC1")
    assert lan is _zone_of(plan, graph, "YY-ACC2") and lan.kind == "internal"
    assert lan.title == "LAN / USER"


# ---- floors ---------------------------------------------------------------------------------------------------------------------------------------------

def _floor():
    devices = [_dev("FL-SW1", "C9300-48P", ["FL-DS", "FL-SW2"], hosts=6), _dev("FL-SW2", "C9200-24P", ["FL-SW1"], hosts=4), _dev("FL-DS", "C9500-24Y4C", ["FL-SW1"])]
    graph = build(devices)
    roles.classify(graph)
    return graph


def test_a_floor_whose_uplink_is_at_another_site_gets_zones_round_its_switch():
    graph = _floor()
    keys = list(graph.nodes)
    plan = zones.plan(graph, keys, ghosts={"FL-DS"})
    assert plan is not None
    assert {graph.nodes[k].hostname for k in plan.centre} == {"FL-SW1"}
    kinds = {z.kind for z in plan.zones}
    assert "ghost" in kinds and "internal" in kinds


def test_a_small_network_with_no_core_and_no_other_site_keeps_the_plain_rows():
    graph = _floor()
    why: list[str] = []
    assert zones.plan(graph, list(graph.nodes), why=why) is None and why


# ---- children stand under their own parent ----------------------------------------------------------------------------------------------------------

def _tor_net():
    devices = [_dev("QQ-AGG1", "C9500-24Y4C", ["QQ-TORA", "QQ-TORB"]), _dev("QQ-AGG2", "C9500-24Y4C", ["QQ-TORA", "QQ-TORB"]),
               _dev("QQ-TORA", "C9300-24T", ["QQ-AGG1", "QQ-AGG2"], hosts=10), _dev("QQ-TORB", "C9300-24T", ["QQ-AGG1", "QQ-AGG2", "QQ-TORC"], hosts=3),
               _dev("QQ-TORC", "C9300-24T", ["QQ-TORB"], hosts=3)]
    graph = build(devices)
    roles.classify(graph)
    graph.group_endpoints = True
    return graph


def test_the_frame_of_end_points_is_a_grid_under_its_switch():
    graph = _tor_net()
    placed, _, _ = layout.layered(graph, list(graph.nodes))
    mine = [p for k, p in placed.items() if p.box == "QQ-TORA"]
    assert len(mine) == 10
    assert len({round(p.x) for p in mine}) == layout.frame_columns(10)               # every line of the grid stands on the same columns
    assert len({round(p.y) for p in mine}) == -(-10 // layout.frame_columns(10))


def test_a_grid_stays_a_grid_in_a_row_that_also_holds_a_switch_with_a_frame_of_its_own():
    """The tiers of a zone block put the end points of one switch in the row of a switch below another one: the row is fitted frame by frame, not icon by icon (which stretched every
    grid into one long staircase, each line a step further right)."""
    graph = _tor_net()
    forced = {k: (0.0 if "AGG" in k else 1.0 if k in ("QQ-TORA", "QQ-TORB") else 2.0 if k == "QQ-TORC" or "TORAX" in k or "TORBX" in k else 3.0) for k in graph.nodes}
    placed, _, _ = layout.layered(graph, list(graph.nodes), forced=forced)
    mine = [p for p in placed.values() if p.box == "QQ-TORA"]
    assert len(mine) == 10
    assert len({round(p.x) for p in mine}) == layout.frame_columns(10)
    tora = next(p for k, p in placed.items() if k == "QQ-TORA")
    assert min(p.x for p in mine) - 150 <= tora.x <= max(p.x for p in mine) + 150          # the switch stands over its own grid
    toraC = next(p for k, p in placed.items() if k == "QQ-TORC")
    assert toraC.x > max(p.x for p in mine)                                                 # the other switch of the row stands beside the frame, not in it


# ---- a run that is built twice counts once ------------------------------------------------------------------------------------------------------------

def test_wireless_clients_are_counted_again_not_added_when_the_tables_are_read_twice():
    from test_aruba_parsing_and_topology_checks import _wireless_files
    result = service.build_topology(_wireless_files(5), include_hosts=True)
    graph = result["graph"]
    devices = {d.key: d for d in result["devices"]}
    before = sum(devices["WL-SW1"].wireless_clients.values())
    hosts.collect(graph, devices)
    hosts.collect(graph, devices)
    assert sum(devices["WL-SW1"].wireless_clients.values()) == before == 5


def test_fitting_a_row_icon_by_icon_stretches_the_grid_again(monkeypatch):
    """Mutation check of the test above: without the unit per frame the row is the old one, and the grid becomes a staircase."""
    monkeypatch.setattr(layout, "_collapse_frames", lambda items, want, gaps, spot, frame_of, xstep: (items, gaps, {k: want[k] for k in items if k in want}, {}))
    graph = _tor_net()
    forced = {k: (0.0 if "AGG" in k else 1.0 if k in ("QQ-TORA", "QQ-TORB") else 2.0 if k == "QQ-TORC" or "TORAX" in k or "TORBX" in k else 3.0) for k in graph.nodes}
    placed, _, _ = layout.layered(graph, list(graph.nodes), forced=forced)
    mine = [p for p in placed.values() if p.box == "QQ-TORA"]
    assert len({round(p.x) for p in mine}) > layout.frame_columns(10)
