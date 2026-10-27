"""Topology Builder v0.9: lines between site boxes go around the boxes in between.  Synthetic fixtures only."""

from __future__ import annotations

from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.layout import NODE_H, NODE_W, Placed
from features.topology.scene import Page, _clips, _route


def _page(n_lanes: int = 1) -> Page:
    """Three site boxes in a row (W, M, E); lines from W to E must not run through M."""
    nodes = {"W1": Placed(40, 100, 0), "E1": Placed(1040, 100, 0), "M1": Placed(540, 100, 0), "E2": Placed(1040, 300, 0), "W2": Placed(40, 300, 0)}
    devices = {k: Device(key=k, hostname=k, captured=True, role_hint="router", model="") for k in nodes}
    pairs = [("W1", "E1")] + [("W2", "E2")] * (n_lanes - 1)
    conns = [Connection(a, b, [Link(a, "Gi0/0", b, "Gi0/0", "confirmed", {"CDP"}, "")]) for a, b in pairs]
    graph = Graph(nodes=devices, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set(), vpc_pairs=[])
    page = Page("Overview", nodes=nodes)
    page.boxes = [("W", 0, 0, 200, 500), ("M", 500, 0, 200, 500), ("E", 1000, 0, 200, 500)]
    page.connections = graph.connections
    return page


def test_a_line_between_two_site_boxes_goes_around_the_box_in_between():
    page = _page()
    _route(page)
    centres = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}
    middle = (500, 0, 700, 500)
    points = [centres["W1"], *page.routes[0], centres["E1"]]
    assert page.routes[0], "the straight line crosses box M, so it needs waypoints"
    assert not any(_clips(middle, points[i], points[i + 1]) for i in range(len(points) - 1))


def test_a_line_that_does_not_cross_another_box_stays_straight():
    page = _page()
    page.connections = [Connection("W1", "W2", [Link("W1", "Gi0/0", "W2", "Gi0/0", "confirmed", {"CDP"}, "")])]
    _route(page)
    assert 0 not in page.routes


def test_lines_of_one_pair_of_boxes_take_their_own_lane():
    page = _page(4)
    page.connections = [Connection("W1", "E1", [Link("W1", "Gi0/0", "E1", f"Gi0/{i}", "confirmed", {"CDP"}, "")]) for i in range(3)]
    _route(page)
    firsts = {tuple(round(v) for v in page.routes[i][0]) for i in range(3)}
    assert len(firsts) == 3                                  # three lanes, not one line drawn three times


# ----------------------------------------------------------------------------------------------------------------- Palo Alto aggregate-ethernet
PAN_SET = """set deviceconfig system hostname FW-AE1
set network interface aggregate-ethernet ae1 layer3
set network interface aggregate-ethernet ae1 layer3 lacp enable yes
set network interface aggregate-ethernet ae1 layer3 ip 192.0.2.1/24
set network interface aggregate-ethernet ae1 comment "to core"
set network interface aggregate-ethernet ae1 layer3 units ae1.100 tag 100
set network interface aggregate-ethernet ae1 layer3 units ae1.100 ip 198.51.100.1/24
set network interface ethernet ethernet1/1 aggregate-group ae1
set network interface ethernet ethernet1/2 aggregate-group ae1
set network interface ethernet ethernet1/3 layer3 ip 203.0.113.1/30
set zone trust network layer3 [ ae1 ae1.100 ]
"""

PAN_XML = """<config version="11.1.0"><devices><entry name="localhost.localdomain">
<deviceconfig><system><hostname>FW-AE2</hostname></system></deviceconfig>
<network><interface>
<aggregate-ethernet><entry name="ae1"><layer3><lacp><enable>yes</enable><mode>active</mode></lacp><ip><entry name="192.0.2.1/24"/></ip>
<units><entry name="ae1.100"><tag>100</tag><ip><entry name="198.51.100.1/24"/></ip></entry></units></layer3><comment>to core</comment></entry></aggregate-ethernet>
<ethernet><entry name="ethernet1/1"><aggregate-group>ae1</aggregate-group></entry><entry name="ethernet1/2"><aggregate-group>ae1</aggregate-group></entry>
<entry name="ethernet1/3"><layer3><ip><entry name="203.0.113.1/30"/></ip></layer3></entry></ethernet>
</interface><virtual-router><entry name="default"><interface><member>ae1</member><member>ae1.100</member></interface></entry></virtual-router></network>
<vsys><entry name="vsys1"><import><network><interface><member>ae1</member><member>ae1.100</member><member>ethernet1/3</member></interface></network></import>
<zone><entry name="trust"><network><layer3><member>ae1</member><member>ae1.100</member></layer3></network></entry></zone></entry></vsys>
</entry></devices></config>"""

PAN_CURLY = """config {
  devices { localhost.localdomain {
    deviceconfig { system { hostname FW-AE3; } }
    network { interface {
      aggregate-ethernet { ae1 { layer3 { lacp { enable yes; } ip { 192.0.2.1/24; } } } }
      ethernet { ethernet1/1 { aggregate-group ae1; } ethernet1/2 { aggregate-group ae1; } }
    } }
  } }
}
"""


def _units(text, name):
    from features.topology import panosdev
    return panosdev.read_units(text, name)


def test_pan_aggregate_group_is_a_bundle_of_its_member_ports_in_set_format():
    (device,) = _units(PAN_SET, "fw.txt")
    assert device.bundles == {"ae1": ["Eth1/1", "Eth1/2"]}
    assert device.bundle_of == {"Eth1/1": "ae1", "Eth1/2": "ae1"}
    assert device.bundle_info["ae1"]["protocol"] == "LACP" and device.bundle_info["ae1"]["description"] == "to core"
    rows = {r["name"]: r for r in device.l3}
    assert rows["ae1"]["ip"] == "192.0.2.1" and rows["ae1.100"]["parent"] == "ae1"          # the address and the sub-interface stay on the group
    assert "Eth1/3" in device.unit_ports and "Eth1/3" not in device.bundle_of


def test_pan_aggregate_group_in_xml_export_with_virtual_router_and_zone():
    (device,) = _units(PAN_XML, "fw.xml")
    assert device.bundles == {"ae1": ["Eth1/1", "Eth1/2"]}
    rows = {r["name"]: r for r in device.l3}
    assert rows["ae1"]["vrf"] == "default" and rows["ae1"]["role"] == "trust"
    assert rows["ae1.100"]["vlan_id"] == 100 and rows["ae1.100"]["parent"] == "ae1"


def test_pan_aggregate_group_in_the_curly_cli_view():
    (device,) = _units(PAN_CURLY, "fw3.txt")
    assert device.bundles == {"ae1": ["Eth1/1", "Eth1/2"]} and device.bundle_info["ae1"]["protocol"] == "LACP"


def test_pan_aggregate_without_lacp_is_a_static_bundle():
    text = PAN_SET.replace("set network interface aggregate-ethernet ae1 layer3 lacp enable yes\n", "")
    (device,) = _units(text, "fw.txt")
    assert device.bundle_info["ae1"]["protocol"] == "static"


def test_pan_aggregate_members_follow_the_vsys_that_imports_the_group():
    xml = """<config><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>FWV</hostname></system></deviceconfig>
<network><interface><aggregate-ethernet><entry name="ae1"><layer3><ip><entry name="192.0.2.1/24"/></ip></layer3></entry></aggregate-ethernet>
<ethernet><entry name="ethernet1/1"><aggregate-group>ae1</aggregate-group></entry><entry name="ethernet1/5"><layer3><ip><entry name="203.0.113.1/30"/></ip></layer3></entry></ethernet></interface></network>
<vsys><entry name="vsys1"><import><network><interface><member>ae1</member></interface></network></import></entry>
<entry name="vsys2"><import><network><interface><member>ethernet1/5</member></interface></network></import></entry></vsys></entry></devices></config>"""
    by_unit = {d.unit: d for d in _units(xml, "fwv.xml")}
    assert set(by_unit) == {"vsys1", "vsys2"}
    assert "Eth1/1" in by_unit["vsys1"].unit_ports and "Eth1/1" not in by_unit["vsys2"].unit_ports


# ----------------------------------------------------------------------------------------------------------------- sites of a virtualised firewall
def test_the_units_of_one_firewall_chassis_share_one_site():
    from features.topology.layout import groups_of
    names = {"FW1 [DR-OL-FG]": "FW-DC", "FW1 [DR-MAIN-FG]": "FW-DC", "FW1 [root]": "FW-DC"}
    nodes = {k: Device(key=k, hostname=k, captured=True, role_hint="firewall", chassis=v) for k, v in names.items()}
    nodes["SW-A"] = Device(key="SW-A", hostname="SW-A", captured=True, role_hint="access")
    nodes["SW-B"] = Device(key="SW-B", hostname="SW-B", captured=True, role_hint="access")
    graph = Graph(nodes=nodes, links=[], connections=[], hidden_kinds=set(), vpc_pairs=[])
    groups = groups_of(graph, "prefix1")
    assert sorted(groups["FW"]) == sorted(names)                       # one site FW, not "FW1 [DR" and "FW1 [root]"
    assert sorted(groups["SW"]) == ["SW-A", "SW-B"]
