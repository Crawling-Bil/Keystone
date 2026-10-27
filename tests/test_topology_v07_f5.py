"""Topology Builder v0.7-F: the F5 map page (virtual servers round the BIG-IP, pools with their members, nodes, VLAN / interface tables).  Synthetic fixtures."""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from features.topology import f5page
from features.topology.extract import Device
from features.topology.graph import Graph
from features.topology.service import build_topology, read_devices

FIXTURES = Path(__file__).parent / "fixtures" / "loadbalancer"
LIVE = (FIXTURES / "bigip_capture_live_members_synthetic.txt").read_text(encoding="utf-8")
CONFIG_ONLY = (FIXTURES / "bigip_capture_synthetic.txt").read_text(encoding="utf-8")


@pytest.fixture()
def client():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _tree(virtuals: int, pools: int = 3, members: int = 2) -> list[dict]:
    """A synthetic Network Map tree: ``virtuals`` virtual servers, each with the default pool ``pool_i % pools``; pool members share addresses across pools."""
    out, n = [], 0
    for i in range(virtuals):
        vid = f"v{i}"
        out.append({"id": vid, "parent": "", "type": "virtual", "name": f"vs_{i:02d}", "status": "available", "badge": f"10.0.0.{i + 1}:443", "source": "config", "reason": "", "facts": {"Destination": f"10.0.0.{i + 1}:443"}})
        pool = f"pool_{i % pools}"
        pid = f"p{i}"
        out.append({"id": pid, "parent": vid, "type": "pool", "name": pool, "status": "available", "badge": f"{members} member(s)", "source": "config", "reason": "", "facts": {}})
        for m in range(members):
            out.append({"id": f"e{i}-{m}", "parent": pid, "type": "member", "name": f"192.0.2.{m + 1}:80", "status": "unverified", "badge": "", "source": "config", "reason": "",
                        "facts": {"Address": f"192.0.2.{m + 1}", "Port": "80", "Pool": pool}})
    return out


def _graph(tree: list[dict]) -> Graph:
    device = Device(key="LB1", hostname="LB1", captured=True, role_hint="loadbalancer", model="BIG-IP")
    device.l3facts = {"f5": {"map": tree, "vlans": [], "interfaces": [], "trunks": {}}}
    return Graph(nodes={"LB1": device})


# ----------------------------------------------------------------------------------------------------------- layout
def test_virtual_servers_go_round_the_bigip_left_right_top_left_top_right():
    page = f5page.page_for(_graph(_tree(4)), "LB1")
    externals = [s for s in page.shapes if s.kind == "external"]
    lb = page.nodes["LB1"]
    centre = lb.x + 38
    left, right, top_left, top_right = externals
    assert left.x + left.w < centre and right.x > centre                   # first two: left and right column
    assert top_left.y + top_left.h < lb.y and top_right.y + top_right.h < lb.y      # the next two sit above the BIG-IP
    assert top_left.x + top_left.w <= centre and top_right.x >= centre


def test_a_side_column_holds_at_most_eight_and_the_rest_goes_on_top():
    page = f5page.page_for(_graph(_tree(40)), "LB1")
    externals = [s for s in page.shapes if s.kind == "external"]
    lb = page.nodes["LB1"]
    assert len(externals) == 40
    columns: dict[float, int] = {}
    for s in externals:
        if s.y + s.h > lb.y:                                                 # beside or below the BIG-IP: a side column
            columns[s.x] = columns.get(s.x, 0) + 1
    assert set(columns.values()) == {8}


def test_shapes_do_not_overlap():
    for n in (1, 5, 26, 90):
        page = f5page.page_for(_graph(_tree(n, pools=7, members=3)), "LB1")
        boxes = [(s.x, s.y, s.x + s.w, s.y + s.h) for s in page.shapes if s.kind in ("external", "member", "node")]
        lb = page.nodes["LB1"]
        boxes.append((lb.x, lb.y, lb.x + 76, lb.y + 76))
        for i, a in enumerate(boxes):
            for b in boxes[i + 1:]:
                assert a[2] <= b[0] + 0.5 or b[2] <= a[0] + 0.5 or a[3] <= b[1] + 0.5 or b[3] <= a[1] + 0.5, (n, a, b)


def test_a_pool_that_several_virtual_servers_use_is_drawn_once_with_its_members_inside():
    page = f5page.page_for(_graph(_tree(6, pools=2, members=2)), "LB1")
    pools = [s for s in page.shapes if s.kind == "pool"]
    assert sorted(p.lines[0] for p in pools) == ["pool_0", "pool_1"]
    assert "used by 3 virtual server(s)" in pools[0].lines[1]
    for pool in pools:
        inside = [s for s in page.shapes if s.kind == "member" and s.attrs["pool"] == pool.lines[0]]
        assert len(inside) == 2 and all(pool.x <= m.x and m.x + m.w <= pool.x + pool.w and pool.y <= m.y and m.y + m.h <= pool.y + pool.h for m in inside)


def test_nodes_are_one_box_per_member_address_below_the_pools():
    page = f5page.page_for(_graph(_tree(6, pools=2, members=2)), "LB1")
    nodes = [s for s in page.shapes if s.kind == "node"]
    assert sorted(n.lines[0] for n in nodes) == ["192.0.2.1", "192.0.2.2"]
    assert all(n.y > max(s.y + s.h for s in page.shapes if s.kind == "pool") for n in nodes)


def test_lines_join_every_external_to_the_bigip_and_the_bigip_to_the_pool_group_to_the_node_group():
    page = f5page.page_for(_graph(_tree(5)), "LB1")
    ends = {(e.a, e.b) for e in page.shape_edges}
    assert sum(1 for a, b in ends if b == "node:LB1") == 5
    assert ("node:LB1", "g-pools") in ends and ("g-pools", "g-nodes") in ends
    ids = {s.ident for s in page.shapes}
    assert all((e.a in ids or e.a == "node:LB1") and (e.b in ids or e.b == "node:LB1") for e in page.shape_edges)


def test_a_unit_with_nothing_to_map_has_no_page():
    assert f5page.page_for(_graph([]), "LB1") is None
    assert f5page.f5_pages(Graph(nodes={"SW": Device(key="SW", hostname="SW", captured=True, role_hint="core")})) == []


def test_a_big_unit_gets_wider_top_blocks_not_a_taller_page():
    small, big = f5page.page_for(_graph(_tree(30)), "LB1"), f5page.page_for(_graph(_tree(150)), "LB1")
    assert big.width > small.width
    assert big.height < small.height * 5


# ----------------------------------------------------------------------------------------------------------- real reading
def test_the_synthetic_bigip_capture_makes_a_map_page_with_live_member_state():
    devices, _ = read_devices([("lb.txt", LIVE)])
    facts = devices[0].l3facts["f5"]
    kinds = {n["type"] for n in facts["map"]}
    assert {"virtual", "pool", "member"} <= kinds
    assert "monitor" not in kinds                                           # monitors are leaves of every member and stay in the Load Balancer Analyzer
    assert {n["status"] for n in facts["map"] if n["type"] == "member"} >= {"available", "offline", "forced down"}


def test_config_only_capture_says_configured_not_available():
    devices, _ = read_devices([("lb.txt", CONFIG_ONLY)])
    members = [n for n in devices[0].l3facts["f5"]["map"] if n["type"] == "member"]
    assert members and {n["status"] for n in members} <= {"unverified", "unknown", "forced down", "disabled", "parent disabled"}


def test_the_page_carries_the_vlan_and_interface_tables():
    result = build_topology([("lb.txt", LIVE)], view="f5map")
    page = next(p for p in result["svgs"] if p["view"] == "f5map")
    assert "VLANs and self IPs" in page["svg"] and "Interfaces" in page["svg"]


def test_build_with_f5_map_view_draws_the_page_in_svg_and_drawio():
    result = build_topology([("lb.txt", LIVE)], view="f5map")
    assert [p["view"] for p in result["svgs"]].count("f5map") == 1
    xml = ET.fromstring(result["drawio"])
    names = [d.get("name") for d in xml.findall("diagram")]
    assert any(n.startswith("F5 map") for n in names)
    diagram = next(d for d in xml.findall("diagram") if d.get("name", "").startswith("F5 map"))
    objects = {o.get("object"): 0 for o in diagram.iter("object")}
    for o in diagram.iter("object"):
        objects[o.get("object")] = objects.get(o.get("object"), 0) + 1
    assert {"Virtual server", "Pool", "Pool member", "Node"} <= set(objects)
    ids = [c.get("id") for c in diagram.iter() if c.get("id")]
    assert len(ids) == len(set(ids))
    cells = {c.get("id") for c in diagram.iter() if c.tag in ("mxCell", "object")}
    for cell in diagram.iter("mxCell"):
        for end in ("source", "target"):
            if cell.get(end):
                assert cell.get(end) in cells, (end, cell.get(end))


def test_lines_lie_under_the_boxes_in_drawio():
    result = build_topology([("lb.txt", LIVE)], view="f5map")
    diagram = next(d for d in ET.fromstring(result["drawio"]).findall("diagram") if d.get("name", "").startswith("F5 map"))
    order = [c for c in diagram.find("mxGraphModel/root")]
    first_edge = next(i for i, c in enumerate(order) if c.tag == "mxCell" and c.get("edge") == "1" or (c.tag == "object" and any(m.get("edge") == "1" for m in c.findall("mxCell"))))
    last_edge = max(i for i, c in enumerate(order) if c.tag == "mxCell" and c.get("edge") == "1")
    first_box = next(i for i, c in enumerate(order) if c.tag == "object" and c.get("object"))
    assert last_edge < first_box and first_edge < first_box


def test_all_views_has_the_f5_map_last_and_a_switch_only_build_has_none():
    with_lb = build_topology([("lb.txt", LIVE)], view="all")
    assert [p["view"] for p in with_lb["svgs"]][-1] == "f5map"
    from tests.topology_samples import iosxe_capture
    plain = build_topology([("sw.txt", iosxe_capture("SW1", "FOC00000091", "10.9.0.1", cdp=[]))], view="all")
    assert "f5map" not in [p["view"] for p in plain["svgs"]]


def test_the_view_can_be_chosen_in_the_form(client):
    data = {"files": [(io.BytesIO(LIVE.encode("utf-8")), "lb.txt")], "view": "f5map"}
    body = client.post("/topology/api/build", data=data, content_type="multipart/form-data").get_json()
    assert body["ok"] and any(p["view"] == "f5map" for p in body["pages"])
    assert body["legend"]["f5map"] and any("virtual servers" in row[1] for row in body["legend"]["f5map"])


# ----------------------------------------------------------------------------------------------------------- vCMP
VCMP_HOST = (FIXTURES / "bigip_vcmp_host_synthetic.conf").read_text(encoding="utf-8")


def test_a_vcmp_host_configuration_is_one_load_balancer_node_per_guest():
    devices, skipped = read_devices([("host.conf", VCMP_HOST)])
    assert skipped == [] and [d.hostname for d in devices] == ["LTM-WEB-01", "LTM-APP-01"]
    web, app = devices
    assert web.chassis == app.chassis == "VCMP-HOST-01" and web.role_hint == "loadbalancer" and web.vendor == "F5"
    assert (web.mgmt_ip, app.mgmt_ip) == ("192.0.2.21", "192.0.2.22")
    assert web.unit_ports >= {"1.1", "1.2", "trk_uplink"} and app.unit_ports >= {"1.3"} and "1.3" not in web.unit_ports
    assert web.bundles == {"trk_uplink": ["1.1", "1.2"]} and web.l3facts["f5"]["vcmp"]["state"] == "deployed"


def test_a_switch_neighbor_of_the_host_lands_on_the_guest_whose_vlans_use_the_port():
    from features.topology.extract import HalfEdge
    from features.topology.graph import build
    devices, _ = read_devices([("host.conf", VCMP_HOST)])
    switch = Device(key="", hostname="CORE-SW", captured=True)
    switch.halves.append(HalfEdge(local_port="Eth1/1", remote_name="vcmp-host-01.lab.example", remote_port="1.3", protocols={"LLDP"}))
    switch.halves.append(HalfEdge(local_port="Eth1/2", remote_name="vcmp-host-01.lab.example", remote_port="1.1", protocols={"LLDP"}))
    g = build([switch, *devices])
    assert {(l.a_port, l.b) for l in g.links} == {("Eth1/1", "LTM-APP-01"), ("Eth1/2", "LTM-WEB-01")}


def test_the_guests_own_capture_replaces_its_stub_from_the_host():
    own = LIVE.replace("lb-hq-01", "ltm-web-01").replace("LB-HQ-01", "LTM-WEB-01")
    devices, _ = read_devices([("host.conf", VCMP_HOST), ("own.txt", own)])
    names = [d.hostname for d in devices]
    assert names.count("LTM-WEB-01") == 1 and "LTM-APP-01" in names
    kept = next(d for d in devices if d.hostname == "LTM-WEB-01")
    assert not (kept.l3facts["f5"].get("vcmp"))                                   # the real capture, not the stub


def test_a_vcmp_guest_page_has_the_vlan_and_guest_tables_and_no_virtual_servers():
    result = build_topology([("host.conf", VCMP_HOST)], view="f5map")
    pages = [p for p in result["svgs"] if p["view"] == "f5map"]
    assert len(pages) == 2 and all("vCMP guest" in p["svg"] and "VLANs and self IPs" in p["svg"] for p in pages)
    assert "f5-external" not in pages[0]["svg"]
    graph = result["graph"]
    assert {k for k, n in graph.nodes.items() if n.captured} == {"LTM-WEB-01", "LTM-APP-01"}
