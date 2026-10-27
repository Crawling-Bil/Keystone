"""Topology Builder v0.8: uplink routers on top, router chain order, four-switch box, end points under their switch in the Overview, assumed F5 neighbors.
Synthetic fixtures only (invented names, documentation address ranges)."""

from __future__ import annotations

from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link


def _graph(links, roles, captured=None, models=None, names=None, vpc=None):
    nodes = {n: Device(key=n, hostname=(names or {}).get(n, n), captured=(captured is None or n in captured), role_hint=r, model=(models or {}).get(n, "")) for n, r in roles.items()}
    conns = [Connection(a, b, [Link(a, "Gi0/0", b, "Gi0/0", "confirmed", {"CDP"}, "")]) for a, b in links]
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set(), vpc_pairs=vpc or [])


# ----------------------------------------------------------------------------------------------------------------- router order
def test_a_chain_of_routers_reads_left_to_right_in_the_star_layout():
    from features.topology.scene import build_pages
    roles = {"R1": "router", "R2": "router", "R3": "router", "FW1": "firewall"}
    graph = _graph([("R1", "R2"), ("R2", "R3"), ("R1", "FW1"), ("R2", "FW1"), ("R3", "FW1")], roles)
    page = build_pages(graph)[0]
    x = {k: page.nodes[k].x for k in ("R1", "R2", "R3")}
    assert x["R1"] < x["R2"] < x["R3"] or x["R3"] < x["R2"] < x["R1"]                 # the middle router is in the middle, no line runs through an icon


def test_a_same_row_line_over_other_devices_is_a_crossing():
    from features.topology.layout import _crossings
    rows = {0.0: ["A", "B", "C"]}
    near = {"A": {"C"}, "B": set(), "C": {"A"}}
    over, _ = _crossings(rows, [0.0], near, {"A": 0.0, "B": 1.0, "C": 2.0})
    clear, _ = _crossings(rows, [0.0], near, {"A": 0.0, "B": 2.0, "C": 1.0})
    assert over == 1 and clear == 0


# ----------------------------------------------------------------------------------------------------------------- uplink routers
def test_routers_seen_beside_the_captured_router_go_one_row_above_it():
    from features.topology.scene import build_pages
    roles = {"EDGE": "router", "UP1": "router", "UP2": "router", "SW": "access"}
    graph = _graph([("EDGE", "UP1"), ("EDGE", "UP2"), ("UP1", "UP2"), ("EDGE", "SW")], roles, captured={"EDGE", "SW"})
    page = build_pages(graph)[0]
    assert page.nodes["UP1"].y < page.nodes["EDGE"].y and page.nodes["UP2"].y < page.nodes["EDGE"].y
    assert page.nodes["UP1"].y == page.nodes["UP2"].y and page.nodes["SW"].y > page.nodes["EDGE"].y


def test_uplink_routers_leave_a_router_with_something_below_it():
    from features.topology.layout import uplink_routers
    graph = _graph([("EDGE", "OTHER"), ("OTHER", "SW")], {"EDGE": "router", "OTHER": "router", "SW": "access"}, captured={"EDGE", "SW"})
    assert uplink_routers(graph, list(graph.nodes), {"EDGE": 0.0, "OTHER": 0.0, "SW": 3.0}) == {}


# ----------------------------------------------------------------------------------------------------------------- four-switch box
BOX_ROLES = {"HQCORENX1": "core", "HQCORENX2": "core", "HQEDGNX1": "core", "HQEDGNX2": "core"}
BOX_LINKS = [("HQCORENX1", "HQEDGNX1"), ("HQCORENX1", "HQEDGNX2"), ("HQCORENX2", "HQEDGNX1"), ("HQCORENX2", "HQEDGNX2"), ("HQEDGNX1", "HQEDGNX2"), ("HQCORENX1", "HQCORENX2")]
BOX_MODELS = {k: "N9K-C93108TC-EX" for k in BOX_ROLES}


def test_four_switches_in_a_full_mesh_stand_as_a_box_with_one_pair_above_the_other():
    from features.topology.layout import find_meshes
    graph = _graph(BOX_LINKS, BOX_ROLES, models=BOX_MODELS)
    keys = list(graph.nodes)
    near = {k: {m for a, b in BOX_LINKS for m in (a, b) if k in (a, b) and m != k} for k in keys}
    found = find_meshes(graph, keys, {k: 1.0 for k in keys}, near)
    assert len(found) == 1 and {frozenset(found[0][0]), frozenset(found[0][1])} == {frozenset(("HQCORENX1", "HQCORENX2")), frozenset(("HQEDGNX1", "HQEDGNX2"))}


def test_the_box_puts_both_cores_in_one_row_and_both_edges_half_a_row_below():
    from features.topology.layout import layered
    graph = _graph(BOX_LINKS, BOX_ROLES, models=BOX_MODELS)
    placed, _, _ = layered(graph, list(graph.nodes))
    assert placed["HQCORENX1"].y == placed["HQCORENX2"].y and placed["HQEDGNX1"].y == placed["HQEDGNX2"].y
    assert placed["HQEDGNX1"].y > placed["HQCORENX1"].y


def test_two_spines_over_six_leaves_are_not_a_box():
    from features.topology.layout import find_meshes
    links = [(s, f"LEAF{i}") for s in ("SPINE1", "SPINE2") for i in range(6)]
    roles = {"SPINE1": "core", "SPINE2": "core", **{f"LEAF{i}": "core" for i in range(6)}}
    graph = _graph(links, roles, models={k: "N9K-C93108TC-EX" for k in roles})
    keys = list(graph.nodes)
    near = {k: {m for a, b in links for m in (a, b) if k in (a, b) and m != k} for k in keys}
    assert find_meshes(graph, keys, {k: 1.0 for k in keys}, near) == []


# ----------------------------------------------------------------------------------------------------------------- end points under their switch
def _two_sites():
    roles = {"AAA-SW1": "access", "BBB-SW1": "access", "SEP1": "phone", "SEP2": "phone", "SEP3": "phone", "PC1": "host"}
    links = [("AAA-SW1", "BBB-SW1"), ("AAA-SW1", "SEP1"), ("AAA-SW1", "SEP2"), ("BBB-SW1", "SEP3"), ("AAA-SW1", "PC1"), ("BBB-SW1", "PC1")]
    return _graph(links, roles, captured={"AAA-SW1", "BBB-SW1"})


def test_a_phone_follows_the_site_of_its_switch_instead_of_other_devices():
    from features.topology.layout import groups_of
    groups = groups_of(_two_sites(), "prefix1")
    assert {"SEP1", "SEP2"} <= set(groups["AAA"]) and "SEP3" in groups["BBB"]


def test_a_device_linked_to_two_sites_stays_in_other_devices():
    from features.topology.layout import groups_of
    assert groups_of(_two_sites(), "prefix1")["Other devices"] == ["PC1"]


def test_the_auto_sizing_counts_network_devices_only():
    from features.topology.layout import groups_of
    groups = groups_of(_two_sites(), "prefix1", follow=False)
    assert groups["AAA"] == ["AAA-SW1"] and set(groups["Other devices"]) == {"SEP1", "SEP2", "SEP3", "PC1"}


# ----------------------------------------------------------------------------------------------------------------- F5 assumed neighbors
def _bigip(host: str, arp: list[tuple[str, str, str]], vlans: list[dict], routes: list[dict] | None = None, up: tuple[str, ...] = ("1.1", "1.2", "1.3"), bundles=None) -> Device:
    node = Device(key=host, hostname=host, captured=True, vendor="F5", model="BIG-IP", role_hint="loadbalancer")
    node.arp_table = [{"ip_address": ip, "mac_address": mac, "interface": vlan, "vrf": "global"} for ip, mac, vlan in arp]
    node.port_state = {p: "up" for p in up}
    node.bundles = dict(bundles or {})
    node.l3facts = {"routes": routes or [], "f5": {"vlans": vlans, "map": [], "interfaces": [], "trunks": {}}}
    for v in vlans:
        for address in v["self_ips"]:
            node.ips.add(address.split("/")[0])
    return node


def _vlan(name: str, ports: list[str], self_ip: str, floating: str = "") -> dict:
    return {"vlan": name, "tag": 100, "interfaces": [f"{p} (tagged)" for p in ports], "self_ips": [self_ip], "floating_ips": [floating] if floating else [], "route_domain": "global", "description": ""}


def _assume(*devices: Device, extra: Graph | None = None):
    from features.topology.f5neighbors import assume_f5_neighbors
    graph = extra or Graph()
    for d in devices:
        graph.nodes[d.key] = d
    facts = assume_f5_neighbors(graph)
    return graph, facts


def _far(graph: Graph, key: str) -> dict[str, list]:
    return {(c.b if c.a == key else c.a): [(l.a_port, sorted(l.protocols)) for l in c.links] for c in graph.connections if key in (c.a, c.b)}


def test_virtual_macs_of_the_first_hop_redundancy_protocols_give_the_group():
    from features.topology.f5neighbors import fhrp_of
    assert fhrp_of("00:00:0c:07:ac:29") == ("HSRP", 41)
    assert fhrp_of("0000.0c9f.f0fa") == ("HSRPv2", 250)
    assert fhrp_of("00-00-5e-00-01-0a") == ("VRRP", 10)
    assert fhrp_of("00:07:b4:00:03:01") == ("GLBP", 0)             # the prefix is documented, the group split is not: no group is claimed
    assert fhrp_of("00:50:56:b9:23:91") is None and fhrp_of("garbage") is None


def test_an_hsrp_gateway_is_one_assumed_router_with_a_dashed_line_on_every_port_the_vlan_is_tagged_on():
    lb = _bigip("LB1", [("192.0.2.1", "0000.0c07.ac01", "WEB")], [_vlan("WEB", ["1.1", "1.2"], "192.0.2.10/24", "192.0.2.11/24")])
    graph, facts = _assume(lb)
    gateway = graph.nodes["GATEWAY-192-0-2-1"]
    assert not gateway.captured and gateway.role_hint == "router" and "HSRP group 1" in gateway.model
    assert _far(graph, "LB1")["GATEWAY-192-0-2-1"] == [("1.1", ["ARP", "HSRP"]), ("1.2", ["ARP", "HSRP"])]
    assert [f["evidence"] for f in facts] == ["ARP+HSRP", "ARP+HSRP"] and all(l.state == "inferred" for l in graph.links)


def test_a_port_that_is_down_is_not_drawn_when_another_one_is_up():
    lb = _bigip("LB1", [("192.0.2.1", "0000.0c07.ac01", "WEB")], [_vlan("WEB", ["1.1", "1.2"], "192.0.2.10/24")], up=("1.1",))
    lb.port_state["1.2"] = "down"
    graph, _ = _assume(lb)
    assert _far(graph, "LB1")["GATEWAY-192-0-2-1"] == [("1.1", ["ARP", "HSRP"])]


def test_the_next_hop_of_a_route_is_a_gateway_even_without_a_virtual_mac_and_even_without_an_arp_entry():
    lb = _bigip("LB1", [("192.0.2.1", "aabb.ccdd.eeff", "WEB")], [_vlan("WEB", ["1.1"], "192.0.2.10/24"), _vlan("APP", ["1.2"], "198.51.100.10/24")],
                [{"vrf": "global", "next_hop": "192.0.2.1", "default": True, "prefixes": ["0.0.0.0/0"]}, {"vrf": "global", "next_hop": "198.51.100.1", "default": False, "prefixes": ["10.0.0.0/8"]}])
    graph, facts = _assume(lb)
    far = _far(graph, "LB1")
    assert far["GATEWAY-192-0-2-1"] == [("1.1", ["ARP", "ROUTE"])]
    assert far["GATEWAY-198-51-100-1"] == [("1.2", ["ROUTE"])]                       # no ARP entry (expired), the VLAN that contains the address says where
    assert "default gateway" in graph.nodes["GATEWAY-192-0-2-1"].model


def test_a_gateway_shared_by_the_two_units_of_a_pair_is_one_node():
    rows = [("192.0.2.1", "0000.0c07.ac01", "WEB")]
    a = _bigip("LB1", rows, [_vlan("WEB", ["1.1"], "192.0.2.10/24")])
    b = _bigip("LB2", rows, [_vlan("WEB", ["1.1"], "192.0.2.12/24")])
    graph, _ = _assume(a, b)
    assert sum(1 for k in graph.nodes if k.startswith("GATEWAY-")) == 1
    assert "GATEWAY-192-0-2-1" in _far(graph, "LB1") and "GATEWAY-192-0-2-1" in _far(graph, "LB2")


def test_many_gateways_behind_the_same_ports_fold_into_one_node_but_the_default_gateway_stays_apart():
    vlans = [_vlan(f"V{i}", ["1.1"], f"10.{i}.0.10/24") for i in range(1, 8)] + [_vlan("OUT", ["1.1"], "203.0.113.10/24")]
    arp = [(f"10.{i}.0.1", f"0000.0c07.ac{i:02x}", f"V{i}") for i in range(1, 8)] + [("203.0.113.1", "aabb.ccdd.eeff", "OUT")]
    lb = _bigip("LB1", arp, vlans, [{"vrf": "global", "next_hop": "203.0.113.1", "default": True, "prefixes": ["0.0.0.0/0"]}])
    graph, _ = _assume(lb)
    far = _far(graph, "LB1")
    assert "GATEWAY-203-0-113-1" in far and len(far) == 2
    folded = next(k for k in far if k.startswith("UPSTREAM-"))
    assert graph.nodes[folded].hostname == "7 gateways" and graph.nodes[folded].role_hint == "router"


def test_the_sync_vlan_gives_the_ha_peer_and_a_known_unit_is_joined_on_both_ports_once():
    lone = _bigip("LB1", [("192.0.2.2", "aabb.ccdd.0001", "SYNC")], [_vlan("SYNC", ["1.3"], "192.0.2.1/30")])
    graph, _ = _assume(lone)
    peer = graph.nodes["PEER-192-0-2-2"]
    assert peer.role_hint == "loadbalancer" and not peer.captured and _far(graph, "LB1")["PEER-192-0-2-2"] == [("1.3", ["ARP", "VLAN"])]
    a = _bigip("LB1", [("192.0.2.2", "aabb.ccdd.0001", "SYNC")], [_vlan("SYNC", ["1.3"], "192.0.2.1/30")])
    b = _bigip("LB2", [("192.0.2.1", "aabb.ccdd.0002", "SYNC")], [_vlan("SYNC", ["1.3"], "192.0.2.2/30")])
    pair, facts = _assume(a, b)
    assert len(facts) == 1 and len(pair.links) == 1 and (pair.links[0].a_port, pair.links[0].b_port) == ("1.3", "1.3")
    assert not [k for k in pair.nodes if k.startswith("PEER-")]


def test_an_address_alone_on_a_small_subnet_is_the_router_on_the_far_end_and_a_provider_vlan_makes_it_a_cloud():
    lb = _bigip("LB1", [("203.0.113.1", "aabb.ccdd.0001", "ISP_A_VLAN"), ("198.51.100.1", "aabb.ccdd.0002", "TRANSIT")],
                [_vlan("ISP_A_VLAN", ["1.1"], "203.0.113.2/29"), _vlan("TRANSIT", ["1.2"], "198.51.100.2/30")])
    graph, _ = _assume(lb)
    assert graph.nodes["203-0-113-1"].role_hint == "cloud" and graph.nodes["203-0-113-1"].hostname == "ISP_A_VLAN"
    assert graph.nodes["198-51-100-1"].role_hint == "router"


def test_hosts_on_a_shared_vlan_are_listed_not_linked_and_vmware_is_named():
    lb = _bigip("LB1", [("192.0.2.50", "0050.56b9.2391", "WEB"), ("192.0.2.51", "aabb.ccdd.0003", "WEB")], [_vlan("WEB", ["1.1"], "192.0.2.10/24")])
    graph, _ = _assume(lb)
    assert not graph.connections and {h["ips"][0]: h["kind"] for h in graph.f5_hosts} == {"192.0.2.50": "VMware", "192.0.2.51": ""}


def test_a_port_with_a_cdp_neighbor_is_left_alone():
    lb = _bigip("LB1", [("192.0.2.1", "0000.0c07.ac01", "WEB")], [_vlan("WEB", ["1.1"], "192.0.2.10/24")])
    graph = Graph(nodes={"SW1": Device(key="SW1", hostname="SW1", captured=True, role_hint="access")})
    link = Link("LB1", "1.1", "SW1", "Eth1/1", "confirmed", {"LLDP"}, "")
    graph.links.append(link)
    graph.connections.append(Connection("LB1", "SW1", [link]))
    graph, facts = _assume(lb, extra=graph)
    assert facts == [] and not [k for k in graph.nodes if k.startswith("GATEWAY-")]


def test_a_gateway_that_is_a_captured_device_is_joined_to_it_not_to_a_new_node():
    lb = _bigip("LB1", [("192.0.2.1", "aabb.ccdd.0001", "WEB")], [_vlan("WEB", ["1.1"], "192.0.2.10/24")], [{"vrf": "global", "next_hop": "192.0.2.1", "default": True, "prefixes": ["0.0.0.0/0"]}])
    core = Device(key="CORE1", hostname="CORE1", captured=True, role_hint="core", mgmt_ip="192.0.2.1")
    core.ips.add("192.0.2.1")
    graph, _ = _assume(lb, extra=Graph(nodes={"CORE1": core}))
    assert _far(graph, "LB1") == {"CORE1": [("1.1", ["ARP", "ROUTE"])]} and not [k for k in graph.nodes if k.startswith("GATEWAY-")]


def test_the_generic_arp_inference_leaves_a_bigip_alone_because_its_arp_names_vlans_not_ports():
    from features.topology.inferred import infer_neighbors
    lb = _bigip("LB1", [("192.0.2.2", "aabb.ccdd.0001", "SYNC")], [_vlan("SYNC", ["1.3"], "192.0.2.1/30")])
    other = _bigip("LB2", [], [_vlan("SYNC", ["1.3"], "192.0.2.2/30")])
    graph = Graph(nodes={"LB1": lb, "LB2": other})
    assert infer_neighbors(graph) == [] and not graph.connections


def test_a_real_capture_flow_draws_the_default_gateway_dashed_and_lists_it_in_topo_027():
    from features.topology.service import build_topology
    from tests.test_topology_bigip import SHOW, _config
    result = build_topology([("lab-lb1.txt", _config() + "\n" + SHOW)])
    graph = result["graph"]
    assert _far(graph, "LAB-LB1")["GATEWAY-192-0-2-254"] == [("1.1", ["ARP", "ROUTE"])]
    finding = next(f for f in result["findings"] if f["id"] == "TOPO-027")
    assert "LAB-LB1 1.1 -> Gateway 192.0.2.254 (ARP+ROUTE)" in finding["detail"] and "BIG-IP has no neighbor table" in finding["recommendation"]
    assert 'stroke-dasharray' in result["svgs"][0]["svg"] and "Gateway 192.0.2.254" in result["svgs"][0]["svg"]
