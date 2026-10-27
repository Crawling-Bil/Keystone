"""Topology Builder v0.6: FortiGate devices, switch L3 facts, SD-WAN site focus, grouped lines, VIP next hops. Synthetic data only."""

from __future__ import annotations

from pathlib import Path

from features.topology import fortidev, l3switch
from features.topology.extract import Device
from features.topology.graph import Graph
from features.topology.l3engine import DOWN, UP, build
from features.topology.l3focus import MORE_KEY, Focus, parse_sites
from features.topology.l3tables import overlay_sites_table, overlay_table

FIXTURES = Path(__file__).parent / "fixtures"


def _row(name, ip, plen=30, vrf="", status="up/up", kind="routed"):
    return {"name": name, "ip": ip, "prefix_len": plen, "vrf": vrf, "kind": kind, "shutdown": False, "description": "", "status": status, "secondary": []}


def _dev(key, rows, **facts):
    d = Device(key=key, hostname=key, role_hint="router", l3=rows, mgmt_ip=rows[0]["ip"] if rows else "")
    d.l3facts = {"routes": [], "neighbors": [], "overlay": [], "tunnels": [], "state": {}, **facts}
    return d


def _graph(*devices):
    return Graph(nodes={d.key: d for d in devices})


# ---------------------------------------------------------------- FortiGate as a device
def _forti():
    return fortidev.read((FIXTURES / "firewall/fortigate_vdom_edge_synthetic.conf").read_text(encoding="utf-8"), "fw.conf")


def test_fortigate_vdom_is_the_vrf_and_the_device_is_a_firewall():
    d = _forti()
    assert (d.hostname, d.role_hint, d.vendor) == ("FW-EDGE-01", "firewall", "Fortinet")
    assert {r["name"]: r["vrf"] for r in d.l3} == {"agg-core.100": "DMZ-FG", "port3": "DMZ-FG", "mgmt": "root"}
    assert d.l3facts["ha"] == "a-p" and d.l3facts["vdoms"] == ["root", "DMZ-FG", "WAN-FG"]


def test_fortigate_aggregate_is_a_bundle_and_its_alias_is_the_port_description():
    d = _forti()
    assert d.bundles == {"agg-core": ["port1", "port2"]} and d.bundle_of["port1"] == "agg-core"
    assert d.descriptions["agg-core"] == "to SW-EDGE-1 - Eth1/39"
    sub = next(r for r in d.l3 if r["name"] == "agg-core.100")
    assert sub["parent"] == "agg-core" and str(sub["vlan_id"]) == "100" and sub["kind"] == "Sub-interface"


def test_fortigate_static_routes_are_grouped_by_vdom_and_next_hop_and_transparent_vdom_is_ignored():
    routes = _forti().l3facts["routes"]
    assert {(r["vrf"], r["next_hop"]) for r in routes} == {("DMZ-FG", "198.51.100.1"), ("DMZ-FG", "192.0.2.2")}
    assert next(r for r in routes if r["next_hop"] == "198.51.100.1")["default"] is True
    assert _forti().l3facts["transparent"] == ["WAN-FG"]


def test_fortigate_and_a_router_on_its_subnet_make_a_p2p_edge_that_carries_the_vdom_default_route():
    firewall = _forti()
    firewall.key = "FW-EDGE-01"                      # the service assigns the key; the reader leaves it empty
    router = _dev("RTR-WAN-1", [_row("Gi0/0/1", "198.51.100.1", 24)])
    model = build(_graph(firewall, router))
    edge = next(e for e in model.edges if e.kind == "p2p")
    assert {(edge.a, edge.a_if), (edge.b, edge.b_if)} == {("FW-EDGE-01", "port3"), ("RTR-WAN-1", "Gi0/0/1")}
    assert any(r["default"] for r in edge.routes)
    assert [e.kind for e in model.edges if e.kind == "gateway"] == ["gateway"]       # 192.0.2.2 (DMZ uplink) is a router nobody captured


# ---------------------------------------------------------------- switch L3 facts
def test_switch_facts_group_routes_by_next_hop_and_skip_connected_and_local():
    result = {"hostname": "SW1", "routing_table": [
        {"vrf": "default", "protocol": "ospf", "destination": "10.1.0.0/16", "next_hop": "10.0.0.2", "interface": "Ethernet1/1"},
        {"vrf": "default", "protocol": "ospf", "destination": "10.2.0.0/16", "next_hop": "10.0.0.2", "interface": "Ethernet1/1"},
        {"vrf": "default", "protocol": "static", "destination": "0.0.0.0/0", "next_hop": "10.0.0.9", "interface": "Vlan10"},
        {"vrf": "default", "protocol": "direct", "destination": "10.0.0.0/30", "next_hop": "10.0.0.1", "interface": "Ethernet1/1"},
        {"vrf": "default", "protocol": "static", "destination": "10.9.0.0/16", "next_hop": "Null0", "interface": ""}]}
    routes = l3switch.facts(result)["routes"]
    assert len(routes) == 2
    ospf = next(r for r in routes if r["protocol"] == "ospf")
    assert ospf["count"] == 2 and ospf["vrf"] == "global" and ospf["prefixes"] == ["10.1.0.0/16", "10.2.0.0/16"]
    assert next(r for r in routes if r["protocol"] == "static")["default"] is True


def test_switch_facts_carry_ospf_neighbors_and_fhrp_groups():
    result = {"hostname": "SW1", "ospf_live": {"neighbors": [{"neighbor_id": "1.1.1.2", "address": "10.0.0.2", "state": "FULL", "role": "BDR", "interface": "Vlan10", "vrf": "default"}]},
              "fhrp": {"groups": [{"interface": "Vlan10", "group": "10", "virtual_ip": "10.0.10.1", "state": "Active"}, {"interface": "Vlan11", "group": "11"}]}}
    facts = l3switch.facts(result)
    assert facts["neighbors"][0]["state"] == "FULL/BDR" and facts["neighbors"][0]["protocol"] == "ospf"
    assert [g["virtual_ip"] for g in facts["fhrp"]] == ["10.0.10.1"] and facts["fhrp"][0]["protocol"] == "hsrp"


def test_merge_keeps_what_the_base_has_and_fills_what_it_lacks():
    base = {"routes": [{"x": 1}], "neighbors": [], "interfaces": [{"keep": 1}]}
    merged = l3switch.merge(base, {"routes": [{"y": 2}], "neighbors": [{"n": 1}], "interfaces": [{"other": 1}], "fhrp": [{"g": 1}]})
    assert merged["routes"] == [{"x": 1}] and merged["neighbors"] == [{"n": 1}] and merged["fhrp"] == [{"g": 1}] and merged["interfaces"] == [{"keep": 1}]
    assert l3switch.merge({}, {"routes": [1]}) == {"routes": [1]}


# ---------------------------------------------------------------- virtual addresses, management routes, OSPF 2WAY
def test_route_to_an_hsrp_virtual_address_is_attributed_to_the_pair_that_runs_it():
    fw = _dev("FW", [_row("port1", "10.0.0.2", 24)], routes=[{"vrf": "", "protocol": "static", "next_hop": "10.0.0.1", "interface": "port1", "count": 1, "prefixes": ["0.0.0.0/0"], "default": True}])
    fhrp = [{"interface": "Vlan10", "group": "10", "virtual_ip": "10.0.0.1", "state": "Active"}]
    sw1 = _dev("SW1", [_row("Vlan10", "10.0.0.3", 24, kind="svi")], fhrp=fhrp)
    sw2 = _dev("SW2", [_row("Vlan10", "10.0.0.4", 24, kind="svi")], fhrp=fhrp)
    model = build(_graph(fw, sw1, sw2))
    assert not [u for u in model.unresolved if u.get("address") == "10.0.0.1"]
    assert any("virtual address" in text for e in model.edges for text in e.evidence)


def test_a_route_whose_next_hop_is_on_the_management_interface_does_not_draw_a_line():
    a = _dev("A", [_row("mgmt0", "10.9.9.2", 24, vrf="management"), _row("Gi0/0", "192.0.2.1", 30)], routes=[{"vrf": "management", "protocol": "static", "next_hop": "10.9.9.1", "interface": "mgmt0", "count": 1, "prefixes": ["0.0.0.0/0"], "default": True}])
    model = build(_graph(a))
    assert model.edges == [] and model.unresolved == []


def test_ospf_2way_between_drother_routers_is_healthy():
    a = _dev("R1", [_row("Gi0/0", "10.0.0.1", 24)], neighbors=[{"protocol": "ospf", "address": "10.0.0.2", "state": "2WAY/DROTHER", "vrf": ""}])
    b = _dev("R2", [_row("Gi0/0", "10.0.0.2", 24)])
    c = _dev("R3", [_row("Gi0/0", "10.0.0.3", 24)])
    edge = next(e for e in build(_graph(a, b, c)).edges if e.a == "R1")
    assert edge.state == UP and any("2WAY/DROTHER" in t for t in edge.evidence)
    sick = _dev("R1", [_row("Gi0/0", "10.0.0.1", 24)], neighbors=[{"protocol": "ospf", "address": "10.0.0.2", "state": "INIT/-", "vrf": ""}])
    assert next(e for e in build(_graph(sick, b, c)).edges if e.a == "R1").state == DOWN


# ---------------------------------------------------------------- grouping
def test_many_shared_subnets_between_one_pair_are_drawn_as_one_line_with_their_members_kept():
    rows1 = [_row(f"Vlan{n}", f"10.{n}.0.1", 24, kind="svi") for n in range(10, 15)]
    rows2 = [_row(f"Vlan{n}", f"10.{n}.0.2", 24, kind="svi") for n in range(10, 15)]
    model = build(_graph(_dev("D1", rows1), _dev("D2", rows2)))
    assert len(model.grouped) == 1 and len(model.grouped[0].members) == 5
    assert len(model.drawn()) == 1 and model.grouped[0].ident == "L3-G01"
    assert len(build(_graph(_dev("D1", rows1), _dev("D2", rows2)), group=False).drawn()) == 5


def test_grouped_line_is_down_only_when_every_member_is_down():
    rows1 = [_row(f"Vlan{n}", f"10.{n}.0.1", 24, kind="svi", status="down/down" if n == 10 else "up/up") for n in range(10, 15)]
    rows2 = [_row(f"Vlan{n}", f"10.{n}.0.2", 24, kind="svi") for n in range(10, 15)]
    line = build(_graph(_dev("D1", rows1), _dev("D2", rows2))).grouped[0]
    assert line.state != DOWN and any("1 of 5" in t for t in line.evidence)
    rows1 = [_row(f"Vlan{n}", f"10.{n}.0.1", 24, kind="svi", status="down/down") for n in range(10, 15)]
    assert build(_graph(_dev("D1", rows1), _dev("D2", rows2))).grouped[0].state == DOWN


def test_many_uncaptured_next_hop_routers_become_one_node_per_vrf():
    rows = [_row(f"Vlan{n}", f"10.{n}.0.2", 24, kind="svi") for n in range(10, 20)]
    routes = [{"vrf": "", "protocol": "static", "next_hop": f"10.{n}.0.1", "interface": f"Vlan{n}", "count": 1, "prefixes": [f"172.16.{n}.0/24"], "default": False} for n in range(10, 20)]
    model = build(_graph(_dev("D1", rows, routes=routes)))
    assert "GWG:global" in model.nodes and len([e for e in model.drawn() if e.kind == "gateway"]) == 1
    assert len([n for n in model.nodes if n.startswith("GW:")]) == 10          # the single nodes stay for the tables


# ---------------------------------------------------------------- SD-WAN site focus
def _session(system, site, state="up", colour="mpls"):
    return {"system_ip": system, "site_id": site, "state": state, "local_color": colour, "remote_color": colour}


def _fabric(extra=40):
    sessions = [_session("10.255.0.2", "2")] + [_session(f"10.255.1.{n}", str(100 + n)) for n in range(1, extra + 1)]
    hub = _dev("HUB", [_row("Loopback0", "10.255.0.1", 32, kind="loopback")], overlay=sessions, system_ip="10.255.0.1", site_id="1")
    branch = _dev("BR2", [_row("Loopback0", "10.255.0.2", 32, kind="loopback")], system_ip="10.255.0.2", site_id="2")
    return _graph(hub, branch)


def test_default_focus_draws_captured_sites_and_counts_the_rest_in_one_cloud():
    model = build(_fabric())
    overlay = [e for e in model.edges if e.kind == "overlay"]
    assert len(overlay) == 2 and {e.b for e in overlay} == {"HUB", MORE_KEY}
    cloud = next(e for e in overlay if e.b == MORE_KEY)
    assert cloud.sites == 40 and cloud.sessions == (40, 40) and model.nodes[MORE_KEY].hostname == "+40 SD-WAN sites"
    assert len(model.hidden) == 40


def test_all_mode_draws_a_node_for_every_site():
    model = build(_fabric(5), focus=Focus.of("all"))
    assert MORE_KEY not in model.nodes and len([e for e in model.edges if e.kind == "overlay"]) == 6


def test_typed_site_list_draws_only_those_sites_by_id_ip_or_name():
    model = build(_fabric(), focus=Focus.of("captured", "105, 10.255.1.7"))
    drawn = {e.b for e in model.edges if e.kind == "overlay"}
    assert {"SDWAN:10.255.1.5", "SDWAN:10.255.1.7", MORE_KEY} <= drawn and "BR2" not in drawn      # the captured branch was not typed, so it is counted in the cloud
    assert len(model.hidden) == 39 and "10.255.0.2" in model.hidden


def test_focus_parsing_and_matching():
    assert parse_sites("105, 10.255.1.7;\n branch-a branch-a") == ["105", "10.255.1.7", "branch-a"]
    focus = Focus.of("bogus", "BR-A")
    assert focus.mode == "captured" and focus.narrowed
    assert focus.names(host="KCU-BR-A-01") and not focus.names(host="HQ") and not Focus.of().names("10.1.1.1")
    assert Focus.of("all").draws("1.1.1.1", "9", "", False) and not Focus().draws("1.1.1.1", "9", "", False)


def test_overlay_tables_keep_every_session_and_say_which_are_on_the_picture():
    graph, focus = _fabric(), Focus()
    rows = overlay_table(graph, focus)
    assert len(rows) == 41 and sum(1 for r in rows if r["on_the_picture"] == "yes") == 1
    sites = overlay_sites_table(graph, focus)
    assert len(sites) == 41 and sites[0]["captured_as"] == "BR2" and sites[0]["on_the_picture"] == "yes"
    assert all(s["on_the_picture"] == "no" for s in sites[1:])
    assert sum(1 for r in overlay_table(graph, Focus.of("all")) if r["on_the_picture"] == "yes") == 41


# ---------------------------------------------------------------- through the web route
import io
import zipfile

import pytest

ROUTER = FIXTURES / "router"
SDWAN = ("c8200_sdwan_cedge_masked.txt", "cedge_sdwan_overlay_masked.txt")


@pytest.fixture()
def client():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _post(client, names=SDWAN, extra=None, view=None, with_forti=False):
    files = [(io.BytesIO((ROUTER / n).read_bytes()), n) for n in names]
    if with_forti:
        files.append((io.BytesIO((FIXTURES / "firewall/fortigate_vdom_edge_synthetic.conf").read_bytes()), "fw-edge.conf"))
    data = {"files": files, "group": "none", **({"view": view} if view else {}), **(extra or {})}
    return client.post("/topology/api/build", data=data, content_type="multipart/form-data")


def test_all_views_is_the_default_and_still_holds_l3_over_l2(client):
    from features.topology import routes
    body = _post(client).get_json()
    assert routes.DEFAULT_VIEW == "all" and body["ok"]
    assert any(p["view"] == "l3over2" and "data-l3=" in p["svg"] for p in body["pages"])


def test_unknown_view_and_overlay_mode_fall_back_to_the_defaults(client):
    body = _post(client, view="nonsense", extra={"overlay_sites": "weird"}).get_json()
    assert body["ok"] and any(p["view"] == "l3over2" for p in body["pages"])


def test_sdwan_sites_file_is_offered_and_lists_every_remote_site(client):
    body = _post(client).get_json()
    assert "l3-sdwan-sites.csv" in {d["name"] for d in body["downloads"]}
    assert body["l3_sites"] and {"site_id", "system_ip", "captured_as", "sessions", "on_the_picture"} <= set(body["l3_sites"][0])


def test_typed_site_list_reaches_the_engine_and_the_tables(client):
    everything = _post(client, extra={"overlay_sites": "all"}).get_json()
    nothing = _post(client, extra={"focus_sites": "no-such-site-anywhere"}).get_json()
    assert len(everything["l3_overlay"]) == len(nothing["l3_overlay"]) > 0            # the tables keep every session
    assert all(r["on_the_picture"].startswith("no") for r in nothing["l3_overlay"])
    assert any(r["on_the_picture"] == "yes" for r in everything["l3_overlay"])


def test_fortigate_upload_is_drawn_and_not_skipped(client):
    body = _post(client, with_forti=True).get_json()
    assert body["ok"]
    assert "fw-edge.conf" not in {s["file"] for s in body["skipped"]}
    firewall = next(d for d in body["devices"] if d["device"] == "FW-EDGE-01 [DMZ-FG]")      # one node per VDOM of a multi-VDOM chassis
    assert (firewall["vendor"], firewall["role"], firewall["has_routes"]) == ("Fortinet", "firewall", "yes")


def test_pack_carries_the_sites_table(client):
    body = _post(client).get_json()
    pack = client.get(next(d["url"] for d in body["downloads"] if d["name"] == "keystone-topology-pack.zip")).data
    names = zipfile.ZipFile(io.BytesIO(pack)).namelist()
    assert any(n.endswith("l3-sdwan-sites.csv") for n in names)


# ---------------------------------------------------------------- L3 over L2: sub-interface that names its parent
def test_a_sub_interface_that_names_its_parent_uses_the_cable_of_the_parent():
    from features.topology.l3over2 import _lookup, _parents
    firewall = _forti()
    firewall.key = "FW-EDGE-01"
    graph = _graph(firewall)
    parents = _parents(graph)
    assert parents == {("FW-EDGE-01", "agg-core.100"): "agg-core"}
    index = {("FW-EDGE-01", "agg-core"): 7}
    assert _lookup(index, "FW-EDGE-01", "agg-core.100", parents) == 7
    assert _lookup(index, "FW-EDGE-01", "port3", parents) is None
    chain = {("FW-EDGE-01", "vlan200"): "vlan100", ("FW-EDGE-01", "vlan100"): "agg-core"}
    assert _lookup(index, "FW-EDGE-01", "vlan200", chain) == 7
    assert _lookup(index, "FW-EDGE-01", "vlan200", {("FW-EDGE-01", "vlan200"): "vlan200"}) is None       # a loop in the data ends


# ---------------------------------------------------------------- several inferred cables between the same two devices
def _pair(fw_desc, nx_desc):
    from features.topology.graph import Graph
    firewall = Device(key="FW-EDGE1", hostname="FW-EDGE1", captured=True, descriptions=fw_desc, role_hint="firewall")
    nexus = Device(key="SW-CORE1", hostname="SW-CORE1", captured=True, descriptions=nx_desc)
    return Graph(nodes={"FW-EDGE1": firewall, "SW-CORE1": nexus}, links=[], connections=[], hidden_kinds=set())


def test_three_firewall_ports_named_after_one_switch_are_three_cables_on_one_line():
    from features.topology.inferred import infer_neighbors
    graph = _pair({"port29": "to SW-CORE1", "port31": "to SW-CORE1 - Eth1/39", "port32": "to SW-CORE1 - Eth1/40"}, {})
    infer_neighbors(graph)
    assert len(graph.connections) == 1 and graph.connections[0].kind == "inferred"
    assert sorted((l.a_port, l.b_port) for l in graph.connections[0].links) == [("port29", ""), ("port31", "Eth1/39"), ("port32", "Eth1/40")]


def test_the_far_devices_description_of_the_same_cable_is_not_a_second_cable():
    from features.topology.inferred import infer_neighbors
    graph = _pair({"port31": "to SW-CORE1 - Eth1/39", "port32": "to SW-CORE1 - Eth1/40"}, {"Eth1/39": "to FW-EDGE1 - port31", "Eth1/40": "to FW-EDGE1 - port32"})
    infer_neighbors(graph)
    links = [l for c in graph.connections for l in c.links]
    assert len(graph.connections) == 1 and len(links) == 2


def test_far_side_that_names_the_cable_without_a_port_gets_the_near_port_filled_in():
    from features.topology.inferred import infer_neighbors
    graph = _pair({"port29": "to SW-CORE1"}, {"Eth1/6": "to FW-EDGE1"})
    infer_neighbors(graph)
    links = [l for c in graph.connections for l in c.links]
    assert len(links) == 1 and {links[0].a_port, links[0].b_port} == {"port29", "Eth1/6"}


def test_a_pair_already_joined_by_cdp_is_left_alone():
    from features.topology.graph import Connection, Link
    from features.topology.inferred import infer_neighbors
    graph = _pair({"port31": "to SW-CORE1 - Eth1/39"}, {})
    link = Link("FW-EDGE1", "port1", "SW-CORE1", "Eth1/1", "confirmed", {"CDP"})
    graph.links.append(link)
    graph.connections.append(Connection("FW-EDGE1", "SW-CORE1", [link]))
    infer_neighbors(graph)
    assert len(graph.connections) == 1 and len(graph.connections[0].links) == 1


def test_grouped_line_sentence_names_the_subnets_and_not_an_empty_one():
    from features.topology.l3tables import sentence
    rows1 = [_row(f"Vlan{n}", f"10.{n}.0.1", 24, kind="svi") for n in range(10, 15)]
    rows2 = [_row(f"Vlan{n}", f"10.{n}.0.2", 24, kind="svi") for n in range(10, 15)]
    line = build(_graph(_dev("D1", rows1), _dev("D2", rows2))).grouped[0]
    text = sentence(line, "D1", "D2")
    assert "5 subnets" in text and "10.10.0.0/24" in text and "connected on ." not in text


# ---------------------------------------------------------------- the reading of a capture is kept between builds
def test_a_capture_is_read_once_and_every_build_gets_its_own_copy(monkeypatch):
    from features.topology import service
    calls = []
    real = service._read_one

    def counting(name, text):
        calls.append(name)
        return real(name, text)

    monkeypatch.setattr(service, "_read_one", counting)
    text = (FIXTURES / "firewall/fortigate_vdom_edge_synthetic.conf").read_text(encoding="utf-8") + "\n# cache test\n"
    first, _ = service.read_devices([("cache-test.conf", text)])
    first[0].hostname = "CHANGED-BY-THE-BUILD"
    second, _ = service.read_devices([("cache-test.conf", text)])
    assert calls == ["cache-test.conf"] and second[0].hostname == "FW-EDGE-01 [root]" and second[0] is not first[0]
    service.read_devices([("cache-test.conf", text + "# edited\n")])
    assert len(calls) == 2                                   # a changed capture is read again
