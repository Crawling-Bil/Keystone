"""The L3 model and the 'L3 - Logical and Route' page, built from hand-made devices (synthetic addresses, no real captures)."""

from __future__ import annotations

from features.topology.extract import Device
from features.topology.graph import Graph
from features.topology.l3engine import DOWN, UP, build
from features.topology.l3page import l3_page, route_summary, vrf_colours


def _row(name, ip, plen=30, vrf="", status="up/up", kind="routed"):
    return {"name": name, "ip": ip, "prefix_len": plen, "vrf": vrf, "kind": kind, "shutdown": False, "description": "", "status": status, "secondary": []}


def _dev(key, rows, **facts):
    d = Device(key=key, hostname=key, role_hint="router", l3=rows, mgmt_ip=rows[0]["ip"] if rows else "")
    d.l3facts = {"routes": [], "neighbors": [], "overlay": [], "tunnels": [], "state": {}, **facts}
    return d


def _graph(*devices):
    return Graph(nodes={d.key: d for d in devices})


def test_two_routers_sharing_a_slash30_are_one_p2p_edge_with_ospf_evidence():
    a = _dev("R1", [_row("Gi0/0/0", "10.0.0.1")], neighbors=[{"protocol": "ospf", "address": "10.0.0.2", "state": "FULL/DR", "vrf": ""}])
    b = _dev("R2", [_row("Gi0/0/1", "10.0.0.2")])
    model = build(_graph(a, b))
    assert [(e.kind, e.a, e.b, e.state) for e in model.edges] == [("p2p", "R1", "R2", UP)]
    assert any("OSPF" in text for text in model.edges[0].evidence)


def test_down_interface_makes_the_edge_down():
    a = _dev("R1", [_row("Gi0/0/0", "10.0.0.1", status="down/down")])
    b = _dev("R2", [_row("Gi0/0/1", "10.0.0.2")])
    assert build(_graph(a, b)).edges[0].state == DOWN


def test_three_devices_on_one_vlan_share_a_segment_node():
    rows = [("A", "10.1.1.1"), ("B", "10.1.1.2"), ("C", "10.1.1.3")]
    devices = [_dev(k, [_row("Vlan10", ip, 24, kind="svi")]) for k, ip in rows]
    model = build(_graph(*devices))
    assert {e.kind for e in model.edges} == {"segment"} and len(model.edges) == 3
    assert any(n.role_hint == "segment" for n in model.nodes.values())


def test_route_next_hop_in_a_shared_subnet_attaches_to_that_edge():
    a = _dev("R1", [_row("Gi0/0/0", "10.0.0.1")], routes=[{"vrf": "", "protocol": "static", "next_hop": "10.0.0.2", "interface": "Gi0/0/0", "count": 1, "prefixes": ["0.0.0.0/0"], "default": True}])
    b = _dev("R2", [_row("Gi0/0/1", "10.0.0.2")])
    edge = build(_graph(a, b)).edges[0]
    assert edge.routes[0]["default"] and route_summary(edge.routes) == "static default"


def test_unknown_next_hop_in_a_connected_subnet_becomes_a_gateway_node():
    a = _dev("R1", [_row("Gi0/0/0", "192.0.2.2", 29)], routes=[{"vrf": "", "protocol": "static", "next_hop": "192.0.2.1", "interface": "Gi0/0/0", "count": 1, "prefixes": ["0.0.0.0/0"], "default": True}])
    model = build(_graph(a))
    assert [e.kind for e in model.edges] == ["gateway"] and "GW:192.0.2.1" in model.nodes


def test_next_hop_outside_every_connected_subnet_is_reported_unresolved():
    a = _dev("R1", [_row("Gi0/0/0", "192.0.2.2", 29)], routes=[{"vrf": "", "protocol": "bgp", "next_hop": "203.0.113.9", "interface": "", "count": 5, "prefixes": [], "default": False}])
    model = build(_graph(a))
    assert model.unresolved and model.unresolved[0]["address"] == "203.0.113.9"


def test_sdwan_bfd_sessions_between_two_captured_routers_make_one_overlay_edge():
    s1 = {"system_ip": "10.255.0.2", "site_id": "2", "state": "up", "local_color": "mpls", "remote_color": "mpls"}
    s2 = {"system_ip": "10.255.0.2", "site_id": "2", "state": "down", "local_color": "biz-internet", "remote_color": "biz-internet"}
    a = _dev("HQ", [_row("Loopback0", "10.255.0.1", 32, kind="loopback")], overlay=[s1, s2], system_ip="10.255.0.1")
    b = _dev("BR", [_row("Loopback0", "10.255.0.2", 32, kind="loopback")], system_ip="10.255.0.2")
    edge = [e for e in build(_graph(a, b)).edges if e.kind == "overlay"][0]
    assert edge.sessions == (1, 2) and edge.state == UP and "mpls > mpls" in edge.colours


def test_gre_tunnel_to_a_captured_router_is_a_tunnel_edge():
    a = _dev("R1", [_row("Gi0/0/0", "198.51.100.1", 30), _row("Tunnel1", "172.16.0.1", 30, kind="tunnel")], tunnels=[{"name": "Tunnel1", "source": "198.51.100.1", "destination": "198.51.100.2", "mode": "gre", "vrf": "", "ip": "172.16.0.1/30"}])
    b = _dev("R2", [_row("Gi0/0/0", "198.51.100.2", 30)])
    kinds = {e.kind for e in build(_graph(a, b)).edges}
    assert "tunnel" in kinds


def test_page_colours_each_vrf_and_marks_unproven_lines_dashed():
    a = _dev("R1", [_row("Gi0/0/0", "10.0.0.1", vrf="BLUE"), _row("Gi0/0/1", "10.0.1.1", vrf="RED", status="")])
    b = _dev("R2", [_row("Gi0/0/0", "10.0.0.2", vrf="BLUE"), _row("Gi0/0/1", "10.0.1.2", vrf="RED", status="")])
    page = l3_page(_graph(a, b))
    assert page and page.view == "l3route" and len(page.connections) == 2
    colours = vrf_colours(["BLUE", "RED"])
    assert {c.l3["colour"] for c in page.connections} == {colours["BLUE"], colours["RED"]}
    from features.topology.styles import line_look
    looks = {c.l3["vrf"]: line_look(page.graph, c, "state") for c in page.connections}
    assert looks["BLUE"][2] is False and looks["RED"][2] is True


# ---------------------------------------------------------------- provider clouds
def _wan(key, ip, description="", colour="", gateway="192.0.2.1", vrf=""):
    row = _row("Gi0/0/1", ip, 29, vrf=vrf)
    row["description"] = description
    facts = {"routes": [{"vrf": vrf, "protocol": "static", "next_hop": gateway, "interface": "Gi0/0/1", "count": 1, "prefixes": ["0.0.0.0/0"], "default": True}]}
    if colour:
        facts["wan_colour"] = {"Gi0/0/1": colour}
    return _dev(key, [row], **facts)


def test_description_decides_the_cloud_type_and_provider():
    from features.topology.l3cloud import classify
    g = _graph(_wan("R1", "192.0.2.2", "MPLS TELKOM jakarta"))
    found = classify(g, "R1", "Gi0/0/1", "192.0.2.1")
    assert (found.kind, found.provider) == ("mpls", "Telkom") and "port description" in found.reasons[0]


def test_sdwan_colour_decides_when_the_description_says_nothing():
    from features.topology.l3cloud import classify
    assert classify(_graph(_wan("R1", "192.0.2.2", colour="biz-internet")), "R1", "Gi0/0/1", "192.0.2.1").kind == "internet"
    assert classify(_graph(_wan("R1", "192.0.2.2", colour="metro-ethernet")), "R1", "Gi0/0/1", "192.0.2.1").kind == "metro"
    assert classify(_graph(_wan("R1", "192.0.2.2")), "R1", "Gi0/0/1", "192.0.2.1") is None


def test_typed_hint_beats_description_and_colour():
    from features.topology.l3cloud import classify, parse_hints
    g = _graph(_wan("R1", "192.0.2.2", "MPLS", colour="mpls"))
    found = classify(g, "R1", "Gi0/0/1", "192.0.2.1", {"rules": parse_hints("R1 Gi0/0/1 = internet Biznet")})
    assert (found.kind, found.provider, found.typed) == ("internet", "Biznet", True)


def test_hint_rules_parse_interface_subnet_and_keyword_forms():
    from features.topology.l3cloud import parse_hints
    rules = parse_hints("# comment\nHQWANR1 Gi0/0/1 = mpls Telkom\n203.0.113.0/30 = internet\nMETRO-JKT = metro Moratel\nbroken line\nx = nonsense\n")
    assert [(r.type, r.provider) for r in rules] == [("mpls", "Telkom"), ("internet", ""), ("metro", "Moratel")]
    assert rules[0].device == "hqwanr1" and rules[1].network is not None and rules[2].keyword == "metro-jkt"


def test_two_sites_on_the_same_transport_share_one_cloud_and_keep_their_own_gateway():
    a = _wan("R1", "192.0.2.2", "MPLS Telkom", gateway="192.0.2.1")
    b = _wan("R2", "198.51.100.2", "MPLS Telkom", gateway="198.51.100.1")
    model = build(_graph(a, b))
    clouds = [k for k in model.nodes if k.startswith("CLOUD:")]
    assert clouds == ["CLOUD:mpls:telkom"]
    gateways = sorted(e.b_ip for e in model.edges if e.kind == "gateway")
    assert gateways == ["192.0.2.1", "198.51.100.1"]
    assert all(any("faces MPLS" in text for text in e.evidence) for e in model.edges)


def test_access_link_without_a_route_still_gets_its_cloud_from_the_description():
    d = _dev("R1", [dict(_row("Gi0/0/2", "203.0.113.2", 30), description="INTERNET Biznet")])
    model = build(_graph(d))
    assert [e.kind for e in model.edges] == ["gateway"] and "CLOUD:internet:biznet" in model.nodes


# ---------------------------------------------------------------- curved lines
def _crossing_graph():
    """Three routers in a row: the link A-C passes right through B."""
    from features.topology.scene import Page, Placed
    from features.topology.graph import Connection, Link
    nodes = {k: Device(key=k, hostname=k, role_hint="router") for k in "ABC"}
    graph = Graph(nodes=nodes)
    link = Link("A", "g1", "C", "g1", "confirmed")
    conn = Connection("A", "C", [link])
    graph.links, graph.connections = [link], [conn]
    page = Page("t", {"A": Placed(0, 0, 0), "B": Placed(300, 0, 0), "C": Placed(600, 0, 0)}, set(), [], [conn], {}, 900, 300)
    return graph, page


def test_a_line_through_a_device_goes_over_it_like_a_bridge_by_default_and_curved_on_request():
    from features.topology.scene import CURVE_POINTS, _route
    graph, page = _crossing_graph()
    _route(page)
    assert len(page.routes[0]) == 2                             # two corners, a flat run over the device in between
    (x1, y1), (x2, y2) = page.routes[0]
    assert abs(y1 - y2) < 0.5 and y1 != 0 and x1 < 300 < x2
    graph, page = _crossing_graph()
    page.curved = True
    _route(page)
    assert len(page.routes[0]) == CURVE_POINTS
    xs = [x for x, _ in page.routes[0]]
    assert xs == sorted(xs)                                     # runs from A towards C without doubling back


def test_curved_svg_and_drawio_use_round_joins_and_curved_style():
    from features.topology.svg import to_svg
    from features.topology.drawio import _edge_style
    from features.topology.scene import _route
    graph, page = _crossing_graph()
    page.curved = True
    _route(page)
    assert 'stroke-linejoin="round"' in to_svg(page, graph)
    assert "curved=1" in _edge_style(graph, page.connections[0], "state", True)


# ---------------------------------------------------------------- key addresses on the L2 links
def test_routed_port_address_is_written_next_to_the_port_name_on_the_l2_line():
    from features.topology.graph import Connection, Link
    from features.topology.l2ips import annotate_link_ips
    from features.topology.labels import end_texts
    a = _dev("R1", [_row("Gi0/0/1", "10.0.0.1")])
    b = _dev("SW1", [])
    link = Link("R1", "Gi0/0/1", "SW1", "Gi1/0/1", "confirmed")
    conn = Connection("R1", "SW1", [link])
    graph = Graph(nodes={"R1": a, "SW1": b}, links=[link], connections=[conn])
    assert annotate_link_ips(graph) == 1
    assert end_texts(conn) == ("Gi0/0/1 10.0.0.1/30", "Gi1/0/1")


def test_routed_port_channel_address_is_shown_on_the_bundle():
    from features.topology.graph import Connection, Link
    from features.topology.l2ips import annotate_link_ips
    from features.topology.labels import end_texts
    a = _dev("R1", [_row("Po1", "10.9.9.1", 31)])
    b = _dev("R2", [_row("Po1", "10.9.9.0", 31)])
    links = [Link("R1", "Gi0/1", "R2", "Gi0/1", "confirmed"), Link("R1", "Gi0/2", "R2", "Gi0/2", "confirmed")]
    conn = Connection("R1", "R2", links, "Po1", "Po1", kind="bundle")
    graph = Graph(nodes={"R1": a, "R2": b}, links=links, connections=[conn])
    annotate_link_ips(graph)
    assert end_texts(conn) == ("Po1 10.9.9.1/31", "Po1 10.9.9.0/31")


# ---------------------------------------------------------------- path trace
def _trace_world():
    from features.topology.l3engine import build
    from features.topology.l3trace import trace_data
    r1 = _dev("R1", [_row("Gi0/0", "10.0.0.1")], routes=[{"vrf": "global", "protocol": "static", "next_hop": "10.0.0.2", "interface": "Gi0/0", "count": 1, "prefixes": ["0.0.0.0/0"], "default": True}])
    r2 = _dev("R2", [_row("Gi0/0", "10.0.0.2"), _row("Gi0/1", "10.0.1.1")], routes=[{"vrf": "global", "protocol": "ospf", "next_hop": "10.0.1.2", "interface": "Gi0/1", "count": 1, "prefixes": ["10.20.0.0/16"], "default": False}])
    r3 = _dev("R3", [_row("Gi0/1", "10.0.1.2"), _row("Gi0/2", "10.20.1.1", 24)])
    graph = _graph(r1, r2, r3)
    model = build(graph)
    ids = {id(e): f"L3-{n:02d}" for n, e in enumerate(model.edges, 1)}
    return trace_data(graph, model, ids), model, ids


def test_trace_follows_default_route_then_longest_prefix_and_delivers_into_the_lan():
    from features.topology.l3trace import trace
    data, model, ids = _trace_world()
    result = trace(data, "R1", "10.20.1.55")
    assert result["ok"] and result["arrived"]
    assert [h["device"] for h in result["hops"]] == ["R1", "R2", "R3"]
    assert "0.0.0.0/0 via 10.0.0.2" in result["hops"][0]["action"] and "10.20.0.0/16 via 10.0.1.2" in result["hops"][1]["action"]
    assert "connected subnet 10.20.1.0/24" in result["hops"][2]["action"]
    assert len(result["edge_ids"]) == 2


def test_trace_reports_no_route_and_unknown_inputs():
    from features.topology.l3trace import trace
    data, _, _ = _trace_world()
    assert trace(data, "R3", "172.16.0.1")["message"].startswith("R3 has no route")
    assert not trace(data, "nobody", "10.20.1.55")["ok"] and not trace(data, "R1", "not-an-ip")["ok"]


def test_trace_stops_at_the_device_that_has_no_route():
    from features.topology.l3trace import trace
    data, _, _ = _trace_world()
    r = trace(data, "R1", "8.8.8.8")
    assert [h["device"] for h in r["hops"]] == ["R1", "R2"] and "no route" in r["message"].lower()
