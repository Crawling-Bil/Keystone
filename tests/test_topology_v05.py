"""Topology Builder 0.5: IP view, inferred neighbors, endpoint options, Aruba roles, label placement. Synthetic captures only."""

from __future__ import annotations

import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture, lab_dc, nxos_arp, nxos_capture, nxos_mac_table  # noqa: E402

from features.topology import labelplace  # noqa: E402
from features.topology.inferred import parse_description  # noqa: E402
from features.topology.names import split_platform  # noqa: E402
from features.topology.roles import role_from_caps  # noqa: E402
from features.topology.service import build_topology  # noqa: E402

ROUTED = ("interface Ethernet1/5\n  no switchport\n  description WANR2 G0/1/2\n  ip address 192.0.2.1/30\n"
          "interface Ethernet1/6\n  no switchport\n  description to SRV-APP01\n  ip address 192.0.2.5/30\n")


def _routed_files(arp_extra: str = "") -> list[tuple[str, str]]:
    text = nxos_capture("R-CORE", "FDO00000090", "10.97.0.1", cdp=[], config_extra=ROUTED,
                        extra=nxos_arp("R-CORE", [("192.0.2.2", "0200.5e00.0001", "Ethernet1/5"), ("192.0.2.6", "0200.5e00.0002", "Ethernet1/6")]) + arp_extra)
    return [("r.txt", text)]


# ---- roles ---------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("caps,role", [("Router Switch IGMP", "switch"), ("Router Source-Route-Bridge", "router"), ("Trans-Bridge", "ap"), ("Switch IGMP", "switch")])
def test_role_from_cdp_capabilities(caps, role):
    assert role_from_caps(caps) == role


def test_aruba_anw_system_description_is_split_into_model_and_version():
    parts = split_platform("HPE ANW JL724B ML.10.16.1020")
    assert "JL724B" in parts and "ML.10.16.1020" in parts


# ---- descriptions ----------------------------------------------------------------------------------------------------

def test_description_names_the_neighbor_and_its_port():
    assert parse_description("WANR2 G0/1/2") == ("WANR2", "G0/1/2")


# ---- inferred neighbors ----------------------------------------------------------------------------------------------

def test_router_without_cdp_gets_a_neighbor_from_description_and_arp():
    result = build_topology(_routed_files())
    graph = result["graph"]
    inferred = [c for c in graph.connections if c.kind == "inferred"]
    assert len(inferred) == 1 and inferred[0].links[0].a_port == "Eth1/5"
    other = graph.nodes[inferred[0].a if inferred[0].b == "R-CORE" else inferred[0].b]
    assert other.hostname == "WANR2" and other.captured is False
    assert "ARP" in inferred[0].protocols or "DESC" in inferred[0].protocols
    assert [f for f in result["findings"] if f["id"] == "TOPO-027"]


def test_a_server_description_is_not_turned_into_a_network_device():
    graph = build_topology(_routed_files())["graph"]
    assert not [n for n in graph.nodes.values() if "SRV" in n.hostname.upper()]


def test_inference_can_be_switched_off():
    graph = build_topology(_routed_files(), infer_neighbors_from_arp=False)["graph"]
    assert not [c for c in graph.connections if c.kind == "inferred"]


# ---- IP view ---------------------------------------------------------------------------------------------------------

def _two_routers() -> list[tuple[str, str]]:
    a = iosxe_capture("RTR-A", "FOC00000071", "10.96.0.1", cdp=[], config_extra="interface GigabitEthernet0/0/1\n description to RTR-B\n ip address 192.0.2.1 255.255.255.252\n!\n"
                      "interface Loopback0\n ip address 198.51.100.1 255.255.255.255\n!\n")
    b = iosxe_capture("RTR-B", "FOC00000072", "10.96.0.2", cdp=[], config_extra="interface GigabitEthernet0/0/1\n description to RTR-A\n ip address 192.0.2.2 255.255.255.252\n!\n"
                      "interface GigabitEthernet0/0/2\n description LAN\n ip address 203.0.113.1 255.255.255.0\n!\n")
    return [("a.txt", a), ("b.txt", b)]


def test_ip_view_joins_two_devices_that_share_a_point_to_point_subnet():
    result = build_topology(_two_routers(), view="ip")
    page = result["ip_pages"][0]
    direct = [c for c in page.connections if c.kind == "l3" and c.subnet == "192.0.2.0/30"]
    assert len(direct) == 1
    assert {direct[0].ip_a, direct[0].ip_b} == {"192.0.2.1", "192.0.2.2"}
    assert page.tables and any("RTR-B" in t.title for t in page.tables)       # the device with two addresses gets a table


def test_ip_view_leaves_loopbacks_off_the_lines():
    page = build_topology(_two_routers(), view="ip")["ip_pages"][0]
    assert not [c for c in page.connections if "198.51.100.1" in (c.ip_a, c.ip_b)]


def test_ip_view_only_diagram_has_one_page_and_a_table_cell():
    root = ET.fromstring(build_topology(_two_routers(), view="ip")["drawio"])
    assert [d.get("name") for d in root.findall("diagram")] == ["IP view"]
    assert "192.0.2.2/30" in build_topology(_two_routers(), view="ip")["drawio"]


def test_many_subnets_between_one_pair_are_drawn_as_one_line():
    rows = "".join(f"interface Vlan{v}\n ip address 10.{v}.0.{n} 255.255.255.0\n!\n" for v in range(10, 16) for n in [1])
    rows_b = "".join(f"interface Vlan{v}\n ip address 10.{v}.0.2 255.255.255.0\n!\n" for v in range(10, 16))
    files = [("a.txt", iosxe_capture("SVI-A", "FOC00000073", "10.95.0.1", cdp=[], config_extra=rows)),
             ("b.txt", iosxe_capture("SVI-B", "FOC00000074", "10.95.0.2", cdp=[], config_extra=rows_b))]
    page = build_topology(files, view="ip")["ip_pages"][0]
    direct = [c for c in page.connections if c.kind == "l3"]
    assert len(direct) == 1 and len(direct[0].links) >= 6


def test_view_ip_alone_has_no_physical_page():
    root = ET.fromstring(build_topology(_two_routers(), view="ip")["drawio"])
    assert [d.get("name") for d in root.findall("diagram")] == ["IP view"]


# ---- AOS-CX interface syntax -----------------------------------------------------------------------------------------

def test_aoscx_interface_vlan_with_a_space_is_a_routed_interface():
    text = "hostname AOS1\ninterface vlan 130\n    description USERS\n    ip address 192.0.2.1/24\n!\ninterface loopback 0\n    ip address 198.51.100.9/32\n!\n"
    from features.switch_analyzer.service import analyze
    rows = analyze(text, filename="aos1.txt")["l3"]["interfaces"]
    assert [(r["name"], r["ip"], r["prefix_len"]) for r in rows] == [("vlan130", "192.0.2.1", 24), ("loopback0", "198.51.100.9", 32)]


# ---- endpoints ---------------------------------------------------------------------------------------------------------

def _with_phones(count: int = 6) -> list[tuple[str, str]]:
    cdp = [(f"SEP{i:012x}", f"10.94.1.{i}", "IP Phone 8845", f"Ethernet1/{i + 1}", "Port 1", "Host Phone IGMP") for i in range(count)]
    return [("sw.txt", nxos_capture("PH-SW", "FDO00000075", "10.94.0.1", cdp=cdp))]


def test_exclude_endpoints_removes_phones_from_the_pictures():
    kept = build_topology(_with_phones())
    gone = build_topology(_with_phones(), exclude_endpoints=True)
    assert "phone" in {n.role_hint for n in kept["graph"].nodes.values()} or any("phone" in str(n.role_hint) for n in kept["graph"].nodes.values())
    assert not kept["graph"].hidden_nodes and gone["graph"].hidden_nodes
    assert "PH-SW::phone" not in gone["svgs"][0]["svg"] and len(gone["svgs"][0]["svg"]) < len(kept["svgs"][0]["svg"])


def test_access_points_stay_individual_when_collapse_aps_is_off():
    cdp = [(f"AP-{i}", f"10.93.1.{i}", "AIR-AP2802I", f"Ethernet1/{i + 1}", "GigabitEthernet0", "Trans-Bridge IGMP") for i in range(5)]
    files = [("sw.txt", nxos_capture("ACC-SW", "FDO00000076", "10.93.0.1", cdp=cdp))]
    folded = build_topology(files, collapse_endpoints=True, collapse_aps=True)["graph"]
    single = build_topology(files, collapse_endpoints=True, collapse_aps=False)["graph"]
    names = lambda g: {n.hostname for n in g.nodes.values() if n.role_hint == "ap"}      # noqa: E731
    assert names(single) == {f"AP-{i}" for i in range(5)}
    assert len(names(folded)) < 5


def test_devices_under_one_switch_stay_together_under_it():
    def aps(numbers):
        return [(f"AP-{n}", f"10.94.1.{n}", "AIR-AP2802I", f"Ethernet1/{i + 1}", "GigabitEthernet0", "Trans-Bridge IGMP") for i, n in enumerate(numbers)]
    files = [("core.txt", nxos_capture("CORE-1", "FDO00000101", "10.94.0.1", cdp=[("ACC-A", "10.94.0.2", "C9300L-48P-4X", "Ethernet1/1", "Gi1/0/48"), ("ACC-B", "10.94.0.3", "C9300L-48P-4X", "Ethernet1/2", "Gi1/0/48")])),
             ("a.txt", nxos_capture("ACC-A", "FDO00000102", "10.94.0.2", cdp=aps([1, 3, 5]))),
             ("b.txt", nxos_capture("ACC-B", "FDO00000103", "10.94.0.3", cdp=aps([2, 4])))]
    page = build_topology(files, collapse_endpoints=True, collapse_aps=False)["pages"][0]
    row = [key for _, key in sorted((p.x, key) for key, p in page.nodes.items() if key.startswith("AP-"))]
    assert row == ["AP-1", "AP-3", "AP-5", "AP-2", "AP-4"]           # A's three first, then B's two; name order only inside one switch


# ---- label placement -------------------------------------------------------------------------------------------------

def test_every_label_gets_a_position_and_none_sits_on_a_device():
    result = build_topology(list(lab_dc().items()), view="physical")
    page = result["pages"][0] if "pages" in result else None
    if page is None:
        pytest.skip("pages not exposed")
    assert page.label_pos
    boxes = labelplace._node_boxes(page, result["graph"])
    for (index, slot), (x, y, _) in page.label_pos.items():
        assert not any(a < x < c and b < y < d for a, b, c, d in boxes[: len(page.nodes) * 2:2]), (index, slot)


# ---- ARP of named VRFs ------------------------------------------------------------------------------------------------

def test_arp_of_a_named_vrf_is_read_and_tagged():
    from features.switch_analyzer.service import analyze
    text = iosxe_capture("R1", "FOC00000082", "10.91.0.1", cdp=[],
                         extra="R1#show ip arp\nProtocol  Address          Age (min)  Hardware Addr   Type   Interface\nInternet  10.0.0.1        -   0200.5e00.0010  ARPA   GigabitEthernet0/0/0\n"
                               "R1#show ip arp vrf 1\nProtocol  Address          Age (min)  Hardware Addr   Type   Interface\nInternet  192.0.2.2       4   0200.5e00.0001  ARPA   GigabitEthernet0/0/1\nR1#\n")
    result = analyze(text, filename="r1.txt")
    assert [(r["ip_address"], r["vrf"]) for r in result["arp_vrf_table"]] == [("192.0.2.2", "1")]
    assert all("vrf" not in r for r in result["arp_table"])


def test_neighbor_found_through_arp_of_a_named_vrf():
    config = "interface GigabitEthernet0/0/1\n description WANR9 G0/1/2\n ip vrf forwarding 1\n ip address 192.0.2.1 255.255.255.252\n!\n"
    text = iosxe_capture("R-VRF", "FOC00000081", "10.92.0.1", cdp=[], config_extra=config,
                         extra="R-VRF#show ip arp vrf 1\nProtocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
                               "Internet  192.0.2.2       4   0200.5e00.0001  ARPA   GigabitEthernet0/0/1\nR-VRF#\n")
    graph = build_topology([("v.txt", text)])["graph"]
    inferred = [c for c in graph.connections if c.kind == "inferred"]
    assert len(inferred) == 1 and graph.nodes[inferred[0].b].hostname == "WANR9"
    assert inferred[0].ip_b == "192.0.2.2" or any(l.note.endswith("ARP 192.0.2.2") for l in inferred[0].links)


# ---- order of trust: ARP > MAC address > port description ----------------------------------------------------------------

def _trust_graph(arp: bool = False):
    from features.topology.extract import Device
    from features.topology.graph import Graph
    a = Device(key="SW-A1", hostname="SW-A1", captured=True, ips={"10.0.0.1"}, descriptions={"Eth1/1": "SW-C3 Eth1/1"},
               mac_table=[{"mac_address": "0200.0000.00bb", "interface": "Eth1/1", "type": "dynamic", "vlan": "1"}])
    b = Device(key="SW-B2", hostname="SW-B2", captured=True, macs={"0200000000bb"}, ips={"10.0.0.2"})
    c = Device(key="SW-C3", hostname="SW-C3", captured=True, ips={"10.0.0.3"})
    d = Device(key="SW-D4", hostname="SW-D4", captured=True, ips={"10.0.0.9"})
    if arp:
        a.arp_table = [{"ip_address": "10.0.0.9", "mac_address": "0200.0000.00dd", "interface": "Eth1/1", "age": "3"}]
    return Graph(nodes={n.key: n for n in (a, b, c, d)}, links=[], connections=[], hidden_kinds=set())


def test_mac_address_outranks_the_port_description():
    from features.topology.inferred import infer_neighbors
    graph = _trust_graph()
    facts = infer_neighbors(graph)
    assert [(f["a"], f["b"], f["evidence"], f["conflict"]) for f in facts] == [("SW-A1", "SW-B2", "MAC", "SW-C3")]


def test_arp_outranks_mac_address_and_description():
    from features.topology.inferred import infer_neighbors
    facts = infer_neighbors(_trust_graph(arp=True))
    assert [(f["b"], f["evidence"]) for f in facts] == [("SW-D4", "ARP")] and facts[0]["conflict"] in ("SW-C3", "SW-B2")


def test_a_port_with_hosts_behind_it_is_not_a_mac_link():
    from features.topology.inferred import infer_neighbors
    graph = _trust_graph()
    graph.nodes["SW-A1"].descriptions = {}
    graph.nodes["SW-A1"].mac_table.append({"mac_address": "0200.0000.00ee", "interface": "Eth1/1", "type": "dynamic", "vlan": "1"})   # unknown host MAC on the same port
    assert infer_neighbors(graph) == []


def test_description_naming_another_device_than_the_cdp_neighbor_is_reported():
    from features.topology.extract import Device
    from features.topology.graph import Graph, Link, Connection
    from features.topology.inferred import description_drift
    from features.topology.findings import build_findings
    a = Device(key="SW-A1", hostname="SW-A1", captured=True, descriptions={"Eth1/1": "to SW-C3 Eth1/9"})
    b = Device(key="SW-B2", hostname="SW-B2", captured=True)
    c = Device(key="SW-C3", hostname="SW-C3", captured=True)
    link = Link("SW-A1", "Eth1/1", "SW-B2", "Eth1/1", "confirmed", {"CDP"}, "")
    graph = Graph(nodes={n.key: n for n in (a, b, c)}, links=[link], connections=[Connection("SW-A1", "SW-B2", [link])], hidden_kinds=set())
    graph.issues += description_drift(graph)
    assert [(f["a"], f["says"]) for f in graph.issues if f["type"] == "description-drift"] == [("SW-A1", "SW-C3")]
    assert "TOPO-028" in {f["id"] for f in build_findings(graph)}


# ---- topology name and creation time ---------------------------------------------------------------------------------------

def test_safe_name_and_download_name():
    from features.topology.report import download_name, safe_name
    assert safe_name("  Panin DC / Cabang #1  ") == "Panin-DC-Cabang-1"
    assert safe_name("../../etc/passwd") == "etcpasswd" and safe_name("") == "" and len(safe_name("x" * 200)) == 60
    assert download_name("links.csv", "Panin-DC") == "Panin-DC-links.csv" and download_name("links.csv", "") == "links.csv"


def test_drawio_carries_the_name_and_the_creation_time_under_it():
    import datetime as dt
    xml = build_topology(list(lab_dc().items()), name="Panin DC", created=dt.datetime(2026, 10, 21, 9, 5, 7))["drawio"]
    root = ET.fromstring(xml)
    values = [c.get("value") for c in root.iter("mxCell")]
    assert "Panin DC" in values and "Topology Created at Date 2026:10:21 - Time 09:05:07" in values
    cells = {c.get("id"): c for c in root.iter("mxCell")}
    title_y = float(cells["0-title"].find("mxGeometry").get("y")); created_y = float(cells["0-created"].find("mxGeometry").get("y"))
    assert title_y < created_y < 0                       # above every device, the time below the name


def test_drawio_without_a_name_still_shows_the_creation_time_only():
    values = [c.get("value") for c in ET.fromstring(build_topology(list(lab_dc().items()))["drawio"]).iter("mxCell")]
    assert any(str(v).startswith("Topology Created at ") for v in values) and "0-title" not in {c.get("id") for c in ET.fromstring(build_topology(list(lab_dc().items()))["drawio"]).iter("mxCell")}


def test_route_names_the_downloads_after_the_topology(tmp_path, monkeypatch):
    sys.path.insert(0, str(Path(__file__).parent))
    from app import create_app
    app = create_app() if callable(create_app) else create_app
    client = app.test_client()
    data = {"files": [(__import__("io").BytesIO(text.encode()), name) for name, text in lab_dc().items()], "name": "Panin DC"}
    body = client.post("/topology/api/build", data=data, content_type="multipart/form-data").get_json()
    assert body["ok"] and {d["filename"] for d in body["downloads"]} >= {"Panin-DC-topology.drawio", "Panin-DC-links.csv", "Panin-DC-keystone-topology-pack.zip"}
    response = client.get(body["downloads"][0]["url"])
    assert "Panin-DC-" in response.headers["Content-Disposition"]
    plain = client.post("/topology/api/build", data={"files": [(__import__("io").BytesIO(text.encode()), name) for name, text in lab_dc().items()]}, content_type="multipart/form-data").get_json()
    assert {d["filename"] for d in plain["downloads"]} == {d["name"] for d in plain["downloads"]}


# ---- grouping, hub in the middle, black frames, run settings --------------------------------------------------------------

def _graph_of(names: list[str], links: list[tuple[str, str]], role: str = "access"):
    from features.topology.extract import Device
    from features.topology.graph import Connection, Graph, Link
    nodes = {n: Device(key=n, hostname=n, captured=True, role_hint=role) for n in names}
    conns = [Connection(a, b, [Link(a, "Eth1/1", b, "Eth1/1", "confirmed", {"CDP"}, "")]) for a, b in links]
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set())


def test_group_by_first_three_hostname_words():
    from features.topology.layout import groups_of
    graph = _graph_of(["JKT-GD1-LT1-SW1", "JKT-GD1-LT1-SW2", "JKT-GD1-LT2-SW1", "BGR-RT1"], [])
    assert sorted(groups_of(graph, "prefix3")) == ["BGR-RT1", "JKT-GD1-LT1", "JKT-GD1-LT2"]
    assert sorted(groups_of(graph, "prefix2")) == ["BGR-RT1", "JKT-GD1"]


def test_the_group_with_most_links_sits_in_the_middle_and_boxes_do_not_overlap():
    from features.topology.scene import _arrange_groups
    names = [f"S{i}-SW1" for i in range(1, 9)]
    graph = _graph_of(names, [("S1-SW1", n) for n in names[1:]])
    groups = {n.split("-")[0]: [n] for n in names}
    _, boxes, width, height = _arrange_groups(graph, groups)
    by = {b[0]: b for b in boxes}
    hub = by["S1"]
    cx, cy = hub[1] + hub[3] / 2, hub[2] + hub[4] / 2
    assert abs(cx - width / 2) < width * 0.2 and abs(cy - height / 2) < height * 0.25      # the hub is the centre of the picture
    for i, a in enumerate(boxes):
        for b in boxes[i + 1:]:
            assert a[1] + a[3] <= b[1] + 0.5 or b[1] + b[3] <= a[1] + 0.5 or a[2] + a[4] <= b[2] + 0.5 or b[2] + b[4] <= a[2] + 0.5, (a[0], b[0])


def test_the_busiest_device_of_a_row_is_placed_in_the_middle():
    from features.topology.layout import layered
    names = ["A", "B", "C", "D", "E"]
    graph = _graph_of(names, [("C", "A"), ("C", "B"), ("C", "D"), ("C", "E")])
    placed, _, _ = layered(graph, names)
    xs = sorted(p.x for p in placed.values())
    assert placed["C"].x == xs[2]


def test_group_frames_are_black_in_drawio_and_svg():
    files = [("a.txt", nxos_capture("SITE1-SW1", "FDO00000091", "10.90.0.1", cdp=[("SITE2-SW1", "10.90.0.2", "N9K-C93180YC-FX3", "Ethernet1/1", "Ethernet1/1")])),
             ("b.txt", nxos_capture("SITE2-SW1", "FDO00000092", "10.90.0.2", cdp=[("SITE1-SW1", "10.90.0.1", "N9K-C93180YC-FX3", "Ethernet1/1", "Ethernet1/1")]))]
    result = build_topology(files, group="prefix1")
    assert "strokeColor=#000000;strokeWidth=2;verticalAlign=top;align=left" in result["drawio"] and "#DCE8C7" not in result["drawio"]
    assert 'stroke="#000000" stroke-width="2"' in result["svgs"][0]["svg"]


def test_run_settings_are_recorded_in_the_json_the_report_and_a_text_file():
    import json
    from features.topology.report import build_report, settings_text
    result = build_topology(list(lab_dc().items()), name="Lab", exclude_endpoints=True, collapse_aps=False, infer_neighbors_from_arp=False, group="prefix3")
    s = result["settings"]
    assert s["name"] == "Lab" and s["exclude_endpoints"] is True and s["collapse_aps"] is False and s["infer_neighbors"] is False and s["group"] == "prefix3"
    assert s["tool_version"] and len(s["created"]) == 19
    text = settings_text(s, result["summary"])
    assert "[on ] Exclude IP phones, PCs and servers" in text and "[off] Collapse access points" in text and "Group by first three hostname words (JKT-GD1-LT1)" in text
    from features.topology.service import to_json
    assert json.loads(to_json(result["graph"], result["findings"], result["devices"], s))["build"]["name"] == "Lab"
    html = build_report(result["graph"], result["summary"], result["findings"], [], [], [], [], result["svgs"], [], settings=s)
    assert "Build options" in html and "[off] Collapse access points" in html


def test_collapse_phones_and_hosts_row_hides_when_endpoints_are_excluded():
    html = (Path(__file__).parent.parent / "templates" / "topology.html").read_text(encoding="utf-8")
    first = html.index('data-role="exclude-endpoints"')
    assert html.index('data-role="collapse"') > first and 'data-role="exclude-endpoints" checked' in html
    row = html[html.index('data-role="collapse"') - 120: html.index('data-role="collapse"')]
    assert 'data-dep="no-exclude"' in row
    assert 'data-role="collapse-ap" checked' in html and 'data-role="hosts" checked' not in html
    order = [html.index(f'data-role="{r}"') for r in ("exclude-endpoints", "collapse", "collapse-ap", "ports", "infer", "routed", "mgmt", "hosts")]
    assert order == sorted(order)


def test_topology_name_comes_first_and_device_captures_sit_under_the_options():
    html = (Path(__file__).parent.parent / "templates" / "topology.html").read_text(encoding="utf-8")
    name, options, captures, diagram = (html.index(x) for x in ('data-role="name"', 'data-role="exclude-endpoints"', 'data-role="drop"', 'data-role="group"'))
    assert name < options < captures < diagram


def test_devices_of_one_level_are_placed_left_to_right_in_natural_order():
    from features.topology.layout import natural_key
    assert sorted(["SW-10", "SW-2", "sw-1", "SW-B", "SW-A1", "SW-1A"], key=natural_key) == ["SW-A1", "SW-B", "sw-1", "SW-1A", "SW-2", "SW-10"]
    cdp = [(name, f"10.89.1.{i}", "C9300L-48P-4X", f"Ethernet1/{i + 1}", "Gi1/0/1") for i, name in enumerate(["ACC-10", "ACC-2", "ACC-1", "ACC-B", "ACC-A3"])]
    result = build_topology([("core.txt", nxos_capture("CORE-1", "FDO00000091", "10.89.0.1", cdp=cdp))], exclude_endpoints=True)
    page = result["pages"][0]
    row = sorted((p.x, key) for key, p in page.nodes.items() if key.startswith("ACC-"))
    assert [key for _, key in row] == ["ACC-A3", "ACC-B", "ACC-1", "ACC-2", "ACC-10"]
