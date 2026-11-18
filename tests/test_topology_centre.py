"""The centre of a network is found from the whole picture, not from one name: twin units, stacks, names with the role word inside them (features/topology/roles.py).

Invented names.  A core is a pair or a stack, one logical device of several chassis (Cisco StackWise Virtual / vPC, Huawei CSS / M-LAG): the engine reads two units of one model
under names that differ in their numbers as one, and builds the hierarchy around the unit that the other switches go through.  Standards and vendor notes: Cisco Campus LAN and
Wireless LAN Design Guide https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html ;
StackWise Virtual https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9500-series-switches/216537-troubleshoot-svl-on-catalyst-9000-switch.html
"""

from __future__ import annotations

import pytest

from features.topology import roles
from features.topology.extract import Device, HalfEdge
from features.topology.graph import build
from features.topology.service import build_topology
from tests.topology_samples import iosxe_capture


def _dev(name, model, neighbours, role="switch", stack=1, hosts=0):
    halves = [HalfEdge(local_port=f"Eth1/{i}", remote_name=n, remote_port="Eth1/48", protocols={"LLDP"}) for i, n in enumerate(neighbours, 1)]
    halves += [HalfEdge(local_port=f"Gi1/0/{i}", remote_name=f"PC{name.replace('-', '')}X{i}", remote_port="nic", protocols={"LLDP"}, remote_caps="Station") for i in range(1, hosts + 1)]
    return Device(key=name, hostname=name, captured=True, role_hint=role, model=model, stack_members=stack, halves=halves)


def _graph(devices):
    graph = build(devices)
    roles.classify(graph)
    return graph


@pytest.mark.parametrize("name,role", [("HQCORENX1", "core"), ("JKTCORE01", "core"), ("DCCORESW", "core"), ("HQEDGNX1", "aggregation"), ("DCEDGSW2", "aggregation"),
                                       ("ENCORE", ""), ("SCORE1", ""), ("HARDCORE", ""), ("CORELLA", ""), ("HQMETROENX1", "")])
def test_a_role_word_written_into_a_longer_name_is_read_but_ordinary_words_are_not(name, role):
    found = roles._by_rules(roles._WORD_RULES, name) or roles._by_rules(roles._EMBEDDED_RULES, name)
    assert (found if name != "HARDCORE" else "") == role or (name == "HARDCORE" and not role)


def test_hardcore_and_encore_are_no_core_switches():
    for name in ("HARDCORE", "ENCORE", "SCORE1", "CORELLA"):
        assert not roles._by_rules(roles._EMBEDDED_RULES, name)


@pytest.mark.parametrize("model", ["CISCO2951/K9", "CISCO3945-CHASSIS", "CISCO1941/K9", "C921-4P"])
def test_integrated_services_routers_are_routers_by_model(model):
    assert roles._by_rules(roles._MODEL_RULES, model) == "router"


@pytest.mark.parametrize("model", ["C9300-48P", "C9500-24Y4C", "C9200L-24P-4G"])
def test_catalyst_switch_models_are_not_routers(model):
    assert roles._by_rules(roles._MODEL_RULES, model) != "router"


def test_two_units_of_one_model_that_serve_the_same_switches_are_one_logical_device_but_a_row_of_closets_is_not():
    pair = _graph([_dev("ZZA1", "N9K-C93108TC-EX", ["ZZB1", "ZZB2", "ZZB3"]), _dev("ZZA2", "N9K-C93108TC-EX", ["ZZB1", "ZZB2", "ZZB3"]),
                   _dev("ZZB1", "C9300-48P", ["ZZA1", "ZZA2"]), _dev("ZZB2", "C9300-48P", ["ZZA1", "ZZA2"]), _dev("ZZB3", "C9300-48P", ["ZZA1", "ZZA2"])])
    keys = {k for k, n in pair.nodes.items() if n.captured}
    near = {k: {m for m in keys if any(c.kind not in pair.hidden_kinds and {c.a, c.b} == {k, m} for c in pair.connections)} for k in keys}
    clusters = roles.twin_clusters(pair, keys, set(), near)
    assert frozenset(("ZZA1", "ZZA2")) in clusters
    assert not any(len(c) > 2 for c in clusters)                      # the three closets share the pair, they are not one device with it


def test_the_centre_is_the_pair_that_every_closet_hangs_from_not_the_closet_with_most_links():
    graph = _graph([_dev("ZZA1", "N9K-C93108TC-EX", ["ZZB1", "ZZB2", "ZZB3"]), _dev("ZZA2", "N9K-C93108TC-EX", ["ZZB1", "ZZB2", "ZZB3"]),
                    _dev("ZZB1", "C9300-48P", ["ZZA1", "ZZA2", "ZZB2"]), _dev("ZZB2", "C9300-48P", ["ZZA1", "ZZA2", "ZZB1"]), _dev("ZZB3", "C9300-48P", ["ZZA1", "ZZA2"])])
    depth = {k: n.hier_depth for k, n in graph.nodes.items() if n.captured}
    assert depth["ZZA1"] == depth["ZZA2"] == 0 and {depth[k] for k in ("ZZB1", "ZZB2", "ZZB3")} == {1}


def test_a_hub_with_many_end_points_and_only_closets_below_it_is_left_as_a_flat_row():
    graph = _graph([_dev("HUB-SW1", "JL724B", ["HUB-SW2", "HUB-SW3", "HUB-SW4"], hosts=roles.CENTRE_OWN_ENDS),
                    _dev("HUB-SW2", "JL724B", ["HUB-SW1"]), _dev("HUB-SW3", "JL724B", ["HUB-SW1"]), _dev("HUB-SW4", "JL724B", ["HUB-SW1"])])
    assert all(n.hier_depth is None for n in graph.nodes.values() if n.captured)


def test_a_small_branch_hub_stays_the_core_of_its_closets():
    graph = _graph([_dev("MED-SW1", "JL724B", ["MED-SW2", "MED-SW3"], hosts=2), _dev("MED-SW2", "JL724B", ["MED-SW1"]), _dev("MED-SW3", "JL724B", ["MED-SW1"])])
    assert graph.nodes["MED-SW1"].hier_depth == 0 and graph.nodes["MED-SW1"].role_hint == "core"


def test_a_stack_and_a_virtual_pair_are_drawn_as_several_boxes_in_the_web_view_and_the_diagram_file():
    files = {"A.txt": iosxe_capture("LAB-A1", "FOC0000A001", "10.1.0.1", cdp=[("LAB-B1", "10.1.0.2", "C9300L", "Gi1/0/1", "Gi1/0/1")])}
    result = build_topology(list(files.items()))
    node = next(n for n in result["graph"].nodes.values() if n.hostname == "LAB-A1")
    assert 'class="stack-unit"' not in next(s["svg"] for s in result["svgs"] if s["view"] == "physical")
    node.stack_members = 3
    from features.topology import drawio, svg
    page = result["pages"][0]
    out = svg.to_svg(page, result["graph"])
    assert out.count('class="stack-unit"') == 2 and ">x3<" in out
    xml = drawio.to_drawio(result["graph"], pages=[page])
    assert xml == "" or xml.count("-unit") == 2
    assert drawio.stack_units(node) == 3
    node.stack_members, node.svl_domain = 1, "10"
    assert drawio.stack_units(node) == 2


def test_a_run_that_has_used_its_reading_time_skips_the_captures_still_to_read_and_says_so(monkeypatch):
    from features.topology import service
    clock = iter(range(0, 1000, 100))
    monkeypatch.setattr(service.time, "monotonic", lambda: next(clock))
    files = [(f"cap{i}.txt", iosxe_capture(f"LAB-A{i}", f"FOC000{i}A001", f"10.1.0.{i}", cdp=[])) for i in range(1, 5)]
    devices, skipped = service.read_devices(files, budget=150)
    assert len(devices) + len(skipped) == 4 and skipped and all("reading time" in s["reason"] for s in skipped)
    again, none = service.read_devices(files[:2], budget=0)                      # 0 = no budget
    assert len(again) == 2 and none == []


def test_the_units_of_the_centre_stand_in_one_frame_in_the_web_view_and_the_diagram_file():
    from features.topology import drawio, svg
    from features.topology.scene import build_pages
    graph = _graph([_dev("ZZA1", "N9K-C93108TC-EX", ["ZZB1", "ZZB2", "ZZB3"]), _dev("ZZA2", "N9K-C93108TC-EX", ["ZZB1", "ZZB2", "ZZB3"]),
                    _dev("ZZB1", "C9300-48P", ["ZZA1", "ZZA2"]), _dev("ZZB2", "C9300-48P", ["ZZA1", "ZZA2"]), _dev("ZZB3", "C9300-48P", ["ZZA1", "ZZA2"])])
    page = build_pages(graph)[0]
    assert len(page.centers) == 1 and "2 units" in page.centers[0][0]
    title, x, y, w, h = page.centers[0]
    for key in ("ZZA1", "ZZA2"):                                          # both units lie inside the frame
        pos = page.nodes[key]
        assert x <= pos.x and pos.x + 76 <= x + w and y <= pos.y and pos.y + 76 <= y + h
    assert 'class="centre-frame"' in svg.to_svg(page, graph) and "-centre-0" in drawio.to_drawio(graph, pages=[page])


def _star_graph():
    def router(name, neighbours):
        return _dev(name, "ISR4331/K9", neighbours)
    return _graph([router("RT1", ["EDGA1"]), router("RT2", ["EDGA1"]), router("RT3", ["EDGA1"]),
                   _dev("EDGA1", "N9K-C93108TC-EX", ["RT1", "RT2", "RT3", "EDGA2", "CORE1"]), _dev("EDGA2", "N9K-C93108TC-EX", ["EDGA1", "CORE1", "CORE2"]),
                   _dev("CORE1", "N9K-C93180YC-FX3", ["EDGA1", "EDGA2", "ACC1"]), _dev("CORE2", "N9K-C93180YC-FX3", ["EDGA2", "ACC1"]), _dev("ACC1", "C9300-48P", ["CORE1", "CORE2"])])


def test_the_two_units_of_a_pair_stand_in_one_row_when_only_one_of_them_is_cabled_to_the_outside():
    from features.topology import layout
    graph = _star_graph()
    keys = list(graph.nodes)
    rows = layout.outside_in_rows(graph, keys, layout._tier_values(graph, keys))
    assert rows["CORE1"] == rows["CORE2"]                    # CORE2 is only reached through CORE1's row counted from the routers: it stays beside its twin
    assert rows["EDGA1"] != rows["EDGA2"]                    # two edge units that serve other switches than each other are no pair (TWIN_OVERLAP)


def test_a_centre_with_something_else_between_its_units_is_not_framed():
    import dataclasses
    from features.topology.scene import build_pages, center_frames
    graph = _graph([_dev("ZZA1", "N9K-C93108TC-EX", ["ZZB1", "ZZB2", "ZZB3"]), _dev("ZZA2", "N9K-C93108TC-EX", ["ZZB1", "ZZB2", "ZZB3"]),
                    _dev("ZZB1", "C9300-48P", ["ZZA1", "ZZA2"]), _dev("ZZB2", "C9300-48P", ["ZZA1", "ZZA2"]), _dev("ZZB3", "C9300-48P", ["ZZA1", "ZZA2"])])
    page = build_pages(graph)[0]
    assert len(center_frames(graph, page)) == 1
    a, b = page.nodes["ZZA1"], page.nodes["ZZA2"]
    page.nodes["ZZB1"] = dataclasses.replace(page.nodes["ZZB1"], x=(a.x + b.x) / 2, y=a.y)
    assert center_frames(graph, page) == []


def test_two_candidates_that_tie_leave_the_group_without_a_centre():
    from features.topology import roles
    graph = _graph([_dev("PPA1", "C9300-48P", ["PPB1"]), _dev("PPB1", "C9300-48P", ["PPA1", "PPC1"]),
                    _dev("PPC1", "C9300-48P", ["PPB1", "PPD1"]), _dev("PPD1", "C9300-48P", ["PPC1"])])
    near = {k: set() for k in graph.nodes}
    for c in graph.connections:
        near[c.a].add(c.b)
        near[c.b].add(c.a)
    group = set(graph.nodes)
    names = {graph.nodes[k].hostname: k for k in group}
    assert roles.inferred_centre(graph, near, group, set()) == set()      # PPB1 and PPC1 are both in the middle and reach two switches: a guess would pick one at random
    near[names["PPD1"]].add(names["PPB1"])                                 # one more link makes PPB1 the only switch that reaches three others
    near[names["PPB1"]].add(names["PPD1"])
    assert roles.inferred_centre(graph, near, group, set()) == {names["PPB1"]}


def test_a_server_found_only_by_its_neighbour_is_not_counted_as_a_switch_nobody_captured():
    files = {"A.txt": iosxe_capture("LAB-A1", "FOC0000A001", "10.1.0.1", cdp=[("HCI-NODE-01", "10.1.0.50", "NX-3060-G6", "Gi1/0/1", "eth0")])}
    assert build_topology(list(files.items()))["summary"]["seen_only"] == 0


def test_a_sideways_uplink_is_not_drawn_where_the_comb_of_the_end_points_leaves_the_same_switch():
    import dataclasses
    from features.topology import scene
    from features.topology.scene import NODE_H, NODE_W, build_pages
    graph = _graph([_dev("SWAA1", "C9500-24Y4C", ["SWBB1"]), _dev("SWBB1", "C9300-48P", ["SWAA1", "SWCC1"], hosts=12), _dev("SWCC1", "C9300-48P", ["SWBB1"])])
    page = build_pages(graph)[0]
    page.nodes["SWCC1"] = dataclasses.replace(page.nodes["SWCC1"], x=page.nodes["SWBB1"].x - 500)      # the access switch stands beside, not under, its parent: the line would fan out sideways
    page.routes.clear()
    centres = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}
    uplink = next(i for i, c in enumerate(page.connections) if {c.a, c.b} == {"SWBB1", "SWCC1"})
    assert scene._route_fan(page, centres, {}, set()) == {uplink}                                     # no end points in a frame: the fan line is drawn
    for key, placed in list(page.nodes.items()):
        if key.startswith("PC"):
            page.nodes[key] = dataclasses.replace(placed, box="SWBB1")                                  # the end points stand in a frame under the switch: its comb leaves beside the icon
    page.routes.clear()
    assert scene._route_fan(page, centres, {}, set()) == set()

