"""Topology Builder v0.7: all views in one file, end-point boxes per switch, star layout of router pages, one firewall per VDOM / vsys,
BIG-IP interface tables and the virtual-server map.  Synthetic data only."""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import pytest

from tests.topology_samples import iosxe_capture

FIXTURES = Path(__file__).parent / "fixtures"
ROUTER = FIXTURES / "router"
SDWAN = ("c8200_sdwan_cedge_masked.txt", "cedge_sdwan_overlay_masked.txt")


@pytest.fixture()
def client():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _two_routers():
    a = iosxe_capture("RTR-A", "FOC00000071", "10.96.0.1", cdp=[], config_extra="interface GigabitEthernet0/0/1\n description to RTR-B\n ip address 192.0.2.1 255.255.255.252\n!\n"
                      "interface Loopback0\n ip address 198.51.100.1 255.255.255.255\n!\n")
    b = iosxe_capture("RTR-B", "FOC00000072", "10.96.0.2", cdp=[], config_extra="interface GigabitEthernet0/0/1\n description to RTR-A\n ip address 192.0.2.2 255.255.255.252\n!\n"
                      "interface GigabitEthernet0/0/2\n description LAN\n ip address 203.0.113.1 255.255.255.0\n!\n")
    return [("a.txt", a), ("b.txt", b)]


def _post(client, files=None, extra=None, view=None):
    files = files or _two_routers()
    data = {"files": [(io.BytesIO(text.encode("utf-8")), name) for name, text in files], "group": "none", **({"view": view} if view else {}), **(extra or {})}
    return client.post("/topology/api/build", data=data, content_type="multipart/form-data")


def _page_names(drawio: str):
    return [d.get("name") for d in ET.fromstring(drawio).findall("diagram")]


# ---------------------------------------------------------------- B: all views
def test_all_views_puts_every_view_in_the_drawio_file():
    from features.topology.service import build_topology
    names = _page_names(build_topology(_two_routers(), view="all")["drawio"])
    assert names == ["Overview · L3 over L2", "L3 - Logical and Route", "IP view", "Overview", "How to read this diagram"]


def test_all_views_adds_the_vpc_view_last_when_the_captures_have_a_pair():
    from features.topology.service import build_topology
    from tests.topology_samples import lab_dc
    names = _page_names(build_topology(list(lab_dc().items()), view="all")["drawio"])
    assert names[-1] == "Overview (vPC view)" and "Overview" in names and names.index("Overview") < len(names) - 1


def test_all_views_order_is_l3_over_l2_route_ip_physical():
    from features.topology.service import all_views_order
    assert all_views_order(["o"], ["r"], ["i"], ["p"], ["v"]) == ["o", "r", "i", "p", "v"]
    assert all_views_order([], [], [], ["p"], []) == ["p"]


def test_the_zip_and_the_report_hold_every_view_too(client):
    body = _post(client).get_json()
    assert {p["view"] for p in body["pages"]} == {"l3over2", "l3route", "ip", "physical"}
    pack = next(d for d in body["downloads"] if d["name"] == "keystone-topology-pack.zip")
    with zipfile.ZipFile(io.BytesIO(client.get(pack["url"]).data)) as archive:
        diagrams = [n for n in archive.namelist() if "/diagrams/" in n]
        report = archive.read(next(n for n in archive.namelist() if n.endswith("topology-report.html"))).decode("utf-8")
        settings = archive.read(next(n for n in archive.namelist() if n.endswith("run-settings.txt"))).decode("utf-8")
    assert len(diagrams) == 4
    assert all(f"({kind})" in report for kind in ("L3 over L2", "L3 route view", "IP view", "Physical view"))
    assert "All views" in settings


def test_the_default_of_the_web_form_is_all_views(client):
    from features.topology import routes
    assert routes.DEFAULT_VIEW == "all"
    body = _post(client, view="nonsense").get_json()
    assert {p["view"] for p in body["pages"]} >= {"l3over2", "l3route", "physical"}


def test_a_single_view_still_gives_a_single_view():
    from features.topology.service import build_topology
    names = _page_names(build_topology(_two_routers(), view="physical")["drawio"])
    assert names == ["Overview"]


def test_the_form_offers_all_views_first_and_the_script_opens_the_l3_view(client):
    page = client.get("/topology").data.decode("utf-8")
    select = page[page.index('data-role="view"'):]
    assert select.index('value="all"') < select.index('value="l3over2"')
    script = Path(__file__).resolve().parents[1].joinpath("static/js/topology.js").read_text(encoding="utf-8")
    assert "function startView" in script and 'choice === "all"' in script


# ---------------------------------------------------------------- C: end points framed per switch
def _endpoint_graph(counts: dict[str, int], extra_links: list[tuple[str, str]] | None = None, group: bool = True):
    """Switches SW-<n> under one core, each with ``counts[switch]`` phones that nobody captured."""
    from features.topology.extract import Device
    from features.topology.graph import Connection, Graph, Link
    nodes = {"CORE": Device(key="CORE", hostname="CORE", captured=True, role_hint="core")}
    conns = []

    def join(a, b):
        conns.append(Connection(a, b, [Link(a, "Eth1/1", b, "Eth1/1", "confirmed", {"CDP"}, "")]))

    for sw, n in counts.items():
        nodes[sw] = Device(key=sw, hostname=sw, captured=True, role_hint="access")
        join("CORE", sw)
        for i in range(n):
            ph = f"{sw}-PH{i + 1}"
            nodes[ph] = Device(key=ph, hostname=ph, captured=False, role_hint="phone")
            join(sw, ph)
    for a, b in extra_links or []:
        join(a, b)
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set(), group_endpoints=group)


def test_end_points_of_one_switch_get_one_titled_frame_and_frames_do_not_overlap():
    from features.topology.scene import build_pages
    page = build_pages(_endpoint_graph({"SW-A": 5, "SW-B": 2, "SW-C": 9}))[0]
    assert sorted(t for t, *_ in page.end_boxes) == ["SW-A", "SW-B", "SW-C"]
    boxes = sorted(page.end_boxes, key=lambda b: b[1])
    for (_, x, y, w, h), (_, x2, y2, w2, h2) in zip(boxes, boxes[1:]):
        assert x + w + 20 <= x2 or y + h <= y2 or y2 + h2 <= y            # a free strip between two frames
    for title, x, y, w, h in page.end_boxes:                              # every icon of the switch is inside its frame and nobody else's
        inside = {k for k, p in page.nodes.items() if x <= p.x and p.x + 76 <= x + w and y <= p.y and p.y + 76 <= y + h}
        assert {k for k in inside if k.startswith(title + "-PH")} == {k for k in page.nodes if k.startswith(title + "-PH")}
        assert not {k for k in inside if "-PH" in k and not k.startswith(title + "-PH")}


def test_a_switch_with_one_end_point_is_not_framed_and_the_option_can_be_off():
    from features.topology.scene import build_pages
    assert build_pages(_endpoint_graph({"SW-A": 1, "SW-B": 1}))[0].end_boxes == []
    assert build_pages(_endpoint_graph({"SW-A": 4, "SW-B": 4}, group=False))[0].end_boxes == []


def test_a_dual_homed_end_point_stays_outside_every_frame():
    from features.topology.extract import Device
    from features.topology.scene import build_pages
    graph = _endpoint_graph({"SW-A": 3, "SW-B": 3})
    graph.nodes["SRV"] = Device(key="SRV", hostname="SRV", captured=False, role_hint="server")
    from features.topology.graph import Connection, Link
    for sw in ("SW-A", "SW-B"):
        graph.connections.append(Connection(sw, "SRV", [Link(sw, "Eth1/9", "SRV", "", "confirmed", {"CDP"}, "")]))
    page = build_pages(graph)[0]
    assert page.nodes["SRV"].box == "" and len(page.end_boxes) == 2


def test_the_frames_are_drawn_in_svg_and_drawio_and_survive_the_other_views():
    import xml.etree.ElementTree as ET
    from features.topology.drawio import to_drawio
    from features.topology.scene import build_pages
    from features.topology.svg import to_svg
    graph = _endpoint_graph({"SW-A": 4, "SW-B": 3})
    pages = build_pages(graph)
    svg = to_svg(pages[0], graph)
    assert "End points of SW-A" in svg and "End points of SW-B" in svg
    cells = [c for c in ET.fromstring(to_drawio(graph, pages=pages)).iter("mxCell") if "endbox" in (c.get("id") or "")]
    assert sorted(c.get("value") for c in cells) == ["SW-A", "SW-B"]


def test_without_frames_the_switch_layout_is_unchanged():
    from features.topology.scene import build_pages
    plain = build_pages(_endpoint_graph({"SW-A": 4, "SW-B": 3}, group=False))[0]
    framed = build_pages(_endpoint_graph({"SW-A": 4, "SW-B": 3}, group=True))[0]
    assert plain.end_boxes == [] and framed.end_boxes
    assert all(p.box == "" for p in plain.nodes.values())                                        # the plain page is the old layered row layout
    phones = sorted(p.x for k, p in plain.nodes.items() if "-PH" in k)
    assert len({p.y for k, p in plain.nodes.items() if "-PH" in k}) == 1 and all(b - a >= 229 for a, b in zip(phones, phones[1:]))


def test_the_option_acts_only_when_end_points_are_drawn_one_by_one():
    from features.topology.service import build_topology
    from tests.topology_samples import lab_dc
    files = list(lab_dc().items())
    assert build_topology(files, collapse_endpoints=False)["settings"]["group_endpoints"] is True
    assert build_topology(files, collapse_endpoints=True)["settings"]["group_endpoints"] is False
    assert build_topology(files, collapse_endpoints=False, exclude_endpoints=True)["settings"]["group_endpoints"] is False
    assert build_topology(files, collapse_endpoints=False, group_endpoints=False)["settings"]["group_endpoints"] is False


def test_the_form_has_the_checkbox_checked_by_default(client):
    page = client.get("/topology").data.decode("utf-8")
    row = page[page.index('data-role="group-endpoints"') - 120:page.index('data-role="group-endpoints"') + 80]
    assert 'data-dep="no-exclude no-collapse"' in row and "checked" in row
    body = _post(client, extra={"collapse_endpoints": "0", "exclude_endpoints": "0"}).get_json()
    assert body["ok"]


# ---------------------------------------------------------------- D: star layout of router pages
def _star_graph(links, roles, captured=None, models=None):
    from features.topology.extract import Device
    from features.topology.graph import Connection, Graph, Link
    nodes = {n: Device(key=n, hostname=n, captured=(captured is None or n in captured), role_hint=r, model=(models or {}).get(n, "")) for n, r in roles.items()}
    conns = [Connection(a, b, [Link(a, "Gi0/0", b, "Gi0/0", "confirmed", {"CDP"}, "")]) for a, b in links]
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set())


def _crossings_and_hits(page):
    from features.topology.layout import NODE_H, NODE_W

    def turn(p, q, r):
        return (q[0] - p[0]) * (r[1] - p[1]) - (q[1] - p[1]) * (r[0] - p[0])

    lines = []
    for i, c in enumerate(page.connections):
        a, b = page.nodes[c.a], page.nodes[c.b]
        lines.append((c, [(a.x + NODE_W / 2, a.y + NODE_H / 2), *page.routes.get(i, []), (b.x + NODE_W / 2, b.y + NODE_H / 2)]))
    crossings = 0
    for i, (c1, p1) in enumerate(lines):
        for c2, p2 in lines[i + 1:]:
            if {c1.a, c1.b} & {c2.a, c2.b}:
                continue
            crossings += any(turn(p1[x], p1[x + 1], p2[y]) * turn(p1[x], p1[x + 1], p2[y + 1]) < 0 and turn(p2[y], p2[y + 1], p1[x]) * turn(p2[y], p2[y + 1], p1[x + 1]) < 0
                             for x in range(len(p1) - 1) for y in range(len(p2) - 1))
    hits = 0
    for c, pts in lines:
        for key, p in page.nodes.items():
            if key in (c.a, c.b):
                continue
            for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
                if any(p.x - 2 < x1 + (x2 - x1) * t / 40 < p.x + NODE_W + 2 and p.y - 2 < y1 + (y2 - y1) * t / 40 < p.y + NODE_H + 2 for t in range(1, 40)):
                    hits += 1
                    break
    return crossings, hits


ROLES = {"R1": "router", "R2": "router", "R3": "router", "ISP-RT": "router", "FW1": "firewall", "FW2": "firewall", "CORE1": "core", "CORE2": "core", "SW1": "access"}
LINKS = [("R1", "R2"), ("R2", "R3"), ("R1", "R3"), ("ISP-RT", "R1"), ("R1", "FW1"), ("R2", "FW2"), ("R3", "FW1"), ("FW1", "FW2"), ("FW1", "CORE1"), ("FW2", "CORE2"),
         ("CORE1", "CORE2"), ("CORE1", "SW1"), ("CORE2", "SW1")]
CAPTURED = {"R1", "R2", "R3", "FW1", "FW2", "CORE1", "CORE2", "SW1"}


def test_a_page_of_routers_is_laid_out_as_a_star_and_a_page_of_switches_is_not():
    from features.topology.layout import star_applicable
    routers = _star_graph(LINKS, ROLES, CAPTURED)
    assert star_applicable(routers, list(routers.nodes))
    switches = _star_graph([("A", "B")], {"A": "core", "B": "access"})
    assert not star_applicable(switches, ["A", "B"])
    one = _star_graph([("R1", "SW1")], {"R1": "router", "SW1": "access"})
    assert not star_applicable(one, ["R1", "SW1"])


def test_three_routers_that_all_talk_to_each_other_form_a_triangle_not_a_line_through_an_icon():
    from features.topology.scene import build_pages
    page = build_pages(_star_graph(LINKS, ROLES, CAPTURED))[0]
    crossings, hits = _crossings_and_hits(page)
    assert hits == 0
    assert crossings <= 2


def test_a_router_nobody_captured_sits_in_the_outside_row_above_the_captured_ones():
    from features.topology.scene import build_pages
    page = build_pages(_star_graph(LINKS, ROLES, CAPTURED))[0]
    assert page.nodes["ISP-RT"].y < min(page.nodes[k].y for k in ("R1", "R2", "R3"))


def test_the_two_units_of_a_firewall_pair_stand_next_to_each_other():
    from features.topology.layout import ha_pairs
    from features.topology.scene import build_pages
    graph = _star_graph(LINKS, ROLES, CAPTURED, {"FW1": "FortiGate-1101E", "FW2": "FortiGate-1101E"})
    assert ha_pairs(graph, list(graph.nodes)) == {frozenset(("FW1", "FW2"))}
    page = build_pages(graph)[0]
    assert abs(page.nodes["FW1"].x - page.nodes["FW2"].x) <= 460


def test_a_pair_at_the_end_of_a_wide_row_is_stacked_one_over_the_other():
    from features.topology.layout import _stack_ha_pairs
    rows = {1.0: ["FW1", "FW2", "C1", "C2"]}
    spot = {"FW1": 0.0, "FW2": 1.0, "C1": 2.0, "C2": 3.0}
    slots: dict[str, float] = {}
    _stack_ha_pairs(rows, [1.0], {frozenset(("FW1", "FW2"))}, spot, 0, slots)
    assert slots == {"FW1": 0.0, "FW2": 1.0, "C1": 0.0, "C2": 0.0}
    assert 0.5 < spot["FW2"] - spot["FW1"] < 0.7                       # one over the other, a little off the vertical
    rows = {1.0: ["C1", "FW1", "FW2", "C2"]}
    spot = {"C1": 0.0, "FW1": 1.0, "FW2": 2.0, "C2": 3.0}
    slots = {}
    _stack_ha_pairs(rows, [1.0], {frozenset(("FW1", "FW2"))}, spot, 0, slots)
    assert slots == {} and (spot["FW1"], spot["FW2"]) == (1.0, 2.0)  # between the main devices the pair stays side by side


def test_star_rows_never_put_two_icons_on_top_of_each_other():
    from features.topology.layout import NODE_H, NODE_W
    from features.topology.scene import build_pages
    page = build_pages(_star_graph(LINKS, ROLES, CAPTURED))[0]
    nodes = list(page.nodes.values())
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            assert abs(a.x - b.x) >= NODE_W or abs(a.y - b.y) >= NODE_H


def test_satellites_of_the_l3_over_l2_page_stand_on_free_spots_beside_what_they_serve():
    from features.topology.satellites import CELL_H, CELL_W, Extra, place
    fixed = {"A": (400.0, 400.0), "B": (900.0, 400.0)}
    spots = place(fixed, [Extra("NET", ["A", "B"]), Extra("CLOUD", ["A"], above=True), Extra("GW1", ["A"]), Extra("GW2", ["A"]), Extra("GW3", ["B"])])
    assert spots["CLOUD"][1] < 400 - CELL_H * 0.8                                       # a provider goes above its device
    everything = {**fixed, **spots}
    keys = list(everything)
    for i, k in enumerate(keys):
        for m in keys[i + 1:]:
            (x1, y1), (x2, y2) = everything[k], everything[m]
            assert abs(x1 - x2) >= CELL_W - 1 or abs(y1 - y2) >= CELL_H - 1, (k, m)     # no two nodes share a spot
