"""Zone layout (v2.2): the core in the middle, the way out above it, the user LAN and the server farm below it, a box round each zone (features/topology/zones.py, zonelayout.py).

Built from the invented ``dcdrc`` demo set (HQ-DC, DRC and branches).  The expected picture is the one an engineer draws by hand for such a site: WAN routers, edge pair and the
firewalls of the way out on top; the core pair in a frame in the middle; the LAN zone (firewall pair, distribution pair, access switches, PCs) and the server farm (firewall pair,
server-farm pair, top-of-rack switches, servers) under it; the other site (a ghost of this page) at the side.  The rules are about roles and cables, not names: the last tests change
the names and the picture must not change.

Standards for the shape: Cisco Campus LAN and Wireless LAN Design Guide https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html ;
Cisco Massively Scalable Data Center (spine/leaf blocks) https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/white-paper-c11-743245.html
"""

from __future__ import annotations

import io
import json
import re

import pytest

from features.topology import demo, service, zones
from features.topology.service import build_topology


def _captures(setid: str = "dcdrc") -> list[tuple[str, str]]:
    return [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / setid).glob("*.txt"))]


def _built(**more) -> dict:
    return build_topology(_captures(), group="auto", collapse_endpoints=False, include_hosts=False, view="all", group_endpoints=True, collapse_aps=False, **more)


@pytest.fixture(scope="module")
def built() -> dict:
    return _built()


def _page(result: dict, name: str = "HQ-DC"):
    return next(p for p in result["pages"] if p.name == name and p.view == "physical")


def _y(page, key: str) -> float:
    return page.nodes[key].y


def _x(page, key: str) -> float:
    return page.nodes[key].x


def test_the_way_out_stands_above_the_core_and_the_inside_below_it(built):
    page = _page(built)
    core = _y(page, "HQ-DC-CORE1")
    for key in ("HQ-DC-WANR1", "HQ-DC-EDGE1", "HQ-DC-FGWAN1"):
        assert _y(page, key) < core, key
    for key in ("HQ-DC-FGLAN1", "HQ-DC-DS1", "HQ-DC-ACC1", "HQ-DC-PC1", "HQ-DC-PADC1", "HQ-DC-SF1", "HQ-DC-TOR1", "HQ-DC-SRV1"):
        assert _y(page, key) > core, key


def test_the_core_pair_stands_in_the_middle_of_the_page(built):
    page = _page(built)
    inner = [n for k, n in page.nodes.items() if k not in page.ghosts]
    left, right = min(n.x for n in inner), max(n.x for n in inner)
    core = (_x(page, "HQ-DC-CORE1") + _x(page, "HQ-DC-CORE2")) / 2
    assert left + 0.3 * (right - left) < core < left + 0.7 * (right - left)


def test_lan_and_server_farm_are_two_zones_side_by_side_under_the_core(built):
    page = _page(built)
    lan = [k for k, n in page.nodes.items() if n.zone == "LAN / USER"]
    farm = [k for k, n in page.nodes.items() if n.zone == "SERVER FARM"]
    assert {"HQ-DC-FGLAN1", "HQ-DC-DS1", "HQ-DC-ACC1", "HQ-DC-PC1"} <= set(lan)
    assert {"HQ-DC-PADC1", "HQ-DC-SF1", "HQ-DC-TOR1", "HQ-DC-SRV1"} <= set(farm)
    assert max(page.nodes[k].x for k in lan) < min(page.nodes[k].x for k in farm)          # one beside the other: no icon of one in the columns of the other


def test_a_server_farm_hangs_from_the_pair_the_core_is_cabled_to(built):
    page = _page(built)
    assert _y(page, "HQ-DC-PADC1") < _y(page, "HQ-DC-SF1") < _y(page, "HQ-DC-TOR1") < _y(page, "HQ-DC-SRV1")


def test_the_other_site_stands_outside_the_zones_of_this_one(built):
    page = _page(built)
    mine = [n for k, n in page.nodes.items() if k not in page.ghosts]
    for key in page.ghosts:
        assert page.nodes[key].zone == "OTHER SITE"
        assert page.nodes[key].x > max(n.x for n in mine) or page.nodes[key].x + 76 < min(n.x for n in mine)


def test_every_zone_has_a_box_that_holds_its_devices_and_no_two_boxes_overlap(built):
    page = _page(built)
    assert {title for title, *_ in page.zones} >= {"WAN / BRANCH", "LAN / USER", "SERVER FARM", "OTHER SITE"}
    by_title = {title: (x, y, x + w, y + h) for title, kind, x, y, w, h in page.zones}
    for key, node in page.nodes.items():
        if node.zone in by_title:
            x0, y0, x1, y1 = by_title[node.zone]
            assert x0 <= node.x and node.x + 76 <= x1 and y0 <= node.y and node.y + 76 <= y1, (key, node.zone)
    boxes = list(by_title.values())
    for i, a in enumerate(boxes):
        for b in boxes[i + 1:]:
            assert a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1]


def test_the_kinds_say_where_a_zone_belongs(built):
    kinds = {title: kind for title, kind, *_ in _page(built).zones}
    assert kinds["WAN / BRANCH"] == "external"
    assert kinds["LAN / USER"] == kinds["SERVER FARM"] == "internal"
    assert kinds["OTHER SITE"] == "ghost"


def test_the_svg_has_the_boxes_in_one_group_the_page_can_hide(built):
    svg = next(s["svg"] for s in built["svgs"] if s["name"] == "HQ-DC" and s["view"] == "physical")
    assert svg.count('class="zone-boxes"') == 1
    assert svg.index('class="zone-boxes"') < svg.index("<polyline")                            # under the lines
    for title in ("WAN / BRANCH", "LAN / USER", "SERVER FARM"):
        assert f">{title}</text>" in svg


def test_the_drawio_boxes_are_a_locked_layer_of_their_own_under_the_diagram(built):
    xml = built["drawio"]
    diagram = next(d for d in xml.split("<diagram")[1:] if 'value="Zones"' in d)                  # the page of HQ-DC
    first = diagram.index('value="Zones"')
    assert 'style="locked=1;"' in diagram[first - 80:first + 80]
    assert first < diagram.index('id="1" parent="0"')                                          # the layer comes first: drawn at the bottom
    assert re.search(r'parent="\d+-zones"', diagram)


def test_zone_boxes_off_draws_none_but_keeps_the_placement():
    result = _built(zone_boxes=False)
    page = _page(result)
    assert page.zones == []
    assert _y(page, "HQ-DC-WANR1") < _y(page, "HQ-DC-CORE1") < _y(page, "HQ-DC-DS1")           # the placement is the same
    assert "zone-boxes" not in next(s["svg"] for s in result["svgs"] if s["name"] == "HQ-DC" and s["view"] == "physical")
    assert 'value="Zones"' not in result["drawio"]


def test_zone_layout_off_is_the_compact_rows():
    page = _page(_built(zone_layout="off"))
    assert all(not n.zone for n in page.nodes.values()) and page.zones == []


def test_zone_layout_always_keeps_the_zones_even_where_the_rows_cross_less():
    result = _built(zone_layout="always")
    assert _page(result).zones and result["settings"]["zone_layout"] == "always"


def test_automatic_keeps_the_zones_when_they_are_not_clearly_worse(built):
    assert built["settings"]["zone_layout"] == "auto" and _page(built).zones


def test_automatic_falls_back_to_the_rows_when_the_zones_cost_many_more_crossings(monkeypatch):
    real = service._total_cost
    monkeypatch.setattr(service, "_total_cost", lambda result: 10_000.0 if any(n.zone for p in result["pages"] for n in p.nodes.values()) else real(result))
    result = _built()
    assert all(not n.zone for p in result["pages"] for n in p.nodes.values())
    assert result["settings"]["zone_layout"] == "off (kept the plain rows)"
    assert any("Zone layout" in note for note in result["notices"])


def test_a_page_with_only_a_router_and_one_switch_is_not_split_into_zones():
    result = build_topology(_captures("before"), group="none", collapse_endpoints=False, view="physical")
    page = result["pages"][0]
    graph = result["graph"]
    why: list[str] = []
    assert zones.plan(graph, list(page.nodes), why=why) is None or len({n.zone_id for n in page.nodes.values() if n.zone_id}) >= 2
    assert why or any(n.zone for n in page.nodes.values())


def test_the_plan_names_the_zones_from_roles_and_cables(built):
    graph = built["graph"]
    page = _page(built)
    found = zones.plan(graph, [k for k in page.nodes if k not in page.ghosts] + sorted(page.ghosts), page.ghosts)
    kinds = sorted(z.kind for z in found.zones if z.kind != "ghost")
    assert kinds == ["external", "internal", "internal"]
    assert {graph.nodes[k].hostname for k in found.centre} == {"HQ-DC-CORE1", "HQ-DC-CORE2"}


def test_a_centre_nobody_captured_still_gets_its_zones(built):
    """The centre is found from the cables (the switch the others go through), so a core that was only seen by its neighbours is a core all the same."""
    graph = built["graph"]
    page = _page(built)
    keys = [k for k in page.nodes if k not in page.ghosts]
    centre = zones.find_centre(graph, set(keys))
    assert centre
    for key in centre:
        graph.nodes[key].captured = False
    try:
        assert zones.plan(graph, keys) is not None
    finally:
        for key in centre:
            graph.nodes[key].captured = True


def test_the_names_only_title_the_zones_the_placement_follows_the_cables(monkeypatch):
    before = {k: (n.x, n.y) for k, n in _page(_built()).nodes.items()}
    monkeypatch.setattr(zones, "TITLE_WORDS", ())                                              # no host name says anything about a zone any more
    page = _page(_built())
    assert {k: (n.x, n.y) for k, n in page.nodes.items()} == before
    assert sorted(kind for _, kind, *_ in page.zones) == ["external", "ghost", "internal", "internal"]          # the same zones, titled from the functions of their devices


def test_one_zone_with_nearly_everything_is_no_picture_of_zones(built, monkeypatch):
    graph, page = built["graph"], _page(built)
    keys = [k for k in page.nodes if k not in page.ghosts]
    assert zones.plan(graph, keys) is not None
    monkeypatch.setattr(zones, "BIGGEST_SHARE", 0.2)                                           # the largest zone holds a third of the devices here: too much for this limit
    assert zones.plan(graph, keys) is None


def test_the_page_keeps_the_rows_when_the_zones_make_the_lines_much_longer(monkeypatch):
    from features.topology import scene
    assert _page(_built()).zones
    monkeypatch.setattr(scene, "ZONE_LENGTH", 0.5)                                             # the zones may not be longer than half the rows: never true
    page = _page(_built())
    assert page.zones == [] and all(not n.zone for n in page.nodes.values())


def test_the_page_keeps_the_rows_when_the_zones_cross_more(monkeypatch):
    from features.topology import scene
    real = scene._cost
    monkeypatch.setattr(scene, "_cost", lambda graph, keys, placed, ghosts: (1000.0, 1.0) if any(p.zone for p in placed.values()) else real(graph, keys, placed, ghosts))
    page = _page(_built())
    assert page.zones == []


# ---- a zone with its own way out and its own servers (a DMZ) stands at the side ----------------------------------------------

def _tall_network():
    from features.topology import roles
    from features.topology.extract import Device, HalfEdge
    from features.topology.graph import build

    def dev(name, model, neighbours, role="switch", hosts=0, stack=1):
        halves = [HalfEdge(local_port=f"Eth1/{i}", remote_name=n, remote_port="Eth1/48", protocols={"LLDP"}) for i, n in enumerate(neighbours, 1)]
        halves += [HalfEdge(local_port=f"Gi1/0/{i}", remote_name=f"HOST{name.replace('-', '')}X{i}", remote_port="nic", protocols={"LLDP"}, remote_caps="Station") for i in range(1, hosts + 1)]
        return Device(key=name, hostname=name, captured=True, role_hint=role, model=model, stack_members=stack, halves=halves)

    devices = [
        dev("ZZ-CORE1", "N9K-C93180YC-FX3", ["ZZ-CORE2", "ZZ-AGGL1", "ZZ-AGGL2", "ZZ-FWD1", "ZZ-FWD2"]),
        dev("ZZ-CORE2", "N9K-C93180YC-FX3", ["ZZ-CORE1", "ZZ-AGGL1", "ZZ-AGGL2", "ZZ-FWD1", "ZZ-FWD2"]),
        dev("ZZ-AGGL1", "C9500-24Y4C", ["ZZ-CORE1", "ZZ-CORE2", "ZZ-AGGL2", "ZZ-ACCL1", "ZZ-ACCL2"]),
        dev("ZZ-AGGL2", "C9500-24Y4C", ["ZZ-CORE1", "ZZ-CORE2", "ZZ-AGGL1", "ZZ-ACCL1", "ZZ-ACCL2"]),
        dev("ZZ-ACCL1", "C9300-48P", ["ZZ-AGGL1", "ZZ-AGGL2"], hosts=2),
        dev("ZZ-ACCL2", "C9300-48P", ["ZZ-AGGL1", "ZZ-AGGL2"], hosts=2),
        dev("ZZ-FWD1", "FortiGate-600F", ["ZZ-CORE1", "ZZ-CORE2", "ZZ-FWD2", "ZZ-XRT1", "ZZ-XRT2", "ZZ-SVD1", "ZZ-SVD2"], role="firewall"),
        dev("ZZ-FWD2", "FortiGate-600F", ["ZZ-CORE1", "ZZ-CORE2", "ZZ-FWD1", "ZZ-XRT1", "ZZ-XRT2", "ZZ-SVD1", "ZZ-SVD2"], role="firewall"),
        dev("ZZ-XRT1", "ISR4331/K9", ["ZZ-FWD1", "ZZ-FWD2"], role="router"),
        dev("ZZ-XRT2", "ISR4331/K9", ["ZZ-FWD1", "ZZ-FWD2"], role="router"),
        dev("ZZ-SVD1", "C9300-24T", ["ZZ-FWD1", "ZZ-FWD2"], hosts=2),
        dev("ZZ-SVD2", "C9300-24T", ["ZZ-FWD1", "ZZ-FWD2"], hosts=2),
    ]
    graph = build(devices)
    roles.classify(graph)
    return graph


def test_a_zone_with_its_own_way_out_and_its_own_servers_stands_at_the_side():
    graph = _tall_network()
    keys = [k for k, n in graph.nodes.items() if n.captured or n.role_hint in ("host", "server")]
    found = zones.plan(graph, keys)
    assert found is not None
    assert sorted(z.kind for z in found.zones) == ["internal", "tall"]
    tall = next(z for z in found.zones if z.kind == "tall")
    assert {graph.nodes[k].hostname for k in tall.members} >= {"ZZ-XRT1", "ZZ-FWD1", "ZZ-SVD1"}
    from features.topology import layout
    placed, _, _ = layout.layered(graph, keys, zoned=True)
    core = placed["ZZ-CORE1"]
    assert placed["ZZ-XRT1"].x + 76 < core.x or placed["ZZ-XRT1"].x > core.x + 76               # the DMZ is beside the core column, not above or below it


# ---- the orthogonal line shape ---------------------------------------------------------------------------------------------

def test_orthogonal_lines_have_only_right_angles_between_the_stubs():
    result = _built(line_shape="orthogonal")
    page = _page(result)
    bent = [route for route in page.routes.values() if len(route) >= 4]
    assert bent
    for route in bent:
        inner = route[1:-1]                                                                   # the first and last point are the stubs under the icons
        for (x0, y0), (x1, y1) in zip(inner, inner[1:]):
            assert abs(x0 - x1) < 0.5 or abs(y0 - y1) < 0.5, route


def test_orthogonal_lines_that_share_a_strip_lie_on_different_lanes():
    page = _page(_built(line_shape="orthogonal"))
    runs: dict[int, list[tuple[float, float]]] = {}
    for route in page.routes.values():
        if len(route) < 4:
            continue
        (x0, y0), (x1, y1) = route[1], route[2]
        if abs(y0 - y1) < 0.5:
            runs.setdefault(round(y0), []).append((min(x0, x1), max(x0, x1)))
    for lane, spans in runs.items():
        for i, a in enumerate(spans):
            for b in spans[i + 1:]:
                assert min(a[1], b[1]) - max(a[0], b[0]) <= 4, lane                          # two runs on one track over more than 4 px would look like one line


def test_the_options_reach_the_build_and_unknown_values_fall_back(tmp_path, monkeypatch):
    from app import create_app
    from features.topology import routes
    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    sets = {s["id"]: s for s in client.get("/topology/api/demo").get_json()["sets"]}
    files = [(io.BytesIO(client.get(f"/topology/api/demo/dcdrc/{f['name']}").data), f["name"]) for f in sets["dcdrc"]["files"]]
    body = client.post("/topology/api/build", data={"files": files, "group": "auto", "zone_layout": "always", "zone_boxes": "0", "line_shape": "orthogonal", "view": "physical"},
                       content_type="multipart/form-data").get_json()
    assert body["ok"]
    saved = json.loads((tmp_path / body["export_id"] / "topology.json").read_text(encoding="utf-8"))["build"]
    assert saved["zone_layout"] == "always" and saved["zone_boxes"] is False and saved["line_shape"] == "orthogonal"
    files = [(io.BytesIO(client.get(f"/topology/api/demo/dcdrc/{f['name']}").data), f["name"]) for f in sets["dcdrc"]["files"]]
    body = client.post("/topology/api/build", data={"files": files, "group": "auto", "zone_layout": "sideways", "line_shape": "zigzag", "view": "physical"}, content_type="multipart/form-data").get_json()
    saved = json.loads((tmp_path / body["export_id"] / "topology.json").read_text(encoding="utf-8"))["build"]
    assert saved["zone_layout"] in ("auto", "off (kept the plain rows)") and saved["line_shape"] == "angled"


def test_the_page_offers_the_options_and_the_zone_toggle():
    html = (service.__file__.rsplit("/features/", 1)[0] + "/templates/topology.html")
    text = open(html, encoding="utf-8").read()
    assert 'data-role="zone-layout"' in text and 'data-role="zone-boxes"' in text and 'value="orthogonal"' in text
    js = open(html.replace("templates/topology.html", "static/js/topology.js"), encoding="utf-8").read()
    assert 'body.append("zone_layout"' in js and 'body.append("zone_boxes"' in js and 'data-zoom="zones"' in js
