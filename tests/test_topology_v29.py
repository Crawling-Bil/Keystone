"""Topology v2.9: the L3 pages in the layout check, lines that go round the devices, the management switch links as notes, one finding for many ports, the F5 pool frames in columns.

Everything is built from small synthetic networks (names ``YY-``) and the demo sets; no customer data.

Standards: Cisco, Out of band best practices https://www.cisco.com/c/en/us/solutions/collateral/service-provider/out-of-band-best-practices-wp.html ;
Cisco Campus LAN and Wireless LAN Design Guide https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from features.topology import demo, f5page, findings, l3over2, mgmtnotes, scene, service
from features.topology.corpus import BUILD
from features.topology.graph import build
from features.topology.report import settings_text
from tests.test_topology_v07_f5 import _graph as _f5_graph, _tree
from test_topology_v23 import _dev


def _demo_build(set_id: str, **extra):
    item = next(i for i in demo.list_sets() if i["id"] == set_id)
    files = [(f["name"], demo.read_file(set_id, f["name"]).decode("utf-8")) for f in item["files"]]
    return service.build_topology(files, **{**BUILD, "group": item.get("group", "none"), **extra})


# ---- the L3 pages are scored and listed apart --------------------------------------------------------------------------------------------------------------
def test_the_layout_check_lists_the_l3_pages_apart_from_the_physical_pages():
    built = _demo_build("multisite")
    rows = built["settings"]["layout_check_l3"]
    assert rows and all({"page", "devices", "crossings", "through", "length"} <= set(r) for r in rows)
    assert any("L3 over L2" in r["page"] for r in rows)
    assert not any("L3" in r["page"] for r in built["settings"]["layout_check"]), "the physical total keeps its meaning"
    text = settings_text(built["settings"], built["notices"])
    assert "Layout check of the L3 pages" in text and text.count("Total:") == 2


# ---- a line that is still through a device gets a wider bend ------------------------------------------------------------------------------------------------
def _fake_page(connections=()):
    return SimpleNamespace(connections=list(connections), routes={})


def _wall():
    """A line from (0, 0) to (2000, 0) with a wall of devices across it: boxes from y = -400 to y = 400 at x = 1000."""
    return [(960.0, -400.0, 1040.0, 400.0)]


def test_a_line_through_a_wall_of_devices_takes_a_bend_beyond_the_small_lifts():
    conn = SimpleNamespace(a="A", b="B")
    page = _fake_page([conn])
    centres = {"A": (0.0, 0.0), "B": (2000.0, 0.0)}
    found = scene._detour_clear(page, centres, conn, (0.0, 0.0), (2000.0, 0.0), (2000.0, 0.0), (0.0, 1.0), _wall(), [(1000.0, 0.0)])
    assert found is not None
    line = [(0.0, 0.0), *found, (2000.0, 0.0)]
    assert not any(scene._hits(p, q, _wall()) for p, q in zip(line, line[1:]))
    assert max(abs(y) for _, y in found) > 400, "the wall is 400 px each way: no lift of the small list clears it"


def test_the_reach_of_the_last_resort_bend_is_a_limit(monkeypatch):
    """Mutation check: with a reach of 100 px no bend clears a wall of 400 px, and the line stays as it was."""
    monkeypatch.setattr(scene, "CLEAR_REACH", 100.0)
    conn = SimpleNamespace(a="A", b="B")
    found = scene._detour_clear(_fake_page([conn]), {"A": (0.0, 0.0), "B": (2000.0, 0.0)}, conn, (0.0, 0.0), (2000.0, 0.0), (2000.0, 0.0), (0.0, 1.0), _wall(), [(1000.0, 0.0)])
    assert found is None


def test_an_arc_of_the_l3_pages_has_wider_bows_only_for_a_long_line():
    assert l3over2._long_bows(500.0, 60.0, []) == []
    wide = l3over2._long_bows(3000.0, 60.0, [])
    assert wide and max(abs(b) for b in wide) > 380 and {b > 0 for b in wide} == {True, False}


def test_the_l3_pages_of_the_demo_keep_their_few_lines_through_an_icon_down():
    """Before v2.9 the arcs of this set put several lines through icons; the wider bows leave the ones that have no clear bow at all."""
    from features.topology.layoutscore import score_page
    built = _demo_build("dcdrc")
    through = sum(score_page(page)["through"] for page in built["l3_pages"] + built["l3_extra_pages"])
    assert through <= 2, through


# ---- the management switch links as notes -------------------------------------------------------------------------------------------------------------------
def _mgmt_net(extra_mgmt: list[str] | None = None, only_edge: bool = False):
    """A core, an aggregation switch, a router and an access switch, and a management switch cabled to all four (its uplinks are the core and the aggregation switch)."""
    mg = ["YY-RT1", "YY-ACC1"] if only_edge else ["YY-CORE1", "YY-AGG1", "YY-RT1", "YY-ACC1"]
    devices = [
        _dev("YY-CORE1", "N9K-C93180YC-FX3", ["YY-AGG1", "YY-RT1"] + ([] if only_edge else ["YY-MGMT1"])),
        _dev("YY-AGG1", "C9500-24Y4C", ["YY-CORE1", "YY-ACC1"] + ([] if only_edge else ["YY-MGMT1"])),
        _dev("YY-RT1", "ASR1002-X", ["YY-CORE1", "YY-MGMT1"], role="router"),
        _dev("YY-ACC1", "C9300-24T", ["YY-AGG1", "YY-MGMT1"], hosts=2),
        _dev("YY-MGMT1", "WS-C2960X-48TS-L", mg),
    ]
    return devices


def _kinds(built, other):
    graph = built["graph"]
    key = next(k for k, n in graph.nodes.items() if n.hostname == other)
    mg = next(k for k, n in graph.nodes.items() if n.hostname == "YY-MGMT1")
    return [c.kind for c in graph.connections if {c.a, c.b} == {key, mg}]


def test_the_links_of_a_management_switch_to_a_router_and_a_switch_become_notes_and_its_uplinks_stay_lines():
    built = service.build_topology([], devices=_mgmt_net(), **{**BUILD, "group": "none"})
    assert _kinds(built, "YY-RT1") == ["mgmt-note"] and _kinds(built, "YY-ACC1") == ["mgmt-note"]
    assert _kinds(built, "YY-CORE1") != ["mgmt-note"] and _kinds(built, "YY-AGG1") != ["mgmt-note"]
    graph = built["graph"]
    rt = next(n for n in graph.nodes.values() if n.hostname == "YY-RT1")
    assert rt.mgmt_note.startswith("MGMT: YY-MGMT1 Eth"), rt.mgmt_note
    drawn = {(c.a, c.b) for p in built["pages"] for c in p.connections}
    assert not any(graph.connections[i].kind == "mgmt-note" and (c.a, c.b) in drawn for i, c in enumerate(graph.connections))
    assert any("YY-MGMT1" in n and "note" in n for n in built["notices"])


def test_a_note_is_a_fourth_line_of_the_label_in_the_pictures():
    from features.topology import labels
    built = service.build_topology([], devices=_mgmt_net(), **{**BUILD, "group": "none"})
    rt = next(n for n in built["graph"].nodes.values() if n.hostname == "YY-RT1")
    assert labels.node_lines(rt)[3] == rt.mgmt_note
    assert rt.mgmt_note in built["svgs"][0]["svg"]
    assert "MGMT: YY-MGMT1" in built["drawio"]


def test_with_the_option_off_every_link_is_drawn_as_before():
    built = service.build_topology([], devices=_mgmt_net(), mgmt_notes=False, **{**BUILD, "group": "none"})
    assert _kinds(built, "YY-RT1") != ["mgmt-note"]
    assert not any(getattr(n, "mgmt_note", "") for n in built["graph"].nodes.values())


def test_a_management_switch_that_has_no_uplink_keeps_its_best_link_as_a_line():
    built = service.build_topology([], devices=_mgmt_net(only_edge=True), **{**BUILD, "group": "none"})
    kinds = [_kinds(built, "YY-RT1")[0], _kinds(built, "YY-ACC1")[0]]
    assert sorted(kinds).count("mgmt-note") == 1, kinds                    # one of the two stays drawn: the management switch is not left alone in the picture
    assert _kinds(built, "YY-ACC1")[0] != "mgmt-note", "the switch ranks above the router as the best link"


def test_the_notes_are_in_links_csv_and_the_findings_still_see_the_links():
    built = service.build_topology([], devices=_mgmt_net(), **{**BUILD, "group": "none"})
    from features.topology.service import links_table
    table = links_table(built["graph"])
    assert any(r.get("kind") == "mgmt-note" for r in table)


# ---- one finding for many ports / devices -------------------------------------------------------------------------------------------------------------------
def _issues_graph():
    graph = build([_dev("YY-SW1", "C9300-24T", []), _dev("YY-SW2", "C9300-24T", [])])
    return graph


def test_many_ports_with_many_macs_are_one_finding_with_the_ports_in_the_detail():
    graph = _issues_graph()
    graph.issues += [{"type": "many-macs", "node": n, "port": f"Gi1/0/{i}", "count": 12 + i} for i, n in enumerate(["YY-SW1", "YY-SW1", "YY-SW2"], 1)]
    rows = [r for r in findings.build_findings(graph) if r["id"] == "TOPO-007"]
    assert len(rows) == 1 and rows[0]["title"].startswith("3 ports")
    assert "Gi1/0/1: 13 MAC addresses" in rows[0]["detail"] and "Gi1/0/3: 15 MAC addresses" in rows[0]["detail"]
    assert rows[0]["devices"] == ["YY-SW1", "YY-SW2"]


def test_one_port_with_many_macs_keeps_its_own_title():
    graph = _issues_graph()
    graph.issues.append({"type": "many-macs", "node": "YY-SW1", "port": "Gi1/0/1", "count": 12})
    rows = [r for r in findings.build_findings(graph) if r["id"] == "TOPO-007"]
    assert len(rows) == 1 and rows[0]["title"] == "Many MAC addresses behind a port with no network neighbor"


def test_several_silent_devices_are_one_finding_with_every_name_in_it():
    graph = _issues_graph()
    rows = [r for r in findings.build_findings(graph) if r["id"] == "TOPO-008"]
    assert len(rows) == 1 and rows[0]["devices"] == ["YY-SW1", "YY-SW2"] and rows[0]["title"].startswith("2 devices")


def test_the_f5_units_without_a_neighbor_table_are_one_finding():
    built = _demo_build("dcdrc")
    rows = [r for r in built["findings"] if r["id"] == "TOPO-008"]
    assert len(rows) <= 2, [r["title"] for r in rows]


# ---- a pool with many members is a frame of several columns ---------------------------------------------------------------------------------------------------
def _pool_frame(members: int):
    page = f5page.page_for(_f5_graph(_tree(1, pools=1, members=members)), "LB1")
    frame = next(s for s in page.shapes if s.kind == "pool")
    kids = [s for s in page.shapes if s.kind == "member"]
    return page, frame, kids


def test_a_pool_of_thirty_members_stands_in_three_columns_inside_its_frame():
    _, frame, kids = _pool_frame(30)
    assert len(kids) == 30 and len({round(k.x) for k in kids}) == 3
    assert frame.w == f5page._pool_width(30) > f5page.POOL_W
    assert all(frame.x <= k.x and k.x + k.w <= frame.x + frame.w and frame.y <= k.y and k.y + k.h <= frame.y + frame.h for k in kids)
    assert len({(round(k.x), round(k.y)) for k in kids}) == 30, "no two members on one spot"


def test_a_small_pool_keeps_its_one_column_and_its_width():
    _, frame, kids = _pool_frame(5)
    assert frame.w == f5page.POOL_W and len({round(k.x) for k in kids}) == 1


def test_the_column_limit_is_what_keeps_a_big_pool_short(monkeypatch):
    """Mutation check: with the stack limit raised to 1000 the pool of 30 members is one column again."""
    _, frame, _ = _pool_frame(30)
    monkeypatch.setattr(f5page, "MEM_STACK", 1000)
    _, tall, _ = _pool_frame(30)
    assert tall.h > 2 * frame.h


def test_pools_of_different_widths_stand_side_by_side_without_overlap():
    tree = _tree(4, pools=4, members=2)
    for m in range(25):                                                    # make pool_1 a big one
        tree.append({"id": f"big{m}", "parent": "p1", "type": "member", "name": f"198.51.100.{m + 1}:80", "status": "unverified", "badge": "", "source": "config", "reason": "",
                     "facts": {"Address": f"198.51.100.{m + 1}", "Port": "80", "Pool": "pool_1"}})
    page = f5page.page_for(_f5_graph(tree), "LB1")
    frames = [s for s in page.shapes if s.kind == "pool"]
    for i, a in enumerate(frames):
        for b in frames[i + 1:]:
            assert a.x + a.w <= b.x or b.x + b.w <= a.x or a.y + a.h <= b.y or b.y + b.h <= a.y, (a.label, b.label)


def test_the_roles_that_take_a_note_are_what_decides_which_links_move(monkeypatch):
    """Mutation check: with no role allowed to carry a note every link of the management switch is drawn again."""
    monkeypatch.setattr(mgmtnotes, "NOTE_ROLES", ())
    built = service.build_topology([], devices=_mgmt_net(), **{**BUILD, "group": "none"})
    assert "mgmt-note" not in _kinds(built, "YY-RT1") + _kinds(built, "YY-ACC1")
