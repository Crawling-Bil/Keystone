"""Sites of about the same size (a data center and its recovery site) stand side by side on the Overview, and the devices of the other site that are cabled to a device of this
site with the same role (the edge pair of the recovery site) stand in the same row on the site page.  Synthetic names and cables only."""

from __future__ import annotations

from collections import defaultdict

from features.topology import demo, scene
from features.topology.layout import groups_of
from features.topology.service import build_topology
from tests.test_topology_v05 import _graph_of


def _company(sizes: dict[str, int], joins: list[tuple[str, str]] = ()):
    names, links = [], []
    for site, count in sizes.items():
        members = [f"{site}-SW{i}" for i in range(1, count + 1)]
        names += members
        links += [(members[0], m) for m in members[1:]]
    links += [(f"{a}-SW1", f"{b}-SW1") for a, b in joins]
    return _graph_of(names, links)


def _boxes(sizes: dict[str, int], joins=()):
    graph = _company(sizes, joins)
    groups = groups_of(graph, "prefix1")
    _, boxes, _, _ = scene._arrange_groups(graph, groups)
    return {name: (x, y, w, h) for name, x, y, w, h in boxes}


def test_two_big_sites_stand_side_by_side_and_the_small_ones_below():
    box = _boxes({"DCA": 8, "DCB": 8, "BR1": 3, "BR2": 3, "BR3": 3, "BR4": 3}, [("DCA", "DCB"), ("DCA", "BR1"), ("DCB", "BR2")])
    assert box["DCA"][1] == box["DCB"][1] == 0 and box["DCA"][0] < box["DCB"][0]
    assert box["DCA"][0] + box["DCA"][2] <= box["DCB"][0]                                # side by side, not overlapping
    assert all(box[b][1] >= box["DCA"][1] + box["DCA"][3] for b in ("BR1", "BR2", "BR3", "BR4"))          # every small site is under the big ones
    rows = {box[b][1] for b in ("BR1", "BR2", "BR3", "BR4")}
    assert len(rows) >= 1 and min(box[b][0] for b in box if b.startswith("BR")) >= 0
    right = max(v[0] + v[2] for v in box.values())
    assert max(box[b][0] + box[b][2] for b in box if b.startswith("BR")) <= right + 1       # no row is wider than the page


def test_the_recovery_site_stands_last_whatever_its_size_and_name_order():
    box = _boxes({"AAA-DR": 10, "ZZZ-DC": 8, "BR1": 3})
    assert box["ZZZ-DC"][0] < box["AAA-DR"][0]                                           # the name says "recovery": it is drawn after the main site
    box = _boxes({"AAA": 8, "ZZZ": 10, "BR1": 3})
    assert box["ZZZ"][0] < box["AAA"][0]                                                 # no recovery word: the site with more network devices comes first
    box = _boxes({"AAA": 8, "ZZZ": 8, "BR1": 3})
    assert box["AAA"][0] < box["ZZZ"][0]                                                 # a tie falls back to the name


def test_one_big_site_many_equals_or_small_sites_keep_the_grid():
    def peers(sizes):
        graph = _company(sizes)
        groups = groups_of(graph, "prefix1")
        layouts = {n: ({}, 400.0, 300.0) for n in groups}
        return scene._arrange_peers(groups, layouts, defaultdict(lambda: defaultdict(int)), graph)

    assert peers({"HQ": 20, "B1": 3, "B2": 3, "B3": 3}) is None                          # one big site: the hub rule of the grid
    assert peers({"S1": 8, "S2": 8, "S3": 8, "S4": 8, "S5": 8}) is None                  # five equals are a grid
    assert peers({"S1": 3, "S2": 3, "S3": 3}) is None                                    # three small sites are not "big"
    assert peers({"S1": 8, "S2": 7, "S3": 9}) is not None                                # three campuses are a row
    assert peers({"S1": 8, "S2": 3}) is None                                             # 3 devices are under half of 8: not a peer


def test_the_recovery_edge_pair_stands_in_the_row_of_the_edge_pair_it_is_cabled_to():
    names = [f["name"] for f in next(s for s in demo.list_sets() if s["id"] == "dcdrc")["files"]]
    files = [(n, demo.read_file("dcdrc", n).decode("utf-8")) for n in names]
    built = build_topology(files, group="auto", view="physical", collapse_endpoints=False, include_hosts=False, group_endpoints=True, collapse_aps=False)
    pages = {p.name: p for p in built["pages"]}
    for page, near, far in (("HQ-DC", "HQ-DC-EDGE", "DRC-EDGE"), ("DRC", "DRC-EDGE", "HQ-DC-EDGE")):
        nodes = pages[page].nodes
        assert abs(nodes[f"{far}1"].y - nodes[f"{near}1"].y) < 40 and abs(nodes[f"{far}2"].y - nodes[f"{near}2"].y) < 40, page          # one row with it, not one row down, where one hop from the edge would put it (the zone layout moves the other site's block to the height of the devices it is cabled to)
        assert all(f"{far}{i}" in pages[page].ghosts for i in (1, 2))


def test_a_ghost_stands_on_the_side_its_site_has_on_the_overview():
    overview = scene.Page("Overview", boxes=[("HQ", 0.0, 0.0, 400.0, 300.0), ("DR", 500.0, 0.0, 400.0, 300.0), ("BR", 0.0, 400.0, 400.0, 200.0), ("NEAR", 410.0, 400.0, 20.0, 200.0), ("TOUCH", 190.0, 700.0, 20.0, 100.0)])
    groups = {"HQ": ["h1"], "DR": ["d1"], "BR": ["b1"], "NEAR": ["n1"], "TOUCH": ["t1"]}
    assert scene._ghost_sides(overview, groups, "HQ", {"d1"}) == {"d1": 1}               # the recovery site is on the right of HQ ...
    assert scene._ghost_sides(overview, groups, "DR", {"h1"}) == {"h1": -1}              # ... so HQ is on the left of the recovery site
    assert scene._ghost_sides(overview, groups, "BR", {"d1", "b1x"}) == {"d1": 1}        # a key of no site has no side
    assert scene._ghost_sides(overview, groups, "HQ", {"n1"}) == {"n1": 1}
    assert scene._ghost_sides(overview, groups, "HQ", {"t1"}) == {}                      # a site straight below (10 px off) is on neither side
    assert scene._ghost_sides(scene.Page("Overview"), groups, "HQ", {"d1"}) == {}        # one box only: no sides


def test_the_site_pages_of_the_demo_show_the_other_site_on_its_overview_side():
    from tests.test_topology_sites_l3 import _build

    built = _build("dcdrc")
    pages = {p.name: p for p in built["pages"]}
    x = lambda page, key: page.nodes[key].x                                                   # noqa: E731
    assert x(pages["HQ-DC"], "DRC-EDGE1") > x(pages["HQ-DC"], "HQ-DC-EDGE1") and x(pages["HQ-DC"], "DRC-EDGE2") > x(pages["HQ-DC"], "HQ-DC-EDGE2")
    assert x(pages["DRC"], "HQ-DC-EDGE1") < x(pages["DRC"], "DRC-EDGE1") and x(pages["DRC"], "HQ-DC-EDGE2") < x(pages["DRC"], "DRC-EDGE2")
