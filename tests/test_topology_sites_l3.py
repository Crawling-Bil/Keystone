"""The "Sites · L3 over L2" page: on a large Overview, only the L3 links that leave a site, drawn on the devices that carry them.  Invented demo sets only."""

from __future__ import annotations

from functools import lru_cache

import pytest

from features.topology import corpus, demo, service as S

SITES = "Sites · L3 over L2"


@lru_cache(maxsize=None)
def _build(set_id: str):
    item = next(i for i in demo.list_sets() if i["id"] == set_id)
    files = [(f["name"], demo.read_file(set_id, f["name"]).decode("utf-8")) for f in item["files"]]
    return S.build_topology(files, **{**corpus.BUILD, "group": item.get("group", "none")})


def _page(built, name):
    return next((p for p in built["l3_pages"] if p.name == name), None)


def _site_of(page, key):
    node = page.nodes[key]
    return next((t.split(" · ")[0] for t, x, y, w, h in page.boxes if x <= node.x <= x + w and y <= node.y <= y + h), None)


@pytest.mark.parametrize("set_id", ["multisite", "dcdrc"])
def test_a_large_overview_gets_a_page_of_the_links_between_sites(set_id):
    built = _build(set_id)
    full, sites = _page(built, "Overview · L3 over L2"), _page(built, SITES)
    assert sites is not None
    assert [p.name for p in built["l3_pages"]].index(SITES) == [p.name for p in built["l3_pages"]].index("Overview · L3 over L2") + 1
    assert len(sites.nodes) < 0.4 * len(full.nodes)
    drawn = [c for c in sites.connections if (c.l3 or {}).get("over2")]
    assert drawn
    captured = {k for k, n in sites.graph.nodes.items() if n.captured}
    for conn in drawn:                                       # a link between two captured devices joins two sites; the others end at a cloud or a remote peer
        if conn.a in captured and conn.b in captured:
            assert _site_of(sites, conn.a) != _site_of(sites, conn.b)
    assert corpus.row(sites)["cross"] < corpus.row(full)["cross"] / 3


def test_the_box_titles_say_how_many_devices_are_shown():
    sites = _page(_build("dcdrc"), SITES)
    titles = {t.split(" · ")[0]: t for t, *_ in sites.boxes}
    assert titles["HQ-DC"].endswith("of 28 devices") and titles["BAL"].endswith("1 of 16 devices")
    shown = sum(int(t.split(" · ")[1].split(" of ")[0]) for t in titles.values())
    assert shown == len([k for k in sites.nodes if k in sites.graph.nodes and sites.graph.nodes[k].captured])


def test_a_vlan_of_one_site_is_not_a_link_between_sites():
    sites = _page(_build("dcdrc"), SITES)
    assert not [n for n in sites.graph.nodes.values() if n.role_hint == "segment"]
    full = _page(_build("dcdrc"), "Overview · L3 over L2")
    assert any(n.role_hint == "segment" for n in full.graph.nodes.values())               # the full page has them, this one does not


def test_the_site_boxes_keep_the_order_of_the_overview():
    built = _build("dcdrc")
    sites, overview = _page(built, SITES), next(p for p in built["pages"] if p.name == "Overview")
    left = lambda page, name: next(x for t, x, *_ in page.boxes if t.split(" · ")[0] == name)
    assert left(sites, "HQ-DC") < left(sites, "DRC") and left(overview, "HQ-DC") < left(overview, "DRC")


def test_a_small_network_gets_no_such_page():
    for set_id in ("before", "after", "edge"):
        assert _page(_build(set_id), SITES) is None


def test_the_tables_do_not_list_a_link_twice():
    built = _build("dcdrc")
    ids = [row["id"] for row in built["l3_links"] if "id" in row]
    assert len(ids) == len(set(ids))


def test_a_page_is_made_only_when_the_links_between_sites_touch_few_devices(monkeypatch):
    from features.topology import l3over2

    built = _build("dcdrc")
    full = _page(built, "Overview · L3 over L2")
    args = (built["graph"], next(p for p in built["pages"] if p.name == "Overview"), full.l3["model"], full.l3["colours"], {id(e): i for i, e in full.l3["all"]}, full.l3["names"])
    assert l3over2.sites_page(*args) is not None
    monkeypatch.setattr(l3over2, "SITES_MIN_SHRINK", 0.1)                 # 24 of 140 devices is 17 %
    assert l3over2.sites_page(*args) is None
    monkeypatch.setattr(l3over2, "SITES_MIN_SHRINK", 0.75)
    monkeypatch.setattr(l3over2, "SITES_MIN_DEVICES", 200)
    assert l3over2.sites_page(*args) is None


def test_a_cloud_across_the_top_edge_of_its_box_goes_up_out_of_it():
    from features.topology.l3over2 import CAPTION_H, FRAME_AIR, _clear_frames
    from features.topology.layout import NODE_H, NODE_W
    from features.topology.scene import Page, Placed

    nodes = {"A": Placed(100.0, 300.0, 0, 0), "B": Placed(400.0, 300.0, 0, 1)}
    page = Page("t", nodes, set(), [("One", 20.0, 200.0, 300.0, 300.0), ("Two", 340.0, 200.0, 300.0, 300.0)], [], {}, 700.0, 600.0)
    ends = {"cloud": ["A"], "wide": ["A", "B"], "inside": ["B"], "above": ["B"]}
    spots = {"cloud": (100.0, 120.0), "wide": (560.0, 120.0), "inside": (420.0, 300.0), "above": (420.0, 20.0)}
    moved = _clear_frames(page, spots, ends, set())
    assert moved == {"cloud": (100.0, 200.0 - FRAME_AIR - NODE_H - CAPTION_H)}        # the caption of "cloud" (120 .. 120 + NODE_H + CAPTION_H) is cut by the edge at y = 200; the others are left
    assert _clear_frames(page, {"cloud": (100.0, 205.0)}, ends, set())["cloud"][1] < 200.0          # a cloud on the title strip goes up too
    assert _clear_frames(page, spots, ends, {"cloud"}) == {}                                          # a cloud in the WAN band stays
    assert NODE_W > 0


@pytest.mark.parametrize("set_id", ["multisite", "dcdrc"])
def test_no_cloud_stands_across_the_top_edge_of_a_site_box_on_the_sites_page(set_id):
    from features.topology.l3over2 import CAPTION_H
    from features.topology.layout import NODE_H

    page = _page(_build(set_id), SITES)
    clouds = [k for k, n in page.graph.nodes.items() if not n.captured and k in page.nodes]
    assert clouds
    for key in clouds:
        y = page.nodes[key].y
        for _, bx, by, bw, bh in page.boxes:
            assert not (y < by < y + NODE_H + CAPTION_H and page.nodes[key].x < bx + bw and page.nodes[key].x + 76 > bx), (key, by)


def test_a_lifted_node_slides_sideways_when_it_would_land_on_the_caption_of_another():
    """Lifting a node out of its box changes only its height: a neighbour that was clear before may now stand just beside it.  The lifted node slides to the nearest free place."""
    from features.topology.l3over2 import CAPTION_H, FRAME_AIR, _clear_frames, _off_neighbours
    from features.topology.layout import NODE_H, NODE_W
    from features.topology.satellites import CELL_W
    from features.topology.scene import Page, Placed

    nodes = {"A": Placed(100.0, 300.0, 0, 0), "B": Placed(400.0, 300.0, 0, 1)}
    page = Page("t", nodes, set(), [("One", 20.0, 200.0, 300.0, 300.0), ("Two", 340.0, 200.0, 300.0, 300.0)], [], {}, 700.0, 600.0)
    top = 200.0 - FRAME_AIR - NODE_H - CAPTION_H
    spots = {"cloud": (100.0, 120.0), "next": (100.0 + 113.0, top - 12.0)}          # 'next' stands beside the place the cloud is lifted to (113 px away: its caption would overlap)
    moved = _clear_frames(page, spots, {"cloud": ["A"]}, set())
    x, y = moved["cloud"]
    assert y == top and abs(x - spots["next"][0]) >= CELL_W
    assert _off_neighbours((100.0, top), "cloud", {"cloud": (100.0, 120.0)}) == (100.0, top)          # nothing near: stays
