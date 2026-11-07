"""The placement engine counts rows from the outside in when the role rows contradict the cables (``layout.outside_in_rows``).

The role rows put every core switch above every distribution switch.  A pair of edge switches between the WAN routers and the core then landed below the core it feeds,
and every line of the page ran upward past it.  These tests build the multi-site head quarter without any saved layout and measure the picture with straight lines.
"""

from __future__ import annotations

import itertools

import pytest

from features.topology import demo, layout
from features.topology.service import build_topology


def _captures(setid: str) -> list[tuple[str, str]]:
    return [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / setid).glob("*.txt"))]


def _build(setid: str) -> dict:
    return build_topology(_captures(setid), group="auto" if setid == "multisite" else "none", collapse_endpoints=False, include_hosts=False, view="physical", group_endpoints=True, collapse_aps=False)


def _crossings(page) -> int:
    centre = {k: (n.x + 38, n.y + 38) for k, n in page.nodes.items()}
    lines = [(c.a, c.b) for c in page.connections if c.a in centre and c.b in centre and c.kind != "host"]

    def turn(a, b, c):
        return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])

    count = 0
    for (a, b), (x, y) in itertools.combinations(lines, 2):
        if len({a, b, x, y}) < 4:
            continue
        p1, p2, p3, p4 = centre[a], centre[b], centre[x], centre[y]
        if turn(p3, p4, p1) * turn(p3, p4, p2) < 0 and turn(p1, p2, p3) * turn(p1, p2, p4) < 0:
            count += 1
    return count


def _hq(built: dict):
    return next(p for p in built["pages"] if p.name == "HQ")


def test_the_edge_switches_stand_between_the_wan_routers_and_the_core():
    page = _hq(_build("multisite"))
    y = lambda name: page.nodes[name].y                                      # noqa: E731
    assert max(y("HQ-WANR1"), y("HQ-WANR2")) < min(y("HQ-EDGE1"), y("HQ-EDGE2"))         # the routers are the outside row
    assert max(y("HQ-EDGE1"), y("HQ-EDGE2")) < min(y("HQ-CORE1"), y("HQ-CORE2"))        # the edge pair is above the core it feeds, not below it
    assert max(y("HQ-CORE1"), y("HQ-CORE2")) < min(y("HQ-ACC1"), y("HQ-ACC2"), y("HQ-TOR1"), y("HQ-TOR2"))


def test_the_head_quarter_page_has_far_fewer_crossings_than_the_role_rows_gave():
    assert _crossings(_hq(_build("multisite"))) <= 18                         # 34 with the role rows alone


def _places(built: dict) -> dict:
    return {(p.name, k): (round(n.x), round(n.y)) for p in built["pages"] for k, n in p.nodes.items()}


def test_the_rule_stays_out_of_pages_whose_role_rows_agree_with_the_cables(monkeypatch):
    with_rule = {setid: _places(_build(setid)) for setid in ("before", "after", "edge")}
    monkeypatch.setattr(layout, "outside_in_rows", lambda graph, keys, value: {})
    without = {setid: _places(_build(setid)) for setid in ("before", "after", "edge")}
    assert with_rule == without and all(with_rule.values())                  # the small sets keep every position they always had


def test_without_the_rule_the_edge_switches_fall_below_the_core(monkeypatch):
    monkeypatch.setattr(layout, "outside_in_rows", lambda graph, keys, value: {})
    page = _hq(_build("multisite"))
    assert page.nodes["HQ-EDGE1"].y > page.nodes["HQ-CORE1"].y               # the mutation check: the tests above fail for this reason
    assert _crossings(page) > 18


def test_a_row_made_only_of_pairs_keeps_every_pair_side_by_side():
    page = _hq(_build("multisite"))
    for a, b in (("HQ-CORE1", "HQ-CORE2"), ("HQ-FGWAN1", "HQ-FGWAN2"), ("HQ-EDGE1", "HQ-EDGE2"), ("HQ-FGLAN1", "HQ-FGLAN2"), ("HQ-PADC1", "HQ-PADC2")):
        assert page.nodes[a].y == page.nodes[b].y, (a, b)                    # the vPC cores and the WAN firewalls share one row: no diagonal peer-link
        assert 0 < page.nodes[b].x - page.nodes[a].x < 1000, (a, b)
    assert _crossings(page) <= 18


def _route_page(setid: str = "multisite"):
    built = build_topology(_captures(setid), group="auto" if setid == "multisite" else "none", collapse_endpoints=False, include_hosts=False, view="all", group_endpoints=True, collapse_aps=False)
    return next(p for p in built["l3_extra_pages"] if p.view == "l3route")


def _long_ways(page) -> int:
    """Lines whose routed path is far longer than the straight line: a line that was sent round the outside of a row."""
    count = 0
    for index, conn in enumerate(page.connections):
        a, b = page.nodes[conn.a], page.nodes[conn.b]
        path = [(a.x, a.y), *page.routes.get(index, []), (b.x, b.y)]
        way = sum(((p[0] - q[0]) ** 2 + (p[1] - q[1]) ** 2) ** 0.5 for p, q in zip(path, path[1:]))
        straight = ((a.x - b.x) ** 2 + (a.y - b.y) ** 2) ** 0.5
        if way > 1.15 * straight + 100:
            count += 1
    return count


def test_provider_clouds_stand_at_the_height_that_keeps_their_lines_short(monkeypatch):
    page = _route_page()
    clouds = [k for k, n in page.graph.nodes.items() if n.role_hint == "cloud"]
    assert len(clouds) == 6 and len({round(page.nodes[k].y) for k in clouds}) >= 2          # one cloud stands higher than the rest
    assert _long_ways(page) == 0                                                           # no line runs over the top of the row of clouds
    from features.topology import l3page
    monkeypatch.setattr(l3page, "CLOUD_LEVELS", 1)                                         # the mutation check: every cloud in one row, as before
    assert _long_ways(_route_page()) >= 3


def test_the_single_cloud_of_a_small_page_keeps_its_row():
    page = _route_page("edge")
    clouds = [k for k, n in page.graph.nodes.items() if n.role_hint == "cloud"]
    assert len(clouds) == 1 and all(page.nodes[c].y < page.nodes[k].y for c in clouds for k in page.nodes if k not in clouds)       # above every device, as always
    assert _long_ways(page) == 0


def _overview_page():
    built = build_topology(_captures("multisite"), group="auto", collapse_endpoints=False, include_hosts=False, view="all", group_endpoints=True, collapse_aps=False)
    return next(p for p in list(built["l3_pages"]) + list(built["l3_extra_pages"]) if p.view == "l3over2" and p.name.startswith("Overview"))


def _routed_crossings(page) -> tuple[int, float]:
    """Crossings between the routed paths of lines that share no device, and the total length of the paths."""
    def turn(a, b, c):
        return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])

    lines = []
    for index, conn in enumerate(page.connections):
        a, b = page.nodes.get(conn.a), page.nodes.get(conn.b)
        if a is None or b is None:
            continue
        lines.append(({conn.a, conn.b}, [(a.x + 38, a.y + 38), *[tuple(p) for p in page.routes.get(index, [])], (b.x + 38, b.y + 38)]))
    segs = [(i, s) for i, (_, pts) in enumerate(lines) for s in zip(pts, pts[1:])]
    count = sum(1 for (i, p), (j, q) in itertools.combinations(segs, 2)
                if i != j and not lines[i][0] & lines[j][0] and turn(*q, p[0]) * turn(*q, p[1]) < 0 and turn(*p, q[0]) * turn(*p, q[1]) < 0)
    length = sum(((p[0] - q[0]) ** 2 + (p[1] - q[1]) ** 2) ** 0.5 for _, pts in lines for p, q in zip(pts, pts[1:]))
    return count, length


def test_provider_clouds_of_the_overview_stand_in_a_band_between_the_site_boxes(monkeypatch):
    page = _overview_page()
    shared = [k for k, n in page.graph.nodes.items() if n.role_hint == "cloud" and len({e for c in page.connections for e in (c.a, c.b) if k in (c.a, c.b)} - {k}) >= 2]
    top = min(y for _, _, y, _, _ in page.boxes)
    inside = lambda k: any(x <= page.nodes[k].x + 38 <= x + w and y <= page.nodes[k].y + 38 <= y + h for _, x, y, w, h in page.boxes)      # noqa: E731
    wan = [k for k in shared if not inside(k)]                                              # the clouds that stand in no box
    assert len(wan) >= 4 and all(page.nodes[k].y > top for k in wan)                        # and below the top of the topmost row of boxes: in the strip between the rows
    crossings, length = _routed_crossings(page)
    from features.topology import l3over2
    monkeypatch.setattr(l3over2, "_open_wan_band", lambda phys, ends: (phys, {}))          # the mutation check: no band, the clouds above the page as before
    before_crossings, before_length = _routed_crossings(_overview_page())
    assert crossings <= before_crossings - 10 and length < before_length - 2000


def _stack_of_boxes():
    """Four site boxes in a column (one device each, 500 px apart); returns the page and the key of the device of every box."""
    from features.topology.layout import Placed
    from features.topology.scene import Page

    page = Page("Overview")
    for i in range(4):
        page.nodes[f"d{i}"] = Placed(300.0, 100.0 + i * 500.0, 0)
        page.boxes.append((f"site{i}", 100.0, i * 500.0, 600.0, 300.0))
    page.height = 2000.0
    return page


def test_the_band_for_provider_clouds_is_the_strip_nearest_the_devices_they_serve():
    from features.topology.l3over2 import _open_wan_band

    page = _stack_of_boxes()
    moved, placed = _open_wan_band(page, {"isp": ["d2", "d3"]})                           # a provider of the two lower sites
    assert placed["isp"][1] > 800 and moved.height > page.height - 1                       # between the second and the third box (and below the page's top part)
    assert moved.nodes["d3"].y > page.nodes["d3"].y                                       # the boxes below the strip moved down to make room for it
    moved, placed = _open_wan_band(page, {"isp": ["d0", "d1"]})                           # a provider of the two upper sites
    assert 300 < placed["isp"][1] < 600                                                   # the strip between them, not the one near the lower sites


def test_a_provider_cloud_of_one_site_box_or_a_page_of_two_boxes_is_not_given_a_band():
    from features.topology.l3over2 import _open_wan_band

    page = _stack_of_boxes()
    assert _open_wan_band(page, {"isp": ["d1"]})[1] == {}                                  # one site only: the satellites place it
    small = _stack_of_boxes()
    small.boxes = small.boxes[:2]
    assert _open_wan_band(small, {"isp": ["d0", "d1"]})[1] == {}                           # fewer than three boxes
