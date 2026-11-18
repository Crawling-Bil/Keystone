"""v3.1 layout round (invented demo sets only): zone boxes in the vPC view, label-aware spacing, mesh titles, child-switch corridors.

Zone boxes in the vPC view help a newcomer read the same areas (outside, core, LAN, server farm) on the collapsed picture.
Standards for the shape: Cisco Campus LAN and Wireless LAN Design Guide https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html ;
Cisco vPC https://www.cisco.com/c/it_it/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html
"""

from __future__ import annotations

import pytest

from features.topology import demo
from features.topology.layout import NODE_H, NODE_W
from features.topology.service import build_topology
from features.topology.svg import to_svg


def _captures(setid: str = "dcdrc") -> list[tuple[str, str]]:
    return [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / setid).glob("*.txt"))]


@pytest.fixture(scope="module")
def built() -> dict:
    return build_topology(_captures(), group="auto", collapse_endpoints=False, include_hosts=False, view="all", group_endpoints=True, collapse_aps=False)


def _centre(page, key):
    p = page.nodes[key]
    return p.x + NODE_W / 2, p.y + NODE_H / 2


def test_vpc_pages_carry_the_zone_boxes_of_their_physical_page(built):
    twins = [p for p in built["logical_pages"] if p.view == "logical"]
    assert twins, "the demo has vPC pairs"
    boxed = 0
    for twin in twins:
        physical = next(p for p in built["pages"] if p.name + " (vPC view)" == twin.name)
        if not physical.zones:
            assert twin.zones == []
            continue
        boxed += 1
        assert twin.zones, f"{twin.name} lost its zone boxes"
        assert sorted(z[0] for z in twin.zones) == sorted(z[0] for z in physical.zones)


def test_vpc_zone_boxes_hold_only_their_own_devices_and_whole_frames(built):
    for twin in built["logical_pages"]:
        for title, _kind, x, y, w, h in twin.zones:
            for key, placed in twin.nodes.items():
                cx, cy = _centre(twin, key)
                if x <= cx <= x + w and y <= cy <= y + h and placed.zone_id:
                    assert placed.zone == title, f"{key} ({placed.zone}) stands in the box of {title}"
            for frame in twin.pair_boxes.values():
                members_in = [x <= twin.nodes[m].x and twin.nodes[m].x + NODE_W <= x + w and y <= twin.nodes[m].y <= y + h for m in frame.members]
                if all(members_in):
                    assert x <= frame.x and frame.x + frame.w <= x + w and y <= frame.y and frame.y + frame.h <= y + h


def test_vpc_zone_boxes_do_not_overlap_each_other(built):
    for twin in built["logical_pages"]:
        zones = twin.zones
        for i in range(len(zones)):
            for j in range(i + 1, len(zones)):
                a, b = zones[i], zones[j]
                apart = a[2] + a[4] <= b[2] or b[2] + b[4] <= a[2] or a[3] + a[5] <= b[3] or b[3] + b[5] <= a[3]
                assert apart, f"{twin.name}: {a[0]} and {b[0]} overlap"


def test_vpc_svg_draws_the_zone_group_and_the_note_is_gone(built):
    from features.topology import service
    for twin in built["logical_pages"]:
        svg = to_svg(twin, built["graph"], True, "straight", None)
        assert ('class="zone-boxes"' in svg) == bool(twin.zones)
        if twin.zones:
            assert service._zone_note(twin, built["graph"]) == ""


def test_vpc_zone_boxes_off_in_options_stay_off():
    result = build_topology(_captures(), group="auto", collapse_endpoints=False, include_hosts=False, view="all", group_endpoints=True, collapse_aps=False, zone_boxes=False)
    for twin in result["logical_pages"]:
        assert twin.zones == []


# ---- label-aware spacing ---------------------------------------------------------------------------------------------------------------------------------------------------------

def _long_names() -> list[tuple[str, str]]:
    """The invented DC / DRC set with every HQ-DC device renamed to a long, capital-letter name (30 characters), the kind a real estate has."""
    import re
    return [(re.sub(r"HQ-DC-", "HEADQUARTERS-DATACENTER-", n), re.sub(r"HQ-DC-", "HEADQUARTERS-DATACENTER-", t)) for n, t in _captures()]


def _caption_overlaps(page, graph) -> list[tuple[str, str]]:
    from features.topology import labels
    from features.topology.textwidth import text_width
    boxes = []
    for key, placed in page.nodes.items():
        node = graph.nodes.get(key)
        if node is None:
            continue
        lines = [line[:34] for line in labels.node_lines(node) if line]
        width = max((text_width(line) for line in lines), default=0.0)
        boxes.append((key, placed.x + NODE_W / 2 - width / 2, placed.x + NODE_W / 2 + width / 2, placed.y + NODE_H + 4, placed.y + NODE_H + 4 + 14 * len(lines) + 4))
    return [(a[0], b[0]) for i, a in enumerate(boxes) for b in boxes[i + 1:] if a[2] > b[1] and b[2] > a[1] and a[4] > b[3] and b[4] > a[3]]


def test_text_width_uses_real_letter_widths():
    from features.topology.textwidth import text_width, widest
    assert text_width("") == 0
    assert text_width("iii") < text_width("WWW")                                   # a narrow and a wide letter differ a lot
    assert abs(text_width("HQ-DC-CORE1") - 84.7) < 1.0                              # capitals and digits are wider than the old 7 px a letter
    assert widest(["abc", "", "abcdef"]) == text_width("abcdef")
    assert widest(["x" * 80]) == text_width("x" * 34)                                # cut at 34 letters like the picture


def test_row_step_grows_with_the_widest_caption():
    from features.topology import layout
    result = build_topology(_long_names(), group="auto", collapse_endpoints=False, include_hosts=False, view="all", group_endpoints=True, collapse_aps=False)
    graph = result["graph"]
    keys = [k for k in graph.nodes if "HEADQUARTERS" in graph.nodes[k].hostname]
    assert keys
    step = layout._x_step(graph, keys)
    assert step >= max(layout.caption_width(graph, k) for k in keys) + layout.CAPTION_MARGIN
    assert layout.X_STEP <= step <= layout.X_MAX


def test_long_capital_names_never_overlap_on_any_page():
    result = build_topology(_long_names(), group="auto", collapse_endpoints=False, include_hosts=False, view="all", group_endpoints=True, collapse_aps=False)
    graph = result["graph"]
    pages = [p for key in ("pages", "l3_pages") for p in result.get(key) or []]
    assert pages
    for page in pages:
        assert _caption_overlaps(page, getattr(page, "graph", None) or graph) == [], page.name


def test_the_head_pair_of_a_zone_block_keeps_clear_of_each_others_names():
    from features.topology import layout
    result = build_topology(_long_names(), group="auto", collapse_endpoints=False, include_hosts=False, view="all", group_endpoints=True, collapse_aps=False)
    graph = result["graph"]
    page = next(p for p in result["pages"] if p.name == "HEADQUARTERS")
    heads = sorted((p.x, k) for k, p in page.nodes.items() if k.startswith("HEADQUARTERS-DATACENTER-DS"))
    assert len(heads) == 2
    (xa, a), (xb, b) = heads
    assert xb - xa >= (layout.caption_width(graph, a) + layout.caption_width(graph, b)) / 2 + layout.CAPTION_MARGIN - 1


# ---- child switches and the cables to end points ---------------------------------------------------------------------------------------------------------------------------------

def _corridor_graph():
    """Two parent switches P1 / P2, two child switches C1 / C2 each cabled to both parents (a mesh in the row below), and P1 with two end points two rows down."""
    from features.topology.extract import Device
    from features.topology.graph import Connection, Graph
    graph = Graph()
    for key, role in (("P1", "access"), ("P2", "access"), ("C1", "access"), ("C2", "access"), ("H1", "host"), ("H2", "host")):
        graph.nodes[key] = Device(key=key, hostname=key, role_hint=role)
    for a, b in (("P1", "C1"), ("P1", "C2"), ("P2", "C1"), ("P2", "C2"), ("P1", "H1"), ("P1", "H2")):
        graph.connections.append(Connection(a, b, [], kind="host" if b.startswith("H") else "link"))
    return graph


def _corridor_placed(shift: float = 0.0):
    from features.topology.layout import Placed
    return {
        "P1": Placed(300, 0, 1.0, "", None), "P2": Placed(900, 0, 1.0, "", None),
        "C1": Placed(330, 250, 2.0, "", None), "C2": Placed(630, 250, 2.0, "", None),
        "H1": Placed(150 + shift, 500, 3.0, "P1", None), "H2": Placed(450 + shift, 500, 3.0, "P1", None),
    }


def _cost(graph, placed):
    from features.topology.layoutscore import crosses
    centre = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in placed.items()}
    mine = [(centre["P1"], centre[k]) for k in ("H1", "H2")]
    others = [(centre[a], centre[b]) for a, b in (("P2", "C1"), ("P2", "C2"))]
    return sum(1 for p, q in mine for r, s in others if crosses((*p, *q), (*r, *s)))


def test_frame_of_end_points_slides_out_of_the_corridor_of_the_child_switches():
    from features.topology.layout import clear_corridors
    graph, placed = _corridor_graph(), _corridor_placed()
    before = _cost(graph, placed)
    assert before > 0, "the set-up must start with an end-point cable that crosses a cable of the children"
    assert clear_corridors(graph, placed, 230) is True
    assert _cost(graph, placed) == 0
    assert placed["H2"].x - placed["H1"].x == 300                                   # the end points keep their spacing and their order
    assert {k: (p.x, p.y) for k, p in placed.items() if k not in ("H1", "H2")} == {k: (p.x, p.y) for k, p in _corridor_placed().items() if k not in ("H1", "H2")}


def test_corridor_rule_leaves_a_clear_page_alone():
    from features.topology.layout import clear_corridors
    graph, placed = _corridor_graph(), _corridor_placed(shift=-400)
    assert _cost(graph, placed) == 0
    snapshot = {k: (p.x, p.y) for k, p in placed.items()}
    assert clear_corridors(graph, placed, 230) is False
    assert {k: (p.x, p.y) for k, p in placed.items()} == snapshot


def test_corridor_rule_never_puts_the_frame_over_another_icon():
    from features.topology.layout import Placed, clear_corridors
    graph, placed = _corridor_graph(), _corridor_placed()
    for shift in range(-700, -340, 40):                                              # every place to the left is taken by an icon that is not an end point
        placed[f"X{shift}"] = Placed(300 + shift, 500, 3.0, "", None)
        from features.topology.extract import Device
        graph.nodes[f"X{shift}"] = Device(key=f"X{shift}", hostname=f"X{shift}", role_hint="access")
    clear_corridors(graph, placed, 230)
    frame = (min(placed[k].x for k in ("H1", "H2")) - 85, max(placed[k].x for k in ("H1", "H2")) + 161)
    for key, p in placed.items():
        if key.startswith("X"):
            assert not (frame[0] < p.x + NODE_W and p.x < frame[1]), f"{key} stands inside the frame"


def test_corridor_rule_on_a_built_page_does_not_add_crossings(built):
    """On the invented sets the rule never makes a page worse: the layout score of each page is not above that of the same page with the rule switched off."""
    from features.topology import layout
    from features.topology.layoutscore import score_page
    original = layout.clear_corridors
    try:
        layout.clear_corridors = lambda graph, placed, xstep: False
        plain = build_topology(_captures(), group="auto", collapse_endpoints=False, include_hosts=False, view="all", group_endpoints=True, collapse_aps=False)
    finally:
        layout.clear_corridors = original
    off = {p.name: score_page(p) for p in plain["pages"]}
    for page in built["pages"]:
        now = score_page(page)
        assert now["crossings"] + 5 * now["through"] <= off[page.name]["crossings"] + 5 * off[page.name]["through"], page.name


# ---- frame titles ----------------------------------------------------------------------------------------------------------------------------------------------------------------

def test_short_variants_cut_at_the_dot_separator():
    from features.topology.titles import short_variants
    assert short_variants("CORE · 2 units · twin units") == ["CORE · 2 units · twin units", "CORE · 2 units", "CORE"]
    assert short_variants("INTERNAL") == ["INTERNAL"]


def _wall(x: float, y: float, h: float = 60.0):
    return (x, y - 10, x, y + h)                                      # a vertical line through the title strip


def test_a_core_title_takes_a_shorter_form_when_no_gap_holds_the_long_one():
    from features.topology.titles import CENTRE_LEFT, centre_title
    title = "CORE · 2 units · twin units"
    box = (title, 0.0, 0.0, 366.0, 182.0)
    walls = [_wall(x, 0.0) for x in (100, 250, 340)]                 # the gaps (100 and 150 px) are too narrow for the long title (about 158 px with padding), wide enough for its shorter forms
    fitted = centre_title(None, box, walls, [])
    assert fitted.hits == 0 and fitted.text != title and title.startswith(fitted.text)
    assert fitted.spot >= CENTRE_LEFT


def test_a_title_that_no_form_can_keep_clear_says_so():
    from features.topology.titles import centre_title, end_title, zone_title
    title = "CORE · 2 units · twin units"
    walls = [_wall(x, 0.0) for x in range(6, 360, 14)]                # a comb of lines across the whole strip
    assert centre_title(None, (title, 0.0, 0.0, 366.0, 182.0), walls, []).hits > 0
    assert end_title(None, ("SWITCH-A", 0.0, 0.0, 300.0, 180.0), [_wall(x, 0.0) for x in range(6, 300, 10)], []).hits > 0
    assert zone_title(None, ("LAN / USER", "internal", 0.0, 0.0, 300.0, 180.0), [_wall(x, 0.0) for x in range(6, 300, 10)], []).hits > 0


def test_a_clean_title_is_written_as_before():
    from features.topology.titles import centre_title
    title = "CORE · 2 units · twin units"
    fitted = centre_title(None, (title, 0.0, 0.0, 366.0, 182.0), [], [])
    assert fitted == type(fitted)(title, 10.0, 0)


def test_a_title_a_line_must_cross_is_drawn_on_top_with_a_halo(built, monkeypatch):
    """Every title in the SVG is in its frame (a clean gap) or in a layer over the lines with a halo; with a comb of lines across a zone's title strip, its name goes on top."""
    import re
    from features.topology import svg as svg_module
    page = next(p for p in built["pages"] if p.zones)
    graph = built["graph"]
    clean = to_svg(page, graph, True, "state", None)
    _t, _k, x, y, w, _h = page.zones[0]
    comb = [(x + dx, y - 20, x + dx, y + 60) for dx in range(4, int(w), 8)]
    monkeypatch.setattr(svg_module, "page_segments", lambda page_: comb)
    blocked = to_svg(page, graph, True, "state", None)
    assert blocked.count('class="title-on-top"') > clean.count('class="title-on-top"')
    layer = re.search(r'<g class="zone-boxes zone-titles">(.*?)</g>', blocked, flags=re.S)
    assert layer and 'paint-order="stroke"' in layer.group(1) and "pointer-events" in layer.group(1)
    assert blocked.index('class="zone-boxes zone-titles"') > blocked.index("<polyline")              # drawn after the lines, so the halo covers them


def test_zone_toggle_hides_every_zone_group_in_the_page_script():
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / "static" / "js" / "topology.js").read_text(encoding="utf-8")
    assert 'querySelectorAll(".zone-boxes")' in js and "boxGroups.forEach" in js


def _mesh_below_pair_graph(hosts: int = 2):
    """An aggregation pair (cabled to each other), two access switches cabled to both of them, and `hosts` end points under each aggregation switch: the DRC picture of the user's report."""
    from features.topology.extract import Device
    from features.topology.graph import Connection, Graph
    graph = Graph(group_endpoints=True)
    for key, role in (("P1", "aggregation"), ("P2", "aggregation"), ("C1", "access"), ("C2", "access")):
        graph.nodes[key] = Device(key=key, hostname=key, role_hint=role)
    for parent in ("P1", "P2"):
        for i in range(hosts):
            host = f"{parent}H{i}"
            graph.nodes[host] = Device(key=host, hostname=host, role_hint="host", captured=False)
            graph.connections.append(Connection(parent, host, [], kind="host"))
    for a, b in (("P1", "C1"), ("P1", "C2"), ("P2", "C1"), ("P2", "C2"), ("P1", "P2")):
        graph.connections.append(Connection(a, b, [], kind="link"))
    return graph


def _host_lines_across_switch_lines(graph, placed) -> int:
    from features.topology.layoutscore import crosses
    centre = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in placed.items()}
    hosts = [(c.a, c.b) for c in graph.connections if c.kind == "host"]
    switches = [(c.a, c.b) for c in graph.connections if c.kind != "host"]
    return sum(1 for a, b in hosts for c, d in switches if not {a, b} & {c, d} and crosses((*centre[a], *centre[b]), (*centre[c], *centre[d])))


def test_layered_keeps_the_end_point_cables_out_of_the_mesh_of_the_child_switches(monkeypatch):
    from features.topology import layout
    graph = _mesh_below_pair_graph()
    placed, _width, _height = layout.layered(graph, list(graph.nodes))
    assert _host_lines_across_switch_lines(graph, placed) == 0
    monkeypatch.setattr(layout, "clear_corridors", lambda *args: False)
    plain, _w, _h = layout.layered(graph, list(graph.nodes))
    assert _host_lines_across_switch_lines(graph, plain) > 0, "without the rule the same page has a crossing: the set-up still shows the problem"
    assert min(p.x for p in placed.values()) >= layout.MARGIN                          # a frame that moved out to the left never leaves the page
