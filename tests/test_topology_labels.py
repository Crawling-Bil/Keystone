"""Topology Builder 0.6: long middle labels are wrapped at their separators and a label keeps off the other lines. Synthetic data only."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from features.topology import labelplace, labels
from features.topology.drawio import MID_LABEL, to_drawio
from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.layout import NODE_H, NODE_W, Placed
from features.topology.scene import Page
from features.topology.svg import to_svg


def test_wrap_breaks_only_at_separators_and_respects_the_width():
    text = "SD-WAN overlay BFD 6/6 up · 3 sites not drawn · custom1 > mpls custom2 > mpls · OMP default + 1506 prefixes"
    rows = labels.wrap_centre(text, 44)
    assert " · ".join(rows) == text.replace(" · ", " · ")            # nothing lost, nothing added
    assert all(len(row) <= 44 for row in rows)
    assert len(rows) >= 2


def test_a_short_label_and_a_single_long_part_stay_one_line():
    assert labels.wrap_centre("10.0.0.1 - 10.0.0.2") == ["10.0.0.1 - 10.0.0.2"]
    one = "x" * 80
    assert labels.wrap_centre(one) == [one]                           # a part is never cut in the middle
    assert labels.wrap_centre("") == [""]


def test_the_placer_sizes_a_wrapped_label_by_its_widest_row():
    text = "172.17.169.1 · 172.17.169.0/24 · OSPF 2259 prefixes, static default + 13 prefixes"
    wide, tall = labelplace._size(text, mid=True)
    flat_wide, flat_tall = labelplace._size(text, mid=False)
    assert wide < flat_wide and tall > flat_tall


def _cross_page(label: str) -> tuple[Page, Graph]:
    """a --- b is a long horizontal line with a long label; c and d form a vertical line through its middle."""
    nodes = {k: Device(key=k, hostname=k, role_hint="router") for k in "abcd"}
    horizontal = Connection("a", "b", [Link("a", "Gi0/1", "b", "Gi0/1", "confirmed")], kind="routed", subnet=label)
    vertical = Connection("c", "d", [Link("c", "Gi0/2", "d", "Gi0/2", "confirmed")])
    graph = Graph(nodes=nodes, links=[horizontal.links[0], vertical.links[0]], connections=[horizontal, vertical])
    placed = {"a": Placed(0, 300, 0), "b": Placed(1400, 300, 0), "c": Placed(700, 0, 0), "d": Placed(700, 600, 0)}
    return Page("t", placed, set(), [], [horizontal, vertical], {}, 1600, 800, view="physical", graph=graph), graph


def test_a_middle_label_moves_off_a_line_that_crosses_its_first_choice():
    page, graph = _cross_page("10.99.0.0/30")
    graph.connections[0].subnet = "x" * 60 + " · " + "y" * 20      # wide enough to cover the crossing at the middle
    labelplace.place_labels(page, graph, True)
    cx, cy, share = page.label_pos[(0, "mid")]
    w, h = labelplace._size(labels.center_text(page.connections[0], graph), mid=True)
    rect = (cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2)
    assert not labelplace._clips(rect, (NODE_W / 2 + 700, NODE_H / 2), (NODE_W / 2 + 700, NODE_H / 2 + 600))
    assert share != 0.5


def test_the_line_test_is_exact_for_horizontal_vertical_and_outside_segments():
    rect = (10.0, 10.0, 50.0, 30.0)
    assert labelplace._clips(rect, (0, 20), (100, 20))                # passes through
    assert labelplace._clips(rect, (30, 0), (30, 100))
    assert labelplace._clips(rect, (20, 15), (40, 25))                # fully inside
    assert not labelplace._clips(rect, (0, 0), (100, 0))              # above
    assert not labelplace._clips(rect, (60, 0), (60, 100))            # right of it
    assert not labelplace._clips(rect, (0, 40), (30, 80))


def test_svg_and_drawio_write_the_same_rows_for_a_wrapped_label():
    page, graph = _cross_page("a" * 30 + " · " + "b" * 30)
    labelplace.place_labels(page, graph, True)
    rows = labels.wrap_centre(labels.center_text(page.connections[0], graph))
    assert len(rows) == 2
    svg = to_svg(page, graph)
    assert all(f">{row}</tspan>" in svg for row in rows)
    xml = to_drawio(graph, pages=[page])
    values = [cell.get("value") for cell in ET.fromstring(xml).iter("mxCell") if cell.get("style") == MID_LABEL]
    assert values == ["<br>".join(rows)]
