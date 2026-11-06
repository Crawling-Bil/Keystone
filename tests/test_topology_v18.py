"""Topology Builder 1.8: in one big diagram the switches under a switch stand next to it (not thousands of pixels away), and a second, inferred cable that comes from far
above into a frame of end points takes the way in that crosses the fewest lines.  Synthetic captures only (invented names)."""

from __future__ import annotations

import pytest

from features.topology import layout, scene
from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.layout import NODE_H, NODE_W, X_STEP
from features.topology.scene import build_pages


def _estate(parents: int, aps: int = 12, with_second_cable: bool = False) -> Graph:
    """A WAN router over one core over ``parents`` distribution switches; most carry end points (a frame), some carry none, a few have several child switches."""
    nodes = {"WAN": Device(key="WAN", hostname="WAN", captured=False, role_hint="router"), "CORE": Device(key="CORE", hostname="CORE", captured=True, role_hint="core")}
    conns: list[Connection] = []

    def link(a: str, pa: str, b: str, pb: str, state: str = "confirmed") -> None:
        conns.append(Connection(a, b, [Link(a, pa, b, pb, state, {"LLDP"}, "")]))

    link("WAN", "Gi0", "CORE", "Gi0/0")
    for i in range(parents):
        ds = f"DS-{i:02d}"
        nodes[ds] = Device(key=ds, hostname=ds, captured=True, role_hint="core")
        link("CORE", f"Gi1/0/{i + 1}", ds, "Gi1/0/48")
        for j in range(aps + 7 * (i % 3) if i % 4 else 0):
            ap = f"{ds}-AP{j:02d}"
            nodes[ap] = Device(key=ap, hostname=ap, captured=False, role_hint="ap")
            link(ds, f"Gi1/0/{j + 1}", ap, "Gi0")
        for c in range(2 if i % 5 == 0 else (1 if i % 4 else 0)):
            sw = f"{ds}-AS{c}"
            nodes[sw] = Device(key=sw, hostname=sw, captured=True, role_hint="access")
            link(ds, f"Gi1/0/{40 + c}", sw, "Gi1/0/48")
            host = f"{sw}-H"
            nodes[host] = Device(key=host, hostname=host, captured=False, role_hint="host")
            link(sw, "Gi1/0/1", host, "Gi0")
    if with_second_cable:
        link(f"DS-{parents - 2:02d}", "Gi9/9", f"DS-{parents - 1:02d}-AP05", "Gi1", "inferred")             # the access point is cabled to its switch, and guessed on the next switch of the row, far above the frame
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set(), group_endpoints=True)


def _child_steps(page, graph) -> list[float]:
    """Distance, in icon steps, of every child switch from the distribution switch it hangs under."""
    out = []
    for key, placed in page.nodes.items():
        if "-AS" in key and not key.endswith("-H"):
            parent = page.nodes[key.rsplit("-AS", 1)[0]]
            out.append(abs(placed.x - parent.x) / X_STEP)
    return out


@pytest.mark.parametrize("parents", [12, 27, 40])
def test_child_switches_stand_next_to_the_switch_they_hang_under(parents):
    graph = _estate(parents)
    page = build_pages(graph)[0]
    steps = _child_steps(page, graph)
    assert len(steps) > parents // 2
    assert max(steps) < 6, max(steps)                       # before 1.8 the children of a big estate drifted 20 to 80 steps from their parent
    assert sum(steps) / len(steps) < 3


def test_the_children_stay_under_a_row_of_switches_and_never_on_the_row_of_their_parent():
    page = build_pages(_estate(20))[0]
    for key, placed in page.nodes.items():
        if "-AS" in key and not key.endswith("-H"):
            assert placed.y > page.nodes[key.rsplit("-AS", 1)[0]].y


def test_a_child_that_already_stands_near_keeps_its_place():
    """Only what the sweeps left far from its parent comes back: with a handful of switches the picture is the one of 1.7 (the threshold is FOLLOW_FAR steps)."""
    small = build_pages(_estate(3))[0]
    assert max(_child_steps(small, None)) < layout.FOLLOW_FAR
    assert layout.FOLLOW_FAR >= 3


def test_no_switch_overlaps_another_after_the_children_have_moved():
    page = build_pages(_estate(27))[0]
    boxes = [(p.x, p.y, p.x + NODE_W, p.y + NODE_H) for k, p in page.nodes.items()]
    for i, a in enumerate(boxes):
        for b in boxes[i + 1:]:
            assert not (a[0] < b[2] - 1 and b[0] < a[2] - 1 and a[1] < b[3] - 1 and b[1] < a[3] - 1)


# ---- a second cable from far above into a frame -----------------------------------------------------------------------------------------

def _centres(page):
    return {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}


def test_crossings_of_counts_the_lines_a_path_crosses_and_skips_the_lines_of_its_own_ends():
    page = build_pages(_estate(6))[0]
    centre = _centres(page)
    row = centre["DS-01"][1]
    low, high = min(c[0] for c in centre.values()), max(c[0] for c in centre.values())
    across = [(low - 50, row + 120), (high + 50, row + 120)]          # right across the page between the distribution switches and the frames: every line down to an end point crosses it
    total = scene._crossings_of(across, page, centre, set())
    assert total >= 10
    assert scene._crossings_of(across, page, centre, {"DS-01"}) < total                    # the lines of the end of the path do not count
    assert scene._crossings_of([(low - 50, -500), (high + 50, -500)], page, centre, set()) == 0


def _fan(hosts: int, switches: int) -> Graph:
    nodes = {"CORE": Device(key="CORE", hostname="CORE", captured=True, role_hint="core")}
    conns = []
    for s in range(switches):
        sw = f"SW-{s}"
        nodes[sw] = Device(key=sw, hostname=sw, captured=True, role_hint="access")
        conns.append(Connection("CORE", sw, [Link("CORE", f"Po{s}", sw, "Po1", "confirmed", {"CDP"}, "")]))
        for i in range(hosts):
            key = f"{sw}-H{i:02d}"
            nodes[key] = Device(key=key, hostname=key, captured=False, role_hint="host")
            conns.append(Connection(sw, key, [Link(sw, f"Gi1/0/{i + 1}", key, "Gi0", "confirmed", {"LLDP"}, "")]))
    return Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set(), group_endpoints=True)


def _tall_page():
    """Two access switches with a frame each; the second one also has a guessed cable to an end point of the first, and stands far above that frame."""
    page = build_pages(_fan(6, switches=2))[0]
    page.nodes["SW-1"].y -= 2 * scene.TALL_DROP
    page.connections.append(Connection("SW-1", "SW-0-H05", [Link("SW-1", "Gi1/0/48", "SW-0-H05", "Gi0", "inferred", {"ARP"}, "")], kind="inferred"))
    page.routes.pop(len(page.connections) - 1, None)
    return page, len(page.connections) - 1


def _boxes(page):
    return {k: (p.x - 8, p.y - 8, p.x + NODE_W + 8, p.y + NODE_H + 52) for k, p in page.nodes.items()}


def test_a_cable_guessed_from_far_above_drops_beside_its_source_and_runs_along_the_top_of_the_frame():
    page, index = _tall_page()
    centre = _centres(page)
    boxes = _boxes(page)
    assert scene._route_into_frames(page, centre, boxes, set()) >= {index}
    route = page.routes[index]
    sx = centre["SW-1"][0]
    assert len(route) == 3, route                                                         # down beside the source, along the top of the frame, down the strip
    assert 0 < abs(route[0][0] - sx) <= max(scene.DROP_OFFSETS) + 1 and route[0][1] == route[1][1]
    assert scene._comb_free(route, centre["SW-1"], centre["SW-0-H05"], boxes, {"SW-1", "SW-0-H05"})


def test_a_cable_from_just_above_the_frame_goes_straight_to_the_strip():
    page, index = _tall_page()
    page.nodes["SW-1"].y += 2 * scene.TALL_DROP
    centre = _centres(page)
    boxes = _boxes(page)
    scene._route_into_frames(page, centre, boxes, set())
    route = page.routes.get(index)
    assert route is not None and len(route) == 2, route


def test_the_way_in_is_one_of_the_offered_ones_and_tall_means_far_above():
    assert scene.TALL_DROP > 0
    assert len(scene.DROP_OFFSETS) >= 3 and all(o > 0 for o in scene.DROP_OFFSETS)
    assert len(set(scene.DROP_OFFSETS)) == len(scene.DROP_OFFSETS)


def test_the_version_is_at_least_1_8():
    from core.modules import TOOLS
    version = next(t for t in TOOLS if t.key == "topology").version
    assert tuple(int(p) for p in version.split(".")) >= (1, 8)
    from features.topology.service import _tool_version
    assert _tool_version() == version
