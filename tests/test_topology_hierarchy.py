"""Core, distribution and access: found from the host names (SWCO / SWDI / SWAC) or from the shape of the network, and drawn as rows under the core with
the switches of one parent side by side under it.  Synthetic captures only (invented names, documentation addresses)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture  # noqa: E402

from features.topology.layout import NODE_W  # noqa: E402
from features.topology.service import build_topology  # noqa: E402

PLATFORM = "cisco WS-C2960X-24PS-L"


def _entry(name: str, ip: str, local: str, remote: str) -> tuple:
    return (name, ip, PLATFORM, local, remote)


def _build(files: list[tuple[str, str]]):
    return build_topology(files, group="none", view="physical")


def _tree(core: str, dists: list[str], access: dict[str, list[str]], direct: list[str] | None = None):
    """A core over two distribution switches with three access switches each (captured: core and distribution); ``direct`` access switches hang off the core."""
    files = []
    core_rows = [_entry(d, f"192.0.2.{10 + i}", f"Gi1/0/{i + 1}", f"Gi1/0/48") for i, d in enumerate(dists)]
    core_rows += [_entry(a, f"192.0.2.{50 + i}", f"Gi1/0/{20 + i}", "Gi0/1") for i, a in enumerate(direct or [])]
    files.append(("core.txt", iosxe_capture(core, "FOC00000001", "192.0.2.2", cdp=core_rows)))
    for n, dist in enumerate(dists):
        rows = [_entry(core, "192.0.2.2", "Gi1/0/48", f"Gi1/0/{n + 1}")]
        rows += [_entry(a, f"192.0.2.{100 + 10 * n + i}", f"Gi1/0/{i + 1}", "Gi0/1") for i, a in enumerate(access[dist])]
        files.append((f"d{n}.txt", iosxe_capture(dist, f"FOC0000001{n}", f"192.0.2.{10 + n}", cdp=rows)))
    return _build(files)


TREE = dict(core="LAB-ALPHA", dists=["LAB-BRAVO", "LAB-CHARLIE"], access={"LAB-BRAVO": ["LAB-ECHO-1", "LAB-ECHO-2", "LAB-ECHO-3"], "LAB-CHARLIE": ["LAB-FOXTROT-1", "LAB-FOXTROT-2", "LAB-FOXTROT-3"]})


def _role(graph, host: str) -> str:
    return graph.nodes[host].role_hint


def test_host_name_words_give_core_distribution_and_access():
    files = [("a.txt", iosxe_capture("SITE-SWCODI-C3650", "FOC00000001", "192.0.2.2", cdp=[
        ("SITE-SWDI-A-S5731", "192.0.2.10", "Huawei Switch S5731-S24P4X", "Gi1/0/1", "GE0/0/1", "Switch IGMP"),
        ("SITE-SWAC-ISP-S5735", "192.0.2.11", "Huawei Switch S5735-L-V2", "Gi1/0/2", "GE0/0/1", "Switch IGMP")]))]
    graph = _build(files)["graph"]
    assert _role(graph, "SITE-SWCODI-C3650") == "core"
    assert _role(graph, "SITE-SWDI-A-S5731") == "aggregation"
    assert _role(graph, "SITE-SWAC-ISP-S5735") == "access"


def test_the_core_is_found_from_the_shape_when_the_names_say_nothing():
    graph = _tree(**TREE)["graph"]
    assert _role(graph, "LAB-ALPHA") == "core"
    assert {_role(graph, d) for d in TREE["dists"]} == {"aggregation"}
    assert {_role(graph, a) for kids in TREE["access"].values() for a in kids} == {"access"}


def test_rows_run_core_distribution_access_with_children_under_their_parent():
    page = _tree(**TREE)["pages"][0]
    at = {k: p for k, p in page.nodes.items()}
    assert at["LAB-ALPHA"].y < at["LAB-BRAVO"].y == at["LAB-CHARLIE"].y < at["LAB-ECHO-1"].y == at["LAB-FOXTROT-3"].y
    for parent, kids in TREE["access"].items():
        xs = [at[k].x for k in kids]
        assert min(xs) <= at[parent].x <= max(xs)                       # the parent stands over its own access switches
    assert max(at[k].x for k in TREE["access"]["LAB-BRAVO"]) < min(at[k].x for k in TREE["access"]["LAB-CHARLIE"])   # the two families never mix
    assert min(at["LAB-BRAVO"].x, at["LAB-CHARLIE"].x) < at["LAB-ALPHA"].x < max(at["LAB-BRAVO"].x, at["LAB-CHARLIE"].x)    # the core is between its distribution switches


def test_an_access_switch_on_the_core_stands_in_the_row_under_it_beside_the_distribution_switches():
    result = _tree(**TREE, direct=["LAB-GOLF-1"])
    at = result["pages"][0].nodes
    assert at["LAB-GOLF-1"].y == at["LAB-BRAVO"].y                      # no line that jumps over the distribution row
    assert at["LAB-GOLF-1"].y > at["LAB-ALPHA"].y


def test_lines_to_the_switches_below_leave_beside_the_icon_not_through_its_name():
    page = _tree(**TREE)["pages"][0]
    core = page.nodes["LAB-ALPHA"]
    centre = core.x + NODE_W / 2
    routed = [(c, page.routes[i]) for i, c in enumerate(page.connections) if "LAB-ALPHA" in (c.a, c.b) and i in page.routes]
    assert len(routed) == 2
    sides = set()
    for conn, path in routed:
        waypoints = path if conn.a == "LAB-ALPHA" else path[::-1]       # a route runs from the line's first end to its second
        sides.add(round(waypoints[0][0] - centre))
        assert abs(waypoints[0][0] - centre) == NODE_W / 2              # out of the side of the icon, never its bottom middle
        assert waypoints[0][1] == waypoints[1][1]                       # then straight along, and down into the switch
        assert waypoints[1][0] == page.nodes[conn.b if conn.a == "LAB-ALPHA" else conn.a].x + NODE_W / 2
    assert len(sides) == 2                                              # one line on each side


def test_a_role_from_the_host_name_is_not_overruled_by_the_shape():
    graph = _tree(core="LAB-ALPHA", dists=["LAB-ACCESS-1", "LAB-CHARLIE"], access={"LAB-ACCESS-1": ["LAB-ECHO-1", "LAB-ECHO-2", "LAB-ECHO-3"], "LAB-CHARLIE": ["LAB-FOXTROT-1", "LAB-FOXTROT-2", "LAB-FOXTROT-3"]})["graph"]
    assert _role(graph, "LAB-ACCESS-1") == "access"                     # named access stays access although switches hang under it
    assert _role(graph, "LAB-ALPHA") == "core"


def test_a_tie_between_unrelated_switches_leaves_the_group_alone():
    files = [(f"{n}.txt", iosxe_capture(n, f"FOC0000000{i}", f"192.0.2.{i + 2}", cdp=[
        _entry(m, f"192.0.2.{j + 2}", "Gi1/0/1", "Gi1/0/1") for j, m in enumerate(("LAB-ONE", "LAB-TWO", "LAB-THREE")) if m != n]))
        for i, n in enumerate(("LAB-ONE", "LAB-TWO", "LAB-THREE"))]
    graph = _build(files)["graph"]                                      # a triangle: nothing marks a core
    assert {getattr(n, "hier_depth", None) for n in graph.nodes.values()} == {None}
    assert {_role(graph, n) for n in ("LAB-ONE", "LAB-TWO", "LAB-THREE")} == {"access"}
