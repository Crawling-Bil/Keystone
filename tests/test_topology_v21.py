"""Topology Builder 2.1: a lone end point (a PC) or a small frame of end points of a distribution switch stands in the gap between frames that is nearest to its
switch, not on the far side of other switches' frames (its line ran through them).  Synthetic captures only (invented names)."""

from __future__ import annotations

import random

import pytest

from features.topology import layout
from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.layout import X_STEP
from features.topology.scene import build_pages


def _estate(seed: int):
    """CORE over DS; DS over access switches (60 % through a middle switch) with 6 to 20 access points each, and one or two PCs on DS itself."""
    r = random.Random(seed)
    nodes = {"CORE": Device(key="CORE", hostname="CORE", captured=True, role_hint="core"), "DS": Device(key="DS", hostname="DS", captured=True, role_hint="aggregation")}
    conns = []

    def link(a, pa, b, pb):
        conns.append(Connection(a, b, [Link(a, pa, b, pb, "confirmed", {"LLDP"}, "")]))

    link("CORE", "Te1/0/1", "DS", "Te1/0/1")
    pcs = []
    for i in range(r.randint(4, 10)):
        a = f"A-{i}"
        nodes[a] = Device(key=a, hostname=a, captured=True, role_hint="access")
        if r.random() < 0.6:
            m = f"M-{i}"
            nodes[m] = Device(key=m, hostname=m, captured=True, role_hint="access")
            link("DS", f"Te1/0/{i + 2}", m, "Te1/0/48")
            link(m, "Gi1/0/48", a, "Te1/0/48")
        else:
            link("DS", f"Te1/0/{i + 2}", a, "Te1/0/48")
        for j in range(r.choice([6, 12, 20])):
            k = f"{a}-AP{j:02d}"
            nodes[k] = Device(key=k, hostname=k, captured=False, role_hint="ap")
            link(a, f"Gi1/0/{j + 1}", k, "Gi0")
    for q in range(r.choice([1, 1, 2])):
        p = f"PC-{q}"
        nodes[p] = Device(key=p, hostname=p, captured=False, role_hint="host")
        link("DS", f"Gi1/0/{q + 1}", p, "eth0")
        pcs.append(p)
    return Graph(nodes=nodes, links=[x for c in conns for x in c.links], connections=conns, hidden_kinds=set(), group_endpoints=True), pcs


def _worst(seed: int) -> float:
    graph, pcs = _estate(seed)
    page = build_pages(graph)[0]
    return max(abs(page.nodes[p].x - page.nodes["DS"].x) / X_STEP for p in pcs)


@pytest.mark.parametrize("seed", [23, 38, 99, 128])
def test_a_pc_of_a_distribution_switch_is_not_left_on_the_far_side_of_other_frames(seed):
    assert _worst(seed) <= layout.LONE_FAR              # 2.0 left these 10.7 to 12.1 steps from DS


def test_three_hundred_estates_keep_their_pcs_near_the_switch():
    worst = [_worst(seed) for seed in range(300)]
    assert max(worst) <= 7.0                              # 2.0: 12.2
    assert sum(1 for w in worst if w > layout.LONE_FAR) <= 6          # 2.0: 41 of 300; the rest stand where the frames beside the switch are too wide to come closer


def test_a_lone_end_point_never_lands_inside_a_frame():
    for seed in (23, 38, 68, 99):
        graph, pcs = _estate(seed)
        page = build_pages(graph)[0]
        for pc in pcs:
            same = [n for k, n in page.nodes.items() if k != pc and abs(n.y - page.nodes[pc].y) < 4]
            before = [n.x for n in same if n.x < page.nodes[pc].x]
            after = [n.x for n in same if n.x >= page.nodes[pc].x]
            if before and after:
                assert page.nodes[pc].x - max(before) >= X_STEP * 0.5 and min(after) - page.nodes[pc].x >= X_STEP * 0.5


def test_the_constants_are_set():
    assert layout.LONE_FAR == 6.0 and layout.LONE_FRAME_MAX == 3


def test_the_version_is_at_least_2_1():
    from core.modules import TOOLS
    version = next(t for t in TOOLS if t.key == "topology").version
    assert tuple(int(p) for p in version.split(".")) >= (2, 1)


# ---- a confirmed link beats a port description for an access point or a phone ----------------------------------------------------------------------------------

def _two_switch_graph(descr_ap_role: str = "ap"):
    from features.topology.inferred import infer_neighbors  # noqa: F401  (imported by the tests below)
    a = Device(key="SW-A1", hostname="SW-A1", captured=True)
    b = Device(key="SW-B2", hostname="SW-B2", captured=True, descriptions={"Gi1/0/45": "To AP-7"})
    ap = Device(key="AP-7", hostname="AP-7", captured=False, role_hint=descr_ap_role)
    link = Link("AP-7", "Gi0", "SW-A1", "Gi1/0/29", "single", {"CDP"}, "peer not captured")
    return Graph(nodes={n.key: n for n in (a, b, ap)}, links=[link], connections=[Connection("AP-7", "SW-A1", [link])], hidden_kinds=set())


def test_a_description_on_another_switch_does_not_draw_a_second_cable_to_an_access_point(monkeypatch):
    from features.topology import inferred
    monkeypatch.setattr(inferred, "_find_by_name", lambda graph, text, own: "AP-7" if "AP-7" in text else "")
    facts = inferred.infer_neighbors(_two_switch_graph())
    assert [f for f in facts if f["type"] == "inferred-link"] == []
    assert [(f["a"], f["b"], f["says"]) for f in facts if f["type"] == "description-elsewhere"] == [("SW-B2", "SW-A1", "AP-7")]


def test_the_stale_description_is_a_line_of_topo_028():
    from features.topology.findings import build_findings
    graph = _two_switch_graph()
    graph.issues.append({"type": "description-elsewhere", "a": "SW-B2", "a_port": "Gi1/0/45", "b": "SW-A1", "b_port": "", "a_host": "SW-B2", "b_host": "SW-A1", "says": "AP-7", "description": "To AP-7"})
    rows = [r for r in build_findings(graph) if r["id"] == "TOPO-028"]
    assert rows and "SW-B2 Gi1/0/45 is described as AP-7, which reports itself on SW-A1" in rows[0]["detail"]
    assert "a device that reports itself on another switch" in rows[0]["title"]


def test_a_router_named_by_a_description_still_gets_its_inferred_line(monkeypatch):
    from features.topology import inferred
    monkeypatch.setattr(inferred, "_find_by_name", lambda graph, text, own: "AP-7" if "AP-7" in text else "")
    facts = inferred.infer_neighbors(_two_switch_graph("router"))
    assert [f["b"] for f in facts if f["type"] == "inferred-link"] == ["AP-7"]      # only an access point or a phone has one cable


# ---- roles from a neighbour's own description -------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("text, role", [
    ("Ubuntu 22.04.3 LTS Linux 5.15.0-91-generic #101-Ubuntu SMP x86_64", "server"),
    ("Debian GNU/Linux 12", "server"),
    ("VMware ESXi 8.0.1 build-21495797", "server"),
    ("Proxmox VE 8.1", "server"),
    ("Microsoft Windows Server 2019", "server"),
    ("KVM Hypervisor 8.2", "server"),
    ("XCP-ng 8.2 (Xen)", "server"),
    ("FreeBSD 13.2-RELEASE", "server"),
    ("UniFi AP-Pro", "ap"),
    ("UAP-AC-Pro, 6.5.28", "ap"),
    ("U6-Pro 6.2", "ap"),
    ("Cumulus Linux version 5.4.0 running on Dell S5248F-ON", ""),      # a Linux switch is not a host
    ("Arista Networks EOS version 4.28", ""),
    ("Cisco IOS Software, C9300 Software", ""),
])
def test_what_a_neighbour_says_about_itself_names_its_kind(text, role):
    from features.topology.roles import role_from_description
    assert role_from_description(text) == role


# ---- two long bridges on one bearing (scene._ride / _detour_apart) ----------------------------------------------------------------------------------

def test_ride_counts_only_runs_that_lie_on_one_another():
    from features.topology.scene import _ride

    line = [(0.0, 0.0), (1000.0, 250.0)]
    assert abs(_ride(line, [(200.0, 50.0), (900.0, 225.0)]) - 721) < 2                            # inside the first run (700 px of x on a 1.03 slope)
    assert _ride(line, [(0.0, 20.0), (1000.0, 270.0)]) == 0                                       # parallel, 20 px off: two lines, not one
    assert _ride(line, [(0.0, 250.0), (1000.0, 0.0)]) == 0                                        # crossing
    assert _ride(line, [(1200.0, 300.0), (1500.0, 375.0)]) == 0                                   # same bearing, but after the end


def test_a_bridge_that_would_ride_on_a_routed_line_takes_the_next_lift():
    from types import SimpleNamespace

    from features.topology.scene import _detour_apart

    centres = {"A": (0.0, 0.0), "B": (1000.0, 0.0), "X": (0.0, 0.0), "Y": (1000.0, 0.0)}
    wall = [(480.0, -40.0, 520.0, 40.0)]                                                          # a device in the way: lift 0 does not clear it
    conn = Connection("A", "B", [])
    first = [(60.0, 70.0), (940.0, 70.0)]                                                         # the bridge another line already takes (lift 70)
    page = SimpleNamespace(connections=[Connection("X", "Y", []), conn], routes={0: first})
    found = _detour_apart(page, centres, conn, centres["A"], centres["B"], (1000.0, 0.0), (0.0, 1.0), 0.0, True, [0.0, 70.0, -70.0], wall)
    assert found == [(60.0, -70.0), (940.0, -70.0)]                                               # lift 70 rides on the routed line, lift -70 does not
    alone = SimpleNamespace(connections=[conn], routes={})
    assert _detour_apart(alone, centres, conn, centres["A"], centres["B"], (1000.0, 0.0), (0.0, 1.0), 0.0, True, [0.0, 70.0, -70.0], wall) == [(60.0, 70.0), (940.0, 70.0)]
    boxed = SimpleNamespace(connections=[Connection("X", "Y", []), conn], routes={0: first})
    only = _detour_apart(boxed, centres, conn, centres["A"], centres["B"], (1000.0, 0.0), (0.0, 1.0), 0.0, True, [70.0], wall)
    assert only == [(60.0, 70.0), (940.0, 70.0)]                                                  # every lift rides: the first one stays


def test_the_pitch_of_a_frame_is_the_gap_of_its_full_line():
    """A full line of columns 210 px apart gives 208 (rounded to 4 px) however a short last line is offset; a line of one column gives nothing."""
    from features.topology.scene import _row_pitch

    assert _row_pitch([0, 210, 420, 630]) == 208
    assert _row_pitch([0, 210, 420, 630, 735]) == 208                                              # a half-step column at the end does not shrink it
    assert _row_pitch([100]) == 0 and _row_pitch([]) == 0
    assert _row_pitch([0, 10, 20]) == 0                                                            # columns closer than 20 px are not columns
    assert _row_pitch([0, 100, 300, 400]) == 100                                                   # two gaps of 100, one of 200: the common one


def test_another_lift_is_taken_only_when_it_crosses_no_more_lines():
    from types import SimpleNamespace

    from features.topology.scene import _detour_apart

    centres = {"A": (0.0, 0.0), "B": (1000.0, 0.0), "X": (0.0, 0.0), "Y": (1000.0, 0.0), "Z": (500.0, -100.0), "W": (500.0, -40.0)}
    wall = [(480.0, -40.0, 520.0, 40.0)]
    conn = Connection("A", "B", [])
    first = [(60.0, 70.0), (940.0, 70.0)]
    page = SimpleNamespace(connections=[Connection("X", "Y", []), Connection("Z", "W", []), conn], routes={0: first})
    found = _detour_apart(page, centres, conn, centres["A"], centres["B"], (1000.0, 0.0), (0.0, 1.0), 0.0, True, [0.0, 70.0, -70.0], wall)
    assert found == first                                                                          # the free lift (-70) would cross the line Z-W: riding is the lesser evil


def _corner_page(routes=None):
    from types import SimpleNamespace

    centres = {"A": (0.0, 0.0), "B": (2500.0, 0.0)}
    conn = Connection("A", "B", [])
    page = SimpleNamespace(connections=[conn], routes=routes or {})
    return page, centres, conn


def test_a_long_loop_round_one_device_becomes_one_bend():
    from features.topology.scene import _detour_corner, _path_length

    page, centres, conn = _corner_page()
    blocker = [(1190.0, -60.0, 1310.0, 60.0)]                                                         # a device on the straight line
    loop = [(60.0, -460.0), (2440.0, -460.0)]                                                         # the bridge that moved the whole line sideways
    found = _detour_corner(page, centres, conn, centres["A"], centres["B"], (2500.0, 0.0), (0.0, 1.0), blocker, loop)
    assert found is not None and len(found) == 1
    assert _path_length([centres["A"], *found, centres["B"]]) < 2700                                  # the loop was 3,300 px
    assert abs(found[0][1]) <= 160                                                                    # the bend stands close to the line


def test_a_loop_is_kept_when_a_bend_is_not_shorter_or_cannot_clear():
    from features.topology.scene import _detour_corner

    page, centres, conn = _corner_page()
    blocker = [(1190.0, -60.0, 1310.0, 60.0)]
    short = [(1250.0, -100.0)]                                                                        # already a single bend: nothing to gain
    assert _detour_corner(page, centres, conn, centres["A"], centres["B"], (2500.0, 0.0), (0.0, 1.0), blocker, short) is None
    wall = [(1000.0, -3000.0, 1400.0, 3000.0)]                                                        # no bend within reach clears a wall this tall
    loop = [(60.0, -460.0), (2440.0, -460.0)]
    assert _detour_corner(page, centres, conn, centres["A"], centres["B"], (2500.0, 0.0), (0.0, 1.0), wall, loop) is None
