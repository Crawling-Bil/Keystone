"""A star of switches (SW1 with two downlink switches, SW2 and SW3): the engine finds the hub from the shape, draws it over the two switches, keeps each
switch over its own end points, and does not tell a small branch to dual-home to a core in another city.  Synthetic captures only (invented names and
documentation addresses; the multi-site demo set is invented too)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture  # noqa: E402

from features.topology import demo, l2findings  # noqa: E402
from features.topology.layoutscore import score_pages  # noqa: E402
from features.topology.service import build_topology  # noqa: E402

PLATFORM = "cisco WS-C2960X-24PS-L"
BRANCHES = ("MKS", "MED", "BAL")                  # the three branches of the multi-site demo that are a star


def _entry(name: str, ip: str, local: str, remote: str) -> tuple:
    return (name, ip, PLATFORM, local, remote)


def _star(prefix: str, extra: list[tuple[str, list[tuple]]] | None = None):
    """``X-SW1`` with two downlinks, ``X-SW2`` and ``X-SW3`` (one cable each); ``extra``: more captures (name, cdp rows) added to the picture."""
    sw1 = [_entry(f"{prefix}-SW2", "192.0.2.12", "Gi1/0/1", "Gi1/0/48"), _entry(f"{prefix}-SW3", "192.0.2.13", "Gi1/0/2", "Gi1/0/48")]
    files = [("sw1.txt", iosxe_capture(f"{prefix}-SW1", "FOC00000001", "192.0.2.11", cdp=sw1)),
             ("sw2.txt", iosxe_capture(f"{prefix}-SW2", "FOC00000002", "192.0.2.12", cdp=[_entry(f"{prefix}-SW1", "192.0.2.11", "Gi1/0/48", "Gi1/0/1")])),
             ("sw3.txt", iosxe_capture(f"{prefix}-SW3", "FOC00000003", "192.0.2.13", cdp=[_entry(f"{prefix}-SW1", "192.0.2.11", "Gi1/0/48", "Gi1/0/2")]))]
    for number, (name, rows) in enumerate(extra or []):
        files.append((f"x{number}.txt", iosxe_capture(name, f"FOC0000010{number}", f"192.0.2.{100 + number}", cdp=rows)))
    return build_topology(files, group="none", view="physical")


def _demo_build():
    names = [f["name"] for f in next(s for s in demo.list_sets() if s["id"] == "multisite")["files"]]
    files = [(name, demo.read_file("multisite", name).decode("utf-8")) for name in names]
    return build_topology(files, group="auto", view="physical")


def _page(result, name: str):
    return next(p for p in result["pages"] if p.name == name)


def test_a_switch_named_only_sw_does_not_state_its_tier():
    """SW says "a switch", not where it stands: the hub is found from the shape, the same as for a name with no role word."""
    graph = _star("LAB")["graph"]
    assert graph.nodes["LAB-SW1"].role_hint == "core"
    assert graph.nodes["LAB-SW2"].role_hint == "access" and graph.nodes["LAB-SW3"].role_hint == "access"
    assert graph.nodes["LAB-SW1"].hier_depth == 0 and graph.nodes["LAB-SW2"].hier_depth == 1


def test_a_name_that_says_access_still_states_the_tier():
    """ACC says where the switch stands: three ACC switches in a star stay access, whatever their links look like."""
    sw1 = [_entry("LAB-ACC2", "192.0.2.12", "Gi1/0/1", "Gi1/0/48"), _entry("LAB-ACC3", "192.0.2.13", "Gi1/0/2", "Gi1/0/48")]
    files = [("a.txt", iosxe_capture("LAB-ACC1", "FOC00000001", "192.0.2.11", cdp=sw1))]
    graph = build_topology(files, group="none", view="physical")["graph"]
    assert {graph.nodes[f"LAB-ACC{n}"].role_hint for n in (1, 2, 3)} == {"access"}
    assert all(graph.nodes[f"LAB-ACC{n}"].hier_depth is None for n in (1, 2, 3))


def test_the_hub_is_drawn_over_its_two_downlinks_with_no_crossing():
    result = _star("LAB")
    page = _page(result, "Overview")
    hub, left, right = (page.nodes[f"LAB-SW{n}"] for n in (1, 2, 3))
    assert hub.y < left.y == right.y
    assert left.x < hub.x < right.x
    assert sum(row["crossings"] for row in score_pages(result["pages"])) == 0


@pytest.mark.parametrize("code", BRANCHES)
def test_the_demo_branches_are_a_star_drawn_as_a_tree(code):
    result = _demo_build()
    page = _page(result, code)
    hub, left, right = (page.nodes[f"{code}-SW{n}"] for n in (1, 2, 3))
    router = page.nodes[f"{code}-RTR1"]
    assert router.y < hub.y < left.y == right.y                 # the router over the hub, the hub over its two downlinks
    assert left.x < hub.x < right.x
    row = next(r for r in score_pages([page]))
    assert row["crossings"] == 0 and row["through"] == 0


@pytest.mark.parametrize("code", BRANCHES)
def test_each_branch_switch_stands_over_its_own_end_points(code):
    """SW2 and SW3 stand over the end points that hang on them alone, so their lines never run through the end points of SW1."""
    result = _demo_build()
    page = _page(result, code)
    degree: dict[str, int] = {}
    for conn in result["graph"].connections:
        degree[conn.a] = degree.get(conn.a, 0) + 1
        degree[conn.b] = degree.get(conn.b, 0) + 1
    for number in (2, 3):
        switch = f"{code}-SW{number}"
        ends = [k for k in page.nodes if degree.get(k) == 1 and any({c.a, c.b} == {switch, k} for c in result["graph"].connections)]
        assert len(ends) >= 2, switch
        middle = (min(page.nodes[k].x for k in ends) + max(page.nodes[k].x for k in ends)) / 2
        assert abs(page.nodes[switch].x - middle) < 1


def test_the_chain_of_the_other_branches_is_left_as_it_was():
    """A chain (SW1 - SW2 - SW3) has no hub: the three switches stay in one row."""
    page = _page(_demo_build(), "JKT")
    assert len({round(page.nodes[f"JKT-SW{n}"].y) for n in (1, 2, 3)}) == 1


def _far_core(hops_between: int):
    """A branch star (LAB-SW1 ... SW3) and a second core, FAR-CORE2, ``hops_between`` links away from LAB-SW1 through routers."""
    chain = ["LAB-SW1"] + [f"RTR-{n}" for n in range(1, hops_between)] + ["FAR-CORE2"]
    extra = []
    for index in range(1, len(chain) - 1):
        rows = [_entry(chain[index - 1], "192.0.2.200", "Gi0/0", "Gi0/1"), _entry(chain[index + 1], "192.0.2.201", "Gi0/2", "Gi0/1")]
        extra.append((chain[index], rows))
    extra.append(("FAR-CORE2", [_entry(chain[-2], "192.0.2.202", "Gi1/0/1", "Gi0/2")]))
    sw1_rows = [_entry("LAB-SW2", "192.0.2.12", "Gi1/0/1", "Gi1/0/48"), _entry("LAB-SW3", "192.0.2.13", "Gi1/0/2", "Gi1/0/48"), _entry(chain[1], "192.0.2.203", "Gi1/0/3", "Gi0/0")]
    files = [("sw1.txt", iosxe_capture("LAB-SW1", "FOC00000001", "192.0.2.11", cdp=sw1_rows)),
             ("sw2.txt", iosxe_capture("LAB-SW2", "FOC00000002", "192.0.2.12", cdp=[_entry("LAB-SW1", "192.0.2.11", "Gi1/0/48", "Gi1/0/1")])),
             ("sw3.txt", iosxe_capture("LAB-SW3", "FOC00000003", "192.0.2.13", cdp=[_entry("LAB-SW1", "192.0.2.11", "Gi1/0/48", "Gi1/0/2")]))]
    for number, (name, rows) in enumerate(extra):
        files.append((f"x{number}.txt", iosxe_capture(name, f"FOC0000010{number}", f"192.0.2.{100 + number}", cdp=rows)))
    return build_topology(files, group="none", view="physical")


def _single_uplink(result):
    return [f for f in result["findings"] if f["id"] == "TOPO-035"]


def test_a_core_of_another_site_is_not_a_second_uplink():
    """The only other core is four links away (over routers, a WAN): SW2 and SW3 cannot be wired to it, so there is nothing to report."""
    result = _far_core(4)
    assert result["graph"].nodes["FAR-CORE2"].role_hint == "core"
    assert l2findings._near_upper(result["graph"], "LAB-SW1") == set()
    assert not _single_uplink(result)


def test_a_core_next_to_the_hub_is_a_second_uplink():
    """The same star with a second core one link from the hub: that is a place to dual-home to, and the single uplinks are reported."""
    result = _far_core(1)
    assert l2findings._near_upper(result["graph"], "LAB-SW1") == {"FAR-CORE2"}
    found = _single_uplink(result)
    assert found and set(found[0]["devices"]) == {"LAB-SW1", "LAB-SW2", "LAB-SW3"}
    assert "FAR-CORE2" in found[0]["recommendation"]          # the spare core in reach is named


def test_the_demo_branches_report_no_single_uplink_finding():
    assert not _single_uplink(_demo_build())
