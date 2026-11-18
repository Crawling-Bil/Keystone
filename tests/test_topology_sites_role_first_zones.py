"""A data center named role first and zone last (SW-AGG1-DC, RTR-INET2-DC, SW-TOR1A-DRC): the zone is the site, the role is not.

Found on a real DC and DRC set: 36 captured devices all ended in -DC or -DRC, but 38 neighbours nobody captured (branch routers, a fabric interconnect, a firewall) spelled no zone,
so the zone share fell under the limit and the two sites became one place called SW cut into one page per device family.  The captures are the evidence; the neighbours follow
their cables.  And with one zone only (the DC alone) SW and RTR are what the devices are, not sites.  Synthetic names only.
"""

from __future__ import annotations

import pytest

from features.topology import sites
from features.topology.extract import Device
from features.topology.graph import Connection, Link
from features.topology.layout import SITES_MODE, auto_mode, groups_of
from tests.test_topology_v05 import _graph_of

ROLES = ("AGG1", "AGG2", "CORE", "DIST", "EDGE1", "MGMT1", "TOR1A", "TOR1B", "TOR2A")


def _zone(zone, extra=()):
    return [f"SW-{role}-{zone}" for role in ROLES] + [f"RTR-WAN{n}-{zone}" for n in (1, 2)] + list(extra)


def _links(zone):
    core = f"SW-CORE-{zone}"
    out = [(core, f"SW-AGG1-{zone}"), (core, f"SW-AGG2-{zone}"), (core, f"SW-DIST-{zone}"), (core, f"SW-EDGE1-{zone}"), (core, f"RTR-WAN1-{zone}"), (core, f"RTR-WAN2-{zone}")]
    out += [(f"SW-AGG1-{zone}", f"SW-TOR{t}-{zone}") for t in ("1A", "1B", "2A")] + [(f"SW-DIST-{zone}", f"SW-MGMT1-{zone}")]
    return out


def _with_neighbours(names, links, neighbours):
    """The captured set plus devices nobody captured, each cabled to one captured device."""
    graph = _graph_of(names, links)
    for n, (name, attached) in enumerate(neighbours):
        graph.nodes[name] = Device(key=name, hostname=name, captured=False, role_hint="router")
        graph.connections.append(Connection(attached, name, [Link(attached, f"Eth1/{40 + n}", name, "Gi0/0", "confirmed", {"CDP"}, "")]))
    return graph


BRANCHES = [(f"RTR-{city}", f"RTR-WAN1-DC") for city in ("ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO", "FOXTROT", "GOLF", "HOTEL", "INDIA", "JULIET", "KILO", "LIMA")]


def _two_zones():
    return _with_neighbours(_zone("DC") + _zone("DRC"), _links("DC") + _links("DRC"), BRANCHES)


def test_uncaptured_neighbours_that_spell_no_zone_do_not_hide_the_zones():
    found = sites.detect_zones(_two_zones())
    assert found is not None and {n for n in found.groups if n != sites.OTHER} == {"DC", "DRC"}
    graph = _two_zones()
    keys = {sites._host(graph, k): n for n, ks in sites.detect_zones(graph).groups.items() for k in ks}
    assert keys["SW-CORE-DC"] == "DC" and keys["SW-CORE-DRC"] == "DRC" and keys["RTR-ALPHA"] == "DC"          # a neighbour follows the cable it hangs from


def test_automatic_draws_the_dc_and_the_drc_as_two_sites_not_one_page_per_role():
    graph = _two_zones()
    assert auto_mode(graph) == SITES_MODE
    found = {n: len(k) for n, k in groups_of(graph, SITES_MODE).items() if n != sites.OTHER}
    assert sorted(found) == ["DC", "DRC"]


def test_with_no_device_captured_there_are_no_zones_to_judge():
    names = _zone("DC") + _zone("DRC")
    graph = _graph_of(names, _links("DC") + _links("DRC"))
    for node in graph.nodes.values():
        node.captured = False
    assert sites.detect_zones(graph) is None                                  # a zone is a site only when captures stand in it


def test_a_set_where_the_captures_do_not_spell_a_zone_is_not_cut_by_zone():
    names = [f"SW-{role}-{z}" for role in ROLES for z in ("DC",)] + [f"RTR-X{n}" for n in range(1, 12)]
    assert sites.detect_zones(_graph_of(names, [])) is None                 # no second zone: the DC alone is no split


def test_one_zone_alone_is_one_diagram_not_a_page_for_sw_and_a_page_for_rtr():
    graph = _with_neighbours(_zone("DC"), _links("DC"), BRANCHES)
    assert auto_mode(graph) == "none"
    assert sites.choose(graph) is None


@pytest.mark.parametrize("word,expected", [("JKT", True), ("SENAYAN", True), ("S01", True), ("LT3", True), ("A02", True), ("HQ", True),
                                           ("AGG1", False), ("ASR1", False), ("TOR10A", False), ("SW", False), ("CORE", False), ("DC", False), ("DRC", False), ("EDGE1", False), ("1", False)])
def test_what_may_name_a_place(word, expected):
    assert sites._place_word(word) is expected


def test_a_role_first_name_with_a_place_second_is_still_a_site():
    found = sites.Sites(0, set(), {"SW-JKT": ["a"], "SW-BDG": ["b"]})
    assert not sites._named_by_role(found)
    assert sites._named_by_role(sites.Sites(0, set(), {"SW-AGG1": ["a"], "RTR-ASR1": ["b"], sites.OTHER: ["c"]}))
    assert not sites._named_by_role(sites.Sites(0, set(), {sites.OTHER: ["c"]}))


def test_the_reason_for_one_diagram_names_the_role_first_names_and_their_zone():
    graph = _with_neighbours(_zone("DC"), _links("DC"), BRANCHES + [(f"RTR-EXTRA{n}", "RTR-WAN1-DC") for n in range(12)])          # 35 devices: past the size where Automatic starts to split
    from features.topology.layout import auto_reason
    text = auto_reason(graph, "none")
    assert "say the role first" in text and "same zone, DC" in text and "give no site" not in text
