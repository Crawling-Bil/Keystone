"""A zone word written in front of the name with no separator (HQCORE1, DRCORE1) is the site, learned from the names alone.

The firewalls of one Panorama have no cable between them, so no site code can be learned from the cables; their names say HQ and DR all the same.  A zone word is believed
only when names are the same behind it and behind another zone word (HQCORE1 beside DRCORE1): that is what tells HQ from a word that just begins with the same letters.
Synthetic names only.
"""

from __future__ import annotations

from features.topology import sites
from features.topology.layout import SITES_MODE, groups_of
from tests.test_topology_v05 import _graph_of

HQ = [f"HQ{r}{n}" for r in ("CORE", "EDGE", "FWALL", "ACCSW") for n in (1, 2)] + ["HQMGMT1"]
DR = [f"DR{r}{n}" for r in ("CORE", "EDGE", "FWALL") for n in (1, 2)] + ["DRMGMT1"]


def _sites(names, links=()):
    graph = _graph_of(names, list(links))
    return graph, {n: sorted(k) for n, k in groups_of(graph, SITES_MODE).items() if n != sites.OTHER}


def test_names_with_a_zone_word_in_front_and_twins_behind_it_are_two_sites_with_no_cable():
    graph, found = _sites(HQ + DR)
    assert found == {"HQ": sorted(HQ), "DR": sorted(DR)}
    assert sites.is_recovery("DR") and not sites.is_recovery("HQ")


def test_a_zone_word_with_no_twin_is_not_believed():
    names = [f"HQ{w}{n}" for w in ("ALPHA", "BRAVO", "DELTA", "ECHO") for n in (1, 2)] + [f"DR{w}{n}" for w in ("SIERRA", "TANGO", "VICTOR", "ZULU") for n in (1, 2)]
    assert sites.glued_zones(_graph_of(names, [])) == {}                  # no name is the same behind HQ and behind DR: two habits, not two sites


def test_one_zone_alone_is_not_a_split():
    assert sites.glued_zones(_graph_of(HQ + [f"HQEXTRA{n}" for n in range(1, 6)], [])) == {}


def test_the_zone_word_is_the_shortest_that_the_twins_confirm():
    zones = sites.glued_zones(_graph_of(HQ + DR, []))
    assert zones["DRCORE1"] == "DR" and zones["HQCORE1"] == "HQ"           # DR + CORE1, not DRC + ORE1: only CORE1 is behind both zones


def test_a_device_that_spells_no_zone_follows_its_cable():
    from features.topology.extract import Device
    from features.topology.graph import Connection, Link

    graph = _graph_of(HQ + DR, [])
    graph.nodes["BORDER-X"] = Device(key="BORDER-X", hostname="BORDER-X", captured=False, role_hint="firewall")
    graph.connections.append(Connection("DRCORE1", "BORDER-X", [Link("DRCORE1", "Eth1/9", "BORDER-X", "Gi0/0", "confirmed", {"LLDP"}, "")]))
    assert "BORDER-X" in groups_of(graph, SITES_MODE)["DR"]


def _four_sites(size: int):
    names = [f"{z}{p}-SW{n}" for z in ("HQ", "DR") for p in ("NORTH", "SOUTH") for n in range(1, size + 1)]
    links = [(f"{z}{p}-SW1", f"{z}{p}-SW{n}") for z in ("HQ", "DR") for p in ("NORTH", "SOUTH") for n in range(2, size + 1)]
    return _sites(names, links)[1]


def test_sites_of_the_names_that_hold_more_than_a_handful_of_devices_are_kept():
    assert sorted(_four_sites(6)) == ["DRNORTH", "DRSOUTH", "HQNORTH", "HQSOUTH"]       # four sites that read: the zone word does not merge them into two


def test_sites_of_the_names_that_are_all_fragments_give_way_to_the_zone_word():
    assert sorted(_four_sites(4)) == ["DR", "HQ"]                                        # four devices a site and a zone word in front of every name: HQ and DR


def test_a_set_of_pairs_with_no_cable_is_read_as_two_sites_by_automatic():
    from features.topology.layout import auto_mode

    assert auto_mode(_graph_of(HQ + DR, [])) == SITES_MODE


def test_one_name_in_common_is_not_enough_to_believe_a_zone_word():
    names = HQ + ["DRCORE1"] + [f"DR{w}{n}" for w in ("SIERRA", "TANGO", "VICTOR") for n in (1, 2)]
    assert sites.glued_zones(_graph_of(names, [])) == {}                  # only CORE1 is behind both words: a chance, not a plan


def test_most_of_the_named_devices_have_to_spell_a_zone():
    branches = [f"BRANCH-{c}{n}" for c in "ABCDEF" for n in (1, 2)]
    assert sites.glued_zones(_graph_of(HQ + DR + branches, [])) == {}     # 16 of 28: the zone word is a habit of some names, not the plan of the network
    assert len(sites.glued_zones(_graph_of(HQ + DR + branches[:6], []))) == 16


def test_a_zone_with_fewer_than_three_devices_is_not_a_site():
    names = HQ + ["DRCORE1", "DRCORE2"]
    assert sites.glued_zones(_graph_of(names, [])) == {}                  # one real zone is no split, and two devices are not a site


def test_two_small_zones_are_not_drawn_as_sites_when_nothing_else_reads():
    names = ["HQCORE1", "HQCORE2", "HQEDGE1", "DRCORE1", "DRCORE2", "DREDGE1"]
    graph = _graph_of(names, [])
    assert sites.glued_zones(graph) and sites.choose(graph) is None       # six devices are a picture of their own, not two boxes


def test_a_zero_in_front_of_a_number_does_not_make_another_name():
    names = HQ + [n.replace("1", "01").replace("2", "02") for n in DR]
    assert sorted(set(sites.glued_zones(_graph_of(names, [])).values())) == ["DR", "HQ"]


def test_the_zone_word_is_the_one_whose_rest_of_the_name_is_shared():
    names = HQ + DR + ["DRCSWAA1", "DRCSWAA2", "DCSWAA1", "DCSWAA2"]      # DRC and DC are believed too, behind SWAA1 and SWAA2
    assert sites.glued_zones(_graph_of(names, []))["DRCORE1"] == "DR"


def test_a_zone_word_is_followed_by_letters_and_the_rest_is_not_a_stub():
    assert sites._glued_options("HQ1CORE1") == [] and sites._glued_options("HQAB") == []
    assert sites._glued_options("HQAB1") == [("HQ", "AB1")] and sites._glued_options("DRCORE01") == [("DRC", "ORE1"), ("DR", "CORE1")]


def test_a_zero_in_a_later_word_does_not_make_another_name_either():
    hq = [f"HQ{r}-{n:02d}" for r in ("CORE", "EDGE", "FWALL", "ACCSW") for n in (1, 2)]
    dr = [f"DR{r}-{n}" for r in ("CORE", "EDGE", "FWALL") for n in (1, 2)] + ["DRMGMT-1"]
    assert sorted(set(sites.glued_zones(_graph_of(hq + dr, [])).values())) == ["DR", "HQ"]


def test_a_zone_needs_two_captured_devices_not_only_names():
    graph = _graph_of(HQ + DR, [])
    for name in DR[1:]:
        graph.nodes[name].captured = False                                 # the recovery site is named by neighbors of one capture: that is no site to compare
    assert sites.glued_zones(graph) == {}


def test_five_devices_a_site_are_not_fragments():
    assert sorted(_four_sites(5)) == ["DRNORTH", "DRSOUTH", "HQNORTH", "HQSOUTH"]


def test_a_zone_that_is_too_big_for_a_page_is_not_a_site():
    words = [c * 3 for c in "ABCDEFGHIJKL"]
    names = [f"{z}{w}-SW{n}" for z, ws in (("HQ", words), ("DR", words[:3])) for w in ws for n in range(1, 5)]
    links = [(f"{z}{w}-SW1", f"{z}{w}-SW{n}") for z, ws in (("HQ", words), ("DR", words[:3])) for w in ws for n in range(2, 5)]
    found = _sites(names, links)[1]
    assert "HQ" not in found and len(found) == 15                          # HQ would hold 48 network devices: more than one readable page, so the 15 small sites stay
