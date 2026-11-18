"""A zone word at the END of the hostnames (SW-AGG1-DC beside SW-AGG1-DRC) is the site, not the role.

The prefix grouping reads the first words: it would put the DC and the DRC switch with the same role into one box (``SW-AGG1``) and no site would be a data center, so none of
the recovery-site findings could run.  Synthetic names only; the rule reads the hostnames and the cables of the graph, nothing else.
"""

from __future__ import annotations

from features.topology import sites
from features.topology.layout import SITES_MODE, auto_mode, groups_of
from tests.test_topology_v05 import _graph_of

DC = ["SW-AGG1-DC", "SW-AGG2-DC", "SW-TOR1A-DC", "SW-TOR1B-DC", "SW-TOR2A-DC"]
DRC = ["SW-AGG1-DRC", "SW-AGG2-DRC", "SW-TOR1A-DRC", "SW-TOR1B-DRC"]


def _links(names: list[str]) -> list[tuple[str, str]]:
    return [(names[0], n) for n in names[1:]]


def test_the_zone_at_the_end_of_the_name_is_the_site():
    graph = _graph_of(DC + DRC, _links(DC) + _links(DRC))
    groups = {n: keys for n, keys in groups_of(graph, SITES_MODE).items() if n != sites.OTHER}
    assert sorted(groups) == ["DC", "DRC"]
    assert sorted(groups["DC"]) == sorted(DC) and sorted(groups["DRC"]) == sorted(DRC)


def test_zone_suffix_reads_the_last_word_and_a_place_in_front():
    assert sites.zone_suffix("SW-AGG1-DC") == ("", "DC")
    assert sites.zone_suffix("sw-tor2a-drc") == ("", "DRC")
    assert sites.zone_suffix("BGR-AGG1-DC") == ("BGR", "DC")             # a place in front of the role: the site is BGR-DC
    assert sites.zone_suffix("SW1-AGG1-DC") == ("", "DC")                 # a first word with a counter is a device type (SW1), not a place
    assert sites.zone_suffix("HQ-DC") is None                            # two words: the zone is the site word, the prefix grouping reads it
    assert sites.zone_suffix("SW-AGG1") is None and sites.zone_suffix("SW-DC-AGG1") is None


def test_a_place_in_front_names_the_sites_after_it():
    names = ["BGR-AGG1-DC", "BGR-AGG2-DC", "BGR-TOR1-DC", "BGR-AGG1-DRC", "BGR-AGG2-DRC", "BGR-TOR1-DRC"]
    graph = _graph_of(names, _links(names[:3]) + _links(names[3:]))
    assert sorted(n for n in groups_of(graph, SITES_MODE) if n != sites.OTHER) == ["BGR-DC", "BGR-DRC"]


def test_one_zone_or_a_stray_device_is_not_a_split():
    only_dc = _graph_of(DC, _links(DC))
    assert sites.detect_zones(only_dc) is None                           # one zone: nothing to tell apart
    stray = _graph_of(DC + ["SW-AGG1-DRC", "SW-AGG2-DRC"], _links(DC))
    assert sites.detect_zones(stray) is None                             # two devices are not a site of their own


def test_names_that_mostly_spell_no_zone_keep_the_prefix_grouping():
    names = DC + DRC + [f"SW-FLOOR{i}-ACC1" for i in range(1, 13)]
    graph = _graph_of(names, [])
    assert sites.detect_zones(graph) is None                              # 9 of 21 spell a zone: it is a habit of some names, not the plan of the network


def test_a_device_with_no_zone_follows_its_cables_and_a_shared_one_stays_out():
    from features.topology.extract import Device

    graph = _graph_of(DC + DRC, _links(DC) + _links(DRC))
    for name in ("FW-NGFW", "ROUTER-X"):
        graph.nodes[name] = Device(key=name, hostname=name, captured=False, role_hint="firewall")
    from features.topology.graph import Connection, Link

    for a, b in (("SW-AGG1-DRC", "FW-NGFW"), ("SW-AGG1-DC", "ROUTER-X"), ("SW-AGG1-DRC", "ROUTER-X")):
        link = Link(a, "Eth1/9", b, "Gi0/0", "confirmed", {"LLDP"}, "")
        graph.connections.append(Connection(a, b, [link]))
    groups = groups_of(graph, SITES_MODE)
    assert "FW-NGFW" in groups["DRC"]                                      # cabled to the DRC only
    assert "ROUTER-X" in groups[sites.OTHER]                               # cabled to both zones: it belongs to neither


def test_the_recovery_zone_is_drawn_after_the_main_one_and_read_as_its_twin():
    from features.topology.sitefindings import twin_sites

    graph = _graph_of(DC + DRC, _links(DC) + _links(DRC))
    groups = groups_of(graph, SITES_MODE)
    assert sites.is_recovery("DRC") and not sites.is_recovery("DC")
    assert twin_sites(graph, groups) == [("DC", "DRC")]


def test_automatic_chooses_the_zones_for_a_network_that_names_the_zone_last():
    names = [f"SW-TOR{i}A-DC" for i in range(1, 14)] + [f"SW-TOR{i}A-DRC" for i in range(1, 9)] + ["SW-AGG1-DC", "SW-AGG2-DC", "SW-AGG1-DRC", "SW-AGG2-DRC"]
    graph = _graph_of(names, [("SW-AGG1-DC", n) for n in names if n.endswith("A-DC")] + [("SW-AGG1-DRC", n) for n in names if n.endswith("A-DRC")])
    assert auto_mode(graph) == SITES_MODE
    assert sorted(n for n in groups_of(graph, SITES_MODE) if n != sites.OTHER) == ["DC", "DRC"]
