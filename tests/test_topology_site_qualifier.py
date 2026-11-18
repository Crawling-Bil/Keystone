"""A site is named ``HQ-DC``, not ``HQ``, when every captured device of it spells HQ-DC-...: the second word is a zone word (DC, DR, DRC), not a role or a counter.

Synthetic names only; the rule reads the hostnames of the graph, nothing else.
"""

from __future__ import annotations

from features.topology.layout import groups_of
from tests.test_topology_v05 import _graph_of


def _sites(names: list[str], mode: str = "prefix1") -> dict[str, list[str]]:
    return groups_of(_graph_of(names, []), mode)


def test_a_site_whose_devices_all_spell_the_zone_word_carries_it_in_its_name():
    groups = _sites(["HQ-DC-CORE1", "HQ-DC-CORE2", "HQ-DC-SF1", "JKT-RTR1", "JKT-SW1"])
    assert sorted(groups) == ["HQ-DC", "JKT"] and groups["HQ-DC"] == ["HQ-DC-CORE1", "HQ-DC-CORE2", "HQ-DC-SF1"]


def test_every_zone_word_counts_and_letter_case_does_not():
    assert sorted(_sites(["HQ-DR-CORE1", "HQ-DR-CORE2", "JKT-RTR1"])) == ["HQ-DR", "JKT"]
    assert sorted(_sites(["hq-dr-core1", "hq-dr-core2", "jkt-rtr1"])) == ["hq-dr", "jkt"]            # the site keeps the case its first word was spelled in
    assert sorted(_sites(["BDG-DRC-SW1", "BDG-DRC-SW2", "JKT-RTR1"])) == ["BDG-DRC", "JKT"]


def test_a_site_with_two_different_second_words_keeps_its_name():
    groups = _sites(["HQ-DC-CORE1", "HQ-DC-CORE2", "HQ-LAN-SW1", "JKT-RTR1"])
    assert sorted(groups) == ["HQ", "JKT"]                                   # the LAN switches are in the same site: the name stays the one word they share


def test_a_role_or_a_counter_is_not_a_zone_word():
    groups = _sites(["HQ-CORE1", "HQ-CORE2", "JKT-RTR1", "JKT-RTR2"])
    assert sorted(groups) == ["HQ", "JKT"]
    assert sorted(_sites(["HQ-SW1", "HQ-SW1B", "JKT-SW1"])) == ["HQ", "JKT"]


def test_a_device_that_is_only_seen_does_not_change_the_name():
    from features.topology.extract import Device

    graph = _graph_of(["HQ-DC-CORE1", "HQ-DC-CORE2", "JKT-RTR1"], [])
    graph.nodes["HQ-LAN-SW9"] = Device(key="HQ-LAN-SW9", hostname="HQ-LAN-SW9", captured=False, role_hint="access")
    groups = groups_of(graph, "prefix1")
    assert sorted(groups) == ["HQ-DC", "JKT"] and "HQ-LAN-SW9" in groups["HQ-DC"]       # an uncaptured neighbour is not evidence of what the site spells


def test_the_qualified_name_is_not_taken_from_another_site():
    # a site called "HQ-DC" already exists as a first-two-words family: the other keeps its short name
    groups = _sites(["HQ-DC-CORE1", "HQ-DC-CORE2"], mode="prefix2")
    assert sorted(groups) == ["HQ-DC"]


def test_two_zones_under_one_first_word_become_two_sites():
    names = ["HQ-DC-CORE1", "HQ-DC-CORE2", "HQ-DR-CORE1", "HQ-DR-CORE2", "JKT-RTR1"]
    groups = _sites(names)
    assert sorted(groups) == ["HQ-DC", "HQ-DR", "JKT"]
    assert groups["HQ-DC"] == ["HQ-DC-CORE1", "HQ-DC-CORE2"] and groups["HQ-DR"] == ["HQ-DR-CORE1", "HQ-DR-CORE2"]
    assert sorted(_sites(["HQ-DC-A1", "HQ-DC-A2", "HQ-DRC-A1", "HQ-DRC-A2"])) == ["HQ-DC", "HQ-DRC"]


def test_a_zone_word_on_one_device_or_beside_another_word_does_not_split_a_site():
    assert sorted(_sites(["HQ-DC-CORE1", "HQ-DC-CORE2", "HQ-DR-CORE1", "JKT-RTR1"])) == ["HQ", "JKT"]                # one device is not a zone
    assert sorted(_sites(["HQ-DC-CORE1", "HQ-DC-CORE2", "HQ-DR-CORE1", "HQ-DR-CORE2", "HQ-CORE9", "JKT-RTR1"])) == ["HQ", "JKT"]          # a device with no zone word: the first word is one place
    assert sorted(_sites(["HQ-DC-CORE1", "HQ-DC-CORE2", "HQ-LAN-SW1", "HQ-LAN-SW2", "JKT-RTR1"])) == ["HQ", "JKT"]


def test_a_device_nobody_captured_follows_the_zone_it_is_cabled_to():
    from features.topology.extract import Device

    graph = _graph_of(["HQ-DC-CORE1", "HQ-DC-CORE2", "HQ-DR-CORE1", "HQ-DR-CORE2"], [])
    graph.nodes["HQ-ISP-X"] = Device(key="HQ-ISP-X", hostname="HQ-ISP-X", captured=False, role_hint="router")
    from features.topology.graph import Connection, Link

    link = Link("HQ-DR-CORE2", "Eth1/9", "HQ-ISP-X", "Gi0/0", "confirmed", {"LLDP"}, "")
    graph.connections.append(Connection("HQ-DR-CORE2", "HQ-ISP-X", [link]))
    groups = groups_of(graph, "prefix1")
    assert "HQ-ISP-X" in groups["HQ-DR"] and "HQ-ISP-X" not in groups["HQ-DC"]


def test_the_other_zone_words_primary_secondary_and_continuity_count_too():
    from features.topology import sites

    assert sorted(_sites(["HQ-PDC-CORE1", "HQ-PDC-CORE2", "JKT-RTR1"])) == ["HQ-PDC", "JKT"]
    groups = _sites(["HQ-PDC-CORE1", "HQ-PDC-CORE2", "HQ-SDC-CORE1", "HQ-SDC-CORE2", "JKT-RTR1"])
    assert sorted(groups) == ["HQ-PDC", "HQ-SDC", "JKT"]                      # one first word, two zones: two sites
    assert [n for n in groups if sites.is_recovery(n)] == ["HQ-SDC"]
    assert sites.is_recovery("HQ-BCP") and sites.is_recovery("BDG-DRS") and not sites.is_recovery("HQ-PDC") and not sites.is_recovery("HQ-NDC")


def test_the_role_first_form_names_the_zone_as_the_site():
    from features.topology import sites

    groups = _sites(["DC-JKT-SW1", "DC-JKT-SW2", "DR-JKT-SW1", "DR-JKT-SW2"])
    assert sorted(groups) == ["DC", "DR"] and sites.is_recovery("DR") and not sites.is_recovery("DC")


def test_the_reason_names_the_zone_rule_and_the_site_rule_that_overrides_it():
    from features.topology.layout import _zone_hint

    names = [f"HQ-DC-SW{i}" for i in range(1, 5)] + [f"HQ-DR-SW{i}" for i in range(1, 5)] + ["JKT-SW1", "JKT-SW2"]
    graph = _graph_of(names, [("HQ-DC-SW1", "HQ-DR-SW1")])
    text = _zone_hint(graph, groups_of(graph, "prefix1"))
    assert "HQ-DC, HQ-DR are named after the zone word" in text and "HQ-DR is read as the recovery site of HQ-DC" in text
    assert 'Site rules, for example "HQ-DC = HQ-DC-"' in text
    plain = _graph_of(["AAA-SW1", "AAA-SW2", "BBB-SW1", "BBB-SW2"], [])
    assert _zone_hint(plain, groups_of(plain, "prefix1")) == ""               # plain names: nothing to add


def _hq_with_branch(state: str):
    """A head office of four switches and a branch of two (router and switch, cabled to each other), the branch joined to the head office by one line of the given state."""
    from features.topology.graph import Connection, Link

    hq = ["HQ-CORE1", "HQ-CORE2", "HQ-WAN1", "HQ-ACC1", "HQ-ACC2"]
    branch = ["KCU-OAKS-RTR1", "KCU-OAKS-SW1"]
    graph = _graph_of(hq + branch, [("HQ-CORE1", n) for n in hq[1:]] + [("KCU-OAKS-RTR1", "KCU-OAKS-SW1")])
    link = Link("HQ-WAN1", "Gi0/1", "KCU-OAKS-RTR1", "Gi0/0", state, {"CDP"} if state == "confirmed" else set(), "")
    graph.connections.append(Connection("HQ-WAN1", "KCU-OAKS-RTR1", [link], kind="inferred" if state == "inferred" else "link"))
    return graph


def test_a_branch_joined_only_by_an_inferred_circuit_is_not_taken_into_the_head_office():
    from features.topology.layout import SITES_MODE

    groups = groups_of(_hq_with_branch("inferred"), SITES_MODE)
    assert sorted(groups) == ["HQ", "KCU"] and sorted(groups["KCU"]) == ["KCU-OAKS-RTR1", "KCU-OAKS-SW1"]


def test_a_small_family_with_a_confirmed_cable_to_one_site_is_still_part_of_it():
    from features.topology.layout import SITES_MODE

    groups = groups_of(_hq_with_branch("confirmed"), SITES_MODE)
    assert sorted(groups) == ["HQ"] and "KCU-OAKS-RTR1" in groups["HQ"]            # one cable that a capture confirms: the family hangs from that site


def test_an_inferred_line_to_an_end_point_is_not_a_wan_circuit():
    from features.topology.extract import Device
    from features.topology.graph import Connection, Link
    from features.topology.sites import _guessed_between_devices

    graph = _hq_with_branch("inferred")
    graph.nodes["SRV-1"] = Device(key="SRV-1", hostname="SRV-1", captured=False, role_hint="server")
    link = Link("HQ-WAN1", "Gi0/2", "SRV-1", "eth0", "inferred", set(), "")
    to_server = Connection("HQ-WAN1", "SRV-1", [link], kind="inferred")
    assert not _guessed_between_devices(graph, to_server)                            # one end is a host: it hangs from the device it is attached to
    assert _guessed_between_devices(graph, graph.connections[-1])                    # two network devices: a circuit
