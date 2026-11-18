"""The two units of a Palo Alto HA pair are found by more than the HA1 address: the same address pair is used by every pair of every site.

An HA1 address is set on each unit alone and a dedicated cable joins the two units of a pair, so 1.1.1.1 and 1.1.1.2 are the right answer for a pair at the head office and
for a pair at the recovery site.  Matching the first unit that holds the address joined firewalls of two sites by a line that no cable made.  Synthetic names only.
https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-admin/high-availability/set-up-activepassive-ha/configuration-guidelines-for-activepassive-ha
"""

from __future__ import annotations

from features.topology.service import build_topology


def _unit(host: str, own: str, peer: str, group: int = 1, priority: int = 100, mode: str = "active-passive", ha2: str = "ethernet1/8") -> str:
    return f"""set deviceconfig system hostname {host}
set deviceconfig high-availability enabled yes
set deviceconfig high-availability group group-id {group}
set deviceconfig high-availability group peer-ip {peer}
set deviceconfig high-availability group mode {mode}
set deviceconfig high-availability group election-option device-priority {priority}
set deviceconfig high-availability interface ha1 port ethernet1/7
set deviceconfig high-availability interface ha1 ip-address {own}
set deviceconfig high-availability interface ha2 port {ha2}
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.1/30
"""


def _pairs(files) -> set[frozenset]:
    graph = build_topology(files, view="physical")["graph"]
    return {frozenset((l.a, l.b)) for l in graph.links if "HA" in l.protocols}, graph


def _four_units():
    return [("a.txt", _unit("HQFW2", "1.1.1.2", "1.1.1.1")), ("b.txt", _unit("DRFW2", "1.1.1.2", "1.1.1.1")),
            ("c.txt", _unit("HQFW1", "1.1.1.1", "1.1.1.2")), ("d.txt", _unit("DRFW1", "1.1.1.1", "1.1.1.2"))]


def test_pairs_that_reuse_the_same_ha1_addresses_are_not_mixed_across_sites():
    ha, graph = _pairs(_four_units())
    assert ha == {frozenset(("HQFW1", "HQFW2")), frozenset(("DRFW1", "DRFW2"))}
    assert not [k for k in graph.nodes if k.startswith("HAPEER-")]


def test_the_upload_order_does_not_change_the_pairs():
    files = _four_units()
    assert _pairs(files)[0] == _pairs(list(reversed(files)))[0] == _pairs(files[1:] + files[:1])[0]


def test_units_that_disagree_on_the_group_id_or_the_mode_are_not_a_pair():
    graph = _pairs([("a.txt", _unit("FWA", "1.1.1.1", "1.1.1.2", group=1)), ("b.txt", _unit("FWB", "1.1.1.2", "1.1.1.1", group=2))])[1]
    assert not [l for l in graph.links if "HA" in l.protocols and l.a in ("FWA", "FWB") and l.b in ("FWA", "FWB")]       # PAN-OS needs the same Group ID on both units
    assert len([k for k in graph.nodes if k.startswith("HAPEER-")]) == 2
    graph = _pairs([("a.txt", _unit("FWA", "1.1.1.1", "1.1.1.2")), ("b.txt", _unit("FWB", "1.1.1.2", "1.1.1.1", mode="active-active"))])[1]
    assert len([k for k in graph.nodes if k.startswith("HAPEER-")]) == 2


def test_a_unit_whose_peer_was_not_uploaded_does_not_take_the_unit_of_another_pair():
    files = [("a.txt", _unit("HQFW1", "1.1.1.1", "1.1.1.2")), ("b.txt", _unit("HQFW2", "1.1.1.2", "1.1.1.1")), ("c.txt", _unit("DRFW1", "1.1.1.1", "1.1.1.2"))]
    ha, graph = _pairs(files)
    assert frozenset(("HQFW1", "HQFW2")) in ha
    assert not any("DRFW1" in pair and ("HQFW1" in pair or "HQFW2" in pair) for pair in ha)
    assert "HAPEER-DRFW1" in graph.nodes                                                       # the unit that has no partner among the uploads gets an assumed one


def test_a_unit_with_two_equally_good_partners_is_left_unpaired_and_not_guessed():
    files = [("x.txt", _unit("FW-X", "1.1.1.1", "1.1.1.2")), ("y.txt", _unit("FW-Y", "1.1.1.2", "1.1.1.1")), ("z.txt", _unit("FW-Z", "1.1.1.2", "1.1.1.1"))]
    ha, graph = _pairs(files)
    assert ha == {frozenset(("FW-X", "HAPEER-FW-X")), frozenset(("FW-Y", "HAPEER-FW-Y")), frozenset(("FW-Z", "HAPEER-FW-Z"))}


def test_a_lone_pair_with_different_names_is_still_found():
    ha = _pairs([("a.txt", _unit("EDGE-PRIMARY", "10.255.0.1", "10.255.0.2")), ("b.txt", _unit("EDGE-STANDBY", "10.255.0.2", "10.255.0.1"))])[0]
    assert ha == {frozenset(("EDGE-PRIMARY", "EDGE-STANDBY"))}


def test_a_unit_that_names_the_address_back_is_preferred_to_one_that_does_not():
    files = [("x.txt", _unit("FW-AAA1", "1.1.1.1", "1.1.1.2")), ("y.txt", _unit("ZZ-9", "1.1.1.2", "1.1.1.1")), ("z.txt", _unit("FW-AAA2", "1.1.1.2", "1.1.1.9"))]
    ha = _pairs(files)[0]
    assert frozenset(("FW-AAA1", "ZZ-9")) in ha and not any("FW-AAA2" in pair and "FW-AAA1" in pair for pair in ha)    # a name alike is the last thing that counts


def test_the_unit_that_leaves_its_ha_links_on_the_same_ports_is_preferred():
    files = [("x.txt", _unit("FW-AAA1", "1.1.1.1", "1.1.1.2")), ("y.txt", _unit("ZZ-9", "1.1.1.2", "1.1.1.1")), ("z.txt", _unit("FW-AAA2", "1.1.1.2", "1.1.1.1", ha2="ethernet1/9"))]
    ha = _pairs(files)[0]
    assert frozenset(("FW-AAA1", "ZZ-9")) in ha and not any("FW-AAA2" in pair and "FW-AAA1" in pair for pair in ha)
