"""Topology Builder: smart sites (``features/topology/sites.py``).  Invented hostnames only.

The plain prefix grouping cuts the first words of a hostname.  These tests keep what real networks need on top of that: a site code glued to the role (HQWANR1), zeros and
letter case that do not make another word, a device with a name of its own that follows its cables or the last word of its name, and a name family that falls into
parts with no cable between them.  Every rule has a mutation check: the constant that switches it on is changed and the old answer must come back.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import nxos_capture  # noqa: E402

from features.topology import sites  # noqa: E402
from features.topology.extract import Device  # noqa: E402
from features.topology.graph import Connection, Graph, Link  # noqa: E402
from features.topology.layout import auto_mode, groups_of  # noqa: E402
from features.topology.service import GROUP_MODES, build_topology  # noqa: E402


def _graph(names: list[str], links: list[tuple[str, str]], seen: tuple[str, ...] = (), role: str = "access", roles: dict[str, str] | None = None) -> Graph:
    """Captured devices ``names``, devices nobody captured ``seen`` and a cable for every pair of ``links``."""
    roles = roles or {}
    nodes = {n: Device(key=n, hostname=n, captured=True, role_hint=roles.get(n, role)) for n in names}
    nodes.update({n: Device(key=n, hostname=n, captured=False, role_hint=roles.get(n, role)) for n in seen})
    conns = [Connection(a, b, [Link(a, "Eth1/1", b, "Eth1/1", "confirmed", {"CDP"}, "")]) for a, b in links]
    return Graph(nodes=nodes, links=[link for c in conns for link in c.links], connections=conns, hidden_kinds=set())


def _chain(names: list[str]) -> list[tuple[str, str]]:
    return list(zip(names, names[1:]))


HQ = ["HQWANR1", "HQWANR2", "HQEDGNX1", "HQEDGNX2", "HQKSR1", "HQSDWANR2"]            # glued names: no separator between the site and the role
BRANCH = ["BRN-SENAYAN-SW1", "BRN-SENAYAN-SW2", "BRN-SENAYAN-SW3", "BRN-SENAYAN-RTR1"]


def test_a_site_code_glued_to_the_role_is_learned_from_the_names():
    graph = _graph(HQ + BRANCH, _chain(HQ) + _chain(BRANCH))
    assert sites.learn_codes(graph, list(graph.nodes), sites._near(graph, set(graph.nodes))) == {"HQ"}
    found = sites.detect(graph, 1)
    assert sorted(found.groups) == ["BRN", "HQ"] and sorted(found.groups["HQ"]) == sorted(HQ)
    plain = groups_of(graph, "prefix1")                                                      # the plain grouping has a "site" for every glued name
    assert len(plain) > 6 and "HQWANR1" in plain


def test_a_start_shared_by_names_that_are_not_cabled_is_no_site_code():
    names = ["FWDMZ1", "FWEDGE1", "FWINT1", "FWOUT1"]
    graph = _graph(names, [])
    assert sites.learn_codes(graph, names, sites._near(graph, set(names))) == set()          # four firewalls that happen to start alike
    graph = _graph(names, _chain(names))
    assert sites.learn_codes(graph, names, sites._near(graph, set(names))) == {"FW"}          # cabled to each other they are one family


def test_a_counter_after_the_code_is_not_a_role_word():
    names = ["SW1", "SW2", "SW3", "SW4"]
    graph = _graph(names, _chain(names))
    assert sites.learn_codes(graph, names, sites._near(graph, set(names))) == set()          # the letters after SW never differ: only numbers follow


def test_a_zero_in_front_of_a_number_and_the_letter_case_do_not_make_another_word():
    assert sites.name_key("DEA-OFF-LT02-ACC1", 3, set()) == sites.name_key("dea-off-lt2-ap1", 3, set()) == "DEA-OFF-LT2"
    graph = _graph(["DEA-OFF-LT02-ACC1", "DEA-OFF-LT02-CORE1", "dea-off-lt2-sw1", "BRN-SW1", "BRN-SW2"], [])
    assert sorted(groups_of(graph, "prefix3")) == ["BRN-SW1", "BRN-SW2", "DEA-OFF-LT02", "dea-off-lt2"]            # the plain grouping: three names for one floor
    found = sites.detect(graph, 3).groups
    assert sorted(found) == ["BRN-SW1", "BRN-SW2", "DEA-OFF-LT02"]                  # one floor, named as most of its devices spell it (LT02, not the zero-less key)
    assert len(found["DEA-OFF-LT02"]) == 3


def test_a_device_with_its_own_name_follows_the_last_word_of_the_site_name():
    members = [f"KCU-SENAYAN-JAS-{i}-SW" for i in range(1, 5)]
    graph = _graph(members + ["BRN-SW1", "BRN-SW2"], _chain(members), seen=("MIKROTIK-JAS",), roles={"MIKROTIK-JAS": "router"})
    found = sites.detect(graph, 3)
    assert "MIKROTIK-JAS" in found.groups["KCU-SENAYAN-JAS"] and sites.OTHER not in found.groups
    assert sites.OTHER in groups_of(graph, "prefix3")                                         # the plain grouping leaves it "other"
    other = _graph(members + ["BRN-SW1", "BRN-SW2"], _chain(members) + [("MIKROTIK-JAS", "BRN-SW1")], seen=("MIKROTIK-JAS",), roles={"MIKROTIK-JAS": "router"})
    assert "MIKROTIK-JAS" not in sites.detect(other, 3).groups["KCU-SENAYAN-JAS"]            # its cable leads to another site: the name does not win


def test_a_small_family_with_its_own_name_joins_the_site_its_cables_lead_to(monkeypatch):
    floor = [f"DEA-OFF-LT{i}-ACC1" for i in range(1, 5)]
    graph = _graph(floor + ["JLN-WLC-01", "BRN-SW1", "BRN-SW2"], _chain(floor) + [("DEA-OFF-LT1-ACC1", "JLN-WLC-01")])
    assert "JLN-WLC-01" in sites.detect(graph, 1).groups["DEA"]
    monkeypatch.setattr(sites, "SMALL_SITE", 0)                                               # the mutation check: no family is small
    assert "JLN" in sites.detect(graph, 1).groups
    monkeypatch.undo()
    big = _graph(floor + ["JLN-WLC-01", "JLN-WLC-02", "JLN-WLC-03", "BRN-SW1", "BRN-SW2"],
                 _chain(floor) + [("DEA-OFF-LT1-ACC1", "JLN-WLC-01"), ("JLN-WLC-01", "JLN-WLC-02"), ("JLN-WLC-02", "JLN-WLC-03")])
    assert "JLN" in sites.detect(big, 1).groups                                               # three devices of its own is a site of its own


def test_a_name_family_in_two_parts_with_no_cable_between_them_is_two_sites(monkeypatch):
    gd1, gd2 = ["JKT-GD1-SW1", "JKT-GD1-SW2"], ["JKT-GD2-SW1", "JKT-GD2-SW2"]
    graph = _graph(gd1 + gd2 + ["BAL-SW1", "BAL-SW2"], _chain(gd1) + _chain(gd2) + [("BAL-SW1", "BAL-SW2")])
    assert sorted(sites.detect(graph, 1).groups) == ["BAL", "JKT-GD1", "JKT-GD2"]
    joined = _graph(gd1 + gd2 + ["BAL-SW1", "BAL-SW2"], _chain(gd1) + _chain(gd2) + [("JKT-GD1-SW2", "JKT-GD2-SW1"), ("BAL-SW1", "BAL-SW2")])
    assert sorted(sites.detect(joined, 1).groups) == ["BAL", "JKT"]                           # one cable between the parts: one site
    monkeypatch.setattr(sites, "SPLIT_MIN_SITE", 99)                                          # the mutation check: no site is ever split
    assert sorted(sites.detect(graph, 1).groups) == ["BAL", "JKT"]


def test_automatic_draws_a_small_network_by_sites_when_two_sites_are_clear():
    phones = [f"SEP{i:012d}" for i in range(1, 6)]
    graph = _graph(HQ + BRANCH, _chain(HQ) + _chain(BRANCH), seen=tuple(phones), roles={p: "phone" for p in phones})
    graph.connections += [Connection(p, "BRN-SENAYAN-SW1", [Link(p, "Eth1/1", "BRN-SENAYAN-SW1", "Gi1/0/1", "single", {"CDP"}, "")]) for p in phones]
    assert auto_mode(graph) == "sites"
    assert sorted(groups_of(graph, "sites")) == ["BRN", "HQ"] and all(p in groups_of(graph, "sites")["BRN"] for p in phones)
    tiny = _graph(HQ[:2] + BRANCH[:2], _chain(HQ[:2]) + _chain(BRANCH[:2]))
    assert auto_mode(tiny) == "none"                                                          # four devices stay one diagram


def test_automatic_keeps_the_plain_answer_when_the_names_are_tidy():
    names = [f"{site}-SW{i}" for site in ("JKT", "BGR", "SBY", "MDN", "BDG", "SMG") for i in range(1, 7)]
    graph = _graph(names, [(f"{site}-SW1", f"{site}-SW{i}") for site in ("JKT", "BGR", "SBY", "MDN", "BDG", "SMG") for i in range(2, 7)])
    assert auto_mode(graph) == "prefix1"


def test_sites_is_a_choice_of_the_page_and_builds_one_page_per_site():
    assert "sites" in [value for value, _ in GROUP_MODES]
    files, serial = [], 100
    for site, count in (("HQ", 4), ("RMBR", 3)):
        names = [f"{site}{role}{n}" if site == "HQ" else f"{site}-{role}{n}" for role, n in zip(("WANR", "CORE", "DIST", "ACC"), range(1, count + 2))][:count + 1]
        for i, host in enumerate(names):
            cdp = [(names[j], f"10.9.{j}.1", "N9K-C93180YC-FX3", "Eth1/1", "Eth1/2") for j in (i - 1, i + 1) if 0 <= j < len(names)]
            serial += 1
            files.append((f"{host}.txt", nxos_capture(host, f"FDO{serial:08d}", f"10.9.{i}.{serial}", cdp)))
    result = build_topology(files, group="sites")
    assert [p.name for p in result["pages"]] == ["Overview", "HQ", "RMBR"]


def test_the_choice_that_is_not_possible_falls_back_to_one_diagram_for_one_site():
    graph = _graph([f"KCU-SW{i}" for i in range(1, 7)], _chain([f"KCU-SW{i}" for i in range(1, 7)]))
    assert groups_of(graph, "sites") != {}
    assert auto_mode(graph) == "none"


@pytest.mark.parametrize("host", ["10-10-1-17", "172-17-171-2", "2cfa.a29b.f8bb", "00:03:56:1F:94:65", ""])
def test_an_address_or_a_mac_address_is_not_a_name(host):
    assert not sites.is_named(host)


def test_a_mistyped_site_name_that_is_cabled_to_its_site_is_one_site(monkeypatch):
    main = [f"KCU-SENAYAN-JAS-{i}" for i in range(1, 4)]
    odd = ["KCU-SENAYN-JAS-4", "KCU-SENAYN-JAS-5", "KCU-SENAYN-JAS-6"]        # three devices: more than a "small family", so only the near name joins them
    graph = _graph(main + odd + ["BRN-SW1", "BRN-SW2"], _chain(main) + [("KCU-SENAYAN-JAS-3", "KCU-SENAYN-JAS-4"), ("KCU-SENAYN-JAS-4", "KCU-SENAYN-JAS-5"), ("KCU-SENAYN-JAS-5", "KCU-SENAYN-JAS-6")])
    assert sorted(sites.detect(graph, 3).groups) == ["BRN-SW1", "BRN-SW2", "KCU-SENAYAN-JAS"] and len(sites.detect(graph, 3).groups["KCU-SENAYAN-JAS"]) == 6
    apart = _graph(main + odd + ["BRN-SW1", "BRN-SW2"], _chain(main) + [("KCU-SENAYN-JAS-4", "KCU-SENAYN-JAS-5"), ("KCU-SENAYN-JAS-5", "KCU-SENAYN-JAS-6")])
    assert "KCU-SENAYN-JAS" in sites.detect(apart, 3).groups                                  # no cable between them: two sites, however alike the names
    floors = _graph(["TWR-LANTAI1-SW1", "TWR-LANTAI1-SW2", "TWR-LANTAI2-SW1", "TWR-LANTAI2-SW2"], [("TWR-LANTAI1-SW1", "TWR-LANTAI2-SW1")])
    assert len(sites.detect(floors, 2).groups) == 2                                           # one digit apart is a floor, not a typo
    monkeypatch.setattr(sites, "NEAR_MIN_LEN", 99)                                            # the mutation check: no word is long enough
    assert "KCU-SENAYN-JAS" in sites.detect(graph, 3).groups


def _office(aps: int = 26):
    """A floor of one office: five switches of the DEA family, a WLC named after its vendor (family JLN) cabled to a switch, and access points named JLN-AP-n that plug into the
    switches.  The plain first-word grouping makes two sites of it (DEA and JLN); with the cables it is one."""
    switches = [f"DEA-SW{i}" for i in range(1, 6)]
    aps_ = [f"JLN-AP-{i:02d}" for i in range(1, aps + 1)]
    graph = _graph(switches + ["JLN-WLC-01"], _chain(switches) + [("DEA-SW1", "JLN-WLC-01")], seen=tuple(aps_), roles={a: "ap" for a in aps_})
    graph.connections += [Connection(a, switches[i % 5], [Link(a, "Gi0", switches[i % 5], f"Gi1/0/{i + 1}", "single", {"CDP"}, "")]) for i, a in enumerate(aps_)]
    return graph


def test_a_family_that_the_cables_put_inside_another_one_is_not_a_page_of_its_own(monkeypatch):
    graph = _office()
    assert sorted(groups_of(graph, "prefix1")) == ["DEA", "JLN"]                              # the plain grouping: a page for the WLC and its access points
    assert auto_mode(graph) == "none"                                                         # one office, one diagram
    monkeypatch.setattr(sites, "one_site", lambda graph, take: False)                          # the mutation check: the plain grouping is believed
    assert auto_mode(graph) == "prefix1"


def test_a_vdom_without_a_cable_stands_next_to_the_vdoms_of_its_own_firewall(monkeypatch):
    from features.topology import layout

    names = ["CORE1", "FWA [v1]", "FWB [v1]", "FWA [v2]"]
    graph = _graph(names, [("CORE1", "FWA [v1]"), ("CORE1", "FWB [v1]")], role="firewall", roles={"CORE1": "core"})
    graph.chassis_units = {"FWA": ["FWA [v1]", "FWA [v2]"], "FWB": ["FWB [v1]"]}
    placed, _, _ = layout.layered(graph, names)
    near = lambda p: abs(p["FWA [v2]"].x - p["FWA [v1]"].x) < abs(p["FWA [v2]"].x - p["FWB [v1]"].x)          # noqa: E731
    assert near(placed) and placed["FWA [v2]"].tier == placed["FWA [v1]"].tier
    monkeypatch.setattr(layout, "unlinked_siblings", lambda graph, keys, tier_value: {})        # the mutation check: no sibling rule, the unlinked VDOM goes to the end of the row
    placed, _, _ = layout.layered(graph, names)
    assert not near(placed)


def test_unlinked_siblings_take_the_row_of_the_sibling_with_most_cables():
    from features.topology import layout

    graph = _graph(["A [x]", "A [y]", "A [z]", "S1", "S2"], [("A [x]", "S1"), ("A [x]", "S2"), ("A [y]", "S1")], role="firewall")
    graph.chassis_units = {"A": ["A [x]", "A [y]", "A [z]"]}
    tier = {"A [x]": 2.0, "A [y]": 3.0, "A [z]": 1.0, "S1": 4.0, "S2": 4.0}
    assert layout.unlinked_siblings(graph, list(tier), tier) == {"A [z]": "A [x]"} and tier["A [z]"] == 2.0


# ---- floors of one building: Automatic goes by the first two hostname words (invented names) ----

def _building(floors: int = 14, aps: int = 2):
    """An aggregation floor (A02) with two aggregation switches and one access switch with access points on every other floor, all cabled to the aggregation pair."""
    names = ["BLD-A02-AGG1", "BLD-A02-AGG2", "BLD-A02-ACC1"]
    links = [("BLD-A02-AGG1", "BLD-A02-AGG2"), ("BLD-A02-AGG1", "BLD-A02-ACC1"), ("BLD-A02-AGG2", "BLD-A02-ACC1")]
    roles = {"BLD-A02-AGG1": "core", "BLD-A02-AGG2": "core"}
    for number in range(3, 3 + floors):
        switch = f"BLD-A{number:02d}-SW1"
        names.append(switch)
        links += [("BLD-A02-AGG1", switch), ("BLD-A02-AGG2", switch)]
        for ap in range(1, aps + 1):
            names.append(f"BLD-A{number:02d}-AP{ap}")
            roles[names[-1]] = "ap"
            links.append((switch, names[-1]))
    return _graph(names, links, roles=roles)


def test_the_floors_of_one_building_are_pages_of_their_own_by_the_first_two_words():
    graph = _building()
    assert auto_mode(graph) == "prefix2"
    assert len(groups_of(graph, "prefix2")) == 15                                              # A02 plus fourteen floors
    found = sites.detect(graph, 2)
    assert len([n for n in found.groups if n != sites.OTHER]) == 15                            # the cables do not merge a floor into the aggregation floor
    assert sites.joined(graph, found)                                                          # ... and the floors are cabled together: one building


def test_a_floor_with_one_switch_is_not_merged_into_the_aggregation_floor(monkeypatch):
    graph = _building()
    monkeypatch.setattr(sites, "PEERS", 99)                    # the mutation check: no row of peers, the cables pull the one-switch floors into the aggregation floor
    found = sites.detect(graph, 2)
    assert len([n for n in found.groups if n != sites.OTHER]) < 15


def test_the_parts_of_a_site_hanging_from_one_captured_switch_are_one_site():
    names = ["X-A1", "X-A2", "X-B1", "X-B2", "UP1"]
    graph = _graph(names, [("X-A1", "X-A2"), ("X-B1", "X-B2"), ("UP1", "X-A1"), ("UP1", "X-B1")])
    near = sites._near(graph, set(names))
    inside = {"X-A1", "X-A2", "X-B1", "X-B2"}
    parts = [["X-A1", "X-A2"], ["X-B1", "X-B2"]]
    assert len(sites._join_by_shared_uplink(graph, parts, near, inside)) == 1                  # the same captured uplink: one site
    graph.nodes["UP1"].captured = False
    assert len(sites._join_by_shared_uplink(graph, parts, near, inside)) == 2                  # a router nobody captured says nothing


def test_automatic_says_why_it_chose_one_site_a_campus_or_several_sites():
    from features.topology.layout import auto_reason

    campus = _building()
    text = auto_reason(campus, "prefix2")
    assert "One place (BLD)" in text and "15 floors or areas" in text and "first 2 hostname words" in text and "BLD-A02 (" in text
    small = _graph(["A-SW1", "A-SW2"], [("A-SW1", "A-SW2")])
    assert "few enough for one readable diagram" in auto_reason(small, "none")
    two = _graph(HQ + BRANCH, _chain(HQ) + _chain(BRANCH))
    assert "separate sites" in auto_reason(two, "sites") and "hostname families and the cables" in auto_reason(two, "sites") and "HQ (" in auto_reason(two, "sites") and "BRN (" in auto_reason(two, "sites")
    office = _office()
    assert "cabled together as one site" in auto_reason(office, "none")


def test_the_reason_reaches_the_result_and_the_run_settings_text():
    from features.topology.report import settings_text
    from test_topology_sites import _site_files

    result = build_topology(_site_files(8, 4), group="auto")
    assert "8 separate sites" in result["group_reason"] and result["settings"]["group_reason"] == result["group_reason"]
    assert "Why: " + result["group_reason"] in settings_text(result["settings"], result["summary"], result["notices"])
    fixed = build_topology(_site_files(8, 4), group="none")
    assert fixed["group_reason"] == ""                                                         # a grouping the user chose needs no explanation


def test_a_site_is_named_as_most_of_its_devices_spell_it():
    graph = _graph(["DEA-LT02-SW1", "DEA-LT02-SW2", "DEA-lt2-SW3", "BRN-SW1", "BRN-SW2"], [])
    names = sorted(sites.detect(graph, 2).groups)
    assert "DEA-LT02" in names and "DEA-LT2" not in names


def test_the_floors_of_a_small_building_are_left_to_the_plain_words_until_it_is_too_big_for_one_diagram(monkeypatch):
    graph = _building()
    assert sites.choose(graph) is None                         # connected floors, fewer devices than CONNECTED_SPLIT_MIN: the plain first two words do it
    monkeypatch.setattr(sites, "CONNECTED_SPLIT_MIN", 1)       # the mutation check: no gate, the smart sites are offered too
    graph.__dict__.pop("_sites_cache", None)
    assert sites.choose(graph) is not None


def test_the_floors_that_hang_from_one_floor_do_not_make_its_page_ten_thousand_pixels_wide(monkeypatch):
    from features.topology import layout

    floors = [f"BLD-A{n:02d}-SW1" for n in range(3, 25)]
    graph = _graph(["BLD-A02-AGG1", *floors], [("BLD-A02-AGG1", f) for f in floors], roles={"BLD-A02-AGG1": "core"})
    keys = list(graph.nodes)
    _, wide, _ = layout.layered(graph, keys)                                   # drawn as a plain page: one row of 22
    placed, narrow, _ = layout.layered(graph, keys, ghosts=set(floors))        # the same floors as neighbours of another site
    assert narrow < wide / 2
    assert len({round(p.y) for k, p in placed.items() if k in floors}) == 3     # dealt out over three lines
    monkeypatch.setattr(layout, "GHOST_ROW_MAX", 999)                          # the mutation check: no limit, one long row again
    _, again, _ = layout.layered(graph, keys, ghosts=set(floors))
    assert again == wide


def _server_on_two_racks():
    """Two core switches, six access switches, a server cabled with ten links to the first access switch and with six to a rack switch that hangs from the last access switch by two."""
    access = [f"RK-SW{n}" for n in range(1, 7)]
    names = ["RK-CORE1", "RK-CORE2", *access, "RK-LEAF", "SRV-NIC"]
    roles = {"RK-CORE1": "core", "RK-CORE2": "core"}
    graph = _graph(names, [], roles=roles)
    graph.nodes["SRV-NIC"].captured = False
    pairs = [(c, a, 1) for c in ("RK-CORE1", "RK-CORE2") for a in access] + [("RK-SW6", "RK-LEAF", 2), ("RK-SW1", "SRV-NIC", 10), ("RK-LEAF", "SRV-NIC", 6)]
    graph.connections = [Connection(a, b, [Link(a, f"Eth1/{i}", b, f"Eth1/{i}", "confirmed", {"CDP"}, "") for i in range(n)]) for a, b, n in pairs]
    graph.links = [link for c in graph.connections for link in c.links]
    return graph


def test_a_device_cabled_much_more_to_a_row_mate_than_to_the_switch_above_stands_next_to_that_row_mate(monkeypatch):
    from features.topology import layout

    graph = _server_on_two_racks()
    row = ["SRV-NIC", "RK-SW-X", "RK-LEAF"]                                                  # the order the anchors give: the server under its rack, the leaf under its own
    graph.nodes["RK-SW-X"] = Device(key="RK-SW-X", hostname="RK-SW-X", captured=True, role_hint="access")
    known = {"RK-SW1", "RK-SW6"}
    spot = {"RK-SW1": 0.0, "RK-SW6": 5.0}
    want = {"SRV-NIC": 0.0, "RK-LEAF": 5.0}
    new_row, new_want = layout._pull_to_heavy_peer(graph, row, spot, known, want)
    assert new_row.index("RK-LEAF") == new_row.index("SRV-NIC") + 1                          # next to the server it is cabled to with six links
    assert new_want["SRV-NIC"] == 0.0 and 0.0 < new_want["RK-LEAF"] < 2.0                    # it wishes a place near the server, the server keeps its rack
    monkeypatch.setattr(layout, "PEER_TIE_MIN", 10 ** 6)                                    # the mutation check: no pull, the leaf stays under its own rack
    same_row, same_want = layout._pull_to_heavy_peer(graph, row, spot, known, want)
    assert same_row == row and same_want == want


def test_a_row_of_a_real_page_keeps_its_order_when_no_device_is_tied_that_heavily():
    from features.topology import layout

    graph = _server_on_two_racks()
    row = ["RK-SW1", "RK-SW2", "RK-SW3"]
    spot = {"RK-CORE1": 0.0, "RK-CORE2": 1.0}
    want = {"RK-SW1": 0.0, "RK-SW2": 0.5, "RK-SW3": 1.0}
    assert layout._pull_to_heavy_peer(graph, row, spot, {"RK-CORE1", "RK-CORE2"}, want) == (row, want)


# ---- role first, site second (SW-JKT-1, RTR-JKT-1, FW-JKT-1): the first word is the role, the second the site ----

SITES4 = ["JKT", "BDG", "SBY", "MDN", "SMG"]


def _role_first(cabled: bool = True):
    names, links = [], []
    for site in SITES4:
        site_names = [f"SW-{site}-{n}" for n in range(1, 6)] + [f"RTR-{site}-1", f"FW-{site}-1", f"AP-{site}-1"]
        names += site_names
        if cabled:
            links += _chain(site_names[:5]) + [(f"RTR-{site}-1", f"SW-{site}-1"), (f"FW-{site}-1", f"RTR-{site}-1")]
    roles = {n: "router" for n in names if n.startswith("RTR")} | {n: "firewall" for n in names if n.startswith("FW")} | {n: "ap" for n in names if n.startswith("AP")}
    return _graph(names, links, roles=roles)


def test_role_words_that_come_first_are_not_the_site():
    graph = _role_first()
    leads = sites.learn_leads(graph, list(graph.nodes))
    assert leads == {"SW", "RTR", "FW", "AP"}                                  # the roles that stand before the site word
    found = sites.detect(graph, 1)
    assert sorted(n for n in found.groups if n != sites.OTHER) == sorted(SITES4)
    assert all(len(keys) == 8 for n, keys in found.groups.items() if n in SITES4)           # every site holds its switches, router, firewall and access point


def test_automatic_goes_by_the_site_word_when_the_role_comes_first_with_and_without_cables():
    for cabled in (True, False):
        graph = _role_first(cabled)
        assert auto_mode(graph) == "sites"                                                  # the plain words give a page per role and site (SW-JKT, RTR-JKT)
        assert sorted(groups_of(graph, "sites")) == sorted(SITES4)


def test_a_site_word_first_is_never_taken_for_a_role_word():
    names = [f"{site}-SW{n}" for site in SITES4 for n in range(1, 8)]
    graph = _graph(names, [])
    assert sites.learn_leads(graph, names) == set()                                         # JKT, BDG ... each start few names with no word shared between them


def test_a_single_role_word_in_front_of_many_sites_is_a_lead(monkeypatch):
    names = [f"SW-{site}-{n}" for site in SITES4 for n in range(1, 4)]
    graph = _graph(names, [])
    assert sites.learn_leads(graph, names) == {"SW"}
    monkeypatch.setattr(sites, "LEAD_MIN_SITES", 99)                                       # the mutation check: no lead is learned
    assert sites.learn_leads(graph, names) == set()


def test_without_the_lead_words_automatic_keeps_the_plain_pages_per_role_and_site(monkeypatch):
    graph = _role_first()
    monkeypatch.setattr(sites, "learn_leads", lambda graph, keys: set())                       # the mutation check: no role word is learned
    graph.__dict__.pop("_sites_cache", None)
    assert auto_mode(graph) != "sites" or sorted(groups_of(graph, "sites")) != sorted(SITES4)


# ---- role first, floor or building second (SW-A02-1, RTR-A02-1): letters and a number are the site word ----

FLOORS = ["A02", "A08", "B01", "B03", "C05", "C11"]


def _role_floor(cabled: bool = True):
    names, links = [], []
    for floor in FLOORS:
        floor_names = [f"SW-{floor}-{n}" for n in range(1, 5)] + [f"RTR-{floor}-1", f"AP-{floor}-1"]
        names += floor_names
        if cabled:
            links += _chain(floor_names[:4]) + [(f"RTR-{floor}-1", f"SW-{floor}-1")]
    roles = {n: "router" for n in names if n.startswith("RTR")} | {n: "ap" for n in names if n.startswith("AP")}
    return _graph(names, links, roles=roles)


def test_a_floor_or_building_word_after_a_role_is_the_site_even_when_the_floors_share_a_letter():
    graph = _role_floor()
    assert sites.learn_leads(graph, list(graph.nodes)) == {"SW", "RTR", "AP"}               # A02 and A08 are two floors, not one word "A"
    found = sites.detect(graph, 1)
    assert sorted(n for n in found.groups if n != sites.OTHER) == sorted(sites._pad(f) for f in FLOORS)
    assert all(len(keys) == 6 for n, keys in found.groups.items() if n != sites.OTHER)


def test_automatic_goes_by_the_floor_word_when_the_role_comes_first(monkeypatch):
    for cabled in (True, False):
        graph = _role_floor(cabled)
        assert auto_mode(graph) == "sites" and len(groups_of(graph, "sites")) == len(FLOORS)
    monkeypatch.setattr(sites, "ROLE_WORDS", set())                                         # the mutation check: with no role words nothing is learned
    graph = _role_floor()
    assert sites.learn_leads(graph, list(graph.nodes)) == set()


def test_a_city_and_a_floor_read_the_same_way_so_a_floor_word_only_counts_after_a_role():
    names = [f"{city}-LT{n}-SW{k}" for city in ("KCU", "BDG", "SRG") for n in range(1, 5) for k in (1, 2)]
    graph = _graph(names, [])
    assert sites.learn_leads(graph, names) == set()                                         # KCU, BDG, SRG are sites; LT1..LT4 are their floors


def test_a_counter_after_a_site_is_not_taken_for_a_floor():
    names = [f"SW-{site}-{n}" for site in ("JKT", "BDG") for n in range(1, 4)] + [f"SW-SW{n}-{k}" for n in range(1, 4) for k in (1, 2)]
    graph = _graph(names, [])
    assert "SW" not in sites._learn_unit_leads(*_after(graph, names))                      # SW1, SW2, SW3 are role counters


def _after(graph, names):
    from collections import defaultdict
    after = defaultdict(lambda: defaultdict(int))
    for name in names:
        parts = [sites._pad(p) for p in sites.words(name)]
        if len(parts) >= 2:
            after[parts[0]][parts[1]] += 1
    eligible = {w: seconds for w, seconds in after.items() if sum(seconds.values()) >= sites.LEAD_MIN_DEVICES}
    return after, eligible, set()


# ---- the engineer's own site rules ("Label = start, start") ----

def test_site_rules_are_read_one_per_line_and_bad_lines_are_ignored():
    text = "HQ = HQWAN, hq-acc ,\n# a comment\nno equal sign\n = HQ\nDC1 =\nDC2 = DCA-, DCB-"
    assert sites.parse_rules(text) == [("HQ", ["HQWAN", "HQ-ACC"]), ("DC2", ["DCA-", "DCB-"])]
    assert sites.parse_rules("") == [] and len(sites.parse_rules("\n".join(f"S{n} = X{n}" for n in range(200)))) == sites.RULES_MAX


def test_a_rule_moves_devices_by_the_start_of_their_hostname_and_their_end_points_follow():
    names = ["AAA-SW1", "AAA-SW2", "BBB-SW1", "BBB-SW2", "ODD-RTR1", "ODD-AP1"]
    graph = _graph(names, [("ODD-RTR1", "AAA-SW1"), ("ODD-AP1", "ODD-RTR1"), ("AAA-SW1", "AAA-SW2")], roles={"ODD-AP1": "ap"})
    plain = {"AAA": ["AAA-SW1", "AAA-SW2"], "BBB": ["BBB-SW1", "BBB-SW2"], "ODD": ["ODD-RTR1", "ODD-AP1"]}
    moved = sites.apply_rules(graph, plain, sites.parse_rules("Main = AAA, odd-"))
    assert sorted(moved) == ["BBB", "Main"] and sorted(moved["Main"]) == ["AAA-SW1", "AAA-SW2", "ODD-AP1", "ODD-RTR1"]
    assert sites.apply_rules(graph, plain, []) is plain


def test_the_rules_act_on_every_grouping_but_one_diagram():
    from features.topology.layout import groups_of

    names = ["AAA-SW1", "AAA-SW2", "BBB-SW1", "BBB-SW2", "CCC-SW1", "CCC-SW2"]
    graph = _graph(names, [])
    assert sorted(groups_of(graph, "prefix1")) == ["AAA", "BBB", "CCC"]
    graph.site_rules = sites.parse_rules("North = AAA, BBB")
    assert sorted(groups_of(graph, "prefix1")) == ["CCC", "North"] and sorted(groups_of(graph, "sites")) == ["CCC", "North"]
    assert list(groups_of(graph, "none")) == ["All devices"]


def test_a_build_with_rules_draws_one_page_for_the_merged_sites():
    from test_topology_sites import _site_files

    result = build_topology(_site_files(8, 4), group="prefix1", site_rules="Both = S01, S02")
    names = [page.name for page in result["pages"]]
    assert "Both" in names and "S01" not in names and "S02" not in names and len(names) == 8          # Overview + Both + S03..S08
    assert result["settings"]["site_rules"] == 1
    assert "Site rules typed for the grouping: 1 rule(s)" in __import__("features.topology.report", fromlist=["settings_text"]).settings_text(result["settings"])
    assert build_topology(_site_files(8, 4), group="prefix1")["settings"]["site_rules"] == 0
