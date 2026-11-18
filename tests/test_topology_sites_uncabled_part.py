"""A small part of a site that no cable joins to anything is no site of its own.

A firewall pair read from its manager's configuration (Panorama, FortiManager) shows no neighbours: no cable ties it to the switches of its building, yet the names say it is
there.  It joins the largest part of the site instead of getting a page with two boxes.  A part of any size that is cabled to something captured, or a part bigger than
``UNCABLED_PART``, keeps its own page.  Synthetic names only.
"""

from __future__ import annotations

from features.topology import sites
from features.topology.layout import SITES_MODE, groups_of
from tests.test_topology_v05 import _graph_of

CORE = [f"HQ-CORE-SW{n}" for n in (1, 2, 3)]
FLOOR = [f"HQ-FLOOR2-SW{n}" for n in (1, 2, 3)]
LINKS = [("HQ-CORE-SW1", "HQ-CORE-SW2"), ("HQ-CORE-SW2", "HQ-CORE-SW3"), ("HQ-FLOOR2-SW1", "HQ-FLOOR2-SW2"), ("HQ-FLOOR2-SW2", "HQ-FLOOR2-SW3"),
         ("XA-RTR1", "HQ-CORE-SW1"), ("XB-RTR1", "HQ-FLOOR2-SW1")]        # each part has its own upstream router: two parts, not one
OUTSIDE = ["XA-RTR1", "XB-RTR1"]


def _found(extra, links=()):
    graph = _graph_of(CORE + FLOOR + OUTSIDE + extra, LINKS + list(links))
    return {name: sorted(keys) for name, keys in groups_of(graph, SITES_MODE).items() if name != sites.OTHER}


def _page_of(found, key):
    return next(name for name, keys in found.items() if key in keys)


def test_a_firewall_pair_that_no_cable_reaches_joins_the_largest_part_of_its_site():
    found = _found(["HQ-FWALL1", "HQ-FWALL2"], [("HQ-FWALL1", "HQ-FWALL2")])
    assert sorted(found) == ["HQ-1", "HQ-2"]
    assert _page_of(found, "HQ-FWALL1") == _page_of(found, "HQ-FWALL2") == _page_of(found, "HQ-CORE-SW1")          # 4 in the core part (with its router), 4 in the floor part: the first




def test_the_largest_part_takes_the_pair_whichever_comes_first():
    more = [f"HQ-FLOOR2-SW{n}" for n in (4, 5)]
    found = _found(["HQ-FWALL1", "HQ-FWALL2"] + more, [("HQ-FWALL1", "HQ-FWALL2"), ("HQ-FLOOR2-SW3", "HQ-FLOOR2-SW4"), ("HQ-FLOOR2-SW4", "HQ-FLOOR2-SW5")])
    assert _page_of(found, "HQ-FWALL1") == _page_of(found, "HQ-FLOOR2-SW1") != _page_of(found, "HQ-CORE-SW1")


def test_a_pair_cabled_to_a_captured_device_follows_that_cable():
    found = _found(["HQ-FWALL1", "HQ-FWALL2"], [("HQ-FWALL1", "HQ-FWALL2"), ("HQ-FWALL1", "XB-RTR1")])
    assert _page_of(found, "HQ-FWALL1") == _page_of(found, "HQ-FLOOR2-SW1")


def test_a_part_bigger_than_the_limit_keeps_its_own_page():
    names = [f"HQ-LAB-SW{n}" for n in range(1, sites.UNCABLED_PART + 2)]
    links = [(a, b) for a, b in zip(names, names[1:])]
    found = _found(names, links)
    assert len(found) == 3 and _page_of(found, names[0]) not in (_page_of(found, "HQ-CORE-SW1"), _page_of(found, "HQ-FLOOR2-SW1"))


def test_a_part_of_exactly_the_limit_joins():
    names = [f"HQ-LAB-SW{n}" for n in range(1, sites.UNCABLED_PART + 1)]
    links = [(a, b) for a, b in zip(names, names[1:])]
    found = _found(names, links)
    assert len(found) == 2 and _page_of(found, names[0]) in (_page_of(found, "HQ-CORE-SW1"), _page_of(found, "HQ-FLOOR2-SW1"))


def test_when_every_part_is_uncabled_nothing_joins():
    graph = _graph_of(CORE + FLOOR, LINKS[:4])
    found = {n: sorted(k) for n, k in groups_of(graph, SITES_MODE).items() if n != sites.OTHER}
    assert sorted(found) == ["HQ-CORE", "HQ-FLOOR2"]             # the plain naming rule, as before: no part has a cable to anything to follow


def _with_neighbour(neighbour, units=3, **fields):
    from features.topology.extract import Device
    from features.topology.graph import Connection, Link

    firewalls = [f"HQ-FWALL{n}" for n in range(1, units + 1)]
    graph = _graph_of(CORE + FLOOR + OUTSIDE + firewalls, LINKS + list(zip(firewalls, firewalls[1:])))
    graph.nodes[neighbour] = Device(key=neighbour, hostname=neighbour, **fields)
    graph.connections.append(Connection("HQ-FWALL1", neighbour, [Link("HQ-FWALL1", "Eth1/5", neighbour, "Eth1/1", "confirmed", {"LLDP"}, "")]))
    return {name: sorted(keys) for name, keys in groups_of(graph, SITES_MODE).items() if name != sites.OTHER}


def test_a_neighbour_nobody_captured_is_no_cable_to_the_rest_of_the_site():
    found = _with_neighbour("PROVIDER-ROUTER", units=2, captured=False, role_hint="router")
    assert _page_of(found, "HQ-FWALL1") in (_page_of(found, "HQ-CORE-SW1"), _page_of(found, "HQ-FLOOR2-SW1")) and len(found) == 2


def test_an_end_point_is_no_cable_to_the_rest_of_the_site():
    found = _with_neighbour("HQ-PC-LT1", captured=True, role_hint="host")
    assert _page_of(found, "HQ-FWALL1") in (_page_of(found, "HQ-CORE-SW1"), _page_of(found, "HQ-FLOOR2-SW1"))
