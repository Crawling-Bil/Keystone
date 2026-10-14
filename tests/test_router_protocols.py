"""Router Analyzer: ``show ip protocols`` (live routing protocols, information sources, BGP neighbor policy).

The sample uses RFC 5737 addresses and generic names; its layout is copied from a real ASR1002-X capture (OSPF as an ASBR with
redistribution from BGP, BGP with a route-map on every neighbor).  The router that runs no protocol prints one line, which
the analyzer must read as an answer ("no routing protocol is running") and not as an unreadable block.
"""

from __future__ import annotations

from features.router_analyzer import context as ctxmod
from features.router_analyzer import runtime_protocols as rp
from features.router_analyzer.service import analyze

PROTOCOLS = """\
*** IP Routing is NSF aware ***

Routing Protocol is "ospf 100"
  Outgoing update filter list for all interfaces is not set
  Incoming update filter list for all interfaces is not set
  Router ID 192.0.2.1
  It is an autonomous system boundary router
 Redistributing External Routes from,
    bgp 65000 with metric mapped to 10, includes subnets in redistribution
  Number of areas in this router is 1. 1 normal 0 stub 0 nssa
  Maximum path: 4
  Routing for Networks:
    198.51.100.0 0.0.0.255 area 0.0.0.0
    203.0.113.0 0.0.0.255 area 0.0.0.0
  Passive Interface(s):
    GigabitEthernet0/1/2
    GigabitEthernet0/1/5
  Routing Information Sources:
    Gateway         Distance      Last Update
    192.0.2.2             110      00:18:59
    192.0.2.3             110      3y26w
    192.0.2.4             110      6y49w
    192.0.2.5             110      1w6d
  Distance: (default is 110)

Routing Protocol is "bgp 65000"
  Outgoing update filter list for all interfaces is not set
  Incoming update filter list for all interfaces is not set
  IGP synchronization is disabled
  Automatic route summarization is disabled
  Redistributing: static, ospf 100 (internal)

  Neighbor(s):
    Address          FiltIn FiltOut DistIn DistOut Weight RouteMap
    192.0.2.11                    2                       MAP_IN
    192.0.2.12                    2                   200 MAP_IN
    192.0.2.13                    3                   300 MAP_IN
    192.0.2.14                   10                       MAP_IN
    192.0.2.15                                            MAP_IN
  Maximum path: 1
  Routing Information Sources:
    Gateway         Distance      Last Update
    192.0.2.14           20      2w2d
    192.0.2.11            20      8y28w
  Distance: external 20 internal 200 local 200
"""
NO_PROTOCOL = "*** IP Routing is NSF aware ***\n"


def lines(text: str) -> list[str]:
    return text.rstrip("\n").split("\n")


def capture(*blocks: tuple[str, str]) -> str:
    return "".join(f"EDGE-A#{command}\n{body.rstrip(chr(10))}\n\n" for command, body in blocks)


def test_ospf_record_keeps_role_areas_networks_passive_and_redistribution():
    ospf, bgp = rp.parse_ip_protocols(lines(PROTOCOLS))
    assert (ospf["kind"], ospf["id"], ospf["router_id"], ospf["asbr"], ospf["max_paths"]) == ("ospf", "100", "192.0.2.1", True, 4)
    assert ospf["areas"] == "1 (1 normal, 0 stub, 0 nssa)"
    assert [(n["network"], n["wildcard"], n["area"]) for n in ospf["networks"]] == [("198.51.100.0", "0.0.0.255", "0.0.0.0"), ("203.0.113.0", "0.0.0.255", "0.0.0.0")]
    assert ospf["passive"] == ["GigabitEthernet0/1/2", "GigabitEthernet0/1/5"]
    assert ospf["redistribute"] == [{"source": "bgp 65000", "detail": "metric mapped to 10, includes subnets"}]
    assert ospf["distance"] == "(default is 110)" and ospf["outgoing_filter"] == "not set"
    assert bgp["redistribute"] == [{"source": "static", "detail": ""}, {"source": "ospf 100", "detail": "internal"}]
    assert bgp["notes"] == ["IGP synchronization is disabled", "Automatic route summarization is disabled"]


def test_information_source_ages_are_kept_as_printed_and_never_judged():
    ospf, bgp = rp.parse_ip_protocols(lines(PROTOCOLS))
    assert [(s["gateway"], s["distance"], s["last_update"]) for s in ospf["sources"]] == [("192.0.2.2", 110, "00:18:59"), ("192.0.2.3", 110, "3y26w"), ("192.0.2.4", 110, "6y49w"), ("192.0.2.5", 110, "1w6d")]
    assert all(set(s) == {"gateway", "distance", "last_update"} for s in ospf["sources"] + bgp["sources"])


def test_bgp_neighbor_values_are_assigned_by_the_column_they_are_printed_under():
    bgp = rp.parse_ip_protocols(lines(PROTOCOLS))[1]
    got = [(n["address"], n["filter_in"], n["filter_out"], n["distance_in"], n["distance_out"], n["weight"], n["route_map"]) for n in bgp["neighbors"]]
    assert got == [("192.0.2.11", "", "2", "", "", "", "MAP_IN"), ("192.0.2.12", "", "2", "", "", "200", "MAP_IN"), ("192.0.2.13", "", "3", "", "", "300", "MAP_IN"),
                   ("192.0.2.14", "", "10", "", "", "", "MAP_IN"), ("192.0.2.15", "", "", "", "", "", "MAP_IN")]


def test_a_router_without_a_routing_protocol_answers_with_one_line():
    assert rp.parse_ip_protocols(lines(NO_PROTOCOL)) == []
    rows = {row["command"]: row for row in ctxmod.gather(capture(("show clock", "20:21:00.123 WIB Mon Oct 12 2026"), ("show ip protocols", NO_PROTOCOL)), "x.txt").coverage}
    assert rows["show ip protocols"]["status"] == "analysed" and "no routing protocol is running" in rows["show ip protocols"]["note"]


def test_unknown_text_in_the_block_is_not_called_an_empty_answer():
    odd = NO_PROTOCOL + "% Some new IOS message\n"
    rows = {row["command"]: row for row in ctxmod.gather(capture(("show clock", "20:21:00.123 WIB Mon Oct 12 2026"), ("show ip protocols", odd)), "x.txt").coverage}
    assert rows["show ip protocols"]["status"] == "not parsed"


def section(result: dict, section_id: str) -> dict:
    return next((s for s in result["sections"] if s["id"] == section_id), {})


def test_tables_show_the_live_protocols_and_their_sources_without_a_stale_verdict():
    result = analyze(capture(("show clock", "20:21:00.123 WIB Mon Oct 12 2026"), ("show ip protocols", PROTOCOLS)), filename="proto.txt")
    live = section(result, "ip_protocols")
    assert live["group"] == "Routing" and [row["protocol"] for row in live["rows"]] == ["OSPF", "BGP"]
    ospf = live["rows"][0]
    assert ospf["role"].startswith("ASBR") and ospf["redistribute"] == ["bgp 65000 (metric mapped to 10, includes subnets)"] and ospf["networks"] == 2 and ospf["sources"] == 4
    sources = section(result, "ip_protocol_sources")
    assert sources["total"] == 6 and {row["protocol"] for row in sources["rows"]} == {"ospf 100", "bgp 65000"}
    assert not any(f["id"].startswith("RTR-PRO") for f in result["findings"]), "a large 'last update' is normal on a stable network"
    # no running-config in this capture: the per-neighbor policy of 'show ip protocols' is the only source of it
    policy = section(result, "ip_protocol_bgp_policy")
    assert policy["group"] == "BGP" and [(r["address"], r["weight"]) for r in policy["rows"]][:3] == [("192.0.2.11", ""), ("192.0.2.12", "200"), ("192.0.2.13", "300")]


def test_empty_protocol_answer_adds_no_table():
    result = analyze(capture(("show clock", "20:21:00.123 WIB Mon Oct 12 2026"), ("show ip protocols", NO_PROTOCOL)), filename="none.txt")
    assert not section(result, "ip_protocols") and not section(result, "ip_protocol_sources")
