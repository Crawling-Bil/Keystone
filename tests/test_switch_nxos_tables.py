"""Switch Analyzer: the three NX-OS layouts that used to be "not parsed" -- ``show ip route`` (features/switch_analyzer/
nxos_routes.py), ``show ip arp summary`` and ``show interface trunk`` (features/switch_analyzer/show_tables.py).

* ``cisco_nxos_9k_routes_arp_masked.txt`` is a masked copy of real output from a Nexus 9000 pair (host name replaced,
  10.85.x.x addresses re-numbered to 10.99.x.x; the layout is untouched).
* ``synthetic_nxos_trunk_and_vrf_routes.txt`` is NOT a real capture. It follows the documented layouts: the route lines are
  the ones Cisco prints in "Configure Route Redistribution on Nexus Switches" and the trunk tables are the five sections
  Cisco Community posts show from Nexus 5000/9000 (status, allowed, err-disabled, STP forwarding, FabricPath).
"""
from __future__ import annotations

import unittest
from pathlib import Path

from features.switch_analyzer import capture_text, l3, nxos_routes, service, show_tables

FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def clean(name: str) -> list[str]:
    return capture_text.clean_lines(fixture(name))


REAL = "cisco_nxos_9k_routes_arp_masked.txt"
SYNTHETIC = "synthetic_nxos_trunk_and_vrf_routes.txt"


class NxosRouteTests(unittest.TestCase):
    def test_real_capture_gives_one_row_per_next_hop(self):
        rows = nxos_routes.parse_ip_routes(clean(REAL))
        self.assertEqual(len(rows), 19)
        default = rows[0]
        self.assertEqual((default["destination"], default["next_hop"], default["protocol"], default["vrf"]), ("0.0.0.0/0", "10.99.3.26", "static", "default"))
        self.assertEqual((default["distance"], default["metric"], default["age"]), ("1", "0", "1y6w"))
        svi = next(row for row in rows if row["destination"] == "10.99.3.24/29")
        self.assertEqual((svi["protocol"], svi["interface"], svi["next_hop"], svi["attached"]), ("direct", "Vlan205", "10.99.3.29", True))
        self.assertEqual(sorted({row["protocol"] for row in rows}), ["direct", "hsrp", "local", "static"])

    def test_equal_cost_paths_tags_leaks_and_interface_only_routes(self):
        rows = nxos_routes.parse_ip_routes(clean(SYNTHETIC))
        ecmp = [row for row in rows if row["destination"] == "172.16.0.0/16"]
        self.assertEqual([(r["next_hop"], r["interface"]) for r in ecmp], [("10.12.1.2", "Eth1/36"), ("10.12.1.6", "Eth1/37")])
        self.assertEqual({(r["distance"], r["metric"], r["protocol"], r["detail"]) for r in ecmp}, {("110", "41", "ospf-21", "intra")})
        redistributed = next(row for row in rows if row["destination"] == "172.17.0.0/16")
        self.assertEqual(redistributed["detail"], "type-2, tag 6500")     # the line Cisco documents
        bgp = next(row for row in rows if row["destination"] == "192.168.50.0/24")
        self.assertEqual((bgp["next_hop"], bgp["interface"], bgp["protocol"], bgp["detail"]), ("10.1.1.9", "", "bgp-65000", "internal, tag 65000"))
        null = next(row for row in rows if row["destination"] == "198.51.100.0/24")
        self.assertEqual((null["next_hop"], null["interface"], null["distance"]), ("", "Null0", "220"))
        leaked = next(row for row in rows if row["vrf"] == "TENANT-A")
        self.assertEqual(leaked["next_hop"], "10.1.1.9")                   # "%default" names the VRF the next hop lives in

    def test_vrf_all_gives_every_table_with_default_first(self):
        rows = nxos_routes.parse_ip_routes(clean(SYNTHETIC))
        order = []
        for row in rows:
            if row["vrf"] not in order:
                order.append(row["vrf"])
        self.assertEqual(order, ["default", "TENANT-A", "management"])

    def test_the_fullest_run_of_a_repeated_command_wins(self):
        text = clean(REAL)
        half = text[:text.index("IP Route Table for VRF \"default\"") + 14]
        doubled = half + ["LAB-NX9K-A# sh ip route "] + text
        self.assertEqual(len(nxos_routes.parse_ip_routes(doubled)), 19)

    def test_the_table_is_found_when_the_command_echo_was_lost(self):
        body = clean(REAL)
        start = body.index("IP Route Table for VRF \"default\"")
        end = next(i for i, line in enumerate(body) if "sh ip arp summary" in line)
        self.assertEqual(len(nxos_routes.parse_ip_routes(body[start:end])), 19)

    def test_an_error_reply_gives_no_rows(self):
        self.assertEqual(nxos_routes.parse_ip_routes(["SW# show ip route", "% Invalid command at '^' marker."]), [])

    def test_ios_output_is_left_to_the_ios_reader(self):
        ios = ["SW#show ip route", "Codes: C - connected, S - static", "Gateway of last resort is 10.0.0.1 to network 0.0.0.0", "",
               "S*    0.0.0.0/0 [1/0] via 10.0.0.1", "      10.0.0.0/24 is subnetted, 1 subnets", "C        10.0.0.0 is directly connected, Vlan1"]
        self.assertEqual(nxos_routes.parse_ip_routes(ios), [])

    def test_command_abbreviations(self):
        for command in ("show ip route", "sh ip route", "sh ip ro", "show ip route vrf all", "sh ip route vrf TENANT-A", "show ip route unicast"):
            lines = [f"SW# {command}", 'IP Route Table for VRF "default"', "10.0.0.0/24, ubest/mbest: 1/0, attached", "    *via 10.0.0.1, Vlan1, [0/0], 1d, direct"]
            self.assertEqual(len(nxos_routes.parse_ip_routes(lines)), 1, command)


class ProtocolGroupTests(unittest.TestCase):
    def test_nxos_process_names_map_to_the_protocol(self):
        for label, group in (("ospf-1", "OSPF"), ("ospf-21", "OSPF"), ("eigrp-100", "EIGRP"), ("bgp-65000", "BGP"), ("isis-core", "IS-IS"), ("rip-1", "RIP"),
                             ("static", "Static"), ("direct", "Connected"), ("local", "Local"), ("hsrp", "FHRP"), ("vrrp", "FHRP"),
                             ("O E2", "OSPF"), ("S*", "Static"), ("is-is", "IS-IS"), ("am", "Other"), ("", "")):
            self.assertEqual(l3.protocol_group(label), group, label)


class NxosArpSummaryTests(unittest.TestCase):
    def test_real_adjacency_summary(self):
        summary = show_tables.build_arp_summary(clean(REAL))
        self.assertEqual((summary["total"], summary["incomplete"], summary["resolved"], summary["unknown"], summary["throttled"]), (180, 25, 155, 0, 0))
        self.assertEqual(summary["source"], "show ip arp summary")

    def test_ios_summary_still_reads(self):
        lines = ["SW#show ip arp summary", "58 IP ARP entries, with 3 of them incomplete"]
        self.assertEqual(show_tables.build_arp_summary(lines), {"total": 58, "incomplete": 3, "source": "show ip arp summary"})

    def test_a_summary_without_a_total_is_not_a_result(self):
        self.assertEqual(show_tables.parse_arp_summary_nxos(["IP ARP Table - Adjacency Summary", "  Resolved   : 4"]), {})


class NxosTrunkTests(unittest.TestCase):
    def setUp(self):
        self.trunks = show_tables.build_trunks(clean(SYNTHETIC))
        self.rows = {row["port"]: row for row in self.trunks["rows"]}

    def test_every_port_of_the_status_table_is_a_row(self):
        self.assertTrue(self.trunks["captured"])
        self.assertEqual(list(self.rows), ["Eth1/1", "Eth1/2", "Eth1/3", "Eth1/10", "Eth1/11", "Po10"])

    def test_status_native_vlan_and_port_channel(self):
        self.assertEqual((self.rows["Eth1/2"]["status"], self.rows["Eth1/2"]["port_channel"], self.rows["Eth1/2"]["native_vlan"]), ("trnk-bndl", "Po10", "1"))
        self.assertEqual((self.rows["Eth1/10"]["native_vlan"], self.rows["Eth1/10"]["port_channel"]), ("99", ""))
        self.assertEqual(self.rows["Eth1/11"]["status"], "not-trunking")

    def test_allowed_wrapped_over_two_lines_and_stp_forwarding(self):
        self.assertEqual(self.rows["Eth1/2"]["allowed"], "10,20,30-34,100,200,300,400,500,600,700,800,900,1000,1100,1200,1300,1400,1500,1600")
        self.assertEqual(self.rows["Eth1/2"]["allowed_count"], 23)
        self.assertEqual(self.rows["Eth1/1"]["forwarding"], "1,10,20,30-34")
        self.assertTrue(self.rows["Eth1/1"]["allowed_all"])
        self.assertEqual(self.rows["Eth1/3"]["forwarding"], "none")

    def test_the_dashed_rule_after_the_last_row_is_not_part_of_a_vlan_list(self):
        last = self.rows["Po10"]
        for key in ("allowed", "forwarding", "errdisabled"):
            self.assertNotIn("-----", last[key], key)
        self.assertEqual(last["allowed"], "10,20,30-34")

    def test_the_fabricpath_section_is_not_mistaken_for_a_vlan_list(self):
        self.assertEqual(self.rows["Eth1/1"]["pruned"], "")
        self.assertEqual(self.rows["Eth1/1"]["errdisabled"], "none")

    def test_ios_layout_is_unchanged_and_has_no_port_channel(self):
        ios = ["SW#show interfaces trunk", "Port        Mode             Encapsulation  Status        Native vlan", "Gi1/0/1     on               802.1q         trunking      1", "",
               "Port        Vlans allowed on trunk", "Gi1/0/1     1-4094", "", "Port        Vlans allowed and active in management domain", "Gi1/0/1     1,10,20"]
        row = show_tables.build_trunks(ios)["rows"][0]
        self.assertEqual((row["mode"], row["encapsulation"], row["status"], row["port_channel"], row["active"]), ("on", "802.1q", "trunking", "", "1,10,20"))


class NxosServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = service.analyze(fixture(REAL), filename="nxos.txt")
        cls.synthetic = service.analyze(fixture(SYNTHETIC), filename="synthetic.txt")

    def test_vendor_is_recognised_without_the_vendor_box(self):
        # no show version in the excerpt: the NX-OS route / ARP layouts are the evidence
        self.assertEqual(self.result["detection"]["vendor_used"], "Cisco")

    def test_routing_table_reaches_the_result_with_groups_and_gateway(self):
        self.assertEqual(len(self.result["routing_table"]), 19)
        table = self.result["l3"]["routing_table"]
        self.assertEqual(table["by_protocol"], {"Static": 1, "Connected": 6, "FHRP": 6, "Local": 6})
        self.assertEqual(table["gateway_of_last_resort"], "10.99.3.26")
        self.assertEqual({row["group"] for row in self.result["routing_table"]}, {"Static", "Connected", "FHRP", "Local"})

    def test_arp_summary_count_is_attached_to_the_arp_check(self):
        self.assertEqual(self.result["table_checks"]["arp"]["device"]["total"], 180)

    def test_coverage_lists_the_route_and_arp_summary_commands_as_analyzed(self):
        status = {row["command"]: row["status"] for row in self.result["coverage"]["rows"]}
        self.assertEqual(status["sh ip route"], "analyzed")
        self.assertEqual(status["sh ip arp summary"], "analyzed")

    def test_trunks_reach_the_result_and_the_trunk_tab(self):
        self.assertEqual(len(self.synthetic["trunks"]["rows"]), 6)
        tabs = {tab["key"]: tab for tab in self.synthetic["tabs"]}
        self.assertTrue(tabs["trunks"]["has"])
        self.assertEqual(tabs["trunks"]["count"], 6)

    def test_multi_vrf_routes_carry_their_vrf_to_the_result(self):
        self.assertEqual({row["vrf"] for row in self.synthetic["routing_table"]}, {"default", "management", "TENANT-A"})
        self.assertEqual(self.synthetic["l3"]["routing_table"]["gateway_of_last_resort"], "192.0.2.1")   # the default VRF's own default route

    def test_a_table_whose_command_echo_was_lost_is_analyzed_not_missing(self):
        body = fixture(REAL)
        lost = body.replace("LAB-NX9K-A# sh ip route \n", "")
        result = service.analyze(lost, filename="lost.txt", vendor="Cisco")
        row = next(r for r in result["coverage"]["rows"] if r["command"] == "show ip route")
        self.assertEqual(row["status"], "analyzed")
        self.assertIn("read by its header", row["note"])
        self.assertEqual(len(result["routing_table"]), 19)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
