"""Layer-3 view of a switch capture (features/switch_analyzer/l3.py) and its
Compare section: gateways, default / static routes, OSPF, ACLs.

Checked against masked excerpts of the real Oct 2026 TAM captures (see
tests/fixtures/real_captures/README.md) and against small inline configs for
the forms the corpus does not contain. The raw captures gave these facts, each
pinned below
  L1  A `router ospf 100` with only `log-adjacency-changes` (no `network`, no
      `ip ospf` on an interface) runs OSPF nowhere: it forms no neighbour and
      advertises nothing (NVDC 3560G, whose face readers were unreachable).
  L2  Five Cisco captures enable OSPF only on the interface (`ip ospf 100 area
      0`) and have no `network` line at all: they must NOT be reported as an
      empty OSPF process.
  L3  `network <addr> <wildcard> area <a>` enables OSPF on the interfaces whose
      address falls inside the range, and `passive-interface default` +
      `no passive-interface X` leaves only X forming neighbours.
  L4  A Huawei capture echoes `ip route-static ...` three times (config, then
      the `| include` runs): that is one route, not three.
  L5  Huawei `dhcp snooping enable` typed inside a `vlan N` view is the
      per-VLAN form; the VLAN list used to come back empty.
  L6  A Layer-2 Catalyst has no routes: `ip default-gateway` is its default
      route. Huawei always routes: the same gateway is `ip route-static`.
  L7  Cisco `ip access-group NAME in` on Vlan214 becomes Huawei
      `acl name NAME advance` + `traffic classifier` + `traffic policy` +
      `traffic-policy NAME inbound` on Vlanif214; both must show the ACL as
      applied to the same VLAN interface.
  L8  Nexus keeps its default route inside `vrf context management`.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from features.switch_analyzer import capture_text, l3
from features.switch_analyzer.compare import _compress, _vlan_numbers, compare, l3_compare
from features.switch_analyzer.service import analyze

FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def build(text: str, vendor: str = "cisco", **kwargs):
    return l3.build_l3(capture_text.clean_lines(text), vendor, **kwargs)


def codes(findings) -> list[str]:
    return [item["code"] for item in findings]


def by_name(rows, name):
    return next(row for row in rows if row["name"] == name)


class GatewayTests(unittest.TestCase):
    def test_every_svi_with_an_address_is_listed_and_unnumbered_ones_are_not(self):
        view = build(fixture("cisco_3560g_l3_ospf_process_without_networks.txt"))
        self.assertEqual(
            [(row["name"], row["address"], row["kind"]) for row in view["interfaces"]],
            [("Vlan53", "10.255.0.1/30", "SVI"), ("Vlan700", "10.255.0.2/27", "SVI"), ("Vlan701", "10.255.0.3/24", "SVI")],
        )
        self.assertEqual(by_name(view["interfaces"], "Vlan700")["network"], "10.255.0.0/27")

    def test_huawei_vlanif_that_asks_for_dhcp_is_listed_as_dhcp(self):
        view = build(fixture("huawei_s5755_l3_vlan_snooping_and_repeated_static_route.txt"), "huawei")
        vlanif1 = by_name(view["interfaces"], "Vlanif1")
        self.assertEqual(vlanif1["address"], "DHCP")
        self.assertEqual(vlanif1["ip"], "")
        self.assertEqual(by_name(view["interfaces"], "Vlanif700")["address"], "10.255.0.2/27")

    def test_aruba_vlan_block_address(self):
        view = build(fixture("aruba_2540_l3_vlan_ip_and_default_gateway.txt"), "aruba")
        self.assertEqual([(row["name"], row["address"]) for row in view["interfaces"]], [("Vlan213", "10.255.0.2/24")])

    def test_interface_names_match_across_vendors(self):
        self.assertEqual(l3.ifkey("Vlanif53"), l3.ifkey("Vlan53"))
        self.assertEqual(l3.ifkey("Eth-Trunk1"), l3.ifkey("Port-channel1"))
        self.assertEqual(l3.ifkey("Loopback0"), l3.ifkey("loopback0"))
        self.assertEqual(l3.ifkey("GigabitEthernet0/1"), l3.ifkey("Gi0/1"))
        self.assertNotEqual(l3.ifkey("Vlan5"), l3.ifkey("Vlan53"))

    def test_secondary_address_helper_and_vrf(self):
        text = (
            "hostname X\n!\n"
            "interface Vlan10\n ip vrf forwarding GUEST\n ip address 10.1.1.1 255.255.255.0\n"
            " ip address 10.1.2.1 255.255.255.0 secondary\n ip helper-address 10.9.9.9\n ip helper-address 10.9.9.8\n"
            " ip access-group EDGE in\n!\n"
        )
        row = build(text)["interfaces"][0]
        self.assertEqual(row["address"], "10.1.1.1/24")
        self.assertEqual(row["secondary"], ["10.1.2.1/24"])
        self.assertEqual(row["helpers"], ["10.9.9.9", "10.9.9.8"])
        self.assertEqual(row["vrf"], "GUEST")
        self.assertEqual(row["acl_in"], "EDGE")

    def test_huawei_sub_address_and_relay(self):
        text = (
            "sysname X\n#\ninterface Vlanif20\n ip address 10.2.0.1 255.255.255.0\n ip address 10.2.1.1 255.255.255.0 sub\n"
            " dhcp select relay\n dhcp relay server-ip 10.9.9.9\n#\n"
        )
        row = build(text, "huawei")["interfaces"][0]
        self.assertEqual(row["secondary"], ["10.2.1.1/24"])
        self.assertEqual(row["helpers"], ["10.9.9.9"])

    def test_nexus_slash_notation_and_management_vrf(self):
        text = "feature ospf\n!\ninterface mgmt0\n  vrf member management\n  ip address 10.5.5.5/24\n!\ninterface Vlan9\n  ip address 10.6.6.1/23\n!\n"
        view = build(text)
        self.assertEqual(by_name(view["interfaces"], "mgmt0")["kind"], "Management")
        self.assertEqual(by_name(view["interfaces"], "mgmt0")["vrf"], "management")
        self.assertEqual(by_name(view["interfaces"], "Vlan9")["address"], "10.6.6.1/23")


class StaticRouteTests(unittest.TestCase):
    def test_route_echoed_three_times_is_one_route(self):
        view = build(fixture("huawei_s5755_l3_vlan_snooping_and_repeated_static_route.txt"), "huawei")
        self.assertEqual(len(view["static_routes"]), 1)
        self.assertEqual(view["static_routes"][0]["cidr"], "0.0.0.0/0")
        self.assertEqual(view["static_routes"][0]["next_hop"], "10.255.0.4")
        self.assertEqual(view["static_routes"][0]["via"], "ip route-static")

    def test_service_counts_the_route_once(self):
        result = analyze(fixture("huawei_s5755_l3_vlan_snooping_and_repeated_static_route.txt"), vendor="Huawei")
        self.assertEqual(result["cards"]["total_routes"], 1)
        self.assertEqual(len(result["routes"]), 1)
        self.assertEqual(result["routes"][0]["mask"], "0.0.0.0")

    def test_distance_and_name_on_cisco_and_preference_and_description_on_huawei(self):
        cisco = build(fixture("cisco_3650_l3_acl_applied_on_svi_and_static_routes.txt"))
        self.assertEqual(
            [(row["next_hop"], row["distance"], row["description"]) for row in cisco["static_routes"]],
            [("10.255.0.5", 5, "SANGFOR-NSF"), ("10.255.0.6", 10, "TO-BCQ-ROU-BACKUP")],
        )
        huawei = build(fixture("huawei_s5755_l3_traffic_policy_acl_and_vpn_instance_route.txt"), "huawei")
        self.assertEqual(
            [(row["next_hop"], row["distance"], row["description"]) for row in huawei["static_routes"]],
            [("10.255.0.30", 5, "SANGFOR-NSF"), ("10.255.0.31", 10, "TO-BCQ-ROU-BACKUP")],
        )
        self.assertEqual(len(huawei["default_routes"]), 2)

    def test_layer2_switch_default_gateway_is_its_default_route(self):
        view = build(fixture("cisco_2960_l3_default_gateway_only.txt"))
        self.assertEqual(view["static_routes"], [])
        self.assertEqual([(row["next_hop"], row["via"]) for row in view["default_routes"]], [("10.255.0.2", "ip default-gateway")])

    def test_aruba_default_gateway(self):
        view = build(fixture("aruba_2540_l3_vlan_ip_and_default_gateway.txt"), "aruba")
        self.assertEqual([(row["next_hop"], row["via"]) for row in view["default_routes"]], [("10.255.0.1", "ip default-gateway")])

    def test_nexus_route_inside_vrf_context(self):
        view = build(fixture("nxos_9000_l3_vrf_context_static_routes.txt"))
        self.assertEqual(
            [(row["vrf"], row["cidr"], row["next_hop"]) for row in view["static_routes"]],
            [("management", "0.0.0.0/0", "10.255.0.1")],
        )

    def test_forms_not_in_the_corpus(self):
        text = (
            "ip route vrf RED 10.0.0.0 255.0.0.0 10.1.1.1\n"
            "ip route 192.168.0.0 255.255.0.0 Null0 250\n"
            "ip route 172.16.0.0 255.240.0.0 GigabitEthernet0/1 10.2.2.2 name LAB tag 7 track 5\n"
        )
        rows = {row["cidr"]: row for row in build(text)["static_routes"]}
        self.assertEqual(rows["10.0.0.0/8"]["vrf"], "RED")
        self.assertTrue(rows["192.168.0.0/16"]["discard"])
        self.assertEqual(rows["192.168.0.0/16"]["distance"], 250)
        lab = rows["172.16.0.0/12"]
        self.assertEqual((lab["next_hop"], lab["interface"], lab["description"], lab["tag"], lab["track"]), ("10.2.2.2", "GigabitEthernet0/1", "LAB", "7", "5"))
        huawei = (
            "ip route-static vpn-instance management 0.0.0.0 0.0.0.0 10.85.250.1 description MGMT\n"
            "ip route-static 10.0.0.0 255.0.0.0 NULL0\n"
            "ip route-static 10.20.0.0 24 10.1.1.9 preference 70 track 3\n"
        )
        hrows = {row["cidr"]: row for row in build(huawei, "huawei")["static_routes"]}
        self.assertEqual((hrows["0.0.0.0/0"]["vrf"], hrows["0.0.0.0/0"]["description"]), ("management", "MGMT"))
        self.assertTrue(hrows["10.0.0.0/8"]["discard"])
        self.assertEqual((hrows["10.20.0.0/24"]["distance"], hrows["10.20.0.0/24"]["track"]), (70, "3"))

    def test_routing_table_summary_and_gateway_of_last_resort(self):
        table = [{"protocol": "C"}, {"protocol": "C"}, {"protocol": "O"}, {"protocol": "S*"}, {"protocol": "O IA"}]
        text = "Gateway of last resort is 10.1.1.1 to network 0.0.0.0\n"
        summary = build(text, routing_table=table)["routing_table"]
        self.assertEqual(summary["by_protocol"], {"Connected": 2, "OSPF": 2, "Static": 1})
        self.assertEqual(summary["gateway_of_last_resort"], "10.1.1.1")


class OspfTests(unittest.TestCase):
    def test_process_without_network_or_interface_command_runs_nowhere(self):  # L1
        view = build(fixture("cisco_3560g_l3_ospf_process_without_networks.txt"))
        self.assertTrue(view["ospf"]["configured"])
        self.assertEqual(view["ospf"]["interfaces"], [])
        self.assertEqual(codes(view["ospf"]["findings"]), ["ospf_no_interfaces"])
        self.assertIn("ospf_no_interfaces", codes(view["findings"]))

    def test_interface_level_ospf_is_not_an_empty_process(self):  # L2
        view = build(fixture("cisco_3650_l3_interface_level_ospf_and_acls.txt"))
        ospf = view["ospf"]
        self.assertEqual(ospf["processes"][0]["networks"], [])
        self.assertEqual(len(ospf["interfaces"]), 8)
        self.assertEqual({row["how"] for row in ospf["interfaces"]}, {"interface command"})
        self.assertEqual({row["area"] for row in ospf["interfaces"]}, {"0"})
        self.assertEqual(ospf["findings"], [])
        self.assertNotIn("ospf_no_interfaces", codes(view["findings"]))

    def test_passive_default_leaves_only_the_active_interface(self):  # L2 / L3
        view = build(fixture("cisco_3650_l3_interface_level_ospf_and_acls.txt"))
        passive = {row["interface"]: row["passive"] for row in view["ospf"]["interfaces"]}
        self.assertFalse(passive["Vlan50"])
        self.assertTrue(all(value for name, value in passive.items() if name != "Vlan50"))
        row = by_row(view["ospf"]["interfaces"], "Vlan50")
        self.assertEqual(row["network_type"], "point-to-point")

    def test_network_statement_matches_interface_addresses(self):  # L3
        view = build(fixture("cisco_3560_l3_ospf_network_statements.txt"))
        names = {row["interface"]: row for row in view["ospf"]["interfaces"]}
        self.assertEqual(set(names), {"GigabitEthernet0/1", "Vlan701"})
        self.assertEqual({row["area"] for row in names.values()}, {"0.0.0.40"})
        self.assertFalse(names["GigabitEthernet0/1"]["passive"])
        self.assertTrue(names["Vlan701"]["passive"])
        self.assertEqual(view["ospf"]["findings"], [])
        process = view["ospf"]["processes"][0]
        self.assertEqual(process["router_id"], "10.255.1.2")
        self.assertEqual([net["cidr"] for net in process["networks"]], ["10.255.1.0/30", "10.255.3.0/24"])
        self.assertEqual(process["networks"][1]["matched_interfaces"], ["Vlan701"])

    def test_most_specific_network_statement_wins(self):
        text = (
            "interface Vlan10\n ip address 10.1.1.5 255.255.255.0\n!\n"
            "router ospf 1\n network 10.0.0.0 0.255.255.255 area 0\n network 10.1.1.0 0.0.0.255 area 7\n!\n"
        )
        self.assertEqual(build(text)["ospf"]["interfaces"][0]["area"], "7")

    def test_network_statements_that_match_no_interface(self):
        text = "interface Vlan10\n ip address 10.1.1.5 255.255.255.0\n!\nrouter ospf 1\n network 172.16.0.0 0.0.255.255 area 0\n!\n"
        self.assertEqual(codes(build(text)["ospf"]["findings"]), ["ospf_network_matches_nothing"])

    def test_every_interface_passive(self):
        text = (
            "interface Vlan10\n ip address 10.1.1.5 255.255.255.0\n ip ospf 1 area 0\n!\n"
            "router ospf 1\n passive-interface default\n!\n"
        )
        self.assertEqual(codes(build(text)["ospf"]["findings"]), ["ospf_all_passive"])

    def test_shutdown_interface_still_listed_but_marked(self):
        text = "interface Vlan10\n ip address 10.1.1.5 255.255.255.0\n ip ospf 1 area 0\n shutdown\n!\nrouter ospf 1\n!\n"
        row = build(text)["ospf"]["interfaces"][0]
        self.assertTrue(row["shutdown"])

    def test_huawei_process_area_network_silent_interface_and_interface_command(self):
        text = (
            "sysname X\n#\n"
            "interface Vlanif10\n ip address 10.1.1.1 255.255.255.0\n#\n"
            "interface Vlanif20\n ip address 10.2.2.1 255.255.255.0\n ospf enable 1 area 0.0.0.5\n ospf network-type p2p\n#\n"
            "ospf 1 router-id 10.9.9.9\n silent-interface all\n undo silent-interface Vlanif20\n import-route static\n area 0.0.0.0\n  network 10.1.1.0 0.0.0.255\n#\n"
        )
        view = build(text, "huawei")
        interfaces = {row["interface"]: row for row in view["ospf"]["interfaces"]}
        self.assertEqual(interfaces["Vlanif10"]["area"], "0.0.0.0")
        self.assertTrue(interfaces["Vlanif10"]["passive"])
        self.assertEqual(interfaces["Vlanif20"]["area"], "0.0.0.5")
        self.assertFalse(interfaces["Vlanif20"]["passive"])
        self.assertEqual(interfaces["Vlanif20"]["network_type"], "p2p")
        process = view["ospf"]["processes"][0]
        self.assertEqual((process["id"], process["router_id"], process["redistribute"]), ("1", "10.9.9.9", ["static"]))

    def test_same_process_printed_twice_is_one_process(self):
        text = "router ospf 100\n log-adjacency-changes\n!\nrouter ospf 100\n router-id 1.1.1.1\n!\n"
        processes = build(text)["ospf"]["processes"]
        self.assertEqual(len(processes), 1)
        self.assertEqual(processes[0]["router_id"], "1.1.1.1")

    def test_other_protocols_are_named(self):
        view = build(fixture("cisco_3650_l3_interface_level_ospf_and_acls.txt"))
        self.assertEqual([item["protocol"] for item in view["other_protocols"]], ["EIGRP"])

    def test_no_ospf_means_nothing_to_report(self):
        view = build(fixture("cisco_2960_l3_default_gateway_only.txt"))
        self.assertFalse(view["ospf"]["configured"])
        self.assertEqual(view["findings"], [])


def by_row(rows, interface):
    return next(row for row in rows if row["interface"] == interface)


class AclTests(unittest.TestCase):
    def test_cisco_acl_applied_to_the_svi(self):  # L7
        view = build(fixture("cisco_3650_l3_acl_applied_on_svi_and_static_routes.txt"))
        acl = by_name(view["acls"]["definitions"], "VOIP-GA-BCQ")
        self.assertEqual((acl["rules"], acl["applied"], acl["kind"]), (24, True, "extended"))
        self.assertEqual(
            view["acls"]["bindings"],
            [{"target": "Vlan214", "kind": "interface", "acl": "VOIP-GA-BCQ", "direction": "in", "via": "ip access-group", "defined": True}],
        )

    def test_huawei_acl_reaches_the_vlanif_through_classifier_and_policy(self):  # L7
        view = build(fixture("huawei_s5755_l3_traffic_policy_acl_and_vpn_instance_route.txt"), "huawei")
        acl = by_name(view["acls"]["definitions"], "VOIP-GA-BCQ")
        self.assertEqual((acl["rules"], acl["applied"], acl["kind"]), (24, True, "advance"))
        binding = view["acls"]["bindings"][0]
        self.assertEqual((binding["target"], binding["acl"], binding["direction"]), ("Vlanif214", "VOIP-GA-BCQ", "in"))
        self.assertTrue(binding["via"].startswith("traffic-policy"))
        # the same ACL, the same VLAN: Compare sees no difference
        cisco = build(fixture("cisco_3650_l3_acl_applied_on_svi_and_static_routes.txt"))
        rows = l3_compare({"l3": cisco}, {"l3": view})["acls"]
        self.assertEqual([(row["name"], row["status"]) for row in rows], [("VOIP-GA-BCQ", "same")])

    def test_acl_used_by_a_route_map_is_referenced_not_applied(self):
        view = build(fixture("cisco_3650_l3_interface_level_ospf_and_acls.txt"))
        names = {item["name"]: item for item in view["acls"]["definitions"]}
        self.assertFalse(any(item["applied"] for item in names.values()))
        referenced = [item for item in names.values() if item["referenced_by"]]
        self.assertEqual(len(referenced), 1)
        self.assertTrue(referenced[0]["referenced_by"][0].startswith("route-map"))

    def test_generated_acls_are_flagged_as_system(self):
        text = (
            "ip access-list extended AutoQos-4.0-wlan-Acl-Bulk-Data\n permit tcp any any eq 22\n!\n"
            "ip access-list extended CUSTOMER\n 10 permit ip any any\n 20 deny ip any host 10.1.1.1\n!\n"
        )
        defs = {item["name"]: item for item in build(text)["acls"]["definitions"]}
        self.assertTrue(defs["AutoQos-4.0-wlan-Acl-Bulk-Data"]["system"])
        self.assertFalse(defs["CUSTOMER"]["system"])
        self.assertEqual(defs["CUSTOMER"]["rule_lines"], ["permit ip any any", "deny ip any host 10.1.1.1"])

    def test_numbered_acl_vty_binding_and_undefined_acl(self):
        text = (
            "access-list 10 permit 10.1.1.0 0.0.0.255\naccess-list 10 deny any\n!\n"
            "line vty 0 4\n access-class 10 in\n access-class MISSING in\n!\n"
        )
        view = build(text)["acls"]
        self.assertEqual((view["definitions"][0]["name"], view["definitions"][0]["rules"]), ("10", 2))
        self.assertEqual({(item["acl"], item["defined"]) for item in view["bindings"]}, {("10", True), ("MISSING", False)})

    def test_huawei_numbered_and_named_acls(self):
        text = "acl number 2000\n rule 5 permit source 10.1.1.0 0.0.0.255\n#\nacl name MGMT basic\n rule 5 permit\n rule 10 deny\n#\nuser-interface vty 0 4\n acl 2000 inbound\n#\n"
        view = build(text, "huawei")["acls"]
        self.assertEqual({(item["name"], item["rules"], item["kind"]) for item in view["definitions"]}, {("2000", 1, ""), ("MGMT", 2, "basic")})
        self.assertEqual(view["bindings"][0]["target"], "vty 0 4")

    def test_device_reported_acl_count_and_system_lists(self):
        text = (
            "SW#show access-lists\n"
            "Extended IP access list EDGE\n    10 permit ip any any\n"
            "IP access list copp-system-p-acl-bgp\n    10 permit tcp any gt 1024 any eq bgp\n"
            "SW#show version\nCisco IOS\n"
        )
        view = build(text)["acls"]
        self.assertEqual(view["reported_count"], 2)
        self.assertEqual(view["reported_names"], ["EDGE", "copp-system-p-acl-bgp"])
        self.assertEqual(view["reported_not_in_config"], ["EDGE", "copp-system-p-acl-bgp"])
        huawei = build("<SW>display acl all\nTotal nonempty ACL number is 0\n<SW>display version\n", "huawei")["acls"]
        self.assertEqual(huawei["reported_count"], 0)
        self.assertIsNone(build("hostname X\n")["acls"]["reported_count"])


class FindingsTests(unittest.TestCase):
    def test_ip_routing_off_only_on_an_ios_switch_with_two_active_subnets(self):
        two_svi = "interface Vlan1\n ip address 10.1.1.1 255.255.255.0\n!\ninterface Vlan2\n ip address 10.2.2.1 255.255.255.0\n!\nip default-gateway 10.1.1.254\n"
        self.assertIn("ip_routing_off", codes(build(two_svi)["findings"]))
        self.assertNotIn("ip_routing_off", codes(build("ip routing\n!\n" + two_svi)["findings"]))
        shut = two_svi.replace("interface Vlan2\n", "interface Vlan2\n shutdown\n")
        self.assertNotIn("ip_routing_off", codes(build(shut)["findings"]))
        nexus = "feature interface-vlan\n!\n" + two_svi
        self.assertNotIn("ip_routing_off", codes(build(nexus)["findings"]))
        self.assertNotIn("ip_routing_off", codes(build(fixture("nxos_9000_l3_vrf_context_static_routes.txt"))["findings"]))
        self.assertNotIn("ip_routing_off", codes(build(two_svi, "huawei")["findings"]))

    def test_capture_without_a_config_says_so(self):
        self.assertEqual(codes(build("SW#show version\nCisco IOS Software\n")["findings"]), ["no_l3_found"])


class ServiceTests(unittest.TestCase):
    def test_result_carries_the_l3_view_and_cards(self):
        result = analyze(fixture("cisco_3560g_l3_ospf_process_without_networks.txt"), vendor="Cisco")
        self.assertIn("l3", result)
        cards = result["cards"]
        self.assertEqual(cards["l3_interface_count"], 3)
        self.assertEqual(cards["default_route"], "10.255.0.4")
        self.assertEqual(cards["ospf_status"], "Configured, not running")
        self.assertEqual(cards["acl_count"], 0)
        self.assertEqual(cards["l3_finding_count"], 1)

    def test_ospf_status_card_for_interface_level_ospf(self):
        result = analyze(fixture("cisco_3650_l3_interface_level_ospf_and_acls.txt"), vendor="Cisco")
        self.assertEqual(result["cards"]["ospf_status"], "Running on 8 interfaces")

    def test_live_state_and_virtual_ip_are_copied_onto_the_l3_rows(self):
        text = fixture("cisco_3560g_l3_ospf_process_without_networks.txt") + "\nVlan700    10.255.0.2    YES NVRAM  up    up\n"
        interfaces = [{"name": "Vlan700", "status": "up", "status_detail": "line protocol up", "hsrp_vrrp_ip": "10.255.0.254"}]
        view = build(text, interfaces=interfaces)
        row = by_name(view["interfaces"], "Vlan700")
        self.assertEqual((row["status"], row["virtual_ip"]), ("up", "10.255.0.254"))

    def test_huawei_per_vlan_dhcp_snooping_lists_the_vlans(self):  # L5
        result = analyze(fixture("huawei_s5755_l3_vlan_snooping_and_repeated_static_route.txt"), vendor="Huawei")
        snooping = result["dhcp"]["snooping"]
        self.assertTrue(snooping["enabled"])
        self.assertEqual(snooping["vlans"], ["53", "700", "701"])
        self.assertEqual(snooping["trusted_interfaces"], ["Port-channel1"])


class CompareTests(unittest.TestCase):
    def pair(self, a_text, b_text, a_vendor="cisco", b_vendor="huawei", dhcp_a=None, dhcp_b=None):
        return l3_compare(
            {"l3": build(a_text, a_vendor), "dhcp": dhcp_a or {}},
            {"l3": build(b_text, b_vendor), "dhcp": dhcp_b or {}},
        )

    def test_nvdc_migration_pair(self):
        cmp = self.pair(
            fixture("cisco_3560g_l3_ospf_process_without_networks.txt"),
            fixture("huawei_s5755_l3_vlan_snooping_and_repeated_static_route.txt"),
        )
        rows = {row["label"]: row["status"] for row in cmp["interfaces"]}
        self.assertEqual((rows["Vlan53"], rows["Vlan700"], rows["Vlan701"]), ("same", "same", "same"))
        self.assertEqual(rows["Vlanif1"], "only b")
        self.assertEqual(cmp["default_route"]["status"], "same")
        self.assertEqual(cmp["default_route"]["a"]["via"], "ip route")
        self.assertEqual(cmp["default_route"]["b"]["via"], "ip route-static")
        self.assertEqual(cmp["ospf"]["a"]["state"], "Configured, not running")
        self.assertEqual(cmp["ospf"]["b"]["state"], "Not configured")
        # a DHCP-client Vlanif1 and an OSPF process that carried nothing are not problems
        self.assertEqual(codes(cmp["findings"]), ["ospf_inactive_a"])
        self.assertEqual(cmp["findings"][0]["level"], "info")

    def test_layer2_switch_default_gateway_against_huawei_static_default(self):  # L6
        cmp = self.pair(
            fixture("cisco_2960_l3_default_gateway_only.txt"),
            "sysname X\n#\ninterface Vlanif700\n ip address 10.255.0.1 255.255.255.224\n#\nip route-static 0.0.0.0 0.0.0.0 10.255.0.2\n#\n",
        )
        self.assertEqual(cmp["default_route"]["status"], "same")
        self.assertEqual(cmp["findings"], [])

    def test_changed_missing_moved_and_new_gateways(self):
        a = (
            "interface Vlan10\n ip address 10.1.10.1 255.255.255.0\n ip helper-address 10.9.9.9\n!\n"
            "interface Vlan20\n ip address 10.1.20.1 255.255.255.0\n!\n"
            "interface Vlan30\n ip address 10.1.30.1 255.255.255.0\n!\n"
            "ip route 0.0.0.0 0.0.0.0 10.1.10.254\n"
        )
        b = (
            "sysname X\n#\n"
            "interface Vlanif10\n ip address 10.1.10.2 255.255.255.0\n#\n"
            "interface Vlanif21\n ip address 10.1.20.1 255.255.255.0\n#\n"
            "interface Vlanif40\n ip address 10.1.40.1 255.255.255.0\n#\n"
            "ip route-static 0.0.0.0 0.0.0.0 10.1.10.253\n#\n"
        )
        cmp = self.pair(a, b)
        rows = {row["label"]: row for row in cmp["interfaces"]}
        self.assertEqual(rows["Vlan10"]["status"], "changed")
        self.assertEqual(rows["Vlan20"]["status"], "moved")
        self.assertEqual(rows["Vlan20"]["b"]["name"], "Vlanif21")
        self.assertEqual(rows["Vlan30"]["status"], "only a")
        self.assertEqual(rows["Vlanif40"]["status"], "only b")
        got = codes(cmp["findings"])
        for expected in ("l3_address_changed", "l3_address_moved", "l3_interface_missing_b", "l3_interface_only_b",
                         "dhcp_helper_differs", "default_route_changed"):
            self.assertIn(expected, got)
        self.assertEqual(cmp["findings"][0]["level"], "warning")

    def test_static_routes_are_compared_on_next_hop(self):
        a = "ip route 10.0.0.0 255.0.0.0 10.1.1.1\nip route 172.16.0.0 255.240.0.0 10.1.1.2\nip route 192.168.0.0 255.255.0.0 10.1.1.3\n"
        b = "ip route-static 10.0.0.0 255.0.0.0 10.1.1.1\nip route-static 172.16.0.0 255.240.0.0 10.1.1.99\nip route-static 100.64.0.0 255.192.0.0 10.1.1.4\n"
        rows = {row["cidr"]: row["status"] for row in self.pair(a, b)["static_routes"]}
        self.assertEqual(rows, {"10.0.0.0/8": "same", "172.16.0.0/12": "changed", "192.168.0.0/16": "only a", "100.64.0.0/10": "only b"})

    def test_ospf_running_on_a_but_absent_on_b(self):
        cmp = self.pair(fixture("cisco_3560_l3_ospf_network_statements.txt"), "sysname X\n#\n")
        self.assertIn("ospf_missing_b", codes(cmp["findings"]))
        self.assertEqual(cmp["ospf"]["a"]["state"], "Running")

    def test_ospf_area_difference(self):
        a = "interface Vlan10\n ip address 10.1.1.1 255.255.255.0\n ip ospf 1 area 0\n!\nrouter ospf 1\n!\n"
        b = "sysname X\n#\ninterface Vlanif10\n ip address 10.1.1.1 255.255.255.0\n ospf enable 1 area 0.0.0.5\n#\nospf 1\n#\n"
        self.assertIn("ospf_area_differs", codes(self.pair(a, b)["findings"]))

    def test_acl_only_on_a_is_a_warning_and_a_system_acl_is_not(self):
        a = "ip access-list extended CUSTOMER\n permit ip any any\n!\nip access-list extended AutoQos-4.0-x\n permit ip any any\n!\n"
        cmp = self.pair(a, "sysname X\n#\n")
        self.assertEqual(codes(cmp["findings"]), ["acl_missing_b"])
        self.assertTrue(by_name(cmp["acls"], "AutoQos-4.0-x")["system"])

    def test_inter_vlan_routing_becomes_active_on_huawei(self):
        a = "interface Vlan10\n ip address 10.1.10.1 255.255.255.0\n!\ninterface Vlan20\n ip address 10.1.20.1 255.255.255.0\n!\nip default-gateway 10.1.10.254\n"
        b = (
            "sysname X\n#\ninterface Vlanif10\n ip address 10.1.10.1 255.255.255.0\n#\n"
            "interface Vlanif20\n ip address 10.1.20.1 255.255.255.0\n#\nip route-static 0.0.0.0 0.0.0.0 10.1.10.254\n#\n"
        )
        self.assertIn("inter_vlan_routing_new", codes(self.pair(a, b)["findings"]))

    def test_dhcp_snooping_vlans_are_compared_as_numbers(self):
        snoop_a = {"snooping": {"enabled": True, "vlans": ["53,700-701"]}}
        snoop_b = {"snooping": {"enabled": True, "vlans": ["53", "700", "701"]}}
        cmp = self.pair("hostname A\n", "sysname B\n", dhcp_a=snoop_a, dhcp_b=snoop_b)
        self.assertEqual(cmp["findings"], [])
        self.assertEqual(cmp["dhcp_snooping"]["a_vlans"], "53, 700-701")
        missing = self.pair("hostname A\n", "sysname B\n", dhcp_a=snoop_a, dhcp_b={})
        self.assertIn("dhcp_snooping_missing_b", codes(missing["findings"]))

    def test_vlan_list_forms(self):
        self.assertEqual(_compress(_vlan_numbers(["1 to 3", "10,20", "700-701", "30 31"])), "1-3, 10, 20, 30-31, 700-701")
        self.assertEqual(_vlan_numbers([]), set())

    def test_compare_result_carries_the_l3_section(self):
        a = analyze(fixture("cisco_3560g_l3_ospf_process_without_networks.txt"), vendor="Cisco")
        b = analyze(fixture("huawei_s5755_l3_vlan_snooping_and_repeated_static_route.txt"), vendor="Huawei")
        result = compare(a, b)
        self.assertIn("l3", result)
        self.assertEqual(codes(result["l3"]["findings"]), ["ospf_inactive_a"])
        self.assertEqual(result["l3"]["dhcp_snooping"]["b_vlans"], "53, 700-701")

    def test_result_without_an_l3_key_does_not_break_compare(self):
        cmp = l3_compare({}, {})
        self.assertEqual((cmp["findings"], cmp["interfaces"], cmp["static_routes"]), ([], [], []))
        self.assertEqual(cmp["default_route"]["status"], "none")


if __name__ == "__main__":
    unittest.main()
