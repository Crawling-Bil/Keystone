"""Switch Analyzer: the nine Cisco commands that used to be "not parsed" (features/switch_analyzer/show_tables.py,
stp_detail.py, licence_detail.py) and how they reach the tabs, the findings and the Coverage tab.

The captures are masked copies of real output (``fixtures/real_captures``): host names, MAC addresses, accounts and
serials are replaced, the layout is untouched.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

from features.switch_analyzer import capture_text, licence_detail, live_state, service, show_tables, stp_detail

FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def clean(name: str) -> list[str]:
    return capture_text.clean_lines(fixture(name))


L2 = "cisco_2960_l2_tables_masked.txt"


class CommandPatternTests(unittest.TestCase):
    def matches(self, key: str, command: str) -> bool:
        return any(re.fullmatch(pattern, command) for pattern in show_tables.PATTERNS[key])

    def test_ios_accepts_any_unique_prefix_so_the_patterns_do(self):
        for key, commands in {
            "vlan": ("show vlan", "sh vlan", "show vlan brief", "sh vlan br"),
            "vlan_summary": ("show vlan summary", "sh vlan sum", "show vlan su"),
            "int_desc": ("show interface description", "show interfaces description", "show interface desc", "sh int desc", "sh int des"),
            "trunk": ("show interface trunk", "show interfaces trunk", "sh int tru", "sh int trunk"),
            "arp_summary": ("show ip arp summary", "sh ip arp su", "sh ip arp sum"),
            "stp": ("show spanning-tree", "sh span", "sh spanning-tree", "show spanning-tree vlan 10", "show spanning-tree active"),
            "lic_usage": ("show license usage", "sh lic usage", "sh license us"),
            "lic_all": ("show license all", "sh lic all", "sh license al"),
            "mac_count": ("show mac address-table count", "sh mac add count", "show mac-address-table count", "sh mac address-table cou"),
        }.items():
            for command in commands:
                self.assertTrue(self.matches(key, command), f"{key}: {command}")

    def test_neighbouring_commands_are_not_taken_for_them(self):
        for key, command in (("int_desc", "show interface status"), ("trunk", "show interface transceiver"), ("arp_summary", "show ip arp"),
                             ("stp", "show spanning-tree summary"), ("vlan", "show vlan summary"), ("lic_all", "show license summary"),
                             ("mac_count", "show mac address-table"), ("vlan_summary", "show vlan brief")):
            self.assertFalse(self.matches(key, command), f"{key}: {command}")


class VlanTests(unittest.TestCase):
    def test_show_vlan_reads_state_ports_type_and_mtu(self):
        db = show_tables.build_vlan_db(clean(L2))
        rows = {row["vlan_id"]: row for row in db["rows"]}
        self.assertEqual(rows[1]["ports"], ["Fa0/7", "Fa0/8", "Fa0/10", "Fa0/11", "Fa0/12", "Fa0/13", "Fa0/14", "Fa0/15", "Gi0/1"])  # wrapped port list
        self.assertEqual(rows[21]["port_count"], 5)
        self.assertEqual(rows[22]["ports"], [])
        self.assertEqual(rows[30]["status"], "act/lshut")
        self.assertEqual(rows[23]["mtu"], 9000)
        self.assertEqual(rows[10]["type"], "enet")
        self.assertTrue(rows[1003]["builtin"])
        self.assertFalse(rows[10]["builtin"])

    def test_summary_is_checked_against_the_rows(self):
        db = show_tables.build_vlan_db(clean(L2))
        self.assertEqual(db["summary"], {"existing": 10, "vtp": 10, "extended": 0})
        self.assertEqual(len(db["rows"]), 10)
        self.assertTrue(db["complete"])
        short = "\n".join(line for line in fixture(L2).splitlines() if not line.startswith(("30 ", "22 ", "23 ")))
        self.assertFalse(show_tables.build_vlan_db(capture_text.clean_lines(short))["complete"])

    def test_aruba_show_vlan(self):
        db = show_tables.build_vlan_db(clean("aruba_2540_show_vlan_and_stp_off_masked.txt"))
        self.assertEqual([(row["vlan_id"], row["name"]) for row in db["rows"]], [(1, "DEFAULT_VLAN"), (213, "Management"), (214, "Voip")])
        self.assertEqual(db["rows"][2]["mode"], "voice")

    def test_error_reply_gives_nothing(self):
        db = show_tables.build_vlan_db(capture_text.clean_lines("SW1#show vlan\n% Invalid input detected at '^' marker.\nSW1#"))
        self.assertEqual(db["rows"], [])
        self.assertFalse(db["captured"])


class DescriptionAndTrunkTests(unittest.TestCase):
    def test_interface_descriptions(self):
        rows = {row["interface"]: row for row in show_tables.build_descriptions(clean(L2))["rows"]}
        self.assertEqual(rows["Fa0/3"]["status"], "admin down")
        self.assertEqual(rows["Fa0/3"]["description"], "")
        self.assertEqual(rows["Fa0/2"]["description"], "spare patch")       # quotes are not part of the text
        self.assertEqual(rows["Po1"]["description"], "Etherchannel to LAB-CORE")
        self.assertEqual(rows["Vl1"]["protocol"], "up")

    def test_nxos_two_column_layout(self):
        text = "SW#show interface description\n-------------------------------------------------\nInterface   Description\n-------------------------------------------------\nmgmt0       --\nEth1/1      uplink to core\n"
        rows = show_tables.parse_interface_descriptions(capture_text.clean_lines(text))
        self.assertEqual([(row["interface"], row["description"]) for row in rows], [("mgmt0", ""), ("Eth1/1", "uplink to core")])

    def test_description_command_is_a_live_state_source(self):
        observed = live_state.observe_interface_states(clean(L2))
        by_key = {key: live_state.resolve_state(items) for key, items in observed.items()}
        self.assertEqual(by_key["fa0/3"]["state"], live_state.ADMIN_DOWN)
        self.assertEqual(by_key["fa0/1"]["state"], live_state.UP)
        self.assertEqual(by_key["fa0/2"]["state"], live_state.DOWN)
        self.assertEqual(by_key["po1"]["sources"], ["show interfaces description"])

    def test_trunks_with_wrapped_vlan_lists(self):
        rows = {row["port"]: row for row in show_tables.build_trunks(clean(L2))["rows"]}
        self.assertEqual(rows["Gi0/1"]["native_vlan"], "1")
        self.assertTrue(rows["Gi0/1"]["allowed_all"])
        self.assertFalse(rows["Po1"]["allowed_all"])
        self.assertTrue(rows["Po1"]["allowed"].endswith("300-301,307,900,999"))     # continuation line joined
        self.assertEqual(rows["Gi0/1"]["active"], "1,10,21-23,30")
        self.assertEqual(rows["Gi0/1"]["active_count"], 6)
        self.assertEqual(rows["Po1"]["forwarding_count"], 2)

    def test_expand_vlans(self):
        self.assertEqual(show_tables.expand_vlans("1,10,21-23"), [1, 10, 21, 22, 23])
        self.assertEqual(show_tables.expand_vlans("none"), [])


class CounterTests(unittest.TestCase):
    def test_arp_summary(self):
        self.assertEqual(show_tables.build_arp_summary(clean(L2)), {"total": 3, "incomplete": 0, "source": "show ip arp summary"})

    def test_mac_count_per_vlan_and_total(self):
        count = show_tables.build_mac_count(clean(L2))
        self.assertEqual((count["total"], count["dynamic"], count["static"], count["available"]), (4, 4, 0, 8188))
        self.assertEqual([(item["vlan"], item["total"]) for item in count["vlans"]], [(10, 1), (21, 2), (23, 1)])

    def test_mac_count_on_an_older_ios_without_totals(self):
        text = "SW#show mac address-table count\n\nMac Entries for Vlan 1:\n---------------------------\nDynamic Address Count  : 3\nStatic  Address Count  : 1\nTotal Mac Addresses    : 4\n"
        count = show_tables.build_mac_count(capture_text.clean_lines(text))
        self.assertEqual((count["total"], count["dynamic"], count["static"]), (4, 3, 1))

    def test_mac_count_on_nxos(self):
        text = ("SW# show mac address-table count\n\nMAC Entries for all VLANS:\nDynamic Local Address Count:\t\t          50\n"
                "Dynamic Remote Address Count:\t\t           0\nStatic Remote Address (User-defined) Count:\t           0\n"
                "Static Local Address (User-defined) Count:\t           2\nSecure Address Count:\t\t\t           0\n"
                "Total MAC Addresses in Use (DLAC + DRAC + SLAC + SRAC + SAC):     52\nSW# \n")
        count = show_tables.build_mac_count(capture_text.clean_lines(text))
        self.assertEqual((count["total"], count["dynamic"], count["static"]), (52, 50, 2))

    def test_rejected_command_gives_nothing(self):
        self.assertEqual(show_tables.build_mac_count(capture_text.clean_lines("SW#show mac-address-table count\nInvalid input: mac-address-table\nSW#")), {})


class SpanningTreeTests(unittest.TestCase):
    def setUp(self):
        self.stp = stp_detail.build_spanning_tree(clean(L2))

    def test_instances_root_and_bridge(self):
        instances = {item["id"]: item for item in self.stp["instances"]}
        self.assertEqual(set(instances), {"VLAN0001", "VLAN0010"})
        one, ten = instances["VLAN0001"], instances["VLAN0010"]
        self.assertTrue(one["is_root"])
        self.assertFalse(ten["is_root"])
        self.assertEqual((ten["root_priority"], ten["root_cost"], ten["root_port"], ten["bridge_priority"]), (24586, 19, "FastEthernet0/4", 32778))
        self.assertEqual((ten["hello"], ten["max_age"], ten["forward_delay"]), (2, 20, 15))
        self.assertEqual(self.stp["root_for"], ["VLAN0001"])
        self.assertEqual(self.stp["root_bridges"], 2)

    def test_ports_roles_states_and_types(self):
        ports = {(p["instance"], p["interface"]): p for p in self.stp["ports"]}
        self.assertEqual(len(self.stp["ports"]), 7)
        self.assertEqual(ports[("VLAN0010", "Fa0/4")]["role_name"], "Root port")
        self.assertEqual(ports[("VLAN0010", "Gi0/1")]["state_name"], "Blocking")
        self.assertEqual(ports[("VLAN0010", "Gi0/1")]["type"], "P2p Peer(STP)")
        self.assertEqual(ports[("VLAN0010", "Fa0/9")]["type"], "P2p Edge")
        self.assertEqual((ports[("VLAN0010", "Gi0/1")]["priority"], ports[("VLAN0010", "Gi0/1")]["port_number"]), (128, 25))

    def test_broken_port_with_cost_glued_to_the_state(self):
        broken = self.stp["broken"]
        self.assertEqual([(p["interface"], p["state"], p["cost"]) for p in broken], [("Fa0/14", "BKN", 19)])
        self.assertIn("Type inconsistent", broken[0]["inconsistent"])
        self.assertEqual(self.stp["blocking"], 2)      # one BLK, one BKN

    def test_no_instance(self):
        out = stp_detail.build_spanning_tree(capture_text.clean_lines("SW#show spanning-tree\nNo spanning tree instance exists.\nSW#"))
        self.assertTrue(out["captured"])
        self.assertEqual(out["instances"], [])
        self.assertIn("No spanning tree instance", out["note"])

    def test_aruba_summary_only(self):
        out = stp_detail.build_spanning_tree(clean("aruba_2540_show_vlan_and_stp_off_masked.txt"))
        self.assertFalse(out["enabled"])
        self.assertEqual(out["summary"]["STP Enabled"], "No")

    def test_mst_block(self):
        text = ("SW#show spanning-tree\n\nMST0\n  Spanning tree enabled protocol mstp\n  Root ID    Priority    32768\n             Address     0011.2233.7700\n"
                "             Cost        0\n             Port        1 (GigabitEthernet0/1)\n             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec\n\n"
                "  Bridge ID  Priority    32768  (priority 32768 sys-id-ext 0)\n             Address     0011.2233.7701\n"
                "             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec\n\nInterface        Role Sts Cost      Prio.Nbr Type\n"
                "---------------- ---- --- --------- -------- ----------------\nGi0/1            Root FWD 20000     128.1    P2p\nSW#")
        out = stp_detail.build_spanning_tree(capture_text.clean_lines(text))
        self.assertEqual(out["instances"][0]["id"], "MST0")
        self.assertEqual(out["instances"][0]["protocol"], "mstp")
        self.assertEqual(out["ports"][0]["cost"], 20000)


class LicenceTests(unittest.TestCase):
    def test_smart_licensing_using_policy(self):
        detail = licence_detail.build_licence_detail(clean("cisco_9300x_show_license_all_policy_masked.txt"))
        self.assertEqual(detail["mode"], "Smart Licensing Using Policy")
        self.assertEqual(detail["smart_account"], "Example Corp")
        self.assertEqual(detail["transport"], "cslu")
        self.assertEqual(detail["next_ack"], "Oct 14 18:56:26 2026 UTC")
        names = {item["name"]: item for item in detail["entitlements"]}
        self.assertEqual(names["dna-essentials"]["license_type"], "Subscription")
        self.assertEqual(names["C9K HSEC"]["status"], "NOT IN USE")
        self.assertEqual(names["network-essentials"]["count"], 2)
        terms = {item["license"]: item for item in detail["terms"]}
        self.assertEqual(terms["C9300X Low-density DNA Essentials Fiber Agg/Core"]["end"], "2030-JUL-20 UTC")
        self.assertEqual(licence_detail.licence_findings(detail), [])

    def test_value_in_angle_brackets_is_not_a_prompt(self):
        # "<none>" ended the licence output early because it looked like a Huawei prompt
        lines = clean("cisco_9300x_show_license_all_policy_masked.txt")
        block = max(show_tables.blocks(lines, "lic_all"), key=len)
        self.assertGreater(len(block), 60)
        self.assertIsNone(capture_text.split_prompt("    <none>"))
        self.assertIsNotNone(capture_text.split_prompt("<HUAWEI>display version"))

    def test_expired_evaluation_with_a_nameless_entitlement(self):
        detail = licence_detail.build_licence_detail(clean("cisco_3650_show_license_all_eval_expired_masked.txt"))
        self.assertEqual(detail["mode"], "Smart Licensing (classic)")
        self.assertEqual(detail["registration"], "UNREGISTERED")
        self.assertEqual([(item["name"], item["status"]) for item in detail["entitlements"]], [("C3650-24 IP Services", "EVAL EXPIRED")])
        found = licence_detail.licence_findings(detail)
        self.assertEqual([item["code"] for item in found], ["SW-LIC-002"])
        self.assertEqual(found[0]["doc"], "smart_eval")

    def test_right_to_use_evaluation_in_use(self):
        detail = licence_detail.build_licence_detail(clean("cisco_3560_show_license_all_rtu_masked.txt"))
        self.assertEqual(detail["mode"], "Right-to-use (RTU)")
        self.assertEqual(len(detail["rtu"]), 3)
        evaluation = detail["rtu"][0]
        self.assertEqual((evaluation["license_type"], evaluation["eval_left"], evaluation["in_use"]), ("Evaluation", "2 weeks 3 days", True))
        self.assertEqual(evaluation["eval_left_seconds"], (14 + 3) * 86400)
        self.assertFalse(detail["rtu"][2]["in_use"])                      # "Active, Not in Use"
        self.assertEqual([item["code"] for item in licence_detail.licence_findings(detail)], ["SW-LIC-005"])


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = service.analyze(fixture(L2), filename="lab-sw1.txt")

    def test_vlans_get_state_and_ports_without_the_built_in_ones(self):
        vlans = {item["vlan_id"]: item for item in self.result["vlans"]}
        self.assertEqual(sorted(vlans), [10, 21, 22, 23, 30])
        self.assertEqual(vlans[21]["port_count"], 5)
        self.assertEqual(vlans[21]["status"], "active")
        self.assertEqual(vlans[10]["source"], "device only")                  # no running-config in this capture
        summary = self.result["vlan_summary"]
        self.assertEqual((summary["device"]["existing"], summary["listed"], summary["builtin"], summary["default_vlan_ports"]), (10, 10, 5, 9))

    def test_interfaces_take_description_state_and_trunk_mode_from_the_show_commands(self):
        interfaces = {item["name"]: item for item in self.result["interfaces"]}
        by_short = {live_state.interface_key(name): item for name, item in interfaces.items()}
        self.assertEqual(by_short[live_state.interface_key("Fa0/1")]["description"], "USER PC LAB-01")
        self.assertEqual(by_short[live_state.interface_key("Fa0/1")]["status"], "up")
        self.assertEqual(by_short[live_state.interface_key("Fa0/3")]["status"], "admin down")
        self.assertEqual(by_short[live_state.interface_key("Gi0/1")]["mode"], "trunk")

    def test_device_counts_sit_next_to_the_table_checks(self):
        checks = self.result["table_checks"]
        self.assertIn("The device counts 3 IP ARP entries (0 incomplete); this capture lists 3 rows.", checks["arp"]["device_note"])
        # four host rows in the table (the two CPU rows are the switch's own and are not counted)
        self.assertIn("counts 4 MAC entries (4 dynamic, 0 static); this capture lists 4 host rows", checks["mac"]["device_note"])
        self.assertEqual(checks["mac"]["device_gap"], 0)

    def test_large_gap_is_named(self):
        check: dict = {}
        service._attach_device_counts(check, 100, {"total": 300, "dynamic": 290, "static": 10}, "MAC", "MAC entries")
        self.assertEqual(check["device_gap"], 200)
        self.assertIn("200 entries are not in the table above", check["device_note"])
        service._attach_device_counts(check, 298, {"total": 300}, "MAC", "MAC entries")
        self.assertNotIn("not in the table", check["device_note"])        # a gap of 2 is aging, not loss

    def test_broken_port_becomes_a_finding_with_a_documentation_link(self):
        item = next(f for f in self.result["findings"] if f["id"] == "SW-STP-101")
        self.assertEqual(item["severity"], "medium")
        self.assertIn("Fa0/14", item["object"])
        self.assertIn("Type inconsistent", item["detail"])
        self.assertTrue(item["reference"].startswith("https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"))

    def test_every_one_of_the_nine_commands_is_analysed_even_when_typed_short(self):
        status = {row["command"]: row["status"] for row in self.result["coverage"]["rows"]}
        for command in ("show vlan", "sh vlan sum", "sh int desc", "sh int tru", "sh ip arp su", "sh span", "sh mac add count"):
            self.assertEqual(status[command], "analysed", command)

    def test_licence_commands_are_analysed_in_coverage(self):
        for name, command in (("cisco_9300x_show_license_all_policy_masked.txt", "show license all"),
                              ("cisco_3650_show_license_all_eval_expired_masked.txt", "show license all"),
                              ("cisco_3560_show_license_all_rtu_masked.txt", "show license all")):
            result = service.analyze(fixture(name), filename="x.txt", vendor="Cisco")
            row = next(r for r in result["coverage"]["rows"] if r["command"] == command)
            self.assertEqual(row["status"], "analysed", name)
        usage = service.analyze(fixture("cisco_9300x_show_license_all_policy_masked.txt"), filename="x.txt", vendor="Cisco")
        self.assertEqual(next(r for r in usage["coverage"]["rows"] if r["command"] == "show license usage")["status"], "analysed")

    def test_a_licence_only_excerpt_is_recognised_as_cisco_without_the_vendor_box(self):
        # no hostname / show version / running-config in these captures: the licence layout is the only evidence
        for name in ("cisco_9300x_show_license_all_policy_masked.txt", "cisco_3650_show_license_all_eval_expired_masked.txt",
                     "cisco_3560_show_license_all_rtu_masked.txt"):
            result = service.analyze(fixture(name), filename="x.txt")  # vendor defaults to Auto Detect
            self.assertEqual(result["detection"]["vendor_used"], "Cisco", name)
            self.assertEqual(result["detection"]["method"], "device identity", name)
            self.assertIn(result["detection"]["confidence"], ("medium", "high"), name)
            self.assertTrue(result["health"]["licence"]["detail"]["captured"], name)

    def test_licence_signals_do_not_pull_other_vendors_to_cisco(self):
        from features.switch_analyzer import fingerprint
        huawei = "<LAB>display version\nHuawei Versatile Routing Platform Software\nVRP (R) software, Version 5.170 (S5735 V200R021C10SPC600)\n<LAB>display license\nActive license : flash:/license.dat\n"
        aruba = "show version\nImage stamp: /ws/swbuild/xx\nSoftware revision  : WC.16.10.0003\nBase MAC Addr: 000000-000000\n"
        self.assertEqual(fingerprint.detect(huawei).vendor, "Huawei")
        self.assertEqual(fingerprint.detect(aruba).vendor, "Aruba")

    def test_expired_evaluation_reaches_the_findings(self):
        result = service.analyze(fixture("cisco_3650_show_license_all_eval_expired_masked.txt"), filename="x.txt", vendor="Cisco")
        item = next(f for f in result["findings"] if f["id"] == "SW-LIC-002")
        self.assertIn("EVAL EXPIRED", item["detail"])
        self.assertTrue(item["reference"].startswith("https://www.cisco.com/c/en/us/support/docs/ip/syslog/"))

    def test_tabs_for_trunks_and_spanning_tree(self):
        tabs = {tab["key"]: tab for tab in self.result["tabs"]}
        self.assertTrue(tabs["trunks"]["has"])
        self.assertEqual(tabs["trunks"]["count"], 2)
        self.assertTrue(tabs["stp"]["has"])
        bare = service.analyze("hostname LAB\n!\nvlan 10\n name USERS\n!\n", filename="b.txt")
        bare_tabs = {tab["key"]: tab for tab in bare["tabs"]}
        self.assertFalse(bare_tabs["trunks"]["has"])
        self.assertIn("show interface trunk", bare_tabs["trunks"]["why"])
        self.assertIn("show spanning-tree", bare_tabs["stp"]["why"])

    def test_a_capture_without_device_data_keeps_the_plain_vlan_rows(self):
        result = service.analyze("hostname LAB\n!\nvlan 10\n name USERS\n!\n", filename="b.txt")
        self.assertEqual(result["vlans"], [{"vlan_id": 10, "name": "USERS"}])
        self.assertFalse(result["vlan_summary"]["captured"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
