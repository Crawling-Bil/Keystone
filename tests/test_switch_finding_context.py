"""Bundle membership (bundles.py), related detail on findings (finding_context.py) and the NX-OS log time stamp.

The layouts are those of real Nexus 9000 captures; every name, address and number below is invented.
"""
from __future__ import annotations

import unittest

from features.switch_analyzer import bundles, finding_context, logs
from features.switch_analyzer.service import analyze

NXOS = """LAB-N9K-A# show running-config
hostname LAB-N9K-A
feature lacp
feature vpc
vpc domain 7
  peer-keepalive destination 192.0.2.2 source 192.0.2.1
interface port-channel7
  switchport mode trunk
  vpc peer-link
interface port-channel10
  description To LAB-SRV-1
  switchport mode trunk
  switchport trunk allowed vlan 100,200
  vpc 10
interface port-channel20
  description To LAB-SRV-2
  switchport mode trunk
  vpc 20
interface Ethernet1/1
  description LAB-SRV-1 nic0
  switchport mode trunk
  channel-group 10 mode active
interface Ethernet1/2
  description LAB-SRV-2 nic0
  switchport mode trunk
  channel-group 20 mode active
interface Ethernet1/3
  description LAB-SRV-2 nic1
  switchport mode trunk
  channel-group 20 mode active
LAB-N9K-A# show version
Cisco Nexus Operating System (NX-OS) Software
Software
  NXOS: version 10.4(3)
Hardware
  cisco Nexus9000 C93180YC-FX Chassis
  Device name: LAB-N9K-A
LAB-N9K-A# show interface status
--------------------------------------------------------------------------------
Port          Name               Status    Vlan      Duplex  Speed   Type
--------------------------------------------------------------------------------
Po7           --                 connected trunk     full    10G     --
Po10          To LAB-SRV-1       connected trunk     full    10G     --
Po20          To LAB-SRV-2       sfpAbsent trunk     auto    auto    --
Eth1/1        LAB-SRV-1 nic0     connected trunk     full    10G     10Gbase-SR
Eth1/2        LAB-SRV-2 nic0     sfpAbsent trunk     auto    auto    --
Eth1/3        LAB-SRV-2 nic1     sfpAbsent trunk     auto    auto    --
LAB-N9K-A# show lacp neighbor
Flags:  S - Device is requesting Slow LACPDUs   F - Device is requesting Fast LACPDUs
        A - Device is in Active mode       P - Device is in Passive mode
port-channel10 neighbors
Partner's information
            Partner                Partner                     Partner
Port        System ID              Port Number     Age         Flags
Eth1/1      32768,0-50-56-0-0-1    0x101           1000        SA
            LACP Partner           Partner                 Partner
            Port Priority          Oper Key                State
            32768                  0x8000                  0x3d
LAB-N9K-A# show lldp neighbors
Capability codes:
  (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device
  (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other
Device ID            Local Intf      Hold-time  Capability  Port ID
LAB-SRV-1.example    Eth1/1          120        S           eth2
LAB-N9K-A# show logging last 100
2026 Sep 23 15:25:40 LAB-N9K-A %ETHPORT-5-IF_DOWN_NONE: Interface port-channel10 is down (No operational members)
2026 Sep 23 15:26:00 LAB-N9K-A %ETHPORT-5-IF_UP: Interface port-channel10 is up in mode trunk
2026 Sep 24 10:00:01 LAB-N9K-A %ETHPORT-5-IF_DOWN_NONE: Interface port-channel10 is down (No operational members)
2026 Sep 24 10:00:30 LAB-N9K-A %ETHPORT-5-IF_UP: Interface port-channel10 is up in mode trunk
2026 Sep 25 11:00:01 LAB-N9K-A %ETHPORT-5-IF_DOWN_NONE: Interface port-channel10 is down (No operational members)
2026 Sep 25 11:00:30 LAB-N9K-A %ETHPORT-5-IF_UP: Interface port-channel10 is up in mode trunk
"""


def result():
    return analyze(NXOS, filename="lab.txt")


class LogTimeStampTests(unittest.TestCase):
    def test_nxos_host_name_after_the_clock_is_not_a_time_zone(self):
        message = logs.parse_message("2026 Sep 23 15:25:40 LABNXTOR1 %ETHPORT-5-IF_DOWN_NONE: Interface port-channel10 is down (No operational members)")
        self.assertEqual(message["ts"], "2026 Sep 23 15:25:40")
        self.assertEqual(message["host"], "LABNXTOR1")

    def test_all_capital_host_name_is_not_cut_either(self):
        message = logs.parse_message("2026 Sep 23 15:25:40.123 CORE %ETHPORT-5-SPEED: Interface Ethernet1/1, operational speed changed to 10 Gbps")
        self.assertEqual(message["ts"], "2026 Sep 23 15:25:40.123")
        self.assertEqual(message["host"], "CORE")

    def test_ios_time_zone_stays_in_the_stamp(self):
        message = logs.parse_message("Oct 12 10:00:00.123 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down")
        self.assertEqual(message["ts"], "Oct 12 10:00:00.123 UTC")
        self.assertNotIn("host", message)


class BundleTests(unittest.TestCase):
    def test_member_ports_name_their_bundle(self):
        by_name = {item["name"]: item for item in result()["interfaces"]}
        self.assertEqual(by_name["Ethernet1/1"]["bundle"], "Po10")
        self.assertEqual(by_name["Ethernet1/1"]["bundle_mode"], "active")
        self.assertTrue(by_name["Ethernet1/1"]["bundle_state"].startswith("bundled"))
        self.assertEqual(by_name["Ethernet1/2"]["bundle"], "Po20")
        self.assertNotIn("bundle", by_name["port-channel10"])   # a bundle interface is not a member of anything
        self.assertEqual([m["port"] for m in by_name["port-channel20"]["bundle_members"]], ["Ethernet1/2", "Ethernet1/3"])

    def test_member_the_lacp_table_does_not_list_says_so(self):
        by_name = {item["name"]: item for item in result()["interfaces"]}
        self.assertIn("not listed in show lacp neighbor", by_name["Ethernet1/2"]["bundle_state"])

    def test_bundle_without_a_summary_table_gets_a_port_channel_row(self):
        data = result()
        names = {row["name"] for row in data["port_channels"]}
        self.assertEqual(names, {"Po10", "Po20"})
        row = next(item for item in data["port_channels"] if item["name"] == "Po10")
        self.assertEqual(row["members"], "Ethernet1/1")
        self.assertEqual(row["protocol"], "LACP")
        self.assertIn("no bundle summary", row["source"])

    def test_live_bundle_table_wins_over_the_configuration(self):
        interfaces = [{"name": "Gi1/0/1", "status": "up"}, {"name": "Gi1/0/2", "status": "up"}, {"name": "Port-channel5", "status": "up"}]
        channels = [{"name": "Po5", "protocol": "LACP", "status": "SU", "members": "Gi1/0/1, Gi1/0/2",
                     "member_states": [{"port": "Gi1/0/1", "flag": "P", "meaning": "bundled"}, {"port": "Gi1/0/2", "flag": "s", "meaning": "suspended"}]}]
        view = bundles.build(interfaces, channels, [], [])
        self.assertEqual(view["added"], 0)
        self.assertEqual(interfaces[1]["bundle"], "Po5")
        self.assertEqual(interfaces[1]["bundle_state"], "suspended")
        self.assertEqual(len(channels), 1)

    def test_bundle_without_an_interface_row_is_named_the_way_the_platform_names_it(self):
        class Item:
            name, channel_group, lacp_mode = "GigabitEthernet0/0/1", 3, ""
        interfaces = [{"name": "GigabitEthernet0/0/1", "status": "up"}]
        channels: list = []
        bundles.build(interfaces, channels, [], [Item()], bundles.default_prefix("Huawei"))
        self.assertEqual(interfaces[0]["bundle"], "Eth-Trunk3")
        self.assertEqual(channels[0]["name"], "Eth-Trunk3")
        self.assertEqual(bundles.default_prefix("Aruba", True), "lag")
        self.assertEqual(bundles.default_prefix("Cisco"), "Po")

    def test_huawei_eth_trunk_label_is_kept(self):
        class Item:
            name, channel_group, lacp_mode = "GigabitEthernet0/0/1", 3, ""
        interfaces = [{"name": "GigabitEthernet0/0/1", "status": "up"}, {"name": "Eth-Trunk3", "status": "up"}]
        bundles.build(interfaces, [], [], [Item()])
        self.assertEqual(interfaces[0]["bundle"], "Eth-Trunk3")
        self.assertEqual(interfaces[0]["bundle_id"], "3")


class FindingContextTests(unittest.TestCase):
    def finding(self, rule, **match):
        for item in result()["findings"]:
            if item["id"] == rule and all(match[key] in str(item.get(key, "")) for key in match):
                return item
        self.fail(f"no {rule} finding {match}")

    def test_flapping_port_channel_shows_state_neighbour_and_members(self):
        item = self.finding("SW-EVT-001", object="port-channel10")
        labels = {row["label"]: row["value"] for row in item["evidence"]}
        self.assertIn("up", labels["Port now"])
        self.assertIn("LAB-SRV-1.example", labels["Connected to"])
        self.assertIn("eth2", labels["Connected to"])
        self.assertIn("Ethernet1/1", labels["Member ports"])
        self.assertEqual(labels["Logged by"], "LAB-N9K-A")
        self.assertTrue(item["meaning"])
        rows = item["related"]["rows"]
        self.assertEqual([row["interface"] for row in rows], ["port-channel10", "Ethernet1/1"])
        self.assertEqual(rows[1]["device"], "LAB-SRV-1.example")

    def test_log_times_carry_no_host_name(self):
        item = self.finding("SW-EVT-001", object="port-channel10")
        self.assertNotIn("LAB-N9K-A", item["detail"])
        self.assertIn("2026 Sep 23 15:25:40", item["detail"])

    def test_port_without_neighbour_says_so(self):
        index = finding_context._Index(result())
        text = index.no_neighbour_text()
        self.assertIn("No CDP / LLDP neighbour", text)

    def test_vlan_list_is_compacted_without_cutting_a_range(self):
        text = "VLAN0848, VLAN1040-VLAN1041, VLAN2019, VLAN2070-VLAN2073 VLAN2075-VLAN2078,"
        self.assertEqual(finding_context.compact_vlans(text), "848, 1040-1041, 2019, 2070-2073, 2075-2078")
        self.assertEqual(finding_context.compact_vlans(text, 20), "848, 1040-1041, 2019 and 2 more range(s)")
        self.assertEqual(finding_context.vlan_phrase("MST0"), "MST0")

    def test_unknown_object_adds_nothing(self):
        data = {"findings": [{"id": "SW-AAA-001", "title": "AAA is not enabled", "object": ""}], "interfaces": [], "neighbors": []}
        finding_context.attach(data)
        self.assertNotIn("evidence", data["findings"][0])
        self.assertNotIn("related", data["findings"][0])

    def test_more_ports_finding_has_no_meaning_about_one_port(self):
        data = {"findings": [{"id": "SW-EVT-001", "title": "11 more ports went down 3 or more times", "object": ""}], "interfaces": [], "neighbors": []}
        finding_context.attach(data)
        self.assertNotIn("meaning", data["findings"][0])

    def test_single_cdp_and_lldp_listing_of_one_port_is_one_link(self):
        data = {"findings": [{"id": "SW-EVT-005", "title": "x", "object": "Eth1/1"}],
                "interfaces": [{"name": "Ethernet1/1", "status": "up", "status_detail": "connected"}],
                "neighbors": [{"protocol": "LLDP", "neighbor_id": "FAR-1", "local_interface": "Eth1/1", "remote_interface": "p1", "platform": ""},
                              {"protocol": "CDP", "neighbor_id": "FAR-1", "local_interface": "Eth1/1", "remote_interface": "p1", "platform": "X"}]}
        finding_context.attach(data)
        value = next(row["value"] for row in data["findings"][0]["evidence"] if row["label"] == "Connected to")
        self.assertTrue(value.startswith("FAR-1 on its port p1"))
        self.assertNotIn("links", value)


if __name__ == "__main__":
    unittest.main()
