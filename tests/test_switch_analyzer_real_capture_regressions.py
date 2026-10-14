"""Regression tests for parser bugs found by running the Switch Analyzer
against the real TAM Cisco/Aruba -> Huawei migration captures (Oct 2026).

Every fixture in tests/fixtures/real_captures/ is a masked excerpt of ONE
command's output from a real device, produced with mask_capture.py: the column
layout is the device's own, hostnames/IPs/MACs are replaced. The raw captures
are not in this repository.

  F1  Aruba 2540 "show interfaces brief" was never parsed, so every port was
      reported Up (real result: 14 up / 14 down, analyzer said 28 / 0).
  F2  Cisco VLANs live in the VLAN database, not only in the running-config
      ("show vlan brief" has 4 VLANs on a 3650 whose config has none).
  F3  Cisco "show lldp neighbors" cuts a long Device ID at 20 characters and
      prints Local Intf right after it, which swapped columns; the detail
      command was not parsed at all.
  F4  Huawei V600R025C00 "display poe information" has no per-port rows; the
      per-port data is in "display poe power-state" and "display poe power".
  F9  Two parser interactions found while verifying the above: the CDP-detail
      de-dupe dropped every LLDP row whose peer name matched a CDP detail entry,
      and the Huawei "display eth-trunk" reader never stopped at the end of its
      command, so later "<port> up/down" rows were added to the last trunk.

Two inputs below are NOT captures and are labelled as such: the PoE table in
the layout of the V600R025C00 command reference's own example (a powered port
and no FAST-ON column), and small synthetic wrappers (a hostname and a couple
of config lines) placed around a fixture so analyze() can detect the vendor.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from features.switch_analyzer import runtime_parser
from features.switch_analyzer.service import analyze

FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def fixture_lines(name: str) -> list[str]:
    return fixture_text(name).splitlines()


class ArubaInterfacesBriefTest(unittest.TestCase):
    def test_real_2540_reports_each_port_up_or_down(self):
        brief = runtime_parser.parse_interface_brief(fixture_lines("aruba_2540_show_interfaces_brief.txt"))
        self.assertEqual(len(brief), 28)
        self.assertEqual(sum(1 for v in brief.values() if v["status"] == "up"), 14)
        self.assertEqual(brief["1"]["status"], "up")
        self.assertEqual(brief["2"]["status"], "down")

    def test_admin_disabled_port_is_administratively_down(self):
        # Port 16 prints "Enabled: No, Status: Down" -- the same wording the
        # Cisco brief table uses, which _build_interfaces folds into "down".
        brief = runtime_parser.parse_interface_brief(fixture_lines("aruba_2540_show_interfaces_brief.txt"))
        self.assertEqual(brief["16"]["status"], "administratively down")
        self.assertEqual(brief["22"]["status"], "administratively down")

    def test_empty_sfp_cage_with_blank_type_still_parses(self):
        brief = runtime_parser.parse_interface_brief(fixture_lines("aruba_2540_show_interfaces_brief.txt"))
        for port in ("25", "26", "27", "28"):
            self.assertEqual(brief[port]["status"], "down", port)

    def test_dead_snapshot_has_no_port_up(self):
        brief = runtime_parser.parse_interface_brief(
            fixture_lines("aruba_2540_all_down_show_interfaces_brief.txt")
        )
        self.assertEqual(len(brief), 28)
        self.assertEqual(sum(1 for v in brief.values() if v["status"] == "up"), 0)

    def test_table_without_the_pipe_separator_is_not_an_aruba_table(self):
        lines = [
            "SW#show interfaces brief",
            "Port      Status   Speed",
            "Eth1/1    up       10G",
        ]
        self.assertEqual(runtime_parser.parse_interface_brief(lines), {})

    def test_analyze_uses_the_brief_state_instead_of_assuming_up(self):
        config = (
            "; JL356A Configuration Editor; Created on release #YC.16.06.0006\n"
            'hostname "EXAMPLE-ACCESS-1"\n'
            "vlan 1\n   name \"DEFAULT_VLAN\"\n   untagged 1-28\n   exit\n"
            "interface 16\n   disable\n   exit\n"
            "interface 2\n   exit\n"
        )
        result = analyze(config + "\n" + fixture_text("aruba_2540_show_interfaces_brief.txt"), filename="x.txt")
        self.assertEqual(result["vendor"], "Aruba")
        # Enabled=No (ports 16 and 20-23) is an intentional shutdown, so it is
        # reported as "admin down" instead of being folded into "down".
        self.assertEqual(result["cards"]["interfaces_up"], 14)
        self.assertEqual(result["cards"]["interfaces_down"], 9)
        self.assertEqual(result["cards"]["interfaces_admin_down"], 5)
        self.assertEqual(result["cards"]["interfaces_unknown"], 0)
        by_name = {item["name"]: item["status"] for item in result["interfaces"]}
        self.assertEqual(by_name["1"], "up")
        self.assertEqual(by_name["2"], "down")  # in the config, but the link is down
        self.assertEqual(by_name["16"], "admin down")  # "disable" in the config + Enabled=No live


class VlanBriefTest(unittest.TestCase):
    def test_3650_vlan_database_without_any_config(self):
        vlans = runtime_parser.parse_vlan_brief(fixture_lines("cisco_3650_show_vlan_brief.txt"))
        self.assertEqual(
            vlans,
            [
                {"vlan_id": 100, "name": "P2P-To-NSF"},
                {"vlan_id": 213, "name": "management"},
                {"vlan_id": 214, "name": "voip"},
                {"vlan_id": 710, "name": "OT-HRGA"},
            ],
        )

    def test_2960_reads_all_18_vlans_and_ignores_wrapped_port_lists(self):
        vlans = runtime_parser.parse_vlan_brief(fixture_lines("cisco_2960_show_vlan_brief.txt"))
        self.assertEqual(
            [item["vlan_id"] for item in vlans],
            [8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 20, 25, 53, 54, 100, 102, 109, 112],
        )
        self.assertEqual({item["vlan_id"]: item["name"] for item in vlans}[8], "MGMT-SERVER")

    def test_built_in_vlans_are_not_reported(self):
        vlans = runtime_parser.parse_vlan_brief(fixture_lines("cisco_2960_show_vlan_brief.txt"))
        ids = {item["vlan_id"] for item in vlans}
        self.assertFalse(ids & {1, 1002, 1003, 1004, 1005})

    def test_no_show_vlan_brief_means_no_rows(self):
        self.assertEqual(runtime_parser.parse_vlan_brief(["SW#show version", "Cisco IOS"]), [])

    def test_analyze_adds_database_vlans_missing_from_the_config(self):
        config = "hostname EXAMPLE-3650\n!\nvlan 100\n name P2P-To-NSF\n!\ninterface GigabitEthernet1/0/1\n switchport mode access\n!\n"
        result = analyze(config + "\n" + fixture_text("cisco_3650_show_vlan_brief.txt"), filename="c.txt")
        self.assertEqual(result["vendor"], "Cisco")
        self.assertEqual([item["vlan_id"] for item in result["vlans"]], [100, 213, 214, 710])
        self.assertEqual(result["cards"]["total_vlans"], 4)

    def test_config_only_capture_is_unchanged(self):
        config = "hostname EXAMPLE-3650\n!\nvlan 10\n name USERS\n!\nvlan 20\n name SERVERS\n!\n"
        result = analyze(config, filename="c.txt")
        self.assertEqual(result["vlans"], [{"vlan_id": 10, "name": "USERS"}, {"vlan_id": 20, "name": "SERVERS"}])

    def test_config_vlan_without_a_name_takes_the_database_name(self):
        config = "hostname EXAMPLE-3650\n!\nvlan 213\n!\n"
        result = analyze(config + "\n" + fixture_text("cisco_3650_show_vlan_brief.txt"), filename="c.txt")
        names = {item["vlan_id"]: item["name"] for item in result["vlans"]}
        self.assertEqual(names[213], "management")


class CiscoLldpTest(unittest.TestCase):
    def _brief_only_lines(self) -> list[str]:
        lines = fixture_lines("cisco_3650_lldp.txt")
        cut = next(i for i, line in enumerate(lines) if line.endswith("#show lldp neighbors detail"))
        return lines[:cut]

    def test_truncated_device_id_does_not_swap_columns(self):
        # Real rows look like "vksu-j77_80.zhgjwzvtGi1/0/23   120  R  675c.d9e9.6309":
        # the 20-character Device ID column runs straight into Local Intf.
        lldp = [n for n in runtime_parser.parse_neighbors(self._brief_only_lines()) if n["protocol"] == "LLDP"]
        self.assertEqual([n["local_interface"] for n in lldp], ["Gi1/0/23", "Gi1/1/1", "Gi1/1/2", "Gi1/0/22"])
        self.assertEqual([n["remote_interface"] for n in lldp], ["675c.d9e9.6309", "25", "10GE1/0/1", "24"])
        self.assertEqual(lldp[0]["neighbor_id"], "vksu-j77_80.zhgjwzvt")
        self.assertTrue(all(len(n["neighbor_id"]) <= 20 for n in lldp))

    def test_detail_gives_full_names_and_platform_without_duplicates(self):
        lldp = [n for n in runtime_parser.parse_neighbors(fixture_lines("cisco_3650_lldp.txt")) if n["protocol"] == "LLDP"]
        self.assertEqual(len(lldp), 4)
        by_local = {n["local_interface"]: n for n in lldp}
        self.assertEqual(by_local["Gi1/0/23"]["neighbor_id"], "vksu-j77_80.zhgjwzvtkau")
        self.assertEqual(by_local["Gi1/1/1"]["neighbor_id"], "SOX-OCKW-GGQSZP2-2339")
        self.assertEqual(by_local["Gi1/1/1"]["remote_interface"], "25")
        self.assertEqual(by_local["Gi1/1/1"]["platform"], "Aruba JL356A 2540-24G-PoE+-4SFP+ Switch")
        # Huawei prints a generic banner first; the model is on the "HUAWEI ..." line.
        self.assertEqual(by_local["Gi1/1/2"]["platform"], "CloudEngine S5735-L-V2")

    def test_brief_rows_for_ports_the_detail_does_not_cover_are_kept(self):
        lines = """
SW1#show lldp neighbors
Device ID           Local Intf     Hold-time  Capability      Port ID
switch2             Gi1/0/1        120        B,R             Gi1/0/2
switch3             Gi1/0/2        120        B,R             Gi1/0/3
Total entries displayed: 2
SW1#show lldp neighbors detail
------------------------------------------------
Local Intf: Gi1/0/1
Chassis id: aaaa.bbbb.cccc
Port id: Gi1/0/2
Port Description: uplink
System Name: switch2.example.net

System Description:
Cisco IOS Software, Catalyst L3 Switch Software

Time remaining: 99 seconds
""".strip().splitlines()
        lldp = [n for n in runtime_parser.parse_neighbors(lines) if n["protocol"] == "LLDP"]
        by_local = {n["local_interface"]: n["neighbor_id"] for n in lldp}
        self.assertEqual(by_local, {"Gi1/0/1": "switch2.example.net", "Gi1/0/2": "switch3"})

    def test_neighbor_without_a_system_name_is_listed_by_chassis_id(self):
        lines = """
SW1#show lldp neighbors detail
------------------------------------------------
Local Intf: Gi1/0/9
Chassis id: 0011.2233.4455
Port id: 0011.2233.4455
Port Description: Phone port

System Description:
IP Phone

Time remaining: 90 seconds
""".strip().splitlines()
        lldp = runtime_parser.parse_neighbors(lines)
        self.assertEqual(len(lldp), 1)
        self.assertEqual(lldp[0]["neighbor_id"], "0011.2233.4455")
        self.assertEqual(lldp[0]["local_interface"], "Gi1/0/9")

    def test_peer_seen_by_both_cdp_and_lldp_keeps_one_row_per_protocol(self):
        # Same peer on the same port, reported by CDP and by LLDP under the same
        # (full) name. CDP detail replaces the CDP brief row; it must not take
        # the LLDP rows with it. Layout follows a real Catalyst 2960-X pair; names
        # are placeholders.
        lines = """
SW1#show cdp neighbors detail
-------------------------
Device ID: PEER-SW.example.net
Entry address(es):
  IP address: 192.0.2.19
Platform: cisco WS-C2960X-24TS-L,  Capabilities: Router Switch IGMP
Interface: GigabitEthernet1/0/23,  Port ID (outgoing port): GigabitEthernet2/0/23
Holdtime : 128 sec

Version :
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(2)E6, RELEASE SOFTWARE (fc1)

SW1#show lldp neighbors
Device ID           Local Intf     Hold-time  Capability      Port ID
PEER-SW.example.net Gi1/0/23       120        B,R             Gi2/0/23
Total entries displayed: 1
SW1#show lldp neighbors detail
------------------------------------------------
Local Intf: Gi1/0/23
Chassis id: aaaa.bbbb.cccc
Port id: Gi2/0/23
Port Description: uplink
System Name: PEER-SW.example.net

System Description:
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(2)E6, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport

Time remaining: 109 seconds
""".strip().splitlines()
        rows = runtime_parser.parse_neighbors(lines)
        self.assertEqual(sorted(n["protocol"] for n in rows), ["CDP", "LLDP"])
        lldp = next(n for n in rows if n["protocol"] == "LLDP")
        self.assertEqual(lldp["neighbor_id"], "PEER-SW.example.net")
        self.assertEqual(lldp["local_interface"], "Gi1/0/23")
        self.assertEqual(lldp["remote_interface"], "Gi2/0/23")

    def test_cisco_ios_platform_is_the_family_not_the_operating_system_banner(self):
        self.assertEqual(
            runtime_parser._cisco_lldp_platform([
                "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(2)E6, RELEASE SOFTWARE (fc1)",
            ]),
            "C2960X Software (C2960X-UNIVERSALK9-M)",
        )
        self.assertEqual(runtime_parser._cisco_lldp_platform([]), "")

    def test_analyze_reports_the_four_real_neighbors(self):
        config = "hostname EXAMPLE-3650\n!\ninterface GigabitEthernet1/0/1\n switchport mode access\n!\n"
        result = analyze(config + "\n" + fixture_text("cisco_3650_lldp.txt"), filename="c.txt")
        self.assertEqual(result["cards"]["neighbor_count"], 4)


class HuaweiPoePerPortTest(unittest.TestCase):
    def test_real_s5755h_lists_every_port_even_when_nothing_is_plugged_in(self):
        poe = runtime_parser.parse_poe(fixture_lines("huawei_s5755h_show_poe.txt"))
        self.assertEqual(len(poe), 48)
        first = poe[0]
        self.assertEqual(first["interface"], "MultiGE1/0/1")
        self.assertEqual(first["admin_status"], "Enabled")
        self.assertEqual(first["oper_status"], "detecting")
        self.assertEqual(first["power_watts"], "0.0")
        self.assertEqual(first["max_watts"], "90.0")
        self.assertEqual(poe[-1]["interface"], "MultiGE1/0/48")

    def test_power_state_without_the_power_table_still_gives_rows(self):
        lines = [line for line in fixture_lines("huawei_s5755h_show_poe.txt")]
        start = next(i for i, line in enumerate(lines) if line.endswith("display poe power-state"))
        poe = runtime_parser.parse_poe(lines[start:])
        self.assertEqual(len(poe), 48)
        self.assertEqual(poe[0]["max_watts"], "")

    def test_reference_layout_with_a_powered_port_and_no_fast_on_column(self):
        # Layout and values taken from the V600R025C00 command reference
        # examples (DISPLAYPOEPOWERSTATE / DISPLAYPOEPOWER); not a capture.
        lines = """
<SW>display poe power-state
--------------------------------------------------------------------------------
PortName               PowerOn/Off  Enabled    Priority   Status
--------------------------------------------------------------------------------
GE1/0/1                on           enable     Low      powering
GE1/0/2                off          enable     Low      detecting
<SW>display poe power
Codes: REFPW(Reference power), USMPW(User set max power),
       CURPW(Current power), PKPW(Peak power), AVGPW(Average power)
--------------------------------------------------------------------------------
PortName               Class  REFPW(mW)  USMPW(mW)  CURPW(mW)  PKPW(mW)   AVGPW(mW)
--------------------------------------------------------------------------------
GE1/0/1                  0      15400      60000      4300       6300       4300
GE1/0/2                  0      0          60000      0          0          0
""".strip().splitlines()
        poe = {row["interface"]: row for row in runtime_parser.parse_poe(lines)}
        self.assertEqual(poe["GE1/0/1"]["oper_status"], "powering")
        self.assertEqual(poe["GE1/0/1"]["power_watts"], "4.3")
        self.assertEqual(poe["GE1/0/1"]["class"], "0")
        self.assertEqual(poe["GE1/0/1"]["max_watts"], "60.0")
        self.assertEqual(poe["GE1/0/2"]["oper_status"], "detecting")
        self.assertEqual(poe["GE1/0/2"]["power_watts"], "0.0")

    def test_unrecognized_command_error_creates_no_rows(self):
        lines = [
            "<SW>display poe power-management",
            "                                     ^",
            "Error: Unrecognized command found at '^' position.",
        ]
        self.assertEqual(runtime_parser.parse_poe(lines), [])

    def test_analyze_reports_live_ports_instead_of_the_config_fallback(self):
        config = "sysname EXAMPLE-S5755\n#\ninterface MultiGE1/0/1\n poe enable\n#\nreturn\n"
        result = analyze(config + "\n" + fixture_text("huawei_s5755h_show_poe.txt"), filename="h.txt")
        self.assertEqual(result["vendor"], "Huawei")
        self.assertEqual(result["cards"]["poe_port_count"], 48)
        self.assertEqual(result["poe"][0]["source"], "display poe power-state / display poe power")


def _load_mask_module():
    spec = importlib.util.spec_from_file_location("mask_capture", FIXTURES / "mask_capture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HuaweiEthTrunkTest(unittest.TestCase):
    def test_members_stop_at_the_end_of_display_eth_trunk(self):
        # Real S5735 capture: "display eth-trunk" is followed by "display stack
        # topology", whose rows ("1   down   --") look like member rows to a
        # reader that does not notice the next command has started.
        lines = fixture_lines("huawei_s5735_eth_trunk_then_stack_topology.txt")
        trunks = runtime_parser.parse_port_channels(lines)
        self.assertEqual(len(trunks), 1)
        self.assertEqual(trunks[0]["name"], "Eth-Trunk1")
        self.assertEqual(trunks[0]["status"], "up")
        self.assertEqual(trunks[0]["members"], "10GE1/0/2, 10GE1/0/3")

    def test_two_trunks_in_one_command_are_both_kept(self):
        lines = """
<SW>display eth-trunk
Eth-Trunk1's state information is:
Operating Status: up            Number Of Up Ports In Trunk: 1
ActorPortName              Status   PortType PortPri PortNo PortKey PortState Weight
10GE1/0/1                  Selected 1GE      32768   1      305     10100010  1
Eth-Trunk2's state information is:
Operating Status: down          Number Of Up Ports In Trunk: 0
ActorPortName              Status   PortType PortPri PortNo PortKey PortState Weight
10GE1/0/2                  Unselect 1GE      32768   1      306     10100010  1
<SW>display stack topology
1          down   --         down   --
""".strip().splitlines()
        trunks = {t["name"]: t for t in runtime_parser.parse_port_channels(lines)}
        self.assertEqual(sorted(trunks), ["Eth-Trunk1", "Eth-Trunk2"])
        self.assertEqual(trunks["Eth-Trunk1"]["members"], "10GE1/0/1")
        self.assertEqual(trunks["Eth-Trunk2"]["members"], "10GE1/0/2")


class MaskCaptureTest(unittest.TestCase):
    """The masking tool is what keeps raw captures out of the repository, so
    its guarantees are tested too."""

    @classmethod
    def setUpClass(cls):
        cls.mask = _load_mask_module()

    def test_pseudonym_keeps_length_and_character_classes(self):
        name = "Core-SW_01.example"
        fake = self.mask.pseudonym(name)
        self.assertEqual(len(fake), len(name))
        self.assertNotEqual(fake, name)
        for original, replaced in zip(name, fake):
            self.assertEqual(original.isupper(), replaced.isupper())
            self.assertEqual(original.isdigit(), replaced.isdigit())
            if not original.isalnum():
                self.assertEqual(original, replaced)

    def test_masking_is_deterministic(self):
        text = "SW-A#show version\nIP 10.1.2.3 mac aabb.ccdd.eeff\n"
        self.assertEqual(self.mask.mask(text, [])[0], self.mask.mask(text, [])[0])

    def test_truncated_device_id_gets_the_matching_pseudonym_prefix(self):
        text = (
            "SW-A#show lldp neighbors detail\n"
            "System Name: LONG-NEIGHBOR-NAME-01\n"
            "SW-A#show lldp neighbors\n"
            "LONG-NEIGHBOR-NAME-Gi1/0/1\n"
        )
        masked, _ = self.mask.mask(text, [])
        full = self.mask.pseudonym("LONG-NEIGHBOR-NAME-01")
        self.assertIn(full[:19] + "Gi1/0/1", masked)

    def test_ip_mac_secret_and_serial_are_replaced_and_masks_are_kept(self):
        text = (
            "ip address 192.168.7.9 255.255.255.0\n"
            "chassis aabb.ccdd.eeff / aa:bb:cc:dd:ee:ff\n"
            "snmp-server community s3cr3t RO\n"
            "SN: FDO2218E1CQ\n"
            "Processor board ID FOC0000ABCD\n"
        )
        masked, _ = self.mask.mask(text, [])
        self.assertNotIn("192.168.7.9", masked)
        self.assertIn("255.255.255.0", masked)
        self.assertNotIn("aabb.ccdd.eeff", masked.lower())
        self.assertNotIn("s3cr3t", masked)
        self.assertNotIn("FDO2218E1CQ", masked)
        self.assertNotIn("FOC0000ABCD", masked)
        self.assertIn("<REDACTED>", masked)

    def test_clock_times_and_nxos_arp_ages_are_not_masked_as_ipv6(self):
        # 00:05:47 has the shape of a short IPv6 address. Masking it rewrote the
        # Age column of an NX-OS `show ip arp` and the timestamps of a session
        # log, which are exactly the layouts the fixtures exist to keep.
        text = (
            "10.1.1.9  00:05:47  aabb.ccdd.eeff  Vlan10\n"
            "08/10/2026 14:02:40|001|TERM|001|show ip arp\n"
            "peer fe80::aabb:ccdd:eeff:1122 on Vlan10\n"
        )
        masked, _ = self.mask.mask(text, [])
        self.assertIn("00:05:47", masked)
        self.assertIn("14:02:40", masked)
        self.assertNotIn("fe80::aabb:ccdd:eeff:1122", masked.lower())

    def test_verify_flags_anything_left_behind(self):
        originals = {"names": {"CORE-SW-1"}, "ips": {"10.1.1.1"}, "macs": set()}
        self.assertEqual(self.mask.verify("clean text", originals), [])
        self.assertTrue(self.mask.verify("still core-sw-1 here", originals))

    def test_committed_fixtures_contain_no_site_names_or_management_networks(self):
        for path in FIXTURES.glob("*.txt"):
            text = path.read_text(encoding="utf-8").lower()
            for needle in ("ttc-", "ccy-", "drc-", "10.85."):
                self.assertNotIn(needle, text, f"{path.name} contains {needle}")


if __name__ == "__main__":
    unittest.main()
