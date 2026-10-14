"""Switch Analyzer Health tab (features/switch_analyzer/health.py).

Cases come from two real sources: the 11 Oct 2026 LXS case (a Huawei Eth-Trunk
stayed down because the Cisco member ports did not match Port-channel7) and the
Jalin sample captures (one core stack, four access switches, IOS XE 17.9-17.15).
The live-table fixture is a masked excerpt of the real core capture; the
configuration cases are written by hand in the same IOS XE syntax.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from features.switch_analyzer import capture_text, health
from features.switch_analyzer.service import analyze

FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"


def live_tables() -> str:
    return (FIXTURES / "cisco_c9300x_health_live_tables.txt").read_text(encoding="utf-8")


LXS_BEFORE = """\
hostname EXAMPLE-SWCO
!
interface Port-channel7
 description uplink
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/0/9
 channel-group 7 mode active
!
interface GigabitEthernet2/0/9
 channel-group 7 mode active
!
"""

LXS_AFTER = LXS_BEFORE.replace(
    " channel-group 7 mode active",
    " switchport access vlan 10\n switchport mode access\n channel-group 7 mode active",
)


def build(text: str, vendor: str = "Cisco", interfaces=None, port_channels=None, dhcp=None) -> dict:
    clean = capture_text.clean_lines(text)
    return health.build_health(clean, vendor, interfaces=interfaces or [], port_channels=port_channels if port_channels is not None else [], dhcp=dhcp)


def codes(result: dict) -> list[str]:
    return [item["code"] for item in result["findings"]]


class PortChannelMemberMatchTests(unittest.TestCase):
    """LXS: members without the Po's switchport mode / VLAN are suspended by Cisco."""

    def test_members_that_do_not_match_the_port_channel_are_flagged(self):
        result = build(LXS_BEFORE)
        mismatches = [item for item in result["findings"] if item["code"] == "SW-LACP-002"]
        self.assertEqual(sorted(item["where"] for item in mismatches), ["Gi1/0/9", "Gi2/0/9"])
        self.assertEqual({item["severity"] for item in mismatches}, {"high"})
        self.assertIn("member dynamic auto / Po7 access", mismatches[0]["text"])
        self.assertIn("access vlan: member 1 / Po7 10", mismatches[0]["text"])
        self.assertIn("etherchannel", mismatches[0]["doc"]["url"])

    def test_members_configured_like_the_port_channel_pass(self):
        self.assertNotIn("SW-LACP-002", codes(build(LXS_AFTER)))

    def test_trunk_port_channel_compares_allowed_and_native_vlans(self):
        text = (
            "hostname X\ninterface Port-channel1\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n"
            "interface TenGigabitEthernet1/1/1\n switchport mode trunk\n switchport trunk allowed vlan 10\n channel-group 1 mode active\n"
        )
        item = next(i for i in build(text)["findings"] if i["code"] == "SW-LACP-002")
        self.assertIn("trunk allowed: member 10 / Po1 10,20", item["text"])
        self.assertEqual(item["where"], "Te1/1/1")

    def test_members_with_different_channel_group_modes(self):
        text = LXS_AFTER.replace("channel-group 7 mode active", "channel-group 7 mode passive", 1)
        self.assertIn("SW-LACP-005", codes(build(text)))


SUMMARY_SUSPENDED = """\
EX#show etherchannel summary
Group  Port-channel  Protocol    Ports
------+-------------+-----------+---------------------------
1      Po1(SU)         LACP        Gi1/0/1(P)      Gi2/0/1(P)
7      Po7(SU)         LACP        Gi1/0/9(s)      Gi2/0/9(I)
2      Po2(SD)         LACP        Gi1/0/2(D)      Gi2/0/2(D)
"""


class EtherchannelFlagTests(unittest.TestCase):
    def test_flags_are_read_per_member(self):
        flags = health.parse_etherchannel_flags(capture_text.command_outputs(capture_text.clean_lines(SUMMARY_SUSPENDED), [r"sh(?:ow)? etherchannel summary"])[0])
        self.assertEqual([m["flag"] for m in flags["Po7"]["members"]], ["s", "I"])
        self.assertEqual(flags["Po7"]["protocol"], "LACP")
        self.assertEqual(flags["Po2"]["state"], "SD")

    def test_suspended_and_standalone_members_are_findings_bundled_and_unused_are_not(self):
        result = build("hostname EX\n" + SUMMARY_SUSPENDED)
        by_where = {item["where"]: item for item in result["findings"] if item["code"] == "SW-LACP-001"}
        self.assertEqual(sorted(by_where), ["Gi1/0/9", "Gi2/0/9"])
        self.assertEqual(by_where["Gi1/0/9"]["severity"], "high")
        self.assertIn("suspended", by_where["Gi1/0/9"]["title"])
        self.assertEqual(by_where["Gi2/0/9"]["severity"], "medium")

    def test_real_core_capture_has_no_member_findings(self):
        result = build(live_tables())
        self.assertFalse([c for c in codes(result) if c.startswith("SW-LACP")])

    def test_member_text_as_the_service_builds_it(self):
        rows = [{"name": "Po1", "members": "Twe1/0/4, Twe2/0/4"}]
        build(live_tables(), port_channels=rows)
        self.assertEqual(rows[0]["lacp_partner"], "0000.5e00.5301")

    def test_real_core_analysis_shows_partner_on_the_port_channel_row(self):
        result = analyze(live_tables() + "\nEX#show running-config\nhostname EX\ninterface Port-channel1\n description x\n", filename="core.txt")
        row = next(item for item in result["port_channels"] if item["name"] == "Po1")
        self.assertEqual(row["lacp_partner"], "0000.5e00.5301")
        self.assertEqual([m["flag"] for m in row["member_states"]], ["P", "P"])

    def test_port_channel_rows_get_member_state_and_partner(self):
        rows = [{"name": "Po1", "members": ["Twe1/0/4", "Twe2/0/4"]}]
        build(live_tables(), port_channels=rows)
        self.assertEqual([m["flag"] for m in rows[0]["member_states"]], ["P", "P"])
        self.assertEqual(rows[0]["lacp_partner"], "0000.5e00.5301")


class LacpNeighborTests(unittest.TestCase):
    def test_real_neighbor_table(self):
        clean = capture_text.clean_lines(live_tables())
        rows = health.parse_lacp_neighbors(capture_text.command_outputs(clean, [r"sh(?:ow)? lacp neighbor"])[0])
        self.assertGreaterEqual(len(rows), 4)
        self.assertTrue(all(row["healthy"] and row["state"] == "0x3d" for row in rows))
        self.assertEqual(rows[0]["state_bits"], "Activity, Aggregation, Synchronization, Collecting, Distributing")

    def test_unhealthy_and_absent_partners(self):
        text = (
            "EX#show lacp neighbor\nChannel group 7 neighbors\n\n"
            "Port          Flags  Priority  Dev ID          Age  key    Key    Number  State\n"
            "Gi1/0/9       SA     32768     0000.0000.0000  0s   0x0    0x0    0x0     0x45\n"
            "Gi2/0/9       SA     32768     0000.5e00.0001  4s   0x0    0x2    0x132   0x05\n"
        )
        found = build("hostname EX\n" + text)
        self.assertEqual(sorted(i["where"] for i in found["findings"] if i["code"] == "SW-LACP-004"), ["Gi1/0/9"])
        self.assertEqual([i["where"] for i in found["findings"] if i["code"] == "SW-LACP-003"], ["Gi2/0/9"])


class SpanningTreeTests(unittest.TestCase):
    def test_real_summary(self):
        result = build(live_tables())
        self.assertEqual(result["stp"]["mode"], "rapid-pvst")
        self.assertEqual(result["stp"]["root_vlan_count"], 6)
        self.assertEqual(result["stp"]["bpduguard_default"], "disabled")
        self.assertTrue(result["stp"]["root_for"].startswith("VLAN0160"))

    def test_wrapped_root_list_is_joined(self):
        lines = ["Switch is in rapid-pvst mode", "Root bridge for: VLAN0001-VLAN0003, VLAN0010", "  VLAN0020-VLAN0021", "Extended system ID                      is enabled"]
        self.assertEqual(health.parse_stp_summary(lines)["root_vlan_count"], 6)

    def test_root_without_priority_is_flagged_and_with_priority_is_not(self):
        text = "EX#show running-config\nhostname EX\nspanning-tree mode rapid-pvst\n!\nEX#show spanning-tree summary\nSwitch is in rapid-pvst mode\nRoot bridge for: VLAN0001-VLAN0002\n"
        self.assertIn("SW-STP-001", codes(build(text)))
        fixed = text.replace("spanning-tree mode rapid-pvst\n", "spanning-tree mode rapid-pvst\nspanning-tree vlan 1-2 priority 4096\n")
        self.assertNotIn("SW-STP-001", codes(build(fixed)))

    def test_portfast_without_bpdu_guard(self):
        base = "hostname EX\ninterface GigabitEthernet1/0/1\n switchport mode access\n spanning-tree portfast\n"
        self.assertIn("SW-STP-002", codes(build(base)))
        self.assertNotIn("SW-STP-002", codes(build(base + " spanning-tree bpduguard enable\n")))
        self.assertNotIn("SW-STP-002", codes(build("spanning-tree portfast bpduguard default\n" + base)))


MANAGEMENT = """\
hostname EX
aaa new-model
enable password cisco123
username admin privilege 15 password 7 0822455D0A16
username ops privilege 15 secret 5 $1$abcd$hashhashhash
snmp-server community very-private-name RW
snmp-server community other-name RO
ip http server
ip http secure-server
ntp server 192.0.2.1
interface GigabitEthernet1/0/1
 switchport mode access
interface GigabitEthernet1/0/24
 switchport mode trunk
"""


class ManagementTests(unittest.TestCase):
    def test_rules_fire_on_the_lines_that_exist(self):
        result = build(MANAGEMENT, interfaces=[{"name": "Gi1/0/1", "mode": "access"}])
        got = set(codes(result))
        self.assertTrue({"SW-USER-001", "SW-USER-002", "SW-ENA-001", "SW-HTTP-001", "SW-SNMP-001", "SW-LOG-001", "SW-NTP-001", "SW-TRK-001", "SW-STORM-001", "SW-SSH-001", "SW-DHCP-001"} <= got)
        self.assertNotIn("SW-AAA-001", got)
        snmp = next(i for i in result["findings"] if i["code"] == "SW-SNMP-001")
        self.assertEqual(snmp["severity"], "medium")  # one community is read-write
        self.assertIn("1 read-write", snmp["title"])

    def test_no_secret_value_is_ever_in_the_output(self):
        blob = json.dumps(build(MANAGEMENT))
        for secret in ("very-private-name", "other-name", "0822455D0A16", "$1$abcd$hashhashhash", "cisco123"):
            self.assertNotIn(secret, blob)

    def test_clean_configuration_has_no_management_findings(self):
        text = (
            "hostname EX\naaa new-model\nusername a privilege 15 secret 9 $9$x\nenable secret 9 $9$y\nip ssh version 2\nno ip http server\n"
            "ip http secure-server\nntp server 192.0.2.1\nntp server 192.0.2.2\nlogging host 192.0.2.9\nip dhcp snooping\n"
            "interface GigabitEthernet1/0/1\n switchport mode access\n storm-control broadcast level 5\n"
            "interface GigabitEthernet1/0/24\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n"
        )
        # `ip dhcp snooping` is read by the full analyzer (dhcp dict); build() is told directly.
        result = build(text, dhcp={"pools": [], "snooping": {"enabled": True}})
        self.assertEqual(codes(result), [])

    def test_dhcp_pools_without_snooping_is_medium(self):
        result = build("hostname EX\ninterface GigabitEthernet1/0/1\n", dhcp={"pools": [{"name": "a"}, {"name": "b"}], "snooping": {"enabled": False}})
        item = next(i for i in result["findings"] if i["code"] == "SW-DHCP-001")
        self.assertEqual((item["severity"], "2 pool(s)" in item["title"]), ("medium", True))


class DeviceTests(unittest.TestCase):
    def test_real_environment_table(self):
        env = build(live_tables())["environment"]
        self.assertEqual((len(env["power_supplies"]), env["problems"]), (4, 0))  # a 2-member stack: 1A 1B 2A 2B
        self.assertGreaterEqual(len(env["sensors"]), 10)
        self.assertEqual(env["fans"][0]["state"], "OK")
        self.assertIn("PS1 Vout", [s["name"] for s in env["sensors"]])

    def test_bad_power_supply_fan_and_sensor_are_findings(self):
        text = (
            "EX#show env all\nSensor List: Environmental Monitoring\n"
            " Sensor          Location        State               Reading       Range(min-max)\n"
            " SYSTEM INLET    1               RED                 80 Celsius   0 - 56\n\n"
            "Switch   FAN     Speed   State   Airflow direction\n---------------------------------------------------\n"
            "  1       1     0         FAULTY  Front to Back\n\n"
            "SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts\n--  ------------------  ----------  ---------------  -------  -------  -----\n"
            "1A  PWR-C1-715WAC-P     FOC0000X000  Not Present     Bad      n/a      715\n"
        )
        self.assertEqual(sorted(codes(build("hostname EX\n" + text))), ["SW-ENV-001", "SW-ENV-002", "SW-ENV-003"])

    def test_licence_and_uptime(self):
        result = build(live_tables())
        self.assertEqual(result["licence"]["smart_account"], "Example Org")
        self.assertEqual([row["status"] for row in result["licence"]["licenses"]], ["IN USE", "IN USE", "NOT IN USE"])
        self.assertEqual(result["software"]["uptime_days"], 365 + 12 * 7 + 2)
        self.assertIn("SW-VER-001", codes(result))
        self.assertNotIn("SW-LIC-001", codes(result))

    def test_licence_in_use_without_smart_account(self):
        text = "EX#show license summary\nAccount Information:\n  Smart Account: <none>\n  Virtual Account: <none>\n\nLicense Usage:\n  License                 Entitlement Tag               Count Status\n  -----------------------------------------------------------------------------\n  air-network-advantage   (DNA_NWStack)                     7 IN USE\n"
        self.assertIn("SW-LIC-001", codes(build("hostname EX\n" + text)))


class ScopeAndCaptureTests(unittest.TestCase):
    def test_huawei_and_aruba_have_their_own_scope_and_no_cisco_rules(self):
        for vendor, scope in (("Huawei", "Huawei VRP / YunShan OS"), ("Aruba", "ArubaOS-Switch")):
            result = build("sysname X\n", vendor=vendor)
            self.assertTrue(result["supported"])
            self.assertEqual(result["scope"], scope)
            self.assertEqual(result["findings"], [])
            self.assertNotIn("Cisco IOS", result["note"])

    def test_a_platform_with_no_health_rules_is_reported_unsupported(self):
        result = build("hostname X\n", vendor="Juniper")
        self.assertFalse(result["supported"])
        self.assertEqual(result["findings"], [])
        self.assertIn("Cisco IOS", result["note"])

    def test_nexus_is_judged_by_the_nxos_rules_not_the_ios_ones(self):
        result = build("Cisco Nexus Operating System (NX-OS) Software\nhostname N9K\n")
        self.assertTrue(result["supported"])
        self.assertEqual(result["scope"], "Cisco NX-OS")
        self.assertIn("show vpc", {item["command"] for item in result["capture"]["missing"]})

    def test_missing_commands_are_listed_not_assumed_healthy(self):
        result = build("hostname EX\ninterface GigabitEthernet1/0/1\n")
        missing = {item["command"] for item in result["capture"]["missing"]}
        self.assertTrue({"show spanning-tree summary", "show lacp neighbor", "show env all", "show mac address-table"} <= missing)
        self.assertEqual(result["environment"]["problems"], 0)
        self.assertEqual(result["lacp"], [])

    def test_no_running_config_skips_configuration_rules(self):
        result = build(live_tables())
        self.assertFalse(result["capture"]["config_found"])
        self.assertEqual(result["capture"]["missing"][0]["command"], "show running-config")
        self.assertNotIn("SW-AAA-001", codes(result))

    def test_findings_are_sorted_most_severe_first(self):
        order = [{"high": 0, "medium": 1, "low": 2, "info": 3}[i["severity"]] for i in build(MANAGEMENT + SUMMARY_SUSPENDED)["findings"]]
        self.assertEqual(order, sorted(order))

    def test_every_documentation_link_is_a_cisco_https_url(self):
        for item in build(MANAGEMENT + LXS_BEFORE)["findings"]:
            if "doc" in item:
                self.assertTrue(item["doc"]["url"].startswith("https://www.cisco.com/"), item["code"])


class ServiceIntegrationTests(unittest.TestCase):
    def test_analyze_returns_health_and_cards(self):
        result = analyze(LXS_BEFORE, filename="lxs.txt")
        self.assertIn("SW-LACP-002", [i["code"] for i in result["health"]["findings"]])
        self.assertEqual(result["cards"]["health_findings"], len(result["health"]["findings"]))
        self.assertGreaterEqual(result["cards"]["health_attention"], 2)

    def test_uncaptured_tables_are_marked_not_captured(self):
        bare = analyze("hostname EX\ninterface GigabitEthernet1/0/1\n", filename="bare.txt")
        self.assertFalse(bare["table_checks"]["mac"]["captured"])
        self.assertFalse(bare["table_checks"]["arp"]["captured"])
        mac = "EX#show mac address-table\n          Mac Address Table\n-------------------------------------------\n\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n  10    0000.5e00.0001    DYNAMIC     Gi1/0/1\nTotal Mac Addresses for this criterion: 1\n"
        got = analyze("hostname EX\n" + mac, filename="m.txt")
        self.assertTrue(got["table_checks"]["mac"]["captured"])
        self.assertFalse(got["table_checks"]["arp"]["captured"])

    def test_huawei_capture_without_health_commands_has_no_health_data(self):
        result = analyze("sysname EX-S5735\n#\nvlan batch 10\n#\n", filename="h.txt", vendor="Huawei")
        self.assertTrue(result["health"]["supported"])
        self.assertEqual(result["cards"]["health_findings"], 0)
        self.assertEqual(result["health"]["software"], {})
        self.assertIn("display version", {item["command"] for item in result["health"]["capture"]["missing"]})
        self.assertFalse(next(t for t in result["tabs"] if t["key"] == "health")["has"])


if __name__ == "__main__":
    unittest.main()
