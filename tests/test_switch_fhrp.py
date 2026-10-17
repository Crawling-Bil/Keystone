"""HSRP / VRRP groups (features/switch_analyzer/fhrp.py).

The NX-OS and Huawei layouts are those of real captures (a Nexus 9000 pair with ``hsrp <group>`` blocks, a Huawei S5755 pair with ``vrrp vrid`` and ``display vrrp``);
every address, name and key below is invented.  The IOS ``standby`` form follows the published syntax and has no capture behind it.
"""
from __future__ import annotations

import json
import unittest

from features.switch_analyzer import capture_text, fhrp
from features.switch_analyzer.service import analyze

NXOS = """NXSW1# show running-config
hostname NXSW1
feature hsrp
feature interface-vlan

interface Vlan10
  description Users
  no shutdown
  ip address 192.0.2.2/24
  hsrp version 2
  hsrp 10
    name USERS-GW
    preempt delay minimum 60
    priority 110
    timers msec 250 msec 750
    authentication md5 key-string 7 SUPERSECRETKEY
    track 5 decrement 20
    ip 192.0.2.1

interface Vlan20
  no shutdown
  ip address 198.51.100.2/24
  hsrp 20
    ip 198.51.100.1
    ip 198.51.100.254 secondary
  hsrp 21 ipv6
    ip autoconfig

interface Vlan30
  no shutdown

NXSW1#
"""

HUAWEI = """<SW1>display current-configuration
#
sysname SW1
#
interface Vlanif201
 description Servers
 ip address 192.0.2.2 255.255.255.0
 vrrp vrid 201 virtual-ip 192.0.2.1
 vrrp vrid 201 priority 120
 vrrp vrid 201 authentication-mode md5 %^%#SECRETCIPHER%^%#
 undo vrrp vrid 201 preempt-mode
#
interface Vlanif205
 ip address 198.51.100.2 255.255.255.0
 vrrp vrid 205 virtual-ip 198.51.100.1
#
return
<SW1>display vrrp
Type:
  N: Normal
  A: Administrator
  M: Member
  L: Load-Balance
  LM: Load-Balance-Member
  H: Hrp
Total:3     Master:1    Backup:1    Non-active:0
VRID State       Interface               Type    Virtual IP
----------------------------------------------------------------
 201 Master      Vlanif201               N       192.0.2.1
 205 Backup      Vlanif205               N       198.51.100.1
 300 Master      Vlanif300               N       203.0.113.1
<SW1>
"""

IOS = """SW1#show running-config
hostname SW1
!
interface Vlan10
 ip address 192.0.2.2 255.255.255.0
 standby version 2
 standby 10 ip 192.0.2.1
 standby 10 priority 110
 standby 10 preempt delay minimum 30
 standby 10 timers 1 3
 standby 10 authentication md5 key-string 7 SUPERSECRETKEY
 standby 10 track 1 decrement 15
 standby 10 name GW10
 standby ip 192.0.2.254
 vrrp 7 ip 192.0.2.7
 vrrp 7 priority 150
!
interface Vlan11
 ip address 192.0.2.130 255.255.255.128
!
end
"""


def groups(text: str) -> dict[tuple[str, str, str], dict]:
    return {(g["interface"], g["protocol"], g["group"]): g for g in fhrp.config_groups(capture_text.clean_lines(text))}


class ConfigurationTests(unittest.TestCase):
    def test_nxos_group_block_is_read_with_its_sub_commands(self):
        g = groups(NXOS)[("Vlan10", "HSRP", "10")]
        self.assertEqual((g["virtual_ip"], g["priority"], g["name"], g["version"]), (["192.0.2.1"], "110", "USERS-GW", "2"))
        self.assertEqual((g["preempt"], g["timers"], g["track"]), ("on (delay minimum 60)", "250 ms / 750 ms", ["5 decrement 20"]))

    def test_the_authentication_type_is_kept_and_the_key_never(self):
        g = groups(NXOS)[("Vlan10", "HSRP", "10")]
        self.assertEqual(g["auth"], "md5")
        result = analyze(NXOS, filename="nx.txt")
        self.assertNotIn("SUPERSECRETKEY", json.dumps(result["extra_tables"]))
        self.assertNotIn("SECRETCIPHER", json.dumps(analyze(HUAWEI, filename="hw.txt")["extra_tables"]))

    def test_each_group_has_its_own_options_and_a_lone_command_ends_the_group(self):
        found = groups(NXOS)
        self.assertEqual(found[("Vlan20", "HSRP", "20")]["virtual_ip"], ["198.51.100.1", "198.51.100.254 (secondary)"])
        self.assertEqual(found[("Vlan20", "HSRP", "20")]["priority"], "")             # not configured: blank, never a default of our own
        self.assertEqual(found[("Vlan20", "HSRP", "21")]["family"], "ipv6")
        self.assertEqual(found[("Vlan20", "HSRP", "21")]["virtual_ip"], ["autoconfig"])
        self.assertEqual(found[("Vlan20", "HSRP", "20")]["version"], "1")               # the Cisco guide: version 1 is the default
        self.assertNotIn(("Vlan30", "HSRP", "0"), found)

    def test_ios_standby_and_vrrp_lines(self):
        found = groups(IOS)
        hsrp = found[("Vlan10", "HSRP", "10")]
        self.assertEqual((hsrp["virtual_ip"], hsrp["priority"], hsrp["timers"], hsrp["auth"], hsrp["name"], hsrp["version"]), (["192.0.2.1"], "110", "1 s / 3 s", "md5", "GW10", "2"))
        self.assertEqual(found[("Vlan10", "HSRP", "0")]["virtual_ip"], ["192.0.2.254"])          # `standby ip` without a group number is group 0
        self.assertEqual((found[("Vlan10", "VRRP", "7")]["virtual_ip"], found[("Vlan10", "VRRP", "7")]["priority"]), (["192.0.2.7"], "150"))
        self.assertNotIn("SUPERSECRETKEY", json.dumps(analyze(IOS, filename="ios.txt")["extra_tables"]))

    def test_huawei_vrrp_lines(self):
        g = groups(HUAWEI)[("Vlanif201", "VRRP", "201")]
        self.assertEqual((g["virtual_ip"], g["priority"], g["preempt"], g["auth"]), (["192.0.2.1"], "120", "off", "md5"))
        self.assertEqual(groups(HUAWEI)[("Vlanif205", "VRRP", "205")]["preempt"], "")

    def test_the_same_group_printed_twice_is_one_row(self):
        self.assertEqual(len(fhrp.config_groups(capture_text.clean_lines(NXOS + NXOS))), len(fhrp.config_groups(capture_text.clean_lines(NXOS))))

    def test_a_device_without_first_hop_redundancy_gets_no_table(self):
        result = analyze("hostname SW9\ninterface Vlan1\n ip address 192.0.2.9 255.255.255.0\n!\n", filename="s.txt")
        self.assertFalse([t for t in result["extra_tables"] if t["id"] == "fhrp-groups"])


class LiveStateTests(unittest.TestCase):
    def test_display_vrrp_rows(self):
        rows = fhrp.parse_display_vrrp(capture_text.command_outputs(capture_text.clean_lines(HUAWEI), [r"display vrrp"])[0])
        self.assertEqual([(r["group"], r["state"], r["interface"], r["virtual_ip"]) for r in rows],
                         [("201", "Master", "Vlanif201", "192.0.2.1"), ("205", "Backup", "Vlanif205", "198.51.100.1"), ("300", "Master", "Vlanif300", "203.0.113.1")])

    def test_state_is_merged_into_the_configured_groups_and_a_live_only_group_is_added(self):
        result = analyze(HUAWEI, filename="hw.txt")
        table = next(t for t in result["extra_tables"] if t["id"] == "fhrp-groups")
        self.assertEqual(table["tab"], "routing")
        by_group = {row["group"]: row for row in table["rows"]}
        self.assertEqual((by_group["201"]["state"], by_group["205"]["state"], by_group["300"]["state"]), ("Master", "Backup", "Master"))
        self.assertEqual(by_group["300"]["priority"], "—")
        self.assertIn("state", [c["key"] for c in table["columns"]])
        self.assertEqual((result["extras"]["fhrp"], result["extras"]["fhrp_live"]), (3, 3))

    def test_the_state_column_is_left_out_without_display_vrrp(self):
        table = next(t for t in analyze(NXOS, filename="nx.txt")["extra_tables"] if t["id"] == "fhrp-groups")
        self.assertNotIn("state", [c["key"] for c in table["columns"]])
        keys = [c["key"] for c in table["columns"]]
        self.assertTrue({"timers", "auth", "track", "name", "version"} <= set(keys))        # the optional columns appear when some group uses them
        huawei = next(t for t in analyze(HUAWEI, filename="hw.txt")["extra_tables"] if t["id"] == "fhrp-groups")
        self.assertFalse({"timers", "track", "name", "version"} & {c["key"] for c in huawei["columns"]})

    def test_coverage_marks_display_vrrp_and_cisco_show_standby_brief_analyzed(self):
        rows = {r["command"]: r for r in analyze(HUAWEI, filename="hw.txt")["coverage"]["rows"]}
        self.assertEqual((rows["display vrrp"]["status"], rows["display vrrp"]["tab"]), ("analyzed", "routing"))
        text = IOS + "SW1#show standby brief\nInterface   Grp  Pri P State   Active          Standby         Virtual IP\nVl10        10   110 P Active  local           unknown         192.0.2.1\nSW1#\n"
        row = {r["command"]: r for r in analyze(text, filename="ios.txt")["coverage"]["rows"]}["show standby brief"]
        self.assertEqual((row["status"], row["tab"]), ("analyzed", "routing"))      # fhrp_live reads the brief form since v5


if __name__ == "__main__":
    unittest.main()
