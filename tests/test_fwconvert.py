"""FortiGate <-> PAN-OS converter (``converter_engine/fwconvert``): both directions, the loss report, secrets, formats and golden output.

Synthetic configurations only (documentation addresses, invented names).  The golden files in ``tests/fixtures/firewall/golden`` are the reviewed output; to refresh them after a
deliberate change run ``UPDATE_GOLDEN=1 python -m unittest tests.test_fwconvert`` and read the diff.
"""

from __future__ import annotations

import os
import random
import re
import tempfile
import unittest
from pathlib import Path

from features.configuration_studio.converter_engine.fwconvert import convert
from features.configuration_studio.converter_engine.fwconvert.convert import detect
from features.configuration_studio.converter_engine.fwconvert.pan_read import PNode, tree_of
from features.configuration_studio.converter_engine.parsers.firewall.paloalto import PaloAltoFirewallParser

FIX = Path(__file__).parent / "fixtures" / "firewall"
GOLD = FIX / "golden"
FORTI = (FIX / "fwconvert_fortigate_synthetic.conf").read_text()
PAN = (FIX / "fwconvert_panos_synthetic.txt").read_text()
PAN_EDGES = (FIX / "fwconvert_panos_edges_synthetic.txt").read_text()
CURLY = (FIX / "panos_cli_network_synthetic.txt").read_text()


def lines(text: str) -> list[str]:
    return [x for x in text.splitlines() if x.strip()]


def rows(result, status=None):
    return [r for r in result.report.to_rows() if status is None or r["status"] == status]


def messages(result, status=None):
    return [r["message"] for r in rows(result, status)]


class Golden(unittest.TestCase):
    def check(self, name: str, actual: str) -> None:
        path = GOLD / name
        if os.environ.get("UPDATE_GOLDEN"):
            path.write_text(actual, newline="\n")
        self.assertTrue(path.exists(), f"missing golden file {name}; run with UPDATE_GOLDEN=1")
        self.assertEqual(path.read_text().replace("\r\n", "\n"), actual.replace("\r\n", "\n"))

    def test_forti_to_pan_output(self):
        self.check("forti_to_pan.txt", convert(FORTI, "fortigate", "panos").output)

    def test_forti_to_pan_report(self):
        self.check("forti_to_pan_report.txt", convert(FORTI, "fortigate", "panos").report.to_text())

    def test_pan_to_forti_output(self):
        self.check("pan_to_forti.txt", convert(PAN, "panos", "fortigate").output)

    def test_pan_to_forti_report(self):
        self.check("pan_to_forti_report.txt", convert(PAN, "panos", "fortigate").report.to_text())

    def test_pan_edges_to_forti_output(self):
        self.check("pan_edges_to_forti.txt", convert(PAN_EDGES, "panos", "fortigate").output)

    def test_pan_edges_to_forti_report(self):
        self.check("pan_edges_to_forti_report.txt", convert(PAN_EDGES, "panos", "fortigate").report.to_text())

    def test_forti_edges_to_pan_output(self):
        self.check("forti_edges_to_pan.txt", "\n".join(convert(x, "fortigate", "panos").output for x in (EDGE_POLICIES, EDGE_NAT, EDGE_ROUTING_VPN)))

    def test_forti_edges_to_pan_report(self):
        self.check("forti_edges_to_pan_report.txt", "\n".join(convert(x, "fortigate", "panos").report.to_text() for x in (EDGE_POLICIES, EDGE_NAT, EDGE_ROUTING_VPN)))


class FortiToPan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = convert(FORTI, "fortigate", "panos")
        cls.out = cls.result.output
        cls.set = set(lines(cls.out))

    def has(self, line: str):
        self.assertIn(line, self.set)

    def test_ok(self):
        self.assertTrue(self.result.ok, self.result.error)

    def test_masks_are_prefix_lengths(self):
        self.has("set network interface ethernet ethernet1/1 layer3 ip 203.0.113.2/30")
        self.has("set address LAN-NET ip-netmask 10.10.0.0/24")
        self.has("set address PARTNER-NET ip-netmask 10.60.0.0/16")
        self.has("set network virtual-router default routing-table ip static-route route-2 destination 10.50.0.0/16")
        self.assertNotIn("/32 ", " ".join(x for x in self.set if "10.60.0.0" in x))

    def test_vlan_becomes_subinterface_of_its_parent(self):
        self.has("set network interface ethernet ethernet1/2 layer3 units ethernet1/2.30 tag 30")
        self.has("set network interface ethernet ethernet1/2 layer3 units ethernet1/2.30 ip 10.30.0.1/24")
        self.has("set zone INSIDE network layer3 [ ethernet1/2 ethernet1/2.30 ]")

    def test_aggregate_members_and_lacp(self):
        self.has("set network interface ethernet ethernet1/4 aggregate-group ae1")
        self.has("set network interface ethernet ethernet1/5 aggregate-group ae1")
        self.has("set network interface aggregate-ethernet ae1 layer3 lacp mode active")

    def test_vip_is_destination_nat_and_rule_keeps_external_address(self):
        self.has("set rulebase security rules WAN-to-WEB destination [ WEB-VIP ]")
        self.has("set rulebase security rules WAN-to-WEB to [ port3 ]")
        self.has("set rulebase nat rules WEB-VIP destination-translation translated-address 10.20.0.10")
        self.has("set rulebase nat rules WEB-VIP destination-translation translated-port 8443")
        self.assertNotIn("set rulebase security rules WAN-to-WEB disabled yes", self.set)         # the VIP is a known address, the rule is not widened by it

    def test_no_nat_rule_is_in_front_of_the_overlapping_nat_rule(self):
        order = [x for x in lines(self.out) if x.startswith("set rulebase nat rules") and " from " in x]
        names = [x.split()[4] for x in order]
        self.assertLess(names.index("nonat-To-partner"), names.index("nat-LAN-to-WAN"))

    def test_policies_that_lost_a_restriction_are_disabled(self):
        self.has("set rulebase security rules Office-hours disabled yes")      # schedule
        self.has("set rulebase security rules Admins disabled yes")            # users (and disabled in the source)
        self.assertNotIn("set rulebase security rules LAN-to-WAN disabled yes", self.set)
        self.assertTrue(any("Written DISABLED" in m and "schedule" in m for m in messages(self.result, "Needs review")))

    def test_disable_widened_false_keeps_rule_enabled(self):
        r = convert(FORTI, "fortigate", "panos", disable_widened=False)
        self.assertNotIn("set rulebase security rules Office-hours disabled yes", r.output)
        self.assertIn("set rulebase security rules Admins disabled yes", r.output)         # still disabled in the source

    def test_icmp_service_becomes_application(self):
        self.has("set rulebase security rules LAN-to-WAN-apps application [ ping ]")
        self.has("set rulebase security rules LAN-to-WAN-apps service [ application-default ]")

    def test_nat_rule_with_icmp_matches_any_service(self):
        self.has("set rulebase nat rules nat-LAN-to-WAN service any")

    def test_ip_pool_translation(self):
        self.has("set rulebase nat rules nat-DMZ-out-pool source-translation dynamic-ip-and-port translated-address [ 203.0.113.10 ]")

    def test_geography_address_is_a_region_in_the_rule(self):
        self.has("set rulebase security rules Block-geo source [ KP ]")
        self.has("set rulebase security rules Block-geo action drop")

    def test_service_with_two_protocols_is_split(self):
        self.has("set service DUAL-tcp protocol tcp port 5000")
        self.has("set service DUAL-udp protocol udp port 5001")
        self.has("set service-group DUAL members [ DUAL-tcp DUAL-udp ]")
        self.has("set service APP-SRC protocol tcp source-port 1024-65535")

    def test_routes(self):
        self.has("set network virtual-router default routing-table ip static-route route-3 nexthop discard")
        self.has("set network virtual-router default routing-table ip static-route route-2 admin-dist 20")
        self.has("set network virtual-router default routing-table ip static-route route-2 metric 5")
        self.assertFalse(any("10.99.0.0" in x for x in self.set), "a disabled route must not be written")
        self.assertFalse(any("no gateway" in m for m in messages(self.result)), "a route out of a tunnel needs no next hop")

    def test_bgp_and_ospf(self):
        self.has("set network virtual-router default protocol bgp local-as 65010")
        self.has("set network virtual-router default protocol bgp peer-group EBGP peer peer-203.0.113.1 local-address interface ethernet1/1")
        self.has("set network virtual-router default protocol ospf area 0.0.0.0 interface ae1 enable yes")

    def test_vpn(self):
        self.has("set network ike gateway gw-to-branch protocol version ikev2")
        self.has("set network ike gateway gw-to-dr protocol ikev1 exchange-mode aggressive")
        self.has("set network ike crypto-profiles ike-crypto-profiles to-branch-ike encryption [ aes-256-cbc aes-128-cbc ]")
        self.has("set network ike crypto-profiles ipsec-crypto-profiles to-branch-esp dh-group group14")
        self.has("set network ike crypto-profiles ipsec-crypto-profiles to-dr-esp dh-group no-pfs")
        self.has("set network tunnel ipsec to-branch auto-key proxy-id proxy-1 local 10.10.0.0/24")
        self.has("set network tunnel ipsec to-branch auto-key proxy-id proxy-2 remote 10.60.0.0/16")

    def test_pre_shared_key_is_never_exported(self):
        self.assertNotIn("AAAAAAAA", self.out)
        self.assertNotIn("BBBBBBBB", self.out)
        self.assertEqual(self.out.count('pre-shared-key key "REPLACE-ME"'), 2)

    def test_unconvertible_things_are_reported_not_dropped_silently(self):
        text = " ".join(messages(self.result, "Not converted"))
        self.assertIn("IPv6 policies", text)
        self.assertIn("mac", text)
        self.assertIn("Management", text)

    def test_summary_counts_add_up(self):
        s = self.result.report.summary()
        self.assertEqual(s["policies"]["read"], 8)
        self.assertEqual(s["vpn"]["read"], 2)
        self.assertEqual(s["vpn"]["written"], 2)

    def test_csv_has_header_and_documentation_links(self):
        text = self.result.report.to_csv()
        self.assertTrue(text.startswith("layer,kind,name,status,message,documentation\r\n"))
        for r in rows(self.result):
            self.assertTrue(r["documentation"].startswith("https://") or r["documentation"] == "", r)

    def test_every_report_row_has_a_documentation_link_for_a_problem(self):
        for r in rows(self.result):
            if r["status"] in ("Needs review", "Not converted"):
                self.assertTrue(r["documentation"].startswith("https://"), r)

    def test_parses_back_with_the_pan_os_parser(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "out.txt"
            path.write_text(self.out)
            c = PaloAltoFirewallParser().parse_file(str(path))
        self.assertEqual(len(c.security_rules), 9)
        self.assertEqual(len(c.nat_rules), 4)
        self.assertEqual({z.name for z in c.zones}, {"INSIDE", "wan1", "port3", "to-branch"})
        sub = c.find_interface("ethernet1/2.30")
        self.assertEqual((sub.tag, sub.parent_interface), (30, "ethernet1/2"))
        self.assertEqual(c.find_interface("ethernet1/1").ip_addresses, ["203.0.113.2/30"])
        self.assertEqual({t.name for t in c.ipsec_tunnels}, {"to-branch", "to-dr"})
        self.assertEqual({g.version for g in c.ike_gateways}, {"ikev1", "ikev2"})
        self.assertEqual(len(c.virtual_routers[0].static_routes), 3)

    def test_layer_selection_pulls_in_what_is_needed(self):
        r = convert(FORTI, "fortigate", "panos", layers=["policies"])
        self.assertIn("set rulebase security rules To-partner", r.output)
        self.assertIn("set zone INSIDE", r.output)            # interfaces are added because rules need zones
        self.assertNotIn("set network ike", r.output)
        self.assertNotIn("set rulebase nat", r.output)
        self.assertTrue(any("needed by" in i.name for i in r.report.items))

    def test_objects_only(self):
        r = convert(FORTI, "fortigate", "panos", layers=["objects"])
        self.assertIn("set address LAN-NET", r.output)
        self.assertNotIn("set rulebase security", r.output)

    def test_interface_map_overrides_the_plan(self):
        r = convert(FORTI, "fortigate", "panos", interface_map={"wan1": "ethernet1/9", "port2": "ethernet1/10"})
        self.assertIn("set network interface ethernet ethernet1/9 layer3 ip 203.0.113.2/30", r.output)
        self.assertIn("set zone wan1 network layer3 [ ethernet1/9 ]", r.output)
        self.assertIn("set network interface ethernet ethernet1/10 layer3 ip 10.10.0.1/24", r.output)

    def test_other_fortigate_fixtures_convert(self):
        for name in ("fortigate_synthetic_7.2.conf", "fortigate_hardened_synthetic.conf", "fortigate_multivdom_synthetic.conf", "fortigate_vdom_edge_synthetic.conf", "fortigate_capture_synthetic.txt"):
            text = (FIX / name).read_text(errors="ignore")
            r = convert(text, "fortigate", "panos")
            self.assertTrue(r.ok, name)
            self.assertNotIn("ENC ", r.output, name)

    def test_secrets_of_the_larger_fixture_do_not_leak(self):
        text = (FIX / "fortigate_synthetic_7.2.conf").read_text()
        r = convert(text, "fortigate", "panos")
        for m in re.finditer(r"set (?:psksecret|password|secret) (?:ENC )?(\S+)", text):
            self.assertNotIn(m.group(1), r.output + r.report.to_text())



EDGE_POLICIES = """config system interface
    edit "port1"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        set role lan
    next
    edit "port2"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.0
        set role wan
    next
end
config firewall address
    edit "NET-A"
        set subnet 10.1.0.0 255.255.255.0
    next
end
config firewall schedule recurring
    edit "work"
        set day monday
        set start 08:00
        set end 17:00
    next
end
config firewall policy
    edit 1
        set name "sched"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "NET-A"
        set dstaddr "all"
        set action accept
        set schedule "work"
        set service "HTTPS"
    next
    edit 2
        set name "users"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "NET-A"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS"
        set groups "grp1"
    next
    edit 3
        set name "app"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "NET-A"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set application-list "default"
    next
    edit 4
        set name "isdb"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set internet-service enable
        set action accept
        set schedule "always"
    next
    edit 5
        set name "nolog"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "NET-A"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic disable
        set srcaddr-negate enable
    next
    edit 6
        set name "ghost"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "NET-A"
        set dstaddr "NOPE"
        set action accept
        set schedule "always"
        set service "NOPE-SVC"
    next
end
"""

EDGE_NAT = """config system interface
    edit "port1"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        set role lan
    next
    edit "port2"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.0
        set role wan
    next
end
config firewall address
    edit "NET-A"
        set subnet 10.1.0.0 255.255.255.0
    next
    edit "HOST-MAC"
        set type mac
        set macaddr 00:11:22:33:44:55
    next
end
config firewall ippool
    edit "POOL1"
        set startip 192.0.2.50
        set endip 192.0.2.50
    next
    edit "POOL2"
        set type one-to-one
        set startip 192.0.2.60
        set endip 192.0.2.70
    next
end
config firewall vip
    edit "VIP-WEB"
        set extip 192.0.2.10
        set extintf "port2"
        set mappedip "10.1.0.10"
        set portforward enable
        set protocol udp
        set extport 5000
        set mappedport 6000
    next
    edit "VIP-RANGE"
        set extip 192.0.2.20-192.0.2.22
        set extintf "any"
        set mappedip "10.1.0.20-10.1.0.22"
        set src-filter "1.1.1.0/24"
    next
    edit "VIP-LB"
        set type load-balance
        set extip 192.0.2.30
        set mappedip "10.1.0.30"
    next
    edit "VIP-NOMAP"
        set extip 192.0.2.40
    next
end
config firewall policy
    edit 1
        set name "out"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "NET-A"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
        set ippool enable
        set poolname "POOL1"
    next
    edit 2
        set name "out2"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "NET-A"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
        set ippool enable
        set poolname "POOL2"
    next
    edit 3
        set name "in"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "VIP-WEB"
        set action accept
        set schedule "always"
        set service "ALL"
    next
    edit 4
        set name "noicon"
        set action accept
        set srcaddr "HOST-MAC"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
    next
end
"""


def rule_lines(out: str, name: str, section: str = "security") -> list[str]:
    prefix = f"set rulebase {section} rules {name} "
    return [x for x in out.splitlines() if x.startswith(prefix)]


class PolicyEdges(unittest.TestCase):
    """What the reader does with the policy settings the target cannot carry, and with defaults, one rule each (found by mutation testing)."""

    @classmethod
    def setUpClass(cls):
        cls.pol = convert(EDGE_POLICIES, "fortigate", "panos")
        cls.nat = convert(EDGE_NAT, "fortigate", "panos")

    def test_rules_that_were_restricted_are_written_disabled(self):
        for name, reason in (("sched", "schedule work"), ("users", "user / group match"), ("app", "application control"), ("isdb", "Internet Service object"),
                             ("ghost", "address NOPE not converted")):
            out = rule_lines(self.pol.output, name)
            self.assertIn(f"set rulebase security rules {name} disabled yes", out, name)
            self.assertTrue(any(reason in x for x in out), (name, reason))

    def test_plain_rule_is_not_disabled_and_keeps_its_settings(self):
        out = rule_lines(self.pol.output, "nolog")
        self.assertFalse(any("disabled" in x for x in out))
        self.assertIn("set rulebase security rules nolog negate-source yes", out)
        self.assertFalse(any("log-end" in x for x in out), "logtraffic disable must not log")
        self.assertNotIn("negate-destination yes", " ".join(out))
        for name in ("sched", "users"):
            self.assertIn(f"set rulebase security rules {name} log-end yes", rule_lines(self.pol.output, name))

    def test_unknown_service_and_address_are_left_out_and_reported(self):
        text = " ".join(messages(self.pol, "Needs review"))
        self.assertIn("NOPE", text)
        self.assertIn("set rulebase security rules ghost service [ any ]", self.pol.output.splitlines())

    def test_internet_service_rule_has_any_destination(self):
        self.assertIn("set rulebase security rules isdb destination [ any ]", self.pol.output.splitlines())
        self.assertIn("set rulebase security rules isdb source [ any ]", self.pol.output.splitlines())

    def test_rule_without_interfaces_matches_any_zone(self):
        out = rule_lines(self.nat.output, "noicon")
        for word in ("from", "to", "source", "destination", "service"):
            self.assertIn(f"set rulebase security rules noicon {word} [ any ]", out)
        self.assertIn("set rulebase security rules noicon disabled yes", out)

    def test_vip_port_forward_translates_port_and_keeps_external_port(self):
        out = self.nat.output.splitlines()
        self.assertIn("set service VIP-WEB-udp-5000 protocol udp port 5000", out)
        self.assertIn("set rulebase nat rules VIP-WEB service VIP-WEB-udp-5000", out)
        self.assertIn("set rulebase nat rules VIP-WEB destination-translation translated-port 6000", out)
        self.assertIn("set rulebase nat rules VIP-WEB to [ port2 ]", out)
        self.assertIn("set rulebase nat rules VIP-WEB destination-translation translated-address 10.1.0.10", out)

    def test_vip_range_uses_first_mapped_address_and_any_zone(self):
        out = self.nat.output.splitlines()
        self.assertIn("set address VIP-RANGE ip-range 192.0.2.20-192.0.2.22", out)
        self.assertIn("set rulebase nat rules VIP-RANGE destination-translation translated-address 10.1.0.20", out)
        self.assertIn("set rulebase nat rules VIP-RANGE to [ any ]", out)
        self.assertNotIn("set rulebase nat rules VIP-RANGE destination-translation translated-port", " ".join(out))
        text = " ".join(messages(self.nat, "Needs review"))
        self.assertIn("source filter", text)
        self.assertIn("Mapped range", text)

    def test_vip_of_other_type_or_without_mapped_address_is_not_converted(self):
        text = " ".join(messages(self.nat, "Not converted"))
        self.assertIn("load-balance", text)
        self.assertIn("no mapped address", text)
        self.assertNotIn("VIP-LB", self.nat.output)
        self.assertNotIn("VIP-NOMAP", " ".join(x for x in self.nat.output.splitlines() if x.startswith("set rulebase nat")))

    def test_pool_nat_types(self):
        out = self.nat.output.splitlines()
        self.assertIn("set rulebase nat rules nat-out source-translation dynamic-ip-and-port translated-address [ 192.0.2.50 ]", out)
        self.assertIn("set rulebase nat rules nat-out2 source-translation dynamic-ip translated-address [ 192.0.2.60-192.0.2.70 ]", out)

    def test_address_of_type_mac_is_not_converted(self):
        self.assertNotIn("HOST-MAC", " ".join(x for x in self.nat.output.splitlines() if x.startswith("set address")))
        self.assertIn("mac", " ".join(messages(self.nat, "Not converted")))



EDGE_ROUTING_VPN = """config system settings
    set central-nat enable
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        set role lan
    next
    edit "port2"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.0
        set role wan
    next
    edit "port3"
        set vdom "root"
        set ip 198.51.100.1 255.255.255.0
        set role wan
    next
    edit "dmz"
        set vdom "root"
        set mode dhcp
    next
end
config system zone
    edit "WANZ"
        set interface "port2" "port3"
    next
end
config firewall address
    edit "NET-A"
        set subnet 10.1.0.0 255.255.255.0
    next
    edit "NET-B"
        set subnet 10.2.0.0 255.255.255.0
    next
    edit "RNG"
        set type iprange
        set start-ip 10.9.0.1
        set end-ip 10.9.0.9
    next
end
config firewall ippool
    edit "POOL1"
        set startip 192.0.2.50
        set endip 192.0.2.50
    next
end
config firewall central-snat-map
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set orig-addr "NET-A"
        set dst-addr "all"
        set nat-ippool "POOL1"
    next
    edit 2
        set srcintf "port1"
        set dstintf "WANZ"
        set orig-addr "NET-B"
        set dst-addr "all"
    next
    edit 3
        set srcintf "port1"
        set dstintf "port3"
        set orig-addr "NET-B"
        set dst-addr "NET-A"
        set nat disable
        set protocol 6
        set orig-port 443
        set status disable
    next
end
config router static
    edit 1
        set gateway 192.0.2.254
        set device "port2"
    next
    edit 2
        set dst 10.50.0.0 255.255.0.0
        set gateway 192.0.2.253
        set device "port2"
        set distance 20
        set priority 5
    next
    edit 3
        set dstaddr "NET-B"
        set blackhole enable
        set status disable
    next
    edit 4
        set dstaddr "RNG"
        set device "port3"
    next
    edit 5
        set internet-service 1234
    next
end
config router ospf
    set router-id 1.1.1.1
    config area
        edit 0.0.0.0
        next
        edit 0.0.0.5
        next
    end
    config network
        edit 1
            set prefix 10.0.0.0 255.255.255.0
        next
        edit 2
            set area 0.0.0.5
            set prefix 192.0.2.0 255.255.255.0
        next
    end
end
config vpn ipsec phase1-interface
    edit "T1"
        set interface "port2"
        set ike-version 2
        set remote-gw 203.0.113.9
        set local-gw 192.0.2.1
        set proposal aes256-sha256 aes128-sha1 3des-md5 blowfish-md5
        set dhgrp 14 5
        set keylife 28800
        set authmethod signature
        set nattraversal disable
        set dpd disable
        set psksecret ENC abcdef
    next
    edit "T2"
        set interface "port3"
        set type dynamic
        set mode aggressive
        set proposal aes128-sha256
        set xauthtype auto
    next
    edit "T3"
        set interface "port3"
        set type ddns
        set remote-gw ddns.example.com
    next
end
config vpn ipsec phase2-interface
    edit "T1-p2"
        set phase1name "T1"
        set proposal aes256-sha256 aes128gcm
        set src-addr-type name
        set src-name "NET-A"
        set dst-subnet 10.77.0.0 255.255.0.0
        set pfs disable
        set keylifeseconds 3600
    next
    edit "T1-p2b"
        set phase1name "T1"
        set proposal aes128-sha1
        set src-addr-type name
        set src-name "RNG"
        set dst-addr-type name
        set dst-name "NET-B"
    next
end
"""


class RoutingVpnEdges(unittest.TestCase):
    """Central NAT, static route forms, OSPF areas and the IPsec phases, one case each (found by mutation testing)."""

    @classmethod
    def setUpClass(cls):
        cls.result = convert(EDGE_ROUTING_VPN, "fortigate", "panos")
        cls.out = cls.result.output.splitlines()

    def has(self, line):
        self.assertIn(line, self.out)

    def test_central_snat_pool_interface_and_no_nat(self):
        self.has("set rulebase nat rules snat-1 source-translation dynamic-ip-and-port translated-address [ 192.0.2.50 ]")
        self.has("set rulebase nat rules snat-1 to [ WANZ ]")
        self.assertFalse([x for x in self.out if x.startswith("set rulebase nat rules snat-3 source-translation")])
        self.has("set rulebase nat rules snat-3 disabled yes")
        self.has("set rulebase nat rules snat-3 destination [ NET-A ]")
        text = " ".join(messages(self.result, "Needs review"))
        self.assertIn("central SNAT entry is not one interface", text)
        self.assertIn("protocol and port match of the central SNAT entry", text)

    def test_central_snat_of_a_zone_with_two_ports_asks_for_the_egress_port(self):
        self.assertTrue(any(x.startswith("# NAT rule snat-2:") for x in self.out))

    def test_static_route_forms(self):
        self.has("set network virtual-router default routing-table ip static-route route-1 destination 0.0.0.0/0")
        self.has("set network virtual-router default routing-table ip static-route route-2 destination 10.50.0.0/16")
        self.has("set network virtual-router default routing-table ip static-route route-2 admin-dist 20")
        self.has("set network virtual-router default routing-table ip static-route route-2 metric 5")
        self.has("set network virtual-router default routing-table ip static-route route-1 admin-dist 10")
        self.has("set network virtual-router default routing-table ip static-route route-1 metric 1")
        joined = " ".join(self.out)
        self.assertNotIn("static-route route-4", joined)
        self.assertNotIn("static-route route-5", joined)
        self.assertNotIn("static-route route-3", joined)
        rows_ = [r for r in rows(self.result) if r["layer"].lower().startswith("rout")]
        self.assertEqual(sum(1 for r in rows_ if r["status"] == "Not converted"), 2)
        self.assertTrue(any(r["name"] == "10.2.0.0/24" and "disabled" in r["message"] for r in rows_))

    def test_ospf_areas_and_networks(self):
        self.has("set network virtual-router default protocol ospf router-id 1.1.1.1")
        self.has("set network virtual-router default protocol ospf area 0.0.0.0 interface ethernet1/1 enable yes")
        self.has("set network virtual-router default protocol ospf area 0.0.0.5 interface ethernet1/2 enable yes")

    def test_ospf_network_without_area_goes_to_the_backbone(self):
        text = EDGE_ROUTING_VPN.replace("            set area 0.0.0.5\n", "").replace("        edit 0.0.0.5\n        next\n", "")
        out = convert(text, "fortigate", "panos").output.splitlines()
        self.assertIn("set network virtual-router default protocol ospf area 0.0.0.0 interface ethernet1/2 enable yes", out)
        self.assertFalse([x for x in out if "area 0.0.0.5" in x])

    def test_ike_and_ipsec_profiles_of_the_static_tunnel(self):
        self.has("set network ike crypto-profiles ike-crypto-profiles T1-ike dh-group [ group14 group5 ]")
        self.has("set network ike crypto-profiles ike-crypto-profiles T1-ike encryption [ aes-256-cbc aes-128-cbc 3des ]")
        self.has("set network ike crypto-profiles ike-crypto-profiles T1-ike hash [ sha256 sha1 md5 ]")
        self.has("set network ike crypto-profiles ike-crypto-profiles T1-ike lifetime hours 8")
        self.has("set network ike crypto-profiles ipsec-crypto-profiles T1-esp esp encryption [ aes-256-cbc aes-128-gcm ]")
        self.has("set network ike crypto-profiles ipsec-crypto-profiles T1-esp esp authentication [ sha256 none ]")
        self.has("set network ike crypto-profiles ipsec-crypto-profiles T1-esp dh-group no-pfs")
        self.has("set network ike crypto-profiles ipsec-crypto-profiles T1-esp lifetime hours 1")
        self.has("set network ike gateway gw-T1 protocol version ikev2")
        self.has("set network ike gateway gw-T1 peer-address ip 203.0.113.9")

    def test_selectors_become_proxy_ids(self):
        self.has("set network tunnel ipsec T1 auto-key proxy-id proxy-1 local 10.1.0.0/24")
        self.has("set network tunnel ipsec T1 auto-key proxy-id proxy-1 remote 10.77.0.0/16")
        self.has("set network tunnel ipsec T1 auto-key proxy-id proxy-2 local 0.0.0.0/0")
        self.has("set network tunnel ipsec T1 auto-key proxy-id proxy-2 remote 10.2.0.0/24")

    def test_dialup_tunnel_defaults(self):
        self.has("set network ike gateway gw-T2 protocol version ikev1")
        self.has("set network ike gateway gw-T2 protocol ikev1 exchange-mode aggressive")
        self.has("set network ike gateway gw-T2 peer-address dynamic")
        self.has("set network ike gateway gw-T2 protocol-common nat-traversal enable yes")
        self.has("set network ike gateway gw-T2 protocol-common dpd enable yes")
        self.has("set network ike crypto-profiles ike-crypto-profiles T2-ike lifetime days 1")
        self.has("set network ike crypto-profiles ike-crypto-profiles T2-ike dh-group [ group14 ]")

    def test_t1_turns_off_nat_traversal_and_dpd(self):
        joined = " ".join(self.out)
        self.assertNotIn("gw-T1 protocol-common nat-traversal enable yes", joined)
        self.assertNotIn("gw-T1 protocol-common dpd enable yes", joined)

    def test_vpn_review_messages(self):
        text = " ".join(messages(self.result, "Needs review"))
        for needle in ("blowfish-md5", "different proposals", "REPLACE-ME", "Certificate authentication", "XAUTH", "no phase 2 selector", "ike-version is not in the configuration", "dial-up"):
            self.assertIn(needle, text)
        self.assertIn("ddns", " ".join(messages(self.result, "Not converted")))
        self.assertNotIn("gw-T3", self.result.output)

    def test_dhcp_client_port_is_written(self):
        self.has("set network interface ethernet ethernet1/4 layer3 dhcp-client enable yes")

    def test_zone_with_two_ports(self):
        self.has("set zone WANZ network layer3 [ ethernet1/2 ethernet1/3 ]")

    def test_central_nat_policies_make_no_policy_nat(self):
        self.assertFalse([x for x in self.out if "made from FortiGate policy" in x])



NAT_ORDER = """config system interface
    edit "port1"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "port2"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.0
    next
    edit "port3"
        set vdom "root"
        set ip 198.51.100.1 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "plain-a"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
    edit 2
        set name "nat-a"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
    next
    edit 3
        set name "plain-b"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
    edit 4
        set name "nat-b"
        set srcintf "port1"
        set dstintf "port3"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
    next
    edit 5
        set name "ipsec-policy"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action ipsec
        set schedule "always"
        set service "ALL"
    next
end
"""


class ReaderEdges(unittest.TestCase):
    """VDOM choice, the no-NAT rule that keeps NAT per policy, policy-based VPN, the XML guard and IKE mode (found by mutation testing)."""

    def test_vdom_choice(self):
        text = (FIX / "fortigate_multivdom_synthetic.conf").read_text()
        for wanted, expected_ip, expected_vdom in (("", "10.0.0.2/24", "root"), ("CORP", "10.1.0.1/24", "CORP"), ("no-such-vdom", "10.0.0.2/24", "root")):
            result = convert(text, "fortigate", "panos", vdom=wanted)
            self.assertTrue(result.ok, result.error)
            self.assertIn(f"set network interface ethernet ethernet1/1 layer3 ip {expected_ip}", result.output.splitlines(), wanted)
            self.assertTrue(any(r["name"] and f"Only VDOM {expected_vdom} is converted" in r["message"] for r in rows(result)), wanted)
            others = [r["name"] for r in rows(result) if f"Only VDOM {expected_vdom} is converted" in r["message"]][0]
            self.assertNotIn(expected_vdom, others.split(", "))
            self.assertEqual(len(others.split(", ")), 2)

    def test_no_nat_rule_only_when_a_later_nat_policy_overlaps(self):
        out = convert(NAT_ORDER, "fortigate", "panos").output
        self.assertIn("set rulebase nat rules nonat-plain-a from [ port1 ]", out.splitlines())
        self.assertNotIn("nonat-plain-b", out)
        self.assertNotIn("nonat-nat-a", out)
        names = [x.split()[4] for x in out.splitlines() if x.startswith("set rulebase nat rules") and x.endswith("service any")]
        self.assertEqual(names, ["nonat-plain-a", "nat-nat-a", "nat-nat-b"])

    def test_policy_based_vpn_rule_is_disabled_and_reported(self):
        result = convert(NAT_ORDER, "fortigate", "panos")
        out = rule_lines(result.output, "ipsec-policy")
        self.assertIn("set rulebase security rules ipsec-policy disabled yes", out)
        self.assertTrue(any("policy-based VPN" in x for x in out))
        self.assertIn("policy-based VPN", " ".join(messages(result, "Not converted")))

    def test_xml_with_doctype_or_entity_is_refused(self):
        for text in ('<?xml version="1.0"?><!DOCTYPE config><config version="10.1.0"/>',
                     '<?xml version="1.0"?><!doctype config [<!ENTITY a "b">]><config version="10.1.0"/>',
                     '<?xml version="1.0"?><config version="10.1.0"><!ENTITY a "b"></config>'):
            result = convert(text, "panos", "fortigate")
            self.assertFalse(result.ok, text)
            self.assertEqual(result.output, "")

    def test_exchange_mode_only_counts_for_ikev1(self):
        base = ("set network ike gateway gw protocol version {v}\nset network ike gateway gw protocol ikev1 exchange-mode aggressive\n"
                "set network ike gateway gw peer-address ip 203.0.113.5\nset network ike gateway gw local-address interface ethernet1/1\n"
                "set network tunnel ipsec tun auto-key ike-gateway gw\nset network tunnel ipsec tun tunnel-interface tunnel.1\n"
                "set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24\nset network interface tunnel units tunnel.1\n")
        v1 = convert(base.format(v="ikev1"), "panos", "fortigate").output
        v2 = convert(base.format(v="ikev2"), "panos", "fortigate").output
        self.assertIn("set mode aggressive", v1)
        self.assertNotIn("aggressive", v2)
        pan1 = convert(convert(base.format(v="ikev1"), "panos", "fortigate").output, "fortigate", "panos").output
        self.assertIn("exchange-mode aggressive", pan1)


class PanToForti(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = convert(PAN, "panos", "fortigate")
        cls.out = cls.result.output
        cls.set = set(lines(cls.out))

    def has(self, line: str):
        self.assertIn(line, self.set)

    def test_ok(self):
        self.assertTrue(self.result.ok, self.result.error)

    def test_interfaces(self):
        self.has('    edit "port1"')
        self.has("        set ip 198.51.100.2 255.255.255.248")
        self.has("        set vlanid 20")
        self.has('        set member "port4" "port5"')
        self.has("        set lacp-mode active")
        self.has('    edit "lo1"')

    def test_management_profile_to_allowaccess(self):
        self.has("        set allowaccess ping https ssh")
        self.assertTrue(any("userid-service" in m for m in messages(self.result, "Approximated")))

    def test_zones_allow_traffic_inside_like_the_intrazone_default(self):
        self.assertEqual(self.out.count("set intrazone allow"), 4)

    def test_nat_is_central_nat(self):
        self.has("    set central-nat enable")
        self.assertIn("config firewall central-snat-map", self.out)
        self.has("        set nat disable")                            # the no-NAT rule
        self.has('        set nat-ippool "pool-dmz-pool"')
        self.assertTrue(any("central-snat-map reference" in m for m in messages(self.result, "Needs review")))

    def test_destination_nat_is_a_vip_the_policy_names(self):
        self.has('    edit "vip-inbound-web"')
        self.has("        set extip 198.51.100.4")
        self.has('        set mappedip "10.2.0.10"')
        self.has("        set extport 8443")
        self.has("        set mappedport 443")
        self.has('        set dstaddr "vip-inbound-web"')

    def test_static_source_nat_is_reported_not_converted(self):
        self.assertTrue(any("static-ip" in m for m in messages(self.result, "Not converted")))

    def test_app_id_with_application_default_becomes_ports(self):
        self.has('        set service "HTTPS" "HTTP"')
        self.has('        set service "PING"')

    def test_unknown_application_disables_the_rule(self):
        block = self.out.split('edit 4\n')[1].split("    next")[0] if 'edit 4\n' in self.out else ""
        self.assertIn('set name "social"', block)
        self.assertIn("set status disable", block)

    def test_user_rule_is_disabled(self):
        self.assertTrue(any("source-user" in m for m in messages(self.result, "Needs review")))

    def test_regions_become_geography_addresses(self):
        self.has('        set country "KP"')
        self.has('        set srcaddr "geo-KP" "geo-RU"')

    def test_predefined_services_are_not_redefined(self):
        self.assertNotIn('edit "HTTP"', self.out)
        self.assertNotIn('edit "PING"', self.out)

    def test_pan_builtin_service_is_defined_with_its_real_ports(self):
        self.has('    edit "service-https"')
        self.has("        set tcp-portrange 443")

    def test_source_port_service(self):
        self.has("        set udp-portrange 53:1024-65535")

    def test_routes(self):
        self.has("        set gateway 198.51.100.1")
        self.has('        set device "tun-remote"')
        self.has("        set blackhole enable")
        self.has("        set gateway 10.1.0.254")
        self.has('        set device "port2"')                  # found from the subnet of the next hop

    def test_bgp_and_ospf(self):
        self.has("    set as 65020")
        self.has('        edit "198.51.100.1"')
        self.has("            set prefix 10.3.0.0 255.255.255.0")

    def test_vpn(self):
        self.has('    edit "tun-remote"')
        self.has("        set ike-version 2")
        self.has("        set proposal aes256-sha256 aes256-sha384 aes128-sha256 aes128-sha384")
        self.has("        set dhgrp 14 19")
        self.has("        set proposal aes256gcm")
        self.has("        set src-subnet 10.1.0.0 255.255.255.0")
        self.has("        set dst-subnet 10.50.0.0 255.255.0.0")
        self.has('        set interface "tun-remote"')           # the zone holds the phase 1 interface

    def test_pre_shared_key_is_never_read_or_written(self):
        self.assertNotIn("SyntheticPskNotReal", self.out + self.result.report.to_text())
        self.has("        set psksecret REPLACE-ME")

    def test_report_documentation_links(self):
        for r in rows(self.result):
            if r["status"] in ("Needs review", "Not converted"):
                self.assertTrue(r["documentation"].startswith("https://"), r)

    def test_curly_brace_view_is_read(self):
        r = convert(CURLY, "auto", "fortigate")
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.source, "panos")
        self.assertIn('set hostname "LAB-FW01"', r.output)
        self.assertEqual(r.output.count("set psksecret REPLACE-ME"), 2)
        self.assertNotIn("/29", r.output.split("phase1-interface")[1].split("phase2-interface")[0])       # local-gw is an address, not a prefix
        self.assertNotIn("NOTAREALHASH", r.output)

    def test_application_any_with_application_default_is_disabled(self):
        r = convert(CURLY, "panos", "fortigate")
        block = r.output.split("config firewall policy")[1]
        self.assertIn("set status disable", block)

    def test_name_clash_between_zone_and_interface(self):
        text = "set network interface ethernet ethernet1/1 layer3 ip 10.0.0.1/24\nset zone port1 network layer3 ethernet1/1\n"
        r = convert(text, "panos", "fortigate")
        self.assertIn('edit "z-port1"', r.output)
        self.assertTrue(any("cannot share its name" in m for m in messages(r)))

    def test_unknown_address_in_a_rule_widens_and_disables(self):
        text = ("set network interface ethernet ethernet1/1 layer3 ip 10.0.0.1/24\nset zone a network layer3 ethernet1/1\n"
                "set rulebase security rules r1 from a\nset rulebase security rules r1 to a\nset rulebase security rules r1 source ghost-object\n"
                "set rulebase security rules r1 destination any\nset rulebase security rules r1 application any\nset rulebase security rules r1 service any\nset rulebase security rules r1 action allow\n")
        r = convert(text, "panos", "fortigate")
        self.assertIn("set status disable", r.output)
        self.assertIn('set srcaddr "all"', r.output)              # the unknown object is left out of the rule, not written under its own name
        self.assertNotIn('"ghost-object"', r.output)
        self.assertTrue(any("ghost-object" in x["name"] for x in rows(r, "Needs review")))

    def test_policy_names_are_unique_and_short(self):
        long = "x" * 60
        text = ("set network interface ethernet ethernet1/1 layer3 ip 10.0.0.1/24\nset zone a network layer3 ethernet1/1\n" +
                "".join(f"set rulebase security rules {long}{i} from a\nset rulebase security rules {long}{i} to a\nset rulebase security rules {long}{i} action allow\n" for i in range(2)))
        r = convert(text, "panos", "fortigate")
        names = re.findall(r'set name "([^"]+)"', r.output)
        self.assertEqual(len(names), 2)
        self.assertEqual(len(set(names)), 2)
        self.assertTrue(all(len(n) <= 35 for n in names))


class PanFormats(unittest.TestCase):
    XML = """<config version="11.1.0"><devices><entry name="localhost.localdomain">
<deviceconfig><system><hostname>PA-XML</hostname></system></deviceconfig>
<network><interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="10.9.0.1/24"/></ip></layer3></entry></ethernet></interface></network>
<vsys><entry name="vsys1">
<zone><entry name="lan"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone>
<address><entry name="h1"><ip-netmask>10.9.0.10/32</ip-netmask></entry></address>
<rulebase><security><rules><entry name="r1"><from><member>lan</member></from><to><member>lan</member></to><source><member>h1</member></source>
<destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>allow</action></entry></rules></security></rulebase>
</entry></vsys></entry></devices></config>"""

    def test_xml_equals_set_format(self):
        set_text = ("set deviceconfig system hostname PA-XML\nset network interface ethernet ethernet1/1 layer3 ip 10.9.0.1/24\nset zone lan network layer3 ethernet1/1\n"
                    "set address h1 ip-netmask 10.9.0.10/32\nset rulebase security rules r1 from lan\nset rulebase security rules r1 to lan\nset rulebase security rules r1 source h1\n"
                    "set rulebase security rules r1 destination any\nset rulebase security rules r1 application any\nset rulebase security rules r1 service any\nset rulebase security rules r1 action allow\n")
        a, b = convert(self.XML, "auto", "fortigate"), convert(set_text, "auto", "fortigate")
        self.assertTrue(a.ok and b.ok, (a.error, b.error))
        self.assertEqual(a.output, b.output)
        self.assertIn('set name "r1"', a.output)

    def test_panorama_and_vsys_wrappers_are_merged(self):
        text = ("set template T config devices localhost.localdomain vsys vsys1 zone z1 network layer3 ethernet1/1\n"
                "set device-group DG address a1 ip-netmask 10.0.0.1/32\nset shared address a2 ip-netmask 10.0.0.2/32\nset vsys vsys1 address a3 ip-netmask 10.0.0.3/32\n")
        root = tree_of(text)
        self.assertEqual(root.keys("zone"), ["z1"])
        self.assertEqual(sorted(root.keys("address")), ["a1", "a2", "a3"])

    def test_doctype_is_refused(self):
        r = convert('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><config/>', "panos", "fortigate")
        self.assertFalse(r.ok)
        self.assertIn("DOCTYPE", r.error)

    def test_malformed_xml_is_an_error_not_a_crash(self):
        r = convert("<config><oops", "panos", "fortigate")
        self.assertFalse(r.ok)

    def test_quoted_values_and_lists(self):
        root = tree_of('set address a1 description "two words" ip-netmask 10.0.0.1/32\nset zone z network layer3 [ e1 e2 ]\n')
        self.assertEqual(root.first("address", "a1", "description"), "two words")
        self.assertEqual(root.keys("zone", "z", "network", "layer3"), ["e1", "e2"])

    def test_one_line_management_profile_is_read(self):
        text = ("set network interface ethernet ethernet1/1 layer3 ip 10.0.0.1/24\nset network interface ethernet ethernet1/1 layer3 interface-management-profile M\n"
                "set network profiles interface-management-profile M ping yes https yes ssh no\n")
        self.assertIn("set allowaccess ping https", convert(text, "panos", "fortigate").output)


class Input(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(detect(FORTI), "fortigate")
        self.assertEqual(detect(PAN), "panos")
        self.assertEqual(detect(CURLY), "panos")
        self.assertEqual(detect("hello"), "")

    def test_same_vendor_empty_and_unknown(self):
        self.assertFalse(convert(FORTI, "fortigate", "fortigate").ok)
        self.assertFalse(convert("  \n", "fortigate", "panos").ok)
        self.assertFalse(convert(FORTI, "cisco", "panos").ok)
        self.assertFalse(convert("hello", "auto", "panos").ok)

    def test_oversized_input_is_refused(self):
        import importlib
        mod = importlib.import_module("features.configuration_studio.converter_engine.fwconvert.convert")
        r = mod.convert("x" * (mod.MAX_CHARS + 1), "fortigate", "panos")
        self.assertFalse(r.ok)
        self.assertIn("larger", r.error)

    def test_random_input_never_crashes(self):
        rnd = random.Random(7)
        words = ["set", "config", "edit", "next", "end", "network", "interface", "ethernet", "ethernet1/1", "layer3", "ip", "10.0.0.1/24", "10.0.0.1", "255.255.255.0", "zone", "address", "service",
                 "rulebase", "security", "rules", "from", "to", "[", "]", '"', "any", "allow", "firewall", "policy", "system", "vip", "<a>", "</a>", "{", "}", ";", "\t", "tag", "999999999999"]
        for _ in range(150):
            text = "\n".join(" ".join(rnd.choice(words) for _ in range(rnd.randint(1, 9))) for _ in range(rnd.randint(1, 25)))
            for src, dst in (("fortigate", "panos"), ("panos", "fortigate")):
                r = convert(text, src, dst)
                self.assertIsInstance(r.ok, bool)

    def test_noncontiguous_mask_is_not_converted(self):
        text = "config firewall address\n    edit \"odd\"\n        set subnet 10.0.0.0 255.0.255.0\n    next\nend\n"
        r = convert(text, "fortigate", "panos")
        self.assertTrue(any("not contiguous" in m for m in messages(r, "Not converted")))

    def test_no_network_or_filesystem_access(self):
        import socket
        original = socket.socket
        socket.socket = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used"))      # type: ignore
        try:
            self.assertTrue(convert(FORTI, "fortigate", "panos").ok)
            self.assertTrue(convert(PAN, "panos", "fortigate").ok)
        finally:
            socket.socket = original

    def test_pnode_helpers(self):
        n = PNode()
        n.add("a").add("b")
        self.assertTrue(n.has("a", "b"))
        self.assertEqual(n.first("a"), "b")
        self.assertEqual(n.first("zz", default="d"), "d")
        self.assertFalse(n.flag("a", "b"))


class RoundTrip(unittest.TestCase):
    def test_forti_pan_forti_keeps_the_objects_and_rules(self):
        pan = convert(FORTI, "fortigate", "panos").output
        back = convert(pan, "panos", "fortigate")
        self.assertTrue(back.ok, back.error)
        for name in ("LAN-NET", "WEB-SRV", "PARTNER-NET", "RANGE-A", "UPDATE-FQDN", "INTERNAL"):
            self.assertIn(f'edit "{name}"', back.output)
        self.assertEqual(len(re.findall(r'set name "', back.output)), 9)                 # 8 policies, one of them split for ICMP
        self.assertIn("central-nat enable", back.output)
        self.assertIn('edit "vip-WEB-VIP"', back.output)
        self.assertIn('set dstaddr "vip-WEB-VIP"', back.output)
        self.assertIn("set remote-gw 198.51.100.2", back.output)

    def test_pan_forti_pan_keeps_the_zones_and_rules(self):
        forti = convert(PAN, "panos", "fortigate").output
        back = convert(forti, "fortigate", "panos")
        self.assertTrue(back.ok, back.error)
        self.assertEqual(len([x for x in back.output.splitlines() if re.match(r"set rulebase security rules \S+ action ", x)]), 7)
        for zone in ("untrust", "trust", "dmz", "vpn"):
            self.assertIn(f"set zone {zone} ", back.output)


if __name__ == "__main__":
    unittest.main()
