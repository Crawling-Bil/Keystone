"""Unit tests for PaloAltoFirewallParser -- the PAN-OS "set"-format
parser backing the Config Analyzer's Palo Alto dashboard (see
models/paloalto_native.py for why this targets a dedicated model
rather than the Mikrotik-shaped FirewallConfig).

Two kinds of coverage: round-tripping PaloAltoFirewallTranslator's own
output (both the flat/legacy shape and the Panorama Template/Device
Group wrapped shape) back through this parser -- since that's the
format this parser was built to read first -- and a hand-authored
"real capture"-style flat config exercising object/rule fields our own
translator doesn't happen to emit (e.g. a `disabled yes` rule), so the
parser isn't just curve-fit to its one known producer.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from features.configuration_studio.converter_engine.parsers.firewall.mikrotik import (
    MikrotikFirewallParser,
)
from features.configuration_studio.converter_engine.parsers.firewall.paloalto import (
    PaloAltoFirewallParser,
)
from features.configuration_studio.converter_engine.translators.firewall.paloalto import (
    PaloAltoFirewallTranslator,
)
from tests.test_paloalto_firewall_translator import SAMPLE_CONFIG


def _write(tmp_dir: Path, name: str, text: str) -> Path:
    path = tmp_dir / name
    path.write_text(text, encoding="utf-8")
    return path


def _parse_mikrotik(text: str, tmp_dir: Path):
    path = _write(tmp_dir, "source.rsc", text)
    return MikrotikFirewallParser().parse_file(path)


HAND_AUTHORED_FLAT_CONFIG = """
set deviceconfig system hostname EDGE-FW01
set deviceconfig system dns-setting servers primary 8.8.8.8
set deviceconfig system dns-setting servers secondary 8.8.4.4
set deviceconfig system service disable-telnet yes

set network interface ethernet ethernet1/1 layer3
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.5/29
set network interface ethernet ethernet1/1 comment "ISP uplink"
set network interface ethernet ethernet1/2 layer3
set network interface ethernet ethernet1/2 layer3 ip 192.168.1.1/24
set zone Outside network layer3 [ ethernet1/1 ]
set zone Inside network layer3 [ ethernet1/2 ]

set network virtual-router default interface [ ethernet1/1 ethernet1/2 ]

set address lan-net ip-netmask 192.168.1.0/24
set address-group lan-group static [ lan-net ]
set service web-svc protocol tcp port 8443

set rulebase security rules allow-any-any from [ any ]
set rulebase security rules allow-any-any to [ any ]
set rulebase security rules allow-any-any source [ any ]
set rulebase security rules allow-any-any destination [ any ]
set rulebase security rules allow-any-any service [ any ]
set rulebase security rules allow-any-any application [ any ]
set rulebase security rules allow-any-any action allow
set rulebase security rules old-disabled-rule from [ Outside ]
set rulebase security rules old-disabled-rule to [ Inside ]
set rulebase security rules old-disabled-rule source [ any ]
set rulebase security rules old-disabled-rule destination [ any ]
set rulebase security rules old-disabled-rule service [ web-svc ]
set rulebase security rules old-disabled-rule application [ any ]
set rulebase security rules old-disabled-rule action allow
set rulebase security rules old-disabled-rule disabled yes

set rulebase nat rules outbound-nat from [ Inside ]
set rulebase nat rules outbound-nat to [ Outside ]
set rulebase nat rules outbound-nat source [ any ]
set rulebase nat rules outbound-nat destination [ any ]
set rulebase nat rules outbound-nat source-translation dynamic-ip-and-port interface-address interface ethernet1/1

set network virtual-router default protocol bgp enable yes
set network virtual-router default protocol bgp router-id 203.0.113.5
set network virtual-router default protocol bgp local-as 65030
set network virtual-router default protocol ospf enable no
set network virtual-router default protocol ospf area 0.0.0.0

set network profiles interface-management-profile Outside-Mgmt ping yes
set network profiles interface-management-profile Outside-Mgmt https no

set network profiles zone-protection-profile ZPP-Edge flood tcp-syn enable yes
set network profiles zone-protection-profile ZPP-Edge scan tcp-port-scan enable yes
set zone Outside network zone-protection-profile ZPP-Edge

set mgt-config users fw-admin permissions role-based superuser yes
set mgt-config users fw-viewer permissions role-based custom profile ReadOnlyRole yes

set rulebase pbf rules PBF-Backup from zone [ Inside ]
set rulebase pbf rules PBF-Backup source [ 10.9.0.0/24 ]
set rulebase pbf rules PBF-Backup destination [ any ]
set rulebase pbf rules PBF-Backup application [ any ]
set rulebase pbf rules PBF-Backup service [ any ]
set rulebase pbf rules PBF-Backup action forward egress-interface ethernet1/2
set rulebase pbf rules PBF-Backup action forward nexthop ip-address 192.168.1.254
set rulebase pbf rules PBF-Backup action forward monitor profile SLA-Backup
set rulebase pbf rules PBF-Backup disabled no

# a directive this parser doesn't model yet
set shared botnet-signature-update schedule-time 02:00
"""


class PaloAltoFirewallParserPanoramaRoundTripTests(unittest.TestCase):
    """Parses PaloAltoFirewallTranslator's own Panorama-wrapped output
    back into PaloAltoNativeConfig -- the richest single fixture,
    covering interfaces (ethernet/VLAN-bridge/sub-interface/SD-WAN),
    zones, a virtual router with a static route, IKE/IPsec, address
    objects/groups, a service object, and NAT + security rules."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp_dir, ignore_errors=True)

        mikrotik_config = _parse_mikrotik(SAMPLE_CONFIG, self.tmp_dir)
        mapping = {
            "interfaces": {
                "ether1-wan": {"zone": "Outside", "sdwan_link_type": "mpls"},
                "ether4-dmz": {"zone": "DMZ"},
            },
            "ipsec_tunnels": {"to-hq": {"zone": "IPSEC-Tunnel", "tunnel_unit": 1}},
            "sdwan": {"enabled": True, "zone": "SDWAN"},
            "panorama": {"enabled": True, "template_name": "TEST-Template", "device_group_name": "TEST-DG"},
        }
        translated = PaloAltoFirewallTranslator().translate(mikrotik_config, mapping=mapping)
        pa_path = _write(self.tmp_dir, "panorama-output.cfg", "\n".join(translated))
        self.config = PaloAltoFirewallParser().parse_file(pa_path)

    def test_detects_panorama_wrapping_and_names(self):
        self.assertTrue(self.config.panorama_enabled)
        self.assertEqual(self.config.panorama_template_name, "TEST-Template")
        self.assertEqual(self.config.panorama_device_group_name, "TEST-DG")

    def test_hostname_parsed(self):
        self.assertEqual(self.config.hostname, "BRANCH-ROUTER-01")

    def test_bridge_becomes_vlan_interface_with_zone_and_members(self):
        by_name = {i.name: i for i in self.config.interfaces}
        self.assertIn("vlan.900", by_name)
        self.assertEqual(by_name["vlan.900"].zone, "bridge-lan")
        self.assertEqual(by_name["vlan.900"].ip_addresses, ["192.168.10.1/24"])

        bridges_by_name = {b.name: b for b in self.config.vlan_bridges}
        self.assertIn("bridge-lan", bridges_by_name)
        self.assertEqual(bridges_by_name["bridge-lan"].vlan_interface, "vlan.900")
        self.assertIn("ethernet1/2", bridges_by_name["bridge-lan"].interfaces)
        self.assertIn("ethernet1/3", bridges_by_name["bridge-lan"].interfaces)

    def test_vlan_on_routed_parent_sub_interface(self):
        by_name = {i.name: i for i in self.config.interfaces}
        sub = by_name["ethernet1/4.30"]
        self.assertEqual(sub.interface_type, "subinterface")
        self.assertEqual(sub.parent_interface, "ethernet1/4")
        self.assertEqual(sub.tag, 30)
        self.assertEqual(sub.zone, "vlan30-dmz")
        self.assertEqual(sub.ip_addresses, ["172.16.30.1/24"])

    def test_sdwan_member_interface_and_zone(self):
        by_name = {i.name: i for i in self.config.interfaces}
        member = by_name["ethernet1/1"]
        self.assertTrue(member.sdwan_enabled)
        self.assertEqual(member.sdwan_profile, "mpls-profile")
        self.assertEqual(member.zone, "SDWAN")
        self.assertIn("sdwan.1", by_name)
        self.assertEqual(by_name["sdwan.1"].zone, "SDWAN")

        profiles_by_name = {p.name: p for p in self.config.sdwan_profiles}
        self.assertEqual(profiles_by_name["mpls-profile"].link_type, "mpls")

    def test_virtual_router_members_and_static_route(self):
        vr = self.config.virtual_routers[0]
        self.assertIn("ethernet1/1", vr.interfaces)
        self.assertIn("sdwan.1", vr.interfaces)
        route = vr.static_routes[0]
        self.assertEqual(route.destination, "0.0.0.0/0")
        self.assertEqual(route.nexthop, "203.0.113.1")
        self.assertEqual(route.metric, 1)

    def test_ipsec_tunnel_with_zone_and_crypto_profiles(self):
        tunnel = self.config.ipsec_tunnels[0]
        self.assertEqual(tunnel.name, "to-hq")
        self.assertEqual(tunnel.ike_gateway, "hq-peer")
        self.assertEqual(tunnel.ipsec_crypto_profile, "esp-aes256")
        self.assertEqual(tunnel.tunnel_interface, "tunnel.1")
        self.assertEqual(tunnel.proxy_id_local, "192.168.10.0/24")
        self.assertEqual(tunnel.proxy_id_remote, "172.16.0.0/24")

        by_name = {i.name: i for i in self.config.interfaces}
        self.assertEqual(by_name["tunnel.1"].zone, "IPSEC-Tunnel")

        gateway = self.config.ike_gateways[0]
        self.assertEqual(gateway.name, "hq-peer")
        self.assertEqual(gateway.peer_address, "203.0.113.50")
        self.assertTrue(gateway.has_preshared_key)

        ike_crypto = self.config.ike_crypto_profiles[0]
        self.assertEqual(ike_crypto.dh_group, "modp1024")
        self.assertEqual(ike_crypto.encryption, "aes-256")

    def test_address_objects_groups_and_service(self):
        addresses_by_name = {a.name: a for a in self.config.address_objects}
        self.assertEqual(addresses_by_name["trusted-nets-1"].kind, "ip-netmask")
        self.assertEqual(addresses_by_name["trusted-nets-1"].value, "192.168.10.0/24")
        self.assertEqual(addresses_by_name["blocked-ips-1"].kind, "ip-range")

        groups_by_name = {g.name: g for g in self.config.address_groups}
        self.assertEqual(groups_by_name["trusted-nets"].members, ["trusted-nets-1"])

        services_by_name = {s.name: s for s in self.config.service_objects}
        self.assertEqual(services_by_name["allow-ssh-from-lan-svc"].port, "22")

    def test_nat_rules_source_and_destination_translation(self):
        rules_by_name = {r.name: r for r in self.config.nat_rules}
        outbound = rules_by_name["lan-masquerade"]
        self.assertEqual(outbound.to_zones, ["SDWAN"])
        self.assertIn("interface ethernet1/1", outbound.source_translation)

        port_forward = rules_by_name["port-forward-web"]
        self.assertEqual(port_forward.destination_translated_address, "192.168.10.100")
        self.assertEqual(port_forward.destination_translated_port, "8080")
        self.assertEqual(port_forward.service, "port-forward-web-nat-svc")

    def test_security_rules_action_and_membership(self):
        rules_by_name = {r.name: r for r in self.config.security_rules}
        self.assertEqual(rules_by_name["allow-trusted-out"].action, "allow")
        self.assertEqual(rules_by_name["allow-trusted-out"].source, ["trusted-nets"])
        self.assertEqual(rules_by_name["drop-blocked"].action, "deny")

    def test_nothing_left_unhandled(self):
        # The whole point of building this parser against our own
        # translator's output first: every line it can produce should
        # be recognized. A non-empty unhandled_commands here means
        # either this parser or the translator drifted.
        self.assertEqual(self.config.unhandled_commands, [])


class PaloAltoFirewallParserFlatRoundTripTests(unittest.TestCase):
    """The flat (no mapping / no Panorama) legacy translate(config)
    shape -- confirms the parser doesn't assume every config is
    Panorama-wrapped."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp_dir, ignore_errors=True)

        mikrotik_config = _parse_mikrotik(SAMPLE_CONFIG, self.tmp_dir)
        translated = PaloAltoFirewallTranslator().translate(mikrotik_config)
        pa_path = _write(self.tmp_dir, "flat-output.cfg", "\n".join(translated))
        self.config = PaloAltoFirewallParser().parse_file(pa_path)

    def test_panorama_not_flagged(self):
        self.assertFalse(self.config.panorama_enabled)
        self.assertEqual(self.config.panorama_template_name, "")

    def test_plain_routed_interface_ip_parsed(self):
        by_name = {i.name: i for i in self.config.interfaces}
        self.assertEqual(by_name["ethernet1/1"].ip_addresses, ["203.0.113.10/29"])

    def test_nothing_left_unhandled(self):
        self.assertEqual(self.config.unhandled_commands, [])


class PaloAltoFirewallParserHandAuthoredConfigTests(unittest.TestCase):
    """A flat "set" config in the shape a real PAN-OS device export
    takes (not derived from our own translator) -- exercises a
    `disabled yes` security rule and confirms an unmodeled directive
    lands in unhandled_commands rather than being silently dropped."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp_dir, ignore_errors=True)
        path = _write(self.tmp_dir, "edge-fw01.cfg", HAND_AUTHORED_FLAT_CONFIG)
        self.config = PaloAltoFirewallParser().parse_file(path)

    def test_hostname_and_dns(self):
        self.assertEqual(self.config.hostname, "EDGE-FW01")
        self.assertEqual(self.config.dns_servers, ["8.8.8.8", "8.8.4.4"])

    def test_virtual_router_protocol_detail_parsed_from_set_lines(self):
        # Regression coverage: until now only the XML parser wired
        # "protocol bgp/ospf/rip enable" lines to anything -- a
        # set-format-only capture always showed every VR as pure
        # static regardless of what it actually ran.
        vr = self.config.virtual_routers[0]
        self.assertTrue(vr.bgp_enabled)
        self.assertEqual(vr.bgp_router_id, "203.0.113.5")
        self.assertEqual(vr.bgp_as_number, "65030")
        self.assertFalse(vr.ospf_enabled)
        self.assertEqual(vr.ospf_area_ids, ["0.0.0.0"])

    def test_management_profile_parsed_from_set_lines(self):
        profile = next(p for p in self.config.management_profiles if p.name == "Outside-Mgmt")
        self.assertIn("ping", profile.permitted_services)
        self.assertNotIn("https", profile.permitted_services)

    def test_zone_protection_profile_parsed_and_assigned(self):
        zpp = next(p for p in self.config.zone_protection_profiles if p.name == "ZPP-Edge")
        self.assertEqual(set(zpp.protection_types), {"flood", "reconnaissance-scan"})
        outside_zone = next(z for z in self.config.zones if z.name == "Outside")
        self.assertEqual(outside_zone.zone_protection_profile, "ZPP-Edge")

    def test_administrators_parsed_from_set_lines(self):
        by_name = {a.username: a.role for a in self.config.administrators}
        self.assertEqual(by_name["fw-admin"], "superuser")
        self.assertEqual(by_name["fw-viewer"], "custom:ReadOnlyRole")

    def test_pbf_rule_parsed_from_set_lines(self):
        rule = next(r for r in self.config.pbf_rules if r.name == "PBF-Backup")
        self.assertEqual(rule.from_zones, ["Inside"])
        self.assertEqual(rule.source, ["10.9.0.0/24"])
        self.assertEqual(rule.egress_interface, "ethernet1/2")
        self.assertEqual(rule.nexthop, "192.168.1.254")
        self.assertEqual(rule.monitor_profile, "SLA-Backup")
        self.assertFalse(rule.disabled)

    def test_management_service_disabled(self):
        telnet = self.config.management_services[0]
        self.assertEqual(telnet.field_name, "disable-telnet")
        self.assertTrue(telnet.disabled)

    def test_interfaces_and_zones(self):
        by_name = {i.name: i for i in self.config.interfaces}
        self.assertEqual(by_name["ethernet1/1"].zone, "Outside")
        self.assertEqual(by_name["ethernet1/1"].comment, "ISP uplink")
        self.assertEqual(by_name["ethernet1/2"].zone, "Inside")

    def test_virtual_router_members(self):
        vr = self.config.virtual_routers[0]
        self.assertEqual(set(vr.interfaces), {"ethernet1/1", "ethernet1/2"})

    def test_disabled_security_rule_is_flagged_disabled(self):
        rules_by_name = {r.name: r for r in self.config.security_rules}
        self.assertTrue(rules_by_name["old-disabled-rule"].disabled)
        self.assertFalse(rules_by_name["allow-any-any"].disabled)

    def test_nat_rule_source_translation(self):
        nat = self.config.nat_rules[0]
        self.assertEqual(nat.from_zones, ["Inside"])
        self.assertEqual(nat.to_zones, ["Outside"])
        self.assertIn("dynamic-ip-and-port", nat.source_translation)

    def test_unmodeled_directive_preserved_in_unhandled_commands(self):
        self.assertTrue(
            any("botnet-signature-update" in line for line in self.config.unhandled_commands)
        )

    def test_comment_lines_and_blank_lines_are_not_unhandled(self):
        self.assertFalse(any(line.startswith("#") for line in self.config.unhandled_commands))


if __name__ == "__main__":
    unittest.main()
