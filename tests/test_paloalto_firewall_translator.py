"""Unit tests for PaloAltoFirewallTranslator -- turns the shared
FirewallConfig model (parsed from Mikrotik RouterOS by
MikrotikFirewallParser) into PAN-OS "set" CLI commands.

test_full_sample_config_converts_without_exceptions is the flagship
end-to-end case: a hand-authored RouterOS export covering every
category the user asked for (bridges + VLANs, a VLAN-on-a-routed-port
sub-interface, static routes, address-lists, IPsec, NAT, firewall
filter -> security policy) run through the real parser and translator
together, since there was no real customer Mikrotik export available
yet to validate against.

test_vlan_on_routed_parent_does_not_also_zone_the_bare_parent pins a
real bug caught during development: a physical port that is *only* a
VLAN-trunk parent (no native/untagged IP of its own) was also being
emitted a second time as its own standalone routed interface with a
spurious zone binding -- wrong, since that port carries no untagged
traffic of its own.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from features.configuration_studio.converter_engine.models.firewall import (
    AddressListEntry,
    DhcpServerBinding,
    FirewallConfig,
    Interface,
    InterfaceListMember,
    IpsecPeer,
    IpsecPolicy,
    MssClamp,
    NatRule,
    StaticRoute,
    FirewallFilterRule,
)
from features.configuration_studio.converter_engine.parsers.firewall.mikrotik import (
    MikrotikFirewallParser,
)
from features.configuration_studio.converter_engine.translators.firewall.paloalto import (
    PaloAltoFirewallTranslator,
)

SAMPLE_CONFIG = """
/interface ethernet
set [ find default-name=ether1 ] name=ether1-wan comment="Uplink to ISP"
set [ find default-name=ether2 ] name=ether2-lan comment="LAN switch port 1"
set [ find default-name=ether3 ] name=ether3-lan comment="LAN switch port 2"
set [ find default-name=ether4 ] name=ether4-dmz comment="DMZ uplink"
/interface bridge
add name=bridge-lan comment="Main LAN bridge"
/interface bridge port
add bridge=bridge-lan interface=ether2-lan
add bridge=bridge-lan interface=ether3-lan
/interface vlan
add interface=bridge-lan name=vlan20-guest vlan-id=20 comment="Guest VLAN"
add interface=ether4-dmz name=vlan30-dmz vlan-id=30 comment="DMZ VLAN"
/interface list
add name=WAN
add name=LAN
/interface list member
add interface=ether1-wan list=WAN
add interface=bridge-lan list=LAN
/ip address
add address=192.168.10.1/24 interface=bridge-lan comment="LAN gateway"
add address=192.168.20.1/24 interface=vlan20-guest comment="Guest gateway"
add address=172.16.30.1/24 interface=vlan30-dmz comment="DMZ gateway"
add address=203.0.113.10/29 interface=ether1-wan comment="Public IP"
/ip route
add distance=1 dst-address=0.0.0.0/0 gateway=203.0.113.1 comment="default-route"
/ip firewall address-list
add address=192.168.10.0/24 list=trusted-nets comment="Trusted LAN"
add address=10.0.0.5-10.0.0.10 list=blocked-ips comment="Known bad hosts"
/ip firewall filter
add action=accept chain=forward src-address-list=trusted-nets comment="allow-trusted-out"
add action=drop chain=forward src-address-list=blocked-ips comment="drop-blocked"
add action=accept chain=input protocol=tcp dst-port=22 in-interface-list=LAN comment="allow-ssh-from-lan"
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether1-wan comment="lan-masquerade"
add action=dst-nat chain=dstnat comment="port-forward-web" dst-port=8080 in-interface=ether1-wan protocol=tcp to-addresses=192.168.10.100 to-ports=8080
/ip ipsec proposal
add name=esp-aes256 enc-algorithms=aes-256-cbc auth-algorithms=sha1 pfs-group=modp1024
/ip ipsec profile
add name=ike-main dh-group=modp1024 enc-algorithm=aes-256 hash-algorithm=sha1 lifetime=8h
/ip ipsec peer
add name=hq-peer address=203.0.113.50 profile=ike-main exchange-mode=ike2
/ip ipsec policy
add peer=hq-peer src-address=192.168.10.0/24 dst-address=172.16.0.0/24 proposal=esp-aes256 tunnel=yes comment="to-hq"
/system identity
set name=BRANCH-ROUTER-01
"""


def _parse(text: str) -> FirewallConfig:
    tmp_dir = Path(tempfile.mkdtemp())
    path = tmp_dir / "sample.rsc"
    path.write_text(text, encoding="utf-8")
    return MikrotikFirewallParser().parse_file(path)


class PaloAltoFirewallTranslatorTests(unittest.TestCase):
    def setUp(self):
        self.translator = PaloAltoFirewallTranslator()

    def test_full_sample_config_converts_without_exceptions(self):
        config = _parse(SAMPLE_CONFIG)
        output = self.translator.translate(config)
        text = "\n".join(output)

        self.assertIn("set deviceconfig system hostname BRANCH-ROUTER-01", text)
        # Bridge ports become layer2 physical interfaces.
        self.assertIn("set network interface ethernet ethernet1/2 layer2", text)
        self.assertIn("set network interface ethernet ethernet1/3 layer2", text)
        # VLAN-on-bridge becomes a real vlan.<id> unit.
        self.assertIn("set network vlan vlan20-guest vlan-interface vlan.20", text)
        # VLAN-on-routed-parent becomes an ethernetX/Y.<id> sub-interface.
        self.assertIn(
            "set network interface ethernet ethernet1/4 layer3 units ethernet1/4.30 tag 30", text
        )
        # Static route.
        self.assertIn(
            "set network virtual-router default routing-table ip static-route default-route "
            "destination 0.0.0.0/0",
            text,
        )
        # Address list -> address-group.
        self.assertIn("set address-group trusted-nets static", text)
        # IPsec tunnel with the mandatory PSK placeholder + REVIEW note.
        self.assertIn('authentication pre-shared-key key "REPLACE-ME"', text)
        self.assertIn("REVIEW: ike-gateway hq-peer", text)
        # NAT: masquerade -> dynamic-ip-and-port interface-address.
        self.assertIn("source-translation dynamic-ip-and-port interface-address interface ethernet1/1", text)
        # NAT: dst-nat with port forward.
        self.assertIn("destination-translation translated-address 192.168.10.100", text)
        self.assertIn("destination-translation translated-port 8080", text)
        # Filter rules -> security policy with correct action mapping.
        self.assertIn("set rulebase security rules allow-trusted-out action allow", text)
        self.assertIn("set rulebase security rules drop-blocked action deny", text)
        self.assertIn("set service allow-ssh-from-lan-svc protocol tcp port 22", text)

    def test_vlan_on_routed_parent_does_not_also_zone_the_bare_parent(self):
        config = _parse(SAMPLE_CONFIG)
        output = self.translator.translate(config)
        text = "\n".join(output)
        # ether4-dmz has no IP of its own -- it exists only to carry
        # vlan30-dmz's tagged traffic, so it must not also get emitted
        # as its own bare, traffic-less routed interface + zone.
        self.assertNotIn("set zone ether4-dmz", text)
        self.assertNotIn("set network interface ethernet ethernet1/4 layer3\n", text + "\n")

    def test_pan_name_slugifies_unsafe_characters(self):
        self.assertEqual(PaloAltoFirewallTranslator.pan_name("My Router! #1"), "My-Router---1")
        self.assertEqual(PaloAltoFirewallTranslator.pan_name(""), "unnamed")

    def test_lifetime_seconds_parses_units(self):
        self.assertEqual(PaloAltoFirewallTranslator.lifetime_seconds("8h"), 28800)
        self.assertEqual(PaloAltoFirewallTranslator.lifetime_seconds("1d"), 86400)
        self.assertEqual(PaloAltoFirewallTranslator.lifetime_seconds("30m"), 1800)
        # Unparseable input falls back to PAN-OS's own IKE default.
        self.assertEqual(PaloAltoFirewallTranslator.lifetime_seconds("garbage"), 28800)

    def test_resolve_physical_maps_ether_by_default_name(self):
        interface = Interface(name="wan-uplink", interface_type="ethernet", default_name="ether7")
        review = []
        self.assertEqual(self.translator.resolve_physical(interface, review), "ethernet1/7")
        self.assertEqual(review, [])

    def test_resolve_physical_unmappable_interface_returns_none(self):
        interface = Interface(name="bonding1", interface_type="unknown")
        review = []
        self.assertIsNone(self.translator.resolve_physical(interface, review))

    def test_resolve_physical_none_interface_returns_none(self):
        self.assertIsNone(self.translator.resolve_physical(None, []))

    def test_bridge_zone_takes_priority_over_interface_list_zone(self):
        # bridge-lan is a bridge (own zone "bridge-lan") AND a member
        # of interface list "LAN" -- the bridge-derived zone must win
        # since assign_zones applies bridges before list membership.
        config = FirewallConfig(source_vendor="Mikrotik", source_device_type="Firewall")
        config.interfaces.append(Interface(name="bridge-lan", interface_type="bridge"))
        config.interface_list_members.append(InterfaceListMember(list_name="LAN", interface="bridge-lan"))
        zone_map = self.translator.assign_zones(config)
        self.assertEqual(zone_map["bridge-lan"], "bridge-lan")

    def test_unresolvable_bridge_member_is_review_flagged_not_dropped_silently(self):
        config = FirewallConfig(source_vendor="Mikrotik", source_device_type="Firewall")
        bridge = Interface(name="bridge-lan", interface_type="bridge", bridge_ports=["bonding1"])
        config.interfaces.append(bridge)
        config.interfaces.append(Interface(name="bonding1", interface_type="unknown"))
        output = self.translator.translate(config)
        text = "\n".join(output)
        self.assertIn("REVIEW", text)
        self.assertIn("bonding1", text)

    def test_unresolvable_bridge_member_with_its_own_ip_mentions_the_lost_ip(self):
        # Regression test from a real customer config: an EoIP tunnel
        # used as a bridge member for point-to-point routing also
        # carried its own IP. Since the tunnel can't be mapped to a
        # PAN-OS physical interface, that IP has nowhere to go -- the
        # REVIEW note must say so explicitly rather than just noting
        # the member couldn't be mapped, or the IP silently vanishes
        # with zero trace in the output.
        config = FirewallConfig(source_vendor="Mikrotik", source_device_type="Firewall")
        bridge = Interface(name="bridge-lan", interface_type="bridge", bridge_ports=["eoip-tunnel1"])
        config.interfaces.append(bridge)
        config.interfaces.append(
            Interface(name="eoip-tunnel1", interface_type="unknown", ip_addresses=["10.20.100.2/30"])
        )
        output = self.translator.translate(config)
        text = "\n".join(output)
        self.assertIn("10.20.100.2/30", text)
        self.assertIn("was NOT carried over", text)

    def test_resolvable_bridge_member_with_its_own_ip_is_review_flagged_not_dropped_silently(self):
        # Regression test: a real customer config had a physical port
        # (ether1) that resolved FINE to a PAN-OS ethernet slot but was
        # ALSO a bridge member AND carried its own static IP -- a
        # PAN-OS layer2 interface can't hold an IP, so that address was
        # being silently dropped with no trace at all (the sibling case
        # to test_unresolvable_bridge_member_with_its_own_ip_mentions_the_lost_ip,
        # just on the branch where resolve_physical succeeds).
        config = FirewallConfig(source_vendor="Mikrotik", source_device_type="Firewall")
        config.interfaces.append(
            Interface(name="bridge-wan", interface_type="bridge", bridge_ports=["ether1"])
        )
        config.interfaces.append(
            Interface(
                name="ether1",
                interface_type="ethernet",
                default_name="ether1",
                ip_addresses=["172.16.18.1/24"],
            )
        )
        output = self.translator.translate(config)
        text = "\n".join(output)
        self.assertIn("set network interface ethernet ethernet1/1 layer2", text)
        self.assertIn("member 'ether1' (mapped to ethernet1/1) also carries", text)
        self.assertIn("172.16.18.1/24", text)

    def test_unsupported_nat_action_is_review_flagged(self):
        config = FirewallConfig(source_vendor="Mikrotik", source_device_type="Firewall")
        config.nat_rules.append(NatRule(chain="srcnat", action="redirect"))
        output = self.translator.translate(config)
        text = "\n".join(output)
        self.assertIn("REVIEW", text)
        self.assertIn("no automatic PAN-OS", text)

    def test_unsupported_filter_action_is_review_flagged_and_skipped(self):
        config = FirewallConfig(source_vendor="Mikrotik", source_device_type="Firewall")
        config.filter_rules.append(FirewallFilterRule(chain="forward", action="jump"))
        output = self.translator.translate(config)
        text = "\n".join(output)
        self.assertNotIn("set rulebase security rules forward-rule-1", text)
        self.assertIn("action 'jump' has no direct", text)

    def test_ipsec_peer_missing_profile_gets_review_note(self):
        config = FirewallConfig(source_vendor="Mikrotik", source_device_type="Firewall")
        config.ipsec_peers.append(IpsecPeer(name="orphan-peer", address="203.0.113.1"))
        config.ipsec_policies.append(IpsecPolicy(peer_name="orphan-peer", tunnel=True))
        output = self.translator.translate(config)
        text = "\n".join(output)
        self.assertIn("ike-crypto-profile 'default'", text)

    # ------------------------------------------------------------
    # Scope-expansion translation (timezone / DNS / NTP / DHCP /
    # DNS-static / MSS-clamp / management services)
    # ------------------------------------------------------------

    SCOPE_CONFIG = """
/system identity
set name=TESTRTR
/system clock
set time-zone-name=Asia/Jakarta
/system ntp client
set enabled=yes primary-ntp=10.0.0.1 secondary-ntp=10.0.0.2
/interface ethernet
set [ find default-name=ether1 ] name=ether1-wan
set [ find default-name=ether2 ] name=ether2-lan
/ip address
add address=192.168.1.1/24 interface=ether2-lan
/ip pool
add name=dhcp-pool0 ranges=192.168.1.10-192.168.1.100
/ip dhcp-server
add address-pool=dhcp-pool0 interface=ether2-lan name=dhcp1 lease-time=1d
/ip dhcp-server network
add address=192.168.1.0/24 dns-server=192.168.1.1,8.8.8.8 gateway=192.168.1.1
/ip dhcp-client
add interface=ether1-wan disabled=no add-default-route=yes default-route-distance=1
/ip dns
set servers=8.8.8.8,8.8.4.4
/ip dns static
add address=192.168.1.50 name=printer.local
/ip service
set telnet disabled=yes
set www port=8080 disabled=no
set ssh disabled=no
/ip firewall mangle
add chain=forward action=change-mss new-mss=1360 protocol=tcp tcp-flags=syn in-interface=ether1-wan
"""

    def test_system_settings_translate_timezone_dns_ntp(self):
        config = _parse(self.SCOPE_CONFIG)
        text = "\n".join(self.translator.translate(config))
        self.assertIn("set deviceconfig system timezone Asia/Jakarta", text)
        self.assertIn("set deviceconfig system dns-setting servers primary 8.8.8.8", text)
        self.assertIn("set deviceconfig system dns-setting servers secondary 8.8.4.4", text)
        self.assertIn(
            "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.0.0.1", text
        )
        self.assertIn(
            "set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address 10.0.0.2", text
        )

    def test_dhcp_client_binding_translates_to_dhcp_client_role(self):
        config = _parse(self.SCOPE_CONFIG)
        text = "\n".join(self.translator.translate(config))
        self.assertIn("set network interface ethernet ethernet1/1 layer3 dhcp-client enable yes", text)
        self.assertIn(
            "set network interface ethernet ethernet1/1 layer3 dhcp-client create-default-route yes", text
        )
        self.assertIn(
            "set network interface ethernet ethernet1/1 layer3 dhcp-client default-route-metric 1", text
        )

    def test_dhcp_client_and_static_ip_conflict_is_review_flagged(self):
        # ether2-lan has a real static IP from /ip address AND (in
        # this variant) a DHCP-client binding -- both can't apply on a
        # PAN-OS layer3 interface, so the conflict must be surfaced,
        # not silently resolved one way or the other.
        conflicting = self.SCOPE_CONFIG.replace(
            "add interface=ether1-wan disabled=no add-default-route=yes default-route-distance=1",
            "add interface=ether2-lan disabled=no add-default-route=yes default-route-distance=1",
        )
        config = _parse(conflicting)
        text = "\n".join(self.translator.translate(config))
        self.assertIn("has BOTH a static IP", text)
        self.assertIn("192.168.1.1/24", text)

    def test_dhcp_server_resolves_real_pan_interface_and_matches_network(self):
        config = _parse(self.SCOPE_CONFIG)
        text = "\n".join(self.translator.translate(config))
        # Must resolve to the real PAN-OS interface name (ethernet1/2),
        # not the raw Mikrotik-side interface name (ether2-lan) --
        # "network dhcp interface" is keyed by PAN-OS interface names.
        self.assertIn("set network dhcp interface ethernet1/2 server enable yes", text)
        self.assertIn(
            "set network dhcp interface ethernet1/2 server ip-pool [ 192.168.1.10-192.168.1.100 ]", text
        )
        self.assertIn("set network dhcp interface ethernet1/2 server option gateway 192.168.1.1", text)
        self.assertIn("set network dhcp interface ethernet1/2 server option dns-server-1 192.168.1.1", text)
        self.assertIn("set network dhcp interface ethernet1/2 server option dns-server-2 8.8.8.8", text)
        self.assertNotIn("interface ether2-lan", text)

    def test_dhcp_server_with_missing_pool_is_review_flagged_not_guessed(self):
        config = FirewallConfig(source_vendor="Mikrotik", source_device_type="Firewall")
        config.dhcp_servers.append(
            DhcpServerBinding(name="dhcp1", interface="ether2-lan", address_pool="missing-pool")
        )
        output = self.translator.translate(config)
        text = "\n".join(output)
        self.assertNotIn("set network dhcp interface", text)
        self.assertIn("its address pool 'missing-pool' was not found", text)

    def test_dns_static_translates_to_dns_proxy_object(self):
        config = _parse(self.SCOPE_CONFIG)
        text = "\n".join(self.translator.translate(config))
        self.assertIn('set dns-proxy default static-entries "printer.local" name printer.local', text)
        self.assertIn('set dns-proxy default static-entries "printer.local" address 192.168.1.50', text)
        self.assertIn("DNS Proxy object", text)

    def test_mss_clamp_resolves_interface_and_emits_adjust_tcp_mss(self):
        config = _parse(self.SCOPE_CONFIG)
        text = "\n".join(self.translator.translate(config))
        self.assertIn("set network interface ethernet ethernet1/1 layer3 adjust-tcp-mss enable yes", text)
        self.assertIn(
            "set network interface ethernet ethernet1/1 layer3 adjust-tcp-mss ipv4-mss-adjustment 1360", text
        )

    def test_mss_clamp_with_no_interface_filter_is_review_flagged(self):
        config = FirewallConfig(source_vendor="Mikrotik", source_device_type="Firewall")
        config.mss_clamps.append(MssClamp(new_mss=1400))
        output = self.translator.translate(config)
        text = "\n".join(output)
        self.assertNotIn("adjust-tcp-mss enable", text)
        self.assertIn("applied to ALL forwarded traffic", text)

    def test_management_services_map_telnet_and_http_disable_flags(self):
        config = _parse(self.SCOPE_CONFIG)
        text = "\n".join(self.translator.translate(config))
        self.assertIn("set deviceconfig system service disable-telnet yes", text)
        self.assertIn("set deviceconfig system service disable-http no", text)
        # www had a custom port (8080) -- that must be called out since
        # PAN-OS's disable-http toggle carries no port override.
        self.assertIn("custom port (8080)", text)

    def test_management_service_with_no_pan_os_equivalent_is_review_flagged(self):
        config = _parse(self.SCOPE_CONFIG)
        text = "\n".join(self.translator.translate(config))
        self.assertIn(
            "management service 'ssh' (enabled): no direct PAN-OS deviceconfig system service equivalent",
            text,
        )


if __name__ == "__main__":
    unittest.main()
