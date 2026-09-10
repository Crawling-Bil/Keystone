"""Unit tests for MikrotikFirewallParser -- the RouterOS "/export"
parser backing Configuration Studio's new Mikrotik -> Palo Alto
firewall migration path (see translators/firewall/paloalto.py).

RouterOS export syntax is fundamentally different from the IOS/VRP
line-oriented configs the other parsers in this project handle: it is
grouped under "/path" section headers followed by "add"/"set"
key=value statements, so this parser is a section dispatcher rather
than a per-keyword line matcher. These tests exercise the section
handlers individually plus the two behaviors that needed a real fix
during development: physical interfaces are only ever "set" (never
"add", since ports always exist) and must keep their original
"default-name" even after being renamed, and bridge-port membership
must reconcile correctly regardless of whether a bridge's own "add"
line appears before or after its ports' "add" lines in the file.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from features.configuration_studio.converter_engine.parsers.firewall.mikrotik import (
    MikrotikFirewallParser,
)


def _write_config(tmp_dir: Path, text: str) -> Path:
    path = tmp_dir / "sample.rsc"
    path.write_text(text, encoding="utf-8")
    return path


class MikrotikFirewallParserTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.parser = MikrotikFirewallParser()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_system_identity_sets_hostname(self):
        path = _write_config(
            self.tmp_dir,
            "/system identity\nset name=BRANCH-ROUTER-01\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(config.hostname, "BRANCH-ROUTER-01")

    def test_physical_interface_rename_keeps_default_name(self):
        # A renamed port ("ether1" -> "ether1-wan") must still resolve
        # back to its real RouterOS slot via default_name -- this is
        # exactly what the translator's resolve_physical() depends on.
        path = _write_config(
            self.tmp_dir,
            "/interface ethernet\n"
            'set [ find default-name=ether1 ] name=ether1-wan comment="Uplink"\n',
        )
        config = self.parser.parse_file(path)
        self.assertEqual(len(config.interfaces), 1)
        interface = config.interfaces[0]
        self.assertEqual(interface.name, "ether1-wan")
        self.assertEqual(interface.default_name, "ether1")
        self.assertEqual(interface.comment, "Uplink")
        self.assertEqual(interface.interface_type, "ethernet")

    def test_physical_interface_add_line_is_rejected_to_review(self):
        # Physical ports always exist -- a bare "add" under
        # /interface ethernet is not valid /export output and must be
        # preserved for manual review rather than fabricating a port.
        path = _write_config(
            self.tmp_dir,
            "/interface ethernet\nadd name=ether5 comment=bogus\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(config.interfaces, [])
        self.assertTrue(any("ether5" in item for item in config.review_commands))

    def test_bridge_port_before_bridge_declaration_still_attaches(self):
        # Regression test for the bridge_port_membership post-pass:
        # ports can be listed before their bridge's own "add" line in
        # a hand-trimmed file, and must still end up attached.
        path = _write_config(
            self.tmp_dir,
            "/interface bridge port\n"
            "add bridge=bridge-lan interface=ether2\n"
            "add bridge=bridge-lan interface=ether3\n"
            "/interface bridge\n"
            "add name=bridge-lan comment=LAN\n",
        )
        config = self.parser.parse_file(path)
        bridge = config.find_interface("bridge-lan")
        self.assertIsNotNone(bridge)
        self.assertEqual(bridge.interface_type, "bridge")
        self.assertEqual(sorted(bridge.bridge_ports), ["ether2", "ether3"])

    def test_bridge_declared_before_its_ports_still_attaches(self):
        path = _write_config(
            self.tmp_dir,
            "/interface bridge\n"
            "add name=bridge-lan\n"
            "/interface bridge port\n"
            "add bridge=bridge-lan interface=ether2\n",
        )
        config = self.parser.parse_file(path)
        bridge = config.find_interface("bridge-lan")
        self.assertEqual(bridge.bridge_ports, ["ether2"])

    def test_bridge_port_for_never_declared_bridge_creates_stub(self):
        # A bridge with ports but no "/interface bridge add" line of
        # its own (unusual, but not invalid) must not lose its ports.
        path = _write_config(
            self.tmp_dir,
            "/interface bridge port\nadd bridge=ghost-bridge interface=ether2\n",
        )
        config = self.parser.parse_file(path)
        bridge = config.find_interface("ghost-bridge")
        self.assertIsNotNone(bridge)
        self.assertEqual(bridge.bridge_ports, ["ether2"])

    def test_vlan_interface_parsed_with_parent_and_id(self):
        path = _write_config(
            self.tmp_dir,
            "/interface vlan\n"
            "add interface=bridge-lan name=vlan20-guest vlan-id=20 comment=Guest\n",
        )
        config = self.parser.parse_file(path)
        vlan = config.find_interface("vlan20-guest")
        self.assertEqual(vlan.interface_type, "vlan")
        self.assertEqual(vlan.vlan_id, 20)
        self.assertEqual(vlan.parent_interface, "bridge-lan")

    def test_ip_address_attaches_to_existing_interface(self):
        path = _write_config(
            self.tmp_dir,
            "/interface bridge\nadd name=bridge-lan\n"
            "/ip address\nadd address=192.168.10.1/24 interface=bridge-lan\n",
        )
        config = self.parser.parse_file(path)
        bridge = config.find_interface("bridge-lan")
        self.assertEqual(bridge.ip_addresses, ["192.168.10.1/24"])

    def test_ip_address_for_unknown_interface_creates_unknown_stub(self):
        # A referenced interface this parser has no section handler
        # for (bonding, PPPoE, etc.) must not lose its IP silently.
        path = _write_config(
            self.tmp_dir,
            "/ip address\nadd address=10.0.0.1/30 interface=bonding1\n",
        )
        config = self.parser.parse_file(path)
        stub = config.find_interface("bonding1")
        self.assertIsNotNone(stub)
        self.assertEqual(stub.interface_type, "unknown")
        self.assertEqual(stub.ip_addresses, ["10.0.0.1/30"])

    def test_static_route_fields(self):
        path = _write_config(
            self.tmp_dir,
            "/ip route\n"
            "add distance=1 dst-address=0.0.0.0/0 gateway=203.0.113.1 comment=default\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(len(config.static_routes), 1)
        route = config.static_routes[0]
        self.assertEqual(route.gateway, "203.0.113.1")
        self.assertEqual(route.distance, 1)
        self.assertEqual(route.comment, "default")

    def test_address_list_and_filter_and_nat_rules(self):
        path = _write_config(
            self.tmp_dir,
            "/ip firewall address-list\n"
            "add address=192.168.10.0/24 list=trusted comment=LAN\n"
            "/ip firewall filter\n"
            "add action=accept chain=forward src-address-list=trusted\n"
            "/ip firewall nat\n"
            "add action=masquerade chain=srcnat out-interface=ether1-wan\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(len(config.address_lists), 1)
        self.assertEqual(config.address_lists[0].list_name, "trusted")
        self.assertEqual(len(config.filter_rules), 1)
        self.assertEqual(config.filter_rules[0].src_address_list, "trusted")
        self.assertEqual(len(config.nat_rules), 1)
        self.assertEqual(config.nat_rules[0].action, "masquerade")

    def test_ipsec_sections_parsed(self):
        path = _write_config(
            self.tmp_dir,
            "/ip ipsec proposal\nadd name=esp1 enc-algorithms=aes-256-cbc\n"
            "/ip ipsec profile\nadd name=ike1 dh-group=modp1024\n"
            "/ip ipsec peer\nadd name=hq address=203.0.113.50 profile=ike1\n"
            "/ip ipsec policy\n"
            "add peer=hq src-address=192.168.10.0/24 dst-address=172.16.0.0/24 proposal=esp1 tunnel=yes\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(config.ipsec_proposals[0].name, "esp1")
        self.assertEqual(config.ipsec_profiles[0].name, "ike1")
        self.assertEqual(config.ipsec_peers[0].address, "203.0.113.50")
        self.assertEqual(config.ipsec_policies[0].peer_name, "hq")
        self.assertTrue(config.ipsec_policies[0].tunnel)

    def test_unrecognized_section_goes_to_review_commands(self):
        path = _write_config(
            self.tmp_dir,
            "/some/unhandled/section\nadd foo=bar\n",
        )
        config = self.parser.parse_file(path)
        self.assertTrue(any("foo=bar" in item for item in config.review_commands))

    def test_statement_before_any_section_header_goes_to_review(self):
        path = _write_config(self.tmp_dir, "add name=orphan\n")
        config = self.parser.parse_file(path)
        self.assertIn("add name=orphan", config.review_commands)

    def test_line_continuation_is_joined_before_parsing(self):
        path = _write_config(
            self.tmp_dir,
            "/ip firewall filter\n"
            "add action=accept chain=forward \\\n"
            "    comment=\"multi line comment\"\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(len(config.filter_rules), 1)
        self.assertEqual(config.filter_rules[0].comment, "multi line comment")

    def test_field_wrapped_mid_key_equals_value_is_reconstructed_correctly(self):
        # Regression test: a real customer /export routinely wraps a
        # long line right after "key=", with the value starting on the
        # next (indented) line -- e.g. "comment=\\" then "    \"text\"".
        # An earlier version of _join_continuations rstripped away any
        # real trailing separator space and then unconditionally
        # reinserted exactly one space, which happened to look right
        # for a wrap that falls BETWEEN two tokens but injected a bogus
        # space into a wrap that falls INSIDE "key=value", breaking
        # _KV_RE (whose value pattern doesn't allow whitespace after
        # "=") and silently emptying comment/name/etc. on real files.
        path = _write_config(
            self.tmp_dir,
            "/interface ethernet\n"
            "set [ find default-name=ether5 ] advertise=\\\n"
            "    10M-half,10M-full comment=\\\n"
            '    "BACKUP LINK" mac-address=E4:8D:8C:5F:A8:12 name=\\\n'
            "    ether5-WAN\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(len(config.interfaces), 1)
        interface = config.interfaces[0]
        self.assertEqual(interface.name, "ether5-WAN")
        self.assertEqual(interface.default_name, "ether5")
        self.assertEqual(interface.comment, "BACKUP LINK")

    def test_field_wrapped_between_tokens_keeps_its_separator_space(self):
        # The companion case: a wrap that falls between two whole
        # tokens (not mid "key=value") must still get exactly one
        # space between them, not zero and not two.
        path = _write_config(
            self.tmp_dir,
            "/ip dhcp-server\n"
            "add address-pool=dhcp_pool2 authoritative=after-2sec-delay disabled=no \\\n"
            "    interface=bridge-LAN lease-time=3d10m name=dhcp1\n",
        )
        config = self.parser.parse_file(path)
        # /ip dhcp-server IS modeled (DhcpServerBinding) -- if the wrap
        # joined "disabled=no" and "interface=bridge-LAN" without a
        # separating space, _parse_kv would mangle both fields (e.g.
        # producing "disabled=nointerface=bridge-LAN" as a single
        # bogus token), so correct parsing of each field below is
        # itself proof the continuation join kept its separator space.
        self.assertEqual(len(config.dhcp_servers), 1)
        server = config.dhcp_servers[0]
        self.assertEqual(server.name, "dhcp1")
        self.assertFalse(server.disabled)
        self.assertEqual(server.interface, "bridge-LAN")
        self.assertEqual(server.address_pool, "dhcp_pool2")
        self.assertEqual(server.lease_time, "3d10m")

    def test_disabled_bridge_port_membership_is_excluded_and_reviewed(self):
        # Regression test: a real customer config had a bridge-port
        # membership itself marked disabled=yes (independent of the
        # bridge's and the underlying interface's own disabled state)
        # for a port that separately carried its own routed IP as a
        # standalone WAN/modem uplink. Including it as an active
        # member anyway silently folded that interface into the
        # bridge's zone and dropped its IP with no trace.
        path = _write_config(
            self.tmp_dir,
            "/interface ethernet\n"
            "set [ find default-name=ether4 ] name=ether4-Modem\n"
            "/interface bridge\n"
            "add name=bridge-LAN\n"
            "/interface bridge port\n"
            "add bridge=bridge-LAN disabled=yes interface=ether4-Modem\n"
            "add bridge=bridge-LAN interface=ether4-Modem\n"
            "/ip address\n"
            "add address=192.168.8.2/24 interface=ether4-Modem\n",
        )
        config = self.parser.parse_file(path)
        bridge = config.find_interface("bridge-LAN")
        self.assertEqual(bridge.bridge_ports, ["ether4-Modem"])
        modem = config.find_interface("ether4-Modem")
        self.assertEqual(modem.ip_addresses, ["192.168.8.2/24"])
        self.assertTrue(
            any("disabled bridge-port membership" in item for item in config.review_commands)
        )

    def test_source_vendor_and_device_type_are_stamped(self):
        path = _write_config(self.tmp_dir, "/system identity\nset name=R1\n")
        config = self.parser.parse_file(path)
        self.assertEqual(config.source_vendor, "Mikrotik")
        self.assertEqual(config.source_device_type, "Firewall")

    # ------------------------------------------------------------
    # Scope-expansion handlers (timezone / NTP / DHCP / DNS / mgmt
    # services / MSS clamping / no-equivalent sections)
    # ------------------------------------------------------------

    def test_system_clock_sets_timezone(self):
        path = _write_config(
            self.tmp_dir, "/system clock\nset time-zone-name=Asia/Jakarta\n"
        )
        config = self.parser.parse_file(path)
        self.assertEqual(config.timezone, "Asia/Jakarta")

    def test_ntp_client_collects_primary_and_secondary(self):
        path = _write_config(
            self.tmp_dir,
            "/system ntp client\nset enabled=yes primary-ntp=10.0.0.1 secondary-ntp=10.0.0.2\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(config.ntp_servers, ["10.0.0.1", "10.0.0.2"])

    def test_ip_pool_creates_dhcp_pool(self):
        path = _write_config(
            self.tmp_dir,
            "/ip pool\nadd name=dhcp-pool0 ranges=192.168.1.10-192.168.1.100\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(len(config.dhcp_pools), 1)
        pool = config.dhcp_pools[0]
        self.assertEqual(pool.name, "dhcp-pool0")
        self.assertEqual(pool.ranges, "192.168.1.10-192.168.1.100")

    def test_dhcp_server_network_creates_network_entry(self):
        path = _write_config(
            self.tmp_dir,
            "/ip dhcp-server network\n"
            "add address=192.168.1.0/24 gateway=192.168.1.1 dns-server=192.168.1.1,8.8.8.8\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(len(config.dhcp_server_networks), 1)
        network = config.dhcp_server_networks[0]
        self.assertEqual(network.address, "192.168.1.0/24")
        self.assertEqual(network.gateway, "192.168.1.1")
        self.assertEqual(network.dns_servers, "192.168.1.1,8.8.8.8")

    def test_dhcp_client_binding_records_default_route_distance(self):
        path = _write_config(
            self.tmp_dir,
            "/ip dhcp-client\n"
            "add interface=ether1-WAN disabled=no add-default-route=yes default-route-distance=1\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(len(config.dhcp_client_bindings), 1)
        binding = config.dhcp_client_bindings[0]
        self.assertEqual(binding.interface, "ether1-WAN")
        self.assertEqual(binding.default_route_distance, 1)
        self.assertFalse(binding.disabled)

    def test_dns_sets_server_list(self):
        path = _write_config(self.tmp_dir, "/ip dns\nset servers=8.8.8.8,8.8.4.4\n")
        config = self.parser.parse_file(path)
        self.assertEqual(config.dns_servers, ["8.8.8.8", "8.8.4.4"])

    def test_dns_static_creates_entry(self):
        path = _write_config(
            self.tmp_dir, "/ip dns static\nadd address=192.168.1.50 name=printer.local\n"
        )
        config = self.parser.parse_file(path)
        self.assertEqual(len(config.dns_static_entries), 1)
        entry = config.dns_static_entries[0]
        self.assertEqual(entry.name, "printer.local")
        self.assertEqual(entry.address, "192.168.1.50")

    def test_ip_service_bare_leading_word_is_parsed(self):
        # /ip service uses a naming convention unique among RouterOS
        # sections: "set <service-name> field=value ..." with the
        # object name as a BARE leading word, not a [ find ... ]
        # selector or numeric index like every other section.
        path = _write_config(
            self.tmp_dir,
            "/ip service\nset telnet disabled=yes\nset www port=8080 disabled=no\n",
        )
        config = self.parser.parse_file(path)
        by_name = {svc.name: svc for svc in config.management_services}
        self.assertTrue(by_name["telnet"].disabled)
        self.assertFalse(by_name["www"].disabled)
        self.assertEqual(by_name["www"].port, 8080)

    def test_mangle_change_mss_creates_mss_clamp(self):
        path = _write_config(
            self.tmp_dir,
            "/ip firewall mangle\n"
            "add chain=forward action=change-mss new-mss=1360 protocol=tcp "
            "tcp-flags=syn in-interface=ether1-WAN\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(len(config.mss_clamps), 1)
        clamp = config.mss_clamps[0]
        self.assertEqual(clamp.new_mss, 1360)
        self.assertEqual(clamp.in_interface, "ether1-WAN")

    def test_mangle_non_change_mss_action_is_review_flagged(self):
        path = _write_config(
            self.tmp_dir,
            "/ip firewall mangle\nadd chain=forward action=mark-routing new-routing-mark=viaWAN2\n",
        )
        config = self.parser.parse_file(path)
        self.assertEqual(config.mss_clamps, [])
        self.assertTrue(
            any("mark-routing" in item and "Policy-Based Forwarding" in item
                for item in config.review_commands)
        )

    def test_no_equivalent_section_produces_detailed_review_note(self):
        # /interface eoip has zero PAN-OS equivalent -- per the user's
        # explicit choice, this must NOT be force-mapped to anything
        # (e.g. GRE) but instead land as a detailed REVIEW note
        # carrying both the raw statement and the real alternative.
        path = _write_config(
            self.tmp_dir,
            "/interface eoip\nadd name=eoip-tunnel1 remote-address=1.2.3.4 tunnel-id=5\n",
        )
        config = self.parser.parse_file(path)
        matches = [item for item in config.review_commands if "eoip-tunnel1" in item]
        self.assertEqual(len(matches), 1)
        self.assertIn("remote-address=1.2.3.4", matches[0])
        self.assertIn("GRE", matches[0])


if __name__ == "__main__":
    unittest.main()
