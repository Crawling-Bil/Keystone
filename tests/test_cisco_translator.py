import unittest

from features.configuration_studio.converter_engine.models.switch import (
    Interface,
    StaticRoute,
    SwitchConfig,
    VLAN,
)
from features.configuration_studio.converter_engine.translators.switch.cisco import (
    CiscoSwitchTranslator,
)


class CiscoTranslatorTestBase(unittest.TestCase):
    """
    Shared helpers, mirroring tests/test_huawei_translator.py's
    DhcpSnoopingTranslationTest pattern. Covers the new
    CiscoSwitchTranslator (Section 3a, memory-keystone.md) — a
    baseline translator, scoped comparably to ArubaSwitchTranslator
    rather than HuaweiSwitchTranslator's much deeper correctness-fix
    history. See cisco.py's own class docstring for the exact scope
    rationale.
    """

    def setUp(self):
        self.translator = CiscoSwitchTranslator()

    def _config(self):
        return SwitchConfig(
            source_vendor="Huawei",
            source_device_type="Switch",
            source_file="test.txt",
        )


class HeaderAndVlanTest(CiscoTranslatorTestBase):

    def test_hostname_and_header_emitted(self):
        config = self._config()
        config.hostname = "SW-TEST"
        output = "\n".join(self.translator.translate(config))
        self.assertIn("hostname SW-TEST", output)
        self.assertIn("Generated Huawei -> Cisco Configuration", output)

    def test_vlan_with_name(self):
        config = self._config()
        config.vlans.append(VLAN(vlan_id=10, name="USERS"))
        output = "\n".join(self.translator.translate(config))
        self.assertIn("vlan 10", output)
        self.assertIn(" name USERS", output)


class GlobalLldpAndDhcpSnoopingTest(CiscoTranslatorTestBase):
    """
    Unlike the Cisco -> Huawei direction, Cisco IOS's own LLDP default
    (disabled) already matches config.lldp_enabled's False default, so
    no inversion / REVIEW comment is needed on this side — regression
    guard for that asymmetry.
    """

    def test_lldp_enabled_emits_lldp_run(self):
        config = self._config()
        config.lldp_enabled = True
        output = "\n".join(self.translator.translate(config))
        self.assertIn("lldp run", output)

    def test_lldp_disabled_emits_nothing_and_no_review(self):
        output = "\n".join(self.translator.translate(self._config()))
        self.assertNotIn("lldp run", output)
        self.assertNotIn("REVIEW-LLDP", output)

    def test_dhcp_snooping_global_and_vlan_list(self):
        config = self._config()
        config.dhcp_snooping_enabled = True
        config.dhcp_snooping_vlans = ["10,20,30-32"]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("ip dhcp snooping\n", output)
        self.assertIn("ip dhcp snooping vlan 10,20,30-32", output)

    def test_dhcp_snooping_disabled_emits_nothing(self):
        output = "\n".join(self.translator.translate(self._config()))
        self.assertNotIn("dhcp snooping", output)


class InterfaceSwitchportTest(CiscoTranslatorTestBase):

    def test_access_port(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.mode = "access"
        interface.access_vlan = 20
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn("interface GigabitEthernet1/0/1", output)
        self.assertIn(" switchport mode access", output)
        self.assertIn(" switchport access vlan 20", output)

    def test_trunk_port_with_native_and_allowed(self):
        interface = Interface(name="GigabitEthernet1/0/2")
        interface.mode = "trunk"
        interface.native_vlan = 1
        interface.allowed_vlans = ["10", "20", "30-32"]
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" switchport mode trunk", output)
        self.assertIn(" switchport trunk native vlan 1", output)
        self.assertIn(" switchport trunk allowed vlan 10,20,30-32", output)

    def test_shutdown_only_emitted_when_true(self):
        up_interface = Interface(name="GigabitEthernet1/0/1")
        down_interface = Interface(name="GigabitEthernet1/0/2")
        down_interface.shutdown = True
        config = self._config()
        config.interfaces.extend([up_interface, down_interface])
        output = self.translator.translate(config)
        text = "\n".join(output)
        # Real Cisco "show running-config" convention: "no shutdown"
        # is the implicit default and is never printed.
        self.assertNotIn(" no shutdown", text)
        self.assertIn(" shutdown", text)


class InterfaceRoutedTest(CiscoTranslatorTestBase):

    def test_physical_routed_port_gets_no_switchport(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.ip_address = "10.1.1.1"
        interface.subnet_mask = "255.255.255.0"
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" no switchport", output)
        self.assertIn(" ip address 10.1.1.1 255.255.255.0", output)

    def test_svi_does_not_get_no_switchport(self):
        interface = Interface(name="Vlan10")
        interface.ip_address = "10.1.1.1"
        interface.subnet_mask = "255.255.255.0"
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertNotIn(" no switchport", output)
        self.assertIn(" ip address 10.1.1.1 255.255.255.0", output)

    def test_helper_addresses_and_ospf(self):
        interface = Interface(name="Vlan20")
        interface.ip_address = "10.2.2.1"
        interface.subnet_mask = "255.255.255.0"
        interface.helper_addresses = ["10.85.10.10", "10.85.10.11"]
        interface.ospf_process = 1
        interface.ospf_area = "0.0.0.0"
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" ip helper-address 10.85.10.10", output)
        self.assertIn(" ip helper-address 10.85.10.11", output)
        self.assertIn(" ip ospf 1 area 0.0.0.0", output)


class InterfaceStpVoiceVlanLldpTest(CiscoTranslatorTestBase):
    """
    Cisco's own guard root / guard loop, bpduguard / bpdufilter, and
    voice VLAN are all genuinely per-interface — no global/interface
    scope mismatch to correct for here (contrast huawei.py's BPDU
    Guard handling, which required moving it to a global command).
    """

    def test_portfast_bpduguard_bpdufilter(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.spanning_tree_portfast = True
        interface.bpduguard = True
        interface.bpdufilter = True
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" spanning-tree portfast", output)
        self.assertIn(" spanning-tree bpduguard enable", output)
        self.assertIn(" spanning-tree bpdufilter enable", output)

    def test_root_guard_and_loop_guard_separate_interfaces(self):
        root_if = Interface(name="GigabitEthernet1/0/1")
        root_if.spanning_tree_root_guard = True
        loop_if = Interface(name="GigabitEthernet1/0/2")
        loop_if.spanning_tree_loop_guard = True
        config = self._config()
        config.interfaces.extend([root_if, loop_if])
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" spanning-tree guard root", output)
        self.assertIn(" spanning-tree guard loop", output)

    def test_both_guards_conflict_flagged(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.spanning_tree_root_guard = True
        interface.spanning_tree_loop_guard = True
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" spanning-tree guard root", output)
        self.assertIn("REVIEW-STP-GUARD", output)
        self.assertNotIn(" spanning-tree guard loop", output)

    def test_voice_vlan(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.voice_vlan_id = 150
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" switchport voice vlan 150", output)

    def test_lldp_transmit_and_receive_disabled(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.lldp_transmit_disabled = True
        interface.lldp_receive_disabled = True
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" no lldp transmit", output)
        self.assertIn(" no lldp receive", output)


class InterfaceStormControlPortSecurityDhcpSnoopingTest(CiscoTranslatorTestBase):

    def test_storm_control(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.storm_control_broadcast_level = "80.0"
        interface.storm_control_action = "shutdown"
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" storm-control broadcast level 80.0", output)
        self.assertIn(" storm-control action shutdown", output)

    def test_port_security_with_sticky_macs(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.port_security_enabled = True
        interface.port_security_max = 3
        interface.port_security_violation = "restrict"
        interface.port_security_sticky = True
        interface.port_security_sticky_macs = ["aaaa.bbbb.cccc"]
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" switchport port-security", output)
        self.assertIn(" switchport port-security maximum 3", output)
        self.assertIn(" switchport port-security violation restrict", output)
        self.assertIn(" switchport port-security mac-address sticky", output)
        self.assertIn(
            " switchport port-security mac-address sticky aaaa.bbbb.cccc",
            output,
        )

    def test_dhcp_snooping_trust_and_ipsg(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.dhcp_snooping_trusted = True
        interface.ip_source_guard_enabled = True
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" ip dhcp snooping trust", output)
        self.assertIn(" ip verify source", output)


class LacpModeTest(CiscoTranslatorTestBase):

    def test_known_active_passive_pass_through(self):
        self.assertEqual(
            CiscoSwitchTranslator.translate_lacp_mode("active"), "active"
        )
        self.assertEqual(
            CiscoSwitchTranslator.translate_lacp_mode("passive"), "passive"
        )

    def test_static_and_on_map_to_on(self):
        self.assertEqual(CiscoSwitchTranslator.translate_lacp_mode("static"), "on")
        self.assertEqual(CiscoSwitchTranslator.translate_lacp_mode("on"), "on")

    def test_unrecognized_value_returns_none(self):
        # e.g. a raw Huawei source line, not a normalized keyword.
        self.assertIsNone(
            CiscoSwitchTranslator.translate_lacp_mode("lacp priority 100")
        )

    def test_channel_group_with_unrecognized_lacp_falls_back_to_on_and_reviews(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.channel_group = 5
        interface.lacp_mode = "lacp priority 100"
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" channel-group 5 mode on", output)
        self.assertIn("REVIEW-LACP-MODE", output)

    def test_channel_group_with_known_mode_no_review(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.channel_group = 5
        interface.lacp_mode = "active"
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" channel-group 5 mode active", output)
        self.assertNotIn("REVIEW-LACP-MODE", output)


class InterfaceNameConversionTest(unittest.TestCase):

    def test_aruba_lag_spelling_converted(self):
        self.assertEqual(
            CiscoSwitchTranslator.convert_interface_name("lag 1"),
            "Port-channel1",
        )

    def test_aruba_vlan_spelling_converted(self):
        self.assertEqual(
            CiscoSwitchTranslator.convert_interface_name("vlan 10"),
            "Vlan10",
        )

    def test_already_cisco_style_name_passes_through(self):
        # As produced by HuaweiSwitchParser.normalize_interface_name()
        # (Vlanif10 -> Vlan10, Eth-Trunk1 -> Port-channel1) before this
        # translator ever sees it.
        self.assertEqual(
            CiscoSwitchTranslator.convert_interface_name("Vlan10"), "Vlan10"
        )
        self.assertEqual(
            CiscoSwitchTranslator.convert_interface_name("Port-channel1"),
            "Port-channel1",
        )

    def test_physical_port_name_left_as_is(self):
        self.assertEqual(
            CiscoSwitchTranslator.convert_interface_name("10GE1/0/1"),
            "10GE1/0/1",
        )


class StaticRouteAndGlobalCommandTest(CiscoTranslatorTestBase):

    def test_static_route_with_cidr_destination(self):
        route = StaticRoute(
            destination="10.10.0.0/24", mask="", next_hop="10.1.1.254"
        )
        line = self.translator.translate_static_route(route)
        self.assertEqual(line, "ip route 10.10.0.0 255.255.255.0 10.1.1.254")

    def test_static_route_with_separate_mask(self):
        route = StaticRoute(
            destination="10.10.0.0", mask="255.255.255.0",
            next_hop="10.1.1.254",
        )
        line = self.translator.translate_static_route(route)
        self.assertEqual(line, "ip route 10.10.0.0 255.255.255.0 10.1.1.254")

    def test_default_gateway(self):
        config = self._config()
        config.default_gateway = "10.1.1.1"
        output = "\n".join(self.translator.translate(config))
        self.assertIn("ip default-gateway 10.1.1.1", output)

    def test_known_global_commands_pass_through(self):
        config = self._config()
        config.global_commands = [
            "ntp server 10.1.1.1",
            "snmp-server community public RO",
            "router ospf 1",
        ]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("ntp server 10.1.1.1", output)
        self.assertIn("snmp-server community public RO", output)
        self.assertIn("router ospf 1", output)

    def test_aaa_tacacs_radius_acl_flagged_for_review(self):
        config = self._config()
        config.global_commands = [
            "aaa new-model",
            "tacacs-server host 10.1.1.5",
            "radius-server host 10.1.1.6",
            "ip access-list extended TEST",
        ]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("REVIEW-AAA", output)
        self.assertIn("REVIEW-TACACS", output)
        self.assertIn("REVIEW-RADIUS", output)
        self.assertIn("REVIEW-ACL", output)

    def test_unrecognized_global_command_preserved_verbatim_for_review(self):
        # e.g. raw Huawei-native syntax, which this baseline translator
        # does not attempt to recognize — see cisco.py's class
        # docstring.
        config = self._config()
        config.global_commands = ["snmp-agent sys-info location HQ"]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("REVIEW-UNSUPPORTED", output)
        self.assertIn("snmp-agent sys-info location HQ", output)


class UnsupportedInterfaceCommandsTest(CiscoTranslatorTestBase):

    def test_unrecognized_interface_commands_preserved_for_review(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.commands = ["some-unmapped-command 123"]
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn("REVIEW-UNSUPPORTED: some-unmapped-command 123", output)


class AaaRadiusTacacsPassthroughTest(CiscoTranslatorTestBase):
    """
    Implemented 2026-08-30 (memory-keystone.md Section 3b). Previously
    config.aaa_commands/radius_commands/tacacs_commands were parsed by
    CiscoSwitchParser but NEVER rendered anywhere in translate() —
    silently dropped from every conversion, Cisco-sourced or not, a
    real correctness bug distinct from (and worse than) the
    documented "left as REVIEW-flagged passthrough" scope note. Fixed:
    Cisco-native raw lines pass through cleanly (re-indented where
    they represent a named sub-block).
    """

    def _cisco_config(self):
        return SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )

    def test_classic_radius_and_tacacs_passthrough(self):
        config = self._cisco_config()
        config.aaa_commands = [
            "aaa new-model",
            "aaa authentication login default group RADIUS-Group local",
        ]
        config.radius_commands = [
            "radius-server host 10.1.1.10 auth-port 1812 acct-port 1813 key SECRET",
        ]
        config.tacacs_commands = [
            "tacacs-server host 10.1.1.11 key SECRET2",
        ]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("aaa new-model", output)
        self.assertIn(
            "aaa authentication login default group RADIUS-Group local",
            output,
        )
        self.assertIn(
            "radius-server host 10.1.1.10 auth-port 1812 acct-port 1813 key SECRET",
            output,
        )
        self.assertIn("tacacs-server host 10.1.1.11 key SECRET2", output)

    def test_aaa_new_model_synthesized_when_missing(self):
        # A source with RADIUS/TACACS+ servers but no explicit "aaa
        # new-model" line would otherwise produce config where the
        # server definitions are never actually used for
        # authentication — defensively prepended.
        config = self._cisco_config()
        config.radius_commands = ["radius-server host 10.1.1.10 key SECRET"]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("aaa new-model", output)

    def test_named_radius_block_reindented(self):
        config = self._cisco_config()
        config.radius_commands = [
            "radius server ISE-lab",
            "address ipv4 10.48.39.134 auth-port 1812 acct-port 1813",
            "key Cisco123",
        ]
        output = self.translator.translate(config)
        # Header line unindented (top-level); sub-lines get a single
        # leading space — list-membership checks distinguish the two
        # exactly, since a plain substring check wouldn't.
        self.assertIn("radius server ISE-lab", output)
        self.assertNotIn(" radius server ISE-lab", output)
        self.assertIn(
            " address ipv4 10.48.39.134 auth-port 1812 acct-port 1813",
            output,
        )
        self.assertIn(" key Cisco123", output)

    def test_no_aaa_data_emits_nothing(self):
        config = self._cisco_config()
        output = "\n".join(self.translator.translate(config))
        self.assertNotIn("aaa new-model", output)
        self.assertNotIn("radius", output.lower())


class RadiusTacacsFromHuaweiSourceTest(CiscoTranslatorTestBase):
    """
    Huawei-native "radius-server template"/"hwtacacs-server template"
    blocks (once HuaweiSwitchParser classifies them — see
    tests/test_huawei_parser_gaps.py) translated into real Cisco AAA
    syntax. Cisco target syntax verified against cisco.com (Catalyst
    9800 RADIUS/TACACS+ configuration guide).
    """

    def test_radius_template_translates_to_named_block_and_group(self):
        config = self._config()  # source_vendor="Huawei"
        config.radius_commands = [
            "radius-server template test1",
            "radius-server shared-key cipher %^%#secret%^%#",
            "radius-server authentication 10.1.1.1 1812 weight 80",
            "radius-server accounting 10.1.1.2 1813 weight 80",
        ]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("radius server test1", output)
        self.assertIn(
            " address ipv4 10.1.1.1 auth-port 1812 acct-port 1813", output
        )
        self.assertIn("aaa group server radius test1", output)
        self.assertIn(" server name test1", output)
        self.assertIn(
            "aaa authentication login default group test1 local", output
        )
        self.assertIn("REVIEW-RADIUS-KEY", output)
        # Accounting host differs from auth host — flagged, not dropped.
        self.assertIn("REVIEW-RADIUS", output)

    def test_hwtacacs_template_translates_to_named_block_and_group(self):
        config = self._config()
        config.tacacs_commands = [
            "hwtacacs-server template test1",
            "hwtacacs-server shared-key cipher %^%#secret%^%#",
            "hwtacacs-server authentication 10.1.1.11",
        ]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("tacacs server test1", output)
        self.assertIn(" address ipv4 10.1.1.11", output)
        self.assertIn("aaa group server tacacs+ test1", output)
        self.assertIn(
            "aaa authorization exec default group test1 local", output
        )
        self.assertIn(
            "aaa accounting exec default start-stop group test1", output
        )

    def test_radius_template_without_auth_line_emits_nothing(self):
        config = self._config()
        config.radius_commands = ["radius-server template test1"]
        output = "\n".join(self.translator.translate(config))
        self.assertNotIn("radius server test1", output)
        self.assertNotIn("aaa group server radius", output)


class SnmpTranslationTest(CiscoTranslatorTestBase):
    """
    Implemented 2026-08-30. config.snmp_commands was previously parsed
    but never rendered (same silent-drop bug as AAA above).
    """

    def test_cisco_native_snmp_passthrough(self):
        config = self._cisco_config = SwitchConfig(
            source_vendor="Cisco", source_device_type="Switch", source_file="t"
        )
        config.snmp_commands = [
            "snmp-server community public RO",
            "snmp-server location HQ",
            "snmp-server contact NOC",
        ]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("snmp-server community public RO", output)
        self.assertIn("snmp-server location HQ", output)
        self.assertIn("snmp-server contact NOC", output)

    def test_huawei_snmpv3_translates_to_group_and_user(self):
        config = self._config()  # source_vendor="Huawei"
        config.snmp_commands = [
            "snmp-agent",
            "snmp-agent sys-info version v3",
            "snmp-agent group v3 NETMGMT privacy read-view iso",
            "snmp-agent usm-user v3 netadmin NETMGMT",
            "snmp-agent usm-user v3 netadmin authentication-mode sha cipher X",
            "snmp-agent usm-user v3 netadmin privacy-mode aes128 cipher X",
        ]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("snmp-server group NETMGMT v3 priv read iso", output)
        self.assertIn(
            "snmp-server user netadmin NETMGMT v3 auth sha REVIEW-SNMP-KEY "
            "priv aes 128 REVIEW-SNMP-KEY",
            output,
        )
        self.assertIn("REVIEW-SNMP-KEY", output)

    def test_no_snmp_data_emits_nothing(self):
        config = self._config()
        output = "\n".join(self.translator.translate(config))
        self.assertNotIn("snmp-server", output)


class AclTranslationTest(CiscoTranslatorTestBase):
    """
    Implemented 2026-08-30. config.acl_commands was previously parsed
    but never rendered (same silent-drop bug as AAA/SNMP above).
    """

    def test_cisco_native_named_acl_reindented(self):
        config = SwitchConfig(
            source_vendor="Cisco", source_device_type="Switch", source_file="t"
        )
        config.acl_commands = [
            "ip access-list extended TEST-ACL",
            "permit tcp host 10.1.1.5 any eq 22",
            "deny ip any any",
        ]
        output = self.translator.translate(config)
        self.assertIn("ip access-list extended TEST-ACL", output)
        self.assertIn(" permit tcp host 10.1.1.5 any eq 22", output)
        self.assertIn(" deny ip any any", output)

    def test_synthesized_numbered_acl_header_reindented(self):
        # CiscoSwitchParser synthesizes this header for old-style
        # numbered ACLs — same re-indenting path as a native header.
        config = SwitchConfig(
            source_vendor="Cisco", source_device_type="Switch", source_file="t"
        )
        config.acl_commands = [
            "ip access-list standard ACL-1",
            "permit 10.1.1.0 0.0.0.255",
        ]
        output = self.translator.translate(config)
        self.assertIn("ip access-list standard ACL-1", output)
        self.assertIn(" permit 10.1.1.0 0.0.0.255", output)

    def test_huawei_native_acl_flagged_not_guessed(self):
        config = self._config()  # source_vendor="Huawei"
        config.acl_commands = [
            "acl number 3000",
            "rule 5 permit ip source 10.1.1.0 0.0.0.255",
        ]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("REVIEW-ACL-HUAWEI: acl number 3000", output)
        self.assertIn(
            "REVIEW-ACL-HUAWEI: rule 5 permit ip source 10.1.1.0 0.0.0.255",
            output,
        )

    def test_no_acl_data_emits_nothing(self):
        config = self._config()
        output = "\n".join(self.translator.translate(config))
        self.assertNotIn("access-list", output)
        self.assertNotIn("REVIEW-ACL", output)


class NtpLoggingBannerLineVtyTest(CiscoTranslatorTestBase):
    """
    Implemented 2026-08-30. config.ntp_commands/logging_commands/
    banner_commands/line_vty_commands were previously parsed but never
    rendered (same silent-drop bug class as AAA/SNMP/ACL above). NTP
    and logging get light Huawei-native recognition since
    HuaweiSwitchParser now classifies "ntp-service unicast-server"/
    "info-center loghost" into these same fields.
    """

    def test_cisco_native_ntp_and_logging_passthrough(self):
        config = self._config()
        config.ntp_commands = ["ntp server 10.1.1.1"]
        config.logging_commands = ["logging host 10.1.1.2"]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("ntp server 10.1.1.1", output)
        self.assertIn("logging host 10.1.1.2", output)

    def test_huawei_native_ntp_and_logging_translated(self):
        config = self._config()
        config.ntp_commands = ["ntp-service unicast-server 10.1.1.1"]
        config.logging_commands = ["info-center loghost 10.1.1.2"]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("ntp server 10.1.1.1", output)
        self.assertIn("logging host 10.1.1.2", output)

    def test_line_vty_passthrough(self):
        config = self._config()
        config.line_vty_commands = ["line vty 0 4", "login local"]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("line vty 0 4", output)
        self.assertIn("login local", output)


class DhcpSnoopingOption82AndRateLimitTest(CiscoTranslatorTestBase):
    """Implemented 2026-08-30 — mirrors the Huawei-target coverage in
    tests/test_huawei_translator.py's
    DhcpSnoopingOption82AndRateLimitTranslationTest."""

    def test_option82_emitted_alongside_global_snooping(self):
        config = self._config()
        config.dhcp_snooping_enabled = True
        config.dhcp_snooping_vlans = ["10"]
        config.dhcp_snooping_option82_enabled = True
        output = "\n".join(self.translator.translate(config))
        self.assertIn("ip dhcp snooping", output)
        self.assertIn("ip dhcp snooping vlan 10", output)
        self.assertIn("ip dhcp snooping information option", output)

    def test_option82_absent_emits_nothing(self):
        config = self._config()
        config.dhcp_snooping_enabled = True
        output = "\n".join(self.translator.translate(config))
        self.assertNotIn("information option", output)

    def test_interface_rate_limit_emitted(self):
        config = self._config()
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.dhcp_snooping_rate_limit_pps = 100
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" ip dhcp snooping limit rate 100", output)


if __name__ == "__main__":
    unittest.main()
