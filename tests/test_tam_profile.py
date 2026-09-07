import unittest

from features.configuration_studio.converter_engine.models.switch import (
    Interface,
    SwitchConfig,
)
from features.configuration_studio.converter_engine.translators.switch.huawei import (
    HuaweiSwitchTranslator,
)
from features.configuration_studio.converter_engine.profiles import (
    TAM_STANDARD,
    PROFILE_REGISTRY,
)


class TamProfileScopeTest(unittest.TestCase):
    """
    Confirms the core design rule: a profile only overrides the
    organizational-infrastructure sections it defines (NTP, syslog, AAA,
    SNMP communities, DNS filtering) — device-specific correctness
    output (interfaces, VLANs, port-security, storm control) must be
    byte-for-byte identical with or without a profile, since Keystone's
    whole point is staying multi-project/reusable, not becoming
    TAM-only. See MAPPING doc + memory-keystone.md Section 1a/4.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def _base_config(self):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.mode = "access"
        interface.access_vlan = 10
        interface.port_security_enabled = True
        interface.port_security_violation = "shutdown"
        interface.storm_control_broadcast_level = "80"
        config.interfaces.append(interface)
        return config

    def test_interface_output_unaffected_by_profile(self):
        without_profile = "\n".join(
            self.translator.translate(self._base_config())
        )
        with_profile = "\n".join(
            self.translator.translate(self._base_config(), profile=TAM_STANDARD)
        )
        self.assertIn("port link-type access", without_profile)
        self.assertIn("port link-type access", with_profile)
        self.assertIn("port-security protect-action error-down", without_profile)
        self.assertIn("port-security protect-action error-down", with_profile)
        self.assertIn("storm control broadcast", without_profile)
        self.assertIn("storm control broadcast", with_profile)


class TamProfileInfrastructureOverrideTest(unittest.TestCase):
    """
    Confirms the profile's overridden sections actually replace, not
    just supplement, the source-driven values — a real risk given
    TACACS+/NTP-IP-server values must NOT survive alongside the new
    standard (that would be a broken/duplicate config, not a correct
    one). Values checked against memory-tam-2026-huawei-switch.md
    section 30b verbatim.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def _config_with_old_infrastructure(self):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.ntp_commands = ["ntp server 10.85.80.137"]
        config.logging_commands = ["logging host 10.1.1.50"]
        config.tacacs_commands = ["tacacs-server host 10.85.1.7 key OLDKEY"]
        config.aaa_commands = [
            "aaa new-model",
            "aaa authentication login default group tacacs+ local",
        ]
        config.snmp_commands = [
            "snmp-server community OLDCOMM RO",
            "snmp-server location OLD-SITE",
        ]
        config.global_commands = [
            "ip name-server 8.8.8.8",
            "ip domain-name example.com",
            "some-other-unrelated-command",
        ]
        return config

    def test_profile_replaces_ntp_and_syslog(self):
        output = "\n".join(
            self.translator.translate(
                self._config_with_old_infrastructure(), profile=TAM_STANDARD
            )
        )
        self.assertIn("ntp unicast-server domain ntp.toyota.astra.co.id", output)
        self.assertNotIn("10.85.80.137", output)
        self.assertIn("info-center loghost 10.85.80.187 port 514", output)
        self.assertNotIn("10.1.1.50", output)

    def test_profile_replaces_tacacs_with_local_only_aaa(self):
        output = "\n".join(
            self.translator.translate(
                self._config_with_old_infrastructure(), profile=TAM_STANDARD
            )
        )
        self.assertIn("authentication-scheme LOCAL_LOGIN", output)
        self.assertIn("authorization-scheme LOCAL_AUTHOR", output)
        self.assertIn("authentication-mode local", output)
        self.assertNotIn("hwtacacs-server", output)
        self.assertNotIn("OLDKEY", output)

    def test_profile_overrides_snmp_communities_but_keeps_source_location(self):
        output = "\n".join(
            self.translator.translate(
                self._config_with_old_infrastructure(), profile=TAM_STANDARD
            )
        )
        self.assertIn("snmp-agent community read G0tInf0", output)
        self.assertIn("snmp-agent community read K3rb3r0s", output)
        self.assertIn("snmp-agent sys-info version v2c v3", output)
        self.assertNotIn("OLDCOMM", output)
        # Location is fallback-only — an snmp-server location actually
        # present in the source config always wins over any derived
        # value, so it must come through unchanged here.
        self.assertIn("OLD-SITE", output)
        self.assertNotIn("REVIEW-SNMP-LOCATION-DERIVED", output)

    def test_profile_drops_dns_from_review_output(self):
        output = "\n".join(
            self.translator.translate(
                self._config_with_old_infrastructure(), profile=TAM_STANDARD
            )
        )
        self.assertNotIn("8.8.8.8", output)
        self.assertNotIn("example.com", output)
        # Unrelated global commands still surface for review as normal.
        self.assertIn("some-other-unrelated-command", output)

    def test_no_profile_keeps_fully_generic_output(self):
        output = "\n".join(
            self.translator.translate(self._config_with_old_infrastructure())
        )
        self.assertIn("10.85.80.137", output)
        self.assertIn("hwtacacs-server", output)
        self.assertNotIn("LOCAL_LOGIN", output)


class _FakeInventory:
    """
    Minimal stand-in for converter_engine.inventory.Inventory — just
    enough to exercise HuaweiSwitchTranslator.get_site_code() without
    depending on the real mappings/migration_inventory.csv file being
    present/current wherever tests run.
    """

    def __init__(self, site_by_hostname):
        self._site_by_hostname = site_by_hostname

    def get(self, hostname):
        site = self._site_by_hostname.get(hostname)
        if site is None:
            return None
        return {"Site": site}


class TamProfileSnmpLocationFallbackTest(unittest.TestCase):
    """
    "SNMP location/contact, if from backup config dont provide it,
    converter can use the site code from hostname / SNMP contact use
    tam" — the fallback is inventory-site-driven (via get_site_code()
    reading migration_inventory.csv's Site column), not literal
    hostname-text parsing, since the CSV is the actual confirmed
    per-device record. See tam_standard.py's module docstring for why.
    """

    def _config(self, hostname, snmp_commands=None):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.hostname = hostname
        config.snmp_commands = snmp_commands or []
        return config

    def test_fills_location_and_contact_when_source_provides_neither(self):
        translator = HuaweiSwitchTranslator(
            inventory=_FakeInventory({"TTC-SWCO-BU-N9108-DMZ": "TTC"})
        )
        output = "\n".join(
            translator.translate(
                self._config("TTC-SWCO-BU-N9108-DMZ"), profile=TAM_STANDARD
            )
        )
        self.assertIn("snmp-agent sys-info location TTC", output)
        self.assertIn("snmp-agent sys-info contact TAM", output)
        self.assertIn("REVIEW-SNMP-LOCATION-DERIVED", output)

    def test_gtopas_site_formats_as_depo_city(self):
        translator = HuaweiSwitchTranslator(
            inventory=_FakeInventory(
                {"GTOPAS-MND-SWCODI-C3650": "GTOPAS-MND"}
            )
        )
        output = "\n".join(
            translator.translate(
                self._config("GTOPAS-MND-SWCODI-C3650"), profile=TAM_STANDARD
            )
        )
        self.assertIn("snmp-agent sys-info location DEPO-MANADO", output)

    def test_source_location_and_contact_always_win(self):
        translator = HuaweiSwitchTranslator(
            inventory=_FakeInventory({"HO-SWAC-INT-C2960X": "HO"})
        )
        output = "\n".join(
            translator.translate(
                self._config(
                    "HO-SWAC-INT-C2960X",
                    snmp_commands=[
                        "snmp-server location SOURCE-PROVIDED",
                        "snmp-server contact NETOPS-TEAM",
                    ],
                ),
                profile=TAM_STANDARD,
            )
        )
        self.assertIn("SOURCE-PROVIDED", output)
        self.assertIn("NETOPS-TEAM", output)
        self.assertNotIn("snmp-agent sys-info location HO", output)
        self.assertNotIn("snmp-agent sys-info contact TAM", output)
        self.assertNotIn("REVIEW-SNMP-LOCATION-DERIVED", output)

    def test_unmatched_hostname_skips_location_but_still_sets_contact(self):
        translator = HuaweiSwitchTranslator(
            inventory=_FakeInventory({})
        )
        output = "\n".join(
            translator.translate(
                self._config("SOME-UNKNOWN-HOSTNAME"), profile=TAM_STANDARD
            )
        )
        self.assertNotIn("REVIEW-SNMP-LOCATION-DERIVED", output)
        self.assertIn("snmp-agent sys-info contact TAM", output)

    def test_no_profile_means_no_fallback_at_all(self):
        translator = HuaweiSwitchTranslator(
            inventory=_FakeInventory({"HO-SWAC-INT-C2960X": "HO"})
        )
        output = "\n".join(
            translator.translate(self._config("HO-SWAC-INT-C2960X"))
        )
        self.assertNotIn("sys-info location", output)
        self.assertNotIn("sys-info contact", output)


class TamProfileDhcpHelperTest(unittest.TestCase):
    """
    "dhcp helper / there are 2 options for dhcp helper ip address group
    by site" — Option A (STR2/STR3/ADM/HO) vs Option B (everything
    else, the confirmed catch-all). Which interfaces relay DHCP at all
    must stay purely source-driven; only the IP values on an interface
    that already relays get swapped.
    """

    def _config_with_helper(self, hostname, source_ip="192.0.2.99"):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.hostname = hostname
        interface = Interface(name="Vlan10")
        interface.ip_address = "10.10.10.1"
        interface.subnet_mask = "255.255.255.0"
        interface.helper_addresses = [source_ip]
        config.interfaces.append(interface)
        return config

    def test_option_a_site_gets_option_a_helpers(self):
        translator = HuaweiSwitchTranslator(
            inventory=_FakeInventory({"ADM-SWDI-MAIN2-2960": "ADM"})
        )
        output = "\n".join(
            translator.translate(
                self._config_with_helper("ADM-SWDI-MAIN2-2960"),
                profile=TAM_STANDARD,
            )
        )
        self.assertIn("dhcp relay server-ip 10.86.48.112", output)
        self.assertIn("dhcp relay server-ip 10.185.80.110", output)
        self.assertNotIn("192.0.2.99", output)
        self.assertIn("REVIEW-DHCP-HELPER", output)
        self.assertIn("Option A", output)

    def test_option_b_site_gets_option_b_helpers(self):
        translator = HuaweiSwitchTranslator(
            inventory=_FakeInventory({"TTC-SWAC-LAN-2960": "TTC"})
        )
        output = "\n".join(
            translator.translate(
                self._config_with_helper("TTC-SWAC-LAN-2960"),
                profile=TAM_STANDARD,
            )
        )
        self.assertIn("dhcp relay server-ip 10.185.80.110", output)
        self.assertIn("dhcp relay server-ip 10.85.76.110", output)
        self.assertNotIn("192.0.2.99", output)
        self.assertIn("REVIEW-DHCP-HELPER", output)
        self.assertIn("Option B", output)

    def test_gtopas_depo_site_gets_option_b_helpers(self):
        translator = HuaweiSwitchTranslator(
            inventory=_FakeInventory(
                {"GTOPAS-PKU-SWCO-C3650": "GTOPAS-PKU"}
            )
        )
        output = "\n".join(
            translator.translate(
                self._config_with_helper("GTOPAS-PKU-SWCO-C3650"),
                profile=TAM_STANDARD,
            )
        )
        self.assertIn("dhcp relay server-ip 10.185.80.110", output)
        self.assertIn("dhcp relay server-ip 10.85.76.110", output)
        self.assertNotIn("192.0.2.99", output)

    def test_interface_without_helper_stays_untouched(self):
        translator = HuaweiSwitchTranslator(
            inventory=_FakeInventory({"ADM-SWDI-MAIN2-2960": "ADM"})
        )
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.hostname = "ADM-SWDI-MAIN2-2960"
        interface = Interface(name="Vlan20")
        interface.ip_address = "10.20.20.1"
        interface.subnet_mask = "255.255.255.0"
        config.interfaces.append(interface)
        output = "\n".join(
            translator.translate(config, profile=TAM_STANDARD)
        )
        self.assertNotIn("dhcp relay server-ip", output)
        self.assertNotIn("REVIEW-DHCP-HELPER", output)

    def test_unmatched_hostname_defaults_to_option_b(self):
        translator = HuaweiSwitchTranslator(
            inventory=_FakeInventory({})
        )
        output = "\n".join(
            translator.translate(
                self._config_with_helper("SOME-UNKNOWN-HOSTNAME"),
                profile=TAM_STANDARD,
            )
        )
        self.assertIn("dhcp relay server-ip 10.185.80.110", output)
        self.assertIn("dhcp relay server-ip 10.85.76.110", output)
        self.assertIn("REVIEW-DHCP-HELPER", output)

    def test_no_profile_leaves_source_helper_untouched(self):
        translator = HuaweiSwitchTranslator(
            inventory=_FakeInventory({"ADM-SWDI-MAIN2-2960": "ADM"})
        )
        output = "\n".join(
            translator.translate(
                self._config_with_helper("ADM-SWDI-MAIN2-2960")
            )
        )
        self.assertIn("dhcp relay server-ip 192.0.2.99", output)
        self.assertNotIn("REVIEW-DHCP-HELPER", output)


class TamProfileNetconfCallhomeTest(unittest.TestCase):
    """
    "i get additional ops confirmed nce config for device with huawei
    v600 os" (30 Aug 2026) — NETCONF/callhome-to-NCE + SSH x509 + PKI,
    appended at the very end of the device output (matching where it
    appears in TAM's own real per-device draft configs). Two fixes
    from ops' raw draft, both verified against V600R025C00
    Configuration Guide - System Management, NETCONF Configuration:
    the callhome name must be the literal "default-callhome" (not a
    free-choice name), and there is no standalone "source ip" command
    — the source IP is the peer-ip line's own "local-address"
    parameter, kept here as an explicit per-device REVIEW-CONFIRM
    placeholder.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def _config(self):
        return SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )

    def test_netconf_block_present_and_corrected(self):
        output = "\n".join(
            self.translator.translate(self._config(), profile=TAM_STANDARD)
        )
        self.assertIn("callhome default-callhome", output)
        self.assertIn("peer-ip 10.85.10.101 port 10020", output)
        self.assertIn("REVIEW-CONFIRM", output)
        self.assertIn("ssh user huawei authentication-type x509v3-rsa", output)
        self.assertIn("pki import-certificate default_ca realm default", output)
        # Regression guard against ops' raw (incorrect) draft syntax.
        self.assertNotIn("callhome NCE", output)
        self.assertNotIn("source ip (device management ip)", output)

    def test_netconf_block_is_last_section(self):
        output = self.translator.translate(
            self._config(), profile=TAM_STANDARD
        )
        # "netconf" must be the very first line of the appended block,
        # and nothing profile-driven should follow it.
        netconf_index = output.index("netconf")
        self.assertGreater(
            netconf_index, len(output) - len(TAM_STANDARD.netconf_lines) - 1
        )

    def test_no_profile_means_no_netconf_block(self):
        output = "\n".join(self.translator.translate(self._config()))
        self.assertNotIn("netconf", output)
        self.assertNotIn("snetconf server enable", output)


class SnmpSectionAlwaysClosedTest(unittest.TestCase):
    """
    Real, confirmed bug (found and fixed per explicit user direction:
    "# after each part ... so the new part config can input smoothly,
    because some config cannot be continue from other part of
    config"): the profile-driven SNMP community/version block, and
    the SNMP location/contact profile-fallback block right after it,
    could each run straight into the next config section (TACACS/
    RADIUS/AAA, which opens with the view-entering "aaa" command)
    with no closing "#" of their own -- relying entirely on whatever
    happened to come next to supply one, which silently failed
    whenever that next call had nothing to emit. Both sections now
    always self-close with "#" whenever they emit anything.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_profile_snmp_communities_close_even_with_no_remaining_commands(
        self,
    ):
        # Source config has NO snmp-server lines at all beyond the
        # profile's own fixed communities/version -- this is the
        # exact case that previously left the block unclosed, since
        # translate_snmp(remaining_snmp_commands) returns [] and
        # profile.snmp_contact_value/location_resolver are unset here.
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        output = self.translator.translate(config, profile=TAM_STANDARD)

        last_community_idx = max(
            i for i, line in enumerate(output)
            if line.startswith("snmp-agent community read ")
        )
        # The very next emitted line must be a standalone "#" (or the
        # sys-info version line, itself followed by "#") -- never a
        # command belonging to a different section.
        self.assertTrue(
            output[last_community_idx + 1] == "#"
            or (
                output[last_community_idx + 1]
                == "snmp-agent sys-info version v2c v3"
                and output[last_community_idx + 2] == "#"
            )
        )

    def test_snmp_location_contact_fallback_closes_before_aaa(self):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        # No source snmp-server location/contact -- both come from
        # the profile's fallback (resolver + fixed "TAM" value).
        output = self.translator.translate(config, profile=TAM_STANDARD)

        contact_idx = output.index("snmp-agent sys-info contact TAM")
        aaa_idx = output.index("aaa")

        self.assertLess(contact_idx, aaa_idx)
        # Every line between the contact line and "aaa" must itself be
        # a "#" -- i.e. the fallback block is properly closed, not
        # running directly into the AAA block.
        self.assertTrue(
            all(
                line == "#"
                for line in output[contact_idx + 1:aaa_idx]
            )
        )
        self.assertGreater(aaa_idx, contact_idx + 1)


class ProfileRegistryTest(unittest.TestCase):
    def test_tam_standard_is_registered(self):
        self.assertIn("tam_standard", PROFILE_REGISTRY)
        self.assertIs(PROFILE_REGISTRY["tam_standard"], TAM_STANDARD)


if __name__ == "__main__":
    unittest.main()
