"""Tests for features/configuration_studio/service.py -- the entry
point every conversion in Configuration Studio goes through
(create_engine, convert_file, supported_platforms, safe_name). This
module, and the 6900+ lines of parser/translator code it fronts, had
zero test coverage before this file.

test_convert_file_cisco_to_huawei_end_to_end exercises a real,
representative Cisco-to-Huawei switch conversion through the actual
parser and translator (not mocked) -- vlans, trunk/access interfaces, a
routed VLAN interface, a static route, and SNMP settings -- which is
Configuration Studio's flagship, most-used conversion path (see
README's "Huawei AC6508 validation preserved" section). Deep,
line-by-line coverage of every command the Cisco/Aruba parsers and the
Aruba/Huawei translators (1000+ lines apiece) can handle is still a gap
this file doesn't attempt to close.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from features.configuration_studio.service import convert_file, safe_name, supported_platforms

CISCO_SWITCH_CONFIG = """hostname EDGE-SW01
!
vlan 10
 name USERS
!
vlan 20
 name SERVERS
!
interface GigabitEthernet0/1
 description Uplink to Core
 switchport mode trunk
 switchport trunk native vlan 10
!
interface GigabitEthernet0/2
 description Server Port
 switchport mode access
 switchport access vlan 20
!
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 10.10.10.254
!
snmp-server community public RO
snmp-server location DC1-Rack4
!
end
"""


class TestSafeName(unittest.TestCase):
    def test_strips_unsafe_characters(self):
        self.assertEqual(safe_name("Weird Name!!.cfg"), "Weird_Name_.cfg")

    def test_blank_value_uses_fallback(self):
        self.assertEqual(safe_name(""), "converted-config")
        self.assertEqual(safe_name(None), "converted-config")

    def test_custom_fallback(self):
        self.assertEqual(safe_name("", fallback="my-fallback"), "my-fallback")


class TestSupportedPlatforms(unittest.TestCase):
    def test_returns_only_vendors_with_real_parser_or_translator_classes(self):
        platforms = supported_platforms()
        source_vendors = {item["vendor"] for item in platforms["sources"]}
        target_vendors = {item["vendor"] for item in platforms["targets"]}
        # Parsers exist for all three switch vendors, plus Mikrotik on
        # the firewall side (the new Mikrotik -> Palo Alto migration
        # path -- see MikrotikFirewallParser)...
        self.assertEqual(source_vendors, {"cisco", "huawei", "aruba", "mikrotik"})
        # ...and a CiscoSwitchTranslator now exists too (renders an
        # Aruba/Huawei-sourced config back into Cisco IOS-style CLI --
        # e.g. for rollback documentation / config-parity review), so
        # Cisco is no longer source-only: all three switch vendors are
        # valid translation targets, plus Palo Alto as the firewall
        # target (PaloAltoFirewallTranslator).
        self.assertEqual(target_vendors, {"cisco", "huawei", "aruba", "palo alto"})


class TestConvertFile(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)
        self.source_path = self.tmp_dir / "edge-sw01.cfg"
        self.source_path.write_text(CISCO_SWITCH_CONFIG, encoding="utf-8")

    def test_convert_file_cisco_to_huawei_end_to_end(self):
        result = convert_file(
            self.source_path,
            source_vendor="Cisco",
            source_device_type="Switch",
            target_vendor="Huawei",
            target_device_type="Switch",
        )

        self.assertEqual(result["hostname"], "EDGE-SW01")
        self.assertEqual(result["source_vendor"], "Cisco")
        self.assertEqual(result["target_vendor"], "Huawei")
        self.assertEqual(result["download_name"], "EDGE-SW01_Huawei.cfg")

        output = result["output_text"]
        self.assertIn("sysname EDGE-SW01", output)
        self.assertIn("vlan batch 10 20", output)
        self.assertIn("port link-type trunk", output)
        self.assertIn("port trunk pvid vlan 10", output)
        self.assertIn("port link-type access", output)
        self.assertIn("port default vlan 20", output)
        self.assertIn("interface Vlanif10", output)
        self.assertIn("ip address 10.10.10.1 255.255.255.0", output)
        self.assertIn("ip route-static 0.0.0.0 0.0.0.0 10.10.10.254", output)
        self.assertIn("snmp-agent community read public", output)
        self.assertIn("snmp-agent sys-info location DC1-Rack4", output)

        self.assertEqual(result["source_lines"], len(CISCO_SWITCH_CONFIG.splitlines()))
        self.assertGreater(result["output_lines"], 0)

    def test_convert_file_auto_detects_source_vendor(self):
        result = convert_file(
            self.source_path,
            source_vendor="Auto Detect",
            source_device_type="Auto Detect",
            target_vendor="Huawei",
        )
        self.assertEqual(result["source_vendor"], "Cisco")
        self.assertEqual(result["source_device_type"], "Switch")

    def test_convert_file_raises_when_vendor_cannot_be_resolved(self):
        unrecognizable = self.tmp_dir / "unknown.cfg"
        unrecognizable.write_text("this is not a network config at all", encoding="utf-8")
        with self.assertRaises(ValueError):
            convert_file(unrecognizable, source_vendor="Auto Detect", source_device_type="Auto Detect")

    def test_download_name_is_filesystem_safe_even_for_odd_hostnames(self):
        odd_source = self.tmp_dir / "odd.cfg"
        odd_source.write_text("hostname WEIRD NAME!!\n!\nend\n", encoding="utf-8")
        result = convert_file(odd_source, source_vendor="Cisco", source_device_type="Switch", target_vendor="Huawei")
        self.assertNotIn(" ", result["download_name"])
        self.assertNotIn("!", result["download_name"])


if __name__ == "__main__":
    unittest.main()
