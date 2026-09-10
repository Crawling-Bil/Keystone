"""Unit tests for converter_engine/detector.py -- the marker-scoring
vendor/device-type auto-detection every "Auto Detect" conversion in
Configuration Studio depends on. A wrong detection here silently routes
a config through the wrong parser, so this had no coverage at all
before this file despite being the single most consequential piece of
guesswork in the whole conversion pipeline.
"""

from __future__ import annotations

import unittest

from features.configuration_studio.converter_engine.detector import DeviceDetector, DetectionResult


class TestDeviceDetector(unittest.TestCase):
    def setUp(self):
        self.detector = DeviceDetector()

    def test_cisco_switch_markers(self):
        text = """
        hostname SW01
        interface GigabitEthernet0/1
         switchport mode access
         switchport access vlan 10
        router ospf 1
        """
        result = self.detector.detect_text(text)
        self.assertEqual(result.vendor, "Cisco")
        self.assertEqual(result.device_type, "Switch")
        self.assertGreater(result.confidence, 0)

    def test_huawei_switch_markers(self):
        text = """
        sysname SW01
        interface Vlanif10
        port link-type trunk
        port trunk allow-pass vlan 10 20
        display current-configuration
        """
        result = self.detector.detect_text(text)
        self.assertEqual(result.vendor, "Huawei")
        self.assertEqual(result.device_type, "Switch")

    def test_aruba_switch_markers(self):
        text = """
        hostname SW01
        vlan 10
           untagged 1-10
           tagged 11-20
        manager password
        ip authorized-managers 10.0.0.0 255.0.0.0
        """
        result = self.detector.detect_text(text)
        self.assertEqual(result.vendor, "Aruba")
        self.assertEqual(result.device_type, "Switch")

    def test_fortigate_firewall_markers(self):
        text = """
        config system interface
        config firewall policy
            set srcintf "port1"
            set dstintf "port2"
        end
        """
        result = self.detector.detect_text(text)
        self.assertEqual(result.vendor, "FortiGate")
        self.assertEqual(result.device_type, "Firewall")

    def test_palo_alto_firewall_markers(self):
        text = """
        set deviceconfig system hostname PA-FW01
        set rulebase security rules rule1
        set zone trust
        """
        result = self.detector.detect_text(text)
        self.assertEqual(result.vendor, "Palo Alto")
        self.assertEqual(result.device_type, "Firewall")

    def test_cisco_ftd_asa_markers(self):
        text = """
        nameif inside
        security-level 100
        object network INSIDE-NET
        access-list OUTSIDE_IN extended permit ip any any
        """
        result = self.detector.detect_text(text)
        self.assertEqual(result.vendor, "Cisco FTD")
        self.assertEqual(result.device_type, "Firewall")

    def test_cisco_wlc_markers(self):
        text = """
        config wlan create 1 CORP-WIFI CORP-WIFI
        config wlan enable 1
        config interface address dynamic-interface mgmt 10.0.0.1 255.255.255.0
        """
        result = self.detector.detect_text(text)
        self.assertEqual(result.vendor, "Cisco")
        self.assertEqual(result.device_type, "WLC")

    def test_aruba_wlc_markers(self):
        text = """
        wlan ssid-profile CORP-WIFI
        aaa profile default
        virtual-ap default
        ap-group default
        """
        result = self.detector.detect_text(text)
        self.assertEqual(result.vendor, "Aruba")
        self.assertEqual(result.device_type, "WLC")

    def test_unrecognized_content_returns_unknown_with_zero_confidence(self):
        result = self.detector.detect_text("this is not a network config at all, just prose")
        self.assertEqual(result, DetectionResult(vendor="Unknown", device_type="Unknown", confidence=0))

    def test_empty_content_returns_unknown(self):
        result = self.detector.detect_text("")
        self.assertEqual(result.vendor, "Unknown")

    def test_detection_is_case_insensitive(self):
        text = "SYSNAME SW01\nPORT LINK-TYPE TRUNK\nDISPLAY CURRENT-CONFIGURATION"
        result = self.detector.detect_text(text)
        self.assertEqual(result.vendor, "Huawei")

    def test_mikrotik_routeros_markers(self):
        text = """
        /interface bridge
        add name=bridge-lan
        /interface bridge port
        add bridge=bridge-lan interface=ether2
        /ip firewall filter
        add action=accept chain=forward
        /ip firewall nat
        add action=masquerade chain=srcnat out-interface=ether1
        /system identity
        set name=ROUTER01
        """
        result = self.detector.detect_text(text)
        self.assertEqual(result.vendor, "Mikrotik")
        self.assertEqual(result.device_type, "Firewall")

    def test_cisco_switch_wins_tie_against_aruba_switch(self):
        # "trunk " (Aruba marker) and "switchport mode trunk" (Cisco
        # marker, itself containing "trunk ") can each score 10 from
        # essentially the same line. On an exact confidence tie, Cisco
        # Switch is the first candidate built and must win (max() keeps
        # the first max it sees) -- this pins that ordering so a future
        # reordering of the candidate list doesn't silently flip which
        # vendor "wins" a tie.
        text = "switchport mode trunk \n"
        result = self.detector.detect_text(text)
        self.assertEqual(result.vendor, "Cisco")
        self.assertEqual(result.device_type, "Switch")


if __name__ == "__main__":
    unittest.main()
