"""Tests for the Sizing Assessment module (features/switch_analyzer/
sizing.py). Fixtures below are trimmed real interface/transceiver/PoE
data shapes from this project's real device captures (see
memory-keystone.md Section 1u) rather than invented — in particular
the transceiver-type normalization test reproduces a real, confirmed
vendor-naming difference: Cisco IOS-XE calls a class "1000BaseSX SFP"
while ArubaOS-Switch calls the identical physical part "1000SX"
(TTC-SWAC-PABXGA2-2540, port 25).
"""
from __future__ import annotations

import unittest

from features.switch_analyzer import sizing


class InterfaceCategorizationTest(unittest.TestCase):
    def test_cisco_full_names(self):
        self.assertEqual(sizing._categorize_interface_type("GigabitEthernet1/0/1"), "1G")
        self.assertEqual(sizing._categorize_interface_type("TenGigabitEthernet1/1/1"), "10G")
        self.assertEqual(sizing._categorize_interface_type("FastEthernet0/1"), "100M")
        self.assertEqual(sizing._categorize_interface_type("FortyGigabitEthernet1/1/1"), "40G")
        self.assertEqual(sizing._categorize_interface_type("HundredGigE1/1/1"), "100G")

    def test_huawei_short_names(self):
        self.assertEqual(sizing._categorize_interface_type("GE1/0/1"), "1G")
        self.assertEqual(sizing._categorize_interface_type("10GE1/0/1"), "10G")
        self.assertEqual(sizing._categorize_interface_type("25GE1/0/3"), "25G")
        self.assertEqual(sizing._categorize_interface_type("100GE1/0/1"), "100G")

    def test_logical_interfaces_excluded(self):
        self.assertIsNone(sizing._categorize_interface_type("Port-channel1"))
        self.assertIsNone(sizing._categorize_interface_type("Eth-Trunk1"))
        self.assertIsNone(sizing._categorize_interface_type("Vlan10"))
        self.assertIsNone(sizing._categorize_interface_type("Vlanif10"))
        self.assertIsNone(sizing._categorize_interface_type("Loopback0"))
        self.assertIsNone(sizing._categorize_interface_type("MEth0/0/0"))

    def test_nexus_and_aruba_speed_not_derivable_from_name(self):
        # Real, honest limitation (not a bug): NX-OS's bare "Ethernet"
        # names and ArubaOS-Switch's bare port numbers carry no speed
        # information at all — reported as their own bucket rather
        # than guessed.
        self.assertEqual(sizing._categorize_interface_type("Ethernet1/49"), "Ethernet (speed not in name — check model/config)")
        self.assertEqual(sizing._categorize_interface_type("15"), "Port (speed not in name — check model)")


class TransceiverNormalizationTest(unittest.TestCase):
    def test_aruba_short_form_merges_with_cisco_full_name(self):
        # Real vendor-naming difference for the SAME physical SFP
        # class, confirmed on real captures — must normalize to one
        # bucket so procurement counts aren't split across two rows.
        self.assertEqual(sizing._normalize_transceiver_type("1000SX"), "1000BaseSX SFP")
        self.assertEqual(sizing._normalize_transceiver_type("1000LX"), "1000BaseLX SFP")
        self.assertEqual(sizing._normalize_transceiver_type("1000sx"), "1000BaseSX SFP")

    def test_unrecognized_type_kept_as_is(self):
        # Never fabricate a mapping for something not confirmed —
        # unknown strings pass through exactly as the device reported.
        self.assertEqual(sizing._normalize_transceiver_type("QSFP-40G-SR4"), "QSFP-40G-SR4")
        self.assertEqual(sizing._normalize_transceiver_type("10Gbase-SR"), "10Gbase-SR")
        self.assertEqual(sizing._normalize_transceiver_type("SomeFutureVendorLabel"), "SomeFutureVendorLabel")

    def test_blank_type_reported_as_unknown(self):
        self.assertEqual(sizing._normalize_transceiver_type(""), "Unknown")
        self.assertEqual(sizing._normalize_transceiver_type(None), "Unknown")


class DeviceSizingRowTest(unittest.TestCase):
    def _make_result(self, **overrides):
        base = {
            "hostname": "TEST-SW", "vendor": "Cisco",
            "os_version": {"model": "WS-C2960X", "os_version": "15.2(2)E7"},
            "interfaces": [
                {"name": "GigabitEthernet1/0/1", "status": "up", "mode": "access"},
                {"name": "GigabitEthernet1/0/2", "status": "down", "mode": "trunk"},
                {"name": "Port-channel1", "status": "up", "mode": "trunk"},
                {"name": "Vlan10", "status": "up", "mode": "", "hsrp_vrrp_ip": "10.0.0.1"},
            ],
            "transceivers": [
                {"interface": "GigabitEthernet1/0/1", "type": "1000BaseSX SFP", "present": True},
            ],
            "poe": [
                {"interface": "GigabitEthernet1/0/1", "power_watts": "15.4", "source": "show power inline"},
                {"interface": "GigabitEthernet1/0/2", "power_watts": "0.0", "source": "show power inline"},
            ],
            "vlans": [{"vlan_id": "10", "name": "DATA"}],
            "routes": [],
            "port_channels": [{"name": "Port-channel1"}],
            "vpc_mlag": {"summary": {}, "members": [], "source": "none"},
            "routing_protocols": {},
            "inventory": {"stack": {}},
        }
        base.update(overrides)
        return base

    def test_physical_ports_exclude_logical_interfaces(self):
        row = sizing._device_sizing_row(self._make_result())
        # 2 physical (Gi1/0/1 up, Gi1/0/2 down) — Port-channel1 and
        # Vlan10 are logical, excluded from the physical port count.
        self.assertEqual(row["physical_port_count"], 2)
        self.assertEqual(row["physical_ports_up"], 1)
        self.assertEqual(row["physical_ports_down"], 1)
        self.assertEqual(row["port_type_counts"], {"1G": 2})

    def test_trunk_count_includes_logical_trunks(self):
        row = sizing._device_sizing_row(self._make_result())
        # Gi1/0/2 (physical) + Port-channel1 (logical) are both mode
        # "trunk" — trunk_port_count counts uplinks regardless of
        # whether the interface is physical or a port-channel.
        self.assertEqual(row["trunk_port_count"], 2)

    def test_poe_and_transceiver_rollup(self):
        row = sizing._device_sizing_row(self._make_result())
        self.assertEqual(row["poe_port_count"], 2)
        self.assertEqual(row["poe_total_watts"], 15.4)
        self.assertEqual(row["transceiver_count"], 1)
        self.assertEqual(row["transceiver_type_counts"], {"1000BaseSX SFP": 1})

    def test_hsrp_vrrp_svi_counted(self):
        row = sizing._device_sizing_row(self._make_result())
        self.assertEqual(row["hsrp_vrrp_svi_count"], 1)


class BuildSizingSummaryTest(unittest.TestCase):
    def test_aggregate_totals_and_unique_vlan_dedup(self):
        result_a = {
            "hostname": "SW-A", "vendor": "Cisco", "os_version": {},
            "interfaces": [{"name": "GigabitEthernet1/0/1", "status": "up", "mode": "access"}],
            "transceivers": [{"interface": "GigabitEthernet1/0/1", "type": "1000SX", "vendor_part_number": "GLC-SX-MMD", "present": True}],
            "poe": [], "vlans": [{"vlan_id": "10", "name": "DATA"}, {"vlan_id": "20", "name": "VOICE"}],
            "routes": [], "port_channels": [], "vpc_mlag": {}, "routing_protocols": {}, "inventory": {},
        }
        result_b = {
            "hostname": "SW-B", "vendor": "Aruba", "os_version": {},
            "interfaces": [{"name": "GigabitEthernet1/0/1", "status": "up", "mode": "access"}],
            "transceivers": [{"interface": "1", "type": "1000BaseSX SFP", "vendor_part_number": "J4858C", "present": True}],
            "poe": [], "vlans": [{"vlan_id": "10", "name": "DATA"}],  # VLAN 10 repeats on both switches
            "routes": [], "port_channels": [], "vpc_mlag": {}, "routing_protocols": {}, "inventory": {},
        }
        summary = sizing.build_sizing_summary([result_a, result_b])
        self.assertEqual(summary["totals"]["device_count"], 2)
        # VLAN 10 is on both devices — unique count is 2 (10, 20), not
        # a plain sum of 3, since VLANs commonly repeat across
        # switches at the same site.
        self.assertEqual(summary["totals"]["unique_vlan_count"], 2)
        # Both devices' transceivers are the SAME real class under
        # different vendor spellings — must merge into one bucket.
        self.assertEqual(summary["totals"]["transceiver_type_totals"], {"1000BaseSX SFP": 2})
        self.assertEqual(summary["totals"]["transceiver_count"], 2)
        # But they're two DIFFERENT orderable parts (a genuine Cisco
        # GLC-SX-MMD vs. an Aruba-branded J4858C for the exact same
        # media class) — "what to buy" needs the part number, so the
        # breakdown must NOT merge these into one row the way the
        # type-only total above correctly does.
        self.assertEqual(
            summary["totals"]["transceiver_part_totals"],
            [
                {"type": "1000BaseSX SFP", "vendor_part_number": "GLC-SX-MMD", "count": 1},
                {"type": "1000BaseSX SFP", "vendor_part_number": "J4858C", "count": 1},
            ],
        )

    def test_transceiver_part_totals_merges_same_type_and_part_number(self):
        result_a = {
            "hostname": "SW-A", "vendor": "Cisco", "os_version": {},
            "interfaces": [], "poe": [], "vlans": [], "routes": [], "port_channels": [],
            "vpc_mlag": {}, "routing_protocols": {}, "inventory": {},
            "transceivers": [
                {"interface": "Gi1/0/1", "type": "1000BaseLX SFP", "vendor_part_number": "GLC-LH-SMD", "present": True},
                {"interface": "Gi2/0/1", "type": "1000BaseLX SFP", "vendor_part_number": "GLC-LH-SMD", "present": True},
                {"interface": "Gi3/0/1", "type": "1000BaseLX SFP", "vendor_part_number": "", "present": True},
            ],
        }
        summary = sizing.build_sizing_summary([result_a])
        self.assertEqual(
            summary["totals"]["transceiver_part_totals"],
            [
                {"type": "1000BaseLX SFP", "vendor_part_number": "GLC-LH-SMD", "count": 2},
                {"type": "1000BaseLX SFP", "vendor_part_number": "Unknown", "count": 1},
            ],
        )


if __name__ == "__main__":
    unittest.main()
