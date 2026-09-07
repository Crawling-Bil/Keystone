"""Smoke test for the Switch Analyzer's .xlsx exporter — confirms every
expected sheet is written and non-empty rows survive the round trip,
without asserting on exact cell styling."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openpyxl import load_workbook

from features.switch_analyzer.exporters import SwitchExcelExporter

SAMPLE_RESULT = {
    "hostname": "SW-TEST-01",
    "vendor": "Cisco",
    "device_type": "Switch",
    "os_version": {"os_version": "15.2(7)E3", "model": "WS-C9300-48P"},
    "cards": {"total_interfaces": 2, "interfaces_up": 1, "interfaces_down": 1},
    "inventory": {
        "modules": [{"slot": "Switch 1", "description": "WS-C9300-48P", "pid": "WS-C9300-48P", "serial": "FCW1234A0BC"}],
        "stack": {"mode": "Standalone", "member_count": 1, "members": []},
    },
    "interfaces": [
        {"name": "Gi1/0/1", "status": "up", "protocol": "up", "mode": "access", "vlan": 10, "ip_address": "", "description": "", "port_security": ""},
    ],
    "transceivers": [
        {"interface": "Gi1/0/1", "status": "up", "present": True, "type": "1000BASE-T", "vendor_part_number": "", "serial_number": ""},
    ],
    "port_channels": [],
    "vpc_mlag": {"summary": {}, "members": []},
    "poe": [
        {"interface": "Gi1/0/1", "admin_status": "auto", "oper_status": "on", "power_watts": "15.4", "device": "Ieee PD", "class": "4", "max_watts": "30.0"},
    ],
    "vlans": [{"vlan_id": 10, "name": "DATA"}],
    "neighbors": [],
    "routes": [],
    "routing_table": [],
    "arp_table": [],
    "dns": {"servers": ["8.8.8.8"], "domain": "example.com"},
    "snmp": {"enabled": True, "summary": {"communities": ["public"], "locations": [], "contacts": [], "hosts": []}},
}


SAMPLE_RESULT_2 = {
    "hostname": "SW-TEST-02",
    "vendor": "Huawei",
    "device_type": "Switch",
    "os_version": {"os_version": "V200R023", "model": "S5720"},
    "cards": {"total_interfaces": 1, "interfaces_up": 1, "interfaces_down": 0},
    "inventory": {"modules": [], "stack": {"mode": "Standalone", "member_count": 1, "members": []}},
    "interfaces": [
        {"name": "GE0/0/1", "status": "up", "protocol": "up", "mode": "trunk", "vlan": "", "ip_address": "", "description": "", "port_security": ""},
    ],
    "transceivers": [],
    "port_channels": [],
    "vpc_mlag": {"summary": {}, "members": []},
    "poe": [],
    "vlans": [],
    "neighbors": [],
    "routes": [],
    "routing_table": [],
    "arp_table": [],
    "dns": {"servers": [], "domain": ""},
    "snmp": {"enabled": False, "summary": {"communities": [], "locations": [], "contacts": [], "hosts": []}},
}


class SwitchExcelExportTest(unittest.TestCase):
    def test_export_writes_all_sheets_with_hostname_column(self):
        # Single dict (not wrapped in a list) must still work — the
        # exporter normalizes it to a one-item list internally.
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "export.xlsx"
            SwitchExcelExporter(SAMPLE_RESULT).export(path)
            self.assertTrue(path.exists())

            workbook = load_workbook(path)
            expected_sheets = {
                "Device Info", "Serial Numbers", "Stack Members", "Interfaces",
                "Transceivers", "Port-Channels", "VPC-MLAG Summary", "VPC-MLAG Members",
                "PoE", "VLANs", "Neighbors", "Static Routes", "Routing Table",
                "ARP Table", "DNS-SNMP",
                # New DHCP tab sheets — server pools, relay/helper
                # addresses, and per-interface snooping trust/rate limit.
                "DHCP Summary", "DHCP Pools", "DHCP Relay-Helper", "DHCP Snooping Interfaces",
            }
            self.assertTrue(expected_sheets.issubset(set(workbook.sheetnames)))

            # Every row-based sheet must carry the Hostname column so
            # rows from multiple devices can share one sheet.
            interfaces_sheet = workbook["Interfaces"]
            self.assertEqual(interfaces_sheet["A1"].value, "Hostname")
            self.assertEqual(interfaces_sheet["A2"].value, "SW-TEST-01")
            self.assertEqual(interfaces_sheet["B2"].value, "Gi1/0/1")

            poe_sheet = workbook["PoE"]
            self.assertEqual(poe_sheet["A2"].value, "SW-TEST-01")
            self.assertEqual(poe_sheet["E2"].value, "15.4")

            device_info_sheet = workbook["Device Info"]
            self.assertEqual(device_info_sheet["A1"].value, "Hostname")
            self.assertEqual(device_info_sheet["A2"].value, "SW-TEST-01")

    def test_multiple_devices_combine_into_shared_sheets_not_duplicated(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "combined.xlsx"
            SwitchExcelExporter([SAMPLE_RESULT, SAMPLE_RESULT_2]).export(path)
            workbook = load_workbook(path)

            # One "Device Info" sheet — not one per device — with a row
            # for each device.
            self.assertEqual(workbook.sheetnames.count("Device Info"), 1)
            device_info_sheet = workbook["Device Info"]
            hostnames = [row[0].value for row in device_info_sheet.iter_rows(min_row=2)]
            self.assertEqual(hostnames, ["SW-TEST-01", "SW-TEST-02"])

            interfaces_sheet = workbook["Interfaces"]
            interface_hostnames = [row[0].value for row in interfaces_sheet.iter_rows(min_row=2)]
            self.assertEqual(interface_hostnames, ["SW-TEST-01", "SW-TEST-02"])

    def test_export_handles_empty_optional_sections(self):
        minimal_result = {"hostname": "SW2", "vendor": "Huawei", "cards": {}}
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "export.xlsx"
            SwitchExcelExporter(minimal_result).export(path)
            workbook = load_workbook(path)
            self.assertIn("Transceivers", workbook.sheetnames)
            self.assertEqual(workbook["Transceivers"]["A2"].value, None)


if __name__ == "__main__":
    unittest.main()
