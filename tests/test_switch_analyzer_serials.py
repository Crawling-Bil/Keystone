"""The device's own serial number (and one per stack member) for the Switch
Analyzer, checked against masked excerpts of the real Oct 2026 TAM captures
(see tests/fixtures/real_captures/README.md).

What went wrong before and what is pinned here
  N1  The "serial number" of a device was the first row of `show inventory`.
      On a Nexus capture that lost its first lines this was a fan module whose
      serial is `N/A`, on an Aruba capture that only had `show modules` it was
      empty, and a stack only ever showed member 1.
  N2  Huawei `display lldp neighbor` prints `Device serial number` for the
      NEIGHBOR. It must never be taken as the serial of the device that was
      captured.
  N3  Fans / power supplies / transceivers also have serials in the same
      tables; only the chassis, the main-board rows and the stack members count.

Rules exercised here
  Cisco   `show inventory` entry "Switch N" / "N" (member) or "Chassis"
          (NX-OS), else `show version` "System serial number", else
          "Processor board ID".
  Huawei  `display device elabel brief`: "Equipment SN(ESN)" and the SN of the
          main-board row of every stack member (Sub = `--`).
  Aruba   `show system` "Serial Number", else `show modules` "Chassis: ...
          Serial Number: ...".
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openpyxl import load_workbook

from features.switch_analyzer import capture_text, serials
from features.switch_analyzer.compare import compare
from features.switch_analyzer.exporters import SwitchExcelExporter
from features.switch_analyzer.service import analyze
from features.switch_analyzer.sizing import build_sizing_summary

FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"


def text(*names: str) -> str:
    return "\n".join((FIXTURES / name).read_text(encoding="utf-8") for name in names)


def parse(*names: str, vendor: str = "", stack_members=None) -> dict:
    return serials.parse_serials(capture_text.clean_lines(text(*names)), vendor, stack_members)


def pairs(result: dict) -> list[tuple[str, str, str]]:
    return [(m["member"], m["model"], m["serial"]) for m in result["members"]]


SHOW_SWITCH_STANDBY_FIRST = """
show switch
Switch/Stack Mac Address : 0000.0000.0099
                                               H/W   Current
Switch#  Role   Mac Address     Priority Version  State
----------------------------------------------------------
 1       Standby 0000.0000.0001   1      V02     Ready
*2       Active  0000.0000.0002   15     V02     Ready
"""


class CiscoSerialTest(unittest.TestCase):
    def test_2960x_stack_lists_every_member_from_show_inventory(self):
        result = parse("cisco_2960x_stack_show_inventory_version.txt")
        self.assertEqual(
            pairs(result),
            [("1", "WS-C2960X-24TS-L", "RTD3968P0M6"), ("2", "WS-C2960X-24TS-L", "KMB0125B2R5")],
        )
        self.assertEqual(result["source"], "show inventory")
        self.assertEqual(result["serial_number"], "RTD3968P0M6")
        self.assertEqual(result["checks"], [])  # `show version` agrees member by member

    def test_3850_stack_lists_every_member(self):
        result = parse("cisco_3850_stack_show_inventory_version.txt")
        self.assertEqual([m["serial"] for m in result["members"]], ["TXN7917H1XF", "OCR7835D4R3"])
        self.assertEqual(result["display"].splitlines(), ["1: TXN7917H1XF", "2: OCR7835D4R3"])

    def test_active_member_is_the_primary_serial_and_roles_are_shown(self):
        capture = text("cisco_3850_stack_show_inventory_version.txt") + SHOW_SWITCH_STANDBY_FIRST
        result = analyze(capture, filename="stack.txt")["serials"]
        self.assertEqual(result["serial_number"], "OCR7835D4R3")  # member 2 is Active
        self.assertEqual(
            result["display"].splitlines(),
            ["1 (Standby): TXN7917H1XF", "2 (Active): OCR7835D4R3"],
        )

    def test_standalone_without_inventory_uses_system_serial_of_show_version(self):
        result = parse("cisco_2960s_show_version.txt")
        self.assertEqual(result["serial_number"], "CIZ4605L3KH")
        self.assertEqual(result["source"], "show version (System serial number)")
        self.assertEqual(result["members"], [])

    def test_processor_board_id_is_the_last_resort(self):
        capture = "Cisco IOS Software\nProcessor board ID FOC1234A0BC\n2 Gigabit Ethernet interfaces\n"
        result = serials.parse_serials(capture_text.clean_lines(capture), "Cisco")
        self.assertEqual(result["serial_number"], "FOC1234A0BC")
        self.assertIn("Processor board ID", result["source"])

    def test_nexus_capture_that_lost_its_first_lines_returns_the_chassis_not_a_fan(self):
        # The session-log record header is only on the first line of each TERM
        # chunk, and the capture starts in the middle of a prompt redraw: a
        # naive "first inventory row" picked `Fan 1`, serial N/A.
        result = parse("nxos_show_inventory_session_log_truncated.txt")
        self.assertEqual(result["serial_number"], "YNM04496EU8")
        self.assertNotIn("N/A", result["display"])
        self.assertEqual(analyze(text("nxos_show_inventory_session_log_truncated.txt"), filename="n.txt")["serials"]["serial_number"], "YNM04496EU8")

    def test_inventory_and_show_version_that_disagree_are_reported_not_hidden(self):
        capture = text("cisco_2960x_stack_show_inventory_version.txt").replace("KMB0125B2R5", "KMB0125B2R5X", 1)
        # Only the `show version` copy is changed (first occurrence is the
        # inventory entry), so the two commands now name different serials.
        result = serials.parse_serials(capture_text.clean_lines(capture), "Cisco")
        self.assertTrue(result["checks"], "a disagreement must be flagged")
        self.assertIn("KMB0125B2R5", " ".join(result["checks"]))
        self.assertEqual(result["source"], "show inventory")  # inventory still wins

    def test_transceiver_and_power_supply_serials_are_never_the_device_serial(self):
        capture = text("nxos_show_inventory_session_log_truncated.txt")
        result = serials.parse_serials(capture_text.clean_lines(capture), "Cisco")
        for foreign in ("EJY69664PP5", "UGH34609DOT"):  # the two power supplies
            self.assertNotIn(foreign, result["display"])


class HuaweiSerialTest(unittest.TestCase):
    def test_single_switch_uses_the_equipment_sn(self):
        result = parse("huawei_s5735_display_device_elabel_brief.txt")
        self.assertEqual(result["serial_number"], "ZM8836070388")
        self.assertEqual(result["source"], "display device elabel brief (Equipment SN)")
        self.assertEqual(result["members"], [])

    def test_stack_takes_the_main_board_row_of_every_member(self):
        result = analyze(text("huawei_s5735_stack_display_device_elabel_brief.txt"), filename="h.txt", vendor="Huawei")["serials"]
        self.assertEqual(
            [(m["member"], m["role"], m["serial"]) for m in result["members"]],
            [("1", "Master", "7U7192926730"), ("2", "Standby", "4S5472471912")],
        )
        self.assertEqual(result["serial_number"], "7U7192926730")
        self.assertEqual(result["display"].splitlines(), ["1 (Master): 7U7192926730", "2 (Standby): 4S5472471912"])

    def test_power_supply_rows_of_the_stack_are_not_serials_of_the_switch(self):
        result = parse("huawei_s5735_stack_display_device_elabel_brief.txt", vendor="Huawei")
        for psu in ("2078374294XWR2888531", "8353177747MHI9789508", "9027548977TVX3295180", "7125078161GYT5005501"):
            self.assertNotIn(psu, result["display"])

    def test_lldp_neighbor_device_serial_is_never_used(self):
        lldp_only = parse("huawei_s5735_lldp_neighbor_device_serial.txt", vendor="Huawei")
        self.assertEqual(lldp_only["serial_number"], "")
        self.assertEqual(lldp_only["display"], "")
        together = parse(
            "huawei_s5735_display_device_elabel_brief.txt",
            "huawei_s5735_lldp_neighbor_device_serial.txt",
            vendor="Huawei",
        )
        self.assertEqual(together["serial_number"], "ZM8836070388")
        self.assertNotIn("849252413713", together["display"])  # the neighbor's `Device serial number`
        analyzed = analyze(
            text("huawei_s5735_display_device_elabel_brief.txt", "huawei_s5735_lldp_neighbor_device_serial.txt"),
            filename="h.txt", vendor="Huawei",
        )
        self.assertEqual(analyzed["serials"]["serial_number"], "ZM8836070388")


class ArubaSerialTest(unittest.TestCase):
    def test_show_system(self):
        result = parse("aruba_2540_show_system.txt")
        self.assertEqual((result["serial_number"], result["source"]), ("VV24TXJ3CI", "show system"))

    def test_show_modules_when_show_system_was_not_captured(self):
        result = parse("aruba_2540_show_modules.txt")
        self.assertEqual((result["serial_number"], result["source"]), ("YJ90UAZ1G7", "show modules"))

    def test_show_system_wins_when_both_were_captured(self):
        result = parse("aruba_2540_show_system.txt", "aruba_2540_show_modules.txt")
        self.assertEqual((result["serial_number"], result["source"]), ("VV24TXJ3CI", "show system"))

    def test_a_capture_without_any_serial_gives_an_empty_value_not_a_guess(self):
        result = parse("aruba_2540_show_arp.txt", "aruba_2540_show_mac_address.txt")
        self.assertEqual((result["serial_number"], result["display"], result["members"]), ("", "", []))


class SerialHygieneTest(unittest.TestCase):
    def test_placeholders_and_garbage_are_not_serials(self):
        for token in ("N/A", "n/a", "--", "-", "", None, "NONE", "unknown", "0", "ab", "has space", "x" * 40):
            self.assertEqual(serials.clean_serial(token), "", repr(token))

    def test_real_looking_serials_are_kept(self):
        for token in ("FOC1234A0BC", "7U7192926730", "YJ90UAZ1G7", "2078374294XWR2888531"):
            self.assertEqual(serials.clean_serial(token), token)

    def test_unknown_vendor_tries_every_parser(self):
        result = parse("aruba_2540_show_modules.txt")
        self.assertEqual(result["serial_number"], "YJ90UAZ1G7")


class SerialWiringTest(unittest.TestCase):
    """The same value has to reach the single-device result, the side-by-side
    comparison, the sizing summary and the Excel export."""

    def _stack(self):
        return analyze(
            text("cisco_3850_stack_show_inventory_version.txt") + SHOW_SWITCH_STANDBY_FIRST, filename="stack.txt",
        )

    def _single(self):
        return analyze(text("cisco_2960s_show_version.txt"), filename="single.txt")

    def test_compare_summary_has_a_serial_number_for_both_devices(self):
        diff = compare(self._stack(), self._single())
        self.assertEqual(diff["device_a"]["serial_number"].splitlines(), ["1 (Standby): TXN7917H1XF", "2 (Active): OCR7835D4R3"])
        self.assertEqual(diff["device_b"]["serial_number"], "CIZ4605L3KH")

    def test_sizing_summary_joins_a_stack_on_one_line(self):
        summary = build_sizing_summary([self._stack(), self._single()])
        by_host = {d["hostname"]: d for d in summary["devices"]}
        serials_seen = sorted(d["serial_number"] for d in by_host.values())
        self.assertIn("CIZ4605L3KH", serials_seen)
        self.assertIn("1 (Standby): TXN7917H1XF; 2 (Active): OCR7835D4R3", serials_seen)

    def test_excel_export_has_serial_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.xlsx"
            SwitchExcelExporter([self._stack(), self._single()]).export(path)
            book = load_workbook(path)
        info = [c.value for c in book["Device Info"][1]]
        column = info.index("Serial Number")
        values = [row[column].value for row in book["Device Info"].iter_rows(min_row=2)]
        self.assertIn("CIZ4605L3KH", values)
        self.assertIn("1 (Standby): TXN7917H1XF; 2 (Active): OCR7835D4R3", values)
        members = [c.value for c in book["Stack Members"][1]]
        self.assertIn("Serial Number", members)
        member_serials = [row[members.index("Serial Number")].value for row in book["Stack Members"].iter_rows(min_row=2)]
        self.assertEqual(sorted(v for v in member_serials if v), ["OCR7835D4R3", "TXN7917H1XF"])


if __name__ == "__main__":
    unittest.main()
