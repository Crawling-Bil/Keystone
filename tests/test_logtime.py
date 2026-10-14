"""features/analyzer_core/logtime.py: the Duration shown next to the Window of a device log."""
from __future__ import annotations

import unittest

from features.analyzer_core.logtime import humanize, log_window, parse_stamp


class ParseStampTests(unittest.TestCase):
    def test_ios_stamp_has_no_year(self):
        stamp, has_year = parse_stamp("*Feb 25 11:18:26.118: %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down")
        self.assertEqual((stamp.month, stamp.day, stamp.hour, stamp.minute, stamp.second), (2, 25, 11, 18, 26))
        self.assertFalse(has_year)

    def test_stamps_with_a_year(self):
        for text, year in (("Oct 12 2026 10:00:00+07:00 SW %LINK", 2026), ("2026 Oct 12 10:00:00.123 SW %ETHPORT", 2026),
                           ("2026-10-12T10:00:00 SW", 2026), ("10/12/26 10:00:00 W 2540", 2026)):
            stamp, has_year = parse_stamp(text)
            self.assertTrue(has_year, text)
            self.assertEqual(stamp.year, year, text)
            self.assertEqual((stamp.month, stamp.day), (10, 12), text)

    def test_text_without_a_stamp(self):
        self.assertIsNone(parse_stamp("3d02h: %SYS-5-CONFIG_I: Configured from console"))
        self.assertIsNone(parse_stamp(""))


class HumanizeTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(humanize(93784), "1 day 2 hours 3 minutes")
        self.assertEqual(humanize(3600), "1 hour 0 minutes")
        self.assertEqual(humanize(75), "1 minute 15 seconds")
        self.assertEqual(humanize(0), "under a second")


class LogWindowTests(unittest.TestCase):
    def test_two_days(self):
        out = log_window("Feb 25 11:18:26.118", "Feb 27 05:17:30.000")
        self.assertEqual(out["text"], "1 day 17 hours 59 minutes")
        self.assertTrue(out["reliable"])

    def test_new_year_is_a_real_day_count(self):
        # 30 December 23:00 to 1 January 01:00 is 26 hours (a year-less stamp is compared in a leap year)
        out = log_window("Dec 30 23:00:00.000", "Jan  1 01:00:00.000")
        self.assertEqual(out["seconds"], 26 * 3600)
        self.assertIn("New Year", out["assumed"])

    def test_clock_set_backwards_is_not_calculated(self):
        out = log_window("Mar 10 08:00:00", "Mar 01 08:00:00")
        self.assertFalse(out["reliable"])
        self.assertIsNone(out["seconds"])
        self.assertIn("not calculated", out["text"])

    def test_stamp_with_and_without_year_cannot_be_compared(self):
        out = log_window("Oct 12 2026 10:00:00", "Oct 13 10:00:00")
        self.assertEqual(out["text"], "")

    def test_unreadable_stamps(self):
        self.assertEqual(log_window("", "")["text"], "")
        self.assertEqual(log_window("3d02h", "4d05h")["text"], "")

    def test_huawei_stamps_with_year(self):
        out = log_window("Oct 12 2026 10:00:00+07:00", "Oct 14 2026 12:30:05+07:00")
        self.assertEqual(out["text"], "2 days 2 hours 30 minutes")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
