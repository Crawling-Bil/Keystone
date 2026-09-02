import unittest

from features.wireless_center.summaries import build_ap_device_summary


class APDeviceSummaryTest(unittest.TestCase):
    def test_groups_model_version_and_status(self):
        result = build_ap_device_summary([
            {"model": "AirEngine-5776", "version": "V600R024", "status": "Normal"},
            {"model": "AirEngine-5776", "version": "V600R024", "status": "Standby"},
            {"model": "AirEngine-5776", "version": "V600R023", "status": "Normal"},
            {"model": "AirEngine-6776", "version": "", "status": "Normal"},
        ])
        self.assertEqual(result["summary"], {
            "models": 2,
            "versions": 2,
            "mixed_models": 1,
            "unknown_versions": 1,
        })
        first = result["rows"][0]
        self.assertEqual(first["model"], "AirEngine-5776")
        self.assertEqual(first["total"], 3)
        self.assertEqual(first["consistency"], "Mixed versions")
        self.assertEqual(first["versions"][0]["count"], 2)

    def test_falls_back_to_type_id_and_runtime_message(self):
        result = build_ap_device_summary([
            {"type_id": "125", "version": "", "status": ""},
        ])
        row = result["rows"][0]
        self.assertEqual(row["model"], "125")
        self.assertEqual(row["consistency"], "Runtime data unavailable")
        self.assertEqual(row["versions"][0]["version"], "Unknown version")


if __name__ == "__main__":
    unittest.main()
