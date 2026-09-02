import tempfile
import unittest
from pathlib import Path

from features.wireless_center.importers.ap_inventory_importer import APInventoryImporter
from features.wireless_center.inventory_master import read_inventory
from features.wireless_center.parsers.config_parser import HuaweiConfigParser
from features.wireless_center.service import analyze


class HuaweiAC6508ImportTest(unittest.TestCase):
    CSV_CONTENT = (
        "\tAP ID,\tAP name,\tStatus,\tMAC address,\tAP group,\tIP address,"
        "\tAP type,\tSystem version,\tSerial Number\n"
        "\t1,\tAP-TEST-01,\tstandby,\t0011-2233-4455,\tGROUP-A,"
        "\t192.0.2.10,\tAirEngine-Test,\tV600R024C00SPC100,\tSERIAL-TEST-01\n"
    )

    CONFIG_CONTENT = """sysname WLC-TEST
Software Version V200R024C00SPC100
ap-id 1 type-id 130 ap-mac 0011-2233-4455 ap-sn SERIAL-TEST-01
 ap-name AP-TEST-01
 ap-group GROUP-A
#
"""

    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        handle.write(self.CSV_CONTENT.encode("utf-8"))
        handle.close()
        self.csv_path = Path(handle.name)

    def tearDown(self):
        self.csv_path.unlink(missing_ok=True)

    def test_runtime_columns_are_imported(self):
        importer = APInventoryImporter(self.csv_path)
        records = importer.load()
        self.assertEqual(records[0]["status"], "standby")
        self.assertEqual(records[0]["model"], "AirEngine-Test")
        self.assertEqual(records[0]["version"], "V600R024C00SPC100")

    def test_tab_prefixed_headers_are_normalized(self):
        inventory = read_inventory(self.csv_path, "Huawei")
        self.assertTrue(inventory["summary"]["valid"])
        self.assertEqual(inventory["summary"]["critical"], 0)
        self.assertEqual(inventory["records"][0]["ap_name"], "AP-TEST-01")
        self.assertEqual(inventory["records"][0]["deployment_status"], "standby")

    def test_config_and_runtime_inventory_merge(self):
        aps = HuaweiConfigParser(self.CONFIG_CONTENT).parse()["aps"]
        importer = APInventoryImporter(self.csv_path)
        importer.load()
        result = importer.merge(aps)
        self.assertEqual(result["matched"], 1)
        self.assertEqual(aps[0]["status"], "standby")
        self.assertEqual(aps[0]["model"], "AirEngine-Test")
        self.assertEqual(aps[0]["version"], "V600R024C00SPC100")

    def test_analysis_compares_after_runtime_enrichment(self):
        result = analyze(self.CONFIG_CONTENT, "Huawei", self.csv_path)
        summary = result["deployment_validation"]["summary"]
        self.assertEqual(summary["matched"], 1)
        self.assertEqual(summary["mismatch"], 0)
        self.assertEqual(summary["missing"], 0)
        self.assertEqual(result["status_counts"]["standby"], 1)


if __name__ == "__main__":
    unittest.main()
