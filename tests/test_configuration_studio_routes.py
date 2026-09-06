"""Route-level tests for features/configuration_studio -- single-file
convert, batch/ZIP convert, and the download endpoints, via the real
Flask app factory and test client.
"""

from __future__ import annotations

import io
import os
import unittest
import zipfile

CISCO_SWITCH_CONFIG = b"""hostname EDGE-SW01
!
vlan 10
 name USERS
!
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10
!
end
"""


class ConfigurationStudioRoutesTests(unittest.TestCase):
    def setUp(self):
        os.environ["NES_DISABLE_AUTH"] = "1"
        self.addCleanup(os.environ.pop, "NES_DISABLE_AUTH", None)

        import app as nes_app
        self.client = nes_app.create_app().test_client()

    def test_index_page_loads(self):
        response = self.client.get("/configuration/")
        self.assertEqual(response.status_code, 200)

    def test_convert_with_no_input_is_a_400(self):
        response = self.client.post("/configuration/api/convert", data={"target_vendor": "Huawei"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])

    def test_convert_pasted_text(self):
        response = self.client.post("/configuration/api/convert", data={
            "config_text": CISCO_SWITCH_CONFIG.decode(),
            "source_vendor": "Cisco",
            "source_device_type": "Switch",
            "target_vendor": "Huawei",
        })
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["hostname"], "EDGE-SW01")
        self.assertIn("download_url", payload["result"])

    def test_convert_uploaded_file_and_download_it(self):
        response = self.client.post(
            "/configuration/api/convert",
            data={
                "config_file": (io.BytesIO(CISCO_SWITCH_CONFIG), "edge-sw01.cfg"),
                "source_vendor": "Cisco",
                "source_device_type": "Switch",
                "target_vendor": "Huawei",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        download_url = response.get_json()["result"]["download_url"]

        download = self.client.get(download_url)
        self.assertEqual(download.status_code, 200)
        self.assertIn(b"sysname EDGE-SW01", download.data)

    def test_convert_rejects_unsupported_file_extension(self):
        response = self.client.post(
            "/configuration/api/convert",
            data={"config_file": (io.BytesIO(b"whatever"), "edge-sw01.exe")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def test_batch_convert_zip_and_download(self):
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as archive:
            archive.writestr("edge-sw01.cfg", CISCO_SWITCH_CONFIG)
            archive.writestr("edge-sw02.cfg", CISCO_SWITCH_CONFIG.replace(b"EDGE-SW01", b"EDGE-SW02"))
        zip_buffer.seek(0)

        response = self.client.post(
            "/configuration/api/batch",
            data={
                "config_files": (zip_buffer, "batch.zip"),
                "source_vendor": "Cisco",
                "source_device_type": "Switch",
                "target_vendor": "Huawei",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["converted_count"], 2)
        self.assertEqual(payload["result"]["failed_count"], 0)

        preview_url = payload["result"]["converted"][0]["preview_url"]
        preview = self.client.get(preview_url)
        self.assertEqual(preview.status_code, 200)
        self.assertTrue(preview.get_json()["ok"])

        download = self.client.get(payload["result"]["download_url"])
        self.assertEqual(download.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(download.data)) as archive:
            self.assertIn("NES_Batch_Summary.json", archive.namelist())

    def test_batch_convert_with_no_files_is_a_400(self):
        response = self.client.post("/configuration/api/batch", data={})
        self.assertEqual(response.status_code, 400)

    def test_batch_preview_rejects_malformed_identifiers(self):
        response = self.client.get("/configuration/api/batch/not-a-hex-id/preview/also-not-hex")
        self.assertEqual(response.status_code, 400)

    def test_download_missing_export_is_a_404(self):
        response = self.client.get("/configuration/download/" + "0" * 32 + "?name=x.cfg")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
