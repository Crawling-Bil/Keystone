"""Route-level tests for features/configuration_studio -- single-file
convert, batch/ZIP convert, and the download endpoints, via the real
Flask app factory and test client.
"""

from __future__ import annotations

import io
import json
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

    def test_convert_accepts_mikrotik_rsc_upload(self):
        # .rsc is the extension RouterOS uses for its plain-text
        # "/export" config format (see MikrotikFirewallParser) -- it
        # was missing from ALLOWED_CONFIG_EXTENSIONS, so uploading a
        # real Mikrotik export through Configuration Studio's UI was
        # rejected before it ever reached the parser.
        rsc_config = (
            b"/system identity\n"
            b"set name=EDGE-RTR01\n"
            b"/interface ethernet\n"
            b"set [ find default-name=ether1 ] name=ether1-wan\n"
        )
        response = self.client.post(
            "/configuration/api/convert",
            data={
                "config_file": (io.BytesIO(rsc_config), "edge-rtr01.rsc"),
                "source_vendor": "Mikrotik",
                "source_device_type": "Firewall",
                "target_vendor": "Palo Alto",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["hostname"], "EDGE-RTR01")

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


MIKROTIK_MAPPING_CONFIG = (
    b"/system identity\n"
    b"set name=GLT-BRANCH\n"
    b"/interface ethernet\n"
    b"set [ find default-name=ether1 ] name=ether1-wan\n"
    b"set [ find default-name=ether2 ] name=ether2-lan\n"
    b"/ip address\n"
    b"add address=132.132.132.1/30 interface=ether1-wan\n"
    b"add address=192.168.9.1/24 interface=ether2-lan\n"
)


class ConfigurationStudioMappingTests(unittest.TestCase):
    """
    Route-level coverage for the interface/zone mapping preview step
    (/api/preview-mapping) and for /api/convert accepting an edited
    mapping back as `interface_mapping` -- the "preview & edit before
    generate" flow discussed for the Mikrotik -> Palo Alto SD-WAN
    migration, built on top of PaloAltoFirewallTranslator's
    build_interface_mapping_preview()/mapping-aware translate().
    """

    def setUp(self):
        os.environ["NES_DISABLE_AUTH"] = "1"
        self.addCleanup(os.environ.pop, "NES_DISABLE_AUTH", None)

        import app as nes_app
        self.client = nes_app.create_app().test_client()

    def test_preview_mapping_returns_interface_rows_for_mikrotik_to_paloalto(self):
        response = self.client.post(
            "/configuration/api/preview-mapping",
            data={
                "config_file": (io.BytesIO(MIKROTIK_MAPPING_CONFIG), "glt-branch.rsc"),
                "source_vendor": "Mikrotik",
                "source_device_type": "Firewall",
                "target_vendor": "Palo Alto",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        result = payload["result"]
        self.assertTrue(result["supported"])
        self.assertEqual(result["hostname"], "GLT-BRANCH")
        by_name = {row["name"]: row for row in result["interfaces"]}
        self.assertEqual(by_name["ether1-wan"]["suggested_pan_interface"], "ethernet1/1")
        self.assertEqual(by_name["ether2-lan"]["suggested_pan_interface"], "ethernet1/2")
        self.assertEqual(result["suggested_template_name"], "GLT-BRANCH-Template")

    def test_preview_mapping_reports_unsupported_for_non_paloalto_target(self):
        response = self.client.post(
            "/configuration/api/preview-mapping",
            data={
                "config_file": (io.BytesIO(MIKROTIK_MAPPING_CONFIG), "glt-branch.rsc"),
                "source_vendor": "Mikrotik",
                "source_device_type": "Firewall",
                "target_vendor": "Huawei",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["result"]["supported"])

    def test_preview_mapping_with_no_input_is_a_400(self):
        response = self.client.post(
            "/configuration/api/preview-mapping",
            data={"source_vendor": "Mikrotik", "target_vendor": "Palo Alto"},
        )
        self.assertEqual(response.status_code, 400)

    def test_convert_applies_edited_interface_mapping_and_panorama_wrapping(self):
        mapping = {
            "interfaces": {
                "ether1-wan": {"pan_interface": "ethernet1/2", "zone": "Outside"},
                "ether2-lan": {"pan_interface": "ethernet1/1", "zone": "Inside"},
            },
            "panorama": {"enabled": True, "template_name": "GLT-Template", "device_group_name": "GLT-DG"},
        }
        response = self.client.post(
            "/configuration/api/convert",
            data={
                "config_file": (io.BytesIO(MIKROTIK_MAPPING_CONFIG), "glt-branch.rsc"),
                "source_vendor": "Mikrotik",
                "source_device_type": "Firewall",
                "target_vendor": "Palo Alto",
                "interface_mapping": json.dumps(mapping),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        output_text = payload["result"]["output_text"]
        # The swapped interface numbers from the mapping, not the ether1
        # -> ethernet1/1 auto-guess.
        self.assertIn(
            "set template GLT-Template config devices localhost.localdomain network interface "
            "ethernet ethernet1/2 layer3 ip 132.132.132.1/30",
            output_text,
        )
        self.assertIn(
            "set template GLT-Template config devices localhost.localdomain network interface "
            "ethernet ethernet1/1 layer3 ip 192.168.9.1/24",
            output_text,
        )
        self.assertIn("network layer3 [ ethernet1/2 ]", output_text)
        self.assertIn("Outside", output_text)
        self.assertIn("Inside", output_text)

    def test_convert_with_malformed_interface_mapping_json_is_a_400(self):
        response = self.client.post(
            "/configuration/api/convert",
            data={
                "config_file": (io.BytesIO(MIKROTIK_MAPPING_CONFIG), "glt-branch.rsc"),
                "source_vendor": "Mikrotik",
                "source_device_type": "Firewall",
                "target_vendor": "Palo Alto",
                "interface_mapping": "{not valid json",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
