import json
import unittest
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from features.ztp.core import store as ztp_store


class ZtpStoreTests(unittest.TestCase):
    def setUp(self):
        self._scratch = Path(tempfile.mkdtemp())
        self._orig_data_dir = ztp_store.DATA_DIR
        self._orig_devices_file = ztp_store.DEVICES_FILE
        ztp_store.DATA_DIR = self._scratch
        ztp_store.DEVICES_FILE = self._scratch / "ztp_devices.json"

    def tearDown(self):
        ztp_store.DATA_DIR = self._orig_data_dir
        ztp_store.DEVICES_FILE = self._orig_devices_file
        shutil.rmtree(self._scratch, ignore_errors=True)

    def _valid_record(self, **overrides):
        record = {
            "esn": "2102311LDL0000000806",
            "mac": "AA:BB:CC:DD:EE:01",
            "hostname": "TTC-SWAC-TEST-01",
            "mgmt_ip": "10.50.1.11",
            "vrp_username": "keystone-ztp",
            "vrp_password": "Str0ngP@ssw0rd!",
        }
        record.update(overrides)
        return record

    def test_upsert_and_list(self):
        ztp_store.upsert_device(self._valid_record())
        devices = ztp_store.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["esn"], "2102311LDL0000000806")
        self.assertEqual(devices[0]["status"], "pending")
        # MAC is normalized to lowercase.
        self.assertEqual(devices[0]["mac"], "aa:bb:cc:dd:ee:01")

    def test_upsert_is_idempotent_on_esn(self):
        ztp_store.upsert_device(self._valid_record(hostname="FIRST"))
        ztp_store.upsert_device(self._valid_record(hostname="SECOND"))
        devices = ztp_store.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["hostname"], "SECOND")

    def test_rejects_invalid_esn(self):
        with self.assertRaises(ztp_store.ZtpStoreError):
            ztp_store.upsert_device(self._valid_record(esn="bad esn!"))

    def test_rejects_invalid_mac(self):
        with self.assertRaises(ztp_store.ZtpStoreError):
            ztp_store.upsert_device(self._valid_record(mac="not-a-mac"))

    def test_requires_password(self):
        record = self._valid_record()
        record.pop("vrp_password")
        with self.assertRaises(ztp_store.ZtpStoreError):
            ztp_store.upsert_device(record)

    def test_requires_hostname_and_ip(self):
        with self.assertRaises(ztp_store.ZtpStoreError):
            ztp_store.upsert_device(self._valid_record(hostname=""))
        with self.assertRaises(ztp_store.ZtpStoreError):
            ztp_store.upsert_device(self._valid_record(mgmt_ip=""))

    def test_delete_device(self):
        ztp_store.upsert_device(self._valid_record())
        self.assertTrue(ztp_store.delete_device("2102311LDL0000000806"))
        self.assertEqual(ztp_store.list_devices(), [])
        self.assertFalse(ztp_store.delete_device("2102311LDL0000000806"))

    def test_mark_status(self):
        ztp_store.upsert_device(self._valid_record())
        updated = ztp_store.mark_status("2102311LDL0000000806", "provisioned")
        self.assertEqual(updated["status"], "provisioned")
        self.assertEqual(ztp_store.get_device("2102311LDL0000000806")["status"], "provisioned")

    # ------------------------------------------------------------------
    # Regression (production-debugger pass): _read_unlocked() used to
    # catch (json.JSONDecodeError, OSError) unconditionally and return
    # the caller's empty-list default for BOTH "file doesn't exist yet"
    # and "file exists but a transient read error occurred" -- callers
    # like upsert_device() couldn't tell the difference, and
    # upsert_device() unconditionally writes at the end of its critical
    # section regardless of whether the read that fed it actually
    # succeeded. That meant a single transient read glitch during ANY
    # registration silently wiped every other pre-registered device --
    # with the API call still returning 200 success. These tests pin
    # down the fix: an existing-but-unreadable store must raise loudly
    # and must NOT let a write proceed from bad data.
    # ------------------------------------------------------------------

    def test_missing_file_is_still_a_legitimate_empty_store(self):
        # No file at all (brand new install) must NOT raise -- only an
        # existing-but-unreadable file should.
        self.assertFalse(ztp_store.DEVICES_FILE.exists())
        self.assertEqual(ztp_store.list_devices(), [])

    def test_corrupted_json_raises_read_error_not_silent_empty(self):
        ztp_store.upsert_device(self._valid_record())
        ztp_store.DEVICES_FILE.write_text("{not valid json!!", encoding="utf-8")

        with self.assertRaises(ztp_store.ZtpStoreReadError):
            ztp_store.list_devices()

    def test_os_error_on_read_raises_read_error_not_silent_empty(self):
        ztp_store.upsert_device(self._valid_record())

        with patch("builtins.open", side_effect=OSError("simulated I/O error")):
            with self.assertRaises(ztp_store.ZtpStoreReadError):
                ztp_store.list_devices()

    def test_upsert_does_not_wipe_existing_devices_on_transient_read_failure(self):
        # The actual data-loss bug, reproduced directly: two devices
        # are genuinely on disk, a THIRD registration hits a read
        # failure partway through -- the fix must raise instead of
        # quietly proceeding from an empty list and overwriting the
        # file with just the one new device.
        ztp_store.upsert_device(self._valid_record(esn="2102311LDL0000000806", hostname="ONE"))
        ztp_store.upsert_device(self._valid_record(esn="2102311LDL0000000807", hostname="TWO"))
        self.assertEqual(len(ztp_store.list_devices()), 2)

        with patch.object(
            ztp_store, "_read_unlocked",
            side_effect=ztp_store.ZtpStoreReadError("simulated transient read failure"),
        ):
            with self.assertRaises(ztp_store.ZtpStoreReadError):
                ztp_store.upsert_device(
                    self._valid_record(esn="2102311LDL0000000808", hostname="THREE")
                )

        # Read the file for real (mock is gone) -- both original
        # devices must still be there, completely untouched.
        on_disk = json.loads(ztp_store.DEVICES_FILE.read_text(encoding="utf-8"))
        esns_on_disk = {d["esn"] for d in on_disk["devices"]}
        self.assertEqual(esns_on_disk, {"2102311LDL0000000806", "2102311LDL0000000807"})

    def test_delete_and_mark_status_also_refuse_to_proceed_on_read_failure(self):
        ztp_store.upsert_device(self._valid_record())

        with patch.object(
            ztp_store, "_read_unlocked",
            side_effect=ztp_store.ZtpStoreReadError("simulated transient read failure"),
        ):
            with self.assertRaises(ztp_store.ZtpStoreReadError):
                ztp_store.delete_device("2102311LDL0000000806")
            with self.assertRaises(ztp_store.ZtpStoreReadError):
                ztp_store.mark_status("2102311LDL0000000806", "provisioned")

        # Still there, still "pending" -- neither call was allowed to
        # proceed from bad data.
        devices = ztp_store.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["status"], "pending")


if __name__ == "__main__":
    unittest.main()
