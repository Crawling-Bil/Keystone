"""End-to-end tests for the /ztp/api/* routes, using Flask's
real test client against the real app factory (not just the
underlying features.ztp.core modules in isolation) -- this is what actually
caught the malformed-ESN-crashes-with-500 bug on the delete/status
routes before it shipped."""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class ZtpRoutesTests(unittest.TestCase):
    def setUp(self):
        # Point every data file this app touches at a scratch dir so
        # these tests never read/write the real installation's data.
        self._scratch = Path(tempfile.mkdtemp())

        # ZTP moved to its own blueprint/module (features.ztp) -- Lifecycle's
        # own routes module still owns SETTINGS_FILE/DEVICES_FILE/
        # FIRMWARE_DB_FILE/JOBS_FILE (Discovery/Firmware/Jobs) plus
        # _ztp_auto_mark_provisioned (the one place it still depends on
        # ztp_store), while everything ZTP-specific -- staging paths, the
        # running DHCP/SFTP server instances -- now lives on ztp_routes.
        import features.lifecycle_manager.routes as routes
        import features.ztp.routes as ztp_routes
        import features.ztp.core.store as ztp_store
        import features.ztp.core.activity_log as ztp_activity_log

        self._routes = routes
        self._ztp_routes = ztp_routes
        self._ztp_store = ztp_store
        self._ztp_activity_log = ztp_activity_log
        ztp_activity_log.clear()
        self._orig = {
            "SETTINGS_FILE": routes.SETTINGS_FILE,
            "DEVICES_FILE": routes.DEVICES_FILE,
            "FIRMWARE_DB_FILE": routes.FIRMWARE_DB_FILE,
            "FIRMWARE_DIR": routes.FIRMWARE_DIR,
            "JOBS_FILE": routes.JOBS_FILE,
        }
        self._orig_ztp = {
            "ZTP_DATA_DIR": ztp_routes.ZTP_DATA_DIR,
            "ZTP_STAGING_DIR": ztp_routes.ZTP_STAGING_DIR,
        }
        self._orig_store = {"DATA_DIR": ztp_store.DATA_DIR, "DEVICES_FILE": ztp_store.DEVICES_FILE}

        routes.SETTINGS_FILE = self._scratch / "settings.json"
        routes.DEVICES_FILE = self._scratch / "devices.json"
        routes.FIRMWARE_DB_FILE = self._scratch / "firmware.json"
        routes.JOBS_FILE = self._scratch / "jobs.json"
        routes.FIRMWARE_DIR = self._scratch / "firmware"
        ztp_routes.ZTP_DATA_DIR = self._scratch / "ztp"
        ztp_routes.ZTP_STAGING_DIR = ztp_routes.ZTP_DATA_DIR / "staging"
        ztp_routes.ZTP_STAGING_DIR.mkdir(parents=True, exist_ok=True)
        ztp_store.DATA_DIR = ztp_routes.ZTP_DATA_DIR
        ztp_store.DEVICES_FILE = ztp_routes.ZTP_DATA_DIR / "ztp_devices.json"

        import app as nes_app
        self.client = nes_app.create_app().test_client()

        # A test that reaches a real 200 on dhcp/start leaves the module
        # global set to whatever server instance (real or mocked) it
        # created -- reset it so that leak never fails an unrelated test
        # in this file with a spurious "already running" 400.
        self._orig_dhcp_instance = ztp_routes._ztp_dhcp_instance
        self._orig_syslog_instance = ztp_routes._ztp_syslog_instance

    def tearDown(self):
        routes = self._routes
        ztp_routes = self._ztp_routes
        ztp_store = self._ztp_store
        for key, value in self._orig.items():
            setattr(routes, key, value)
        for key, value in self._orig_ztp.items():
            setattr(ztp_routes, key, value)
        for key, value in self._orig_store.items():
            setattr(ztp_store, key, value)
        ztp_routes._ztp_dhcp_instance = self._orig_dhcp_instance
        ztp_routes._ztp_syslog_instance = self._orig_syslog_instance
        self._ztp_activity_log.clear()
        shutil.rmtree(self._scratch, ignore_errors=True)

    def _register(self, esn="2102311LDL0000000806", **overrides):
        payload = {
            "esn": esn,
            "mac": "AA:BB:CC:DD:EE:01",
            "hostname": "TTC-SWAC-TEST-01",
            "mgmt_ip": "10.50.1.11",
            "gateway": "10.50.1.1",
            "vrp_username": "keystone-ztp",
            "vrp_password": "Str0ngP@ssw0rd!",
        }
        payload.update(overrides)
        return self.client.post("/ztp/api/devices", json=payload)

    def test_register_list_delete_roundtrip(self):
        r = self._register()
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["success"])
        # Password must never be echoed back in plaintext.
        self.assertNotIn("vrp_password", body["device"])
        self.assertTrue(body["device"]["has_password"])

        r = self.client.get("/ztp/api/devices")
        self.assertEqual(len(r.get_json()["devices"]), 1)

        r = self.client.delete("/ztp/api/devices/2102311LDL0000000806")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.get("/ztp/api/devices").get_json()["devices"], [])

    def test_malformed_esn_returns_400_not_500(self):
        # Regression test: this used to raise an uncaught ZtpStoreError
        # inside the route (500, no JSON body) instead of a clean 400.
        r = self.client.delete("/ztp/api/devices/not a valid esn!")
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())

        r = self.client.post(
            "/ztp/api/devices/not a valid esn!/status", json={"status": "provisioned"}
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())

    def test_valid_but_unknown_esn_returns_404(self):
        r = self.client.delete("/ztp/api/devices/2102311LDL0000009999")
        self.assertEqual(r.status_code, 404)

        r = self.client.post(
            "/ztp/api/devices/2102311LDL0000009999/status", json={"status": "provisioned"}
        )
        self.assertEqual(r.status_code, 404)

    def test_status_rejects_unknown_value(self):
        self._register()
        r = self.client.post(
            "/ztp/api/devices/2102311LDL0000000806/status", json={"status": "bogus"}
        )
        self.assertEqual(r.status_code, 400)

    def test_provisioned_devices_are_excluded_from_next_generate(self):
        self._register(esn="2102311LDL0000000806", hostname="DEV-A", mgmt_ip="10.50.1.11")
        self._register(esn="2102311LDL0000000918", hostname="DEV-B", mgmt_ip="10.50.1.12")

        r = self.client.post(
            "/ztp/api/generate", json={"fileserver_url": "sftp://u:p@10.50.1.5:2222/"}
        )
        self.assertEqual(sorted(r.get_json()["config_files"]), ["DEV-A.cfg", "DEV-B.cfg"])

        r = self.client.post(
            "/ztp/api/devices/2102311LDL0000000806/status", json={"status": "provisioned"}
        )
        self.assertEqual(r.get_json()["device"]["status"], "provisioned")

        r = self.client.post(
            "/ztp/api/generate", json={"fileserver_url": "sftp://u:p@10.50.1.5:2222/"}
        )
        # Only the still-pending device should be regenerated -- a
        # provisioned device shouldn't keep reappearing in every future
        # intermediate file / DHCP reservation list.
        self.assertEqual(r.get_json()["config_files"], ["DEV-B.cfg"])

    # ------------------------------------------------------------------
    # Firmware staging on Generate (production-debugger follow-up): a
    # device registered with firmware_filename set must have that file
    # actually copied into ZTP_STAGING_DIR, not just referenced by name
    # in the intermediate file -- otherwise the switch's SFTP GET for
    # its SOFTWARE file fails partway through ZTP with nothing in the
    # UI ever having said so.
    # ------------------------------------------------------------------

    def _add_firmware(self, filename="S5735-V2_V600R025C00SPC500.cc", vendor="Huawei", content=b"fake-image-bytes"):
        vendor_dir = self._routes.FIRMWARE_DIR / vendor.lower()
        vendor_dir.mkdir(parents=True, exist_ok=True)
        (vendor_dir / filename).write_bytes(content)
        self._routes.write_json(self._routes.FIRMWARE_DB_FILE, {
            "firmwares": [{
                "id": "fw-1", "vendor": vendor, "platform": "", "model": "S5735-V2",
                "version": "", "filename": filename, "size": len(content), "checksum": "x",
                "patch_filename": "", "patch_size": 0, "patch_checksum": "", "uploaded_at": "now",
            }]
        })
        return content

    def test_generate_stages_firmware_file_into_staging_dir(self):
        content = self._add_firmware()
        self._register(firmware_filename="S5735-V2_V600R025C00SPC500.cc")

        r = self.client.post(
            "/ztp/api/generate", json={"fileserver_url": "sftp://u:p@10.50.1.5:2222/"}
        )
        self.assertEqual(r.status_code, 200)

        staged = self._ztp_routes.ZTP_STAGING_DIR / "S5735-V2_V600R025C00SPC500.cc"
        self.assertTrue(staged.is_file())
        self.assertEqual(staged.read_bytes(), content)

    def test_generate_skips_recopy_when_already_staged(self):
        # A 200+MB image shouldn't be re-copied on every Generate click
        # once it's already there with the right size.
        self._add_firmware()
        self._register(firmware_filename="S5735-V2_V600R025C00SPC500.cc")
        r1 = self.client.post("/ztp/api/generate", json={"fileserver_url": "sftp://u:p@10.50.1.5:2222/"})
        self.assertEqual(r1.status_code, 200)

        staged = self._ztp_routes.ZTP_STAGING_DIR / "S5735-V2_V600R025C00SPC500.cc"
        staged.write_bytes(b"untouched-marker")  # would be overwritten if re-copied

        r2 = self.client.post("/ztp/api/generate", json={"fileserver_url": "sftp://u:p@10.50.1.5:2222/"})
        self.assertEqual(r2.status_code, 200)
        # Same size as the real image (17 bytes, matches "fake-image-bytes")
        # -> skip-copy path -- our marker survives.
        self.assertEqual(staged.read_bytes(), b"untouched-marker")

    def test_generate_writes_ini_sha256_matching_the_freshly_written_cfg(self):
        # Regression, confirmed against real hardware: build_intermediate_file()
        # (which computes each file's SHA256_n) used to run BEFORE the
        # bootstrap .cfg was rendered and written to ZTP_STAGING_DIR, so
        # it hashed whatever .cfg happened to be left over from the
        # previous /ztp/api/generate call instead of the one it was
        # about to write moments later. Two generates in a row with
        # IDENTICAL device data hid this completely (the stale hash
        # still matched by coincidence); it only surfaced as a real ZTP
        # "Integrity check failed" once the .cfg content actually
        # changed between generates -- which is exactly what this test
        # forces by re-registering the same device (same hostname, so
        # the same .cfg filename) with a different password before the
        # second generate.
        import hashlib
        import re as _re

        self._register(vrp_password="FirstPassw0rd!")
        r1 = self.client.post(
            "/ztp/api/generate", json={"fileserver_url": "sftp://u:p@10.50.1.5:2222/"}
        )
        self.assertEqual(r1.status_code, 200)

        self.client.delete("/ztp/api/devices/2102311LDL0000000806")
        self._register(vrp_password="SecondPassw0rd!")
        r2 = self.client.post(
            "/ztp/api/generate", json={"fileserver_url": "sftp://u:p@10.50.1.5:2222/"}
        )
        self.assertEqual(r2.status_code, 200)

        staging = self._ztp_routes.ZTP_STAGING_DIR
        cfg_files = [p for p in staging.glob("*.cfg")]
        self.assertEqual(len(cfg_files), 1, f"expected exactly one .cfg, found {cfg_files}")
        cfg_path = cfg_files[0]
        self.assertIn("SecondPassw0rd!", cfg_path.read_text(encoding="utf-8"))

        actual_sha256 = hashlib.sha256(cfg_path.read_bytes()).hexdigest()
        ini_text = (staging / "ztp_script.ini").read_text(encoding="utf-8")
        match = _re.search(
            rf"\*FILENAME_\d+={_re.escape(cfg_path.name)}\n\*TYPE_\d+=CFG\n"
            rf"\*EFFECTIVE_MODE_\d+=\d+\nISBATCHPROCESS_\d+=\d+\nSHA256_\d+=([0-9a-f]+)",
            ini_text,
        )
        self.assertIsNotNone(match, f"couldn't find a SHA256_n line for {cfg_path.name} in:\n{ini_text}")
        self.assertEqual(
            match.group(1), actual_sha256,
            "ztp_script.ini's recorded SHA256 for the .cfg doesn't match the "
            "actual .cfg content that was written -- a real device's ZTP "
            "integrity check would reject this download.",
        )

    def test_generate_fails_cleanly_when_firmware_missing_from_repository(self):
        self._register(firmware_filename="never-uploaded.cc")

        r = self.client.post(
            "/ztp/api/generate", json={"fileserver_url": "sftp://u:p@10.50.1.5:2222/"}
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("never-uploaded.cc", r.get_json()["error"])
        # Must fail before writing anything -- no partial staging dir.
        self.assertEqual(list(self._ztp_routes.ZTP_STAGING_DIR.glob("*")), [])

    def test_generate_requires_fileserver_url(self):
        self._register()
        r = self.client.post("/ztp/api/generate", json={})
        self.assertEqual(r.status_code, 400)

    def test_generate_with_no_pending_devices_fails_cleanly(self):
        r = self.client.post(
            "/ztp/api/generate", json={"fileserver_url": "sftp://u:p@10.50.1.5:2222/"}
        )
        self.assertEqual(r.status_code, 400)

    def test_missing_password_on_register_is_400(self):
        payload = {
            "esn": "2102311LDL0000000806",
            "hostname": "TTC-SWAC-TEST-01",
            "mgmt_ip": "10.50.1.11",
        }
        r = self.client.post("/ztp/api/devices", json=payload)
        self.assertEqual(r.status_code, 400)

    def test_dhcp_start_requires_isolated_segment_confirmation(self):
        r = self.client.post("/ztp/api/dhcp/start", json={
            "interface": "eth1", "range_start": "10.50.1.100", "range_end": "10.50.1.199",
            "subnet_mask": "255.255.255.0", "option67_url": "sftp://u:p@h/f.ini",
        })
        self.assertEqual(r.status_code, 400)
        self.assertIn("confirm_isolated_segment", r.get_json()["error"])

    def test_dhcp_start_requires_all_fields(self):
        r = self.client.post("/ztp/api/dhcp/start", json={"confirm_isolated_segment": True})
        self.assertEqual(r.status_code, 400)

    def test_dhcp_start_with_wildcard_interface_is_400_not_500(self):
        # Regression: bad input (a wildcard interface) must be reported
        # as a 400 even on a machine without dnsmasq installed -- it
        # must not be masked by an unrelated 500 "dnsmasq missing"
        # error, which previously happened because the dnsmasq-binary
        # check ran before input validation.
        r = self.client.post("/ztp/api/dhcp/start", json={
            "interface": "0.0.0.0", "range_start": "10.50.1.100", "range_end": "10.50.1.199",
            "subnet_mask": "255.255.255.0", "option67_url": "sftp://u:p@h/f.ini",
            "confirm_isolated_segment": True,
        })
        self.assertEqual(r.status_code, 400)
        self.assertIn("interface", r.get_json()["error"])

    def test_dhcp_start_with_oversized_option67_url_is_400_not_500(self):
        # Regression: a real-world sftp:// URL (user + strong password +
        # host + port + a Huawei-max-length 64-char filename) can easily
        # exceed the 127-byte limit dnsmasq silently truncates to on the
        # wire -- this must be caught here with a clear 400, not shipped
        # to dnsmasq to corrupt silently.
        long_url = "sftp://ztp_user:" + ("x" * 100) + "@10.50.1.5:2222/ztp_script.ini"
        self.assertGreater(len(long_url), 127)
        r = self.client.post("/ztp/api/dhcp/start", json={
            "interface": "eth1", "range_start": "10.50.1.100", "range_end": "10.50.1.199",
            "subnet_mask": "255.255.255.0", "option67_url": long_url,
            "confirm_isolated_segment": True,
        })
        self.assertEqual(r.status_code, 400)
        self.assertIn("127", r.get_json()["error"])

    def test_dhcp_start_passes_lease_time_through_to_the_server(self):
        # A device with no MAC on file never gets a dhcp-host reservation
        # (see ztp_dhcp_start()'s reservations comprehension), so it only
        # gets an address from the shared lease pool -- lease_time is the
        # only knob that controls how fast that pool turns over. Assert
        # it actually reaches ZtpDhcpServer instead of being silently
        # dropped on the floor between the route and the server class.
        with patch.object(self._ztp_routes.ztp_dhcp_module, "ZtpDhcpServer") as mock_server_cls:
            mock_server_cls.return_value.start.return_value = None
            r = self.client.post("/ztp/api/dhcp/start", json={
                "interface": "eth1", "range_start": "10.50.1.100", "range_end": "10.50.1.199",
                "subnet_mask": "255.255.255.0", "option67_url": "sftp://u:p@h/f.ini",
                "lease_time": "15m", "confirm_isolated_segment": True,
            })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(mock_server_cls.call_args.kwargs["lease_time"], "15m")

    def test_dhcp_start_defaults_lease_time_when_omitted(self):
        with patch.object(self._ztp_routes.ztp_dhcp_module, "ZtpDhcpServer") as mock_server_cls:
            mock_server_cls.return_value.start.return_value = None
            r = self.client.post("/ztp/api/dhcp/start", json={
                "interface": "eth1", "range_start": "10.50.1.100", "range_end": "10.50.1.199",
                "subnet_mask": "255.255.255.0", "option67_url": "sftp://u:p@h/f.ini",
                "confirm_isolated_segment": True,
            })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(mock_server_cls.call_args.kwargs["lease_time"], "1h")

    def test_sftp_lifecycle(self):
        r = self.client.post("/ztp/api/sftp/start", json={
            "username": "ztp_user", "password": "ztp_pass", "bind_ip": "127.0.0.1", "port": 0,
        })
        self.assertEqual(r.status_code, 200)
        # port=0 asks the OS for any free port -- the response must echo
        # back the port actually bound, not the literal 0 that was sent,
        # or the frontend's File Server URL / Option 67 auto-fill would
        # build an unusable sftp://host:0/ URL.
        self.assertGreater(r.get_json()["port"], 0)
        self.assertTrue(self.client.get("/ztp/api/sftp/status").get_json()["running"])

        # Starting a second one while the first is still up must be rejected.
        r = self.client.post("/ztp/api/sftp/start", json={
            "username": "ztp_user", "password": "ztp_pass", "bind_ip": "127.0.0.1", "port": 0,
        })
        self.assertEqual(r.status_code, 400)

        self.client.post("/ztp/api/sftp/stop")
        self.assertFalse(self.client.get("/ztp/api/sftp/status").get_json()["running"])

    def test_syslog_lifecycle(self):
        r = self.client.post("/ztp/api/syslog/start", json={"bind_ip": "127.0.0.1", "port": 0})
        self.assertEqual(r.status_code, 200)
        self.assertGreater(r.get_json()["port"], 0)
        self.assertTrue(self.client.get("/ztp/api/syslog/status").get_json()["running"])

        # Starting a second one while the first is still up must be rejected.
        r = self.client.post("/ztp/api/syslog/start", json={"bind_ip": "127.0.0.1", "port": 0})
        self.assertEqual(r.status_code, 400)

        self.client.post("/ztp/api/syslog/stop")
        self.assertFalse(self.client.get("/ztp/api/syslog/status").get_json()["running"])

    def test_activity_feed_empty_by_default(self):
        r = self.client.get("/ztp/api/activity")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["events"], [])

    def test_activity_clear_route_empties_the_feed(self):
        self._ztp_activity_log.record("sftp", "some event")
        self.assertTrue(self.client.get("/ztp/api/activity").get_json()["events"])

        r = self.client.post("/ztp/api/activity/clear")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.get("/ztp/api/activity").get_json()["events"], [])

    def test_activity_feed_returns_events_and_supports_since_id(self):
        self._ztp_activity_log.record("sftp", "first event")
        second = self._ztp_activity_log.record("dhcp", "second event")
        self._ztp_activity_log.record("syslog", "third event")

        r = self.client.get("/ztp/api/activity")
        events = r.get_json()["events"]
        self.assertEqual([e["message"] for e in events], ["first event", "second event", "third event"])

        r = self.client.get(f"/ztp/api/activity?since_id={second['id']}")
        events = r.get_json()["events"]
        self.assertEqual([e["message"] for e in events], ["third event"])

    def test_generate_records_activity_and_clears_previous_cycle(self):
        self._ztp_activity_log.record("sftp", "leftover from a previous cycle")

        self._register()
        r = self.client.post(
            "/ztp/api/generate", json={"fileserver_url": "sftp://u:p@10.50.1.5:2222/"}
        )
        self.assertEqual(r.status_code, 200)

        events = self.client.get("/ztp/api/activity").get_json()["events"]
        messages = [e["message"] for e in events]
        # the stale event from before this generate must be gone --
        # a fresh Generate click means a new test/deployment cycle.
        self.assertFalse(any("leftover from a previous cycle" in m for m in messages))
        self.assertTrue(any("Generating deployment files" in m for m in messages))
        self.assertTrue(any("Wrote" in m for m in messages))

    def test_generate_with_syslog_target_sets_syslog_info_in_ini(self):
        self._register()
        r = self.client.post(
            "/ztp/api/generate",
            json={
                "fileserver_url": "sftp://u:p@10.50.1.5:2222/",
                "syslog_target": "10.50.1.5:514",
            },
        )
        self.assertEqual(r.status_code, 200)

        ini_text = (self._ztp_routes.ZTP_STAGING_DIR / "ztp_script.ini").read_text(encoding="utf-8")
        self.assertIn("SYSLOG_INFO=10.50.1.5:514", ini_text)

    def test_generate_without_syslog_target_leaves_syslog_info_blank(self):
        self._register()
        r = self.client.post(
            "/ztp/api/generate", json={"fileserver_url": "sftp://u:p@10.50.1.5:2222/"}
        )
        self.assertEqual(r.status_code, 200)

        ini_text = (self._ztp_routes.ZTP_STAGING_DIR / "ztp_script.ini").read_text(encoding="utf-8")
        self.assertIn("SYSLOG_INFO=\n", ini_text)

    # ------------------------------------------------------------------
    # Auto-mark-provisioned on discovery (production-debugger follow-up):
    # a device that finishes ZTP and shows up in a real /api/discovery
    # scan should have its ztp_store entry flipped to "provisioned"
    # automatically, using the ESN the Huawei driver already collects
    # via `display esn` -- without this it stays "pending" forever and
    # keeps reappearing in /api/ztp/generate and DHCP reservations.
    # ------------------------------------------------------------------

    def test_auto_mark_provisioned_helper_matches_by_esn(self):
        self._register(esn="2102311LDL0000000806")
        self.assertEqual(
            self._ztp_store.get_device("2102311LDL0000000806")["status"], "pending"
        )

        newly = self._routes._ztp_auto_mark_provisioned([
            {"ip": "10.50.1.50", "status": "online", "serial": "2102311LDL0000000806"},
        ])

        self.assertEqual(newly, ["2102311LDL0000000806"])
        self.assertEqual(
            self._ztp_store.get_device("2102311LDL0000000806")["status"], "provisioned"
        )

    def test_auto_mark_provisioned_helper_ignores_unmatched_and_unknown_serials(self):
        self._register(esn="2102311LDL0000000806")

        newly = self._routes._ztp_auto_mark_provisioned([
            {"ip": "10.50.1.51", "status": "online", "serial": "Unknown"},
            {"ip": "10.50.1.52", "status": "online", "serial": "NOT-PREREGISTERED-ESN"},
            {"ip": "10.50.1.53", "status": "online", "serial": None},
        ])

        self.assertEqual(newly, [])
        self.assertEqual(
            self._ztp_store.get_device("2102311LDL0000000806")["status"], "pending"
        )

    def test_auto_mark_provisioned_helper_is_idempotent(self):
        self._register(esn="2102311LDL0000000806")
        self._ztp_store.mark_status("2102311LDL0000000806", "provisioned")

        # Already provisioned -- must not be reported as newly-flipped
        # again on a second discovery scan that still sees it.
        newly = self._routes._ztp_auto_mark_provisioned([
            {"ip": "10.50.1.50", "status": "online", "serial": "2102311LDL0000000806"},
        ])
        self.assertEqual(newly, [])

    def test_real_discovery_route_auto_provisions_matching_ztp_device(self):
        self._register(esn="2102311LDL0000000806")

        def fake_scan_range(**kwargs):
            return [
                {
                    "ip": "10.50.1.50", "status": "online", "hostname": "sw-01",
                    "vendor": "Huawei", "serial": "2102311LDL0000000806",
                },
            ]

        original_scan_range = self._routes.scan_range
        self._routes.scan_range = fake_scan_range
        try:
            r = self.client.post("/lifecycle/api/discovery", json={
                "demo_mode": False, "start_ip": "10.50.1.50", "end_ip": "10.50.1.50",
                "username": "admin", "password": "admin",
            })
        finally:
            self._routes.scan_range = original_scan_range

        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["ztp_auto_provisioned"], ["2102311LDL0000000806"])
        self.assertEqual(
            self._ztp_store.get_device("2102311LDL0000000806")["status"], "provisioned"
        )

    # ------------------------------------------------------------------
    # Interfaces (dropdown source), Excel template + bulk import
    # ------------------------------------------------------------------

    def test_interfaces_route_never_500s_even_if_listing_fails(self):
        # A platform quirk in interface enumeration must degrade the
        # ZTP tab's dropdown to manual entry, not break the route.
        import features.ztp.core.net_interfaces as nif
        original = nif.list_interfaces
        nif.list_interfaces = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            r = self.client.get("/ztp/api/interfaces")
        finally:
            nif.list_interfaces = original
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["interfaces"], [])
        self.assertFalse(r.get_json()["success"])

    def test_interfaces_route_returns_a_list_on_success(self):
        r = self.client.get("/ztp/api/interfaces")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["success"])
        self.assertIsInstance(r.get_json()["interfaces"], list)

    def test_devices_template_downloads_an_xlsx(self):
        r = self.client.get("/ztp/api/devices/template")
        self.assertEqual(r.status_code, 200)
        self.assertIn("spreadsheetml", r.headers["Content-Type"])
        self.assertGreater(len(r.data), 0)

    def test_devices_import_registers_valid_rows_and_reports_bad_ones(self):
        from io import BytesIO
        from openpyxl import Workbook

        workbook = Workbook()
        sheet = workbook.active
        sheet.append(["ESN (Serial Number)", "Hostname", "Management IP", "SSH Password"])
        sheet.append(["2102311LDL0000000806", "sw-good-01", "10.50.1.11", "Str0ngP@ss!"])
        sheet.append(["BAD ESN WITH SPACES", "sw-bad-01", "10.50.1.12", "Str0ngP@ss!"])
        sheet.append(["2102311LDL0000000807", "sw-missing-pw", "10.50.1.13", ""])
        buf = BytesIO()
        workbook.save(buf)
        buf.seek(0)

        r = self.client.post(
            "/ztp/api/devices/import",
            data={"file": (buf, "devices.xlsx")},
            content_type="multipart/form-data",
        )
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["registered_count"], 1)
        self.assertEqual(body["registered_esns"], ["2102311LDL0000000806"])
        self.assertEqual(len(body["failed"]), 2)
        self.assertIsNotNone(self._ztp_store.get_device("2102311LDL0000000806"))

    def test_devices_import_rejects_non_xlsx_file(self):
        from io import BytesIO
        r = self.client.post(
            "/ztp/api/devices/import",
            data={"file": (BytesIO(b"not a spreadsheet"), "devices.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(r.status_code, 400)

    def test_devices_import_requires_a_file(self):
        r = self.client.post("/ztp/api/devices/import", data={}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
