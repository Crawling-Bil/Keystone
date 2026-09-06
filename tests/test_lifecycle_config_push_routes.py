"""End-to-end tests (real Flask test client, real app factory) for the
Lifecycle Manager's "config_push" job type -- pushing an operator-
prepared draft config to a device Keystone already knows about
(Discovery-found, whether or not it went through ZTP or a firmware
upgrade), plus the config-drafts store that feeds it.
"""

import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class ConfigPushRoutesTests(unittest.TestCase):
    def setUp(self):
        self._scratch = Path(tempfile.mkdtemp())

        import features.lifecycle_manager.routes as routes
        self._routes = routes
        self._orig = {
            "SETTINGS_FILE": routes.SETTINGS_FILE,
            "DEVICES_FILE": routes.DEVICES_FILE,
            "FIRMWARE_DB_FILE": routes.FIRMWARE_DB_FILE,
            "FIRMWARE_DIR": routes.FIRMWARE_DIR,
            "JOBS_FILE": routes.JOBS_FILE,
            "CONFIG_DRAFTS_FILE": routes.CONFIG_DRAFTS_FILE,
        }
        self._orig["BASE_DIR"] = routes.BASE_DIR
        routes.SETTINGS_FILE = self._scratch / "settings.json"
        routes.DEVICES_FILE = self._scratch / "devices.json"
        routes.FIRMWARE_DB_FILE = self._scratch / "firmware.json"
        routes.JOBS_FILE = self._scratch / "jobs.json"
        routes.FIRMWARE_DIR = self._scratch / "firmware"
        routes.CONFIG_DRAFTS_FILE = self._scratch / "config_drafts.json"
        # execute_config_push_job() reads BASE_DIR at call time (not
        # injected), so real-mode job-execution tests need it pointed
        # at the scratch dir too -- otherwise a background job would
        # write real backup files into the actual repo checkout.
        routes.BASE_DIR = self._scratch

        # These tests exercise route logic directly via the real Flask
        # test client, not the login gate (core/auth.py has its own
        # dedicated tests) -- disable it here so requests aren't
        # redirected to /login before reaching the view under test.
        import os
        os.environ["NES_DISABLE_AUTH"] = "1"
        self.addCleanup(os.environ.pop, "NES_DISABLE_AUTH", None)

        import app as nes_app
        self.client = nes_app.create_app().test_client()

    def tearDown(self):
        for key, value in self._orig.items():
            setattr(self._routes, key, value)
        shutil.rmtree(self._scratch, ignore_errors=True)

    def _seed_device(self, ip="10.50.1.11", **overrides):
        device = {
            "ip": ip,
            "hostname": "edge-sw-01",
            "vendor": "Huawei",
            "platform": "VRP",
            "model": "S5735-V2",
            "version": "V200R022",
        }
        device.update(overrides)
        self._routes.write_json(self._routes.DEVICES_FILE, {"devices": [device]})
        return device

    # ---------------------------------------------------------------
    # config-drafts CRUD
    # ---------------------------------------------------------------

    def test_config_draft_crud_lifecycle(self):
        create = self.client.post("/lifecycle/api/config-drafts", json={
            "hostname": "edge-sw-01",
            "vendor": "Huawei",
            "source": "manual",
            "content": "sysname edge-sw-01\nvlan batch 10 20\n",
        })
        self.assertEqual(create.status_code, 200)
        draft = create.get_json()["draft"]
        self.assertEqual(draft["line_count"], 2)

        listing = self.client.get("/lifecycle/api/config-drafts").get_json()
        self.assertEqual(len(listing["drafts"]), 1)
        self.assertEqual(listing["drafts"][0]["id"], draft["id"])

        delete = self.client.delete(f"/lifecycle/api/config-drafts/{draft['id']}")
        self.assertEqual(delete.status_code, 200)
        self.assertEqual(self.client.get("/lifecycle/api/config-drafts").get_json()["drafts"], [])

        missing = self.client.delete(f"/lifecycle/api/config-drafts/{draft['id']}")
        self.assertEqual(missing.status_code, 404)

    def test_config_draft_rejects_empty_content(self):
        response = self.client.post("/lifecycle/api/config-drafts", json={"content": "   "})
        self.assertEqual(response.status_code, 400)

    # ---------------------------------------------------------------
    # create_job(type=config_push)
    # ---------------------------------------------------------------

    def test_create_config_push_job_requires_draft_per_device(self):
        self._seed_device()
        response = self.client.post("/lifecycle/api/jobs", json={
            "type": "config_push",
            "devices": ["10.50.1.11"],
            "configs": {},
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("No draft config", response.get_json()["error"])

    def test_create_config_push_job_success(self):
        self._seed_device()
        response = self.client.post("/lifecycle/api/jobs", json={
            "type": "config_push",
            "devices": ["10.50.1.11"],
            "configs": {"10.50.1.11": "sysname edge-sw-01\nvlan batch 10\n"},
        })
        self.assertEqual(response.status_code, 200)
        job = response.get_json()["job"]
        self.assertEqual(job["type"], "config_push")
        self.assertEqual(job["devices"][0]["draft_config"], "sysname edge-sw-01\nvlan batch 10")
        # no firmware fields leak in from the upgrade-job shape
        self.assertNotIn("firmware_id", job["devices"][0])

    def test_create_upgrade_job_still_defaults_when_type_omitted(self):
        self._routes.write_json(self._routes.FIRMWARE_DB_FILE, {"firmwares": [{
            "id": "fw-1", "vendor": "Huawei", "version": "V200R023", "filename": "x.cc",
        }]})
        self._seed_device()
        response = self.client.post("/lifecycle/api/jobs", json={
            "devices": ["10.50.1.11"],
            "assignments": {"10.50.1.11": "fw-1"},
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["job"]["type"], "upgrade")

    # ---------------------------------------------------------------
    # precheck(type=config_push)
    # ---------------------------------------------------------------

    def _create_config_push_job(self, draft="sysname edge-sw-01\n"):
        self._seed_device()
        response = self.client.post("/lifecycle/api/jobs", json={
            "type": "config_push",
            "devices": ["10.50.1.11"],
            "configs": {"10.50.1.11": draft},
        })
        return response.get_json()["job"]["id"]

    def test_precheck_demo_mode_passes_and_marks_job_ready(self):
        job_id = self._create_config_push_job()
        response = self.client.post(f"/lifecycle/api/jobs/{job_id}/precheck", json={})
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["demo_mode"])
        self.assertEqual(body["job"]["status"], "ready")
        device = body["job"]["devices"][0]
        self.assertEqual(device["status"], "ready")
        check_names = [c["name"] for c in device["precheck"]["checks"]]
        self.assertIn("Draft Config", check_names)

    def test_precheck_fails_when_draft_has_no_real_command_lines(self):
        job_id = self._create_config_push_job(draft="# just a comment\n\n")
        response = self.client.post(f"/lifecycle/api/jobs/{job_id}/precheck", json={})
        body = response.get_json()
        self.assertEqual(body["job"]["status"], "precheck_failed")
        self.assertEqual(body["job"]["devices"][0]["status"], "failed")

    @patch("features.lifecycle_manager.routes.detect_driver")
    @patch("features.lifecycle_manager.routes.SSHManager")
    def test_precheck_real_mode_uses_ssh_manager_and_driver(self, mock_ssh_manager, mock_detect_driver):
        self._routes.write_json(self._routes.SETTINGS_FILE, {
            **self._routes.DEFAULT_SETTINGS,
            "demo_mode": False,
            "ssh": {"username": "keystone", "port": 22, "timeout": 10},
        })
        job_id = self._create_config_push_job()

        fake_connection = MagicMock()
        mock_ssh_manager.connect.return_value = {
            "success": True, "connection": fake_connection, "netmiko_device_type": "huawei",
        }
        fake_driver = MagicMock()
        fake_driver.get_device_info.return_value = {
            "hostname": "edge-sw-01", "model": "S5735-V2", "version": "V200R022",
        }
        mock_detect_driver.return_value = fake_driver

        response = self.client.post(f"/lifecycle/api/jobs/{job_id}/precheck", json={"password": "secret"})
        body = response.get_json()

        self.assertFalse(body["demo_mode"])
        self.assertEqual(body["job"]["status"], "ready")
        mock_ssh_manager.connect.assert_called_once()
        fake_connection.disconnect.assert_called_once()

    @patch("features.lifecycle_manager.routes.SSHManager")
    def test_precheck_real_mode_reports_connection_failure(self, mock_ssh_manager):
        self._routes.write_json(self._routes.SETTINGS_FILE, {
            **self._routes.DEFAULT_SETTINGS,
            "demo_mode": False,
            "ssh": {"username": "keystone", "port": 22, "timeout": 10},
        })
        job_id = self._create_config_push_job()
        mock_ssh_manager.connect.return_value = {"success": False, "error": "connection refused"}

        response = self.client.post(f"/lifecycle/api/jobs/{job_id}/precheck", json={"password": "secret"})
        body = response.get_json()
        self.assertEqual(body["job"]["status"], "precheck_failed")
        self.assertEqual(
            body["job"]["devices"][0]["precheck"]["checks"][0]["message"], "connection refused"
        )

    # ---------------------------------------------------------------
    # start(type=config_push) -- demo-mode end-to-end via the real
    # background worker thread
    # ---------------------------------------------------------------

    @patch("features.lifecycle_manager.core.config_push_engine.time.sleep", return_value=None)
    def test_start_runs_demo_config_push_job_to_completion(self, _mock_sleep):
        job_id = self._create_config_push_job()
        self.client.post(f"/lifecycle/api/jobs/{job_id}/precheck", json={})

        start = self.client.post(f"/lifecycle/api/jobs/{job_id}/start", json={})
        self.assertEqual(start.status_code, 200)

        deadline = time.time() + 5
        job = None
        while time.time() < deadline:
            jobs = self.client.get("/lifecycle/api/jobs").get_json()["jobs"]
            job = next((j for j in jobs if j["id"] == job_id), None)
            if job and job["status"] in ("completed", "failed"):
                break
            time.sleep(0.05)

        self.assertIsNotNone(job)
        self.assertEqual(job["status"], "completed")
        self.assertTrue(all(d["status"] == "completed" for d in job["devices"]))

    def test_start_before_precheck_is_rejected(self):
        job_id = self._create_config_push_job()
        response = self.client.post(f"/lifecycle/api/jobs/{job_id}/start", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Pre-Check", response.get_json()["error"])

    def test_start_real_mode_unsupported_vendor_message_mentions_config_pushes(self):
        self._seed_device(vendor="Cisco", platform="IOS")
        self._routes.write_json(self._routes.SETTINGS_FILE, {
            **self._routes.DEFAULT_SETTINGS,
            "demo_mode": False,
        })
        create = self.client.post("/lifecycle/api/jobs", json={
            "type": "config_push",
            "devices": ["10.50.1.11"],
            "configs": {"10.50.1.11": "sysname edge-sw-01\n"},
        })
        job_id = create.get_json()["job"]["id"]
        # Force the job straight to "ready" so /start's gate is reached
        # without needing a real SSH precheck against a Cisco device.
        database = self._routes.read_json(self._routes.JOBS_FILE, {"jobs": []})
        database["jobs"][0]["status"] = "ready"
        self._routes.write_json(self._routes.JOBS_FILE, database)

        response = self.client.post(f"/lifecycle/api/jobs/{job_id}/start", json={"password": "secret"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("config pushes", response.get_json()["error"])

    # ---------------------------------------------------------------
    # A real-mode job that aborts partway through must still persist
    # the per-line audit trail (regression test for the bug where
    # push_config_lines()'s partial results were discarded on abort --
    # see ConfigPushError in drivers/base_driver.py).
    # ---------------------------------------------------------------

    @patch("features.lifecycle_manager.core.config_push_engine.detect_driver")
    @patch("features.lifecycle_manager.core.config_push_engine.SSHManager")
    def test_aborted_real_job_still_persists_partial_push_results(self, mock_ssh_manager, mock_detect_driver):
        from features.lifecycle_manager.drivers.base_driver import ConfigPushError

        self._routes.write_json(self._routes.SETTINGS_FILE, {
            **self._routes.DEFAULT_SETTINGS,
            "demo_mode": False,
            "ssh": {"username": "keystone", "port": 22, "timeout": 10},
        })
        job_id = self._create_config_push_job(draft="sysname edge-sw-01\nvlan batch 10\nfrobnicate\n")

        # Pre-check goes through routes.py's own SSHManager/detect_driver
        # (patched separately by other tests) -- here it's simplest to
        # just force the job straight to "ready", same as the
        # unsupported-vendor test above does.
        database = self._routes.read_json(self._routes.JOBS_FILE, {"jobs": []})
        database["jobs"][0]["status"] = "ready"
        self._routes.write_json(self._routes.JOBS_FILE, database)

        partial_results = [
            {"line": "sysname edge-sw-01", "status": "success", "output": ""},
            {"line": "vlan batch 10", "status": "success", "output": ""},
            {"line": "frobnicate", "status": "failed", "output": "% Unrecognized command"},
        ]

        fake_connection = MagicMock()
        mock_ssh_manager.connect.return_value = {
            "success": True, "connection": fake_connection, "netmiko_device_type": "huawei",
        }
        fake_driver = MagicMock()
        fake_driver.get_device_info.return_value = {"hostname": "edge-sw-01"}
        fake_driver.backup_config.return_value = {"current_configuration": "sysname edge-sw-01\n"}
        fake_driver.push_config_lines.side_effect = ConfigPushError(
            "device rejected 'frobnicate'", results=partial_results
        )
        mock_detect_driver.return_value = fake_driver

        start = self.client.post(f"/lifecycle/api/jobs/{job_id}/start", json={"password": "secret"})
        self.assertEqual(start.status_code, 200)

        deadline = time.time() + 5
        job = None
        while time.time() < deadline:
            jobs = self.client.get("/lifecycle/api/jobs").get_json()["jobs"]
            job = next((j for j in jobs if j["id"] == job_id), None)
            if job and job["status"] in ("completed", "failed"):
                break
            time.sleep(0.05)

        self.assertIsNotNone(job)
        self.assertEqual(job["status"], "failed")
        device = job["devices"][0]
        self.assertEqual(device["status"], "failed")

        # The actual regression check: the per-line trail up to the
        # rejected line survived all the way through to the persisted
        # job, not just "something failed".
        self.assertIn("config_push_result", device)
        result = device["config_push_result"]
        self.assertTrue(result["aborted"])
        self.assertEqual(result["lines_applied"], 2)
        self.assertEqual(result["results"], partial_results)

    # ------------------------------------------------------------------
    # A different job's Pre-Check must never clobber a currently-running
    # job's persisted state. _precheck_config_push_job()/run_job_precheck()
    # used to take one read_json() snapshot at the top and then call
    # write_json(JOBS_FILE, database) repeatedly across a loop spanning
    # real per-device SSH round trips -- each of those calls overwrote
    # the WHOLE jobs.json with that stale snapshot, silently discarding
    # anything another job's background thread had written via
    # update_json() in the meantime (confirmed empirically: a concurrent
    # writer lost roughly half its entries before the fix). Fixed by
    # routing every persistence point in both Pre-Check functions through
    # _persist_job(), which re-reads fresh and replaces only the one job
    # entry it owns.
    # ------------------------------------------------------------------

    @patch("features.lifecycle_manager.routes.detect_driver")
    @patch("features.lifecycle_manager.routes.SSHManager")
    def test_running_job_survives_a_concurrent_precheck_on_another_job(self, mock_ssh_manager, mock_detect_driver):
        # Job A: simulate it's already running (a real config-push job
        # streaming live command results via update_json(), exactly like
        # execute_config_push_job() does).
        job_a_id = "job-a-running"
        self._routes.write_json(self._routes.JOBS_FILE, {"jobs": [{
            "id": job_a_id, "type": "config_push", "status": "running",
            "devices": [{"ip": "10.50.1.11", "live_command_results": []}],
            "logs": [],
        }]})

        ENTRY_COUNT = 40
        appended_lines = []

        def append_one(n):
            def _apply(database):
                job = next(j for j in database["jobs"] if j["id"] == job_a_id)
                device = job["devices"][0]
                entry = {"line": f"command-{n}", "status": "success", "output": "[OK]"}
                device["live_command_results"].append(entry)
                job["logs"].append({"level": "command-success", "message": f"10.50.1.11 OK $ command-{n}"})
            self._routes.update_json(self._routes.JOBS_FILE, {"jobs": []}, _apply)
            appended_lines.append(n)

        def writer_thread():
            for n in range(ENTRY_COUNT):
                append_one(n)
                time.sleep(0.02)

        # Job B: a normal config-push job, prechecked in REAL mode with a
        # slow mocked driver so the precheck's own wall-clock window
        # (three separate persistence points: before the loop, after
        # this one device, after the whole loop) genuinely overlaps with
        # Job A's background writes above -- this is what actually
        # exercises the bug (a fast precheck wouldn't create any window
        # to race in).
        self._routes.write_json(self._routes.DEVICES_FILE, {"devices": [{
            "ip": "10.50.1.12", "hostname": "edge-sw-02", "vendor": "Huawei", "platform": "VRP",
        }]})
        self._routes.write_json(self._routes.SETTINGS_FILE, {
            **self._routes.DEFAULT_SETTINGS,
            "demo_mode": False,
            "ssh": {"username": "keystone", "port": 22, "timeout": 10},
        })
        create = self.client.post("/lifecycle/api/jobs", json={
            "type": "config_push",
            "devices": ["10.50.1.12"],
            "configs": {"10.50.1.12": "sysname edge-sw-02\n"},
        })
        job_b_id = create.get_json()["job"]["id"]

        fake_connection = MagicMock()
        mock_ssh_manager.connect.return_value = {
            "success": True, "connection": fake_connection, "netmiko_device_type": "huawei",
        }
        fake_driver = MagicMock()

        def slow_get_device_info():
            time.sleep(0.4)
            return {"hostname": "edge-sw-02", "model": "S5735-V2", "version": "V200R022"}

        fake_driver.get_device_info.side_effect = slow_get_device_info
        mock_detect_driver.return_value = fake_driver

        writer = threading.Thread(target=writer_thread)
        writer.start()
        time.sleep(0.05)  # let the writer get going before precheck starts racing it

        precheck_response = self.client.post(
            f"/lifecycle/api/jobs/{job_b_id}/precheck", json={"password": "secret"}
        )
        writer.join()

        self.assertEqual(precheck_response.status_code, 200)
        self.assertEqual(precheck_response.get_json()["job"]["status"], "ready")

        final = self._routes.read_json(self._routes.JOBS_FILE, {"jobs": []})
        job_a_final = next(j for j in final["jobs"] if j["id"] == job_a_id)
        job_b_final = next(j for j in final["jobs"] if j["id"] == job_b_id)

        self.assertEqual(len(appended_lines), ENTRY_COUNT)
        surviving = {r["line"] for r in job_a_final["devices"][0]["live_command_results"]}
        expected = {f"command-{n}" for n in range(ENTRY_COUNT)}
        missing = expected - surviving
        self.assertEqual(
            missing, set(),
            f"Job A lost {len(missing)}/{ENTRY_COUNT} live command results to a "
            f"concurrent Pre-Check on Job B: {sorted(missing)}",
        )
        self.assertEqual(len(job_a_final["logs"]), ENTRY_COUNT)

        # And Job B itself (the one being prechecked) must have gone
        # through all three of its own persistence points correctly too.
        self.assertEqual(job_b_final["status"], "ready")
        self.assertEqual(job_b_final["devices"][0]["status"], "ready")

        print(f"OK: Job A kept all {ENTRY_COUNT}/{ENTRY_COUNT} live command results "
              f"and log lines through a concurrent Pre-Check on Job B")


    # ------------------------------------------------------------------
    # Live per-command streaming: push_config_lines()'s on_result callback
    # (base_driver.py / vrp.py) must reach jobs.json the moment EACH line
    # succeeds or fails, not only once the whole draft finishes -- this is
    # what a live "which commands landed" view depends on.
    # ------------------------------------------------------------------

    @patch("features.lifecycle_manager.core.config_push_engine.detect_driver")
    @patch("features.lifecycle_manager.core.config_push_engine.SSHManager")
    def test_live_command_results_persist_incrementally_and_color_the_log(self, mock_ssh_manager, mock_detect_driver):
        self._seed_device()
        self._routes.write_json(self._routes.SETTINGS_FILE, {
            **self._routes.DEFAULT_SETTINGS,
            "demo_mode": False,
            "ssh": {"username": "keystone", "port": 22, "timeout": 10},
        })
        job_id = self._create_config_push_job(draft="sysname edge-sw-01\nvlan batch 10\n")
        database = self._routes.read_json(self._routes.JOBS_FILE, {"jobs": []})
        database["jobs"][0]["status"] = "ready"
        self._routes.write_json(self._routes.JOBS_FILE, database)

        fake_connection = MagicMock()
        mock_ssh_manager.connect.return_value = {
            "success": True, "connection": fake_connection, "netmiko_device_type": "huawei",
        }

        def fake_push_config_lines(lines, on_result=None):
            results = []
            for line in lines:
                result = {"line": line, "status": "success", "output": "[OK]"}
                results.append(result)
                if on_result:
                    on_result(result)
            return results

        fake_driver = MagicMock()
        fake_driver.get_device_info.return_value = {"hostname": "edge-sw-01"}
        fake_driver.backup_config.return_value = {"current_configuration": "sysname edge-sw-01\n"}
        fake_driver.push_config_lines.side_effect = fake_push_config_lines
        mock_detect_driver.return_value = fake_driver

        start = self.client.post(f"/lifecycle/api/jobs/{job_id}/start", json={"password": "secret"})
        self.assertEqual(start.status_code, 200)

        deadline = time.time() + 5
        job = None
        while time.time() < deadline:
            jobs = self.client.get("/lifecycle/api/jobs").get_json()["jobs"]
            job = next((j for j in jobs if j["id"] == job_id), None)
            if job and job["status"] in ("completed", "failed"):
                break
            time.sleep(0.05)

        self.assertIsNotNone(job)
        self.assertEqual(job["status"], "completed")
        device = job["devices"][0]

        self.assertEqual(device.get("live_command_results"), [
            {"line": "sysname edge-sw-01", "status": "success", "output": "[OK]"},
            {"line": "vlan batch 10", "status": "success", "output": "[OK]"},
        ])

        log_levels_and_messages = [(log["level"], log["message"]) for log in job["logs"]]
        self.assertIn(
            ("command-success", "10.50.1.11 OK $ sysname edge-sw-01"), log_levels_and_messages,
        )
        self.assertIn(
            ("command-success", "10.50.1.11 OK $ vlan batch 10"), log_levels_and_messages,
        )
        # The final lump result (device["config_push_result"]) must still
        # be correct alongside the new live stream, not replaced by it.
        self.assertEqual(device["config_push_result"]["lines_applied"], 2)

    # ------------------------------------------------------------------
    # SSE job stream (/api/jobs/<id>/stream): must carry live command
    # results and log lines as they happen, and terminate cleanly once
    # the job reaches a terminal state.
    # ------------------------------------------------------------------

    def test_stream_unknown_job_returns_error_event(self):
        resp = self.client.get("/lifecycle/api/jobs/does-not-exist/stream")
        body = resp.get_data(as_text=True)
        self.assertIn("event: error", body)
        self.assertIn("Job not found", body)

    @patch("features.lifecycle_manager.core.config_push_engine.detect_driver")
    @patch("features.lifecycle_manager.core.config_push_engine.SSHManager")
    def test_stream_carries_command_results_and_terminates_on_completion(self, mock_ssh_manager, mock_detect_driver):
        self._seed_device()
        self._routes.write_json(self._routes.SETTINGS_FILE, {
            **self._routes.DEFAULT_SETTINGS,
            "demo_mode": False,
            "ssh": {"username": "keystone", "port": 22, "timeout": 10},
        })
        job_id = self._create_config_push_job(draft="sysname edge-sw-01\nvlan batch 10\n")
        database = self._routes.read_json(self._routes.JOBS_FILE, {"jobs": []})
        database["jobs"][0]["status"] = "ready"
        self._routes.write_json(self._routes.JOBS_FILE, database)

        fake_connection = MagicMock()
        mock_ssh_manager.connect.return_value = {
            "success": True, "connection": fake_connection, "netmiko_device_type": "huawei",
        }

        def fake_push_config_lines(lines, on_result=None):
            results = []
            for line in lines:
                # A tiny real delay so the stream's 0.5s poll loop has to
                # observe more than a single already-finished snapshot --
                # this is the difference between testing "the endpoint
                # returns the right JSON" and testing "it actually waits
                # on a job that's still in progress".
                time.sleep(0.3)
                result = {"line": line, "status": "success", "output": "[OK]"}
                results.append(result)
                if on_result:
                    on_result(result)
            return results

        fake_driver = MagicMock()
        fake_driver.get_device_info.return_value = {"hostname": "edge-sw-01"}
        fake_driver.backup_config.return_value = {"current_configuration": "sysname edge-sw-01\n"}
        fake_driver.push_config_lines.side_effect = fake_push_config_lines
        mock_detect_driver.return_value = fake_driver

        start = self.client.post(f"/lifecycle/api/jobs/{job_id}/start", json={"password": "secret"})
        self.assertEqual(start.status_code, 200)

        stream_start = time.time()
        resp = self.client.get(f"/lifecycle/api/jobs/{job_id}/stream")
        body = resp.get_data(as_text=True)
        elapsed = time.time() - stream_start

        self.assertGreater(
            elapsed, 0.3,
            "the stream body was assembled too fast to have actually polled a job "
            "still in progress -- it should have blocked across at least one tick",
        )
        self.assertIn("event: command_result", body)
        self.assertIn('"line": "sysname edge-sw-01"', body)
        self.assertIn('"line": "vlan batch 10"', body)
        self.assertIn("event: status", body)
        self.assertIn('"status": "completed"', body)
        self.assertIn("event: done", body)

    @unittest.skipUnless(os.path.exists("/proc/net/tcp"), "needs /proc/net/tcp to inspect socket state")
    def test_stream_heartbeats_when_idle_so_a_dead_client_is_detected_promptly(self):
        """A job that's "running" with nothing new to report (no new log
        lines, no new command results, no status change) must still make
        stream_job()'s generator perform a real socket write on every
        poll tick -- otherwise a client that vanished (closed tab, lost
        network) is never noticed: Werkzeug only discovers a gone client
        when a write to its socket fails, and a generator that goes
        multiple ticks without yielding anything never attempts that
        write. Unnoticed, the connection sits in CLOSE_WAIT and the
        request-handling thread behind it never exits -- for as long as
        the job stays "running", which can be indefinitely if the
        underlying device push itself hangs.

        This can only be observed with a REAL socket (the Flask test
        client used by every other test in this file never opens one),
        so it starts the real app on a real port in a background thread,
        opens a raw TCP connection to /stream, reads enough to prove the
        stream is genuinely live, then yanks the connection (FIN, no
        clean HTTP-level close -- exactly what a browser tab closing or
        a dropped network does) and checks the server's own view of that
        connection via /proc/net/tcp.
        """
        self._seed_device()
        database = self._routes.read_json(self._routes.JOBS_FILE, {"jobs": []})
        job_id = "idle-running-job"
        database["jobs"].append({
            "id": job_id,
            "type": "config_push",
            "status": "running",
            "logs": [],
            "devices": [{"ip": "10.50.1.11", "status": "running", "live_command_results": []}],
        })
        self._routes.write_json(self._routes.JOBS_FILE, database)

        import app as nes_app
        server_app = nes_app.create_app()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        server_thread = threading.Thread(
            target=lambda: server_app.run(host="127.0.0.1", port=port, threaded=True, use_reloader=False),
            daemon=True,
        )
        server_thread.start()
        self.addCleanup(server_thread.join, timeout=0.1)

        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            self.fail("test server never came up")

        def state_of(local_port):
            target = f"{local_port:04X}"
            with open("/proc/net/tcp") as f:
                next(f)
                for line in f:
                    fields = line.split()
                    if fields[1].split(":")[1] == f"{port:04X}" and fields[2].split(":")[1] == target:
                        return fields[3]
            return None

        client_sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        client_local_port = client_sock.getsockname()[1]
        client_sock.sendall(
            f"GET /lifecycle/api/jobs/{job_id}/stream HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n".encode()
        )
        buf = b""
        client_sock.settimeout(5)
        while b"\r\n\r\n" not in buf:
            buf += client_sock.recv(4096)
        # One more read: with the heartbeat fix this is either a real
        # event or a ": keep-alive" comment line -- either way, proof
        # the stream is genuinely live before we yank the connection.
        client_sock.settimeout(2)
        try:
            buf += client_sock.recv(4096)
        except socket.timeout:
            pass
        self.assertGreater(len(buf), 0, "stream produced no data at all before disconnect")

        # Simulate the client vanishing -- not a clean close() from the
        # app's perspective, just gone.
        client_sock.shutdown(socket.SHUT_RDWR)
        client_sock.close()

        deadline = time.time() + 5.0
        cleared = False
        while time.time() < deadline:
            if state_of(client_local_port) is None:
                cleared = True
                break
            time.sleep(0.1)

        self.assertTrue(
            cleared,
            "the connection never cleared from the server's side within 5s of the "
            "client disconnecting -- stream_job()'s generator went idle without a "
            "heartbeat, so it never attempted the write that would have revealed "
            "the client is gone",
        )


if __name__ == "__main__":
    unittest.main()
