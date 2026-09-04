"""End-to-end tests for POST /lifecycle/api/devices/check-reachability --
a fast, credential-free TCP/SSH-port liveness probe an operator can run
against already-discovered devices, independent of a full Discovery
re-scan (which requires credentials and does a full login + inventory
pull). Exists because Discovery's "online" status is a snapshot with no
timestamp, so there is no way to tell how stale it is from the device
list alone.
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class DeviceReachabilityRoutesTests(unittest.TestCase):
    def setUp(self):
        self._scratch = Path(tempfile.mkdtemp())

        import features.lifecycle_manager.routes as routes
        self._routes = routes
        self._orig = {
            "SETTINGS_FILE": routes.SETTINGS_FILE,
            "DEVICES_FILE": routes.DEVICES_FILE,
        }
        routes.SETTINGS_FILE = self._scratch / "settings.json"
        routes.DEVICES_FILE = self._scratch / "devices.json"

        import app as nes_app
        self.client = nes_app.create_app().test_client()

    def tearDown(self):
        for key, value in self._orig.items():
            setattr(self._routes, key, value)
        shutil.rmtree(self._scratch, ignore_errors=True)

    def _seed_devices(self, devices):
        self._routes.write_json(self._routes.DEVICES_FILE, {"devices": devices})

    def _device(self, ip, **overrides):
        device = {
            "ip": ip,
            "hostname": f"sw-{ip.split('.')[-1]}",
            "vendor": "Huawei",
            "platform": "VRP",
            "model": "S5735-V2",
            "version": "V200R022",
            "status": "online",
        }
        device.update(overrides)
        return device

    @patch("features.lifecycle_manager.routes.check_ssh_port")
    def test_checks_every_known_device_when_no_ips_given(self, mock_check_port):
        self._seed_devices([self._device("10.50.1.11"), self._device("10.50.1.12")])
        mock_check_port.side_effect = lambda ip, port=22, timeout=1.5: ip == "10.50.1.11"

        response = self.client.post("/lifecycle/api/devices/check-reachability", json={})
        self.assertEqual(response.status_code, 200)
        body = response.get_json()

        self.assertEqual(body["results"], {"10.50.1.11": True, "10.50.1.12": False})
        self.assertIsNotNone(body["checked_at"])

        devices_by_ip = {d["ip"]: d for d in body["devices"]}
        self.assertTrue(devices_by_ip["10.50.1.11"]["reachable"])
        self.assertFalse(devices_by_ip["10.50.1.12"]["reachable"])
        self.assertEqual(
            devices_by_ip["10.50.1.11"]["reachability_checked_at"],
            devices_by_ip["10.50.1.12"]["reachability_checked_at"],
        )

        # Persisted to disk too, not just in the response.
        on_disk = self._routes.read_json(self._routes.DEVICES_FILE, {"devices": []})
        self.assertTrue(any(d["ip"] == "10.50.1.11" and d["reachable"] for d in on_disk["devices"]))

    @patch("features.lifecycle_manager.routes.check_ssh_port")
    def test_scoped_to_requested_ips_leaves_others_untouched(self, mock_check_port):
        self._seed_devices([self._device("10.50.1.11"), self._device("10.50.1.12")])
        mock_check_port.return_value = True

        response = self.client.post(
            "/lifecycle/api/devices/check-reachability",
            json={"ips": ["10.50.1.11"]},
        )
        self.assertEqual(response.status_code, 200)
        mock_check_port.assert_called_once()

        devices_by_ip = {d["ip"]: d for d in response.get_json()["devices"]}
        self.assertIn("reachable", devices_by_ip["10.50.1.11"])
        self.assertNotIn("reachable", devices_by_ip["10.50.1.12"])

    def test_unknown_ips_return_400(self):
        self._seed_devices([self._device("10.50.1.11")])
        response = self.client.post(
            "/lifecycle/api/devices/check-reachability",
            json={"ips": ["10.99.9.9"]},
        )
        self.assertEqual(response.status_code, 400)

    def test_no_devices_at_all_returns_400(self):
        response = self.client.post("/lifecycle/api/devices/check-reachability", json={})
        self.assertEqual(response.status_code, 400)

    @patch("features.lifecycle_manager.routes.check_ssh_port")
    def test_does_not_mutate_other_device_fields(self, mock_check_port):
        self._seed_devices([self._device("10.50.1.11", hostname="edge-sw-01", model="S5735-V2")])
        mock_check_port.return_value = True

        response = self.client.post("/lifecycle/api/devices/check-reachability", json={})
        device = response.get_json()["devices"][0]
        self.assertEqual(device["hostname"], "edge-sw-01")
        self.assertEqual(device["model"], "S5735-V2")

    @patch("features.lifecycle_manager.routes.check_ssh_port")
    def test_uses_ssh_port_from_settings(self, mock_check_port):
        self._seed_devices([self._device("10.50.1.11")])
        self._routes.write_json(self._routes.SETTINGS_FILE, {
            **self._routes.DEFAULT_SETTINGS,
            "ssh": {"username": "staging", "port": 2222, "timeout": 10},
        })
        mock_check_port.return_value = True

        self.client.post("/lifecycle/api/devices/check-reachability", json={})

        _, kwargs = mock_check_port.call_args
        # check_ssh_port(ip, port=..., timeout=...) -- called positionally
        # or by keyword depending on the probe closure; assert whichever
        # actually carried the port through.
        called_port = kwargs.get("port") if "port" in kwargs else mock_check_port.call_args[0][1]
        self.assertEqual(called_port, 2222)


if __name__ == "__main__":
    unittest.main()
