import time
from datetime import datetime
from pathlib import Path

from .device_detector import detect_driver
from .ssh_manager import SSHManager


# The fixed set of read-only `display` commands a Config Capture job
# runs against a device, in this exact order. Order matters: the very
# first entry disables pagination for the rest of the SSH session, so
# later commands with long output (the full running-config, license
# verbose, a big MAC table) don't get interrupted by a `---- More
# ----` prompt netmiko never sees. This is an operator-curated list
# (not auto-generated), meant to capture everything worth having in an
# audit/backup snapshot of an already-configured Huawei VRP switch --
# hardware identity, full config, L2/L3 state, LLDP/LACP/STP,
# PoE, stack, licensing, ACLs, and the MAC table.
CONFIG_CAPTURE_COMMANDS = [
    "screen-length 0 temporary",
    "display clock",
    "display version",
    "display current-configuration",
    "display device elabel brief",
    "display device elabel",
    "display vlan summary",
    "display vlan",
    "display interface transceiver",
    "display interface description",
    "display interface brief",
    "display port vlan",
    "display ip interface brief",
    "display arp statistics",
    "display arp",
    "display eth-trunk",
    "display lldp neighbor brief",
    "display lldp neighbor",
    "display lacp brief",
    "display poe-power",
    "display poe device",
    "display poe information",
    "display stp",
    "display stp brief",
    "display stp region-configuration",
    "display device",
    "display device power",
    "display device fan",
    "display stack",
    "display stack configuration",
    "display stack topology",
    "display stack port auto-cable-info",
    "display dual-active",
    "display current-configuration | include route",
    "display current-configuration | include route ignore-case",
    "display current-configuration configuration route-static",
    "display current-configuration configuration route-policy",
    "display ip routing-table",
    "display license",
    "display license resource usage",
    "display license resource usage detail",
    "display license verbose",
    "display acl all",
    "display mac-address",
]


class ConfigCaptureEngine:
    """Pulls a point-in-time snapshot of a device's running state --
    CONFIG_CAPTURE_COMMANDS, run over one SSH session -- and saves it
    as a single backup bundle on disk.

    Deliberately separate from ConfigPushEngine even though the
    SSH/driver plumbing is shared: a capture never mutates the device
    (no system-view, no save, no reboot), never needs a Pre-Check
    stage (there's nothing risky to validate ahead of time -- a job is
    created straight into "ready"), and produces a very different
    artifact (one combined backup file, not a per-line push audit
    trail).
    """

    DEMO_STAGES = [
        ("Connecting (Demo)", 20),
        ("Running Capture Commands (Demo)", 60),
        ("Saving Backup Bundle (Demo)", 85),
        ("Completed", 100),
    ]

    def __init__(self, demo_mode=True, stage_delay=2, username="", password="",
                 port=22, timeout=10, backup_dir=None, max_parallel=1):
        self.demo_mode = bool(demo_mode)
        self.stage_delay = max(float(stage_delay), 0)
        self.username = username
        self.password = password
        self.port = int(port)
        self.timeout = int(timeout)
        self.backup_dir = Path(backup_dir or "backups")
        # Same reasoning as ConfigPushEngine/UpgradeEngine: hard-cap
        # concurrency so one capture job doesn't open a simultaneous
        # SSH session to every device on the subnet at once.
        self.max_parallel = max(1, int(max_parallel or 1))

    def run_job(self, devices, update_callback):
        if self.demo_mode:
            for stage, progress in self.DEMO_STAGES:
                if self.stage_delay:
                    time.sleep(self.stage_delay)
                for device in devices:
                    update_callback(device, stage, progress, "completed" if progress == 100 else "running")
            return

        if not self.username or not self.password:
            raise RuntimeError("SSH username and password are required for a real config capture.")

        from concurrent.futures import ThreadPoolExecutor, as_completed

        max_workers = max(1, min(self.max_parallel, len(devices), 10))
        if max_workers <= 1:
            for device in devices:
                self._capture_device_safely(device, update_callback)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(self._capture_device_safely, device, update_callback)
                    for device in devices
                ]
                for future in as_completed(futures):
                    future.result()

    def _capture_device_safely(self, device, update_callback):
        try:
            self._capture_huawei_device(device, update_callback)
        except Exception as exc:
            # One device's capture failing (bad credentials, dropped
            # connection, unreachable) must not stop the rest of a
            # multi-device batch from being attempted.
            update_callback(device, f"ERROR: {exc}", None, "command")
            short_reason = str(exc).strip().splitlines()[0][:160]
            update_callback(
                device,
                f"Config Capture Failed: {short_reason}" if short_reason else "Config Capture Failed",
                device.get("progress") or 0,
                "failed",
            )

    def _capture_huawei_device(self, device, update_callback):
        vendor = str(device.get("vendor") or device.get("live_vendor") or "").lower()
        platform = str(device.get("platform") or device.get("live_platform") or "").lower()
        if "huawei" not in vendor and "vrp" not in platform:
            raise RuntimeError(f"Real config capture currently supports Huawei VRP only: {device.get('ip')}")

        update_callback(device, "Connecting to Huawei VRP", 10, "running")
        result = SSHManager.connect(
            device.get("ip"), self.username, self.password,
            port=self.port, timeout=self.timeout, preferred_device_type="huawei"
        )
        if not result.get("success"):
            raise RuntimeError(f"{device.get('ip')}: {result.get('error')}")
        connection = result["connection"]

        def log_command(command):
            update_callback(device, command, None, "command")

        def log_command_result(item):
            # Fired the moment EACH command's output is known (see
            # capture_config()'s on_result) -- reuses the exact
            # {"line", "status", "output"} shape push_config_lines()
            # streams, so the same live-command UI renders a capture
            # job's progress command-by-command with no changes.
            update_callback(device, item, None, "command_result")

        driver = detect_driver(connection, result["netmiko_device_type"], log_command)

        try:
            info = driver.get_device_info()
            hostname = info.get("hostname") or device.get("hostname") or device.get("ip")
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / self._safe(hostname) / f"config_capture_{stamp}"
            backup_path.mkdir(parents=True, exist_ok=True)

            update_callback(
                device,
                f"Running {len(CONFIG_CAPTURE_COMMANDS)} Capture Commands",
                40,
                "running",
            )
            capture_results = driver.capture_config(CONFIG_CAPTURE_COMMANDS, on_result=log_command_result)

            update_callback(device, "Saving Backup Bundle", 85, "running")
            bundle_text = self._render_bundle(hostname, device.get("ip"), capture_results)
            bundle_path = backup_path / "capture.txt"
            bundle_path.write_text(bundle_text, encoding="utf-8")

            failed_count = sum(1 for item in capture_results if item.get("status") != "success")
            device["capture_bundle"] = {
                "path": str(bundle_path),
                "captured_at": datetime.now().isoformat(),
                "command_count": len(capture_results),
                "failed_count": failed_count,
            }
        finally:
            try:
                driver.disconnect()
            except Exception:
                pass

        update_callback(device, "Config Capture Completed", 100, "completed")

    @staticmethod
    def _render_bundle(hostname, ip_address, results):
        # Plain-text "show tech"-style bundle: every command as its
        # own clearly-delimited section, in the order it was run --
        # readable standalone (opened in a text editor, pasted into a
        # ticket) without needing Keystone's own UI to make sense of it.
        header = (
            f"Config Capture Backup\n"
            f"Device : {hostname} ({ip_address})\n"
            f"Captured At : {datetime.now().isoformat()}\n"
            f"{'=' * 70}\n\n"
        )
        sections = []
        for item in results:
            command = item.get("line", "")
            status = item.get("status", "unknown")
            output = item.get("output", "")
            sections.append(
                f"$ {command}\n"
                f"[{status.upper()}]\n"
                f"{'-' * 70}\n"
                f"{output}\n"
            )
        return header + "\n".join(sections)

    @staticmethod
    def _safe(value):
        return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(value))

    @staticmethod
    def log_entry(message, level="info"):
        return {"timestamp": datetime.now().isoformat(), "level": level, "message": message}
