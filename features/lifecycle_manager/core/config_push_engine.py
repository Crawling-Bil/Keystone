import time
from datetime import datetime
from pathlib import Path

from .device_detector import detect_driver
from .ssh_manager import SSHManager
from ..drivers.base_driver import ConfigPushError


class ConfigPushEngine:
    """Pushes an operator-prepared draft config to devices Keystone
    already knows about (discovered, provisioned, or not -- doesn't
    matter which), over SSH, line by line.

    Deliberately separate from UpgradeEngine even though the SSH/driver
    plumbing is shared (SSHManager, detect_driver, the same per-device
    backup convention): a config push has no firmware to transfer, no
    reboot, and no reconnect-wait -- collapsing it into UpgradeEngine's
    much longer pipeline would mean threading a bunch of
    firmware-specific steps through with is_config_push flags rather
    than just writing the (much shorter) sequence this operation
    actually needs.
    """

    DEMO_STAGES = [
        ("Backing Up Current Configuration", 30),
        ("Pushing Draft Configuration", 55),
        ("Saving Configuration", 80),
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
        # Config pushes are naturally more independent of each other
        # than a firmware upgrade batch (no shared local file server
        # to worry about), but still hard-cap concurrency the same
        # way UpgradeEngine does, for the same reason: don't let one
        # job hammer a whole subnet with simultaneous SSH sessions.
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
            raise RuntimeError("SSH username and password are required for a real config push.")

        from concurrent.futures import ThreadPoolExecutor, as_completed

        max_workers = max(1, min(self.max_parallel, len(devices), 10))
        if max_workers <= 1:
            for device in devices:
                self._push_device_safely(device, update_callback)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(self._push_device_safely, device, update_callback)
                    for device in devices
                ]
                for future in as_completed(futures):
                    future.result()

    def _push_device_safely(self, device, update_callback):
        try:
            self._push_huawei_device(device, update_callback)
        except Exception as exc:
            # Same reasoning as UpgradeEngine._run_device_safely(): one
            # device's config being rejected must not stop the rest of
            # a multi-device batch from being attempted.
            update_callback(device, f"ERROR: {exc}", None, "command")
            short_reason = str(exc).strip().splitlines()[0][:160]
            update_callback(
                device,
                f"Config Push Failed: {short_reason}" if short_reason else "Config Push Failed",
                device.get("progress") or 0,
                "failed",
            )

    def _push_huawei_device(self, device, update_callback):
        vendor = str(device.get("vendor") or device.get("live_vendor") or "").lower()
        platform = str(device.get("platform") or device.get("live_platform") or "").lower()
        if "huawei" not in vendor and "vrp" not in platform:
            raise RuntimeError(f"Real config push currently supports Huawei VRP only: {device.get('ip')}")

        draft_text = device.get("draft_config") or ""
        lines = draft_text.splitlines()
        non_empty_lines = [ln for ln in lines if ln.strip() and not ln.strip().startswith("#")]
        if not non_empty_lines:
            raise RuntimeError("Draft config is empty (no command lines after stripping blank/comment lines).")

        update_callback(device, "Connecting to Huawei VRP", 15, "running")
        result = SSHManager.connect(
            device.get("ip"), self.username, self.password,
            port=self.port, timeout=self.timeout, preferred_device_type="huawei"
        )
        if not result.get("success"):
            raise RuntimeError(f"{device.get('ip')}: {result.get('error')}")
        connection = result["connection"]

        def log_command(command):
            update_callback(device, command, None, "command")

        def log_command_result(result):
            # Fired the moment EACH pushed line's success/failure is
            # known (push_config_lines' on_result), not only once the
            # whole draft finishes -- this is what lets the job's
            # live view show which commands actually landed as the
            # push happens, instead of a single lump revealed at the
            # very end via device["config_push_result"] below.
            update_callback(device, result, None, "command_result")

        driver = detect_driver(connection, result["netmiko_device_type"], log_command)

        try:
            info = driver.get_device_info()
            hostname = info.get("hostname") or device.get("hostname") or device.get("ip")
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / self._safe(hostname) / f"config_push_{stamp}"
            backup_path.mkdir(parents=True, exist_ok=True)

            update_callback(device, "Backing Up Current Configuration", 30, "running")
            before = driver.backup_config()
            (backup_path / "before.txt").write_text(
                str(before.get("current_configuration", "")), encoding="utf-8"
            )

            update_callback(device, f"Pushing Draft Configuration ({len(non_empty_lines)} line(s))", 55, "running")
            try:
                push_results = driver.push_config_lines(lines, on_result=log_command_result)
            except ConfigPushError as exc:
                # The push aborted partway through -- exc.results is
                # everything that was sent before (and including) the
                # line that failed. Stamp that onto the device now, in
                # the same shape a full success would have used (plus
                # "aborted": True), so the operator still sees exactly
                # which lines got pushed instead of just a generic
                # failure message. Without this, the audit trail
                # collected right up until the failure would otherwise
                # be thrown away along with the exception.
                device["config_push_result"] = {
                    "lines_total": len(non_empty_lines),
                    "lines_applied": sum(1 for r in exc.results if r.get("status") == "success"),
                    "results": exc.results,
                    "backup_dir": str(backup_path),
                    "aborted": True,
                }
                raise
            device["config_push_result"] = {
                "lines_total": len(non_empty_lines),
                "lines_applied": sum(1 for r in push_results if r.get("status") == "success"),
                "results": push_results,
                "backup_dir": str(backup_path),
            }

            update_callback(device, "Saving Configuration", 80, "running")
            driver.save_config()

            update_callback(device, "Verifying Applied Configuration", 90, "running")
            after = driver.backup_config()
            (backup_path / "after.txt").write_text(
                str(after.get("current_configuration", "")), encoding="utf-8"
            )
        finally:
            try:
                driver.disconnect()
            except Exception:
                pass

        update_callback(device, "Config Push Completed", 100, "completed")

    @staticmethod
    def _safe(value):
        return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(value))

    @staticmethod
    def log_entry(message, level="info"):
        return {"timestamp": datetime.now().isoformat(), "level": level, "message": message}
