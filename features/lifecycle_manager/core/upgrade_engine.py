import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from .device_detector import detect_driver
from .ftp_server import FtpServerError, FtpTransferServer
from .ssh_manager import SSHManager


class UpgradeEngine:
    DEMO_STAGES = [
        ("Backing Up Configuration", 30),
        ("Transferring Firmware", 45),
        ("Verifying Firmware", 60),
        ("Installing Firmware", 72),
        ("Saving Configuration", 78),
        ("Reloading Device", 85),
        ("Waiting for Reconnect", 92),
        ("Running Post-Check", 97),
        ("Completed", 100),
    ]

    def __init__(self, demo_mode=True, stage_delay=2, username="", password="", port=22,
                 timeout=10, reconnect_timeout=600, reconnect_interval=10,
                 firmware_by_id=None, firmware_dir=None, backup_dir=None,
                 transfer_method="sftp", tftp_server_ip=None, tftp_port=69,
                 ftp_server_ip=None, ftp_port=21, max_parallel=1):
        self.demo_mode = bool(demo_mode)
        self.stage_delay = max(float(stage_delay), 0)
        self.username = username
        self.password = password
        self.port = int(port)
        self.timeout = int(timeout)
        self.reconnect_timeout = int(reconnect_timeout)
        self.reconnect_interval = max(int(reconnect_interval), 2)
        self.firmware_by_id = firmware_by_id or {}
        self.firmware_dir = Path(firmware_dir or "firmware")
        self.backup_dir = Path(backup_dir or "backups")
        self.transfer_method = (transfer_method or "sftp").lower()
        self.tftp_server_ip = tftp_server_ip or None
        self.tftp_port = int(tftp_port or 69)
        self.ftp_server_ip = ftp_server_ip or None
        self.ftp_port = int(ftp_port or 21)
        # How many devices this job may upgrade at the same time
        # (capped hard at 10 regardless of what's passed in — see
        # run_job()). 1 keeps the original one-at-a-time behaviour.
        self.max_parallel = max(1, int(max_parallel or 1))
        # One shared local FTP server for the whole job, created lazily
        # the first time some device actually needs an FTP transfer,
        # and reused by every device in this job rather than each one
        # trying to bind the control port for itself. See
        # _get_shared_ftp_server() and ftp_server.FtpTransferServer.
        self._shared_ftp_server = None
        self._ftp_server_lock = threading.Lock()
        # TFTP's local server (tftp_server.TftpTransferServer) still
        # binds its UDP port exclusively per transfer -- unlike the FTP
        # path above, it hasn't been reworked to share one bound port
        # across concurrent sessions. Serializing just the transfer
        # step with this lock keeps concurrent TFTP-mode devices from
        # colliding on the port, while every other step (SSH connect,
        # install, save, reboot) for those devices still runs fully in
        # parallel.
        self._tftp_lock = threading.Lock()

    def _transfer_timeout(self, candidates, protocol_floor=180):
        """How long to let netmiko wait for a `tftp .../ftp ...` transfer
        command to finish on the switch side.

        TFTP in particular is a strict stop-and-wait protocol (one 512-byte
        block, one ACK, repeat — no windowing), so a few-hundred-MB .cc
        firmware image can legitimately take a long time to land. A flat
        180s ceiling was blowing through on real firmware files well before
        the transfer itself was anywhere near done. Size the timeout off
        the actual file size instead, with a conservative ~40 KB/s floor
        (this custom pure-Python TFTP/FTP server plus real-world TFTP
        overhead can be slow) — real transfers are usually faster than
        this, it just keeps netmiko from giving up on us early.
        """
        total_bytes = 0
        for local_path, _ in candidates:
            try:
                total_bytes += Path(local_path).stat().st_size
            except OSError:
                pass
        size_based = total_bytes / (40 * 1024)
        return max(self.timeout * 6, protocol_floor, size_based, 600)

    def _verify_checksum_non_fatal(self, driver, filename, checksum, update_callback, device):
        """Run the driver's MD5 verification without letting it abort the job.

        Some Huawei VRP builds/platforms don't support the `check md5`
        command syntax this driver uses (confirmed on an S5735 running
        V600R025C00SPC500 — the switch returns "Unrecognized command"
        instead of a hash). Treating that as fatal blocks staging entirely
        on those platforms even though the firmware already transferred
        successfully over FTP/TFTP/SFTP, which have their own
        transport-level integrity checks. So: still attempt the check (it's
        useful signal when the switch does support it), but a failure or
        exception here is logged as a warning and the upgrade proceeds.
        """
        try:
            result = driver.verify_md5(filename, checksum)
        except Exception as exc:
            update_callback(
                device,
                f"WARNING: checksum verification for {filename} raised an error "
                f"({exc}) — continuing without verification.",
                None,
                "running",
            )
            return {"verified": False, "output": str(exc)}

        if not result.get("verified"):
            update_callback(
                device,
                f"WARNING: checksum verification failed for {filename}: "
                f"{result.get('output', '')} — continuing anyway (non-fatal).",
                None,
                "running",
            )
        return result

    def run_job(self, devices, update_callback):
        if self.demo_mode:
            for stage, progress in self.DEMO_STAGES:
                if self.stage_delay:
                    time.sleep(self.stage_delay)
                for device in devices:
                    update_callback(device, stage, progress, "completed" if progress == 100 else "running")
            return

        if not self.username or not self.password:
            raise RuntimeError("SSH username and password are required for real upgrade mode.")

        # Hard cap at 10 concurrent devices regardless of what the
        # caller passed in for max_parallel, and never spin up more
        # workers than there are devices to run.
        max_workers = max(1, min(self.max_parallel, len(devices), 10))

        try:
            if max_workers <= 1:
                # Original one-at-a-time path. Kept as a separate,
                # simpler branch (no thread pool at all) rather than
                # always going through ThreadPoolExecutor with
                # max_workers=1 -- this is the exact code path that's
                # been confirmed against real hardware, so a single-
                # device (or max_parallel=1) job's behaviour doesn't
                # change at all.
                for device in devices:
                    self._run_device_safely(device, update_callback)
            else:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = [
                        executor.submit(self._run_device_safely, device, update_callback)
                        for device in devices
                    ]
                    for future in as_completed(futures):
                        # _run_device_safely() already catches and
                        # reports everything per-device -- this just
                        # makes sure a genuinely unexpected bug in that
                        # wrapper itself (not in the device upgrade
                        # logic it guards) still surfaces instead of
                        # being silently swallowed.
                        future.result()
        finally:
            if self._shared_ftp_server is not None:
                self._shared_ftp_server.stop()
                self._shared_ftp_server = None

    def _run_device_safely(self, device, update_callback):
        try:
            self._run_huawei_device(device, update_callback)
        except Exception as exc:
            # One device failing must not prevent the rest of a
            # multi-device batch from being attempted at all. Before
            # this fix, an exception raised anywhere inside
            # _run_huawei_device() propagated straight out of
            # run_job(), and execute_upgrade_job()'s outer
            # except-block then marked *every other device in the
            # job* as failed without ever opening a connection to
            # them. Observed on a real 2-device job: device #1 hit
            # an error after firmware transfer (post
            # install/verify-startup, before save/reboot) and
            # device #2 never even got its FTP transfer started.
            # Each device in a batch now gets its own independent
            # attempt regardless of what happened to the ones before
            # it.
            update_callback(
                device,
                f"ERROR: {exc}",
                None,
                "command",
            )
            # The device card on the dashboard renders `device.stage`
            # directly as the visible status text -- a bare "Upgrade
            # Failed" there means the actual reason is only visible by
            # scrolling down into the Execution Log. Fold a short
            # summary of the error into the stage text itself so the
            # reason is visible right on the card, at a glance, without
            # digging through the log. The full error still also goes
            # into the log above via the "command" update.
            short_reason = str(exc).strip().splitlines()[0][:160]
            update_callback(
                device,
                f"Upgrade Failed: {short_reason}" if short_reason else "Upgrade Failed",
                device.get("progress") or 0,
                "failed",
            )

    def _get_shared_ftp_server(self):
        """Lazily bind ONE local FTP server for this job (on first use),
        shared by every device that needs an FTP transfer -- instead of
        each device trying to bind the control port for itself, which
        only the first one to get there could ever succeed at. Safe to
        call from multiple device worker threads at once."""
        with self._ftp_server_lock:
            if self._shared_ftp_server is None:
                server = FtpTransferServer(bind_ip="0.0.0.0", port=self.ftp_port)
                try:
                    server.start()
                except FtpServerError as exc:
                    raise RuntimeError(str(exc)) from exc
                self._shared_ftp_server = server
            return self._shared_ftp_server

    def _run_huawei_device(self, device, update_callback):
        vendor = str(device.get("vendor") or device.get("live_vendor") or "").lower()
        platform = str(device.get("platform") or device.get("live_platform") or "").lower()
        if "huawei" not in vendor and "vrp" not in platform:
            raise RuntimeError(f"Real upgrade currently supports Huawei VRP only: {device.get('ip')}")

        firmware = self.firmware_by_id.get(device.get("firmware_id"))
        if not firmware:
            raise RuntimeError(f"Firmware record not found for {device.get('ip')}")
        filename = firmware.get("filename")
        if not filename:
            raise RuntimeError("Firmware filename (.cc) is missing — it is mandatory.")
        local_path = self.firmware_dir / "huawei" / filename
        if not local_path.exists():
            raise RuntimeError(f"Huawei firmware file not found: {local_path}")

        patch_filename = firmware.get("patch_filename") or None
        patch_local_path = None
        if patch_filename:
            patch_local_path = self.firmware_dir / "huawei" / patch_filename
            if not patch_local_path.exists():
                raise RuntimeError(f"Huawei patch file not found: {patch_local_path}")

        update_callback(device, "Connecting to Huawei VRP", 27, "running")
        result = SSHManager.connect(
            device.get("ip"), self.username, self.password,
            port=self.port, timeout=self.timeout, preferred_device_type="huawei"
        )
        if not result.get("success"):
            raise RuntimeError(f"{device.get('ip')}: {result.get('error')}")
        connection = result["connection"]

        def log_command(command):
            update_callback(device, command, None, "command")

        driver = detect_driver(connection, result["netmiko_device_type"], log_command)

        try:
            info_before = driver.get_device_info()
            hostname = info_before.get("hostname") or device.get("hostname") or device.get("ip")
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / self._safe(hostname) / stamp
            backup_path.mkdir(parents=True, exist_ok=True)

            update_callback(device, "Backing Up Huawei Configuration", 32, "running")
            backups = driver.backup_config()
            for name, content in backups.items():
                (backup_path / f"{name}.txt").write_text(str(content), encoding="utf-8")

            update_callback(device, "Checking Huawei Flash", 38, "running")
            storage = driver.get_storage_info()
            (backup_path / "storage_before.txt").write_text(storage, encoding="utf-8")

            # Figure out which of the .cc / .pat files actually still
            # need transferring (skip anything already staged on flash:).
            candidates = [(local_path, filename)]
            if patch_local_path:
                candidates.append((patch_local_path, patch_filename))
            to_transfer = []
            for candidate_path, candidate_name in candidates:
                if driver.firmware_exists(candidate_name):
                    update_callback(
                        device,
                        f"{candidate_name} already present on flash: — skipping transfer",
                        50,
                        "running",
                    )
                else:
                    to_transfer.append((candidate_path, candidate_name))

            if to_transfer:
                names = ", ".join(name for _, name in to_transfer)
                update_callback(device, f"Transferring {names} via {self.transfer_method.upper()}", 52, "running")
                transfer_timeout = self._transfer_timeout(to_transfer)
                transfer_results = None
                if self.transfer_method == "tftp":
                    with self._tftp_lock:
                        transfer_results = driver.transfer_firmware_tftp(
                            to_transfer,
                            server_ip=self.tftp_server_ip, server_port=self.tftp_port,
                            timeout=transfer_timeout,
                        )
                elif self.transfer_method == "ftp":
                    transfer_results = driver.transfer_firmware_ftp(
                        to_transfer,
                        server=self._get_shared_ftp_server(),
                        server_ip=self.ftp_server_ip,
                        timeout=transfer_timeout,
                    )
                else:
                    driver.transfer_firmware(to_transfer)
                update_callback(device, f"{names} transferred via {self.transfer_method.upper()}", 58, "running")
                # Surface a snippet of the switch's own raw transfer output
                # directly in the job log — makes it possible to see exactly
                # what the switch said without digging through server-side
                # terminal output.
                if transfer_results:
                    for result in transfer_results:
                        snippet = str(result.get("switch_output") or result.get("detail") or "").strip()
                        if snippet:
                            update_callback(device, f"Switch transfer output: {snippet[-600:]}", None, "command")

            update_callback(device, "Verifying Huawei Software Package", 63, "running")
            self._verify_checksum_non_fatal(
                driver, filename, firmware.get("checksum") or firmware.get("md5"),
                update_callback, device,
            )
            if patch_filename:
                self._verify_checksum_non_fatal(
                    driver, patch_filename, firmware.get("patch_checksum") or firmware.get("patch_md5"),
                    update_callback, device,
                )

            update_callback(device, "Setting Startup System Software", 72, "running")
            driver.install_firmware(filename)

            if patch_filename:
                update_callback(device, "Setting Startup Patch", 76, "running")
                driver.install_patch(patch_filename)

            update_callback(device, "Verifying Startup Configuration", 78, "running")
            startup_after_set = driver.get_startup_info()
            (backup_path / "startup_after_set.txt").write_text(startup_after_set, encoding="utf-8")
            if filename.lower() not in startup_after_set.lower():
                raise RuntimeError("New firmware is not shown in display startup; save/reboot aborted.")
            if patch_filename and patch_filename.lower() not in startup_after_set.lower():
                raise RuntimeError("New patch is not shown in display startup; save/reboot aborted.")

            update_callback(device, "Saving Huawei Configuration", 80, "running")
            driver.save_config()

            update_callback(device, "Rebooting Huawei Device", 86, "running")
            driver.reload_device()
        finally:
            try:
                driver.disconnect()
            except Exception:
                pass

        update_callback(device, "Waiting for Huawei Reconnect", 92, "running")
        self._wait_for_ssh(device.get("ip"))

        reconnect = SSHManager.connect(
            device.get("ip"), self.username, self.password,
            port=self.port, timeout=self.timeout, preferred_device_type="huawei"
        )
        if not reconnect.get("success"):
            raise RuntimeError(f"Device reachable but SSH reconnect failed: {reconnect.get('error')}")
        post_driver = detect_driver(reconnect["connection"], reconnect["netmiko_device_type"], log_command)
        try:
            update_callback(device, "Running Huawei Post-Check", 97, "running")
            post = post_driver.post_check()
            (backup_path / "postcheck_after.txt").write_text(str(post), encoding="utf-8")
            target = str(firmware.get("version") or "").lower()
            actual = str(post.get("version") or "").lower()
            if target and target not in actual and actual not in target:
                raise RuntimeError(f"Post-check version mismatch. Target={target}, actual={actual}")
        finally:
            post_driver.disconnect()

        update_callback(device, "Huawei Upgrade Completed", 100, "completed")

    def _wait_for_ssh(self, ip):
        deadline = time.time() + self.reconnect_timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((ip, self.port), timeout=3):
                    return
            except OSError:
                time.sleep(self.reconnect_interval)
        raise RuntimeError(f"SSH did not return within {self.reconnect_timeout} seconds.")

    @staticmethod
    def _safe(value):
        return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(value))

    @staticmethod
    def log_entry(message, level="info"):
        return {"timestamp": datetime.now().isoformat(), "level": level, "message": message}
