import re
from datetime import datetime

from .ssh_manager import SSHManager
from .device_detector import detect_driver


class PrecheckEngine:

    def __init__(self, username, password, port=22, timeout=10):
        self.username = username
        self.password = password
        self.port = int(port)
        self.timeout = int(timeout)

    def run(self, device, firmware=None, log_fn=None):
        checks = []
        connection = None
        driver = None
        live_info = {}
        raw_outputs = {}

        ip = str(device.get("ip", "")).strip()
        if not ip:
            self._add(checks, "Device Address", False, "Device IP address is missing.")
            return self._result(checks, live_info, raw_outputs)

        ssh = SSHManager.connect(
            ip=ip,
            username=self.username,
            password=self.password,
            port=self.port,
            timeout=self.timeout
        )

        if not ssh.get("success"):
            self._add(checks, "SSH Connectivity", False, ssh.get("error", "SSH connection failed."))
            return self._result(checks, live_info, raw_outputs)

        connection = ssh.get("connection")
        self._add(checks, "SSH Connectivity", True, f"SSH login successful ({ssh.get('netmiko_device_type', 'auto')}).")

        try:
            driver = detect_driver(connection, ssh.get("netmiko_device_type"), log_fn)
            self._add(checks, "Driver Detection", True, driver.__class__.__name__)

            live_info = driver.get_device_info() or {}

            if hasattr(driver, "get_precheck_outputs"):
                raw_outputs = driver.get_precheck_outputs() or {}
                command_errors = [
                    item.get("command", key)
                    for key, item in raw_outputs.items()
                    if item.get("status") != "success"
                ]
                self._add(
                    checks,
                    "Huawei Command Collection",
                    not command_errors,
                    (
                        "display version, display startup, display device, dir, and "
                        "display patch-information collected successfully."
                        if not command_errors else
                        "Command collection failed for: " + ", ".join(command_errors)
                    )
                )

            self._add(
                checks,
                "Live Device Information",
                True,
                f"{live_info.get('hostname', 'Unknown')} | {live_info.get('vendor', 'Unknown')} "
                f"{live_info.get('model', 'Unknown')} | {live_info.get('version', 'Unknown')}"
            )

            identity_ok = self._same(device.get("vendor"), live_info.get("vendor")) and self._model_match(
                device.get("model"), live_info.get("model")
            )
            self._add(
                checks,
                "Inventory Identity",
                identity_ok,
                "Live identity matches inventory." if identity_ok else
                f"Inventory {device.get('vendor')} / {device.get('model')} does not match live "
                f"{live_info.get('vendor')} / {live_info.get('model')}."
            )

            firmware_ok = bool(firmware and firmware.get("filename"))
            self._add(
                checks,
                "Firmware Repository",
                firmware_ok,
                firmware.get("filename") if firmware_ok else "Firmware record or filename is missing."
            )

            compatibility_ok, compatibility_message = self._compatibility(device, live_info, firmware)
            self._add(checks, "Firmware Compatibility", compatibility_ok, compatibility_message)

            main_filename = (firmware or {}).get("filename") if firmware_ok else None
            patch_filename_check = (firmware or {}).get("patch_filename") or None
            main_staged = False
            patch_staged = None

            try:
                storage_output = driver.get_storage_info() or ""
                free_bytes = self._free_bytes(storage_output)

                def _is_staged(name):
                    if not name:
                        return False
                    for line in storage_output.splitlines():
                        tokens = line.strip().split()
                        if tokens and tokens[-1] == name:
                            return True
                    return False

                main_staged = _is_staged(main_filename)
                patch_staged = _is_staged(patch_filename_check) if patch_filename_check else True

                # Only count bytes that still need to land on flash. A
                # firmware file that's already staged (a prior transfer
                # completed, then Pre-Check is re-run, or the job is
                # retried) shouldn't count toward the requirement again —
                # its transfer will be skipped, not repeated. Without
                # this, Pre-Check demands headroom for a redundant
                # re-transfer that will never happen, and fails on a
                # device that's actually already correctly staged.
                pending_bytes = 0
                if not main_staged:
                    pending_bytes += self._integer((firmware or {}).get("size"))
                if patch_filename_check and not patch_staged:
                    pending_bytes += self._integer((firmware or {}).get("patch_size"))

                required = int(pending_bytes * 1.10)

                if free_bytes is None:
                    storage_ok = bool(storage_output.strip())
                    message = "Storage command succeeded; free-space value could not be parsed automatically." if storage_ok else "Storage output is empty."
                elif required <= 0:
                    storage_ok = True
                    message = (
                        f"Free {self._format_bytes(free_bytes)}; firmware already staged on flash — "
                        "no additional space required for transfer."
                        if (main_filename or patch_filename_check) else
                        f"Free space {self._format_bytes(free_bytes)}; firmware size unavailable."
                    )
                else:
                    storage_ok = free_bytes >= required
                    message = (f"Free {self._format_bytes(free_bytes)} | pending transfer {self._format_bytes(pending_bytes)} | "
                               f"required with reserve {self._format_bytes(required)}")
                self._add(checks, "Storage Capacity", storage_ok, message)
            except Exception as exc:
                self._add(checks, "Storage Capacity", False, f"Storage check failed: {exc}")

            if firmware_ok:
                try:
                    self._add(
                        checks,
                        "Firmware Staging",
                        True,
                        "Firmware already exists on device storage — transfer will be skipped." if main_staged else "Firmware transfer will be required."
                    )
                except Exception as exc:
                    self._add(checks, "Firmware Staging", True, f"Existing file check skipped: {exc}")

        except Exception as exc:
            self._add(checks, "Pre-Check Engine", False, str(exc))
        finally:
            try:
                if driver:
                    driver.disconnect()
                elif connection:
                    connection.disconnect()
            except Exception:
                pass

        return self._result(checks, live_info, raw_outputs)

    @classmethod
    def _compatibility(cls, device, live, firmware):
        if not firmware:
            return False, "Firmware record not found."
        dv = live.get("vendor") or device.get("vendor")
        dp = live.get("platform") or device.get("platform")
        dm = live.get("model") or device.get("model")
        vendor_ok = cls._same(firmware.get("vendor"), dv)
        platform_ok = not cls._norm(firmware.get("platform")) or cls._same(firmware.get("platform"), dp)
        model_ok = not cls._norm(firmware.get("model")) or cls._model_match(firmware.get("model"), dm)
        ok = vendor_ok and platform_ok and model_ok
        return ok, ("Firmware matches live vendor, platform, and model." if ok else
                    f"Expected {firmware.get('vendor')} / {firmware.get('platform') or '*'} / {firmware.get('model') or '*'}, "
                    f"live {dv} / {dp} / {dm}.")

    @staticmethod
    def _free_bytes(output):
        patterns = [
            r"([\d,]+)\s+bytes?\s+(?:free|available)",
            r"(?:free\s+space|free)\s*[:=]\s*([\d,.]+)\s*(bytes?|kb|mb|gb|tb)",
            r"([\d,.]+)\s*(kb|mb|gb|tb)\s+(?:free|available)"
        ]
        for pattern in patterns:
            match = re.search(pattern, output or "", re.I)
            if not match:
                continue
            value = float(match.group(1).replace(",", ""))
            unit = match.group(2).lower() if match.lastindex and match.lastindex >= 2 else "bytes"
            return int(value * {"byte": 1, "bytes": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}.get(unit, 1))
        return None

    @classmethod
    def _same(cls, first, second):
        return bool(cls._norm(first)) and cls._norm(first) == cls._norm(second)

    @classmethod
    def _model_match(cls, first, second):
        a, b = cls._norm(first), cls._norm(second)
        if not a or not b:
            return True
        return a == b or a in b or b in a

    @staticmethod
    def _norm(value):
        return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())

    @staticmethod
    def _integer(value):
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _format_bytes(value):
        size = float(max(value, 0))
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024 or unit == "TB":
                return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
            size /= 1024

    @staticmethod
    def _add(checks, name, passed, message):
        checks.append({"name": name, "status": "passed" if passed else "failed", "message": str(message)})

    @staticmethod
    def _result(checks, live_info, raw_outputs=None):
        passed = bool(checks) and all(item.get("status") == "passed" for item in checks)
        return {
            "status": "passed" if passed else "failed",
            "checked_at": datetime.now().isoformat(),
            "checks": checks,
            "live_device_info": live_info,
            "raw_outputs": raw_outputs or {}
        }
