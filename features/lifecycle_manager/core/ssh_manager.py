import os
import tempfile

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from paramiko.ssh_exception import SSHException


class SSHManager:

    DEVICE_TYPES = [
        "huawei",
        "cisco_ios",
        "cisco_nxos",
        "aruba_os",
        "aruba_aoscx"
    ]

    @staticmethod
    def connect(ip, username, password, port=22, timeout=10, preferred_device_type=None):
        errors = []
        device_types = list(SSHManager.DEVICE_TYPES)
        if preferred_device_type in device_types:
            device_types.remove(preferred_device_type)
            device_types.insert(0, preferred_device_type)

        for device_type in device_types:
            session_log_fd, session_log_path = tempfile.mkstemp(prefix="nes_ssh_session_", suffix=".log")
            os.close(session_log_fd)
            device = {
                "device_type": device_type,
                "host": ip,
                "username": username,
                "password": password,
                "port": port,
                "timeout": timeout,
                "conn_timeout": timeout,
                "banner_timeout": timeout,
                "auth_timeout": timeout,
                "fast_cli": False,
                # Only the device's own responses are captured here, never
                # what we send — the password itself is never written to
                # this file, only used to diagnose where the device's
                # actual login dialogue diverges from what netmiko expects.
                "session_log": session_log_path,
                "session_log_record_writes": False,
            }
            try:
                connection = ConnectHandler(**device)
                SSHManager._remove_quietly(session_log_path)
                return {
                    "success": True,
                    "connection": connection,
                    "netmiko_device_type": device_type
                }
            except NetmikoAuthenticationException as exc:
                transcript = SSHManager._tail_session_log(session_log_path)
                SSHManager._remove_quietly(session_log_path)
                detail = f"Authentication failed: {exc}"
                if transcript:
                    detail += f"\n\n--- Raw device output during login (what the switch actually sent) ---\n{transcript}"
                return {"success": False, "error": detail}
            except (NetmikoTimeoutException, SSHException, ConnectionResetError, OSError) as exc:
                # Transport-level failure: the TCP/SSH session was refused,
                # timed out, or reset before login was even attempted.
                # A different netmiko device_type string does not change
                # the underlying SSH handshake, so retrying it here just
                # re-triggers the same failure — and on some platforms
                # (Huawei VRP's SSH attack-defense in particular) several
                # rapid reconnect attempts from the same source IP can
                # get that IP temporarily blacklisted, which then blocks
                # even a manual SSH session from the same machine. Stop
                # after the first transport failure instead of hammering
                # the device five times in a row.
                SSHManager._remove_quietly(session_log_path)
                return {
                    "success": False,
                    "error": f"{device_type}: {exc}",
                }
            except Exception as exc:
                SSHManager._remove_quietly(session_log_path)
                errors.append(f"{device_type}: {exc}")

        return {"success": False, "error": " | ".join(errors)}

    @staticmethod
    def _tail_session_log(path, max_chars=2000):
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError:
            return ""
        text = raw.decode("utf-8", errors="replace")
        # Strip ANSI/VT100 escape sequences so the transcript is readable
        # in a plain log panel instead of full of control-code noise.
        import re
        text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)
        text = text.strip()
        if len(text) > max_chars:
            text = "...(truncated)...\n" + text[-max_chars:]
        return text

    @staticmethod
    def _remove_quietly(path):
        try:
            os.remove(path)
        except OSError:
            pass
