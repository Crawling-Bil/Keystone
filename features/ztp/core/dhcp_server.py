"""DHCP server for a ZTP staging segment, wrapping dnsmasq.

WHY DNSMASQ, NOT HAND-ROLLED: a correct DHCP server has to handle
DISCOVER/OFFER/REQUEST/ACK, lease bookkeeping, and vendor-specific
options correctly, or a newly-booted switch just silently never gets
an address. dnsmasq is a small, extremely well-tested daemon that
already does all of that — the same reasoning that led this project to
use pyftpdlib for the FTP server (core/ftp_server.py) instead of
hand-rolling FTP.

THIS IS THE MOST DANGEROUS COMPONENT IN THE ZTP FEATURE. A DHCP server
that answers on the wrong interface becomes a rogue DHCP server and can
hand out leases to production devices, breaking their connectivity in
a way that's confusing to diagnose. Every safeguard below exists
because of that risk specifically:

  * `interface` is REQUIRED and must name one specific NIC/VLAN
    interface (e.g. "eth1", not "eth0" if that's your uplink). There
    is no default and no wildcard/"all interfaces" option on purpose.
  * dnsmasq is started with `bind-interfaces` so it only listens on
    the named interface, and `except-interface=lo` / `port=0` (DNS
    disabled) reduce its footprint further.
  * `require_isolated_ack=True` (the default) makes start() refuse to
    run unless the caller has explicitly acknowledged that the named
    interface is on an isolated staging segment, not the production
    LAN — mirrors run.py's existing refusal to bind a non-loopback
    host without NES_ALLOW_REMOTE=1.

NOT YET VALIDATED end-to-end against real hardware or a real dnsmasq
install (this sandbox doesn't have dnsmasq or a spare switch). Config
rendering is covered by unit tests; `dnsmasq --test` (syntax-checks a
config without starting the server) should be run against the real
binary before this is ever pointed at a real interface.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

logger = logging.getLogger("nes.lifecycle.ztp.dhcp")

# dnsmasq (like every DHCP server that implements RFC 2132 Options 66/67)
# copies an Option 67 value that fits into the legacy BOOTP "file" header
# field (128 bytes, one of which is reserved for the C-string terminator)
# instead of emitting it as a separate option TLV -- this is standard,
# expected DHCP/PXE-style behaviour, not a dnsmasq quirk.
#
# The dangerous part, confirmed against a real dnsmasq 2.90 binary with a
# live packet capture: a value longer than 127 bytes is silently
# TRUNCATED to fit that field -- no error from `dnsmasq --test`, no
# warning at runtime, and dnsmasq's own log even prints the untruncated
# value it was *configured* with, not what actually went out on the wire.
# A switch that receives a truncated sftp:// URL gets a corrupted address
# and simply never completes ZTP, with nothing in any log pointing at
# the DHCP layer as the cause. So this has to be validated here, loudly,
# at config-render time, rather than left to fail silently on the wire.
MAX_OPTION_67_LENGTH = 127


class DhcpServerError(RuntimeError):
    pass


def _needs_sudo_prefix():
    """True when this process is not root on a POSIX system -- binding
    UDP/67 (the DHCP server port) needs root/administrator privileges
    on every OS this project targets, and Keystone itself is normally
    run as a regular user, not as root, so the dnsmasq child process
    it spawns inherits that same non-root privilege by default."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False  # Windows: no such concept here; see the module docstring.
    return geteuid() != 0


def _dnsmasq_launch_command(dnsmasq_path, config_path):
    """Build the argv to launch dnsmasq, prefixed with `sudo -n` when
    this process isn't already root.

    `-n` (non-interactive) is deliberate: there is no channel to relay
    an interactive sudo password prompt from this background
    subprocess into the browser that clicked "Start DHCP Server", so
    asking would just hang forever with nothing visible to the caller.
    Instead this only succeeds if sudo credentials are already cached
    (run `sudo -v` in the same terminal Keystone was started from,
    before clicking Start) -- otherwise it fails fast with a clear
    stderr message, surfaced via the existing "dnsmasq exited
    immediately" error path below."""
    command = [dnsmasq_path, "--no-daemon", "-C", str(config_path)]
    if _needs_sudo_prefix():
        return ["sudo", "-n", *command]
    return command


class DhcpValidationError(DhcpServerError):
    """Raised for bad *input* to render_dnsmasq_config()/ZtpDhcpServer --
    a wildcard interface, an oversized option67_url -- as opposed to a
    runtime/environment failure (dnsmasq missing, bind failed, process
    died). Callers (routes.py) use this distinction to return 400 for a
    caller mistake instead of a 500, which would incorrectly suggest the
    server itself is broken."""
    pass


def render_dnsmasq_config(
    interface,
    range_start,
    range_end,
    subnet_mask,
    option67_url,
    gateway=None,
    dns_server=None,
    lease_time="1h",
    reservations=None,
    log_path=None,
    pid_file=None,
):
    """Build a dnsmasq config that does DHCP only (no DNS, no TFTP) for
    one interface, handing out Option 67 = the ZTP intermediate-file
    SFTP URL. `reservations` is a list of {"mac": ..., "ip": ...}
    dicts — these become `dhcp-host` lines so a given switch always
    gets the same staging IP (a DHCP reservation), independent of
    dnsmasq's own lease pool, which keeps discovery/troubleshooting
    predictable across repeated ZTP attempts."""
    if not interface or interface in ("0.0.0.0", "*", "any", "all"):
        raise DhcpValidationError(
            f"interface must name one specific NIC (got {interface!r}) — "
            "a wildcard/all-interfaces DHCP server risks becoming a rogue "
            "DHCP server on whatever else this host is connected to."
        )

    if not option67_url or len(option67_url) > MAX_OPTION_67_LENGTH:
        raise DhcpValidationError(
            f"option67_url is {len(option67_url or '')} characters long, but "
            f"dnsmasq silently truncates DHCP Option 67 values past "
            f"{MAX_OPTION_67_LENGTH} characters (it has to fit in the legacy "
            "128-byte BOOTP 'file' field alongside a null terminator) -- with "
            "no warning anywhere, including dnsmasq's own log. Shorten the "
            "sftp:// URL (a shorter username/password, an IP instead of a "
            "hostname, a shorter intermediate filename) rather than starting "
            "the server with a value that will reach the switch corrupted."
        )

    lines = [
        f"interface={interface}",
        "bind-interfaces",
        "except-interface=lo",
        "port=0",  # disable dnsmasq's built-in DNS resolver — DHCP only
        "dhcp-authoritative",
        f"dhcp-range={range_start},{range_end},{subnet_mask},{lease_time}",
        # Option 67 (bootfile-name) repurposed by Huawei ZTP to carry
        # the SFTP intermediate-file URL — confirmed in the vendor doc's
        # own worked example (`option 67 cipher sftp://...`).
        f'dhcp-option=67,"{option67_url}"',
    ]
    if gateway:
        lines.append(f"dhcp-option=option:router,{gateway}")
    if dns_server:
        lines.append(f"dhcp-option=option:dns-server,{dns_server}")
    for reservation in reservations or []:
        mac = reservation.get("mac")
        ip = reservation.get("ip")
        if not mac or not ip:
            continue
        lines.append(f"dhcp-host={mac},{ip}")
    if log_path:
        lines.append(f"log-facility={log_path}")
        lines.append("log-dhcp")
    if pid_file:
        # Written by dnsmasq ITSELF, after it successfully forks/execs
        # under `sudo -n` and binds the socket -- this is the one
        # reliable way to learn the real dnsmasq PID. The Popen handle
        # in ZtpDhcpServer only ever points at the `sudo -n dnsmasq`
        # invocation; on macOS/BSD sudo that is answered by a separate
        # monitor + target process pair, and sudo forwarding a signal
        # sent to itself down to that real child is NOT guaranteed
        # across sudo versions/platforms. stop() targets this PID
        # directly instead of hoping sudo relays the signal.
        lines.append(f"pid-file={pid_file}")

    return "\n".join(lines) + "\n"


class ZtpDhcpServer:
    """Manages one dnsmasq subprocess scoped to a single interface.

    Usage:
        server = ZtpDhcpServer(
            interface="eth1", range_start="10.50.1.100",
            range_end="10.50.1.199", subnet_mask="255.255.255.0",
            option67_url="sftp://ztp_user:ztp_pass@10.50.1.5:2222/intermediate.ini",
            gateway="10.50.1.1", reservations=[{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.50.1.11"}],
        )
        server.start(confirm_isolated_segment=True)
        ...
        server.stop()
    """

    def __init__(
        self,
        interface,
        range_start,
        range_end,
        subnet_mask,
        option67_url,
        gateway=None,
        dns_server=None,
        lease_time="1h",
        reservations=None,
        data_dir=None,
    ):
        self.interface = interface
        self.range_start = range_start
        self.range_end = range_end
        self.subnet_mask = subnet_mask
        self.option67_url = option67_url
        self.gateway = gateway
        self.dns_server = dns_server
        self.lease_time = lease_time
        self.reservations = reservations or []
        self.data_dir = Path(data_dir) if data_dir else Path(tempfile.gettempdir()) / "nes_ztp_dhcp"
        self._process = None
        self._config_path = None
        # The REAL dnsmasq PID, learned from the pid-file dnsmasq writes
        # itself once it has bound the socket -- see the long comment in
        # render_dnsmasq_config(). Deterministic path (not per-start) so
        # a fresh ZtpDhcpServer instance (e.g. after Keystone itself was
        # restarted) can still find and clean up a process an EARLIER,
        # ungracefully-terminated instance left running.
        self._pid_file = self.data_dir / "dnsmasq.pid"
        self._dnsmasq_pid = None

    def start(self, confirm_isolated_segment=False):
        if self._process is not None:
            return
        if not confirm_isolated_segment:
            raise DhcpServerError(
                "Refusing to start: pass confirm_isolated_segment=True to "
                "acknowledge that interface "
                f"{self.interface!r} is on an isolated ZTP staging segment, "
                "not shared with production DHCP. A DHCP server on the "
                "wrong interface will hand out leases to production devices."
            )

        # Validate + render the caller's input BEFORE touching the OS
        # (checking for the dnsmasq binary, writing files) -- this way a
        # bad interface name or oversized option67_url is reported as
        # what it is (a DhcpValidationError -> 400 at the route layer)
        # even in an environment where dnsmasq isn't installed yet,
        # rather than being masked by an unrelated "dnsmasq missing"
        # error that would send the caller off to fix the wrong thing.
        self.data_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.data_dir / "dnsmasq.log"
        # Validated + rendered again (pid_file included) further down,
        # right before it's written to disk -- this first pass exists
        # only so a bad interface/option67_url is reported as what it
        # is (DhcpValidationError -> 400) even before checking whether
        # dnsmasq itself is installed, per the comment above.
        render_dnsmasq_config(
            interface=self.interface,
            range_start=self.range_start,
            range_end=self.range_end,
            subnet_mask=self.subnet_mask,
            option67_url=self.option67_url,
            gateway=self.gateway,
            dns_server=self.dns_server,
            lease_time=self.lease_time,
            reservations=self.reservations,
            log_path=str(log_path),
        )

        dnsmasq_path = shutil.which("dnsmasq")
        if not dnsmasq_path:
            raise DhcpServerError(
                "dnsmasq is not installed or not on PATH. Install it "
                "(e.g. `apt install dnsmasq` / `brew install dnsmasq`) — "
                "this module intentionally wraps a well-tested DHCP daemon "
                "rather than hand-rolling DHCP packet handling."
            )

        self._config_path = self.data_dir / "dnsmasq.conf"

        # Defensive cleanup BEFORE launching: if a previous ZtpDhcpServer
        # (possibly from an earlier, ungracefully-terminated Keystone
        # process -- a Ctrl+C that didn't reach stop(), a crash, a
        # closed terminal) left a real dnsmasq still bound to this same
        # config/port, a fresh one starting now will either fail to
        # bind or -- worse -- end up racing the orphan for the same
        # DHCP traffic, producing exactly the "works, then randomly
        # doesn't" behavior this class exists to prevent. Best-effort:
        # never let a cleanup failure block a legitimate start.
        self._kill_stale_pid_file()

        config_text = render_dnsmasq_config(
            interface=self.interface,
            range_start=self.range_start,
            range_end=self.range_end,
            subnet_mask=self.subnet_mask,
            option67_url=self.option67_url,
            gateway=self.gateway,
            dns_server=self.dns_server,
            lease_time=self.lease_time,
            reservations=self.reservations,
            log_path=str(log_path),
        )
        self._config_path.write_text(config_text, encoding="utf-8")

        # `dnsmasq --test` syntax-checks the rendered config without
        # binding any socket — cheap sanity check before we actually
        # try to seize a network interface.
        test = subprocess.run(
            [dnsmasq_path, "--test", "-C", str(self._config_path)],
            capture_output=True, text=True,
        )
        if test.returncode != 0:
            # Every field that ends up in this config (range_start,
            # range_end, subnet_mask, gateway, dns_server, reservation
            # IPs/MACs) came from the caller -- a syntax error dnsmasq
            # itself catches here (a malformed IP, an inverted range)
            # is a bad request, not dnsmasq or the host being broken.
            raise DhcpValidationError(
                f"dnsmasq rejected this configuration: {test.stderr or test.stdout} "
                "-- check range_start/range_end/subnet_mask/gateway/dns_server "
                "for typos or malformed addresses."
            )

        launch_command = _dnsmasq_launch_command(dnsmasq_path, self._config_path)
        try:
            self._process = subprocess.Popen(
                launch_command,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise DhcpServerError(f"Failed to launch dnsmasq: {exc}") from exc

        time.sleep(0.3)
        exit_code = self._process.poll()
        if exit_code is not None:
            stderr = self._process.stderr.read().decode("utf-8", "replace") if self._process.stderr else ""
            self._process = None
            hint = (
                "This process isn't running as root, so it tried `sudo -n` "
                "(non-interactive) to bind UDP/67. If that's what failed, run "
                "`sudo -v` in the same terminal Keystone was started from, "
                "then try Start again while that sudo authorization is still "
                "cached. Otherwise: binding UDP/67 usually requires "
                "root/administrator privileges."
                if launch_command[0] == "sudo"
                else "Binding UDP/67 usually requires root/administrator privileges."
            )
            raise DhcpServerError(
                f"dnsmasq exited immediately (code {exit_code}); stderr: {stderr}. {hint}"
            )

        # The Popen PID above is `sudo -n dnsmasq...`, NOT necessarily
        # the real dnsmasq PID -- on macOS/BSD sudo that command is
        # answered by a monitor + target process pair, and terminating
        # the Popen handle alone doesn't reliably reach the real child
        # (see stop()). dnsmasq's own --pid-file option would normally
        # solve this, but confirmed against a real dnsmasq binary: the
        # `--no-daemon` flag this class deliberately uses (so
        # self._process.poll() can detect an immediate failure, below)
        # ALSO suppresses pid-file writing -- that's documented
        # behavior, `-d`/`--no-daemon` means "foreground, no pid file",
        # not just "don't fork". So instead: find the real dnsmasq
        # process by matching its OWN command line (which, unlike the
        # `sudo -n dnsmasq ...` wrapper's, starts with the dnsmasq
        # binary path itself, not "sudo") against our config path,
        # which is unique to this instance.
        self._dnsmasq_pid = self._find_real_dnsmasq_pid(dnsmasq_path, timeout=3.0)
        if self._dnsmasq_pid is None:
            # It launched and didn't exit in the first 0.3s, but its
            # real process was never found either -- something is
            # wrong even though the naive "is the process still alive"
            # check above passed. Tear it down rather than leaving the
            # caller believing DHCP is serving when it may not be.
            self._process.terminate()
            self._process = None
            raise DhcpServerError(
                "dnsmasq launched but its process could not be found within 3s "
                "-- treating this as a failed start rather than risking a DHCP "
                "server that silently isn't actually bound. Check "
                f"{self.data_dir / 'dnsmasq.log'} for what it actually did."
            )

        # Persist the real pid ourselves (dnsmasq doesn't, per the
        # comment above) so a FUTURE ZtpDhcpServer instance -- e.g.
        # after Keystone itself was restarted, with no in-memory
        # knowledge of this run -- can still find and clean up this
        # exact process if this one never reaches stop() cleanly.
        try:
            self._pid_file.write_text(str(self._dnsmasq_pid), encoding="utf-8")
        except OSError:
            pass

        logger.info(
            "ZTP DHCP server started on interface=%s range=%s-%s (pid=%s)",
            self.interface, self.range_start, self.range_end, self._dnsmasq_pid,
        )

    def _find_real_dnsmasq_pid(self, dnsmasq_path, timeout):
        """Poll `ps` for the actual dnsmasq process (argv starts with
        the dnsmasq binary itself), distinguishing it from the
        `sudo -n dnsmasq ...` wrapper/monitor processes, which mention
        the same config path but start with "sudo". Matches on
        self._config_path, which is unique to this instance/config
        file, so this can't accidentally pick up an unrelated dnsmasq
        someone else on the machine is running."""
        deadline = time.time() + timeout
        config_str = str(self._config_path)
        while time.time() < deadline:
            result = subprocess.run(
                ["ps", "-eo", "pid=,command="],
                capture_output=True, text=True,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or config_str not in line:
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                pid_str, command = parts
                if command.startswith("sudo"):
                    continue  # the wrapper/monitor, not the real process
                if dnsmasq_path not in command:
                    continue
                try:
                    return int(pid_str)
                except ValueError:
                    continue
            time.sleep(0.15)
        return None

    def _sudo_kill(self, pid, sig):
        """Send a signal to a (real, root-owned) dnsmasq PID -- NOT to
        the `sudo -n dnsmasq...` Popen handle, which sudo's own process
        model (a separate monitor + target process on macOS/BSD sudo)
        does not reliably forward signals through. Best-effort: a
        failure here just means the process may already be gone."""
        if not _needs_sudo_prefix():
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
            return
        sig_name = "TERM" if sig == 15 else "KILL"
        subprocess.run(
            ["sudo", "-n", "kill", f"-{sig_name}", str(pid)],
            capture_output=True,
        )

    def _pid_is_alive(self, pid):
        if not _needs_sudo_prefix():
            try:
                os.kill(pid, 0)
                return True
            except (ProcessLookupError, PermissionError):
                return False
        # Root-owned process, we're not root: `kill -0` via sudo -n is
        # the only portable way to ask "does this PID still exist"
        # without a permission error masking the answer.
        result = subprocess.run(
            ["sudo", "-n", "kill", "-0", str(pid)], capture_output=True,
        )
        return result.returncode == 0

    def _kill_stale_pid_file(self):
        """Best-effort cleanup of a real dnsmasq left running by an
        earlier, ungracefully-terminated ZtpDhcpServer instance (a
        crashed/Ctrl+C'd Keystone process, a closed terminal -- none of
        which run this class's own stop()). Never raises: a start()
        that can't clean up a possible orphan should still try to
        start, not fail outright."""
        try:
            if not self._pid_file.exists():
                return
            pid_text = self._pid_file.read_text(encoding="utf-8").strip()
            if not pid_text:
                return
            stale_pid = int(pid_text)
            if self._pid_is_alive(stale_pid):
                logger.warning(
                    "Found a dnsmasq (pid=%s) still running from a previous "
                    "session at %s -- killing it before starting a fresh one, "
                    "to avoid two dnsmasq processes racing for the same "
                    "interface/port.", stale_pid, self._pid_file,
                )
                self._sudo_kill(stale_pid, 15)
                time.sleep(0.3)
                if self._pid_is_alive(stale_pid):
                    self._sudo_kill(stale_pid, 9)
            self._pid_file.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass

    def is_running(self):
        if self._process is None or self._dnsmasq_pid is None:
            return False
        return self._pid_is_alive(self._dnsmasq_pid)

    def stop(self):
        if self._process is None and self._dnsmasq_pid is None:
            return
        # Belt-and-suspenders: try the direct Popen handle first (cheap,
        # and correct on platforms/sudo builds that DO forward the
        # signal) -- but the pid-file-sourced PID below is the part
        # that's actually reliable, since self._process only ever
        # points at the `sudo -n dnsmasq...` wrapper, not necessarily
        # the real daemon (see render_dnsmasq_config()).
        if self._process is not None:
            try:
                self._process.terminate()
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
                try:
                    self._process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            except Exception:
                pass

        if self._dnsmasq_pid is not None:
            self._sudo_kill(self._dnsmasq_pid, 15)
            time.sleep(0.3)
            if self._pid_is_alive(self._dnsmasq_pid):
                self._sudo_kill(self._dnsmasq_pid, 9)

        try:
            self._pid_file.unlink(missing_ok=True)
        except OSError:
            pass

        logger.info("ZTP DHCP server stopped (was pid=%s)", self._dnsmasq_pid)
        self._process = None
        self._dnsmasq_pid = None
