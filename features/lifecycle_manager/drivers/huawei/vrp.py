import re
import socket
import time
from pathlib import Path

from netmiko import file_transfer
from netmiko.exceptions import ReadTimeout

from ..base_driver import BaseDriver, ConfigPushError
from ...core.tftp_server import TftpTransferServer, TftpServerError
from ...core.ftp_server import FtpTransferServer, FtpServerError


class HuaweiVRPDriver(BaseDriver):
    """Huawei VRP driver focused on controlled system-software upgrades.

    Command sequence follows Huawei's own "Example for Upgrading a New
    Device" guide (S/CE series typical configuration examples):
    https://support.huawei.com/enterprise/en/doc/EDOC1000069520/81f2d716/example-for-upgrading-a-new-device
    """

    def _send(self, command, read_timeout=60):
        self._log(command)
        return self.connection.send_command(command, read_timeout=read_timeout)

    def _send_timing(self, command, read_timeout=60):
        self._log(command)
        return self.connection.send_command_timing(command, read_timeout=read_timeout)

    def _send_timing_patient(self, command, read_timeout=180, max_extensions=2):
        """Like _send_timing(), but tolerates a switch that keeps
        streaming NEW output continuously for the entire read_timeout
        window with no pause at all.

        Netmiko's read_channel_timing() (what send_command_timing()
        uses under the hood) treats that specific situation as a hard
        failure -- raises ReadTimeout -- even though on real hardware
        it usually just means the device is still legitimately busy
        (e.g. committing a large save to flash), not actually stuck.
        Observed against real hardware: a plain `save` sometimes
        doesn't go quiet within 180s. Rather than failing the whole
        device on the very first ReadTimeout, keep polling for more
        output (never re-sending the command -- read-only, like
        _wait_for_prompt) for up to `max_extensions` further windows
        of the same length before finally giving up.
        """
        self._log(command)
        try:
            return self.connection.send_command_timing(command, read_timeout=read_timeout)
        except ReadTimeout:
            for _ in range(max_extensions):
                try:
                    return self.connection.read_channel_timing(read_timeout=read_timeout)
                except ReadTimeout:
                    continue
            total = read_timeout * (1 + max_extensions)
            raise RuntimeError(
                f"Device kept streaming output continuously for over {total}s "
                f"after '{command}' with no pause at all -- giving up. This "
                "usually means the device is still legitimately busy (e.g. a "
                "slow flash write) rather than truly stuck; if it keeps "
                "happening, this step's timeout may need to be raised further."
            )

    def _send_patient(self, command, read_timeout=60, max_retries=2, retry_gap=5):
        """Like _send(), but tolerates the device still being busy from a
        previous heavy command (e.g. `startup patch ... all`) when this
        command is issued.

        netmiko's plain send_command() waits for the command's own echo
        before it even starts reading the real response -- but that
        echo-wait window is HARDCODED to 10 seconds inside netmiko itself
        (command_echo_read(cmd, read_timeout=10)) and is NOT affected by
        the read_timeout we pass in. If the device is still internally
        processing the previous command (e.g. validating/writing a patch
        to flash) it can take longer than 10s to even echo the next
        command back -- netmiko reports that as "Pattern not detected"
        (ReadTimeout) even though the device is perfectly healthy and
        just still busy. Observed on real hardware: 192.168.99.15 failed
        `display startup` this way immediately after `startup patch ...
        all` while a second device in the same job (192.168.99.14)
        succeeded -- pure per-device timing, not a parallel-execution
        bug. Retry (re-sending the command) a few times with a short
        pause rather than failing the whole device outright.
        """
        self._log(command)
        last_exc = None
        for attempt in range(max_retries + 1):
            try:
                return self.connection.send_command(command, read_timeout=read_timeout)
            except ReadTimeout as exc:
                last_exc = exc
                if attempt < max_retries:
                    time.sleep(retry_gap)
                    continue
        raise RuntimeError(
            f"Device did not respond to '{command}' after {max_retries + 1} attempts "
            f"(each waiting up to {read_timeout}s) -- it may still be busy from the "
            f"previous command. Original error: {last_exc}"
        )

    def get_device_info(self):
        version_output = self._send("display version", read_timeout=60)
        esn_output = ""
        try:
            esn_output = self._send("display esn", read_timeout=30)
        except Exception:
            pass

        hostname = self.connection.find_prompt().strip().strip("<>[]# ")
        model = "Unknown"
        version = "Unknown"
        serial = "Unknown"

        for pattern in [
            r"VRP.*?Version\s+([^\s\)]+)",
            r"Software Version\s*:\s*(\S+)",
            r"Version\s+([VvRrPpCc0-9.()SPH]+)",
        ]:
            match = re.search(pattern, version_output, re.IGNORECASE)
            if match:
                version = match.group(1).strip()
                break

        for pattern in [
            r"HUAWEI\s+(\S+)\s+uptime",
            r"(\S+)\s+uptime is",
            r"Device Name\s*:\s*(\S+)",
            r"Board Type\s*:\s*(\S+)",
        ]:
            match = re.search(pattern, version_output, re.IGNORECASE)
            if match:
                model = match.group(1).strip()
                break

        for pattern in [
            r"ESN\s+of\s+slot\s+\S+\s+is\s+(\S+)",
            r"ESN\s*:\s*(\S+)",
            r"Electronic Serial Number\s*:\s*(\S+)",
        ]:
            match = re.search(pattern, esn_output, re.IGNORECASE)
            if match:
                serial = match.group(1).strip()
                break

        return {
            "vendor": "Huawei",
            "platform": "VRP",
            "hostname": hostname or "Unknown",
            "model": model,
            "version": version,
            "serial": serial,
        }

    def get_storage_info(self):
        return self._send("dir", read_timeout=60)

    def get_startup_info(self):
        return self._send_patient("display startup", read_timeout=60)

    def get_precheck_outputs(self):
        """Collect Huawei commands that must be reviewed before an upgrade."""
        commands = [
            ("display_version", "display version", 60),
            ("display_startup", "display startup", 60),
            ("display_device", "display device", 60),
            ("directory", "dir", 60),
            ("display_patch_information", "display patch-information", 60),
        ]
        outputs = {}
        for key, command, timeout in commands:
            try:
                outputs[key] = {
                    "command": command,
                    "status": "success",
                    "output": self._send(command, read_timeout=timeout),
                }
            except Exception as exc:
                outputs[key] = {
                    "command": command,
                    "status": "error",
                    "output": str(exc),
                }
        return outputs

    def backup_config(self):
        return {
            "current_configuration": self._send(
                "display current-configuration", read_timeout=180
            ),
            "version_before": self._send(
                "display version", read_timeout=60
            ),
            "startup_before": self.get_startup_info(),
        }

    # =========================================================
    # CONFIG PUSH — apply an operator-prepared draft config
    # line-by-line, for devices that are already discovered/managed
    # (Zero Touch's "push config to a device I already know about"
    # path, as opposed to ZTP proper which only ever runs against a
    # brand-new device during its own DHCP/SFTP bootstrap).
    # =========================================================

    _CONFIG_PUSH_ERROR_MARKERS = (
        "% unrecognized command",
        "% wrong parameter",
        "unrecognized command",
        "% incomplete command",
        "error:",
    )

    def push_config_lines(self, lines, on_result=None):
        """Enter system-view once, send every non-blank/non-comment line
        of `lines` as its own command, and return to user-view.

        VRP's own `display current-configuration` output uses '#' as a
        section-comment marker (never a real command) -- draft configs
        built from that output, or written by hand in the same style,
        are expected to carry the same convention, so '#'-prefixed and
        blank lines are skipped rather than sent to the device.

        Leading/trailing whitespace on each line is stripped before
        sending -- VRP's CLI does not require the indentation
        `display current-configuration` prints for readability, and
        stripping it avoids any ambiguity about what's actually being
        sent versus what's just visual nesting.

        Aborts immediately on the first line the switch rejects,
        identified either by netmiko itself raising (timeout,
        pattern-not-detected) or by VRP's own error markers appearing
        in that line's output -- see module docstring on
        BaseDriver.push_config_lines for why this doesn't try to push
        through past a rejected line. Raises ConfigPushError (not a
        plain RuntimeError) in both cases, carrying every line's
        result up to and including the one that failed in its
        `.results` attribute -- callers must not let the partial
        audit trail collected so far be discarded just because the
        batch as a whole didn't finish.
        """
        def _report(result):
            # A caller streaming this into a UI (job log / live command
            # table) is not a reason to abort an otherwise-successful
            # config push -- same reasoning as BaseDriver._log()
            # swallowing its own callback's errors.
            if on_result is None:
                return
            try:
                on_result(result)
            except Exception:
                pass

        results = []
        self._send_timing("system-view", read_timeout=30)
        try:
            for raw_line in lines:
                stripped = (raw_line or "").strip()
                if not stripped or stripped.startswith("#"):
                    continue
                self._log(stripped)
                try:
                    output = self._send_patient(stripped, read_timeout=60)
                except Exception as exc:
                    result = {"line": stripped, "status": "failed", "output": str(exc)}
                    results.append(result)
                    _report(result)
                    raise ConfigPushError(
                        f"Config push aborted at line {len(results)} of the draft "
                        f"('{stripped}'): device did not respond as expected — {exc}",
                        results=results,
                    ) from exc

                if any(marker in output.lower() for marker in self._CONFIG_PUSH_ERROR_MARKERS):
                    result = {"line": stripped, "status": "failed", "output": output.strip()}
                    results.append(result)
                    _report(result)
                    raise ConfigPushError(
                        f"Config push aborted at line {len(results)} of the draft — "
                        f"device rejected '{stripped}': {output.strip()}",
                        results=results,
                    )

                result = {"line": stripped, "status": "success", "output": output.strip()}
                results.append(result)
                _report(result)
        finally:
            # Always try to leave the session back in user-view, even
            # if a line above failed and raised -- a job that aborts
            # partway through shouldn't also strand the SSH session
            # inside system-view for whatever runs next on it (e.g.
            # the save_config() the caller still wants to attempt on
            # whatever was successfully applied before the failure).
            try:
                self._send_timing("quit", read_timeout=15)
            except Exception:
                pass
        return results

    # =========================================================
    # CONFIG CAPTURE / BACKUP — run a fixed list of read-only
    # `display` commands and return each one's raw output, for a
    # point-in-time snapshot of whatever is actually running on the
    # device (typically pulled once a device is done being
    # configured -- via ZTP, Config Push, or by hand -- as an audit
    # record, not while it is still being provisioned).
    # =========================================================

    # Commands whose output can be large or slow to fully print (a full
    # running-config, elabel, license verbose, a big MAC table) get a
    # longer read timeout than routine one-liners like `display
    # version` -- matched by substring against the lowercased command
    # so it also covers piped variants (e.g. `display
    # current-configuration | include route`).
    _CAPTURE_LONG_TIMEOUT_MARKERS = (
        "current-configuration",
        "elabel",
        "mac-address",
        "license",
        "acl all",
    )

    def capture_config(self, commands, on_result=None):
        """Run every command in `commands`, in order, in user-view (no
        system-view needed -- these are all `display`/read-only), and
        return each one's result.

        Deliberately does NOT abort on a failing command: every
        command here is independent and read-only, so one being
        rejected (unsupported on this platform/firmware version,
        wrong syntax for this VRP release, device momentarily busy)
        should not cost the operator every other command's output
        too. Compare to push_config_lines(), which aborts on the
        first rejected line because pushing configuration on top of
        one line's failure is actually risky -- there's no equivalent
        risk here.
        """
        def _report(result):
            if on_result is None:
                return
            try:
                on_result(result)
            except Exception:
                pass

        results = []
        for raw_command in commands:
            command = (raw_command or "").strip()
            if not command:
                continue

            # No separate self._log(command) call here (unlike
            # push_config_lines' loop) -- _send_patient() already logs
            # the command itself via self._log() internally, and
            # calling it again here would double every one of
            # CONFIG_CAPTURE_COMMANDS' ~40 entries in the Execution Log.
            timeout = (
                120
                if any(marker in command.lower() for marker in self._CAPTURE_LONG_TIMEOUT_MARKERS)
                else 60
            )

            try:
                output = self._send_patient(command, read_timeout=timeout)
                result = {"line": command, "status": "success", "output": output.strip()}
            except Exception as exc:
                result = {"line": command, "status": "failed", "output": str(exc)}

            results.append(result)
            _report(result)

        return results

    # =========================================================
    # FIRMWARE TRANSFER — three interchangeable methods.
    # Each accepts `files`: a list of (local_path, remote_filename)
    # pairs, so the mandatory .cc and optional .pat can travel
    # together where the underlying protocol allows it (FTP, matching
    # the Huawei doc's single ftp session with two `get`s) or
    # sequentially where it doesn't (TFTP: one file per session).
    # =========================================================

    def transfer_firmware(self, files):
        """SCP/SFTP push — requires the switch's SFTP server to be
        enabled (it is not, by default, on Huawei VRP)."""
        results = []
        for local_path, remote_filename in files:
            local_path = str(Path(local_path).resolve())
            self._log(f"(SFTP) put {local_path} -> flash:/{remote_filename}")
            try:
                result = file_transfer(
                    self.connection,
                    source_file=local_path,
                    dest_file=remote_filename,
                    file_system="flash:",
                    direction="put",
                    overwrite_file=False,
                    verify_file=True,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Firmware transfer failed for {remote_filename}: {exc} — if SSH "
                    "login works but the transfer itself fails immediately, the "
                    "switch's SFTP/SCP server is very likely disabled (it's off by "
                    "default on Huawei VRP). On the switch, check/enable it with:\n"
                    "  system-view\n"
                    "  sftp server enable\n"
                    "  aaa\n"
                    "   local-user <username> service-type ssh\n"
                    "   local-user <username> privilege level 3\n"
                    "  ssh user <username> authentication-type password\n"
                    "  ssh user <username> service-type sftp\n"
                    "and confirm the SSH user has an assigned work-directory "
                    "(e.g. `ssh user <username> sftp-directory flash:`)."
                ) from exc
            if not result.get("file_verified"):
                raise RuntimeError(f"Firmware transfer verification failed for {remote_filename}: {result}")
            results.append(result)
        return results

    def _wait_for_prompt(self, expect_tokens, read_timeout=10, retries=5, retry_gap=1.0):
        """Keep reading (without sending anything new) until the
        accumulated output contains one of `expect_tokens`, or give up
        after `retries` attempts.

        Login prompts get detected by matching keywords against output
        already captured by a timing-based read — fine when the prompt
        is fast, but a slow banner (arriving after that read's window
        already closed) meant the code concluded no prompt was coming
        and silently moved on to the next command, feeding it into
        whatever prompt was actually still open (observed: a session
        that skipped straight from `ftp <ip>` to `binary` with no
        username/password ever sent). This rides out that gap by
        polling for more output — never re-sending input — before
        giving up.
        """
        output = ""
        for _ in range(retries):
            try:
                output += self.connection.read_channel_timing(read_timeout=read_timeout)
            except Exception:
                pass
            if any(tok in output.lower() for tok in expect_tokens):
                return output
            time.sleep(retry_gap)
        return output

    def transfer_firmware_tftp(self, files, server_ip=None, server_port=69, timeout=300):
        """Have the switch pull each file from a TFTP server we run
        locally. No configuration is needed on the switch — Huawei's
        TFTP client is available out of the box — but this machine
        must be able to bind UDP port 69 (root/administrator
        privileges) and be reachable from the switch on that port.
        Huawei's `tftp ... get` fetches one file per invocation, so
        multiple files are transferred as separate sequential sessions.
        """
        switch_ip = getattr(self.connection, "host", None)
        if not server_ip:
            if not switch_ip:
                raise RuntimeError("Could not determine this machine's IP for the TFTP server.")
            server_ip = self._local_ip_for(switch_ip)

        results = []
        for local_path, remote_filename in files:
            local_path = Path(local_path).resolve()
            server = TftpTransferServer(local_path, remote_filename, bind_ip="0.0.0.0", port=server_port)
            try:
                server.start()
            except TftpServerError as exc:
                raise RuntimeError(str(exc)) from exc

            try:
                output = self._send_timing(f"tftp {server_ip} get {remote_filename}", read_timeout=timeout)
                chunk = output
                for _ in range(4):
                    low = chunk.lower()
                    if any(token in low for token in ["continue", "confirm", "[y/n]", "are you sure"]):
                        chunk = self._send_timing("y", read_timeout=timeout)
                        output += chunk
                    else:
                        break

                ok, detail = server.wait_for_completion(timeout=timeout)
                if not ok:
                    raise RuntimeError(
                        f"TFTP transfer of {remote_filename} did not complete: {detail}\nSwitch output: {output.strip()}"
                    )
                if any(token in output.lower() for token in ["error", "failed", "timed out", "no route"]):
                    raise RuntimeError(f"Switch reported a transfer error for {remote_filename}: {output.strip()}")
                results.append({"file_verified": True, "detail": detail, "switch_output": output.strip()})
            finally:
                server.stop()
        return results

    def transfer_firmware_ftp(self, files, server, server_ip=None, timeout=300):
        """Have the switch pull the file(s) from an FTP server we run
        locally — this is the transfer method shown in Huawei's own
        upgrade documentation (switch as FTP client, PC as FTP
        server). Unlike TFTP, one FTP session can fetch both the
        system-software and patch file, matching the documented
        `ftp <ip>` / `get x.cc` / `get x.pat` / `bye` sequence.

        `server` is a *shared*, already-started FtpTransferServer
        (one per upgrade job, reused across every device in that job)
        rather than something this method starts/stops itself. That's
        what makes it safe to call this concurrently for several
        devices at once: each call opens its own independent
        username/password session on the same already-bound control
        port instead of each device trying to bind that port for
        itself (which only the first one could ever succeed at).
        """
        switch_ip = getattr(self.connection, "host", None)
        if not server_ip:
            if not switch_ip:
                raise RuntimeError("Could not determine this machine's IP for the FTP server.")
            server_ip = self._local_ip_for(switch_ip)

        serve_dir = {Path(local_path).resolve().parent for local_path, _ in files}
        if len(serve_dir) != 1:
            raise RuntimeError("All files in one FTP transfer must live in the same local directory.")
        serve_dir = next(iter(serve_dir))
        expected_files = [remote_filename for _, remote_filename in files]

        try:
            username, password = server.open_session(serve_dir, expected_files)
        except FtpServerError as exc:
            raise RuntimeError(str(exc)) from exc

        try:
            last_output = self._send_timing(f"ftp {server_ip}", read_timeout=timeout)
            full_transcript = last_output
            if not any(tok in last_output.lower() for tok in ("user", "password")):
                extra = self._wait_for_prompt(("user", "password"))
                last_output += extra
                full_transcript += extra

            login_completed = False
            for _ in range(3):
                low = last_output.lower()
                last_line = last_output.strip().splitlines()[-1].lower() if last_output.strip() else ""
                if "password" in low or "password" in last_line:
                    last_output = self._send_timing(password, read_timeout=timeout)
                    full_transcript += last_output
                    login_completed = True
                    break
                if "user" in low or "user" in last_line:
                    last_output = self._send_timing(username, read_timeout=timeout)
                    full_transcript += last_output
                    if "password" not in last_output.lower():
                        extra = self._wait_for_prompt(("password",))
                        last_output += extra
                        full_transcript += extra
                    continue
                break

            if not login_completed:
                raise RuntimeError(
                    "FTP login prompt never appeared (no Username/Password prompt "
                    "detected from the switch) — aborting instead of sending further "
                    "commands into an unknown session state.\n"
                    f"Switch output so far: {full_transcript.strip()}"
                )
            if any(tok in last_output.lower() for tok in ("incorrect", "failed", "denied", "530", "not logged in")):
                raise RuntimeError(f"FTP login was rejected by the switch.\nSwitch output: {full_transcript.strip()}")

            # Force binary (image / TYPE I) transfer mode before pulling any
            # firmware file. FTP clients — Huawei's included — default a
            # fresh session to ASCII (TYPE A) mode, which silently rewrites
            # certain byte sequences (treated as line endings) in whatever
            # gets transferred. Harmless for text, but it corrupts a binary
            # .cc/.pat image: the `get` itself reports success and the file
            # size can even look right, yet the switch's own
            # `startup system-software` integrity check then rejects it
            # ("the system file in slot X is invalid, please check the
            # file."). Huawei's documented upgrade procedure explicitly
            # issues `binary` before `get` for exactly this reason.
            full_transcript += self._send_timing("binary", read_timeout=timeout)

            for remote_filename in expected_files:
                full_transcript += self._send_timing(f"get {remote_filename}", read_timeout=timeout)

                # Wait for OUR side to confirm THIS file specifically was
                # fully sent before sending anything else — another `get`,
                # or `bye`. send_command_timing's pause-based heuristic
                # returns as soon as output goes quiet for a moment, which
                # can be well before the switch is actually done (observed:
                # a 227MB .cc's `get` returning control after ~3s, nowhere
                # near enough time for that transfer to really finish).
                # Sending the next command into a still-busy interactive
                # ftp session risks it being dropped or misread by the
                # switch's CLI — very likely why a file transfer would
                # report success but the file never actually lands on
                # flash. Confirming per-file completion via our local
                # server (which only fires once the bytes are truly fully
                # sent) avoids that race entirely.
                file_ok = server.wait_for_file(username, remote_filename, timeout=timeout)
                if not file_ok:
                    raise RuntimeError(
                        f"FTP transfer of {remote_filename} did not complete within {timeout}s.\n"
                        f"Switch output: {full_transcript.strip()}"
                    )
                # Brief settle so the switch has a moment to finish
                # committing to flash / return to the ftp> prompt before
                # we send the next command.
                time.sleep(2)

            full_transcript += self._send_timing("bye", read_timeout=timeout)

            ok, detail = server.wait_for_completion(username, timeout=5)
            if not ok:
                detail = f"All {len(expected_files)} file(s) individually confirmed sent."
            # Numeric FTP reply codes (550/552/etc) MUST be matched with word
            # boundaries, not bare substring containment — a byte count or
            # transfer speed in the transcript (e.g. "10415527" bytes) can
            # easily contain a false "552" in the middle of unrelated
            # digits. Text phrases are safe to match as plain substrings.
            numeric_error_codes = ["530", "550", "551", "552", "553", "425", "426", "452"]
            text_error_tokens = [
                "login incorrect", "no such file", "not found", "error",
                "failed", "incomplete", "insufficient", "no space", "disk full",
            ]
            lower_transcript = full_transcript.lower()
            numeric_hit = any(re.search(rf"\b{code}\b", lower_transcript) for code in numeric_error_codes)
            text_hit = any(token in lower_transcript for token in text_error_tokens)
            if numeric_hit or text_hit:
                raise RuntimeError(f"Switch reported an FTP error: {full_transcript.strip()}")
            return [{"file_verified": True, "detail": detail, "switch_output": full_transcript.strip()} for _ in files]
        finally:
            server.close_session(username)

    @staticmethod
    def _local_ip_for(remote_ip):
        """Best-effort discovery of which local IP the switch would see
        us as, by asking the OS which interface it would route through
        to reach the switch (no packets are actually sent)."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((remote_ip, 1))
            return probe.getsockname()[0]

    def verify_md5(self, filename, checksum):
        if not checksum:
            return {"verified": True, "message": "No checksum on file; skipping MD5 verification."}
        output = self._send(f"check md5 flash:/{filename}", read_timeout=600)
        normalized = re.sub(r"[^a-fA-F0-9]", "", output).lower()
        expected = re.sub(r"[^a-fA-F0-9]", "", checksum).lower()
        return {"verified": expected in normalized, "output": output}

    def install_firmware(self, filename):
        # Confirmed working against a real S5735 (2026-08-28): use the
        # full "flash:/<file>" path, not a bare filename. Always run —
        # the .cc file is mandatory.
        #
        # Uses _send_timing_patient() (not the plain _send_timing())
        # because `startup system-software` can spend well over 120s
        # continuously validating a large image with no pause in its
        # output, which used to hit netmiko's absolute ReadTimeout and
        # abort here. Aborting here is worse than just slow: if the
        # switch was still actually validating the image in the
        # background when we gave up and disconnected, its own
        # package-management lock doesn't get released just because
        # our CLI session went away -- every later attempt (even a
        # fresh one, even from a different tool entirely) then fails
        # immediately with "Another user is performing package
        # management operations", because from the switch's own
        # perspective that earlier operation may still be running.
        output = self._send_timing_patient(f"startup system-software flash:/{filename}", read_timeout=250)
        if any(token in output.lower() for token in ["continue", "confirm", "[y/n]", "[y/n]:"]):
            output += self._send_timing_patient("y", read_timeout=250)
        if any(token in output.lower() for token in ["error", "failed", "does not exist", "invalid"]):
            raise RuntimeError(output.strip())
        return output

    def install_patch(self, filename):
        """Set the optional patch package for next startup. Confirmed
        working against a real S5735 (2026-08-28): needs the full
        "flash:/<file>" path plus a trailing "all" (applies the patch
        across all slots/members). Only ever called when a patch file
        was actually staged alongside the .cc (the .cc is mandatory on
        its own; the patch is not).

        Same _send_timing_patient() reasoning as install_firmware()
        above -- this can also run long with continuous output on a
        real device."""
        output = self._send_timing_patient(f"startup patch flash:/{filename} all", read_timeout=250)
        if any(token in output.lower() for token in ["continue", "confirm", "[y/n]", "[y/n]:"]):
            output += self._send_timing_patient("y", read_timeout=250)
        if any(token in output.lower() for token in ["error", "failed", "does not exist", "invalid"]):
            raise RuntimeError(output.strip())
        return output

    def save_config(self):
        # Two things a naive "keep answering y/n until it stops" loop
        # gets wrong here:
        #  1. It must check only the LATEST chunk of output each round,
        #     not the whole accumulated transcript — otherwise an
        #     earlier, already-answered "[Y/N]" is still sitting in the
        #     accumulated text and keeps re-matching, sending extra "y"
        #     answers into whatever prompt comes next.
        #  2. On a switch with no startup-saved-configuration file set
        #     yet, `save` asks for a FILENAME after the [Y/N] warning
        #     ("Please input the file name(*.cfg, *.zip, *.dat):") —
        #     that's not a yes/no prompt, and answering it with "y" gets
        #     rejected as an invalid filename, which then cascades into
        #     "Unrecognized command" on whatever's sent next.
        prompt_tokens = (
            "please input the file name", "input the file name",
            "continue", "confirm", "[y/n]", "are you sure",
        )
        chunk = self._send_timing_patient("save", read_timeout=300)
        full_transcript = chunk
        for _ in range(4):
            low = chunk.lower()
            if not any(tok in low for tok in prompt_tokens):
                # A confirmation or filename prompt can arrive a moment
                # after our read window already closed -- the exact
                # same race already fixed for the FTP login prompt
                # (_wait_for_prompt below). Poll a few more times,
                # read-only, before concluding there's really nothing
                # left to answer -- otherwise a delayed prompt gets
                # silently missed and the switch is left sitting at an
                # unanswered [Y/N] forever, which from the outside just
                # looks like "the job never finished".
                extra = self._wait_for_prompt(prompt_tokens, read_timeout=15, retries=3)
                full_transcript += extra
                chunk = extra
                low = chunk.lower()
            if any(tok in low for tok in ("please input the file name", "input the file name")):
                chunk = self._send_timing_patient("config.cfg", read_timeout=300)
                full_transcript += chunk
                continue
            if any(tok in low for tok in ("continue", "confirm", "[y/n]", "are you sure")):
                chunk = self._send_timing_patient("y", read_timeout=300)
                full_transcript += chunk
                continue
            break
        if any(tok in full_transcript.lower() for tok in ("error", "failed", "invalid file name")):
            raise RuntimeError(full_transcript.strip())
        return full_transcript

    def reload_device(self):
        # Plain "reboot" — confirmed working against a real S5735
        # (2026-08-28). "reboot fast" skips pre-reboot diagnostics and
        # was never actually verified against this platform; don't
        # reintroduce it without testing it explicitly.
        # Same "check only the latest chunk" fix as save_config() — an
        # already-answered confirmation staying in the accumulated
        # transcript would otherwise keep re-triggering extra "y"
        # answers on later rounds.
        prompt_tokens = ("continue", "confirm", "[y/n]", "are you sure")
        chunk = self._send_timing_patient("reboot", read_timeout=200)
        full_transcript = chunk
        for _ in range(4):
            low = chunk.lower()
            if not any(tok in low for tok in prompt_tokens):
                # Same delayed-prompt race as save_config() above --
                # confirmed against real hardware: a job's Execution
                # Log showed "$ reboot" sent but no "$ y" ever
                # followed, and the switch was found still sitting at
                # an unanswered [Y/N]: prompt on manual console check
                # (it only rebooted once the user answered "y"
                # manually). Poll read-only for a bit before deciding
                # there's genuinely no prompt to answer.
                extra = self._wait_for_prompt(prompt_tokens, read_timeout=15, retries=3)
                full_transcript += extra
                chunk = extra
                low = chunk.lower()
            if any(tok in low for tok in prompt_tokens):
                chunk = self._send_timing_patient("y", read_timeout=200)
                full_transcript += chunk
            else:
                break
        return full_transcript

    def post_check(self):
        """Matches the documentation's upgrade-verification table:
        check startup software/patch, patch running-state, any
        remaining version inconsistency, and component health."""
        info = self.get_device_info()
        info["startup"] = self.get_startup_info()
        try:
            info["patch_information"] = self._send("display patch-information", read_timeout=60)
        except Exception as exc:
            info["patch_information"] = f"(unavailable: {exc})"
        try:
            info["version_check"] = self._send("check version", read_timeout=60)
        except Exception as exc:
            info["version_check"] = f"(unavailable: {exc})"
        try:
            info["device_status"] = self._send("display device", read_timeout=60)
        except Exception as exc:
            info["device_status"] = f"(unavailable: {exc})"
        return info
