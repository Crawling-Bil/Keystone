"""Shared, multi-session local FTP server for firmware transfer.

Huawei's own documented upgrade procedure (see the "Example for
Upgrading a New Device" guide) has the switch act as an FTP *client*
that connects out to a PC running an FTP *server* and pulls the
system-software (and optionally patch) file with `get`. This module
is that server.

Built on pyftpdlib (a well-established pure-Python FTP server
library) rather than hand-rolled, since a correct FTP server needs to
handle both active and passive data connections plus the full control
command set — much more surface area than TFTP's handful of opcodes.

This server binds its control port EXACTLY ONCE and can then serve any
number of concurrent, independently-authenticated client sessions —
which is completely ordinary behaviour for a real FTP server (many
clients, one listening socket). Each firmware transfer (one per
device being upgraded) calls `open_session()` to get its own
random username/password pointed at its own serve directory, uses it
to run the switch-side `ftp <ip>` / login / get sequence exactly as
before, and calls `close_session()` when done.

An earlier version of this module created a brand new server (trying
to bind the control port again) for every single transfer. That's
fine for one device at a time, but as soon as two firmware upgrades
ran together the second server's bind failed outright (port already
in use by the first) and that device's transfer never even started.
Binding once and layering sessions on top fixes that without needing
a different port per device, so the switch-side command stays
identical (`ftp <server-ip>`, no port argument) for every device,
sequential or parallel — that exact command sequence is the one
that's been confirmed working against real hardware.
"""

from __future__ import annotations

import logging
import secrets
import string
import threading
import time
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

logging.getLogger("pyftpdlib").setLevel(logging.WARNING)


class FtpServerError(RuntimeError):
    pass


def _random_token(length=12):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


class _CompletionHandler(FTPHandler):
    """Tracks RETR (download/get) completions per logged-in username,
    so each concurrent session's caller can independently tell when
    its own expected file(s) have been fully sent — without seeing or
    being affected by any other session's files."""

    server_ref = None

    def on_file_sent(self, file):
        server = self.server_ref
        username = getattr(self, "username", None)
        if server is None or not username:
            return
        name = Path(file).name
        with server._lock:
            session = server._sessions.get(username)
            if session is None:
                return
            session["completed"].add(name)
            if session["expected"] and session["expected"] <= session["completed"]:
                session["event"].set()


class FtpTransferServer:
    """Bind once, serve many concurrent single-purpose sessions.

    Usage:
        server = FtpTransferServer(port=21)
        server.start()
        ... once per device, possibly from different threads ...
        username, password = server.open_session(serve_dir, ["fw.cc", "fw.pat"])
        ... run the switch-side `ftp <ip>` / login / get sequence
            using that username/password/server.port ...
        ok = server.wait_for_file(username, "fw.cc", timeout=300)
        server.close_session(username)
        ... once the whole job is done ...
        server.stop()
    """

    def __init__(self, bind_ip="0.0.0.0", port=21):
        self.bind_ip = bind_ip
        self.port = port
        self._server = None
        self._thread = None
        self._authorizer = DummyAuthorizer()
        self._lock = threading.Lock()
        self._sessions = {}

    def start(self):
        if self._server is not None:
            return

        handler = type("_Handler", (_CompletionHandler,), {})
        handler.authorizer = self._authorizer
        handler.banner = "NES firmware staging server ready."
        handler.passive_ports = range(60000, 60200)
        handler.server_ref = self

        try:
            self._server = FTPServer((self.bind_ip, self.port), handler)
        except PermissionError as exc:
            raise FtpServerError(
                f"Could not bind TCP port {self.port} — the standard FTP "
                "control port (21) needs administrator/root privileges on "
                "most systems. Run the app with elevated privileges, or "
                "use SFTP/TFTP instead."
            ) from exc
        except OSError as exc:
            raise FtpServerError(f"Could not bind TCP port {self.port}: {exc}") from exc

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def open_session(self, serve_dir, expected_files):
        """Register one new authenticated session serving `serve_dir`
        (read-only), tracked independently of every other session
        currently open on this same server. Returns (username, password)
        for the caller to log in with."""
        serve_dir = Path(serve_dir)
        if not serve_dir.is_dir():
            raise FtpServerError(f"Serve directory not found: {serve_dir}")
        for name in expected_files:
            if not (serve_dir / name).exists():
                raise FtpServerError(f"Expected file not found in serve dir: {name}")

        username = f"nes_{_random_token(6)}"
        password = _random_token(16)

        with self._lock:
            self._authorizer.add_user(
                username, password, str(serve_dir),
                perm="elr",  # enter dir, list, retrieve — read-only, no write/delete
            )
            self._sessions[username] = {
                "expected": set(expected_files),
                "completed": set(),
                "event": threading.Event(),
            }

        return username, password

    def close_session(self, username):
        with self._lock:
            self._sessions.pop(username, None)
            try:
                self._authorizer.remove_user(username)
            except KeyError:
                pass

    def wait_for_file(self, username, filename, timeout=300, poll_interval=0.25):
        """Block until this SPECIFIC session's file has been fully sent,
        or timeout. Used when one session serves multiple files in
        sequence (the switch issues one `get` per file): the caller
        needs to know each individual file actually finished before
        sending the switch's CLI its next command, rather than only
        finding out once every expected file is done."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                session = self._sessions.get(username)
                completed = set(session["completed"]) if session else set()
            if filename in completed:
                return True
            time.sleep(poll_interval)
        return False

    def wait_for_completion(self, username, timeout=300):
        with self._lock:
            session = self._sessions.get(username)
        if session is None:
            return False, "Session not found (already closed?)."

        finished = session["event"].wait(timeout)

        with self._lock:
            session = self._sessions.get(username)
            completed = set(session["completed"]) if session else set()
            expected = set(session["expected"]) if session else set()

        if not finished:
            missing = expected - completed
            return False, f"Timed out after {timeout}s waiting for: {', '.join(sorted(missing)) or 'unknown file(s)'}."
        return True, f"Transferred: {', '.join(sorted(expected))}."

    def stop(self):
        if self._server:
            try:
                self._server.close_all()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None
        with self._lock:
            self._sessions.clear()
