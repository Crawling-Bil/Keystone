"""Read-only SFTP server for ZTP file serving.

Huawei's ZTP (this VRP family) requires the intermediate file AND the
deployment files (config, firmware) to be served over SFTP specifically
-- plain FTP/TFTP are documented as NOT valid for this ("the file
server must be an SFTP file server"). That's a different transport
than the FTP/TFTP servers already in this package (core/ftp_server.py,
core/tftp_server.py), which exist for a different phase entirely (in-
job firmware transfer to a device that's already SSH-managed) and
can't be reused here.

Unlike ftp_server.py's per-job random session credentials, ZTP
credentials must be STABLE and known in advance: the same
username/password gets baked into the DHCP server's Option 67 value
and into every intermediate file's FILESERVER field, before any device
has been dealt with individually. Per-device targeting happens via ESN
matching *inside* the intermediate file, not via distinct SFTP logins.
So this server is intentionally single-credential, read-only, and
scoped to one directory (the "ZTP root") containing the current
intermediate file, every device's bootstrap config, and whichever
firmware files are in use.

Built on paramiko (already a project dependency) rather than a
higher-level SFTP library, because we need a *server*, not a client --
paramiko is one of the few well-maintained Python packages that
provides the server side of the SFTP protocol.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from pathlib import Path

import paramiko

logger = logging.getLogger("nes.lifecycle.ztp.sftp")
# paramiko is chatty at INFO/DEBUG (auth attempts, transport
# negotiation) -- quiet it the same way ftp_server.py already
# does for pyftpdlib.
logging.getLogger("paramiko").setLevel(logging.WARNING)

_HOST_KEY_FILENAME = ".ztp_sftp_host_key"


class SftpServerError(RuntimeError):
    pass


def _get_or_create_host_key(data_dir: Path) -> paramiko.RSAKey:
    """A stable host key (persisted like app.py's own secret key) so
    the server doesn't present a brand new host identity on every
    restart. Not security-critical for this use case (ZTP devices
    generally don't pin the file server's host key), but there's no
    reason to regenerate one every time either."""
    key_path = data_dir / _HOST_KEY_FILENAME
    if key_path.exists():
        try:
            return paramiko.RSAKey(filename=str(key_path))
        except (paramiko.SSHException, OSError):
            pass
    data_dir.mkdir(parents=True, exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    try:
        key.write_private_key_file(str(key_path))
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key


class _ReadOnlySftpHandle(paramiko.SFTPHandle):
    def stat(self):
        try:
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def chattr(self, attr):
        return paramiko.SFTP_PERMISSION_DENIED


class _ReadOnlySftpServerInterface(paramiko.SFTPServerInterface):
    """Confines every path to `root_dir` and refuses anything that
    would write, delete, or rename. `canonicalize()` is the load-
    bearing method here -- everything else operates on its output, so
    that's where path-traversal (`../../etc/passwd` etc.) is closed
    off."""

    def __init__(self, server, root_dir, on_file_request=None, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.root_dir = str(Path(root_dir).resolve())
        self._on_file_request = on_file_request

    def _resolve(self, path):
        # SFTP paths are POSIX-style regardless of host OS; normalize
        # against the confined root rather than trusting the client.
        candidate = os.path.normpath(os.path.join(self.root_dir, path.lstrip("/")))
        if candidate != self.root_dir and not candidate.startswith(self.root_dir + os.sep):
            # Escaped the root — pretend it simply doesn't exist.
            return None
        return candidate

    def canonicalize(self, path):
        resolved = self._resolve(path)
        if resolved is None:
            return path
        relative = os.path.relpath(resolved, self.root_dir)
        return "/" if relative == "." else "/" + relative.replace(os.sep, "/")

    def list_folder(self, path):
        resolved = self._resolve(path)
        if resolved is None or not os.path.isdir(resolved):
            return paramiko.SFTP_NO_SUCH_FILE
        entries = []
        try:
            for name in os.listdir(resolved):
                attr = paramiko.SFTPAttributes.from_stat(os.stat(os.path.join(resolved, name)))
                attr.filename = name
                entries.append(attr)
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        return entries

    def stat(self, path):
        resolved = self._resolve(path)
        if resolved is None:
            return paramiko.SFTP_NO_SUCH_FILE
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(resolved))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    lstat = stat

    def open(self, path, flags, attr):
        # Check write-intent BEFORE existence, so an attempt to create
        # a new file (which by definition doesn't exist yet) is
        # correctly reported as "denied", not "not found".
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            return paramiko.SFTP_PERMISSION_DENIED
        resolved = self._resolve(path)
        if resolved is None or not os.path.isfile(resolved):
            if self._on_file_request:
                try:
                    self._on_file_request(path, False)
                except Exception:
                    pass
            return paramiko.SFTP_NO_SUCH_FILE
        try:
            binary_flags = os.O_RDONLY | (os.O_BINARY if hasattr(os, "O_BINARY") else 0)
            fd = os.open(resolved, binary_flags)
            handle = _ReadOnlySftpHandle(flags)
            handle.readfile = os.fdopen(fd, "rb")
            if self._on_file_request:
                try:
                    self._on_file_request(path, True)
                except Exception:
                    pass
            return handle
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    # Every mutating operation is explicitly denied rather than left to
    # paramiko's default (which may otherwise no-op silently).
    def remove(self, path):
        return paramiko.SFTP_PERMISSION_DENIED

    def rename(self, oldpath, newpath):
        return paramiko.SFTP_PERMISSION_DENIED

    def mkdir(self, path, attr):
        return paramiko.SFTP_PERMISSION_DENIED

    def rmdir(self, path):
        return paramiko.SFTP_PERMISSION_DENIED

    def chattr(self, path, attr):
        return paramiko.SFTP_PERMISSION_DENIED

    def symlink(self, target_path, path):
        return paramiko.SFTP_PERMISSION_DENIED

    def readlink(self, path):
        return paramiko.SFTP_OP_UNSUPPORTED


def _make_server_interface(username, password):
    class _AuthServer(paramiko.ServerInterface):
        def check_auth_password(self, auth_username, auth_password):
            if auth_username == username and auth_password == password:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        def get_allowed_auths(self, auth_username):
            return "password"

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_channel_subsystem_request(self, channel, name):
            if name != "sftp":
                return False
            return super().check_channel_subsystem_request(channel, name)

    return _AuthServer


class ZtpSftpServer:
    """One fixed-credential, read-only SFTP server confined to
    `root_dir`. Usage:

        server = ZtpSftpServer(root_dir, username, password, bind_ip="0.0.0.0", port=2222)
        server.start()
        ...
        server.stop()

    Port 2222 (not 22) by default so this doesn't collide with an SSH
    daemon that might already be running on the same host — the
    DHCP Option 67 FILESERVER URL just needs to name whatever port is
    actually in use (sftp://user:pass@host:2222/...).
    """

    def __init__(self, root_dir, username, password, bind_ip="0.0.0.0", port=2222, data_dir=None,
                 max_session_seconds=900, on_file_request=None):
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.username = username
        self.password = password
        self.bind_ip = bind_ip
        self.port = port
        self._data_dir = Path(data_dir) if data_dir else self.root_dir
        self._host_key = None
        self._sock = None
        self._thread = None
        self._stop_event = threading.Event()
        # A stalled/abandoned client (one that opens a transport and then
        # goes silent without cleanly closing it -- confirmed on real
        # hardware: a ZTP client that gives up on a slow transfer and
        # reconnects, without the old TCP connection ever seeing a clean
        # close) would otherwise pin a thread AND a socket/file-descriptor
        # for as long as this process runs, since transport.is_active()
        # keeps reporting True for a half-dead peer with no idle timeout
        # of its own. Repeated across many retries in one long-running
        # Keystone session, that's exactly the kind of slow resource leak
        # that (confirmed against real hardware) eventually manifests as
        # "Connection reset by peer" / "Can't assign requested address"
        # cascades once the OS runs out of ephemeral ports/fds -- so any
        # single session gets force-closed past this ceiling rather than
        # being trusted to end on its own. 900s (15 min) comfortably
        # exceeds the ~7 minutes a real full firmware transfer took here.
        self._max_session_seconds = max_session_seconds
        # Fired as on_file_request(client_ip, path, found) for every
        # SFTP open() a connected switch makes -- see activity_log.py
        # and routes.py's wiring. None by default so this stays a
        # no-op for anyone constructing ZtpSftpServer directly (tests,
        # anything outside routes.py) without opting in.
        self.on_file_request = on_file_request

    def start(self):
        if self._thread is not None:
            return
        self._host_key = _get_or_create_host_key(self._data_dir)
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind_ip, self.port))
            self._sock.listen(16)
        except OSError as exc:
            raise SftpServerError(f"Could not bind TCP {self.bind_ip}:{self.port}: {exc}") from exc

        # port=0 means "OS picks a free ephemeral port" -- reflect the
        # port actually bound back onto self.port so callers (the route
        # response, the Generate/DHCP URL auto-fill) see the real value
        # instead of echoing back the literal 0 they asked for.
        self.port = self._sock.getsockname()[1]

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        logger.info("ZTP SFTP server listening on %s:%s, root=%s", self.bind_ip, self.port, self.root_dir)

    def _accept_loop(self):
        self._sock.settimeout(1.0)
        while not self._stop_event.is_set():
            try:
                client_sock, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_client, args=(client_sock, addr), daemon=True
            ).start()

    def _handle_client(self, client_sock, addr):
        transport = None
        try:
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(self._host_key)
            root_dir = self.root_dir
            on_file_request = self.on_file_request
            client_ip = addr[0]

            class _Interface(_ReadOnlySftpServerInterface):
                def __init__(self, server, *args, **kwargs):
                    per_conn_callback = (
                        (lambda path, found: on_file_request(client_ip, path, found))
                        if on_file_request else None
                    )
                    super().__init__(server, root_dir, per_conn_callback, *args, **kwargs)

            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, _Interface)
            server_interface = _make_server_interface(self.username, self.password)()
            transport.start_server(server=server_interface)
            channel = transport.accept(20)
            if channel is None:
                return
            # Keep the transport alive while the client drives SFTP
            # over it; it tears itself down when the channel closes --
            # but only up to _max_session_seconds, so a stalled/abandoned
            # client (see the comment on _max_session_seconds) can't pin
            # this thread and its socket/fd forever.
            session_deadline = time.time() + self._max_session_seconds
            while transport.is_active() and not self._stop_event.is_set():
                if time.time() > session_deadline:
                    logger.warning(
                        "ZTP SFTP session from %s exceeded the %ss session "
                        "cap -- closing it as stalled/abandoned rather than "
                        "letting it hold a thread and socket indefinitely.",
                        addr, self._max_session_seconds,
                    )
                    break
                threading.Event().wait(0.5)
        except (paramiko.SSHException, EOFError, OSError) as exc:
            logger.info("ZTP SFTP session from %s ended: %s", addr, exc)
        finally:
            try:
                if transport is not None:
                    transport.close()
            except Exception:
                pass

    def stop(self):
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._sock = None
        self._thread = None
