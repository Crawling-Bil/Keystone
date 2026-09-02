"""UDP syslog receiver for real-time ZTP process visibility.

WHY THIS EXISTS: Huawei's ZTP intermediate-file format (INI) has a
per-device SYSLOG_INFO field -- intermediate_file.py already emits
the key (blank by default) in every DEVICE_TYPE_n DESCRIPTION
section, and it's confirmed straight from a real S5735's own ZTP
engine log that this device's onboard `ztp_base.py` explicitly parses
SYSLOG_INFO out of that section. When set, it's meant to have the
switch forward its ZTP process log lines -- the exact `ztp_base.py:NNN
...` lines this project's testing sessions have so far only ever seen
by hand, via `more flash:/ztp_*.log | include ...` over a console/SSH
session -- to a syslog server in real time while ZTP runs, including
the crucial final "was the config actually accepted as next-startup"
outcome that no amount of watching SFTP transfers can reveal (that
step happens entirely on-device, with no further network call back to
Keystone).

UNVERIFIED, and this is important: the exact value format SYSLOG_INFO
expects. Huawei's own documentation page for this INI table returns
403 to automated fetches as of this writing, so intermediate_file.py
assumes the conventional "<ip>:<port>" form. This is a genuinely
untested guess, not a confirmed fact like the cipher/RSA/SHA256
findings elsewhere in this codebase -- confirm it the next time
deployment files get generated with a syslog target set: if entries
start appearing in the Activity feed while ZTP runs, the format was
right. If the feed stays empty through a full cycle (while SFTP
events still show up fine, proving the receiver itself works), the
device isn't sending anything there, and the format needs adjusting
-- try IP-only next (SYSLOG_INFO=<ip>, default port 514), since some
Huawei per-device INI fields elsewhere in this same table are bare
values without a port suffix.

This is a plain UDP listener -- standard syslog, no TCP, no TLS,
matching every Huawei device's default `info-center loghost` behavior.
Default port 514 is a privileged port (<1024) like dnsmasq's UDP/67
in dhcp_server.py; this module does not attempt to elevate anything
itself -- routes.py either runs Keystone with enough privilege to
bind it, or a high port (>1024) can be used instead if the switch's
side can be pointed at a non-default syslog port.
"""

from __future__ import annotations

import logging
import re
import socket
import threading

logger = logging.getLogger("nes.ztp.syslog")


class SyslogServerError(RuntimeError):
    pass


# Loose match for the exact log shape every manual troubleshooting
# session against this switch has read off `more flash:/ztp_*.log`,
# e.g.:
#   +0000 Jul 12 2026 06:53:21 ERROR    ztp_base.py:352 Set the next ...
# All fields but the trailing message are optional in the pattern so
# a differently-formatted syslog frame (a leading "<PRI>" cookie, a
# hostname/tag syslogd would normally prepend, or the switch just not
# matching this shape at all) still produces a usable message instead
# of silently dropping the line.
_VRP_LOG_RE = re.compile(
    r"^\s*(?:[+-]\d{4}\s+)?"
    r"(?:\w+ \d{1,2} \d{4} \d{2}:\d{2}:\d{2}\s+)?"
    r"(?:(?P<level>DEBUG|INFO|WARNING|ERROR|FATAL)\s+)?"
    r"(?:(?P<source>\S+\.py:\d+)\s+)?"
    r"(?P<message>.*)$"
)

_LEVEL_MAP = {
    "DEBUG": "info",
    "INFO": "info",
    "WARNING": "warning",
    "ERROR": "error",
    "FATAL": "error",
}


def parse_line(raw_text):
    """Best-effort parse of one syslog payload into
    {level, source, message}. Never raises -- an unrecognized shape
    just comes back as {"level": "info", "source": None, "message":
    <the whole decoded text>} so nothing gets silently dropped."""
    text = raw_text.strip()
    # RFC3164-style "<PRI>" framing, if a real syslogd/relay sits in
    # front of the switch instead of it sending straight to us.
    text = re.sub(r"^<\d+>\s*", "", text)
    match = _VRP_LOG_RE.match(text)
    if not match:
        return {"level": "info", "source": None, "message": text}
    message = (match.group("message") or "").strip() or text
    level_key = (match.group("level") or "INFO").upper()
    return {
        "level": _LEVEL_MAP.get(level_key, "info"),
        "source": match.group("source"),
        "message": message,
    }


class ZtpSyslogServer:
    """Threaded UDP syslog receiver. start()/stop()/is_running() mirror
    ZtpDhcpServer and ZtpSftpServer's lifecycle so routes.py can manage
    all three ZTP support servers the same way.

    on_message(source_ip, parsed_dict) is called from the receiver
    thread for every datagram received -- keep it fast and exception-
    safe (exceptions are caught and logged, never allowed to kill the
    receive loop over one bad callback).
    """

    def __init__(self, bind_ip="0.0.0.0", port=514, on_message=None):
        self.bind_ip = bind_ip
        self.port = port
        self.on_message = on_message
        self._sock = None
        self._thread = None
        self._stop_event = threading.Event()

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.is_running():
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.bind_ip, self.port))
            sock.settimeout(0.5)
        except OSError as exc:
            raise SyslogServerError(
                f"Could not bind UDP {self.bind_ip}:{self.port} for the ZTP syslog "
                f"receiver ({exc}). Port 514 is privileged -- Keystone needs root "
                "(or an equivalent capability) to bind it, or use a high port "
                "(>1024) here and point the device's syslog target at that same "
                "port instead."
            ) from exc

        self.port = sock.getsockname()[1]
        self._sock = sock
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        logger.info("ZTP syslog receiver listening on %s:%s (UDP)", self.bind_ip, self.port)

    def _serve(self):
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                continue
            parsed = parse_line(text)
            if self.on_message:
                try:
                    self.on_message(addr[0], parsed)
                except Exception:
                    logger.exception("ZTP syslog on_message callback failed")

    def stop(self):
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
