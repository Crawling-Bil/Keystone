"""Minimal single-file TFTP (RFC 1350) read-only server.

Huawei VRP switches (and most other vendors) ship with a TFTP *client*
enabled out of the box — no configuration needed on the switch. What's
normally missing is a TFTP *server* to pull the file from. This module
is that server: it serves exactly one file to exactly one client, then
stops. It's meant to run for the duration of a single firmware
transfer, not as a long-lived service.

This intentionally implements only what a firmware GET needs: RRQ in
octet ("binary") mode, fixed 512-byte data blocks, and a normal
ACK/DATA/timeout retry loop. Any TFTP option negotiation (RFC 2347)
the client asks for is silently ignored — per the RFC, a client that
gets a DATA/ACK instead of an OACK falls back to default behavior, so
this remains compatible with option-aware clients.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from pathlib import Path

OPCODE_RRQ = 1
OPCODE_DATA = 3
OPCODE_ACK = 4
OPCODE_ERROR = 5

BLOCK_SIZE = 512
RETRY_LIMIT = 5
RETRY_TIMEOUT = 3.0


class TftpServerError(RuntimeError):
    pass


class TftpTransferServer:
    """Serves one specific file to one client, then stops.

    Usage:
        server = TftpTransferServer(local_path, served_name, bind_ip="0.0.0.0", port=69)
        server.start()
        ... trigger the switch's `tftp <server-ip> get <served_name>` ...
        ok, detail = server.wait_for_completion(timeout=180)
        server.stop()
    """

    def __init__(self, local_path, served_name, bind_ip="0.0.0.0", port=69):
        self.local_path = Path(local_path)
        self.served_name = served_name
        self.bind_ip = bind_ip
        self.port = port

        self._socket = None
        self._thread = None
        self._stop_event = threading.Event()
        self._done_event = threading.Event()
        self._result = (False, "Transfer did not start.")

    def start(self):
        if not self.local_path.exists():
            raise TftpServerError(f"Local firmware file not found: {self.local_path}")

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._socket.bind((self.bind_ip, self.port))
        except PermissionError as exc:
            raise TftpServerError(
                f"Could not bind UDP port {self.port} — TFTP requires the "
                "well-known port 69, which needs administrator/root "
                "privileges on most systems. Run the app with elevated "
                "privileges, or use SFTP instead."
            ) from exc
        except OSError as exc:
            raise TftpServerError(f"Could not bind UDP port {self.port}: {exc}") from exc

        self._socket.settimeout(1.0)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def wait_for_completion(self, timeout=180):
        finished = self._done_event.wait(timeout)
        if not finished:
            return False, f"No client requested {self.served_name!r} within {timeout} seconds."
        return self._result

    def stop(self):
        self._stop_event.set()
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    # -- internal --------------------------------------------------

    def _serve(self):
        deadline = time.time() + 300
        while not self._stop_event.is_set() and time.time() < deadline:
            try:
                packet, client_addr = self._socket.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break

            opcode = struct.unpack("!H", packet[:2])[0]
            if opcode != OPCODE_RRQ:
                continue

            try:
                filename, mode = self._parse_rrq(packet)
            except ValueError:
                continue

            if filename != self.served_name:
                self._send_error(client_addr, 1, f"Unknown file: {filename}")
                continue

            ok, detail = self._transfer(client_addr, mode)
            self._result = (ok, detail)
            self._done_event.set()
            return

    @staticmethod
    def _parse_rrq(packet):
        body = packet[2:]
        parts = body.split(b"\x00")
        if len(parts) < 2:
            raise ValueError("Malformed RRQ")
        filename = parts[0].decode("utf-8", errors="replace")
        mode = parts[1].decode("ascii", errors="replace").lower()
        return filename, mode

    def _transfer(self, client_addr, mode):
        try:
            data = self.local_path.read_bytes()
        except OSError as exc:
            self._send_error(client_addr, 0, f"Read error: {exc}")
            return False, f"Could not read local file: {exc}"

        transfer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        transfer_socket.settimeout(RETRY_TIMEOUT)

        block_number = 1
        offset = 0
        total = len(data)

        try:
            while True:
                chunk = data[offset:offset + BLOCK_SIZE]
                sent_ok = self._send_data_block(
                    transfer_socket, client_addr, block_number, chunk
                )
                if not sent_ok:
                    return False, (
                        f"Client stopped acknowledging blocks around byte "
                        f"{offset}/{total}."
                    )
                offset += len(chunk)
                if len(chunk) < BLOCK_SIZE:
                    return True, f"Transferred {total} bytes in {block_number} block(s)."
                block_number = (block_number + 1) % 65536
        finally:
            transfer_socket.close()

    def _send_data_block(self, sock, client_addr, block_number, chunk):
        packet = struct.pack("!HH", OPCODE_DATA, block_number) + chunk
        for _attempt in range(RETRY_LIMIT):
            sock.sendto(packet, client_addr)
            try:
                reply, reply_addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            if reply_addr[0] != client_addr[0]:
                continue
            if len(reply) < 4:
                continue
            reply_opcode, reply_block = struct.unpack("!HH", reply[:4])
            if reply_opcode == OPCODE_ERROR:
                return False
            if reply_opcode == OPCODE_ACK and reply_block == block_number:
                return True
        return False

    def _send_error(self, client_addr, code, message):
        packet = struct.pack("!HH", OPCODE_ERROR, code) + message.encode("utf-8") + b"\x00"
        try:
            self._socket.sendto(packet, client_addr)
        except OSError:
            pass
