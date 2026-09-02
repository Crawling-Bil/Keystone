import shutil
import socket
import tempfile
import time
import unittest
from pathlib import Path

try:
    import paramiko
    HAVE_PARAMIKO = True
except ImportError:
    HAVE_PARAMIKO = False

from features.ztp.core import sftp_server as sftp_mod


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(HAVE_PARAMIKO, "paramiko not installed")
class ZtpSftpServerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.data_dir = Path(tempfile.mkdtemp())
        (self.root / "ztp_script.ini").write_text("dummy intermediate file", encoding="utf-8")
        self.port = _free_port()
        self.server = sftp_mod.ZtpSftpServer(
            root_dir=self.root,
            username="ztp_user",
            password="ztp_pass",
            bind_ip="127.0.0.1",
            port=self.port,
            data_dir=self.data_dir,
        )
        self.server.start()
        time.sleep(0.3)

    def tearDown(self):
        self.server.stop()
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _connect(self, username="ztp_user", password="ztp_pass"):
        transport = paramiko.Transport(("127.0.0.1", self.port))
        transport.connect(username=username, password=password)
        return transport

    def test_on_file_request_fires_for_a_successful_open(self):
        events = []
        self.server.on_file_request = lambda client_ip, path, found: events.append(
            (client_ip, path, found)
        )
        transport = self._connect()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            with sftp.open("ztp_script.ini", "r") as fh:
                fh.read()
        finally:
            transport.close()

        matching = [e for e in events if e[1].endswith("ztp_script.ini")]
        self.assertTrue(matching, f"expected an event for ztp_script.ini, got: {events}")
        client_ip, path, found = matching[0]
        self.assertEqual(client_ip, "127.0.0.1")
        self.assertTrue(found)

    def test_on_file_request_fires_for_a_missing_file(self):
        events = []
        self.server.on_file_request = lambda client_ip, path, found: events.append(
            (client_ip, path, found)
        )
        transport = self._connect()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            with self.assertRaises(IOError):
                sftp.open("does_not_exist.cfg", "r")
        finally:
            transport.close()

        matching = [e for e in events if e[1].endswith("does_not_exist.cfg")]
        self.assertTrue(matching, f"expected a not-found event, got: {events}")
        self.assertFalse(matching[0][2])

    def test_on_file_request_default_none_does_not_break_transfers(self):
        # on_file_request defaults to None (self.server in setUp was
        # built without it) -- a normal read must still work fine.
        transport = self._connect()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            with sftp.open("ztp_script.ini", "r") as fh:
                self.assertEqual(fh.read(), b"dummy intermediate file")
        finally:
            transport.close()

    def test_correct_credentials_can_list_and_read(self):
        transport = self._connect()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            self.assertIn("ztp_script.ini", sftp.listdir("."))
            with sftp.open("ztp_script.ini", "r") as fh:
                self.assertEqual(fh.read(), b"dummy intermediate file")
        finally:
            transport.close()

    def test_wrong_password_is_rejected(self):
        with self.assertRaises(paramiko.AuthenticationException):
            self._connect(password="wrong")

    def test_write_is_denied(self):
        transport = self._connect()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            with self.assertRaises(IOError):
                with sftp.open("new_file.txt", "w") as fh:
                    fh.write("nope")
        finally:
            transport.close()

    def test_delete_is_denied(self):
        transport = self._connect()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            with self.assertRaises(IOError):
                sftp.remove("ztp_script.ini")
        finally:
            transport.close()

    def test_ephemeral_port_zero_is_replaced_by_the_real_bound_port(self):
        # Regression: self.port used to stay whatever was passed in, so a
        # caller that asked for port=0 (let the OS pick one) had no way
        # to find out what it actually got -- every consumer downstream
        # (the /api/sftp/start response, the Generate/Option67 URL
        # auto-fill) would see a useless literal 0 instead of the real
        # port the switch would actually need to connect to.
        server = sftp_mod.ZtpSftpServer(
            root_dir=self.root,
            username="ztp_user",
            password="ztp_pass",
            bind_ip="127.0.0.1",
            port=0,
            data_dir=self.data_dir,
        )
        try:
            server.start()
            self.assertNotEqual(server.port, 0)
            self.assertGreater(server.port, 0)
        finally:
            server.stop()

    def test_path_traversal_is_blocked(self):
        transport = self._connect()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            with self.assertRaises(IOError):
                sftp.open("../../../../etc/passwd", "r")
        finally:
            transport.close()


if __name__ == "__main__":
    unittest.main()
