import unittest
from unittest.mock import patch

from features.ztp.core import net_interfaces as nif


class _FakeAddr:
    def __init__(self, family, address):
        self.family = family
        self.address = address


class _FakeStats:
    def __init__(self, isup):
        self.isup = isup


class ListInterfacesTests(unittest.TestCase):
    def _patch_psutil(self, addrs, stats):
        return patch.multiple(
            nif.psutil,
            net_if_addrs=lambda: addrs,
            net_if_stats=lambda: stats,
        )

    def test_excludes_down_interfaces_by_default(self):
        addrs = {
            "en0": [_FakeAddr(nif.socket.AF_INET, "192.168.1.5")],
            "en5": [_FakeAddr(nif.socket.AF_INET, "10.0.0.5")],
        }
        stats = {"en0": _FakeStats(True), "en5": _FakeStats(False)}
        with self._patch_psutil(addrs, stats):
            result = nif.list_interfaces()
        self.assertEqual([entry["name"] for entry in result], ["en0"])

    def test_includes_down_interfaces_when_requested(self):
        addrs = {"en5": [_FakeAddr(nif.socket.AF_INET, "10.0.0.5")]}
        stats = {"en5": _FakeStats(False)}
        with self._patch_psutil(addrs, stats):
            result = nif.list_interfaces(include_down=True)
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]["up"])

    def test_excludes_loopback_by_default(self):
        addrs = {"lo": [_FakeAddr(nif.socket.AF_INET, "127.0.0.1")]}
        stats = {"lo": _FakeStats(True)}
        with self._patch_psutil(addrs, stats):
            result = nif.list_interfaces()
        self.assertEqual(result, [])

    def test_includes_loopback_when_requested(self):
        addrs = {"lo": [_FakeAddr(nif.socket.AF_INET, "127.0.0.1")]}
        stats = {"lo": _FakeStats(True)}
        with self._patch_psutil(addrs, stats):
            result = nif.list_interfaces(include_loopback=True)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "lo")

    def test_excludes_interfaces_with_no_ipv4_address(self):
        addrs = {"en9": [_FakeAddr(nif.socket.AF_INET6, "fe80::1")]}
        stats = {"en9": _FakeStats(True)}
        with self._patch_psutil(addrs, stats):
            result = nif.list_interfaces()
        self.assertEqual(result, [])

    def test_captures_mac_address_alongside_ipv4(self):
        link_family = getattr(nif.psutil, "AF_LINK", "AF_LINK")
        addrs = {
            "en7": [
                _FakeAddr(nif.socket.AF_INET, "192.168.99.5"),
                _FakeAddr(link_family, "ac:de:48:00:11:22"),
            ],
        }
        stats = {"en7": _FakeStats(True)}
        with self._patch_psutil(addrs, stats):
            result = nif.list_interfaces()
        self.assertEqual(result[0]["ipv4_addresses"], ["192.168.99.5"])
        self.assertEqual(result[0]["mac"], "ac:de:48:00:11:22")

    def test_up_interfaces_sort_before_down_ones(self):
        addrs = {
            "en_down": [_FakeAddr(nif.socket.AF_INET, "10.0.0.1")],
            "en_up": [_FakeAddr(nif.socket.AF_INET, "10.0.0.2")],
        }
        stats = {"en_down": _FakeStats(False), "en_up": _FakeStats(True)}
        with self._patch_psutil(addrs, stats):
            result = nif.list_interfaces(include_down=True)
        self.assertEqual([entry["name"] for entry in result], ["en_up", "en_down"])


if __name__ == "__main__":
    unittest.main()
