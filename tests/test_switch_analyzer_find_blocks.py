"""``find_blocks`` with table headers and the section readers must give what a plain line by line walk gives (they share per-capture indexes)."""

from __future__ import annotations

import re
import unittest

from features.switch_analyzer import capture_text, runtime_parser

CAPTURE = """\
SW1#show interfaces status
Port      Name   Status       Vlan  Duplex  Speed Type
Gi1/0/1   srv    connected    10    a-full  a-1000 10/100/1000BaseTX
Gi1/0/2          notconnect   1     auto    auto   10/100/1000BaseTX
SW1#show ip arp
Protocol  Address      Age (min)  Hardware Addr   Type   Interface
Internet  10.0.0.1            -   0000.0c00.0001  ARPA   Vlan10
SW1#sh mac address-table
Port      Name   Status       Vlan  Duplex  Speed Type
Gi1/0/9          connected    20    a-full  a-1000 10/100/1000BaseTX
SW1#show version
Cisco IOS Software
SW1#show interfaces status
Port      Name   Status       Vlan  Duplex  Speed Type
Gi1/0/3          connected    30    a-full  a-1000 10/100/1000BaseTX
SW1#
""".splitlines()


def reference(lines, patterns=(), headers=()):
    """The walk that find_blocks did before the indexes."""
    compiled = [re.compile(p) for p in patterns]
    header_rx = [re.compile(h, re.IGNORECASE) for h in headers]
    found, index = [], 0
    while index < len(lines):
        parts = capture_text.split_command(lines[index])
        if parts is not None:
            if compiled and any(rx.fullmatch(parts[0]) for rx in compiled):
                block, cursor = capture_text._block_after(lines, index + 1, [parts[1]] if parts[1] else [])
                found.append((index, block))
                index = cursor
                continue
            index += 1
            continue
        if header_rx and any(rx.match(lines[index].strip()) for rx in header_rx):
            block, cursor = capture_text._block_after(lines, index + 1, [lines[index]])
            found.append((index, block))
            index = cursor
            continue
        index += 1
    return found


class FindBlocksTest(unittest.TestCase):
    PATTERNS = [r"show interfaces status", r"show ip arp"]
    HEADERS = [r"Port\s+(?:Name\s+)?Status\s+Vlan\s+Duplex", r"Protocol\s+Address\s+Age"]

    def test_headers_and_patterns_together(self):
        self.assertEqual(capture_text.find_blocks(CAPTURE, self.PATTERNS, self.HEADERS), reference(CAPTURE, self.PATTERNS, self.HEADERS))

    def test_header_only_finds_the_block_whose_echo_was_lost(self):
        got = capture_text.find_blocks(CAPTURE, [], self.HEADERS)
        self.assertEqual(got, reference(CAPTURE, [], self.HEADERS))
        self.assertTrue(any(start == 8 for start, _ in got), "the table under the half-typed 'sh mac address-table' echo is found by its header")

    def test_pattern_only_and_nothing(self):
        self.assertEqual(capture_text.find_blocks(CAPTURE, self.PATTERNS), reference(CAPTURE, self.PATTERNS))
        self.assertEqual(capture_text.find_blocks(CAPTURE), [])

    def test_a_generator_of_headers_is_read_once(self):
        self.assertEqual(capture_text.find_blocks(CAPTURE, self.PATTERNS, (h for h in self.HEADERS)), reference(CAPTURE, self.PATTERNS, self.HEADERS))


class SectionTest(unittest.TestCase):
    def test_first_and_all_occurrences(self):
        first = runtime_parser._extract_section(CAPTURE, ["show interfaces status"])
        self.assertTrue(first and first[0].startswith("Port"))
        self.assertIn("Gi1/0/1", " ".join(first))
        self.assertNotIn("Gi1/0/3", " ".join(first))
        runs = runtime_parser._extract_all_sections(CAPTURE, ["show interfaces status"])
        self.assertEqual([index for index, _ in runs], [0, 12])
        self.assertIn("Gi1/0/3", " ".join(runs[1][1]))

    def test_the_keyword_must_end_the_line(self):
        lines = ["SW1#show cdp neighbors detail", "Device ID: X", "SW1#show cdp neighbors", "Device ID  Local Intrfce", "Y  Gig 1/0/1"]
        section = runtime_parser._extract_section(lines, ["show cdp neighbors"])
        self.assertEqual(section[0], "Device ID  Local Intrfce")

    def test_the_cache_follows_a_new_list(self):
        one = ["SW1#show version", "A"]
        two = ["SW1#show version", "B"]
        self.assertEqual(runtime_parser._extract_section(one, ["show version"]), ["A"])
        self.assertEqual(runtime_parser._extract_section(two, ["show version"]), ["B"])


if __name__ == "__main__":
    unittest.main()
