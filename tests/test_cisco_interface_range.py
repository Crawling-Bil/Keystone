import os
import tempfile
import unittest

from features.configuration_studio.converter_engine.parsers.switch.cisco import (
    CiscoSwitchParser,
)


class ExpandInterfaceRangeTest(unittest.TestCase):
    """
    "interface range GigabitEthernet1/0/1 - 24" used to parse as one
    bogus Interface literally named "range GigabitEthernet1/0/1 - 24".
    expand_interface_range turns a range spec into the real list of
    individual full interface names it represents.
    """

    def setUp(self):
        self.parser = CiscoSwitchParser()

    def test_single_contiguous_range(self):
        names = self.parser.expand_interface_range(
            "GigabitEthernet1/0/1 - 24"
        )
        self.assertEqual(len(names), 24)
        self.assertEqual(names[0], "GigabitEthernet1/0/1")
        self.assertEqual(names[-1], "GigabitEthernet1/0/24")

    def test_comma_separated_groups(self):
        names = self.parser.expand_interface_range(
            "GigabitEthernet1/0/1 - 4, GigabitEthernet1/0/8"
        )
        self.assertEqual(
            names,
            [
                "GigabitEthernet1/0/1",
                "GigabitEthernet1/0/2",
                "GigabitEthernet1/0/3",
                "GigabitEthernet1/0/4",
                "GigabitEthernet1/0/8",
            ],
        )

    def test_abbreviated_prefix_is_resolved(self):
        names = self.parser.expand_interface_range("Gi1/0/1 - 3")
        self.assertEqual(
            names,
            [
                "GigabitEthernet1/0/1",
                "GigabitEthernet1/0/2",
                "GigabitEthernet1/0/3",
            ],
        )

    def test_group_with_no_recognizable_shape_is_dropped(self):
        # No digits at all -> doesn't even match the group shape, so
        # it's dropped rather than becoming a bogus interface name.
        names = self.parser.expand_interface_range("not-a-real-range")
        self.assertEqual(names, [])

    def test_unknown_interface_type_is_kept_literal_not_dropped(self):
        # Matches the "<type><slot/port>" shape but the type prefix
        # isn't a known Cisco interface type or abbreviation -- kept
        # as a literal name (still visible for manual review) rather
        # than silently discarded.
        names = self.parser.expand_interface_range("Weird1/0/1 - 3")
        self.assertEqual(names, ["Weird1/0/1-3"])


class InterfaceRangeParsingIntegrationTest(unittest.TestCase):
    """
    End-to-end: an "interface range" block's sub-commands must be
    mirrored onto every expanded port, matching real IOS "interface
    range" semantics.
    """

    def setUp(self):
        self.parser = CiscoSwitchParser()

    def _parse(self, text):
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            encoding="utf-8",
        ) as handle:
            handle.write(text)
            path = handle.name

        try:
            return self.parser.parse_file(path)
        finally:
            os.unlink(path)

    def test_range_sub_commands_apply_to_every_expanded_port(self):
        config_text = """
hostname TEST-SW
!
interface range GigabitEthernet1/0/1 - 3
 switchport mode access
 switchport access vlan 20
 description Access Ports
!
end
"""
        config = self._parse(config_text)

        expanded = [
            interface
            for interface in config.interfaces
            if interface.name.startswith("GigabitEthernet1/0/")
        ]

        self.assertEqual(len(expanded), 3)

        for interface in expanded:
            self.assertEqual(interface.mode, "access")
            self.assertEqual(interface.access_vlan, 20)
            self.assertEqual(interface.description, "Access Ports")

    def test_single_interface_still_works_after_range_support_added(self):
        config_text = """
hostname TEST-SW
!
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 30
!
end
"""
        config = self._parse(config_text)
        self.assertEqual(len(config.interfaces), 1)
        interface = config.interfaces[0]
        self.assertEqual(interface.name, "GigabitEthernet1/0/5")
        self.assertEqual(interface.access_vlan, 30)


if __name__ == "__main__":
    unittest.main()
