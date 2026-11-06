"""Convert Switch: "Hide passwords and keys in the output".

Every credential in the three invented sources below is a CANARY value.  With the option on, no canary may be left in any of the six cross-vendor
outputs (the REVIEW comments, the pass-through lines and the working commands alike); with it off the converter keeps the values, as the
Huawei local-user block documents.
"""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path

import pytest

from features.configuration_studio.converter_engine.secret_mask import HIDDEN, count_secret_lines, hide_secrets, mask_line, source_values
from features.configuration_studio.service import convert_file

FIXTURES = Path(__file__).parent / "fixtures" / "secrets"
SOURCES = {"Cisco": "cisco_canary_synthetic.txt", "Huawei": "huawei_canary_synthetic.txt", "Aruba": "aruba_canary_synthetic.txt"}
PAIRS = [(src, tgt) for src in SOURCES for tgt in SOURCES if src != tgt]


def _convert(source: str, target: str, **extra):
    return convert_file(FIXTURES / SOURCES[source], domain="switch", source_vendor=source, target_vendor=target, **extra)


@pytest.mark.parametrize("source,target", PAIRS)
def test_hidden_output_holds_no_canary(source, target):
    shown = _convert(source, target, hide_secrets=True)
    assert "CANARY" not in shown["output_text"]
    assert HIDDEN in shown["output_text"]
    assert shown["secrets"]["hidden"] is True and shown["secrets"]["lines"] > 0


@pytest.mark.parametrize("source,target", PAIRS)
def test_default_keeps_the_values_and_says_so(source, target):
    kept = _convert(source, target)
    assert "CANARY" in kept["output_text"]
    assert kept["secrets"]["hidden"] is False and kept["secrets"]["lines"] > 0


@pytest.mark.parametrize("source,target", PAIRS)
def test_hiding_changes_only_credential_lines(source, target):
    kept = _convert(source, target)["output_text"].split("\n")
    shown = _convert(source, target, hide_secrets=True)["output_text"].split("\n")
    assert len(kept) == len(shown)
    changed = [(a, b) for a, b in zip(kept, shown) if a != b]
    assert changed
    for before, after in changed:
        assert "CANARY" in before and "CANARY" not in after


@pytest.mark.parametrize("source,target", PAIRS)
def test_patterns_alone_hide_what_the_source_sweep_would(source, target):
    """The command patterns must not lean on the source sweep: mask each output line without it."""
    out = _convert(source, target)["output_text"]
    leftovers = [line for line in out.split("\n") if "CANARY" in mask_line(line)]
    assert leftovers == []


@pytest.mark.parametrize(
    "line,expected",
    [
        ("enable secret 9 $9$ABCDEFGH", f"enable secret 9 {HIDDEN}"),
        ("username a privilege 15 secret 5 $1$ABCDEFGH", f"username a privilege 15 secret 5 {HIDDEN}"),
        ("username a password 7 ABCDEF123456", f"username a password 7 {HIDDEN}"),
        (" local-user a password irreversible-cipher Abcdef12345", f" local-user a password irreversible-cipher {HIDDEN}"),
        ("snmp-server community SOMENAME RO", f"snmp-server community {HIDDEN} RO"),
        ("snmp-server host 192.0.2.1 version 2c SOMENAME", f"snmp-server host 192.0.2.1 version 2c {HIDDEN}"),
        ("snmp-agent community read cipher SOMENAME", f"snmp-agent community read cipher {HIDDEN}"),
        (" key 7 ABCDEF123456", f" key 7 {HIDDEN}"),
        ("radius-server host 192.0.2.13 key \"SOMEKEY\"", f"radius-server host 192.0.2.13 key \"{HIDDEN}\""),
        ("hwtacacs-server shared-key cipher SOMEKEY", f"hwtacacs-server shared-key cipher {HIDDEN}"),
        (" ip ospf message-digest-key 1 md5 SOMEKEY", f" ip ospf message-digest-key 1 md5 {HIDDEN}"),
        ("  key-string SOMEKEY", f"  key-string {HIDDEN}"),
        ("snmp-server user mon grp v3 auth sha AUTHKEY1 priv aes 128 PRIVKEY1", f"snmp-server user mon grp v3 auth sha {HIDDEN} priv aes 128 {HIDDEN}"),
        ('password manager user-name "admin" sha1 ABCDEF123456', f'password manager user-name "admin" sha1 {HIDDEN}'),
        (" # SOURCE-PASSWORD ops: ABCDEF123456", f" # SOURCE-PASSWORD ops: {HIDDEN}"),
        (" # REVIEW-PASSWORD-HASH ops: Cisco password type 7 ABCDEF123456", f" # REVIEW-PASSWORD-HASH ops: Cisco password type 7 {HIDDEN}"),
    ],
)
def test_mask_line_shapes(line, expected):
    assert mask_line(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "key chain KC",
        " key 1",
        " ip ospf authentication message-digest",
        "interface GigabitEthernet1/0/1",
        " description Password reset kiosk",
        " authentication-mode password",
        "line vty 0 4",
        " login local",
        "aaa authentication login default local",
        "snmp-server location Floor 2",
        "ntp server 192.0.2.5",
    ],
)
def test_mask_line_leaves_ordinary_commands_alone(line):
    assert mask_line(line) == line


def test_source_sweep_hides_a_value_copied_somewhere_unexpected():
    source = "enable secret 9 SWEEPVALUE9999\nhostname X\n"
    output = "! REVIEW-FOO: carried SWEEPVALUE9999 over\nhostname X\n"
    assert "SWEEPVALUE9999" not in hide_secrets(output, source)


def test_short_values_and_keywords_are_not_swept():
    values = source_values("key chain KC\n key 1\nusername a secret 0 abc\nsnmp-server community public\n")
    assert "abc" not in values and "1" not in values and "chain" not in values
    assert "public" in values


def test_count_counts_lines():
    text = "hostname X\nenable secret 9 ABCDEFGH\nsnmp-server community NAMEABCD RO\n description password\n"
    assert count_secret_lines(text) == 2


class HideSecretsRouteTests(unittest.TestCase):
    def setUp(self):
        os.environ["NES_DISABLE_AUTH"] = "1"
        self.addCleanup(os.environ.pop, "NES_DISABLE_AUTH", None)
        import app as nes_app

        self.client = nes_app.create_app().test_client()
        self.text = (FIXTURES / SOURCES["Cisco"]).read_text()

    def _post(self, **extra):
        data = {"config_text": self.text, "source_vendor": "Cisco", "source_device_type": "Switch", "target_vendor": "Huawei", "domain": "switch"}
        data.update(extra)
        return self.client.post("/configuration/api/convert", data=data)

    def test_option_off_keeps_values(self):
        body = self._post().get_json()
        self.assertTrue(body["ok"])
        self.assertIn("CANARY", body["result"]["output_text"])
        self.assertGreater(body["result"]["secrets"]["lines"], 0)

    def test_option_on_hides_values_in_the_screen_text_and_the_download(self):
        body = self._post(hide_secrets="1").get_json()
        self.assertTrue(body["ok"])
        self.assertNotIn("CANARY", body["result"]["output_text"])
        download = self.client.get(body["result"]["download_url"])
        self.assertEqual(download.status_code, 200)
        self.assertNotIn(b"CANARY", download.data)

    def test_the_page_offers_the_option(self):
        page = self.client.get("/convert/switch").get_data(as_text=True)
        self.assertIn('name="hide_secrets"', page)
        self.assertIn('id="secrets-note"', page)
        self.assertNotIn('name="hide_secrets"', self.client.get("/convert/firewall").get_data(as_text=True))


def test_no_stray_canary_in_other_fixtures():
    for path in (Path(__file__).parent / "fixtures").rglob("*"):
        if path.is_file() and FIXTURES not in path.parents:
            assert not re.search(rb"CANARY\d{4}", path.read_bytes()[:2_000_000]), path
