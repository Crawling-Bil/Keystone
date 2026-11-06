"""The source pane of the firewall converters hides the credentials of the uploaded file (invented CANARY values)."""

from __future__ import annotations

import io

import pytest

from features.configuration_studio.converter_engine.fwconvert.mask import HIDDEN, mask_source

XML = ('<config version="11.2.0"><mgt-config><users><entry name="admin"><phash>CANARYphash$1$abcd$EFGH</phash></entry></users></mgt-config>'
       '<devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>fw1</hostname><snmp-setting><access-setting><version><v3><users>'
       '<entry name="u"><authpwd>CANARYauth0123456789012345678901234567890123</authpwd><privpwd>CANARYpriv0123456789012345678901234567890123</privpwd>'
       '<authproto>SHA</authproto></entry></users></v3></version></access-setting></snmp-setting></system></deviceconfig>'
       '<network><ike><gateway><entry name="g"><authentication><pre-shared-key><key>CANARYpsk</key></pre-shared-key></authentication></entry></gateway></ike></network>'
       '</entry></devices></config>')
FORTI = ('config system admin\n    edit "admin"\n        set password ENC CANARYfortipw==\n    next\nend\n'
         'config vpn ipsec phase1-interface\n    edit "t1"\n        set psksecret ENC CANARYforti-psk\n    next\nend\n'
         'config user radius\n    edit "r"\n        set secret ENC CANARYradius\n    next\nend\n'
         'config vpn certificate local\n    edit "c"\n        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----\nCANARYpemline1\nCANARYpemline2\n-----END ENCRYPTED PRIVATE KEY-----\n"\n    next\nend\n'
         'config system password-policy\n    set status enable\n    set minimum-length 8\nend\n')
PAN_SET = ('set mgt-config users admin phash CANARYsetphash\nset network ike gateway g authentication pre-shared-key key CANARYsetpsk\n'
           'set deviceconfig system snmp-setting access-setting version v3 users u authpwd CANARYsetauth\nset mgt-config password-complexity enabled yes\n'
           'set deviceconfig system hostname fw1\n')
PAN_CURLY = 'mgt-config {\n  users {\n    admin {\n      phash CANARYcurlyphash;\n    }\n  }\n}\npre-shared-key {\n  key CANARYcurlypsk;\n}\n'


def test_xml_credentials_are_removed_and_structure_kept():
    shown = mask_source(XML)
    assert "CANARY" not in shown
    assert "<hostname>fw1</hostname>" in shown and "<authproto>SHA</authproto>" in shown


@pytest.mark.parametrize("text", [FORTI, PAN_SET, PAN_CURLY])
def test_cli_credentials_are_hidden(text):
    shown = mask_source(text)
    assert "CANARY" not in shown and HIDDEN in shown


def test_ordinary_settings_are_untouched():
    shown = mask_source(FORTI + PAN_SET)
    for keep in ("set status enable", "set minimum-length 8", "password-complexity enabled yes", "hostname fw1", 'edit "admin"'):
        assert keep in shown


def test_the_convert_page_shows_the_masked_source_but_converts_the_real_one():
    from app import create_app
    client = create_app().test_client()
    reply = client.post("/configuration/api/convert", data={"config_file": (io.BytesIO(XML.encode()), "fw.xml"), "domain": "firewall", "target_vendor": "FortiGate"},
                        content_type="multipart/form-data").get_json()
    assert reply["ok"], reply
    result = reply["result"]
    assert "CANARY" not in result["source_text"] and "CANARY" not in result["output_text"]
    forti = client.post("/configuration/api/convert", data={"config_file": (io.BytesIO(FORTI.encode()), "forti.conf"), "domain": "firewall", "target_vendor": "Palo Alto"},
                        content_type="multipart/form-data").get_json()
    if forti.get("ok"):
        assert "CANARY" not in forti["result"]["source_text"]
