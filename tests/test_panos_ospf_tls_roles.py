"""PAN-OS: OSPF interface authentication, RC4 / 3DES in an SSL/TLS service profile, custom administrator roles.  Invented data; key material is a marker string."""
from __future__ import annotations

import json

from features.firewall_analyzer import service

KEY_MARKER = "OSPF-FAKE-MD5-KEY-MATERIAL"

XML = f"""<?xml version="1.0"?>
<config version="10.2.0">
  <mgt-config><users><entry name="netadmin"><permissions><role-based><custom><profile>ops</profile></custom></role-based></permissions></entry></users></mgt-config>
  <shared>
    <ssl-tls-service-profile>
      <entry name="legacy"><protocol-settings><min-version>tls1-2</min-version><enc-algo-rc4>yes</enc-algo-rc4><enc-algo-3des>yes</enc-algo-3des></protocol-settings></entry>
      <entry name="modern"><protocol-settings><min-version>tls1-2</min-version><enc-algo-rc4>no</enc-algo-rc4></protocol-settings></entry>
    </ssl-tls-service-profile>
    <admin-role>
      <entry name="ops"><description>read mostly</description><role><device><webui><dashboard>enable</dashboard><monitor>read-only</monitor><operations>disable</operations></webui><xmlapi><report>enable</report></xmlapi><cli>basic</cli></device></role></entry>
    </admin-role>
  </shared>
  <devices><entry name="localhost.localdomain">
    <network>
      <virtual-router>
        <entry name="vr1">
          <protocol><ospf>
            <enable>yes</enable><router-id>192.0.2.1</router-id>
            <auth-profile><entry name="md5prof"><md5><entry name="1"><key>{KEY_MARKER}</key><preferred>yes</preferred></entry></md5></entry>
                          <entry name="pwprof"><password>{KEY_MARKER}</password></entry></auth-profile>
            <area><entry name="0.0.0.0"><type><normal/></type><interface>
              <entry name="ethernet1/1"><enable>yes</enable><passive>no</passive><authentication>md5prof</authentication><link-type><broadcast/></link-type></entry>
              <entry name="ethernet1/2"><enable>yes</enable><passive>no</passive><link-type><broadcast/></link-type></entry>
              <entry name="ethernet1/3"><enable>yes</enable><passive>no</passive><authentication>pwprof</authentication></entry>
              <entry name="ethernet1/4"><enable>yes</enable><passive>no</passive><authentication>missing</authentication></entry>
              <entry name="loopback.1"><enable>yes</enable><passive>yes</passive></entry>
            </interface></entry></area>
          </ospf></protocol>
        </entry>
      </virtual-router>
    </network>
    <vsys><entry name="vsys1"/></vsys>
  </entry></devices>
</config>
"""


def _result(xml: str = XML):
    return service.analyze(xml, "pa.xml", "paloalto")


def _ids(result, prefix):
    return sorted((f["id"], f["object"].split("/", 2)[-1]) for f in result["findings"] if f["id"].startswith(prefix))


def test_ospf_interfaces_without_or_with_weak_authentication_are_found():
    result = _result()
    assert _ids(result, "PAN-OSPF") == [("PAN-OSPF-001", "ethernet1/2"), ("PAN-OSPF-002", "ethernet1/3"), ("PAN-OSPF-003", "ethernet1/4")]   # md5 ok, passive loopback skipped


def test_ospf_table_never_shows_key_material():
    result = _result()
    assert KEY_MARKER not in json.dumps(result, default=str)
    rows = {r["interface"]: r for r in next(s for s in result["sections"] if s["id"] == "ospf_interfaces")["rows"]}
    assert rows["ethernet1/1"]["auth"] == "md5prof (md5)" and rows["ethernet1/1"]["key_ids"] == ["1"]
    assert rows["loopback.1"]["passive"] == "yes"


def test_ospf_disabled_virtual_router_raises_nothing():
    result = _result(XML.replace("<enable>yes</enable><router-id>", "<enable>no</enable><router-id>"))
    assert _ids(result, "PAN-OSPF") == []


def test_rc4_and_3des_in_a_tls_profile():
    result = _result()
    hits = [f for f in result["findings"] if f["id"] == "PAN-TLS-003"]
    assert len(hits) == 1 and "legacy" in hits[0]["object"] and "RC4 and 3DES" in hits[0]["title"]


def test_custom_admin_role_counts():
    section = next(s for s in _result()["sections"] if s["id"] == "pan_admin_roles")
    row = section["rows"][0]
    assert row["name"] == "ops" and row["type"] == "device"
    assert row["webui"] == "1 on / 1 read-only / 1 off" and row["xmlapi"] == "1 on / 0 read-only / 0 off" and row["cli"] == "basic"


def test_converter_says_in_english_what_it_cannot_do(tmp_path):
    """A PAN-OS export is not a converter source (it used to stop with an AttributeError); the message says so and points to the analyzer."""
    import pytest

    from features.configuration_studio import service as studio

    path = tmp_path / "pa.xml"
    path.write_text(XML, encoding="utf-8")
    with pytest.raises(ValueError) as excinfo:
        studio.convert_file(path, domain="firewall", target_vendor="Palo Alto")
    text = str(excinfo.value)
    assert "belum tersedia" not in text and "Firewall Analyzer" in text and "already a PAN-OS" in text


def test_fortigate_file_converts_to_panos_since_fwconvert(tmp_path):
    import pytest

    from features.configuration_studio import service as studio

    path = tmp_path / "fgt.conf"
    path.write_text("#config-version=FGT60F-7.2.7-FW-build1:opmode=0:vdom=0:user=admin\nconfig system global\n    set hostname \"LAB\"\nend\nconfig system interface\n    edit \"wan1\"\n        set vdom \"root\"\n        set ip 192.0.2.1 255.255.255.0\n        set allowaccess ping\n        set type physical\n    next\nend\nconfig firewall address\n    edit \"h1\"\n        set subnet 192.0.2.10 255.255.255.255\n    next\nend\nconfig firewall policy\n    edit 1\n        set srcintf \"wan1\"\n        set dstintf \"wan1\"\n        set srcaddr \"h1\"\n        set dstaddr \"all\"\n        set action accept\n        set schedule \"always\"\n        set service \"ALL\"\n    next\nend\n", encoding="utf-8")
    # FortiGate -> Palo Alto is a converter of its own now (fwconvert); it used to be refused with a pointer to the Firewall Analyzer.
    result = studio.convert_file(path, domain="firewall", target_vendor="Palo Alto")
    assert result["source_vendor"] == "FortiGate" and result["target_vendor"] == "Palo Alto"
    assert "belum tersedia" not in result["output_text"] and result["fwconvert"]["rows"]
