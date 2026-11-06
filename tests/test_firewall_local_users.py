"""Firewall Analyzer: every firewall platform says whether local users exist.  Invented data."""
from __future__ import annotations

from features.firewall_analyzer import service

FORTI = """\
#config-version=FGT201F-7.2.10-FW-build1706-250108:opmode=0:vdom=0:user=admin
config system global
    set hostname "LAB-FGT-01"
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC SH2abcdefSECRETHASH
    next
end
config user local
    edit "vpnuser1"
        set type password
        set passwd ENC SH2vpnSECRETHASHvalue
    next
    edit "ldapuser"
        set type ldap
        set ldap-server "LDAP1"
        set two-factor fortitoken
    next
    edit "off"
        set status disable
        set passwd ENC SH2offSECRETHASH
    next
end
"""


def _sections(text):
    return service.analyze(text, "fgt.conf", "fortigate")


def test_fortigate_local_users_are_listed_without_their_hashes():
    import json
    result = _sections(FORTI)
    blob = json.dumps(result)
    assert "SECRETHASH" not in blob and "vpnSECRET" not in blob
    section = next(s for s in result["sections"] if s["id"] == "local_users")
    rows = {r["name"]: r for r in section["rows"]}
    assert set(rows) == {"vpnuser1", "ldapuser", "off"}
    assert rows["vpnuser1"]["password"] == "encrypted" and rows["ldapuser"]["server"] == "LDAP1" and rows["ldapuser"]["two_factor"] == "fortitoken"
    assert rows["off"]["status"] == "disable"


def test_fortigate_without_local_users_says_so():
    result = _sections(FORTI.split("config user local")[0] + "end\n")
    section = next(s for s in result["sections"] if s["id"] == "local_users")
    assert section["rows"] == [] and "No local users" in section["empty"]


PANOS_XML = """<?xml version="1.0"?>
<config version="10.2.0">
  <mgt-config><users><entry name="netadmin"><permissions><role-based><superuser>yes</superuser></role-based></permissions><phash>$1$abcdSECRETPHASH</phash></entry></users></mgt-config>
  <shared>
    <local-user-database>
      <user>
        <entry name="gpuser1"><phash>$1$gpSECRETPHASH</phash></entry>
        <entry name="gpuser2"><disabled>yes</disabled></entry>
      </user>
    </local-user-database>
  </shared>
  <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices>
</config>
"""


def test_panos_local_user_database_is_listed_without_hashes():
    import json
    result = service.analyze(PANOS_XML, "pa.xml", "paloalto")
    assert "SECRETPHASH" not in json.dumps(result)
    section = next(s for s in result["sections"] if s["id"] == "pan_local_users")
    rows = {r["name"]: r for r in section["rows"]}
    assert set(rows) == {"gpuser1", "gpuser2"}
    assert rows["gpuser1"]["password"] == "stored" and rows["gpuser2"]["password"] == "none" and rows["gpuser2"]["enabled"] == "no"
    assert rows["gpuser1"]["scope"] == "shared"


def test_panos_without_local_user_database_says_so():
    result = service.analyze(PANOS_XML.split("<shared>")[0] + "</config>", "pa.xml", "paloalto")
    section = next(s for s in result["sections"] if s["id"] == "pan_local_users")
    assert section["rows"] == [] and "No local user" in section["empty"]
