"""The generic "Other configuration objects" tables of the PAN-OS and FortiGate readers: they show object types that have no table of their own and must never show a secret.  Invented data."""
from __future__ import annotations

import json

from features.firewall_analyzer import service

FORTI = """\
#config-version=FGT201F-7.2.10-FW-build1706-250108:opmode=0:vdom=0:user=admin
config system global
    set hostname "LAB-FGT-01"
end
config user fortitoken
    edit "FTK2000ABCD1234"
        set status active
        set comments "lab token"
        set seed ENC FORTI-FAKE-SEED-VALUE-1234567890
    next
end
config dlp sensor
    edit "block-cards"
        set comment "cards"
        set match-type match-any
        set psksecret ENC FORTI-FAKE-SECRET-VALUE-1234567890
        set widget-code ENC FORTI-FAKE-ODDLY-NAMED-ENC-VALUE
    next
end
config firewall ssh local-key
    edit "LabKey"
        set private-key "-----BEGIN RSA PRIVATE KEY-----\\nFORTI-FAKE-PRIVATE-KEY\\n-----END RSA PRIVATE KEY-----"
        set public-key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7FAKEPUBLICKEYMATERIALFAKEPUBLICKEYMATERIALFAKEPUBLICKEYMATERIALFAKEPUBLICKEYMATERIAL lab"
    next
end
config switch-controller qos dot1p-map
    edit "dot1p-lab"
        set priority-0 queue-0
        set priority-7 queue-3
    next
end
"""

PANOS = """<?xml version="1.0"?>
<config version="10.2.0">
  <devices><entry name="localhost.localdomain">
    <network>
      <tunnel><ipsec><entry name="tun1"><auto-key><proxy-id>
        <entry name="pid1"><local>10.1.0.0/24</local><remote>10.2.0.0/24</remote><protocol><any/></protocol></entry>
      </proxy-id></auto-key><tunnel-interface>tunnel.1</tunnel-interface></entry></ipsec></tunnel>
    </network>
    <vsys><entry name="vsys1">
      <external-list><entry name="edl1"><type><ip><url>https://edl.example.test/list.txt</url><recurring><hourly/></recurring><auth-key>PAN-FAKE-EDL-AUTH-VALUE</auth-key></ip></type></entry></external-list>
      <profiles><spyware><entry name="sp1"><rules><entry name="r-crit"><severity><member>critical</member></severity><action><reset-both/></action></entry></rules></entry></spyware></profiles>
      <rulebase><default-security-rules><rules><entry name="intrazone-default"><action>allow</action><log-start>no</log-start><log-end>yes</log-end></entry></rules></default-security-rules></rulebase>
      <tag><entry name="prod-tag"><color>color5</color><comments>production</comments></entry></tag>
    </entry></vsys>
  </entry></devices>
  <shared><log-settings><syslog><entry name="siem"><server><entry name="siem1"><server>192.0.2.50</server><transport>UDP</transport><port>514</port><format>BSD</format><facility>LOG_USER</facility></entry></server></entry></syslog></log-settings></shared>
</config>
"""


def _rows(result, section_id):
    return next(s for s in result["sections"] if s["id"] == section_id)["rows"]


def test_fortigate_other_objects_are_listed_without_secrets():
    result = service.analyze(FORTI, "fgt.conf", "fortigate")
    blob = json.dumps(result, default=str)
    for marker in ("FORTI-FAKE-SEED", "FORTI-FAKE-SECRET", "FORTI-FAKE-ODDLY-NAMED", "FORTI-FAKE-PRIVATE-KEY", "FAKEPUBLICKEYMATERIAL", "FTK2000ABCD1234"):
        assert marker not in blob
    rows = {(r["type"], r["name"]): r for r in _rows(result, "more_objects")}
    assert ("FortiToken", "***********1234") in rows or any(t == "FortiToken" and n.endswith("1234") for t, n in rows)
    assert rows[("DLP sensor", "block-cards")]["settings"].startswith("comment=cards")
    assert "priority-7=queue-3" in rows[("FortiSwitch 802.1p map", "dot1p-lab")]["settings"]
    assert "characters not shown" in rows[("SSH proxy local key", "LabKey")]["settings"]


def test_panos_other_objects_are_listed_without_secrets():
    result = service.analyze(PANOS, "pa.xml", "paloalto")
    assert "PAN-FAKE-EDL-AUTH" not in json.dumps(result, default=str)
    rows = {(r["type"], r["name"]): r for r in _rows(result, "pan_more_objects")}
    assert "local=10.1.0.0/24" in rows[("IPsec tunnel proxy ID", "pid1")]["settings"] and "remote=10.2.0.0/24" in rows[("IPsec tunnel proxy ID", "pid1")]["settings"]
    assert "edl.example.test" in rows[("External dynamic list", "edl1")]["settings"]
    assert "reset-both" in rows[("Anti-spyware profile rule", "r-crit")]["settings"]
    assert rows[("Default security rule (intrazone / interzone)", "intrazone-default")]["scope"] == "vsys1"


def test_panos_syslog_servers_and_tags_are_listed():
    result = service.analyze(PANOS, "pa.xml", "paloalto")
    rows = {(r["type"], r["name"]): r for r in _rows(result, "pan_more_objects")}
    assert "192.0.2.50" in rows[("Log settings syslog server", "siem1")]["settings"] and "514" in rows[("Log settings syslog server", "siem1")]["settings"]
    assert "color5" in rows[("Tag", "prod-tag")]["settings"]
