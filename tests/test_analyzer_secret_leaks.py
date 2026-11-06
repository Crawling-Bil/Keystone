"""Switch and Router Analyzer: credentials in raw command lists and "referenced by" lists.

A token-by-token scan of real captures found a credential in places the first secret sweep did not reach: the raw AAA and NTP command lists, the ACL
"referenced by" list (`snmp-server community NAME RO acl`) and the Router object cross-reference.  Every value here is an invented CANARY string.
"""

from __future__ import annotations

import json

import pytest

from features.router_analyzer.service import analyze as router_analyze
from features.switch_analyzer.service import analyze as switch_analyze

CISCO = """\
version 17.9
hostname CAN-RTR1
enable secret 9 $9$CANARYLEAK0001
username admin privilege 15 secret 9 $9$CANARYLEAK0002
aaa new-model
tacacs server TAC1
 address ipv4 192.0.2.10
 key 7 CANARYLEAK0003
ntp authentication-key 1 md5 CANARYLEAK0004
ntp authenticate
ntp trusted-key 1
ntp server 192.0.2.5 key 1
ip access-list standard SNMP-RO
 permit 192.0.2.0 0.0.0.255
snmp-server community CANARYLEAK0005 RO SNMP-RO
snmp-server host 192.0.2.20 version 2c CANARYLEAK0006
interface GigabitEthernet0/0
 ip address 192.0.2.1 255.255.255.0
 ip ospf message-digest-key 1 md5 CANARYLEAK0007
line vty 0 4
 password 7 CANARYLEAK0008
 access-class SNMP-RO in
 login
end
"""

HUAWEI = """\
sysname CAN-S1
#
aaa
 local-user admin password irreversible-cipher CANARYLEAK1001
 local-user admin privilege level 15
 local-user admin service-type ssh
#
ntp-service authentication-keyid 1 authentication-mode md5 cipher CANARYLEAK1002
ntp-service authentication enable
ntp-service unicast-server 192.0.2.5
#
snmp-agent community read cipher CANARYLEAK1003 acl 2000
acl number 2000
 rule 5 permit source 192.0.2.0 0.0.0.255
#
hwtacacs-server shared-key cipher CANARYLEAK1004
#
return
"""


def _blob(result) -> str:
    return json.dumps(result, ensure_ascii=False, default=str)


@pytest.mark.parametrize("text", [CISCO, HUAWEI], ids=["cisco", "huawei"])
def test_switch_analyzer_result_holds_no_credential(text):
    blob = _blob(switch_analyze(text, filename="cap.txt"))
    assert "CANARYLEAK" not in blob, [part for part in blob.split('"') if "CANARYLEAK" in part][:3]


def test_router_analyzer_result_holds_no_credential():
    blob = _blob(router_analyze(CISCO, "cap.txt"))
    assert "CANARYLEAK" not in blob, [part for part in blob.split('"') if "CANARYLEAK" in part][:3]


def test_raw_lists_still_show_the_commands():
    result = switch_analyze(CISCO, filename="cap.txt")
    assert any(line.startswith("ntp authentication-key 1 md5") for line in result["ntp_commands"])
    assert any("snmp-server community" in ref for acl in result["l3"]["acls"]["definitions"] for ref in acl["referenced_by"])
