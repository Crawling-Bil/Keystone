"""Switch Analyzer: the Users tab answers "are there local users on this device, and which".  All names, hashes and addresses are invented."""
from __future__ import annotations

import json

import pytest

from features.switch_analyzer import local_users, service

CISCO = """hostname SW1
!
username admin privilege 15 algorithm-type scrypt secret 9 $9$HASHHASHHASH
username bob password 7 0822455D0A16
username legacy privilege 15 password 0 Sup3rSecret
username viewer privilege 1 secret 5 $1$abcd$EFGHIJKLMNOP
username nopw nopassword
!
interface GigabitEthernet1/0/1
 description uplink
!
end
"""
NXOS = """hostname NX1
feature tacacs+
username admin password 5 $5$abcdefgh$ijklmnop role network-admin
username admin passphrase lifetime 99999 warntime 14 gracetime 3
username ops role network-operator
username keyuser sshkey ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ
interface Ethernet1/1
"""
HUAWEI = """sysname HW1
#
aaa
 authentication-scheme default
 local-user password policy administrator
 local-user max-number 1000
 local-user admin password irreversible-cipher $1c$HASHHASH$
 local-user admin privilege level 15
 local-user admin service-type terminal ssh
 local-user oldone password cipher %^%#abcdef%^%#
 local-user oldone service-type telnet
#
interface GigabitEthernet0/0/1
"""
AOSCX = """hostname CX1
user admin group administrators password ciphertext AQBapTHISISNOTAREALHASH
user guest group operators password plaintext letmein
interface 1/1/1
"""
ARUBA = """hostname AS1
password manager user-name "mgr" sha1 "da39a3ee5e6b4b0d3255bfef95601890afd80709"
password operator user-name "ops" sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
interface 1
"""
NO_USERS = "hostname SW9\n!\ninterface GigabitEthernet1/0/1\n!\nend\n"


def _rows(text, family):
    return {r["user"]: r for r in local_users.extract(text.splitlines(), family, True)["rows"]}


def test_cisco_ios_users():
    rows = _rows(CISCO, "cisco")
    assert set(rows) == {"admin", "bob", "legacy", "viewer", "nopw"}
    assert rows["admin"]["privilege"] == "15" and rows["admin"]["strength"] == "strong"
    assert rows["bob"]["strength"] == "weak" and "reversible" in rows["bob"]["storage"]
    assert rows["legacy"]["storage"] == "clear text"
    assert rows["viewer"]["strength"] == "weak" and rows["nopw"]["strength"] == "none"


def test_nxos_roles_and_policy_lines():
    rows = _rows(NXOS, "cisco")
    assert set(rows) == {"admin", "ops", "keyuser"}                  # the passphrase lifetime line is a policy, not a second account
    assert rows["admin"]["role"] == "network-admin" and rows["ops"]["role"] == "network-operator"
    assert rows["keyuser"]["credential"] == "ssh key"


def test_huawei_local_users_merge_their_lines_and_skip_policy_lines():
    rows = _rows(HUAWEI, "huawei")
    assert set(rows) == {"admin", "oldone"}
    assert rows["admin"]["privilege"] == "15" and rows["admin"]["services"] == "ssh, terminal" and rows["admin"]["strength"] == "strong"
    assert rows["oldone"]["strength"] == "weak" and rows["oldone"]["services"] == "telnet"


def test_aruba_cx_and_aruba_switch():
    cx = _rows(AOSCX, "aoscx")
    assert cx["admin"]["role"] == "administrators" and cx["admin"]["strength"] == "strong" and cx["guest"]["strength"] == "weak"
    sw = _rows(ARUBA, "aruba")
    assert sw["mgr"]["role"] == "manager" and sw["mgr"]["strength"] == "weak" and sw["ops"]["strength"] == "ok"


@pytest.mark.parametrize("text,family", [(CISCO, "cisco"), (NXOS, "cisco"), (HUAWEI, "huawei"), (AOSCX, "aoscx"), (ARUBA, "aruba")])
def test_no_credential_value_reaches_the_result(text, family):
    blob = json.dumps(local_users.extract(text.splitlines(), family, True))
    for secret in ("HASHHASH", "0822455D0A16", "Sup3rSecret", "EFGHIJKLMNOP", "ijklmnop", "AAAAB3NzaC1yc2E", "abcdef%^%#", "THISISNOTAREALHASH", "letmein",
                   "da39a3ee5e6b", "e3b0c44298fc"):
        assert secret not in blob


def test_none_configured_is_an_answer_and_no_configuration_is_not():
    answered = local_users.extract(NO_USERS.splitlines(), "cisco", True)
    assert answered["captured"] and answered["rows"] == [] and "No local user" in answered["summary"]["text"]
    unknown = local_users.extract([], "cisco", False)
    assert not unknown["captured"] and "Not in this capture" in unknown["summary"]["text"]
    assert not local_users.extract(CISCO.splitlines(), "mikrotik", True)["captured"]


def test_the_page_result_carries_the_users_tab_and_card():
    result = service.analyze(CISCO, filename="sw1.txt")
    assert [r["user"] for r in result["local_users"]["rows"]] == ["admin", "bob", "legacy", "viewer", "nopw"]
    assert result["cards"]["local_users"] == 5
    tab = next(t for t in result["tabs"] if t["key"] == "users")
    assert tab["has"] and tab["count"] == 5
    empty = service.analyze(NO_USERS, filename="sw9.txt")
    tab = next(t for t in empty["tabs"] if t["key"] == "users")
    assert tab["has"] and tab["count"] is None and empty["cards"]["local_users"] == 0


def test_a_capture_without_configuration_does_not_claim_none():
    text = ("SW1#show version\nCisco IOS XE Software, Version 17.09.04a\nSW1 uptime is 3 weeks\nProcessor board ID FOC0000XXXX\n"
            "SW1#show ip interface brief\nInterface IP-Address OK? Method Status Protocol\nGigabitEthernet1/0/1 unassigned YES unset up up\nSW1#\n")
    result = service.analyze(text, filename="show-only.txt")
    assert result["local_users"]["captured"] is False
    assert "Not in this capture" in result["local_users"]["summary"]["text"]
