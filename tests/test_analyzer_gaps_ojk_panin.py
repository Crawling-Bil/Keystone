"""Analyzer gaps found with the OJK and Panin captures: SD-WAN identity, AOS-CX on the wrong page, vendor hints."""

from __future__ import annotations

import pytest

from features.analyzer_core.vendor_hint import identify, wrong_page_hint
from features.router_analyzer import service as router_service
from features.switch_analyzer import capture_text, service

AOSCX_CONFIG = """\
Current configuration:
!
!Version AOS-CX ML.10.16.1020
hostname CX-LAB-1
vlan 10
    name USERS
spanning-tree mode mstp
ntp server 192.0.2.10
interface 1/1/1
    no shutdown
    no routing
    vlan access 10
interface 1/1/2
    no shutdown
    no routing
    vlan access 10
"""


def test_sdwan_identity_fills_a_blank_model_from_show_sdwan_system_status():
    clean = capture_text.clean_lines(
        "EDGE1#show sdwan system status\nSystem status:\nModel name:   C8200-1N-4T\nVersion:      17.09.04a\nEDGE1#\n"
    )
    updated = service._sdwan_identity(clean, {"model": "", "os_version": ""})
    assert updated["model"] == "C8200-1N-4T" and updated["os_version"] == "17.09.04a"


def test_sdwan_identity_never_overwrites_what_show_version_gave():
    clean = capture_text.clean_lines("EDGE1#show sdwan system status\nModel name:   C8200-1N-4T\nVersion:      17.09.04a\nEDGE1#\n")
    updated = service._sdwan_identity(clean, {"model": "C8300-1N1S-6T", "os_version": "17.12.1"})
    assert updated["model"] == "C8300-1N1S-6T" and updated["os_version"] == "17.12.1"


def test_aoscx_is_recognised_as_a_switch_by_the_vendor_hint():
    found = identify(AOSCX_CONFIG)
    assert found["kind"] == "switch" and found["label"] == "Aruba AOS-CX switch"
    assert "Switch Analyzer" in wrong_page_hint(AOSCX_CONFIG, "router")


def test_the_router_analyzer_points_an_aoscx_config_to_the_switch_analyzer():
    with pytest.raises(ValueError, match="Switch Analyzer"):
        router_service.analyze(AOSCX_CONFIG, filename="cx.txt")


def test_cisco_router_config_is_not_mistaken_for_aoscx():
    cisco = "hostname R1\ninterface GigabitEthernet0/0/0\n ip address 192.0.2.1 255.255.255.0\nrouter ospf 1\nspanning-tree mode rapid-pvst\n"
    assert identify(cisco)["label"] != "Aruba AOS-CX switch"
