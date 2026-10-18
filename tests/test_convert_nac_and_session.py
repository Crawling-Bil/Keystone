"""Convert Switch: session captures, 802.1X / MAB (NAC), TACACS ordering, DHCP and the Aruba CX target.

Fixtures are synthetic: invented host names, documentation addresses (RFC 5737), real Cisco PIDs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from features.configuration_studio.converter_engine import nac
from features.configuration_studio.converter_engine.session_capture import extract_config
from features.configuration_studio.service import convert_file

FIXTURE = Path(__file__).parent / "fixtures" / "switch" / "c9300l_nac_session_synthetic.txt"


def _convert(target: str, tmp_path: Path | None = None, path: Path = FIXTURE) -> dict:
    return convert_file(path, target_vendor=target, domain="switch")


# ------------------------------------------------------------------------------------------ session capture
def test_a_session_capture_is_cut_to_the_running_config():
    result = _convert("Huawei")
    assert result["capture"]["command"] == "show running-config"
    assert result["capture"]["config_lines"] < result["capture"]["total_lines"]
    assert "Cisco IOS XE Software" not in result["output_text"]       # show version text never reaches the translator
    assert result["hostname"] == "SW-LAB-ACC1"


def test_the_chassis_pid_of_show_inventory_still_reaches_the_hardware_catalog():
    assert _convert("Huawei")["interface_map"]["source_model"] == "C9300L-48P-4X"


def test_plain_config_is_not_cut():
    config = "hostname X\n" + "\n".join(f"interface GigabitEthernet1/0/{n}\n switchport mode access\n!" for n in range(1, 12))
    assert not extract_config(config).cut


def test_a_typed_ahead_command_between_the_echo_and_the_output_is_skipped():
    body = "\n".join(f"vlan {n}\n name V{n}" for n in range(1, 12))
    text = f"SW#show run\n\nshow inventory\n\n!Command: show running-config\nversion 10.5\nhostname SW\n{body}\nSW#\n"
    extracted = extract_config(text)
    assert extracted.cut and extracted.text.startswith("!Command: show running-config")
    assert "show inventory" not in extracted.text and "SW#" not in extracted.text


def test_a_capture_without_any_configuration_is_refused(tmp_path):
    text = "".join(f"SW#show {word}\nsome output line {n}\n" for n, word in enumerate(["version", "clock", "inventory", "ntp status", "redundancy"] * 4))
    path = tmp_path / "capture.txt"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="show running-config"):
        convert_file(path, target_vendor="Huawei", domain="switch")


# ------------------------------------------------------------------------------------------------ nac module
def test_nac_extract_reads_one_port_into_settings():
    commands = ["description X", "authentication host-mode multi-domain", "authentication order dot1x mab", "authentication port-control auto", "mab", "dot1x pae authenticator",
                "authentication timer reauthenticate 3600", "authentication event server dead action authorize vlan 20", "dot1x timeout tx-period 7"]
    settings, remaining = nac.extract(commands, access_vlan=10)
    assert remaining == ["description X"]
    assert settings.dot1x and settings.mab and settings.mab_fallback
    assert settings.mode() == "single-voice-with-data"          # multi-domain: one data + one voice user (V600R025C00 command reference)
    assert settings.reauth_period == "3600" and settings.tx_period == "7"
    assert settings.server_dead and settings.access_vlan == 20   # the VLAN of the command wins over the port VLAN


def test_nac_extract_leaves_a_port_without_authentication_alone():
    settings, remaining = nac.extract(["description X", "switchport mode access"])
    assert settings is None and remaining == ["description X", "switchport mode access"]


def test_host_modes_map_to_huawei_authentication_modes():
    assert nac.HOST_MODE == {"multi-auth": "multi-authen", "multi-domain": "single-voice-with-data", "multi-host": "multi-share", "single-host": "single-terminal"}


def test_compact_ports_joins_consecutive_numbers():
    assert nac.compact_ports(["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/5", "Gi2/0/1"]) == "Gi1/0/1-3, Gi1/0/5, Gi2/0/1"


# ----------------------------------------------------------------------------------------- Huawei target
def test_huawei_gets_one_authentication_profile_for_identical_ports():
    out = _convert("Huawei")["output_text"]
    assert out.count("authentication-profile name ") == 1
    assert out.count(" authentication-profile NAC-P1") == 2          # bound on both ports
    assert "dot1x-access-profile name NAC-D1" in out and "mac-access-profile name NAC-M1" in out
    assert " authentication dot1x-mac-bypass" in out and " authentication mode single-voice-with-data" in out
    assert " dot1x timer reauthenticate-period 3600" in out and "dot1x timer tx-period 7" in out
    assert " authentication event authen-server-down action authorize vlan 10" in out
    assert " authentication event authen-server-up action re-authen" in out
    assert "authentication unified-mode" not in out                   # not in V600R025C00


def test_huawei_tacacs_servers_are_primary_secondary_third():
    out = _convert("Huawei")["output_text"]
    assert " hwtacacs-server authentication 192.0.2.11\n" in out
    assert " hwtacacs-server authentication 192.0.2.12 secondary" in out
    assert " hwtacacs-server authentication 192.0.2.13 third" in out


def test_huawei_link_status_trap_off_and_dhcp_exclusion():
    out = _convert("Huawei")["output_text"]
    assert " undo enable snmp trap updown" in out
    assert "excluded-ip-address 192.0.2.1 192.0.2.10" in out


# ------------------------------------------------------------------------------------------ Cisco target
def test_cisco_to_cisco_keeps_the_port_authentication_lines():
    out = _convert("Cisco")["output_text"]
    for line in (" authentication port-control auto", " mab", " dot1x pae authenticator", " authentication order dot1x mab"):
        assert line in out
    assert "REVIEW-CISCO: authentication" not in out


# ------------------------------------------------------------------------------------------- Aruba target
def test_aruba_groups_repeated_port_commands_into_one_block():
    out = _convert("Aruba")["output_text"]
    assert "REVIEW-UNSUPPORTED: authentication port-control auto" not in out
    assert "REVIEW-UNSUPPORTED on 2 port(s) GigabitEthernet1/0/1-2:" in out
    assert out.count("!     dot1x pae authenticator") == 1


def test_aruba_dhcp_pool_does_not_crash_and_keeps_gateway_and_dns():
    out = _convert("Aruba")["output_text"]
    assert "pool LAB" in out and "default-router 192.0.2.1" in out and "dns-server 192.0.2.53" in out
    assert "REVIEW-DHCP: source lease 0 8" in out


def test_aruba_does_not_pass_cisco_logging_options_through(tmp_path):
    path = tmp_path / "cfg.txt"
    path.write_text("hostname S1\nlogging buffered 51200\nlogging synchronous\nlogging host 192.0.2.9\n" + "\n".join(f"vlan {n}" for n in range(10, 30)) + "\n", encoding="utf-8")
    out = convert_file(path, target_vendor="Aruba", source_vendor="Cisco", domain="switch")["output_text"]
    assert "\nlogging 192.0.2.9" in out
    assert "\nlogging buffered" not in out and "REVIEW-LOGGING: logging buffered 51200" in out


AOSCX = """\
Current configuration:
!
!Version AOS-CX ML.10.16.1020
hostname AOS-LAB-1
vlan 10
    name USERS
snmp-server system-location Lab Room
snmp-server system-contact noc@example.com
interface 1/1/1
    no shutdown
    description PC
    no routing
    vlan access 10
interface 1/1/2
    no shutdown
    description PC2
    no routing
    vlan access 10
interface 1/1/3
    no shutdown
    description PC3
    no routing
    vlan access 10
""" + "\n".join(f"vlan {n}\n    name V{n}" for n in range(20, 30)) + "\n"


def test_aoscx_no_routing_is_understood_and_snmp_location_contact_translate(tmp_path):
    path = tmp_path / "aoscx.txt"
    path.write_text(AOSCX, encoding="utf-8")
    huawei = convert_file(path, target_vendor="Huawei", domain="switch")["output_text"]
    assert "REVIEW-CISCO: no routing" not in huawei
    assert "snmp-agent sys-info location Lab Room" in huawei and "snmp-agent sys-info contact noc@example.com" in huawei
    aruba = convert_file(path, target_vendor="Aruba", domain="switch")["output_text"]
    block = aruba.split("interface 1/1/1", 1)[1].split("interface 1/1/2", 1)[0]
    assert "    no routing\n    vlan access 10" in block          # an AOS-CX switchport needs "no routing" before "vlan access"
