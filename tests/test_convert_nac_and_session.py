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


def _provision_config(count: int = 20) -> str:
    vlans = "\n".join(f'vlan {n}\n   name "V{n}"\n   untagged {n}\n   exit' for n in range(1, count))
    return f'Running configuration:\n\n; JL000A Configuration Editor; Created on release #YC.16.06.0006\nhostname "SW-LAB-2540"\nmodule 1 type jl000a\n{vlans}\npassword manager\n'


def test_a_show_tech_capture_ends_the_configuration_at_the_next_bare_command():
    """Aruba ProVision ``show tech`` prints the configuration and then every other ``show`` as a bare line, with no prompt in between."""
    tail = "".join(f"show thing{n}\n\n Status and Counters {n}\n   some output line {n}\n\n" for n in range(40))
    text = f"SW-LAB-2540# show tech\nshow system\n System Name : SW-LAB-2540\n\nshow running-config\n\n{_provision_config()}\n{tail}"
    extracted = extract_config(text)
    assert extracted.cut and extracted.command == "show running-config"
    assert extracted.text.rstrip().endswith("password manager")
    assert "Status and Counters" not in extracted.text and extracted.kept_lines < 120


def test_a_banner_sentence_that_starts_with_show_does_not_end_the_configuration():
    banner = 'banner motd "\nAuthorised use only\nShow your badge at the door\n"\n'
    text = f"SW-LAB-2540# show running-config\n{_provision_config(5)}{banner}{_provision_config(5)}SW-LAB-2540# \n"
    extracted = extract_config(text)
    assert "Show your badge at the door" in extracted.text and extracted.text.count("hostname") == 2


def test_a_typed_ahead_echo_in_the_middle_of_the_configuration_does_not_cut_it():
    body = "\n".join(f"vlan {n}\n name V{n}" for n in range(1, 12))
    text = f"SW#show run\n!Command: show running-config\nversion 10.5\nhostname SW\n{body}\nshow inventory\nvlan 99\n name LAST\nSW#show inventory\nNAME: x\nSW#\n"
    extracted = extract_config(text)
    assert "vlan 99" in extracted.text and "show inventory" not in extracted.text


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
    assert out.count("!     device-tracking") == 1
    assert out.count("!     authentication event server alive action reinitialize") == 1     # no AOS-CX equivalent: reported once
    assert "!     dot1x pae authenticator" not in out                                          # mapped, not just reported


def _aruba_port_block(out: str, name: str) -> list[str]:
    lines = out.splitlines()
    start = lines.index(f"interface {name}")
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "!")
    return lines[start:end]


def test_aruba_generates_8021x_and_mab_per_port_from_the_security_guide_syntax():
    out = _convert("Aruba")["output_text"]
    assert "\naaa authentication port-access dot1x authenticator enable\n" in out
    assert "\naaa authentication port-access mac-auth\n    enable\n" in out
    block = _aruba_port_block(out, "1/1/1")
    for line in (
        "    aaa authentication port-access auth-precedence dot1x mac-auth",       # authentication order dot1x mab
        "    aaa authentication port-access auth-mode multi-domain",                 # host-mode multi-domain
        "    aaa authentication port-access critical-role CRITICAL-VLAN10",         # event server dead action authorize vlan 10
        "    aaa authentication port-access dot1x authenticator",
        "        eapol-timeout 7",                                                    # dot1x timeout tx-period 7
        "        reauth",
        "        reauth-period 3600",
        "    aaa authentication port-access mac-auth",
        "        enable",
    ):
        assert line in block, line
    # the contexts are closed in the order AOS-CX prints them: settings first, enable last
    dot1x = block.index("    aaa authentication port-access dot1x authenticator")
    assert block[dot1x + 1:dot1x + 5] == ["        eapol-timeout 7", "        reauth", "        reauth-period 3600", "        enable"]
    assert "port-access role CRITICAL-VLAN10\n    vlan access 10\n" in out


def test_aruba_mab_first_and_host_modes(tmp_path):
    source = FIXTURE.read_text(encoding="utf-8")
    for cisco, aruba in (
        (" authentication order dot1x mab", " authentication order mab dot1x"),
    ):
        text = source.replace(cisco, aruba)
        path = tmp_path / "mabfirst.txt"
        path.write_text(text, encoding="utf-8")
        block = _aruba_port_block(_convert("Aruba", path=path)["output_text"], "1/1/1")
        assert "    aaa authentication port-access auth-precedence mac-auth dot1x" in block
    for cisco_mode, expected in (
        ("multi-host", "    aaa authentication port-access auth-mode device-mode"),
        ("multi-auth", "    aaa authentication port-access client-limit 256"),
    ):
        path = tmp_path / f"{cisco_mode}.txt"
        path.write_text(source.replace("host-mode multi-domain", f"host-mode {cisco_mode}"), encoding="utf-8")
        block = _aruba_port_block(_convert("Aruba", path=path)["output_text"], "1/1/1")
        assert expected in block
        assert "    aaa authentication port-access auth-mode multi-domain" not in block


def test_aruba_force_authorized_ports_are_not_given_port_access(tmp_path):
    path = tmp_path / "forced.txt"
    path.write_text(FIXTURE.read_text(encoding="utf-8").replace("authentication port-control auto", "authentication port-control force-authorized"), encoding="utf-8")
    out = _convert("Aruba", path=path)["output_text"]
    assert not [line for line in out.splitlines() if line.strip().startswith(("aaa authentication port-access", "port-access role"))]


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


# ----------------------------------------------------------------------------------- Huawei VTY / console, Aruba PoE
VTY_SOURCE = """\
hostname SW-X
ip access-list standard MGMT
 permit 192.0.2.0 0.0.0.255
access-list 10 permit 198.51.100.0 0.0.0.255
line con 0
 exec-timeout 5 0
 login local
 transport input none
line vty 0 4
 access-class MGMT in
 exec-timeout 10 0
 login local
 transport input ssh
line vty 5 15
 access-class 10 in
 transport input ssh
interface Vlan1
 ip address 192.0.2.5 255.255.255.0
"""


def _vty(target: str, tmp_path: Path) -> list[str]:
    path = tmp_path / "vty.txt"
    path.write_text(VTY_SOURCE, encoding="utf-8")
    return convert_file(path, target_vendor=target, source_vendor="Cisco", domain="switch")["output_text"].splitlines()


def test_huawei_vty_access_class_becomes_acl_inbound_and_console_is_converted(tmp_path):
    out = _vty("Huawei", tmp_path)
    block = out[out.index("user-interface vty 0 4"):]
    assert block[1] == " acl MGMT inbound"                       # acl { acl4name | acl4num } inbound, V600R025C00 Command Reference
    assert " protocol inbound ssh" in block[:6]
    assert " acl ACL-10 inbound" in out                           # a numbered Cisco ACL is named ACL-<n> by the parser
    console = out[out.index("user-interface con 0"):]
    assert console[1:3] == [" idle-timeout 5 0", " authentication-mode aaa"]
    assert any(line.startswith(" # REVIEW-CONSOLE: transport input none") for line in console[:5])
    assert not any("REVIEW-VTY-ACL" in line for line in out)


def test_huawei_converted_vty_passes_its_own_baseline(tmp_path):
    from features.switch_analyzer import service
    out = "\n".join(["<SW-X>display current-configuration"] + _vty("Huawei", tmp_path) + ["return"])
    codes = {f["code"] for f in service.analyze(out, filename="o.txt", vendor="Huawei")["health"]["findings"]}
    assert not codes & {"SW-VTY-001", "SW-VTY-002", "SW-VTY-003", "SW-VTY-004", "SW-CON-001"}


def test_aruba_no_poe_line_under_virtual_interfaces(tmp_path):
    path = tmp_path / "svi.txt"
    path.write_text(VTY_SOURCE, encoding="utf-8")
    out = convert_file(path, target_vendor="Aruba", source_vendor="Cisco", domain="switch")["output_text"].splitlines()
    block = out[out.index("interface vlan1"):]
    block = block[:block.index("!")]
    assert "    ip address 192.0.2.5/24" in block and "    no poe-enable" not in block
