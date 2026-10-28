"""Convert Switch: ArubaOS-Switch (ProVision / 2540) port and VLAN statements, and PoE written only when the source set it.

Fixtures are synthetic: invented host names, documentation addresses (RFC 5737).
Reference: HPE Aruba ArubaOS-Switch Management and Configuration Guide, "interface <port-list> enable | disable", "interface <port> name", "vlan <id> ip address"
(https://www.arubanetworks.com/techdocs/ArubaOS-Switch/); Cisco IOS XE "power inline" (https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/power/command/pwr-cr-book.html).
"""

from __future__ import annotations

import re
from pathlib import Path

from features.configuration_studio.service import convert_file

PROVISION = """Running configuration:

; JL356A Configuration Editor; Created on release #YC.16.06.0006
hostname "SW-LAB-2540"
module 1 type jl356a
interface 16
   disable
   exit
interface 20
   name "Uplink to core"
   exit
vlan 1
   name "DEFAULT_VLAN"
   untagged 1-23
   ip address dhcp-bootp
   exit
vlan 10
   name "Voice"
   tagged 24
   exit
vlan 99
   name "Mgmt"
   untagged 24
   tagged 1
   ip address 192.0.2.5 255.255.255.0
   ip helper-address 192.0.2.50
   exit
"""


def _convert(tmp_path: Path, text: str, target: str) -> list[str]:
    path = tmp_path / "source.txt"
    path.write_text(text, encoding="utf-8")
    return convert_file(path, target_vendor=target, domain="switch")["output_text"].splitlines()


def _block(lines: list[str], header: str) -> list[str]:
    """The lines of the interface block that starts with ``header`` (up to the closing ``!`` / ``#``)."""
    start = next(index for index, line in enumerate(lines) if line.strip() == header)
    end = next((index for index in range(start + 1, len(lines)) if lines[index].strip() in ("!", "#")), len(lines))
    return lines[start + 1:end]


def test_a_disabled_provision_port_is_shut_down_and_its_name_becomes_the_description(tmp_path):
    cisco = _convert(tmp_path, PROVISION, "Cisco")
    assert " shutdown" in _block(cisco, "interface GigabitEthernet1/0/16")
    assert " description Uplink to core" in _block(cisco, "interface GigabitEthernet1/0/20")
    huawei = _convert(tmp_path, PROVISION, "Huawei")
    assert " shutdown" in _block(huawei, "interface 16")


def test_a_port_tagged_in_one_vlan_and_untagged_in_a_later_one_stays_a_trunk(tmp_path):
    """VLAN 10 is tagged on port 24 and VLAN 99 is untagged there: a trunk with native VLAN 99, not an access port that drops VLAN 10."""
    cisco = _block(_convert(tmp_path, PROVISION, "Cisco"), "interface GigabitEthernet1/0/24")
    assert " switchport mode trunk" in cisco
    assert " switchport trunk native vlan 99" in cisco
    assert " switchport trunk allowed vlan 10,99" in cisco


def test_a_port_untagged_in_an_earlier_vlan_and_tagged_in_a_later_one_keeps_its_native_vlan_allowed(tmp_path):
    """Port 1 is untagged in VLAN 1 and tagged in VLAN 99: the trunk carries both, the allowed list must hold the native VLAN too."""
    cisco = _block(_convert(tmp_path, PROVISION, "Cisco"), "interface GigabitEthernet1/0/1")
    assert " switchport mode trunk" in cisco and " switchport trunk allowed vlan 1,99" in cisco
    huawei = _block(_convert(tmp_path, PROVISION, "Huawei"), "interface 1")
    assert " port trunk pvid vlan 1" in huawei and " port trunk allow-pass vlan 1 99" in huawei


def test_the_address_inside_a_provision_vlan_becomes_the_svi(tmp_path):
    cisco = _block(_convert(tmp_path, PROVISION, "Cisco"), "interface Vlan99")
    assert " ip address 192.0.2.5 255.255.255.0" in cisco and " ip helper-address 192.0.2.50" in cisco
    assert " ip address 192.0.2.5 255.255.255.0" in _block(_convert(tmp_path, PROVISION, "Huawei"), "interface Vlanif99")
    assert "    ip address 192.0.2.5/24" in _block(_convert(tmp_path, PROVISION, "Aruba"), "interface vlan99")


def test_provision_structure_lines_are_not_review_items(tmp_path):
    text = "\n".join(_convert(tmp_path, PROVISION, "Cisco"))
    for noise in ("REVIEW-UNSUPPORTED: exit", "Configuration Editor", "module 1 type"):
        assert noise not in text
    assert "dhcp-bootp" not in text                                   # a DHCP client address is converted (see the DHCP tests below), not left as a review line


CISCO = """hostname SW-LAB-C9300
vlan 10
 name USERS
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 10
 power inline never
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
end
"""


def test_poe_is_written_only_for_a_port_where_the_source_set_it(tmp_path):
    cisco = _convert(tmp_path, CISCO, "Cisco")
    assert sum(line.strip() == "power inline never" for line in cisco) == 1
    assert " power inline never" in _block(cisco, "interface GigabitEthernet1/0/2")
    assert not any("power inline" in line for line in _block(cisco, "interface GigabitEthernet1/0/1") + _block(cisco, "interface Vlan10"))
    aruba = _convert(tmp_path, CISCO, "Aruba")
    assert sum("no poe-enable" in line for line in aruba) == 1


def test_a_source_without_any_poe_statement_gets_none_on_any_target(tmp_path):
    plain = CISCO.replace(" power inline never\n", "")
    for target in ("Cisco", "Aruba", "Huawei"):
        text = "\n".join(_convert(tmp_path, plain, target))
        assert not re.search(r"power inline|poe-enable|poe enable", text), target


def test_poe_switched_off_in_the_source_is_not_lost_on_a_huawei_target(tmp_path):
    huawei = "\n".join(_convert(tmp_path, CISCO, "Huawei"))
    assert re.search(r"undo poe enable|REVIEW-POE", huawei)


# A banner of an Aruba 2540: one quoted string with "\\n" escapes, wrapped by the device over several lines; "banner motd" may stand alone on its line.
PROVISION_BANNER = (
    "Running configuration:\n\n"
    "; JL356A Configuration Editor; Created on release #YC.16.06.0006\n"
    'hostname "SW-LAB-2540"\n'
    "module 1 type jl356a\n"
    "banner motd\n"
    ' "#############\\n#\n'
    "          LAB NETWORK          # \\n#\n"
    "    Authorised users only      #\n"
    ' \\n#############\\n"\n'
    'banner exec "Welcome\n'
    ' to the lab \\n"\n'
    + "".join(f'vlan {n}\n   name "V{n}"\n   untagged {n - 9}\n   exit\n' for n in range(10, 30))
)


def test_a_wrapped_provision_banner_is_one_clean_banner_per_kind(tmp_path):
    cisco = _convert(tmp_path, PROVISION_BANNER, "Cisco")
    motd = next(index for index, line in enumerate(cisco) if line.startswith("banner motd ^"))
    assert cisco[motd] == "banner motd ^#############"
    assert cisco[motd + 1] == "#          LAB NETWORK          # "
    assert cisco[motd + 2] == "#    Authorised users only      # "
    assert cisco[motd + 3] == "#############^"
    assert cisco[motd + 4] == "banner exec ^Welcome to the lab ^"
    assert not any("REVIEW-UNSUPPORTED" in line and ("LAB NETWORK" in line or "Authorised" in line) for line in cisco)


def test_the_exec_banner_goes_to_the_shell_header_of_a_huawei_switch(tmp_path):
    huawei = _convert(tmp_path, PROVISION_BANNER, "Huawei")
    assert "header login information ^" in huawei and "header shell information ^" in huawei


def test_a_cisco_login_banner_is_not_written_back_as_a_second_motd(tmp_path):
    text = "hostname SW-LAB-C9300\nbanner login ^C\nlogin text\n^C\nbanner motd ^C\nmotd text\n^C\n" + CISCO.split("\n", 1)[1]
    cisco = [line for line in _convert(tmp_path, text, "Cisco") if line.startswith("banner ")]
    assert [line.split()[1] for line in cisco] == ["login", "motd"]


def test_an_aruba_source_gets_no_cisco_cdp_or_lldp_notes(tmp_path):
    aruba = "\n".join(_convert(tmp_path, PROVISION, "Aruba"))
    assert "REVIEW-CDP" not in aruba and "REVIEW-LLDP" not in aruba
    huawei = "\n".join(_convert(tmp_path, PROVISION, "Huawei"))
    assert "lldp enable" in huawei and "REVIEW-LLDP-NO-CDP-EQUIVALENT" not in huawei


def test_a_cisco_source_still_gets_them(tmp_path):
    assert "REVIEW-CDP" in "\n".join(_convert(tmp_path, CISCO, "Aruba"))
    assert "REVIEW-LLDP-NO-CDP-EQUIVALENT" in "\n".join(_convert(tmp_path, CISCO, "Huawei"))


# ----------------------------------------------------------------------------------------------- DHCP client address, fixed speed / duplex
def test_a_provision_vlan_that_takes_its_address_from_dhcp_stays_a_dhcp_client(tmp_path):
    assert " ip address dhcp" in _block(_convert(tmp_path, PROVISION, "Cisco"), "interface Vlan1")
    huawei = _convert(tmp_path, PROVISION, "Huawei")
    assert " ip address dhcp-alloc" in _block(huawei, "interface Vlanif1")
    assert huawei.index("dhcp enable") < huawei.index("interface Vlanif1")      # VRP wants DHCP switched on before the interface uses it


def test_a_dhcp_client_svi_of_a_cisco_source_is_kept_on_every_target(tmp_path):
    text = "hostname SW-LAB-C9300\ninterface Vlan1\n ip address dhcp\nend\n"
    assert " ip address dhcp" in _block(_convert(tmp_path, text, "Cisco"), "interface Vlan1")
    assert " ip address dhcp-alloc" in _block(_convert(tmp_path, text, "Huawei"), "interface Vlanif1")
    aruba = _block(_convert(tmp_path, text, "Aruba"), "interface vlan1")
    assert "    ip dhcp" in aruba and not any("REVIEW-DHCP-CLIENT" in line for line in aruba)       # VLAN 1 is where AOS-CX accepts it


def test_aos_cx_ip_dhcp_is_read_and_written_back(tmp_path):
    text = ("!Version AOS-CX ArubaOS-CX 10.10\nhostname CX-LAB\nssh server vrf mgmt\nvlan 1\ninterface mgmt\n    no shutdown\n    ip dhcp\n"
            "interface 1/1/1\n    no shutdown\n    vlan access 1\ninterface vlan 1\n    ip dhcp\n")
    assert " ip address dhcp" in _block(_convert(tmp_path, text, "Cisco"), "interface Vlan1")
    assert "    ip dhcp" in _block(_convert(tmp_path, text, "Aruba"), "interface vlan1")


CISCO_SPEED = """hostname SW-LAB-C9300
interface GigabitEthernet1/0/1
 switchport mode access
 speed 100
 duplex full
interface GigabitEthernet1/0/2
 switchport mode access
 speed 1000
interface GigabitEthernet1/0/3
 switchport mode access
 duplex half
interface GigabitEthernet1/0/4
 switchport mode access
 speed auto
 duplex auto
end
"""


def test_a_fixed_speed_and_duplex_are_written_on_every_target(tmp_path):
    cisco = _convert(tmp_path, CISCO_SPEED, "Cisco")
    port = _block(cisco, "interface GigabitEthernet1/0/1")
    assert " speed 100" in port and " duplex full" in port and any("REVIEW-SPEED" in line for line in port)
    assert " speed 1000" in _block(cisco, "interface GigabitEthernet1/0/2")
    assert not any(line.strip().startswith("duplex") for line in _block(cisco, "interface GigabitEthernet1/0/2"))     # not configurable at 1 Gbps
    aruba = _convert(tmp_path, CISCO_SPEED, "Aruba")
    assert "    speed 100-full" in _block(aruba, "interface 1/1/1")
    assert "    speed 1000-full" in _block(aruba, "interface 1/1/2")
    huawei = _convert(tmp_path, CISCO_SPEED, "Huawei")
    first = _block(huawei, "interface GE1/0/1")
    assert [line for line in first if line.strip() in ("undo negotiation auto", "speed 100", "duplex full")] == [" undo negotiation auto", " speed 100", " duplex full"]


def test_speed_cases_without_a_safe_form_are_review_lines_and_auto_is_silent(tmp_path):
    huawei = _convert(tmp_path, CISCO_SPEED, "Huawei")
    assert any("REVIEW-SPEED" in line and "speed 1000" in line for line in _block(huawei, "interface GE1/0/2"))      # 1000BASE-T needs auto-negotiation
    assert any("REVIEW-SPEED" in line and "duplex half" in line for line in _block(huawei, "interface GE1/0/3"))
    for target in ("Cisco", "Aruba", "Huawei"):
        port4 = next(index for index, line in enumerate(_convert(tmp_path, CISCO_SPEED, target)) if line.strip() in ("interface GigabitEthernet1/0/4", "interface 1/1/4", "interface GE1/0/4"))
        assert not any("speed" in line for line in _convert(tmp_path, CISCO_SPEED, target)[port4:port4 + 6]), target


def test_provision_speed_duplex_is_carried_and_a_limited_auto_is_left_alone(tmp_path):
    text = PROVISION.replace("interface 16\n   disable\n   exit\n", "interface 16\n   speed-duplex 100-full\n   exit\ninterface 17\n   speed-duplex auto-100\n   exit\n")
    cisco = _convert(tmp_path, text, "Cisco")
    assert " speed 100" in _block(cisco, "interface GigabitEthernet1/0/16") and " duplex full" in _block(cisco, "interface GigabitEthernet1/0/16")
    assert any("auto-100" in line for line in cisco)                                  # still a review line: it limits what is advertised
