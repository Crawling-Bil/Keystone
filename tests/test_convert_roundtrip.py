"""Round-trip check of a switch conversion, and the converter defects it found (synthetic input only: invented names, documentation addresses)."""

from __future__ import annotations

from pathlib import Path

import pytest

from features.configuration_studio import service
from features.configuration_studio.converter_engine.roundtrip import (
    check_conversion, expand_vlans, lag_modes, reading_copy, review_index, service_values, stanzas,
)

FIXTURES = Path(__file__).parent / "fixtures" / "switch"

CISCO = """hostname LAB-RT1
!
vlan 10
 name USERS
vlan 20
 name VOICE
!
interface Port-channel1
 description UPLINK-CORE
 switchport mode trunk
 switchport trunk allowed vlan 10,20
!
interface GigabitEthernet1/0/1
 description LAB-PC
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
!
interface GigabitEthernet1/0/47
 channel-group 1 mode active
 switchport mode trunk
 switchport trunk allowed vlan 10,20
!
interface GigabitEthernet1/0/48
 channel-group 1 mode active
 switchport mode trunk
 switchport trunk allowed vlan 10,20
!
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 ip helper-address 198.51.100.10
!
ip route 0.0.0.0 0.0.0.0 192.0.2.254
ntp server 198.51.100.1
logging host 198.51.100.2
snmp-server community LABRO RO
snmp-server location LAB-ROOM
end
"""

ARUBA_OS_S = """; JL356A Configuration Editor; Created on release #YC.16.06.0006
hostname "LAB-AS1"
snmp-server contact "ops@example.invalid" location "LAB-ROOM"
vlan 1
   name "DEFAULT_VLAN"
   untagged 1-24
   exit
vlan 10
   name "USERS"
   untagged 1-4
   exit
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _convert(path: Path, target: str) -> dict:
    return service.convert_file(path, target_vendor=target)


def _roundtrip(path: Path, target: str, mutate=None) -> dict:
    """Convert, optionally damage the converted text, and run the check on it (the way ``convert_file`` does)."""
    engine = service.create_engine()
    vendor, device_type, _detection = service._resolve_source(engine, path, None, "Auto Detect", "Auto Detect")
    config, lines = engine.convert(filename=path, source_vendor=vendor, source_device_type=device_type, target_vendor=target, target_device_type=device_type)
    text = "\n".join(str(line) for line in lines) + "\n"
    if mutate:
        text = mutate(text)
    return check_conversion(engine, path, source_vendor=vendor, target_vendor=target, output_text=text,
                            port_map=(config.metadata or {}).get("port_map"), include_same=True)


def _rows(result: dict, status: str | None = None, area: str | None = None) -> list[dict]:
    return [r for r in result["rows"] if (status is None or r["status"] == status) and (area is None or r["area"] == area)]


# ---- the comparison ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("target", ["Huawei", "Aruba"])
def test_a_clean_conversion_reads_back_the_same(tmp_path, target):
    result = _roundtrip(_write(tmp_path, "cisco.cfg", CISCO), target)
    assert result["verdict"] in ("equivalent", "flagged"), _rows(result, "missing") + _rows(result, "changed")
    assert result["silent"] == 0
    assert {r["area"] for r in _rows(result, "same")} >= {"VLAN", "Port", "Bundle", "SVI", "Route", "Service"}


def test_a_dropped_line_is_found_and_is_silent(tmp_path):
    path = _write(tmp_path, "cisco.cfg", CISCO)
    broken = _roundtrip(path, "Huawei", mutate=lambda text: "\n".join(l for l in text.splitlines() if "ntp-service" not in l and "ip route-static" not in l) + "\n")
    missing = {(r["area"], r["item"]) for r in _rows(broken, "missing")}
    assert ("Service", "NTP server 198.51.100.1") in missing
    assert any(area == "Route" for area, _ in missing)
    assert broken["verdict"] == "differences" and broken["silent"] >= 2


def test_a_changed_value_is_found(tmp_path):
    path = _write(tmp_path, "cisco.cfg", CISCO)
    broken = _roundtrip(path, "Huawei", mutate=lambda text: text.replace("port default vlan 10", "port default vlan 99"))
    changed = _rows(broken, "changed", "Port")
    assert changed and changed[0]["source"] == "access_vlan: 10" and changed[0]["target"] == "access_vlan: 99"


def test_a_difference_next_to_a_review_line_is_marked_not_silent(tmp_path):
    path = _write(tmp_path, "cisco.cfg", CISCO)
    broken = _roundtrip(path, "Huawei", mutate=lambda text: "\n".join(l for l in text.splitlines() if "ntp-service" not in l) + "\n# REVIEW-NTP: left out on purpose\n")
    row = next(r for r in _rows(broken, "missing") if r["item"].startswith("NTP server"))
    assert row["flagged"] is True and broken["verdict"] == "flagged"


def test_a_bundle_that_changes_from_lacp_to_static_is_found(tmp_path):
    path = _write(tmp_path, "cisco.cfg", CISCO)
    broken = _roundtrip(path, "Huawei", mutate=lambda text: text.replace("mode lacp-static", ""))
    assert any(r["item"] == "Bundle 1 mode" and r["source"] == "lacp" and r["target"] == "static" for r in _rows(broken, "changed"))


def test_the_text_is_unreadable_when_the_target_parser_finds_nothing(tmp_path):
    path = _write(tmp_path, "cisco.cfg", CISCO)
    broken = _roundtrip(path, "Huawei", mutate=lambda text: "sysname X\n")
    assert broken["verdict"] == "unreadable" and "no interface" in broken["reason"]


def test_a_vendor_without_a_parser_has_no_result(tmp_path):
    engine = service.create_engine()
    assert check_conversion(engine, _write(tmp_path, "c.cfg", CISCO), source_vendor="Cisco", target_vendor="Mikrotik", output_text="x", port_map={}) == {}


def test_no_comparison_is_made_of_a_file_without_configuration(tmp_path):
    result = _roundtrip(_write(tmp_path, "cisco.cfg", "hostname LAB-X\nend\n"), "Huawei")
    assert result["verdict"] in ("empty", "unreadable")


def test_convert_file_carries_the_result_for_a_switch(tmp_path):
    result = _convert(_write(tmp_path, "cisco.cfg", CISCO), "Huawei")
    assert result["roundtrip"]["verdict"] in ("equivalent", "flagged")
    assert all(r["status"] != "same" for r in result["roundtrip"]["rows"])           # the agreeing rows are counted, not sent
    assert result["roundtrip"]["same"] > 0


# ---- the helpers -------------------------------------------------------------------------------------------------------

def test_vlan_lists_are_compared_as_sets():
    assert expand_vlans(["10", "20-22"]) == frozenset({10, 20, 21, 22})
    assert expand_vlans(["10 to 12"]) == frozenset({10, 11, 12})
    assert expand_vlans([]) == "all" and expand_vlans(["all"]) == "all" and expand_vlans(["1-4094"]) == "all"


def test_stanzas_end_at_the_next_column_one_line():
    text = "interface GigabitEthernet1/0/1\n description a\n # REVIEW-X\n#\n! REVIEW-VTY: later\ninterface Vlan1\n ip address dhcp\n"
    blocks = stanzas(text)
    assert blocks["ge1/0/1"] == [" description a", " # REVIEW-X"] and blocks["vlan1"] == [" ip address dhcp"]


def test_bundle_modes_are_read_from_the_text_of_each_vendor():
    assert lag_modes("interface Eth-Trunk1\n mode lacp-static\n#\ninterface Eth-Trunk2\n#\n", "Huawei") == {"1": "lacp", "2": "static"}
    assert lag_modes("interface lag 5\n    lacp mode active\n!\ninterface lag 6\n!\n", "Aruba") == {"5": "lacp", "6": "static"}
    assert lag_modes("interface Gi1/0/1\n channel-group 3 mode on\n!\ninterface Gi1/0/2\n channel-group 4 mode active\n", "Cisco") == {"3": "static", "4": "lacp"}


def test_services_are_read_from_the_text_and_comments_are_skipped():
    huawei = "ntp-service unicast-server 198.51.100.1\n# ntp-service unicast-server 198.51.100.9\ninfo-center loghost 198.51.100.2\n"
    found = service_values(huawei, "Huawei")
    assert found["ntp"] == {"198.51.100.1"} and found["syslog"] == {"198.51.100.2"}


def test_review_codes_tie_a_line_to_a_topic():
    text = "# REVIEW-SNMP-COMMUNITY: x\n# REVIEW-UNSUPPORTED-COMMANDS\n# CISCO: tacacs-server host 192.0.2.5\n"
    codes = dict(review_index(text))
    assert "REVIEW-SNMP-COMMUNITY" in codes and "tacacs-server host 192.0.2.5" in codes["REVIEW-UNSUPPORTED-COMMANDS"]


def test_the_reading_copy_drops_quoted_commands_but_keeps_banners():
    text = "banner motd ^\n######\n^C\n! REVIEW-UNSUPPORTED: SW1# show running-config\n"
    copy = reading_copy(text)
    assert "######" in copy and "show running-config" not in copy


# ---- the defects the check found (each was silent) ---------------------------------------------------------------------

def test_aruba_numbered_ports_become_huawei_ports(tmp_path):
    out = _convert(_write(tmp_path, "aruba.cfg", ARUBA_OS_S), "Huawei")["output_text"]
    names = [l for l in out.splitlines() if l.startswith("interface ") and "Vlanif" not in l]
    assert names and all(n.startswith("interface GE") for n in names), names
    assert "interface 1\n" not in out


def test_the_lacp_mode_is_on_the_aruba_lag_not_on_the_member(tmp_path):
    out = _convert(_write(tmp_path, "cisco.cfg", CISCO), "Aruba")["output_text"].splitlines()
    lag = out.index("interface lag 1")
    assert "    lacp mode active" in out[lag:lag + 8]
    member = out.index("interface 1/1/47")
    assert "    lacp mode active" not in out[member:member + 10]


def test_aruba_dhcp_relay_uses_ip_helper_address(tmp_path):
    out = _convert(_write(tmp_path, "cisco.cfg", CISCO), "Aruba")["output_text"]
    assert "    ip helper-address 198.51.100.10" in out and "dhcp-relay 198" not in out


def test_huawei_vpn_instance_routes_keep_their_vrf():
    from features.configuration_studio.converter_engine.parsers.switch.huawei import HuaweiSwitchParser
    import tempfile, os
    text = "sysname LAB-HW\n#\nip route-static vpn-instance MGMT 0.0.0.0 0.0.0.0 192.0.2.1\nip route-static 10.9.0.0 255.255.0.0 192.0.2.2 preference 70\n#\nreturn\n"
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "h.cfg")
        Path(path).write_text(text, encoding="utf-8")
        routes = HuaweiSwitchParser().parse_file(path).routes
    assert [(r.destination, r.mask, r.next_hop, r.vrf, r.distance) for r in routes] == [
        ("0.0.0.0", "0.0.0.0", "192.0.2.1", "MGMT", None), ("10.9.0.0", "255.255.0.0", "192.0.2.2", "", 70)]


def test_aruba_cx_routes_keep_their_vrf_and_multi_chassis_lags_their_number(tmp_path):
    from features.configuration_studio.converter_engine.parsers.switch.aruba import ArubaSwitchParser
    text = "hostname LAB-CX\nvrf mgmt\nvlan 10\n    name USERS\ninterface lag 101 multi-chassis\n    no shutdown\n    vlan trunk allowed 10\ninterface lag 102\n    no shutdown\nip route 0.0.0.0/0 192.0.2.1 vrf mgmt\nip route 10.0.0.0/8 192.0.2.2\n"
    config = ArubaSwitchParser().parse_file(_write(tmp_path, "cx.cfg", text))
    assert [(r.destination, r.next_hop, r.vrf) for r in config.routes] == [("0.0.0.0", "192.0.2.1", "mgmt"), ("10.0.0.0", "192.0.2.2", "")]
    assert {i.name for i in config.interfaces if i.name.startswith("Port-channel")} == {"Port-channel101", "Port-channel102"}


def test_the_aruba_contact_and_location_line_is_split(tmp_path):
    out = _convert(_write(tmp_path, "aruba.cfg", ARUBA_OS_S), "Huawei")["output_text"]
    assert "snmp-agent sys-info contact ops@example.invalid" in out and "snmp-agent sys-info location LAB-ROOM" in out
    assert '"' not in "".join(l for l in out.splitlines() if "sys-info" in l)


def test_nxos_syslog_servers_are_configured(tmp_path):
    text = "hostname LAB-NX\nfeature lldp\nlogging server 198.51.100.2 5 use-vrf management\nlogging server 198.51.100.3\nvlan 10\n name USERS\n" + "interface Ethernet1/1\n switchport\n switchport access vlan 10\n"
    path = _write(tmp_path, "nx.cfg", text)
    huawei = _convert(path, "Huawei")["output_text"]
    assert "info-center loghost 198.51.100.2" in huawei and "info-center loghost 198.51.100.3" in huawei
    assert "logging 198.51.100.2" in _convert(path, "Aruba")["output_text"]


def test_huawei_snmp_communities_are_not_dropped(tmp_path):
    text = ("sysname LAB-HW\n#\nsnmp-agent\nsnmp-agent community read cipher %^%#LABCIPHER%^%#\nsnmp-agent community write plainlab\n"
            "snmp-agent sys-info location LAB-ROOM\n#\ninterface GigabitEthernet0/0/1\n port link-type access\n#\nreturn\n")
    out = _convert(_write(tmp_path, "hw.cfg", text), "Cisco")["output_text"]
    assert "REVIEW-SNMP-COMMUNITY" in out and "snmp-server community plainlab RW" in out and "snmp-server location LAB-ROOM" in out
    assert "! snmp-server community <NEW-RO-COMMUNITY-STRING> RO" in out                  # the cipher cannot be decoded: a commented template, never a live line


def test_a_standalone_huawei_unit_zero_is_member_one_on_the_target(tmp_path):
    text = "sysname LAB-HW\n#\ninterface GigabitEthernet0/0/1\n port link-type access\n#\nreturn\n"
    path = _write(tmp_path, "hw.cfg", text)
    assert "interface 1/1/1" in _convert(path, "Aruba")["output_text"]
    assert "interface GigabitEthernet1/0/1" in _convert(path, "Cisco")["output_text"]


# ---- regression guard: nothing the sample set converts is lost without a REVIEW line -------------------------------------

@pytest.mark.parametrize("sample", sorted(p.name for p in FIXTURES.glob("*.txt")))
@pytest.mark.parametrize("target", ["Huawei", "Aruba", "Cisco"])
def test_the_synthetic_samples_lose_nothing_silently(sample, target):
    path = FIXTURES / sample
    try:
        result = _convert(path, target)
    except ValueError:
        pytest.skip("not a convertible configuration (a collection of show outputs)")
    if result["source_vendor"].lower() == target.lower():
        pytest.skip("same vendor")
    roundtrip = result["roundtrip"]
    assert roundtrip is not None
    assert roundtrip["verdict"] != "unreadable", roundtrip.get("reason")
    assert roundtrip["silent"] == 0, [(r["area"], r["item"], r["source"], r["target"]) for r in roundtrip["rows"] if not r["flagged"]]
