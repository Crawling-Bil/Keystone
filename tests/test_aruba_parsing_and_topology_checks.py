"""Aruba AOS-CX ACL conversion, CDP capabilities, wireless clients behind access points, capture gaps. Synthetic only."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import nxos_capture, nxos_mac_table  # noqa: E402

from features.configuration_studio.converter_engine.parsers.switch import aruba_acl  # noqa: E402
from features.switch_analyzer.service import analyze  # noqa: E402
from features.topology.service import _csv_safe, build_topology, behind_table, capture_gap, links_table  # noqa: E402


# ---- AOS-CX ACLs ---------------------------------------------------------------------------------------------------

def test_aoscx_acl_expands_object_groups_and_drops_counters():
    groups = {("address", "SRV"): ["10 192.0.2.10", "20 192.0.2.0/255.255.255.240"], ("address", "NET"): ["10 198.51.100.0/24"]}
    commands = ["access-list ip DEMO_IN", "10 permit tcp group SRV group NET eq 443 log count", "20 deny any any any", "30 permit any 203.0.113.5 any"]
    out, notes = aruba_acl.convert(commands, groups)
    assert out[0] == "ip access-list extended DEMO_IN"
    https = [line for line in out if "eq 443" in line]
    assert len(https) == 2 and all("count" not in line and line.endswith("log") for line in https)
    assert any("deny ip any any" in line for line in out)
    assert any("permit ip host 203.0.113.5 any" in line for line in out)
    assert len(notes) == 1 and "expanded to 2 rules" in notes[0]


def test_aoscx_acl_unreadable_entry_is_kept_and_noted():
    out, notes = aruba_acl.convert(["access-list ip X", "10 permit nonsense-proto any any"], {})
    assert "10 permit nonsense-proto any any" in out[-1] or "permit nonsense-proto any any" in out[-1]
    assert notes


# ---- CDP capabilities ----------------------------------------------------------------------------------------------

def test_cdp_capabilities_reach_the_neighbor_row():
    text = nxos_capture("CAPS1", "FDO00000011", "10.98.0.1", cdp=[("AP-1", "10.98.1.1", "AIR-AP2802I", "Ethernet1/5", "GigabitEthernet0", "Trans-Bridge IGMP")])
    rows = analyze(text, filename="c.txt")["neighbors"]
    assert any("Trans-Bridge" in str(row.get("capabilities", "")) for row in rows)


# ---- wireless clients behind an access point -----------------------------------------------------------------------

def _wireless_files(clients: int) -> list[tuple[str, str]]:
    macs = [("10", f"0200.5e00.{i:04x}".replace("0200", "0a00"), "Eth1/5") for i in range(clients)]
    text = nxos_capture("WL-SW1", "FDO00000012", "10.98.0.2",
                        cdp=[("WL-AP1", "10.98.1.2", "AIR-AP2802I", "Ethernet1/5", "GigabitEthernet0", "Trans-Bridge IGMP")]) + nxos_mac_table("WL-SW1", macs)
    return [("wl.txt", text)]


def test_macs_behind_an_access_point_are_wireless_clients_not_a_many_macs_finding():
    result = build_topology(_wireless_files(12), include_hosts=True)
    graph = result["graph"]
    assert not [i for i in graph.issues if i["type"] == "many-macs"]
    assert sum(graph.nodes["WL-SW1"].wireless_clients.values()) == 12
    assert not [n for n in graph.nodes if str(n).startswith(("HOST:", "HOSTS:"))]
    rows = behind_table(graph)
    assert rows and rows[0]["behind_role"] == "ap" and rows[0]["mac_addresses"] == 12


# ---- capture gaps ---------------------------------------------------------------------------------------------------

def test_capture_without_a_configuration_command_is_reported():
    text = "x\n" * 7 + "sw1#show version\na\nsw1#show cdp neighbors\nb\nsw1#show vlan\nc\nsw1#show mac address-table\nd\n"
    assert "scrolled" in capture_gap(text)
    assert capture_gap("sw1#show running-config\na\nsw1#show version\nb\nsw1#show vlan\nc\nsw1#show mac address-table\nd\n") == ""
    assert capture_gap("just a fragment\nwith no prompt\n") == ""


def test_csv_cells_keep_a_lone_dash_but_neutralise_formulas():
    assert _csv_safe("-") == "-"
    assert _csv_safe("=1+1") == "'=1+1"
    assert _csv_safe("-5") == "-5"


def test_links_table_carries_rating_state_and_duplex_columns():
    files = [("a.txt", nxos_capture("LK-A", "FDO00000013", "10.98.0.3", cdp=[("LK-B", "10.98.0.4", "N9K-C93180YC-FX3", "Ethernet1/1", "Ethernet1/1")])),
             ("b.txt", nxos_capture("LK-B", "FDO00000014", "10.98.0.4", cdp=[("LK-A", "10.98.0.3", "N9K-C93180YC-FX3", "Ethernet1/1", "Ethernet1/1")]))]
    row = links_table(build_topology(files)["graph"])[0]
    assert {"rated_a", "rated_b", "port_state_a", "port_state_b", "duplex_a", "duplex_b"} <= set(row)
