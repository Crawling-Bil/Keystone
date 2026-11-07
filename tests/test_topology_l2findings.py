"""Topology findings TOPO-031 .. TOPO-034: trunk allowed-VLAN mismatch, STP root placement, default-priority root, uplink oversubscription.
Synthetic captures only (invented names and addresses; command layouts follow what IOS XE prints)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture  # noqa: E402

from features.topology.l2findings import ranges, vlan_set  # noqa: E402
from features.topology.service import build_topology  # noqa: E402
from features.topology.state import read_state  # noqa: E402


# ---- the small helpers --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [("1-4094", set(range(1, 4095))), ("10,21-23", {10, 21, 22, 23}), (" 10 , 20 ", {10, 20}), ("none", set()),
                                          ("all", set(range(1, 4095))), ("10,\n 12", {10, 12})])
def test_vlan_set_reads_the_lists_a_trunk_table_prints(text, expected):
    assert vlan_set(text) == frozenset(expected)


@pytest.mark.parametrize("text", ["", "abc", "10-5", "1-5000", "10,x", None])
def test_vlan_set_refuses_what_is_not_a_list(text):
    assert vlan_set(text) is None


def test_ranges():
    assert ranges({10, 11, 12, 20, 22, 23}) == "10-12,20,22-23" and ranges(set()) == "" and ranges([5]) == "5"


# ---- synthetic captures -------------------------------------------------------------------------------------------

def trunk_text(host: str, rows: list[tuple], native: str = "1") -> str:
    """rows: (port, allowed, active or None).  Prints the four blocks of 'show interfaces trunk'; no 'active' block when no row has one."""
    out = [f"{host}#show interfaces trunk\n\nPort        Mode             Encapsulation  Status        Native vlan\n"]
    out += [f"{port:<11} on               802.1q         trunking      {native}\n" for port, _, _ in rows]
    out.append("\nPort        Vlans allowed on trunk\n" + "".join(f"{port:<11} {allowed}\n" for port, allowed, _ in rows))
    if any(active is not None for _, _, active in rows):
        out.append("\nPort        Vlans allowed and active in management domain\n" + "".join(f"{port:<11} {active}\n" for port, _, active in rows if active is not None))
    return "".join(out)


def stp_text(host: str, mac: str, root_mac: str, priority: int = 32768, root_priority: int | None = None, vlan: int = 1) -> str:
    """One VLAN of 'show spanning-tree'; the switch is the root when ``root_mac`` is its own address."""
    root_priority = priority + vlan if root_priority is None else root_priority
    root_lines = ("             This bridge is the root\n" if root_mac == mac else "             Cost        4\n             Port        1 (TenGigabitEthernet1/1/1)\n")
    return (f"{host}#show spanning-tree\n\nVLAN{vlan:04d}\n  Spanning tree enabled protocol rstp\n  Root ID    Priority    {root_priority}\n"
            f"             Address     {root_mac}\n{root_lines}             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec\n\n"
            f"  Bridge ID  Priority    {priority + vlan}  (priority {priority} sys-id-ext {vlan})\n             Address     {mac}\n"
            "             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec\n             Aging Time  300 sec\n\n"
            "Interface           Role Sts Cost      Prio.Nbr Type\n------------------- ---- --- --------- -------- ----------------\n"
            "Te1/1/1             Desg FWD 4         128.25   P2p\n")


def status_text(host: str, uplink: str, uplink_speed: str, edge: int, edge_speed: str = "a-1000") -> str:
    rows = [f"{uplink:<9} Uplink             connected    trunk      full    {uplink_speed:<6} SFP-10GBase-SR\n"]
    rows += [f"Gi1/0/{n:<2}                      connected    10         a-full  {edge_speed:<6} 10/100/1000BaseTX\n" for n in range(1, edge + 1)]
    return f"{host}#show interfaces status\n\nPort      Name               Status       Vlan       Duplex  Speed Type\n" + "".join(rows)


CORE_MAC, ACC1_MAC, ACC2_MAC = "0011.2233.0001", "0011.2233.0101", "0011.2233.0102"


def lab(core_allowed="10,20,30", core_active="10,20,30", acc_allowed="10,20", acc_active="10,20", acc_edge=4, acc_uplink="10G", acc_root=False,
        core_priority=4096, acc_priority=32768, with_core=True, acc_uplink_name="Te1/1/1"):
    """A core switch and one access switch joined by one link (core Te1/1/1 - access <acc_uplink_name>)."""
    acc_cdp = [("LAB-CORE1.lab.example(FOC00000010)", "10.98.0.1", "C9500-24Y4C", acc_uplink_name.replace("Te", "TenGigabitEthernet"), "TenGigabitEthernet1/1/1")]
    core_cdp = [("LAB-ACC1.lab.example(FOC00000011)", "10.98.0.11", "C9300L-48P-4X", "TenGigabitEthernet1/1/1", acc_uplink_name.replace("Te", "TenGigabitEthernet"))]
    acc_root_mac = ACC1_MAC if acc_root else CORE_MAC
    core_text = stp_text("LAB-CORE1", CORE_MAC, CORE_MAC if not acc_root else ACC1_MAC, priority=core_priority) if with_core else ""
    core = iosxe_capture("LAB-CORE1", "FOC00000010", "10.98.0.1", cdp=core_cdp, model="C9500-24Y4C",
                         extra=trunk_text("LAB-CORE1", [("Te1/1/1", core_allowed, core_active)]) + "\n" + core_text + "\n"
                         + status_text("LAB-CORE1", "Te1/1/1", "10G", 0))
    acc = iosxe_capture("LAB-ACC1", "FOC00000011", "10.98.0.11", cdp=acc_cdp, model="C9300L-48P-4X",
                        extra=trunk_text("LAB-ACC1", [(acc_uplink_name, acc_allowed, acc_active)]) + "\n"
                        + stp_text("LAB-ACC1", ACC1_MAC, acc_root_mac, priority=acc_priority) + "\n" + status_text("LAB-ACC1", acc_uplink_name, acc_uplink, acc_edge))
    return {"LAB-CORE1.txt": core, "LAB-ACC1.txt": acc}


def findings(files, code=None):
    result = build_topology(list(files.items()), group="none")
    return [f for f in result["findings"] if code is None or f["id"] == code], result


# ---- TOPO-031 -----------------------------------------------------------------------------------------------------

def test_a_vlan_active_at_one_end_and_not_allowed_at_the_other_is_a_medium_finding():
    rows, _ = findings(lab(), "TOPO-031")
    assert len(rows) == 1 and rows[0]["severity"] == "medium"
    assert "VLAN 30 (active on LAB-CORE1) is dropped at LAB-ACC1" in rows[0]["detail"]
    assert rows[0]["devices"] == ["LAB-ACC1", "LAB-CORE1"] and "hacampus" not in rows[0]["reference"] and "configuring_vlan_trunks" in rows[0]["reference"]


def test_equal_allowed_lists_are_no_finding():
    assert findings(lab(core_allowed="10,20", core_active="10,20"), "TOPO-031")[0] == []


def test_one_end_allowing_every_vlan_is_fine_when_the_other_end_carries_all_that_is_active():
    assert findings(lab(core_allowed="1-4094", core_active="10,20", acc_allowed="10,20,30"), "TOPO-031")[0] == []


def test_all_vlans_against_a_list_is_found_through_the_active_vlans():
    rows, _ = findings(lab(core_allowed="1-4094", core_active="10,20,30", acc_allowed="10,20"), "TOPO-031")
    assert len(rows) == 1 and rows[0]["severity"] == "medium" and "VLAN 30" in rows[0]["detail"]


def test_all_vlans_against_a_list_without_any_active_table_is_not_judged():
    assert findings(lab(core_allowed="1-4094", core_active=None, acc_allowed="10,20", acc_active=None), "TOPO-031")[0] == []


def test_two_explicit_lists_without_active_tables_are_a_low_finding():
    rows, _ = findings(lab(core_active=None, acc_active=None), "TOPO-031")
    assert len(rows) == 1 and rows[0]["severity"] == "low" and "VLAN 30 (allowed on LAB-CORE1) is not allowed at LAB-ACC1" in rows[0]["detail"]


def test_both_directions_are_reported():
    rows, _ = findings(lab(core_allowed="10,20,30", core_active="10,20,30", acc_allowed="10,20,40", acc_active="10,20,40"), "TOPO-031")
    assert "VLAN 30 (active on LAB-CORE1) is dropped at LAB-ACC1" in rows[0]["detail"] and "VLAN 40 (active on LAB-ACC1) is dropped at LAB-CORE1" in rows[0]["detail"]


def test_an_uncaptured_end_is_not_compared():
    files = lab()
    del files["LAB-ACC1.txt"]
    assert findings(files, "TOPO-031")[0] == []


# ---- TOPO-032 / TOPO-033 ------------------------------------------------------------------------------------------

def test_an_access_switch_that_is_root_while_a_core_is_captured_is_a_medium_finding():
    rows, _ = findings(lab(acc_root=True), "TOPO-032")
    assert len(rows) == 1 and rows[0]["severity"] == "medium" and rows[0]["devices"] == ["LAB-ACC1"]
    assert "LAB-ACC1 (access) is the root of VLAN0001" in rows[0]["detail"] and "LAB-CORE1" in rows[0]["recommendation"]
    assert "10556-16" in rows[0]["reference"]


def test_a_core_that_is_root_is_fine():
    rows, _ = findings(lab(), "TOPO-032")
    assert rows == []


def test_without_a_core_or_distribution_switch_nothing_says_the_root_is_misplaced():
    files = lab(acc_root=True)
    del files["LAB-CORE1.txt"]
    assert findings(files, "TOPO-032")[0] == []


def test_a_root_with_the_default_priority_is_a_low_finding_and_a_set_priority_is_not():
    rows, _ = findings(lab(acc_root=True), "TOPO-033")
    assert len(rows) == 1 and rows[0]["severity"] == "low" and rows[0]["devices"] == ["LAB-ACC1"]
    assert findings(lab(core_priority=4096), "TOPO-033")[0] == []                     # the core is root with priority 4096
    default_core = findings(lab(core_priority=32768), "TOPO-033")[0]
    assert len(default_core) == 1 and default_core[0]["devices"] == ["LAB-CORE1"]


def test_the_root_facts_are_kept_in_the_saved_state():
    from features.topology.service import to_json
    files = lab(acc_root=True)
    result = build_topology(list(files.items()), group="none")
    document = to_json(result["graph"], result["findings"], result["devices"], result["settings"]).encode()
    saved = {d.hostname: d for d in read_state(document)}
    assert saved["LAB-ACC1"].stp_root_for == ["VLAN0001"] and saved["LAB-ACC1"].stp_root_default == ["VLAN0001"]
    assert saved["LAB-ACC1"].port_allowed == {"Te1/1/1": "10,20"} and saved["LAB-ACC1"].port_active == {"Te1/1/1": "10,20"}
    again = build_topology([], previous=list(saved.values()), group="none")
    assert any(f["id"] == "TOPO-032" for f in again["findings"])


# ---- TOPO-034 -----------------------------------------------------------------------------------------------------

def test_edge_ports_far_above_the_uplink_are_reported():
    rows, _ = findings(lab(acc_edge=24, acc_uplink="1000", acc_uplink_name="Gi1/1/1"), "TOPO-034")
    assert len(rows) == 1 and rows[0]["devices"] == ["LAB-ACC1"] and "24G of active ports behind 1G of uplink (24:1, guideline 20:1)" in rows[0]["detail"]
    assert rows[0]["severity"] == "info" and "hacampusdg" in rows[0]["reference"]


def test_a_ratio_of_more_than_twice_the_guideline_is_low():
    rows, _ = findings(lab(acc_edge=48, acc_uplink="1000", acc_uplink_name="Gi1/1/1"), "TOPO-034")
    assert rows and rows[0]["severity"] == "low" and "(48:1" in rows[0]["detail"]


def test_a_ratio_within_the_guideline_is_no_finding():
    assert findings(lab(acc_edge=24, acc_uplink="10G"), "TOPO-034")[0] == []


def test_ports_that_are_down_do_not_count():
    files = lab(acc_edge=24, acc_uplink="1000", acc_uplink_name="Gi1/1/1")
    files["LAB-ACC1.txt"] = files["LAB-ACC1.txt"].replace("connected    10         a-full  a-1000", "notconnect   10         auto    auto  ")
    assert findings(files, "TOPO-034")[0] == []


def test_a_capture_without_interface_speeds_is_not_judged():
    files = lab(acc_edge=24, acc_uplink="1000", acc_uplink_name="Gi1/1/1")
    files["LAB-ACC1.txt"] = files["LAB-ACC1.txt"].split("LAB-ACC1#show interfaces status")[0] + "LAB-ACC1#\n"
    assert findings(files, "TOPO-034")[0] == []


def test_the_new_findings_reach_the_per_device_roll_up():
    _, result = findings(lab(acc_root=True))
    rolled = {row["device"]: row for row in result["findings_by_device"]}
    assert "TOPO-032" in rolled["LAB-ACC1"]["findings"] and "TOPO-031" in rolled["LAB-ACC1"]["findings"]


# ---- the analyzer keeps what the topology needs --------------------------------------------------------------------

def test_a_port_listed_only_in_the_status_table_keeps_its_speed_and_duplex():
    from features.switch_analyzer.service import analyze
    rows = {r["name"]: r for r in analyze(lab(acc_edge=2)["LAB-ACC1.txt"], filename="x.txt")["interfaces"]}
    assert (rows["Gi1/0/1"]["speed_mbps"], rows["Gi1/0/1"]["duplex"]) == (1000, "full")
    assert rows["Te1/1/1"]["speed_mbps"] == 10000


def test_trunk_allowed_lists_and_root_facts_are_read_from_the_capture():
    result = build_topology(list(lab(acc_root=True).items()), group="none")
    acc = next(n for n in result["graph"].nodes.values() if n.hostname == "LAB-ACC1")
    assert acc.port_allowed == {"Te1/1/1": "10,20"} and acc.port_active == {"Te1/1/1": "10,20"}
    assert acc.stp_root_for == ["VLAN0001"] and acc.stp_root_default == ["VLAN0001"] and acc.stp_protocol == "rstp"
