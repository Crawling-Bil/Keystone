"""TOPO-040 to TOPO-043: bundles, OSPF adjacencies, HSRP groups and addresses compared between two captured devices.

Synthetic captures only (invented names, documentation addresses; layouts follow what IOS XE and NX-OS print)."""

from __future__ import annotations

import sys

import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_topology_params import OSPF_IOS, OSPF_NXOS, po_pair  # noqa: E402
from topology_samples import iosxe_capture, nxos_capture  # noqa: E402

from features.topology import service  # noqa: E402

IDS = ("TOPO-040", "TOPO-041", "TOPO-042", "TOPO-043")


def found(files: dict[str, str]) -> dict[str, dict]:
    result = service.build_topology(list(files.items()), group="none")
    return {f["id"]: f for f in result["findings"] if f["id"] in IDS}


# ---- TOPO-040 bundles ---------------------------------------------------------------------------------------------

def members(mode: str) -> str:
    return f" channel-group 1 mode {mode}\n"


def bundle_pair(ios_mode: str, nxos_mode: str, ios_protocol: str = "LACP", nxos_protocol: str = "LACP") -> dict[str, str]:
    files = po_pair("", "")
    ios = files["LAB-R1.txt"].replace(" channel-group 1 mode active\n", members(ios_mode)).replace("Po1(SU)         LACP", f"Po1(SU)         {ios_protocol}")
    nxos = files["LAB-R2.txt"].replace("  channel-group 1 mode active\n", f"  channel-group 1 mode {nxos_mode}\n").replace("Po1(SU)   Eth      LACP", f"Po1(SU)   Eth      {nxos_protocol}")
    return {"LAB-R1.txt": ios, "LAB-R2.txt": nxos}


def test_lacp_active_and_passive_form_a_bundle():
    assert found(bundle_pair("active", "passive")) == {} and found(bundle_pair("active", "active")) == {}


def test_lacp_passive_at_both_ends_is_reported():
    row = found(bundle_pair("passive", "passive"))["TOPO-040"]
    assert row["severity"] == "medium" and "LACP passive at both ends" in row["detail"] and "LAB-R1 Po1 - LAB-R2 Po1" in row["detail"]
    assert row["reference"].endswith("221051-troubleshoot-link-aggregation-control-pr.html") and row["devices"] == ["LAB-R1", "LAB-R2"]


def test_lacp_against_a_static_bundle_is_reported():
    row = found(bundle_pair("active", "on", nxos_protocol="-"))["TOPO-040"]
    assert "LACP at LAB-R1, static at LAB-R2" in row["detail"]


def test_lacp_against_pagp_is_reported():
    assert "LACP at LAB-R1, PAgP at LAB-R2" in found(bundle_pair("active", "desirable", nxos_protocol="PAgP"))["TOPO-040"]["detail"]


def test_pagp_auto_at_both_ends_is_reported():
    assert "PAgP auto at both ends" in found(bundle_pair("auto", "auto", "PAgP", "PAgP"))["TOPO-040"]["detail"]


# ---- TOPO-041 OSPF adjacency --------------------------------------------------------------------------------------

def routers(ios_neighbor: str, nxos_neighbors: str) -> dict[str, str]:
    ios_cfg = "interface GigabitEthernet1/0/1\n no switchport\n ip address 10.60.0.1 255.255.255.252\n" + OSPF_IOS + "!\nrouter ospf 1\n router-id 10.60.255.1\n!\n"
    nxos_cfg = "interface Ethernet1/1\n  no switchport\n  ip address 10.60.0.2/30\n" + OSPF_NXOS + "router ospf 1\n  router-id 10.60.255.2\n"
    ios_cdp = [("LAB-R2.lab.example(FDO96000002)", "10.60.255.2", "N9K-C93180YC-FX3", "GigabitEthernet1/0/1", "Ethernet1/1")]
    nxos_cdp = [("LAB-R1.lab.example(FDO96000001)", "10.60.255.1", "C9300-48P", "Ethernet1/1", "GigabitEthernet1/0/1")]
    ios_show = ("LAB-R1#show ip ospf neighbor\n\nNeighbor ID     Pri   State           Dead Time   Address         Interface\n" + ios_neighbor)
    nxos_show = ("LAB-R2# show ip ospf neighbors\n OSPF Process ID 1 VRF default\n Total number of neighbors: 1\n"
                 " Neighbor ID     Pri State            Up Time  Address         Interface\n" + nxos_neighbors)
    return {"LAB-R1.txt": iosxe_capture("LAB-R1", "FDO96000001", "10.60.255.1", cdp=ios_cdp, config_extra=ios_cfg, extra=ios_show),
            "LAB-R2.txt": nxos_capture("LAB-R2", "FDO96000002", "10.60.255.2", cdp=nxos_cdp, config_extra=nxos_cfg, extra=nxos_show)}


FULL_IOS = "10.60.255.2        1   FULL/DR         00:00:33    10.60.0.2       GigabitEthernet1/0/1\n"
FULL_NXOS = " 10.60.255.1       1 FULL/BDR         1d02h     10.60.0.1       Eth1/1\n"
OTHER_NXOS = " 10.60.255.9       1 FULL/ -          1d02h     10.60.9.1       Eth1/9\n"


def test_a_full_adjacency_on_both_ends_is_fine():
    assert found(routers(FULL_IOS, FULL_NXOS)) == {}


def test_an_adjacency_stuck_in_exstart_is_reported():
    stuck = "10.60.255.2        1   EXSTART/DR      00:00:33    10.60.0.2       GigabitEthernet1/0/1\n"
    row = found(routers(stuck, FULL_NXOS))["TOPO-041"]
    assert "LAB-R1 Gi1/0/1: EXSTART" in row["detail"] and "MTU" in row["recommendation"] and row["reference"].endswith("12151-trouble-main.html")


def test_a_missing_neighbor_is_reported_only_when_the_table_was_captured():
    row = found(routers(FULL_IOS, OTHER_NXOS))["TOPO-041"]
    assert "no OSPF neighbor on Eth1/1 at LAB-R2" in row["detail"]
    assert found(routers("", "")) == {}                                     # neither capture shows a neighbor table row: nothing to judge


def test_a_parameter_mismatch_is_left_to_the_parameter_findings():
    files = routers("10.60.255.2        1   INIT/DROTHER    00:00:33    10.60.0.2       GigabitEthernet1/0/1\n", FULL_NXOS)
    files["LAB-R1.txt"] = files["LAB-R1.txt"].replace(" ip ospf 1 area 0\n", " ip ospf 1 area 0\n ip ospf hello-interval 5\n")
    rows = found(files)
    assert "TOPO-041" not in rows                                           # TOPO-037 explains it


# ---- TOPO-042 HSRP ------------------------------------------------------------------------------------------------

def standby(host: str, rows: str) -> str:
    text = ("                     P indicates configured to preempt.\n                     |\nInterface   Grp  Pri P State   Active          Standby         Virtual IP\n" + rows)
    return iosxe_capture(host, f"FDO9700000{host[-1]}", f"10.70.255.{host[-1]}", cdp=[], extra=f"{host}#show standby brief\n{text}")


def test_a_consistent_pair_is_fine():
    files = {"LAB-S1.txt": standby("LAB-S1", "Vl10        10   110 P Active  local           10.10.0.3       10.10.0.1\n"),
             "LAB-S2.txt": standby("LAB-S2", "Vl10        10   100 P Standby 10.10.0.2       local           10.10.0.1\n")}
    assert found(files) == {}


def test_two_active_routers_and_two_virtual_addresses_are_reported():
    files = {"LAB-S1.txt": standby("LAB-S1", "Vl10        10   110 P Active  local           unknown         10.10.0.1\n"),
             "LAB-S2.txt": standby("LAB-S2", "Vl10        10   100 P Active  local           unknown         10.10.0.254\n")}
    row = found(files)["TOPO-042"]
    assert "HSRP group 10 on Vl10" in row["detail"] and "virtual address LAB-S1 10.10.0.1 / LAB-S2 10.10.0.254" in row["detail"] and "LAB-S1 and LAB-S2 are both Active" in row["detail"]
    assert row["devices"] == ["LAB-S1", "LAB-S2"] and row["reference"].endswith("fhp-hsrp.html")


def test_a_group_on_one_switch_only_is_not_compared():
    assert found({"LAB-S1.txt": standby("LAB-S1", "Vl10        10   110 P Active  local           unknown         10.10.0.1\n")}) == {}


# ---- TOPO-043 duplicate addresses ---------------------------------------------------------------------------------

def with_interface(host: str, block: str) -> str:
    return iosxe_capture(host, f"FDO9800000{host[-1]}", f"10.80.255.{host[-1]}", cdp=[], config_extra=block)


P2P = "interface GigabitEthernet1/0/1\n no switchport\n ip address 10.80.0.1 255.255.255.252\n!\n"
GATEWAY = "interface Vlan10\n ip address 10.80.10.1 255.255.255.0\n!\n"


def test_the_same_address_at_both_ends_of_a_point_to_point_link_is_medium():
    row = found({"LAB-A1.txt": with_interface("LAB-A1", P2P), "LAB-A2.txt": with_interface("LAB-A2", P2P)})["TOPO-043"]
    assert row["severity"] == "medium" and "10.80.0.1: LAB-A1 Gi1/0/1, LAB-A2 Gi1/0/1" in row["detail"] and "anycast" not in row["detail"]


def test_a_shared_gateway_address_on_two_switches_is_low_with_the_anycast_note():
    row = found({"LAB-A1.txt": with_interface("LAB-A1", GATEWAY), "LAB-A2.txt": with_interface("LAB-A2", GATEWAY)})["TOPO-043"]
    assert row["severity"] == "low" and "anycast" in row["detail"]


def test_the_same_gateway_address_on_three_switches_is_the_anycast_pattern():
    assert found({f"LAB-A{n}.txt": with_interface(f"LAB-A{n}", GATEWAY) for n in (1, 2, 3)}) == {}


def test_different_vrfs_and_shut_down_interfaces_do_not_clash():
    other_vrf = P2P.replace(" no switchport\n", " no switchport\n vrf forwarding RED\n")
    shut = P2P.replace(" no switchport\n", " no switchport\n shutdown\n")
    assert found({"LAB-A1.txt": with_interface("LAB-A1", P2P), "LAB-A2.txt": with_interface("LAB-A2", other_vrf)}) == {}
    assert found({"LAB-A1.txt": with_interface("LAB-A1", P2P), "LAB-A2.txt": with_interface("LAB-A2", shut)}) == {}


def test_the_same_address_on_one_device_is_not_a_clash():
    both = P2P + P2P.replace("1/0/1", "1/0/2")
    assert found({"LAB-A1.txt": with_interface("LAB-A1", both)}) == {}


# ---- survivors of the mutation checks -------------------------------------------------------------------------------

def test_passive_against_active_is_a_bundle_in_either_direction():
    assert found(bundle_pair("passive", "active")) == {} and found(bundle_pair("active", "passive")) == {}


def test_pagp_auto_against_desirable_is_a_bundle_in_either_direction():
    assert found(bundle_pair("auto", "desirable", "PAgP", "PAgP")) == {} and found(bundle_pair("desirable", "auto", "PAgP", "PAgP")) == {}


def test_a_protocol_the_capture_does_not_name_is_not_compared():
    assert found(bundle_pair("active", "active", ios_protocol="Unknown-Proto")) == {}


@pytest.mark.parametrize("host", ["LAB-R1", "LAB-R2"])
def test_a_show_only_end_is_never_judged_on_an_adjacency(monkeypatch, host):
    from features.topology import ifparams
    real = ifparams.read

    def read(text, result=None, vendor=""):
        data = real(text, result, vendor)
        if host in str(text)[:600]:
            for record in data["ports"].values():
                if record.get("ospf"):
                    record["ospf"]["assumed"] = True
        return data
    monkeypatch.setattr(service.ifparams, "read", read)
    stuck = "10.60.255.2        1   EXSTART/DR      00:00:33    10.60.0.2       GigabitEthernet1/0/1\n"
    with service._CACHE_LOCK:
        service._CACHE.clear()
    try:
        assert "TOPO-041" not in found(routers(stuck, FULL_NXOS))
    finally:
        with service._CACHE_LOCK:
            service._CACHE.clear()
