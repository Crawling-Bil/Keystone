"""L3 over L2: which cables carry which L3 link. Synthetic IOS XE captures (invented names and documentation addresses)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture  # noqa: E402

from features.topology.service import build_topology  # noqa: E402


def _ospf(host, rid, addr, intf):
    return (f"{host}#show ip ospf neighbor\n\nNeighbor ID     Pri   State           Dead Time   Address         Interface\n"
            f"{rid}          1   FULL/DR         00:00:33    {addr}        {intf}\n")


def _route(host, via):
    return (f"{host}#show ip route\nCodes: L - local, C - connected, S - static, O - OSPF\nGateway of last resort is {via} to network 0.0.0.0\n\n"
            f"S*    0.0.0.0/0 [1/0] via {via}\n")


def _files():
    cdp1 = [("CORE2", "10.0.0.2", "C9300L", "GigabitEthernet1/0/1", "GigabitEthernet1/0/1"), ("DIST1", "10.0.0.3", "C9300L", "GigabitEthernet1/0/24", "GigabitEthernet1/0/24")]
    cfg1 = ("interface Vlan1\n description Management\n ip address 10.0.0.1 255.255.255.0\n!\ninterface GigabitEthernet1/0/1\n no switchport\n description to-CORE2\n ip address 10.9.0.1 255.255.255.252\n!\n"
            "interface GigabitEthernet1/0/2\n no switchport\n description MPLS TELKOM\n ip address 192.0.2.2 255.255.255.248\n!\n"
            "interface GigabitEthernet1/0/24\n no switchport\n ip address 10.9.5.1 255.255.255.252\n!\n")
    cfg2 = "interface GigabitEthernet1/0/1\n no switchport\n description to-CORE1\n ip address 10.9.0.2 255.255.255.252\n!\n"
    cfg3 = "interface GigabitEthernet1/0/24\n no switchport\n ip address 10.9.5.2 255.255.255.252\n!\n"
    return {
        "core1.txt": iosxe_capture("CORE1", "FOC1111A1AA", "10.0.0.1", cdp1, config_extra=cfg1, extra=_ospf("CORE1", "10.9.0.2", "10.9.0.2", "GigabitEthernet1/0/1") + _route("CORE1", "192.0.2.1")),
        "core2.txt": iosxe_capture("CORE2", "FOC2222B2BB", "10.0.0.2", [("CORE1", "10.0.0.1", "C9300L", "GigabitEthernet1/0/1", "GigabitEthernet1/0/1")], config_extra=cfg2),
        "dist1.txt": iosxe_capture("DIST1", "FOC3333C3CC", "10.0.0.3", [("CORE1", "10.0.0.1", "C9300L", "GigabitEthernet1/0/24", "GigabitEthernet1/0/24")], config_extra=cfg3),
    }


def _links(result):
    return {(r["device_a"], r["interface_a"], r["device_b"]): r for r in result["l3_links"]}


def test_management_vlan_is_not_an_l3_link():
    result = build_topology(list(_files().items()), view="l3route")
    assert all("Vlan1" != r["interface_a"] for r in result["l3_links"])


def test_routed_port_link_is_carried_on_its_own_cable_and_the_cable_is_highlighted():
    result = build_topology(list(_files().items()), view="l3over2")
    row = _links(result)[("CORE1", "Gi1/0/1", "CORE2")]
    assert row["state"] == "working" and "Carried on CORE1 Gi1/0/1 - Gi1/0/1 CORE2" in row["meaning"] and row["carried_on"].startswith("carried on")
    page = result["l3_pages"][0]
    carrying = [c for c in page.connections if c.l3.get("role") == "under" and c.l3["carries"]]
    assert len(carrying) == 2 and all(c.l3["width"] == 5 for c in carrying)
    assert all(c.l3["colour"] == "#B8B8B8" and c.l3["width"] == 1.5 for c in page.connections if c.l3.get("role") == "under" and not c.l3["carries"])


def test_provider_cloud_sits_above_the_cables_and_has_no_cable_underneath():
    result = build_topology(list(_files().items()), view="l3over2")
    row = _links(result)[("CORE1", "Gi1/0/2", "MPLS · Telkom")]
    assert "no CDP / LLDP neighbor" in row["meaning"]
    page = result["l3_pages"][0]
    assert page.nodes["CLOUD:mpls:telkom"].y < min(p.y for k, p in page.nodes.items() if k in ("CORE1", "CORE2", "DIST1"))


def test_l3_over_l2_exports_and_svg_are_clickable_and_listed():
    result = build_topology(list(_files().items()), view="l3over2")
    svg = next(s["svg"] for s in result["svgs"] if s["view"] == "l3over2")
    assert 'data-l3="L3-' in svg and "carries L3-" in svg
    assert 'view="l3over2"' not in result["drawio"] and "L3 over L2" in result["drawio"]
