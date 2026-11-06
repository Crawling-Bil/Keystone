"""Neighbors that advertise the same management address (a default or copied address on several switches) stay separate devices.
Synthetic captures only (invented names, documentation addresses)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture  # noqa: E402

from features.topology.graph import find_ambiguous_ips  # noqa: E402
from features.topology.service import build_topology  # noqa: E402

SHARED = "192.0.2.253"


def _lldp(rows: list[tuple[str, str, str, str, str]]) -> str:
    """Cisco ``show lldp neighbors detail``: (local port, chassis id, remote port, system name, management address)."""
    text = "LAB#show lldp neighbors detail\n"
    for local, chassis, remote, name, ip in rows:
        text += (f"------------------------------------------------\nLocal Intf: {local}\nChassis id: {chassis}\nPort id: {remote}\nPort Description: {remote}\n"
                 f"System Name: {name}\n\nSystem Description: \nHuawei Switch S5731-S24P4X\nHuawei Versatile Routing Platform Software\n\n"
                 f"Time remaining: 93 seconds\nSystem Capabilities: B,R\nEnabled Capabilities: B,R\nManagement Addresses:\n    IP: {ip}\n    OID:\n"
                 f"        0.6.15.43.6.1.4.1.2011.5.25.41.1.2.1.1.1.\nVlan ID: 1\n\n")
    return text + "Total entries displayed: %d\n" % len(rows)


def _site(host: str, serial: str, ip: str, rows) -> str:
    return iosxe_capture(host, serial, ip, cdp=[], extra=_lldp(rows))


THREE = [("Gi1/0/22", "48b2.5df8.3b50", "GigabitEthernet0/0/24", "LAB-DIST-A", SHARED),
         ("Gi1/0/23", "48b2.5df8.4260", "GigabitEthernet0/0/24", "LAB-DIST-B", SHARED),
         ("Gi1/1/1", "48b2.5df8.4730", "XGigabitEthernet0/0/1", "LAB-DIST-C", SHARED)]


def _neighbors(graph, host: str) -> set[str]:
    return {l.b if l.a == host else l.a for l in graph.links if host in (l.a, l.b)}


def test_three_lldp_neighbors_with_one_address_are_three_devices():
    graph = build_topology([("core.txt", _site("LAB-CORE", "FOC00000001", "192.0.2.2", THREE))])["graph"]
    assert _neighbors(graph, "LAB-CORE") == {"LAB-DIST-A", "LAB-DIST-B", "LAB-DIST-C"}
    assert {n for n in graph.nodes if n != "LAB-CORE"} == {"LAB-DIST-A", "LAB-DIST-B", "LAB-DIST-C"}
    assert graph.ambiguous_ips == {SHARED: ["LAB-DIST-A", "LAB-DIST-B", "LAB-DIST-C"]}


def test_the_shared_address_never_joins_devices_of_two_captures():
    other = [("Gi1/0/22", "48b2.5df8.9999", "GigabitEthernet0/0/24", "LAB2-DIST-A", SHARED)]
    result = build_topology([("a.txt", _site("LAB-CORE", "FOC00000001", "192.0.2.2", THREE)), ("b.txt", _site("LAB2-CORE", "FOC00000002", "192.0.2.3", other))])
    graph = result["graph"]
    assert _neighbors(graph, "LAB2-CORE") == {"LAB2-DIST-A"}
    assert _neighbors(graph, "LAB-CORE") == {"LAB-DIST-A", "LAB-DIST-B", "LAB-DIST-C"}
    assert len([n for n in graph.nodes if "DIST" in n]) == 4


def test_the_shared_address_is_reported_once_with_the_devices_that_use_it():
    rows = build_topology([("core.txt", _site("LAB-CORE", "FOC00000001", "192.0.2.2", THREE))])["findings"]
    found = [r for r in rows if r["id"] == "TOPO-030"]
    assert len(found) == 1 and SHARED in found[0]["detail"] and set(found[0]["devices"]) == {"LAB-DIST-A", "LAB-DIST-B", "LAB-DIST-C"}
    assert found[0]["reference"].startswith("https://")


def test_cdp_neighbors_with_one_address_stay_apart_too():
    cdp = [("LAB-ACC-A(FOC10000001)", SHARED, "C9300L-48P-4X", "GigabitEthernet1/0/1", "GigabitEthernet1/0/48"),
           ("LAB-ACC-B(FOC10000002)", SHARED, "C9300L-48P-4X", "GigabitEthernet1/0/2", "GigabitEthernet1/0/48")]
    graph = build_topology([("core.txt", iosxe_capture("LAB-CORE", "FOC00000001", "192.0.2.2", cdp=cdp))])["graph"]
    assert _neighbors(graph, "LAB-CORE") == {"LAB-ACC-A", "LAB-ACC-B"}


def test_one_device_under_two_name_forms_is_still_one_device():
    """The domain suffix and the (SERIAL) suffix are not different names: the address keeps identifying the device."""
    a = iosxe_capture("LAB-CORE", "FOC00000001", "192.0.2.2",
                      cdp=[("LAB-ACC1.lab.example(FOC10000001)", "192.0.2.21", "C9300L-48P-4X", "GigabitEthernet1/0/1", "GigabitEthernet1/0/48")])
    b = iosxe_capture("LAB-OTHER", "FOC00000003", "192.0.2.4",
                      cdp=[("LAB-ACC1", "192.0.2.21", "C9300L-48P-4X", "GigabitEthernet1/0/1", "GigabitEthernet1/0/47")])
    graph = build_topology([("a.txt", a), ("b.txt", b)])["graph"]
    assert graph.ambiguous_ips == {} and "LAB-ACC1" in graph.nodes
    assert _neighbors(graph, "LAB-CORE") == {"LAB-ACC1"} and _neighbors(graph, "LAB-OTHER") == {"LAB-ACC1"}


def test_a_neighbor_without_a_name_does_not_make_an_address_ambiguous():
    rows = [("Gi1/0/1", "0011.2233.4455", "Port 1", "", "192.0.2.50"), ("Gi1/0/2", "0011.2233.6677", "Port 1", "LAB-AP-1", "192.0.2.50")]
    graph = build_topology([("core.txt", _site("LAB-CORE", "FOC00000001", "192.0.2.2", rows))])["graph"]
    assert find_ambiguous_ips(graph) == {}
