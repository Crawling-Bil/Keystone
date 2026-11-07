"""Topology Builder: Panorama + a managed firewall + the switch it plugs into.  Invented names only."""

from __future__ import annotations

import json
from pathlib import Path

from features.topology import service as topo

FIX = Path(__file__).parent / "fixtures" / "panorama"
PANO = (FIX / "synthetic_panorama.xml").read_text(encoding="utf-8")
FW = (FIX / "synthetic_managed_fw.xml").read_text(encoding="utf-8")
SWITCH = """LAB-SW-AGG1# show lldp neighbors detail
Chassis id: 0011.2233.4455
Port id: ethernet1/2
Local Port id: Eth1/10
Port Description: uplink
System Name: FW-SYN-DC1
System Description: Palo Alto Networks PA-3260 firewall
System Capabilities: B, R
Management Address: 192.0.2.77
Vlan ID: 1

LAB-SW-AGG1# show version
Cisco Nexus Operating System (NX-OS) Software
  NXOS: version 10.5(6)
  cisco Nexus9000 C9336C-FX2 Chassis
  Device name: LAB-SW-AGG1
LAB-SW-AGG1# show interface description
Eth1/10        eth    10G    FW-SYN-DC1 - ethernet1/2
"""


def build(*extra):
    return topo.build_topology([("Panorama-Syn", PANO), ("FW-SYN-DC1.xml", FW), *extra])


def link_between(built, a, b):
    return [l for l in built["graph"].links if {l.a, l.b} == {a, b}]


def test_the_switch_port_reaches_the_managed_firewall_and_the_panorama_stack_is_kept():
    built = build(("LAB-SW-AGG1.txt", SWITCH))
    nodes = set(built["graph"].nodes)
    assert {"LAB-SW-AGG1", "FW-SYN-DC1", "STK-B"} <= nodes
    assert "STK-A" not in nodes                                   # the stack is drawn as the firewall unit that was uploaded
    assert len(link_between(built, "FW-SYN-DC1", "LAB-SW-AGG1")) == 1
    ids = {f["id"] for f in built["findings"]}
    assert "TOPO-044" in ids                                       # the Panorama link is reported


def test_a_switch_does_not_change_the_firewall_page_or_leak_secrets():
    plain = build()
    with_switch = build(("LAB-SW-AGG1.txt", SWITCH))
    assert {n for n in plain["graph"].nodes} | {"LAB-SW-AGG1"} == set(with_switch["graph"].nodes)
    for built in (plain, with_switch):
        assert "CANARY" not in json.dumps(built, default=str)


def test_upload_order_does_not_matter():
    first = build(("LAB-SW-AGG1.txt", SWITCH))
    reverse = topo.build_topology([("LAB-SW-AGG1.txt", SWITCH), ("FW-SYN-DC1.xml", FW), ("Panorama-Syn", PANO)])
    assert set(first["graph"].nodes) == set(reverse["graph"].nodes)
    assert sorted((l.a, l.b) for l in first["graph"].links) == sorted((l.a, l.b) for l in reverse["graph"].links)
