"""Hyper-converged nodes, hypervisor hosts and NIC vendor strings are servers: the server icon in the web view and in the diagram file (features/topology/roles.py).

Production data centres hang HCI (Nutanix, VxRail, vSAN ready) nodes and adapters that advertise their vendor string ("BROADCOM ADV", "Intel Corporation") on the access
and leaf switches.  Drawn as a PC they read as office workstations; they are servers.  Invented names.  Standard: IEEE 802.1AB (LLDP system name and capabilities are text the
sender chooses), https://1.ieee802.org/maintenance/p802-1ab-2016-revision-station-and-media-access-control-connectivity-discovery/
"""

from __future__ import annotations

import pytest

from features.topology import roles
from features.topology.extract import Device, HalfEdge
from features.topology.graph import build
from features.topology.service import build_topology
from tests.topology_samples import iosxe_capture


def _classified(name, caps="B, W, R", captured=False, model=""):
    switch = Device(key="SW1", hostname="SW1", captured=True, role_hint="access",
                    halves=[HalfEdge(local_port="Gi1/0/1", remote_name=name, remote_port="eth0", protocols={"LLDP"}, remote_caps=caps)])
    graph = build([switch])
    node = next(n for k, n in graph.nodes.items() if k != "SW1")
    node.captured, node.model = captured, model
    roles.classify(graph)
    return node.role_hint


@pytest.mark.parametrize("name", ["HCI-NODE-01", "NTNX-A1", "Nutanix-CVM-3", "VXRAIL-02", "PVE1", "BROADCOM ADV/HCI", "Broadcom Adv", "Intel Corporation", "ESX-07", "BLADE12"])
def test_hci_hypervisor_and_nic_vendor_names_are_servers(name):
    assert _classified(name) == "server"


@pytest.mark.parametrize("name", ["HQ-SW1", "CORE-1", "BRANCH-FW1", "LAB-PC-LT1"])
def test_network_device_names_are_not_servers(name):
    assert _classified(name) != "server"


def test_a_model_of_a_server_family_is_a_server():
    assert _classified("UNKNOWN1", model="ProLiant DL380") == "server"
    assert _classified("UNKNOWN2", model="NX-3060-G6") == "server"


def test_the_web_view_draws_the_server_pictogram_and_the_diagram_file_the_server_icon():
    files = {"A.txt": iosxe_capture("LAB-A1", "FOC0000A001", "10.1.0.1", cdp=[("HCI-NODE-01", "10.1.0.50", "NX-3060-G6", "Gi1/0/1", "eth0")])}
    result = build_topology(list(files.items()))
    svg = next(s["svg"] for s in result["svgs"] if s["view"] == "physical")
    assert 'class="server-glyph"' in svg
    assert "prIcon=server" in result["drawio"]
