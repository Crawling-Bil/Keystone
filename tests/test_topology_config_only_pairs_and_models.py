"""Shapes found on a real DC and DRC set, with invented values.

* A Nexus pair captured with the running configuration only (``vpc domain 140``, ``vpc peer-link``, no ``show vpc``) is still a vPC pair: the domain, the peer-link and the
  vPC numbers of the member ports are in the configuration.  It carries no health, so it never raises "vPC not healthy".
* A Huawei CloudEngine reports its model in ``display version`` ("HUAWEI CE6881-48S6CQ uptime is ...") and in ``device board 1 board-type``; a later "BOARD TYPE = 0x..." line is not the model.
"""

from __future__ import annotations

import pytest

from features.switch_analyzer.fingerprint import detect
from features.topology.service import build_topology
from tests.topology_samples import nxos_capture

PEER_LINK = "interface port-channel240\n  switchport mode trunk\n  vpc peer-link\n"


def _config(host, own, peer):
    return (f"feature vpc\nvpc domain 140\n  peer-keepalive destination {peer} source {own}\n" + PEER_LINK +
            "interface port-channel101\n  vpc 101\n  switchport mode trunk\n")


def _pair(config_only=True):
    a = nxos_capture("LAB-AGG1-DC", "FDO00000001", "10.99.0.11", cdp=[("LAB-AGG2-DC", "10.99.0.12", "N9K-C93180YC-FX3", "Ethernet1/47", "Ethernet1/47"),
                                                                    ("LAB-AGG2-DC", "10.99.0.12", "N9K-C93180YC-FX3", "Ethernet1/48", "Ethernet1/48")],
                     port_channels=[("240", ["Eth1/47", "Eth1/48"])], config_extra=_config("a", "10.90.1.251", "10.90.1.252"))
    b = nxos_capture("LAB-AGG2-DC", "FDO00000002", "10.99.0.12", cdp=[("LAB-AGG1-DC", "10.99.0.11", "N9K-C93180YC-FX3", "Ethernet1/47", "Ethernet1/47"),
                                                                    ("LAB-AGG1-DC", "10.99.0.11", "N9K-C93180YC-FX3", "Ethernet1/48", "Ethernet1/48")],
                     port_channels=[("240", ["Eth1/47", "Eth1/48"])], config_extra=_config("b", "10.90.1.252", "10.90.1.251"))
    return build_topology([("LAB-AGG1-DC.txt", a), ("LAB-AGG2-DC.txt", b)], group="none")


def test_a_configuration_only_pair_is_a_vpc_pair_with_its_domain_and_peer_link():
    graph = _pair()["graph"]
    assert [(graph.nodes[a].hostname, graph.nodes[b].hostname, d) for a, b, d in graph.vpc_pairs] == [("LAB-AGG1-DC", "LAB-AGG2-DC", "140")]
    node = next(n for n in graph.nodes.values() if n.hostname == "LAB-AGG1-DC")
    assert node.vpc_domain == "140" and node.vpc_peer_link == "Po240" and node.vpc_ids == {"Po101": "101"} and node.vpc_keepalive == "10.90.1.252"


def test_a_configuration_only_pair_has_no_health_to_judge():
    result = _pair()
    node = next(n for n in result["graph"].nodes.values() if n.hostname == "LAB-AGG1-DC")
    assert node.vpc_health == {} and node.vpc_member_status == {}
    assert "TOPO-019" not in {f["id"] for f in result["findings"]} and "TOPO-021" not in {f["id"] for f in result["findings"]}


@pytest.mark.parametrize("text,model", [
    ("HUAWEI CE6881-48S6CQ uptime is 10 days, 1 hour, 5 minutes\n", "CE6881-48S6CQ"),
    ("Quidway S5700-24TP-SI Routing Switch uptime is 3 weeks\n", "S5700-24TP-SI"),
    ("#\ndevice board 1 board-type CE6881-48S6CQ\n#\n", "CE6881-48S6CQ"),
])
def test_huawei_model_comes_from_the_version_banner_or_the_board_line(text, model):
    body = f"Huawei Versatile Routing Platform Software\nVRP (R) software, Version 8.220 (CE6881 V200R022C00SPC500)\nCopyright (C) 2012-2022 Huawei Technologies Co., Ltd.\n{text}"
    assert detect(body + "BOARD TYPE = 0x00232718\n").model_hint == model


def test_the_generic_board_type_line_still_names_a_model_when_nothing_better_is_there():
    assert detect("Huawei Versatile Routing Platform Software\nVRP (R) software, Version 5.170\nBOARD TYPE = ABC-1234\n").model_hint == "ABC-1234"
