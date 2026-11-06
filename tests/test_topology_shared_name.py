"""Topology Builder: TOPO-045, one neighbour name on many separate attachments (a NIC that sends a vendor string as its LLDP system name).  Invented names only."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from features.topology import findings  # noqa: E402
from features.topology.extract import Device  # noqa: E402
from features.topology.findings import build_findings  # noqa: E402
from features.topology.graph import Connection, Graph, Link  # noqa: E402


def _link(a: str, b: str, n: int) -> Link:
    return Link(a, f"Eth1/{n}", b, f"Gi0/{n}", "confirmed", {"LLDP"}, "")


def _graph(neighbour_role: str = "access", attachments: int = 7, bundled: bool = True, members: int = 2) -> Graph:
    """Two captured switches and one neighbour nobody captured, attached ``attachments`` times (each a port-channel of ``members`` links, or ``members`` plain cables when not bundled)."""
    nodes = {n: Device(key=n, hostname=n, captured=True, role_hint="access") for n in ("RACK-SW1", "RACK-SW2")}
    nodes["NIC VENDOR"] = Device(key="NIC VENDOR", hostname="NIC VENDOR", captured=False, role_hint=neighbour_role, model="fw_version:1.2.3")
    conns = []
    for i in range(attachments):
        switch = "RACK-SW1" if i % 2 == 0 else "RACK-SW2"
        links = [_link(switch, "NIC VENDOR", i * 10 + m) for m in range(members)]
        conns.append(Connection(switch, "NIC VENDOR", links, a_po=f"Po{i + 1}" if bundled else "", b_po="Po1" if bundled else "", kind="bundle" if bundled else "link"))
    return Graph(nodes=nodes, links=[link for c in conns for link in c.links], connections=conns, hidden_kinds=set())


def _ids(graph: Graph) -> list[str]:
    return [f["id"] for f in build_findings(graph) if f["id"] == "TOPO-045"]


def test_many_port_channels_to_one_uncaptured_name_are_reported_as_several_hosts():
    rows = [f for f in build_findings(_graph()) if f["id"] == "TOPO-045"]
    assert len(rows) == 1 and rows[0]["devices"] == ["NIC VENDOR"]
    assert "7 separate attachments on 2 switch(es)" in rows[0]["title"] and rows[0]["reference"].startswith("https://")


def test_one_port_channel_with_many_members_is_one_attachment():
    assert _ids(_graph(attachments=1, members=16)) == []                                  # sixteen members, one bundle: one device


def test_plain_cables_count_one_by_one_and_a_router_is_not_a_nic():
    assert _ids(_graph(attachments=3, bundled=False, members=3)) == ["TOPO-045"]          # nine separate cables
    assert _ids(_graph(neighbour_role="router")) == []                                    # a router with many links is a router, and a captured device is never reported


def test_the_limit_is_the_mutation_check(monkeypatch):
    assert _ids(_graph(attachments=5)) == []
    monkeypatch.setattr(findings, "SHARED_NAME_MIN_UNITS", 5)                             # lower limit: five attachments are enough
    assert _ids(_graph(attachments=5)) == ["TOPO-045"]
