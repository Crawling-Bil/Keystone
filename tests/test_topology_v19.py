"""Topology Builder 1.9: a switch that only its neighbours have seen (no capture) stands next to the switch it hangs under even when the row it is in holds frames, and a
hypervisor host that advertises Bridge, WLAN, Router and Station is a server, not an access point.  Synthetic captures only (invented names)."""

from __future__ import annotations

import random

import pytest

from features import topology  # noqa: F401
from features.topology import layout, roles
from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.layout import X_STEP
from features.topology.scene import build_pages


def _estate(seed):
    r=random.Random(seed)
    nodes={"CORE":Device(key="CORE",hostname="CORE",captured=True,role_hint="core")}
    conns=[]; leaves=[]
    def link(a,pa,b,pb): conns.append(Connection(a,b,[Link(a,pa,b,pb,"confirmed",{"LLDP"},"")]))
    n=r.randint(5,10)
    for i in range(n):
        a=f"A-{i}"; nodes[a]=Device(key=a,hostname=a,captured=True,role_hint="access"); link("CORE",f"Gi1/0/{i+1}",a,"Gi1/0/48")
        kind=r.choice(["frame","leaf","leaf","plain","chain"])
        if kind=="frame":
            for j in range(r.choice([6,12,20])):
                k=f"{a}-AP{j:02d}"; nodes[k]=Device(key=k,hostname=k,captured=False,role_hint="ap"); link(a,f"Gi1/0/{j+1}",k,"Gi0")
        elif kind=="leaf":
            l=f"L-{i}"; nodes[l]=Device(key=l,hostname=l,captured=False,role_hint="access"); link(a,"Gi1/0/1",l,"Gi1/0/1"); leaves.append((l,a))
        elif kind=="chain":
            b=f"B-{i}"; nodes[b]=Device(key=b,hostname=b,captured=True,role_hint="access"); link(a,"Gi1/0/1",b,"Gi1/0/48")
            for j in range(r.choice([8,16])):
                k=f"{b}-AP{j:02d}"; nodes[k]=Device(key=k,hostname=k,captured=False,role_hint="ap"); link(b,f"Gi1/0/{j+1}",k,"Gi0")
    return Graph(nodes=nodes,links=[x for c in conns for x in c.links],connections=conns,hidden_kinds=set(),group_endpoints=True),leaves


@pytest.mark.parametrize("seed", [242, 69, 56, 299, 47, 1218, 417, 1084, 1091] + list(range(0, 60, 7)))
def test_a_leaf_switch_stands_next_to_its_parent_in_a_row_that_holds_frames(seed):
    graph, leaves = _estate(seed)
    if not leaves:
        pytest.skip("no leaf switch in this estate")
    page = build_pages(graph)[0]
    for leaf, parent in leaves:
        assert abs(page.nodes[leaf].x - page.nodes[parent].x) / X_STEP <= layout.FOLLOW_FAR, (leaf, parent)          # 1.8 left some of them 7 steps and more away


def test_every_estate_keeps_its_leaves_within_the_follow_distance():
    worst = 0.0
    for seed in range(120):
        graph, leaves = _estate(seed)
        if leaves:
            page = build_pages(graph)[0]
            worst = max([worst] + [abs(page.nodes[l].x - page.nodes[a].x) / X_STEP for l, a in leaves])
    assert worst <= layout.FOLLOW_FAR


def test_a_core_with_a_row_of_switches_under_it_does_not_pull_them_together():
    graph, _ = _estate(3)
    page = build_pages(graph)[0]
    xs = sorted(p.x for k, p in page.nodes.items() if k.startswith("A-"))
    assert len(xs) >= 5 and min(b - a for a, b in zip(xs, xs[1:])) >= X_STEP * 0.9


# ---- the roles ---------------------------------------------------------------------------------------------------------------------------

def test_bridge_wlan_router_station_is_a_server_not_an_access_point():
    assert roles.role_from_caps("B, W, R, S") == "server"
    assert roles.role_from_caps("B, W") == "ap"
    assert roles.role_from_caps("W") == "ap"
    assert roles.role_from_caps("Trans-Bridge") == "ap"
    assert roles.role_from_caps("B, R") == "switch"


def test_a_hypervisor_description_is_a_server_and_an_access_point_description_still_an_ap():
    assert roles.role_from_description("NutanixAHV") == "server"
    assert roles.role_from_description("VMware ESXi 7.0.3") == "server"
    assert roles.role_from_description("Cisco AP Software, ap3g3-k9w8") == "ap"


def test_a_host_that_advertises_every_capability_is_drawn_as_a_server():
    nodes = {"SW": Device(key="SW", hostname="SW", captured=True, role_hint="access"),
             "HV01": Device(key="HV01", hostname="HV01", captured=False, role_hint="host", caps="B, W, R, S", descr="NutanixAHV")}
    link = Link("SW", "Eth1/1", "HV01", "eth0", "confirmed", {"LLDP"}, "")
    graph = Graph(nodes=nodes, links=[link], connections=[Connection("SW", "HV01", [link])], hidden_kinds=set(), group_endpoints=True)
    roles.classify(graph)
    assert graph.nodes["HV01"].role_hint == "server"


def test_the_version_is_at_least_1_9():
    from core.modules import TOOLS
    version = next(t for t in TOOLS if t.key == "topology").version
    assert tuple(int(p) for p in version.split(".")) >= (1, 9)
    from features.topology.service import _tool_version
    assert _tool_version() == version


# ---- the member ports of a port-channel --------------------------------------------------------------------------------------------------

def _bundle(a_ports, b_ports, a_po="Po12", b_po=""):
    from features.topology.graph import Connection, Link
    links = [Link("SW-A", ap, "SW-B", bp, "confirmed", {"LLDP"}, "") for ap, bp in zip(a_ports, b_ports)]
    return Connection("SW-A", "SW-B", links, kind="bundle", a_po=a_po, b_po=b_po)


def test_member_ports_are_short_and_in_port_order():
    from features.topology.labels import member_ports
    assert member_ports(["Gi1/0/24", "Gi1/0/23"]) == "Gi1/0/23-24"
    assert member_ports(["Gi1/0/1", "Gi1/0/2", "Gi1/0/4"]) == "Gi1/0/1-2, Gi1/0/4"
    assert member_ports(["GE1/0/22", "GE2/0/22"]) == "GE1/0/22, GE2/0/22"
    assert member_ports(["Te1/0/1"]) == "Te1/0/1"
    assert member_ports([f"Gi1/0/{n}" for n in range(1, 40, 2)]) == "20 members"


def test_a_port_channel_end_names_the_bundle_and_its_members_and_a_plain_end_names_its_ports():
    from features.topology import labels
    conn = _bundle(["Gi0/0/23", "Gi0/0/24"], ["Gi1/0/1", "Gi1/0/2"])
    assert labels.end_texts(conn) == ("Po12", "Gi1/0/1, Gi1/0/2")                         # before the option fills the members: 1.8 text
    graph = Graph(nodes={}, links=[l for l in conn.links], connections=[conn], hidden_kinds=set(), group_endpoints=True)
    assert labels.annotate_members(graph) == 1
    assert labels.end_texts(conn) == ("Po12: Gi0/0/23-24", "Gi1/0/1-2")                  # the plain end is short in the same way
    conn.b_po = "Eth-Trunk3"
    labels.annotate_members(graph)
    assert labels.end_texts(conn) == ("Po12: Gi0/0/23-24", "Eth-Trunk3: Gi1/0/1-2")


def test_the_option_is_on_by_default_and_the_pictures_say_so():
    from features.topology import service
    import inspect
    assert inspect.signature(service.build_topology).parameters["bundle_members"].default is True


def _two_switches_with_a_bundle():
    nodes = {"SW-A": Device(key="SW-A", hostname="SW-A", captured=True, role_hint="core"),
             "SW-B": Device(key="SW-B", hostname="SW-B", captured=True, role_hint="access")}
    nodes["SW-A"].bundles = {"Po12": ["Gi1/0/23", "Gi1/0/24"]}
    nodes["SW-B"].bundles = {"Po12": ["Gi0/0/1", "Gi0/0/2"]}
    return nodes


def test_the_svg_carries_the_member_ports_when_asked_and_not_when_not():
    from features.topology import service
    from features.topology.svg import to_svg
    for flag, expected in ((True, True), (False, False)):
        conn = _bundle(["Gi1/0/23", "Gi1/0/24"], ["Gi0/0/1", "Gi0/0/2"], "Po12", "Po12")
        nodes = _two_switches_with_a_bundle()
        graph = Graph(nodes=nodes, links=list(conn.links), connections=[conn], hidden_kinds=set(), group_endpoints=True)
        if flag:
            from features.topology.labels import annotate_members
            annotate_members(graph)
        page = build_pages(graph)[0]
        from features.topology import labelplace
        labelplace.place_labels(page, graph)
        svg = to_svg(page, graph)
        assert ("Po12: Gi1/0/23-24" in svg) is expected
