"""Topology Builder 2.0: the devices of a row that is moved for a child switch keep their places (a device with no wish used to be packed against the one before it, which
carried a child away from its parent), and a parent may pull up to two switches under it.  Synthetic captures only (invented names)."""

from __future__ import annotations

import random

import pytest

from features.topology import layout
from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.layout import X_STEP
from features.topology.scene import build_pages


def _estate(seed):
    r=random.Random(seed)
    nodes={"CORE":Device(key="CORE",hostname="CORE",captured=True,role_hint="core")}
    conns=[]; leaves=[]
    def link(a,pa,b,pb): conns.append(Connection(a,b,[Link(a,pa,b,pb,"confirmed",{"LLDP"},"")]))
    n=r.randint(5,14)
    for i in range(n):
        a=f"A-{i}"; nodes[a]=Device(key=a,hostname=a,captured=True,role_hint="access"); link("CORE",f"Gi1/0/{i+1}",a,"Gi1/0/48")
        kind=r.choice(["frame","leaf","leaf","plain","chain","leafchain","twoleaf"])
        if kind=="frame":
            for j in range(r.choice([6,12,20])):
                k=f"{a}-AP{j:02d}"; nodes[k]=Device(key=k,hostname=k,captured=False,role_hint="ap"); link(a,f"Gi1/0/{j+1}",k,"Gi0")
        elif kind=="leaf":
            l=f"L-{i}"; nodes[l]=Device(key=l,hostname=l,captured=False,role_hint="access"); link(a,"Gi1/0/1",l,"Gi1/0/1"); leaves.append((l,a))
        elif kind=="leafchain":
            b=f"B-{i}"; nodes[b]=Device(key=b,hostname=b,captured=True,role_hint="access"); link(a,"Gi1/0/1",b,"Gi1/0/48")
            l=f"L-{i}"; nodes[l]=Device(key=l,hostname=l,captured=False,role_hint="access"); link(b,"Gi1/0/2",l,"Gi1/0/1"); leaves.append((l,b))
            for j in range(r.choice([8,16])):
                k=f"{b}-AP{j:02d}"; nodes[k]=Device(key=k,hostname=k,captured=False,role_hint="ap"); link(b,f"Gi1/0/{j+3}",k,"Gi0")
        elif kind=="twoleaf":
            for q in range(2):
                l=f"L-{i}-{q}"; nodes[l]=Device(key=l,hostname=l,captured=False,role_hint="access"); link(a,f"Gi1/0/{q+1}",l,"Gi1/0/1"); leaves.append((l,a))
        elif kind=="chain":
            b=f"B-{i}"; nodes[b]=Device(key=b,hostname=b,captured=True,role_hint="access"); link(a,"Gi1/0/1",b,"Gi1/0/48")
            for j in range(r.choice([8,16])):
                k=f"{b}-AP{j:02d}"; nodes[k]=Device(key=k,hostname=k,captured=False,role_hint="ap"); link(b,f"Gi1/0/{j+1}",k,"Gi0")
    return Graph(nodes=nodes,links=[x for c in conns for x in c.links],connections=conns,hidden_kinds=set(),group_endpoints=True),leaves


def _worst(seed):
    graph, leaves = _estate(seed)
    page = build_pages(graph)[0]
    return max(abs(page.nodes[l].x - page.nodes[a].x) / X_STEP for l, a in leaves)


@pytest.mark.parametrize("seed", [628, 351, 161])
def test_a_leaf_is_not_carried_away_by_the_device_before_it_in_its_row(seed):
    assert _worst(seed) <= layout.FOLLOW_FAR + 0.01          # 1.9 left these 6.9 to 7.4 steps from their parent


def test_the_leaves_of_a_thousand_estates_stay_close_to_their_parent():
    worst = [_worst(seed) for seed in range(1000) if _estate(seed)[1]]
    assert max(worst) <= 8.5                                   # 1.9: 9.3 steps
    assert sum(1 for w in worst if w > layout.FOLLOW_FAR + 0.01) <= 10    # 1.9: 15 of 1,000; the rest stand between channels of cores above and cannot come closer


def test_a_parent_with_two_switches_under_it_may_pull_them():
    assert layout.FOLLOW_KIDS >= 2 and layout.FOLLOW_FAR == 6.0


def test_the_version_is_at_least_2_0():
    from core.modules import TOOLS
    version = next(t for t in TOOLS if t.key == "topology").version
    assert tuple(int(p) for p in version.split(".")) >= (2, 0)
    from features.topology.service import _tool_version
    assert _tool_version() == version
