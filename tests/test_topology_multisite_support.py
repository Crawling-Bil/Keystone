"""Fixes found while building the multi-site demo: a firewall's own alias confirms a cable, Huawei LLDP capabilities tell phones and access points apart,
a FortiGate redundant interface is no bundle mismatch, a PAN-OS ``set`` export gives its management address, and Trigatra is a known provider."""

from __future__ import annotations

from features.topology import demo, service
from features.topology.l3cloud import PROVIDERS

SITE = demo.DEMO_DIR / "multisite"


def _read(*names: str, edit=None):
    files = []
    for name in names:
        text = (SITE / f"{name}.txt").read_text(encoding="utf-8")
        if edit and name in edit:
            text = edit[name](text)
        files.append((f"{name}.txt", text))
    return files


def _link(built, host_a: str, host_b: str):
    return [l for l in built["graph"].links if {l.a, l.b} == {host_a, host_b}]


def test_a_firewall_alias_naming_the_cable_confirms_it():
    built = service.build_topology(_read("HQ-CORE1", "HQ-CORE2", "HQ-FGLAN1"))
    links = _link(built, "HQ-CORE1", "HQ-FGLAN1")
    assert links and all(l.state == "confirmed" and "DESC" in l.protocols for l in links)
    assert not [f for f in built["findings"] if f["id"] == "TOPO-001"]


def test_without_the_alias_the_cable_stays_single_sided():
    built = service.build_topology(_read("HQ-CORE1", "HQ-CORE2", "HQ-FGLAN1", edit={"HQ-FGLAN1": lambda t: t.replace("to HQ-CORE1 - Eth1/11", "uplink").replace("to HQ-CORE2 - Eth1/11", "uplink")}))
    links = _link(built, "HQ-CORE1", "HQ-FGLAN1")
    assert links and all(l.state == "single" for l in links)


def test_an_alias_naming_another_port_does_not_confirm():
    built = service.build_topology(_read("HQ-CORE1", "HQ-CORE2", "HQ-FGLAN1", edit={"HQ-FGLAN1": lambda t: t.replace("to HQ-CORE1 - Eth1/11", "to HQ-CORE1 - Eth1/40")}))
    assert all(l.state == "single" for l in _link(built, "HQ-CORE1", "HQ-FGLAN1") if l.b_port == "port1" or l.a_port == "port1")


def test_huawei_lldp_capabilities_give_phones_and_access_points_their_role():
    built = service.build_topology(_read("YOG-SW1", "YOG-SW2", "YOG-SW3", "YOG-RTR1"), include_hosts=True)
    roles = {n.hostname: n.role_hint for n in built["graph"].nodes.values()}
    assert roles["YOG-PHONE1"] == "phone" and roles["YOG-AP1"] == "ap"


def test_a_fortigate_redundant_interface_is_not_a_bundle_mismatch():
    built = service.build_topology(_read("HQ-ACC1", "HQ-ACC2", "HQ-FGLAN1", "HQ-FGLAN2"))
    assert not [f for f in built["findings"] if f["id"] == "TOPO-010"]


def test_a_pan_os_set_export_gives_its_management_address():
    devices, skipped = service.read_devices(_read("HQ-PADC1"))
    assert not skipped and devices[0].mgmt_ip == "10.10.0.31"


def test_trigatra_is_a_known_provider():
    assert "trigatra" in PROVIDERS
    built = service.build_topology(_read("YOG-SW1", "YOG-SW2", "YOG-SW3", "YOG-RTR1"), view="l3route")
    assert any("trigatra" in str(getattr(n, "key", n)) for page in built["l3_pages"] for n in page.nodes)


# ---- the L3 route page leaves out switches that only have a management address ----------------------------------------------------------------

def _node(role: str, l3: list, **facts):
    from types import SimpleNamespace
    return SimpleNamespace(role_hint=role, l3=l3, l3facts=facts)


def test_a_switch_with_only_a_management_address_and_a_default_route_is_left_off_the_l3_page():
    from features.topology.l3page import _management_only
    mgmt = [{"name": "vlan99", "ip": "10.1.99.12"}]
    default = [{"protocol": "static", "next_hop": "10.1.99.1"}]
    assert _management_only(_node("access", mgmt, routes=default, neighbors=[], tunnels=[], fhrp=None, overlay=[]))
    assert _management_only(_node("aggregation", mgmt))
    assert not _management_only(_node("access", mgmt, routes=default + default))                         # two static routes: it routes something
    assert not _management_only(_node("access", mgmt, routes=[{"protocol": "ospf"}]))
    assert not _management_only(_node("access", mgmt, neighbors=[{"peer": "10.1.1.1"}]))
    assert not _management_only(_node("access", mgmt, fhrp=[{"group": 1}]))
    assert not _management_only(_node("access", mgmt + mgmt))                                            # two routed addresses
    assert not _management_only(_node("router", mgmt)) and not _management_only(_node("firewall", mgmt)) and not _management_only(_node("core", mgmt))


def test_every_device_on_the_demo_l3_page_has_a_line():
    built = service.build_topology([(p.name, p.read_text(encoding="utf-8")) for p in sorted(SITE.glob("*.txt"))], group="auto", view="l3route")
    page = built["l3_pages"][0]
    drawn = {c.a for c in page.connections} | {c.b for c in page.connections}
    assert set(page.nodes) == drawn and len(page.nodes) == 33
    assert not any(k.endswith(("-SW2", "-SW3", "-ACC1", "-ACC2", "-TOR1", "-TOR2", "-SF1", "-SF2")) for k in page.nodes)
    assert all(k in built["graph"].nodes for k in ("BAL-SW2", "HQ-TOR1"))                              # they are still in the tables and the physical pages
