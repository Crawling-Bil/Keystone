"""Huawei (VRP / YunShan) captures: what ``display lldp neighbor`` and ``display eth-trunk`` carry must reach the picture the way Cisco CDP / LLDP does.
The neighbour's management address (plain ``Management address`` on YunShan, ``Management address value`` on older VRP), its multi-line system description
(an access point says what it is only there), the OperMau duplex, the Eth-Trunk working mode (LACP or not) and the member state.  Synthetic captures
only: invented names, documentation addresses (RFC 5737) and made-up MACs."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture  # noqa: E402

from features.switch_analyzer import bundles, live_state, runtime_parser  # noqa: E402
from features.switch_analyzer.runtime_parser import _huawei_lldp_platform  # noqa: E402
from features.topology.names import vendor_from_description  # noqa: E402
from features.topology.roles import role_from_description  # noqa: E402
from features.topology.service import build_topology  # noqa: E402

CORE_DESCR = ("Cisco IOS Software [Everest], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.6.7, RELEASE SOFTWARE (fc2)\n"
              "Technical Support: http://www.cisco.com/techsupport\nCopyright (c) 1986-2019 by Cisco Systems, Inc.\nCompiled Mon 23-Sep-19 12:59 by")
AP_DESCR = ("Cisco AP Software, ap1g7-k9w8 Version: 17.15.6.201\nTechnical Support: http://www.cisco.com/techsupport\n"
            "Copyright (c) 1986-2026 by Cisco Systems, Inc.\nCompiled Sat Aug  8 20:16:59 GMT 2026 by aut")


def _neighbour(local: str, name: str, port: str, descr: str, ip: str, caps: str, mgmt_key: str = "Management address", mau: str = "speed (1000) /duplex (Full)") -> str:
    return (f"{local} has 1 neighbor(s):\n\nNeighbor index                     :1\nChassis type                       :MAC Address\n"
            f"Chassis ID                         :0200-5e00-{sum(map(ord, name)) % 9000 + 1000:04d}\nPort ID subtype                    :Interface Name\n"
            f"Port ID                            :{port}\nPort description                   :{port}\nSystem name                        :{name}\n"
            f"System description                 :{descr}\nSystem capabilities supported      :{caps}\nSystem capabilities enabled        :{caps}\n"
            f"Management address type            :IPv4\n{mgmt_key:<35}:{ip}\nExpired time                       :97s\n\n"
            f"Auto-negotiation supported         :Yes\nAuto-negotiation enabled           :Yes\nOperMau                            :{mau}\n\n")


def _trunk(mode: str, partner_id: str = "0200-5e00-0001") -> str:
    ports = ["10GE1/0/1", "10GE1/0/2", "10GE2/0/1", "10GE2/0/2"]
    rows = "".join(f"{p:<26} Selected 1GE      32768   {i + 1}      305     10111100  1\n" for i, p in enumerate(ports))
    partner = "".join(f"{p:<26} 32768    {partner_id}  32768   {259 + i}    3       10111100\n" for i, p in enumerate(ports))
    return ("Eth-Trunk1's state information is:\nLocal:\n"
            f"LAG ID: 1                       Working Mode: {mode}\nPreempt Delay: Disabled         Hash Arithmetic: profile default\n"
            "System Priority: 32768          System ID: 0200-5e00-00aa\nOperating Status: up            Number Of Up Ports In Trunk: 4\n"
            "------------------------------------------------------------------------------------\n"
            "ActorPortName              Status   PortType PortPri PortNo PortKey PortState Weight\n" + rows + "\nPartner:\n"
            "------------------------------------------------------------------------------------\n"
            "ActorPortName              SysPri   SystemID        PortPri PortNo PortKey PortState\n" + partner + "\n")


def _interface(port: str, speed: int, duplex: str) -> str:
    return (f"{port} current state : UP (ifindex: 25)\nLine protocol current state : UP\nDescription: invented\n"
            f"Speed:                 {speed},     Loopback:                        NONE\n"
            f"Duplex:                {duplex},     Negotiation:                   ENABLE\n")


def huawei_capture(host: str = "LAB-HW-ACC1", mode: str = "Static", mgmt_key: str = "Management address") -> str:
    p = f"<{host}>"
    uplink = "".join(_neighbour(f"10GE{n}", "LAB-CORE1.example.test", f"Gi1/0/{i + 2}", CORE_DESCR, "192.0.2.2", "bridge router", mgmt_key)
                     for i, n in enumerate(("1/0/1", "1/0/2", "2/0/1", "2/0/2")))
    aps = (_neighbour("GE1/0/4", "LAB-AP1", "Gi0", AP_DESCR, "198.51.100.17", "bridge", mgmt_key)
           + _neighbour("GE1/0/5", "LAB-AP2", "Gi0", AP_DESCR, "198.51.100.18", "bridge", mgmt_key, mau="speed (100) /duplex (Half)"))
    return (f"{p}display version\nHuawei YunShan OS\nVersion 1.25.0.1 (S5700 V600R025C00SPC500)\nHUAWEI CloudEngine S5735-S-V2 uptime is 0 day\n\n"
            f"S5735-S24P4XE-V2(Master) 1 : uptime is  0 day\nS5735-S24P4XE-V2 version information:\n3.Board     Type    : S5735-S24P4XE-V2\n\n"
            f"{p}display current-configuration\nsysname {host}\n#\nreturn\n{p}\n"
            f"{p}display eth-trunk\n{_trunk(mode)}{p}\n"
            f"{p}display lldp neighbor\n{uplink}{aps}{p}\n"
            f"{p}display interface\n{_interface('GE1/0/4', 1000, 'FULL')}{_interface('GE1/0/5', 100, 'FULL')}{p}\n")


def _neighbours(text: str) -> dict[str, dict]:
    return {row["local_interface"]: row for row in runtime_parser.parse_neighbors(text.splitlines())}


def test_the_neighbour_management_address_is_read_in_both_vrp_spellings():
    """YunShan prints ``Management address :ip``; older VRP prints ``Management address value :ip``."""
    for key in ("Management address", "Management address value"):
        rows = _neighbours(huawei_capture(mgmt_key=key))
        assert rows["GE1/0/4"]["management_address"] == "198.51.100.17", key
        assert rows["10GE1/0/1"]["management_address"] == "192.0.2.2", key


def test_the_multi_line_system_description_is_kept_as_one_line():
    row = _neighbours(huawei_capture())["GE1/0/4"]
    assert row["system_description"].startswith("Cisco AP Software, ap1g7-k9w8 Version: 17.15.6.201")
    assert "\n" not in row["system_description"] and "System capabilities" not in row["system_description"]


def test_a_description_with_no_capabilities_line_after_it_does_not_swallow_the_address():
    """Older VRP goes from the description straight to ``Management address type`` / ``Management address value``."""
    text = ("<LAB-HW1>display lldp neighbor\nXGE0/0/1 has 1 neighbor(s):\n\nNeighbor index                     :1\n"
            "Chassis ID                         :0200-5e00-0001\nPort ID                            :XGE0/0/5\nSystem name                        :LAB-HW2\n"
            "System description                 :Huawei Switch\nHuawei Versatile Routing Platform Software\n"
            "Management address type            :ipv4\nManagement address value           :192.0.2.12\nPort VLAN ID(PVID)                 :10\n<LAB-HW1>")
    row = runtime_parser.parse_neighbors(text.splitlines())[0]
    assert row["management_address"] == "192.0.2.12" and row["native_vlan"] == "10"
    assert row["system_description"] == "Huawei Switch Huawei Versatile Routing Platform Software"


def test_opermau_gives_the_duplex_the_neighbour_runs():
    rows = _neighbours(huawei_capture())
    assert rows["GE1/0/4"]["duplex"] == "full" and rows["GE1/0/5"]["duplex"] == "half"


@pytest.mark.parametrize(("mode", "expected"), [("Normal", "manual"), ("Static", "lacp-static"), ("Dynamic", "lacp-dynamic")])
def test_eth_trunk_working_mode_says_whether_lacp_runs(mode, expected):
    trunk = runtime_parser.parse_port_channels(huawei_capture(mode=mode).splitlines())[0]
    assert trunk["lacp_mode"] == expected
    assert trunk["protocol"] == "Eth-Trunk"                       # the raw word stays, the mode is added


def test_eth_trunk_members_and_partner_are_read():
    trunk = runtime_parser.parse_port_channels(huawei_capture().splitlines())[0]
    assert [m["port"] for m in trunk["member_states"]] == ["10GE1/0/1", "10GE1/0/2", "10GE2/0/1", "10GE2/0/2"]
    assert {m["flag"] for m in trunk["member_states"]} == {"P"}
    assert trunk["lacp_partner"] == "0200.5e00.0001"


def test_the_bundle_view_carries_the_huawei_mode_to_every_member_port():
    """The Switch Analyzer shows ``lacp-static`` next to each member, the way it shows active / passive for Cisco."""
    lines = huawei_capture(mode="Static").splitlines()
    interfaces = [{"name": port, "state": "up"} for port in ("10GE1/0/1", "10GE1/0/2", "10GE2/0/1", "10GE2/0/2")]
    view = bundles.build(interfaces, runtime_parser.parse_port_channels(lines), None, [], "Eth-Trunk")
    assert {item["bundle_mode"] for item in interfaces} == {"lacp-static"}
    assert {entry["mode"] for entry in view["members"].values()} == {"lacp-static"}


def test_the_long_interface_form_gives_speed_and_duplex():
    seen = live_state.observe_interface_states(huawei_capture().splitlines())
    assert seen["ge1/0/5"][0]["speed_mbps"] == 100 and seen["ge1/0/5"][0]["duplex"] == "full"
    assert seen["ge1/0/4"][0]["speed_mbps"] == 1000


def test_the_model_token_of_a_huawei_neighbour_is_taken_from_its_description():
    assert _huawei_lldp_platform(["Huawei S5735-S24P4XE-V2 Switch, Version 1.25"]) == "S5735-S24P4XE-V2"
    assert _huawei_lldp_platform(["Cisco AP Software, ap1g7-k9w8 Version: 17.15"]) != "S5735-S24P4XE-V2"


def test_vendor_and_role_are_read_from_the_system_description():
    assert vendor_from_description(AP_DESCR) == "Cisco" and vendor_from_description(CORE_DESCR) == "Cisco"
    assert vendor_from_description("Huawei YunShan OS Version 1.25") == "Huawei"
    assert vendor_from_description("FortiGate-100F v7.2") == "Fortinet"
    assert vendor_from_description("") == ""
    assert role_from_description(AP_DESCR) == "ap"
    assert role_from_description("Cisco IOS Software, C9800-CL wireless controller") == "wlc"
    assert role_from_description(CORE_DESCR) == ""                # a switch image says nothing a model name does not


def test_the_aps_a_huawei_switch_sees_are_access_points_with_their_address():
    graph = build_topology([("hw.txt", huawei_capture())], group="none", view="physical")["graph"]
    for name, ip in (("LAB-AP1", "198.51.100.17"), ("LAB-AP2", "198.51.100.18")):
        node = graph.nodes[name]
        assert node.role_hint == "ap" and node.vendor == "Cisco" and node.mgmt_ip == ip, name


def test_the_uncaptured_ap_is_not_reported_as_an_unknown_network_device():
    result = build_topology([("hw.txt", huawei_capture())], group="none", view="physical")
    lines = " ".join(" ".join(f["devices"]) for f in result["findings"] if f["id"] == "TOPO-004")
    assert "LAB-AP1" not in lines and "LAB-AP2" not in lines


@pytest.mark.parametrize(("mode", "label"), [("Static", "LACP"), ("Dynamic", "LACP"), ("Normal", "static")])
def test_the_eth_trunk_is_labelled_by_its_working_mode(mode, label):
    node = build_topology([("hw.txt", huawei_capture(mode=mode))], group="none", view="physical")["graph"].nodes["LAB-HW-ACC1"]
    assert node.bundle_info["Eth-Trunk1"]["protocol"] == label
    assert set(node.member_state.values()) == {"P"} and len(node.member_state) == 4


def test_a_cisco_core_on_lacp_and_a_huawei_manual_trunk_are_reported():
    """TOPO-040 can now compare: the Cisco end runs LACP, the Huawei end ``Working Mode: Normal`` runs no protocol."""
    cisco = iosxe_capture("LAB-CORE1", "FOC00000001", "192.0.2.2",
                          cdp=[("LAB-HW-ACC1", "192.0.2.10", "Huawei S5735-S24P4XE-V2", f"Gi1/0/{n}", f"10GE{p}") for n, p in ((2, "1/0/1"), (3, "1/0/2"), (4, "2/0/1"), (5, "2/0/2"))],
                          port_channels=[(1, ["Gi1/0/2", "Gi1/0/3", "Gi1/0/4", "Gi1/0/5"])])
    clash = build_topology([("c.txt", cisco), ("hw.txt", huawei_capture(mode="Normal"))], group="none", view="physical")["findings"]
    fine = build_topology([("c.txt", cisco), ("hw.txt", huawei_capture(mode="Static"))], group="none", view="physical")["findings"]
    assert any(f["id"] == "TOPO-040" for f in clash)
    assert not any(f["id"] == "TOPO-040" for f in fine)
