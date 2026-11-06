"""TOPO-036 to TOPO-039: MTU and OSPF parameters that the two ends of a link must agree on, and the reader behind them (ifparams.py).

Synthetic captures only (invented names, documentation addresses; the layouts follow what IOS XE, NX-OS, AOS-CX and VRP print)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture, nxos_capture  # noqa: E402

from features.topology import ifparams, service  # noqa: E402

IOS_PORT = "GigabitEthernet1/0/1"


def ios_router(host: str, serial: str, ip: str, local: str, peer: str, peer_ip: str, peer_port: str, interface: str, router: str = " router-id 10.60.255.1\n") -> str:
    cdp = [(f"{peer}.lab.example({'FDO9600000' + peer[-1]})", peer_ip, "C9300-48P", IOS_PORT, peer_port)]
    block = f"interface {IOS_PORT}\n no switchport\n ip address {local} 255.255.255.252\n{interface}!\nrouter ospf 1\n{router}!\n"
    return iosxe_capture(host, serial, ip, cdp=cdp, config_extra=block)


def nxos_router(host: str, serial: str, ip: str, local: str, peer: str, peer_ip: str, interface: str) -> str:
    cdp = [(f"{peer}.lab.example(FDO9600000{peer[-1]})", peer_ip, "C9300-48P", "Ethernet1/1", IOS_PORT)]
    block = f"interface Ethernet1/1\n  no switchport\n  ip address {local}/30\n{interface}\nrouter ospf 1\n  router-id 10.60.255.2\n"
    return nxos_capture(host, serial, ip, cdp=cdp, config_extra=block)


def pair(ios_lines: str, nxos_lines: str, ios_global: str = "", nxos_global: str = "") -> dict[str, str]:
    """LAB-R1 (IOS XE, Gi1/0/1 10.60.0.1/30) cabled to LAB-R2 (NX-OS, Eth1/1 10.60.0.2/30); the lines are the interface commands of each end."""
    return {
        "LAB-R1.txt": ios_global + ios_router("LAB-R1", "FDO96000001", "10.60.255.1", "10.60.0.1", "LAB-R2", "10.60.255.2", "Ethernet1/1", ios_lines),
        "LAB-R2.txt": nxos_global + nxos_router("LAB-R2", "FDO96000002", "10.60.255.2", "10.60.0.2", "LAB-R1", "10.60.255.1", nxos_lines),
    }


OSPF_IOS = " ip ospf 1 area 0\n"
OSPF_NXOS = "  ip router ospf 1 area 0.0.0.0\n"


def found(files: dict[str, str]) -> dict[str, dict]:
    result = service.build_topology(list(files.items()), group="none")
    return {f["id"]: f for f in result["findings"] if f["id"] in ("TOPO-036", "TOPO-037", "TOPO-038", "TOPO-039")}


# ---- the reader ---------------------------------------------------------------------------------------------------

def test_reader_reads_cisco_blocks_and_defaults():
    text = ("hostname R\n!\ninterface GigabitEthernet1/0/1\n no switchport\n ip address 10.1.1.1 255.255.255.252\n mtu 9000\n ip mtu 8900\n"
            " ip ospf 1 area 0\n ip ospf hello-interval 5\n ip ospf network point-to-point\n ip ospf message-digest-key 1 md5 SECRETWORD\n!\n"
            "interface GigabitEthernet1/0/2\n description to X\n shutdown\n!\nrouter ospf 1\n")
    data = ifparams.read(text, None, "cisco")
    assert data["ports"]["Gi1/0/1"]["mtu"] == 9000 and data["ports"]["Gi1/0/1"]["ip_mtu"] == 8900
    ospf = data["ports"]["Gi1/0/1"]["ospf"]
    assert (ospf["area"], ospf["hello"], ospf["dead"], ospf["network"]) == ("0.0.0.0", 5, 20, "point-to-point")      # dead = 4 x hello
    assert "Gi1/0/2" not in data["ports"] and "SECRETWORD" not in repr(data) and "md5" not in repr(data)


def test_reader_defaults_and_slow_network_types():
    text = "interface Ethernet1/1\n  ip router ospf 1 area 0.0.0.5\ninterface Ethernet1/2\n  ip router ospf 1 area 7\n  ip ospf network non-broadcast\n"
    ports = ifparams.read(text, None, "cisco")["ports"]
    assert ports["Eth1/1"]["ospf"] == {"area": "0.0.0.5", "hello": 10, "dead": 40, "network": "broadcast", "mtu_ignore": False, "assumed": False}
    assert (ports["Eth1/2"]["ospf"]["area"], ports["Eth1/2"]["ospf"]["hello"], ports["Eth1/2"]["ospf"]["dead"]) == ("0.0.0.7", 30, 120)


def test_reader_reads_aos_cx_and_huawei():
    cx = "interface 1/1/1\n    no shutdown\n    ip address 10.2.2.1/30\n    mtu 9198\n    ip ospf 1 area 0.0.0.0\n    ip ospf hello-interval 3\n    ip ospf dead-interval 12\n"
    port = ifparams.read(cx, None, "aruba")["ports"]["1/1/1"]
    assert port["mtu"] == 9198 and (port["ospf"]["hello"], port["ospf"]["dead"]) == (3, 12)
    vrp = "#\ninterface GigabitEthernet0/0/1\n undo portswitch\n ip address 10.3.3.1 255.255.255.252\n mtu 1400\n ospf enable 1 area 0.0.0.1\n ospf timer hello 5\n ospf network-type p2p\n#\n"
    port = ifparams.read(vrp, None, "huawei")["ports"]["Gi0/0/1"]
    assert port["mtu"] == 1400 and port["ospf"]["area"] == "0.0.0.1" and port["ospf"]["network"] == "point-to-point"
    assert (port["ospf"]["hello"], port["ospf"]["dead"]) == (5, 40)                  # Huawei keeps the default dead interval


def test_reader_flags_a_global_mtu_and_ignores_show_output():
    assert ifparams.read("system mtu 9198\ninterface Gi1/0/1\n mtu 9000\n", None, "cisco")["global_mtu"] is True
    assert ifparams.read("jumboframe enable 9216\n", None, "huawei")["global_mtu"] is True
    assert ifparams.read("interface Gi1/0/1\n mtu 9000\n", None, "cisco")["global_mtu"] is False
    show = "GigabitEthernet1/0/1 is up, line protocol is up\n  MTU 1500 bytes, BW 1000000 Kbit/sec\nInterface Vlan10 is up\n"
    assert ifparams.read(show, None, "cisco")["ports"] == {}


def test_area_and_network_type_spellings():
    assert ifparams.area_id("0") == "0.0.0.0" and ifparams.area_id("0.0.0.0") == "0.0.0.0" and ifparams.area_id("256") == "0.0.1.0" and ifparams.area_id("") == ""
    assert ifparams.network_type("p2p") == "point-to-point" and ifparams.network_type("Point-to-point") == "point-to-point" and ifparams.network_type("non-broadcast") == "non-broadcast"


# ---- TOPO-036: MTU ------------------------------------------------------------------------------------------------

def test_a_routed_mtu_mismatch_with_ospf_is_reported_with_the_ospf_consequence():
    rows = found(pair(" mtu 9000\n" + OSPF_IOS, OSPF_NXOS))
    row = rows["TOPO-036"]
    assert row["severity"] == "medium" and "9000 bytes at LAB-R1, 1500 bytes at LAB-R2" in row["detail"] and "(OSPF runs on both)" in row["detail"]
    assert "ExStart" in row["recommendation"] and row["reference"].endswith("13684-12.html")
    assert row["devices"] == ["LAB-R1", "LAB-R2"]


def test_equal_mtu_is_no_finding():
    assert "TOPO-036" not in found(pair(" mtu 9000\n" + OSPF_IOS, "  mtu 9000\n" + OSPF_NXOS))


def test_ip_mtu_wins_over_the_interface_mtu():
    assert "TOPO-036" not in found(pair(" mtu 9000\n ip mtu 1500\n" + OSPF_IOS, OSPF_NXOS))                     # the IP packets are 1500 at both ends
    assert "TOPO-036" in found(pair(" mtu 1500\n ip mtu 1400\n" + OSPF_IOS, OSPF_NXOS))


def test_mtu_ignore_drops_the_ospf_sentence_but_not_the_finding():
    row = found(pair(" mtu 9000\n ip ospf mtu-ignore\n" + OSPF_IOS, OSPF_NXOS))["TOPO-036"]
    assert "ExStart" not in row["recommendation"] and row["reference"].endswith("section-10.5")


def test_a_global_jumbo_setting_hides_the_unknown_end():
    # R2 has "system jumbomtu": its routed port MTU is not what the interface says, so it is not compared against R1's explicit value
    assert "TOPO-036" not in found(pair(" mtu 9000\n" + OSPF_IOS, OSPF_NXOS, nxos_global="system jumbomtu 9216\n"))


def test_layer_2_ports_are_compared_only_when_both_ends_say_it():
    ios = "interface GigabitEthernet1/0/1\n switchport mode trunk\n mtu 9216\n!\n"
    cdp_r1 = [("LAB-S2.lab.example(FDO96000012)", "10.60.255.12", "N9K-C93180YC-FX3", IOS_PORT, "Ethernet1/1")]
    cdp_r2 = [("LAB-S1.lab.example(FDO96000011)", "10.60.255.11", "C9300-48P", "Ethernet1/1", IOS_PORT)]
    one = {"LAB-S1.txt": iosxe_capture("LAB-S1", "FDO96000011", "10.60.255.11", cdp=cdp_r1, config_extra=ios),
           "LAB-S2.txt": nxos_capture("LAB-S2", "FDO96000012", "10.60.255.12", cdp=cdp_r2)}
    assert found(one) == {}                                                      # the other end says nothing: a Nexus ignores the interface MTU on layer 2 anyway
    both = dict(one, **{"LAB-S2.txt": nxos_capture("LAB-S2", "FDO96000012", "10.60.255.12", cdp=cdp_r2, config_extra="interface Ethernet1/1\n  switchport\n  mtu 1500\n")})
    assert "TOPO-036" in found(both) and "(OSPF" not in found(both)["TOPO-036"]["detail"]


# ---- TOPO-037 to 039: OSPF ----------------------------------------------------------------------------------------

def test_hello_mismatch_is_reported_and_the_dead_interval_follows_the_hello():
    rows = found(pair(" ip ospf hello-interval 5\n" + OSPF_IOS, OSPF_NXOS))
    assert "hello 5 s / dead 20 s at LAB-R1, hello 10 s / dead 40 s at LAB-R2" in rows["TOPO-037"]["detail"]
    assert rows["TOPO-037"]["reference"].endswith("12151-trouble-main.html") and "RFC 2328" in rows["TOPO-037"]["recommendation"]


def test_same_timers_written_differently_are_equal():
    assert "TOPO-037" not in found(pair(" ip ospf hello-interval 5\n" + OSPF_IOS, "  ip ospf hello-interval 5\n  ip ospf dead-interval 20\n" + OSPF_NXOS))
    assert "TOPO-037" in found(pair(" ip ospf dead-interval 60\n" + OSPF_IOS, OSPF_NXOS))


def test_area_spellings_are_one_area_and_different_areas_are_reported():
    assert "TOPO-039" not in found(pair(OSPF_IOS, OSPF_NXOS))                                # 0 and 0.0.0.0
    rows = found(pair(" ip ospf 1 area 1\n", OSPF_NXOS))
    assert "area 0.0.0.1 at LAB-R1, area 0.0.0.0 at LAB-R2" in rows["TOPO-039"]["detail"] and "TOPO-037" not in rows


def test_network_type_mismatch_is_reported():
    rows = found(pair(" ip ospf network point-to-point\n" + OSPF_IOS, OSPF_NXOS))
    assert "point-to-point at LAB-R1, broadcast at LAB-R2" in rows["TOPO-038"]["detail"] and "TOPO-037" not in rows          # default timers are equal for both types


def test_matching_configuration_has_no_finding():
    assert found(pair(OSPF_IOS, OSPF_NXOS)) == {}
    assert found(pair(" mtu 9000\n ip ospf network point-to-point\n" + OSPF_IOS, "  mtu 9000\n  ip ospf network point-to-point\n" + OSPF_NXOS)) == {}


def test_a_link_without_ospf_on_one_end_is_not_an_ospf_finding():
    rows = found(pair(" ip ospf hello-interval 5\n" + OSPF_IOS, ""))
    assert not {"TOPO-037", "TOPO-038", "TOPO-039"} & set(rows)


def test_an_uncaptured_peer_is_never_a_finding():
    files = pair(" mtu 9000\n ip ospf hello-interval 5\n" + OSPF_IOS, OSPF_NXOS)
    assert found({"LAB-R1.txt": files["LAB-R1.txt"]}) == {}


def test_the_parameters_survive_the_saved_state():
    from features.topology import state
    files = pair(" mtu 9000\n" + OSPF_IOS, OSPF_NXOS)
    devices, _ = service.read_devices(list(files.items()))
    import json
    saved = state.read_state(json.dumps({"state": json.loads(state.state_json(devices))}).encode())
    ios = next(d for d in saved if d.hostname == "LAB-R1")
    assert ios.ifparams["ports"]["Gi1/0/1"]["mtu"] == 9000 and ios.ifparams["ports"]["Gi1/0/1"]["ospf"]["hello"] == 10


def test_a_show_only_end_is_never_judged_on_guessed_timers(monkeypatch):
    # when a capture holds the OSPF state but no interface block, the timers are the defaults: they are shown as "assumed" and not compared
    real = ifparams.read

    def read(text, result=None, vendor=""):
        data = real(text, result, vendor)
        if "LAB-R2" in str(text)[:600]:
            for record in data["ports"].values():
                if record.get("ospf"):
                    record["ospf"]["assumed"] = True
        return data
    monkeypatch.setattr(service.ifparams, "read", read)
    with service._CACHE_LOCK:
        service._CACHE.clear()                                            # the capture reader keeps what it read: read it again through the wrapper
    try:
        rows = found(pair(" ip ospf hello-interval 5\n" + OSPF_IOS, OSPF_NXOS))
    finally:
        with service._CACHE_LOCK:
            service._CACHE.clear()
    assert "TOPO-037" not in rows


def test_the_reader_marks_an_interface_without_a_block_as_assumed():
    result = {"l3": {"ospf": {"interfaces": [{"interface": "GigabitEthernet1/0/9", "area": "0", "passive": False, "network_type": ""}]}, "interfaces": []}}
    data = ifparams.read("", result, "cisco")
    assert data["ports"]["Gi1/0/9"]["ospf"]["assumed"] is True and data["ports"]["Gi1/0/9"]["ospf"]["hello"] == 10


def po_pair(ios_po: str, nxos_po: str) -> dict[str, str]:
    """Two routers joined by a two-member routed port-channel (IOS XE Po1 of Gi1/0/1-2, NX-OS Po1 of Eth1/1-2)."""
    ios_cdp = [("LAB-R2.lab.example(FDO96000002)", "10.60.255.2", "C9300-48P", f"GigabitEthernet1/0/{n}", f"Ethernet1/{n}") for n in (1, 2)]
    nxos_cdp = [("LAB-R1.lab.example(FDO96000001)", "10.60.255.1", "C9300-48P", f"Ethernet1/{n}", f"GigabitEthernet1/0/{n}") for n in (1, 2)]
    ios_cfg = ("interface Port-channel1\n no switchport\n ip address 10.60.0.1 255.255.255.252\n" + ios_po + "!\ninterface GigabitEthernet1/0/1\n channel-group 1 mode active\n!\n"
               "interface GigabitEthernet1/0/2\n channel-group 1 mode active\n!\nrouter ospf 1\n router-id 10.60.255.1\n!\n")
    nxos_cfg = ("interface port-channel1\n  no switchport\n  ip address 10.60.0.2/30\n" + nxos_po + "interface Ethernet1/1\n  channel-group 1 mode active\n"
                "interface Ethernet1/2\n  channel-group 1 mode active\nrouter ospf 1\n  router-id 10.60.255.2\n")
    return {"LAB-R1.txt": iosxe_capture("LAB-R1", "FDO96000001", "10.60.255.1", cdp=ios_cdp, port_channels=[(1, ["Gi1/0/1", "Gi1/0/2"])], config_extra=ios_cfg),
            "LAB-R2.txt": nxos_capture("LAB-R2", "FDO96000002", "10.60.255.2", cdp=nxos_cdp, port_channels=[(1, ["Eth1/1", "Eth1/2"])], config_extra=nxos_cfg)}


def test_a_port_channel_is_judged_on_the_bundle_and_listed_once():
    rows = found(po_pair(" mtu 9000\n ip ospf 1 area 0\n ip ospf hello-interval 5\n", "  ip router ospf 1 area 0.0.0.0\n"))
    assert rows["TOPO-036"]["detail"].count("LAB-R1 Po1 - LAB-R2 Po1") == 1 and "(OSPF runs on both)" in rows["TOPO-036"]["detail"]
    assert rows["TOPO-037"]["detail"].count("LAB-R1 Po1 - LAB-R2 Po1") == 1 and rows["TOPO-037"]["title"].startswith("1 link(s)")
    assert found(po_pair(" mtu 9000\n ip ospf 1 area 0\n", "  mtu 9000\n  ip router ospf 1 area 0.0.0.0\n")) == {}
