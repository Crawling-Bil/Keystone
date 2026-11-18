"""Head quarter: LAN zone, data center zone, core, edge, WAN firewall and WAN routers (hostnames HQ-xxx)."""
from __future__ import annotations
from core import dev, connect, endpoint, mac, DEVICES

HQ = "HQ"
N9K = "N9K-C93180YC-FX3"


def nx(host, role, mgmt, serial, num, **kw):
    d = dev(host, "nxos", kw.pop("model", N9K), serial, mgmt, HQ, role, chassis=0x0a1b00000000 + num)
    return d


def vpc_pair(a, b, domain, peer_ports, vlans, prio=(100, 200)):
    A, B = DEVICES[a], DEVICES[b]
    for d, o, pr, role in ((A, B, prio[0], "primary"), (B, A, prio[1], "secondary")):
        d.vpc = {"domain": domain, "priority": pr, "dst": o.mgmt, "role": role}
        d.po[domain] = {"desc": f"vPC peer-link to {o.host}", "mode": "trunk", "vlans": vlans, "vpc_peer": True, "speed": "100G"}
    for p in peer_ports:
        connect(a, f"Ethernet1/{p}", b, f"Ethernet1/{p}", mode="trunk", vlans=vlans, po=domain, speed="100G", media="QSFP-100G-SR4")


def vpc_port(devs, po, vid, desc, vlans, members, native=None):
    for d, port in zip(devs, members):
        DEVICES[d].po[po] = {"desc": desc, "mode": "trunk", "vlans": vlans, "vpc": vid}
        DEVICES[d].port(port, mode="trunk", vlans=vlans, po=po)


def build():
    # ------------------------------------------------------------------ core, edge, data center switches
    for i, (h, r, m, s) in enumerate([("HQ-CORE1", "core", "10.10.0.11", "FDO2412C0R1"), ("HQ-CORE2", "core", "10.10.0.12", "FDO2412C0R2"), ("HQ-EDGE1", "edge", "10.10.0.13", "FDO2412ED1"),
                                       ("HQ-EDGE2", "edge", "10.10.0.14", "FDO2412ED2"), ("HQ-SF1", "farm", "10.10.0.21", "FDO2412SF1"), ("HQ-SF2", "farm", "10.10.0.22", "FDO2412SF2"),
                                       ("HQ-TOR1", "tor", "10.10.0.23", "FDO2412TR1"), ("HQ-TOR2", "tor", "10.10.0.24", "FDO2412TR2")], 1):
        nx(h, r, m, s, i)
    # firewalls and routers
    fg = lambda h, m, s, n, mgmt: dev(h, "forti", m, s, mgmt, HQ, "firewall", chassis=0x0a1b00000000 + n)
    fg("HQ-FGLAN1", "FortiGate-200F", "FG200F5H24000101", 41, "10.10.0.41"); fg("HQ-FGLAN2", "FortiGate-200F", "FG200F5H24000102", 42, "10.10.0.42")
    fg("HQ-FGWAN1", "FortiGate-600F", "FG6H0F5H24000201", 43, "10.10.0.43"); fg("HQ-FGWAN2", "FortiGate-600F", "FG6H0F5H24000202", 44, "10.10.0.44")
    dev("HQ-PADC1", "pan", "PA-5220", "015351000101", "10.10.0.31", HQ, "firewall", chassis=0x0a1b00000031)
    dev("HQ-PADC2", "pan", "PA-5220", "015351000102", "10.10.0.32", HQ, "firewall", chassis=0x0a1b00000032)
    dev("HQ-WANR1", "iosrtr", "ASR1001-X", "FXS2412Q0W1", "10.10.0.51", HQ, "router", chassis=0x0a1b00000051)
    dev("HQ-WANR2", "iosrtr", "ASR1001-X", "FXS2412Q0W2", "10.10.0.52", HQ, "router", chassis=0x0a1b00000052)
    dev("HQ-ACC1", "ios", "C9300-48P", "FOC2412ACC1", "10.10.199.11", HQ, "access", chassis=0x0a1b00000061)
    dev("HQ-ACC2", "ios", "C9300-48P", "FOC2412ACC2", "10.10.199.12", HQ, "access", chassis=0x0a1b00000062)
    dev("HQ-DS1", "ios", "C9500-24Y4C", "FCW2412DS01", "10.10.199.21", HQ, "distribution", chassis=0x0a1b00000063)
    dev("HQ-DS2", "ios", "C9500-24Y4C", "FCW2412DS02", "10.10.199.22", HQ, "distribution", chassis=0x0a1b00000064)

    # ------------------------------------------------------------------ vPC pairs and their peer-links
    vpc_pair("HQ-CORE1", "HQ-CORE2", 10, (53, 54), "901-902")
    vpc_pair("HQ-EDGE1", "HQ-EDGE2", 20, (53, 54), "911")
    vpc_pair("HQ-SF1", "HQ-SF2", 30, (53, 54), "101-103")
    vpc_pair("HQ-TOR1", "HQ-TOR2", 40, (51, 52), "101-103")

    # ------------------------------------------------------------------ LAN zone: access switches (L2) -> FortiGate HA pair (gateway) -> core vPC
    for acc in ("HQ-ACC1", "HQ-ACC2", "HQ-DS1", "HQ-DS2"):
        A = DEVICES[acc]
        A.vlans = {110: "HQ-USERS", 199: "LAN-MGMT"}
        A.svi[199] = {"ip": (A.mgmt, 24), "desc": "management"}
        A.extra["static"] = ["0.0.0.0 0.0.0.0 10.10.199.1"]
    # distribution pair: FortiGate HA pair above (port3 -> DS1, port4 -> DS2 on both units), two 10G cables between the pair, every access switch on both
    connect("HQ-DS1", "TenGigabitEthernet1/0/1", "HQ-FGLAN1", "port3", mode="trunk", vlans="110,199", native=199, speed="10G")
    connect("HQ-DS1", "TenGigabitEthernet1/0/2", "HQ-FGLAN2", "port3", mode="trunk", vlans="110,199", native=199, speed="10G")
    connect("HQ-DS2", "TenGigabitEthernet1/0/1", "HQ-FGLAN1", "port4", mode="trunk", vlans="110,199", native=199, speed="10G")
    connect("HQ-DS2", "TenGigabitEthernet1/0/2", "HQ-FGLAN2", "port4", mode="trunk", vlans="110,199", native=199, speed="10G")
    for a, b in (("TenGigabitEthernet1/0/23", "TenGigabitEthernet1/0/23"), ("TenGigabitEthernet1/0/24", "TenGigabitEthernet1/0/24")):
        connect("HQ-DS1", a, "HQ-DS2", b, mode="trunk", vlans="110,199", po=1, speed="10G")
    for d in ("HQ-DS1", "HQ-DS2"):
        DEVICES[d].po[1] = {"desc": "inter-switch link DS1 - DS2", "mode": "trunk", "vlans": "110,199"}
    connect("HQ-ACC1", "TenGigabitEthernet1/1/1", "HQ-DS1", "TenGigabitEthernet1/0/3", mode="trunk", vlans="110,199", native=199, speed="10G")
    connect("HQ-ACC1", "TenGigabitEthernet1/1/2", "HQ-DS2", "TenGigabitEthernet1/0/3", mode="trunk", vlans="110,199", native=199, speed="10G")
    connect("HQ-ACC2", "TenGigabitEthernet1/1/1", "HQ-DS1", "TenGigabitEthernet1/0/4", mode="trunk", vlans="110,199", native=199, speed="10G")
    connect("HQ-ACC2", "TenGigabitEthernet1/1/2", "HQ-DS2", "TenGigabitEthernet1/0/4", mode="trunk", vlans="110,199", native=199, speed="10G")
    for acc, host_ports in (("HQ-ACC1", (1, 2)), ("HQ-ACC2", (1, 2))):
        pass
    pcs = [("HQ-ACC1", "GigabitEthernet1/0/1", "HQ-PC1", 0xa11), ("HQ-ACC1", "GigabitEthernet1/0/2", "HQ-PC2", 0xa12), ("HQ-ACC2", "GigabitEthernet1/0/1", "HQ-PC3", 0xa13), ("HQ-ACC2", "GigabitEthernet1/0/2", "HQ-PC4", 0xa14)]
    for sw, port, name, n in pcs:
        DEVICES[sw].port(port, desc=f"{name}", mode="access", access=110)
        endpoint(DEVICES[sw], port, "pc", name, 110, mac(n, "02c0"), f"10.10.110.{n - 0xa10 + 100}")
    # FortiGate LAN pair: redundant interface lan-sw (port3 -> DS1, port4 -> DS2), aggregate agg-core to the core vPC
    for i, fgn in enumerate(("HQ-FGLAN1", "HQ-FGLAN2"), 1):
        F = DEVICES[fgn]
        F.port("port3", type="physical"); F.port("port4", type="physical")
        F.port("lan-sw", type="redundant", members=["port3", "port4"], desc="LAN access switches (redundant)")
        F.port("lan-sw.110", type="vlan", parent="lan-sw", vlanid=110, ip=("10.10.110.1", 24), desc="VLAN 110 HQ users", role="lan", allow="ping")
        F.port("lan-sw.199", type="vlan", parent="lan-sw", vlanid=199, ip=("10.10.199.1", 24), desc="VLAN 199 LAN management", role="lan", allow="ping https ssh")
    # ------------------------------------------------------------------ core <-> LAN firewalls (L3 transit VLAN 901) and DC firewalls (VLAN 902)
    for i, fgn in enumerate(("HQ-FGLAN1", "HQ-FGLAN2")):
        po, port = 111 + i, 11 + i
        connect("HQ-CORE1", f"Ethernet1/{port}", fgn, "port1", mode="trunk", vlans="901", po=po, speed="10G")
        connect("HQ-CORE2", f"Ethernet1/{port}", fgn, "port2", mode="trunk", vlans="901", po=po, speed="10G")
        for c in ("HQ-CORE1", "HQ-CORE2"):
            DEVICES[c].po[po] = {"desc": f"{fgn} agg-core", "mode": "trunk", "vlans": "901", "vpc": po}
            DEVICES[c].port(f"Ethernet1/{port}", desc=f"{fgn} {'port1' if c == 'HQ-CORE1' else 'port2'}")
        F = DEVICES[fgn]
        F.port("agg-core", type="aggregate", members=["port1", "port2"], desc=f"HQ-CORE vPC {po}")
        F.port("agg-core.901", type="vlan", parent="agg-core", vlanid=901, ip=("10.10.251.1", 29), desc="TRANSIT to CORE", role="wan", allow="ping")
        F.port("port1", type="physical", desc=f"to HQ-CORE1 Eth1/{port}"); F.port("port2", type="physical", desc=f"to HQ-CORE2 Eth1/{port}")
    for i, pan in enumerate(("HQ-PADC1", "HQ-PADC2")):
        po, port = 113 + i, 13 + i
        connect("HQ-CORE1", f"Ethernet1/{port}", pan, "ethernet1/1", mode="trunk", vlans="902", po=po, speed="10G")
        connect("HQ-CORE2", f"Ethernet1/{port}", pan, "ethernet1/2", mode="trunk", vlans="902", po=po, speed="10G")
        for c in ("HQ-CORE1", "HQ-CORE2"):
            DEVICES[c].po[po] = {"desc": f"{pan} ae2", "mode": "trunk", "vlans": "902", "vpc": po}
            DEVICES[c].port(f"Ethernet1/{port}", desc=f"{pan} ethernet1/{1 if c == 'HQ-CORE1' else 2}")
    for c, n in (("HQ-CORE1", 2), ("HQ-CORE2", 3)):
        DEVICES[c].vlans = {901: "TRANSIT-FW-LAN", 902: "TRANSIT-FW-DC"}
        DEVICES[c].svi[901] = {"ip": (f"10.10.251.{n}", 29), "desc": "TRANSIT FortiGate LAN", "ospf_area": "0.0.0.0", "ospf_net": "broadcast"}
        DEVICES[c].svi[902] = {"ip": (f"10.10.252.{n}", 29), "desc": "TRANSIT Palo Alto DC", "ospf_area": "0.0.0.0", "ospf_net": "broadcast"}
    # ------------------------------------------------------------------ core <-> edge: four routed /30 links (OSPF area 0)
    for ci, (c, cp, e, ep_, net_) in enumerate([("HQ-CORE1", 49, "HQ-EDGE1", 49, 0), ("HQ-CORE1", 50, "HQ-EDGE2", 49, 4), ("HQ-CORE2", 49, "HQ-EDGE1", 50, 8), ("HQ-CORE2", 50, "HQ-EDGE2", 50, 12)]):
        connect(c, f"Ethernet1/{cp}", e, f"Ethernet1/{ep_}", mode="routed", speed="100G", media="QSFP-100G-SR4")
        DEVICES[c].port(f"Ethernet1/{cp}", ip=(f"10.10.240.{net_ + 1}", 30), ospf_area="0.0.0.0", desc=f"{e} Eth1/{ep_} (routed /30)")
        DEVICES[e].port(f"Ethernet1/{ep_}", ip=(f"10.10.240.{net_ + 2}", 30), ospf_area="0.0.0.0", desc=f"{c} Eth1/{cp} (routed /30)")
    # ------------------------------------------------------------------ data center: servers -> TOR (vPC) -> server farm (vPC) -> Palo Alto HA gateway
    for t in ("HQ-TOR1", "HQ-TOR2", "HQ-SF1", "HQ-SF2"):
        DEVICES[t].vlans = {101: "DC-WEB", 102: "DC-APP", 103: "DC-DB"}
    srv = [("HQ-TOR1", 1, "HQ-SRV1", 101, "00a5.5601"), ("HQ-TOR1", 2, "HQ-SRV3", 103, "02d0.0303"), ("HQ-TOR2", 1, "HQ-SRV2", 102, "00a5.5602"), ("HQ-TOR2", 2, "HQ-SRV4", 103, "02d0.0304")]
    for sw, p, name, vlan, m in srv:
        pn = f"Ethernet1/{p}"
        DEVICES[sw].port(pn, desc=name, mode="access", access=vlan, speed="25G", media="SFP-25G-SR-S")
        endpoint(DEVICES[sw], pn, "server", name, vlan, mac(int(m.replace(".", "")[-4:], 16) + {"HQ-SRV1": 0x10, "HQ-SRV2": 0x20, "HQ-SRV3": 0x30, "HQ-SRV4": 0x40}[name], "0050" if "a5" in m else "02d0"), f"10.10.{vlan}.{ {'HQ-SRV1': 11, 'HQ-SRV2': 11, 'HQ-SRV3': 11, 'HQ-SRV4': 12}[name] }")
    for sw, tor_p, tor, sf_p, sf in (("HQ-TOR1", 53, "HQ-SF1", 49, "HQ-SF1"), ("HQ-TOR1", 54, "HQ-SF2", 49, "HQ-SF2"), ("HQ-TOR2", 53, "HQ-SF1", 50, "HQ-SF1"), ("HQ-TOR2", 54, "HQ-SF2", 50, "HQ-SF2")):
        connect(sw, f"Ethernet1/{tor_p}", sf, f"Ethernet1/{sf_p}", mode="trunk", vlans="101-103", po=141, speed="100G", media="QSFP-100G-SR4")
    for d in ("HQ-TOR1", "HQ-TOR2", "HQ-SF1", "HQ-SF2"):
        DEVICES[d].po[141] = {"desc": "double-sided vPC TOR <-> SERVER FARM", "mode": "trunk", "vlans": "101-103", "vpc": 141}
    for i, pan in enumerate(("HQ-PADC1", "HQ-PADC2")):
        po, port = 121 + i, 11 + i
        connect("HQ-SF1", f"Ethernet1/{port}", pan, "ethernet1/3", mode="trunk", vlans="101-103", po=po, speed="40G")
        connect("HQ-SF2", f"Ethernet1/{port}", pan, "ethernet1/4", mode="trunk", vlans="101-103", po=po, speed="40G")
        for c in ("HQ-SF1", "HQ-SF2"):
            DEVICES[c].po[po] = {"desc": f"{pan} ae1 (server gateway)", "mode": "trunk", "vlans": "101-103", "vpc": po}
            DEVICES[c].port(f"Ethernet1/{port}", desc=f"{pan} ethernet1/{3 if c == 'HQ-SF1' else 4}")
    build2()
    return DEVICES


PROVIDERS = {"TELKOM": 64701, "LINTASARTA": 64702, "ICON+": 64703, "TRIGATRA": 64704}
PROV_NET = {"TELKOM": "198.51.100", "LINTASARTA": "203.0.113", "ICON+": "192.0.2", "TRIGATRA": "198.18.0"}
PE_SLOT = {"HQ": 0, "JKT": 4, "SBY": 4, "YOG": 4, "MKS": 8, "MED": 12, "BAL": 12}


def build2():
    # ------------------------------------------------------------------ Palo Alto DC gateway pair (HA active/passive), L3 gateway of the server VLANs
    for i, pan in enumerate(("HQ-PADC1", "HQ-PADC2"), 1):
        P = DEVICES[pan]
        P.extra.update({"mgmt_gw": "10.10.0.1", "ha_id": 1, "ha_peer_ip": f"10.10.254.{3 - i}", "ha_own_ip": f"10.10.254.{i}", "ha_prio": 90 + (i - 1) * 20,
                        "zones": {"DC-WEB": ["ae1.101"], "DC-APP": ["ae1.102"], "DC-DB": ["ae1.103"], "TRANSIT-CORE": ["ae2.902"]}})
        for port, grp, rem, rp in (("ethernet1/1", "ae2", "HQ-CORE1", "Eth1/%d" % (12 + i)), ("ethernet1/2", "ae2", "HQ-CORE2", "Eth1/%d" % (12 + i)),
                                   ("ethernet1/3", "ae1", "HQ-SF1", "Eth1/%d" % (10 + i)), ("ethernet1/4", "ae1", "HQ-SF2", "Eth1/%d" % (10 + i))):
            P.port(port, type="member", group=grp, desc=f"{rem} - {rp}")
        P.port("ae1", type="ae", desc="Server farm vPC (SF1/SF2)")
        P.port("ae2", type="ae", desc="Core vPC (CORE1/CORE2)")
        for vid, nm in ((101, "DC-WEB"), (102, "DC-APP"), (103, "DC-DB")):
            P.port(f"ae1.{vid}", type="unit", parent="ae1", vlanid=vid, ip=(f"10.10.{vid}.1", 24), desc=f"VLAN {vid} {nm.lower()} servers")
        P.port("ae2.902", type="unit", parent="ae2", vlanid=902, ip=("10.10.252.1", 29), desc="TRANSIT to CORE")
        P.ospf = {"rid": f"10.10.255.{20 + i}", "ifaces": [("ae2.902", 10, "broadcast"), ("ae1.101", 10, "passive"), ("ae1.102", 10, "passive"), ("ae1.103", 10, "passive")]}
    # ------------------------------------------------------------------ FortiGate LAN: HA, DHCP and OSPF
    for i, fgn in enumerate(("HQ-FGLAN1", "HQ-FGLAN2"), 1):
        F = DEVICES[fgn]
        F.extra.update({"ha_role": "primary" if i == 1 else "secondary", "ha_peer": f"HQ-FGLAN{3 - i}", "ha_group": "HQ-FGLAN-HA", "ha_id": 10, "hbdev": "port7", "ha_prio": 200 if i == 1 else 100,
                        "ha_primary": "HQ-FGLAN1", "ha_secondary": "HQ-FGLAN2", "ha_primary_serial": DEVICES["HQ-FGLAN1"].serial, "ha_secondary_serial": DEVICES["HQ-FGLAN2"].serial,
                        "dhcp": [{"id": 1, "gw": "10.10.110.1", "prefix": 24, "iface": "lan-sw.110", "start": "10.10.110.100", "end": "10.10.110.199"}]})
        F.port("mgmt", type="physical", ip=(F.mgmt, 24), allow="ping https ssh", desc="out-of-band management")
        F.ospf = {"rid": f"10.10.255.{10 + i}", "ifaces": [("core", "agg-core.901", "broadcast"), ("lan110", "lan-sw.110", "broadcast"), ("lan199", "lan-sw.199", "broadcast")],
                  "networks": [("10.10.251.0", 29), ("10.10.110.0", 24), ("10.10.199.0", 24)]}
    # ------------------------------------------------------------------ edge: FortiGate WAN pair (VLAN 911), WAN routers, extranet / third party
    for c, n in (("HQ-EDGE1", 2), ("HQ-EDGE2", 3)):
        DEVICES[c].vlans = {911: "TRANSIT-FW-WAN"}
        DEVICES[c].svi[911] = {"ip": (f"10.10.253.{n}", 29), "desc": "TRANSIT FortiGate WAN", "ospf_area": "0.0.0.0", "ospf_net": "broadcast"}
    for i, fgn in enumerate(("HQ-FGWAN1", "HQ-FGWAN2"), 1):
        po, port = 211 + i - 1, 11 + i - 1
        connect("HQ-EDGE1", f"Ethernet1/{port}", fgn, "port1", mode="trunk", vlans="911", po=po, speed="10G")
        connect("HQ-EDGE2", f"Ethernet1/{port}", fgn, "port2", mode="trunk", vlans="911", po=po, speed="10G")
        for c in ("HQ-EDGE1", "HQ-EDGE2"):
            DEVICES[c].po[po] = {"desc": f"{fgn} agg-edge", "mode": "trunk", "vlans": "911", "vpc": po}
            DEVICES[c].port(f"Ethernet1/{port}", desc=f"{fgn} {'port1' if c == 'HQ-EDGE1' else 'port2'}")
        F = DEVICES[fgn]
        F.extra.update({"ha_role": "primary" if i == 1 else "secondary", "ha_peer": f"HQ-FGWAN{3 - i}", "ha_group": "HQ-FGWAN-HA", "ha_id": 20, "hbdev": "port7", "ha_prio": 200 if i == 1 else 100,
                        "ha_primary": "HQ-FGWAN1", "ha_secondary": "HQ-FGWAN2", "ha_primary_serial": DEVICES["HQ-FGWAN1"].serial, "ha_secondary_serial": DEVICES["HQ-FGWAN2"].serial})
        F.port("mgmt", type="physical", ip=(F.mgmt, 24), allow="ping https ssh", desc="out-of-band management")
        F.port("port1", type="physical", desc=f"to HQ-EDGE1 Eth1/{port}"); F.port("port2", type="physical", desc=f"to HQ-EDGE2 Eth1/{port}")
        F.port("agg-edge", type="aggregate", members=["port1", "port2"], desc=f"HQ-EDGE vPC {po}")
        F.port("agg-edge.911", type="vlan", parent="agg-edge", vlanid=911, ip=("10.10.253.1", 29), desc="TRANSIT to EDGE", role="lan", allow="ping")
        F.port("wan1", type="physical", ip=("198.18.1.2", 29), desc="INET TELKOM (internet, BGP)", role="wan", allow="ping")
        F.port("wan2", type="physical", ip=("198.18.2.2", 29), desc="INET ICON+ (internet, BGP)", role="wan", allow="ping")
        F.ospf = {"rid": f"10.10.255.{30 + i}", "ifaces": [("edge", "agg-edge.911", "broadcast")], "networks": [("10.10.253.0", 29)], "fgt_lines": ["set default-information-originate always"]}
        F.bgp = {"asn": 65010, "rid": f"10.10.255.{30 + i}", "neighbors": [("198.18.1.1", 64701, "INET TELKOM"), ("198.18.2.1", 64703, "INET ICON+")], "networks": [("198.19.10.0", 24)]}
        F.extra["static"] = []
    # WAN routers
    for wn, (e1p, e2p, provs) in {"HQ-WANR1": (21, 21, ("TELKOM", "LINTASARTA")), "HQ-WANR2": (22, 22, ("ICON+", "TRIGATRA"))}.items():
        W = DEVICES[wn]
        k = int(wn[-1]) - 1
        connect("HQ-EDGE1", f"Ethernet1/{e1p}", wn, "GigabitEthernet0/0/0", mode="routed", speed="10G")
        connect("HQ-EDGE2", f"Ethernet1/{e2p}", wn, "GigabitEthernet0/0/1", mode="routed", speed="10G")
        a1, a2 = 1 + 8 * k, 5 + 8 * k
        DEVICES["HQ-EDGE1"].port(f"Ethernet1/{e1p}", ip=(f"10.10.241.{a1}", 30), ospf_area="0.0.0.0", desc=f"{wn} Gi0/0/0 (routed /30)")
        DEVICES["HQ-EDGE2"].port(f"Ethernet1/{e2p}", ip=(f"10.10.241.{a2}", 30), ospf_area="0.0.0.0", desc=f"{wn} Gi0/0/1 (routed /30)")
        W.port("GigabitEthernet0/0/0", mode="routed", ip=(f"10.10.241.{a1 + 1}", 30), ospf_area=0, desc="to HQ-EDGE1 Eth1/%d (OSPF)" % e1p)
        W.port("GigabitEthernet0/0/1", mode="routed", ip=(f"10.10.241.{a2 + 1}", 30), ospf_area=0, desc="to HQ-EDGE2 Eth1/%d (OSPF)" % e2p)
        W.lo[0] = (f"10.10.255.{4 + k + 1}", 32)
        nb = []
        for j, pv in enumerate(provs):
            net_ = PROV_NET[pv]
            W.port(f"GigabitEthernet0/0/{2 + j}", mode="routed", ip=(f"{net_}.2", 30), desc=f"MPLS {pv} (BGP AS {PROVIDERS[pv]})")
            nb.append((f"{net_}.1", PROVIDERS[pv], f"MPLS {pv} PE"))
        W.bgp = {"asn": 65010, "rid": f"10.10.255.{5 + k}", "neighbors": nb, "networks": [("10.10.0.0", 16), ("10.0.0.0", 8), ("0.0.0.0", 0)]}
        W.ospf = {"rid": f"10.10.255.{5 + k}", "lines": ["redistribute bgp 65010 subnets metric 100 metric-type 2", "passive-interface GigabitEthernet0/0/2", "passive-interface GigabitEthernet0/0/3"]}
        W.extra["static"] = ["10.10.0.0 255.255.0.0 Null0", "10.0.0.0 255.0.0.0 Null0"]
    # third parties on the edge (not captured): extranet partner and a vendor link, static routed
    DEVICES["HQ-EDGE1"].port("Ethernet1/31", mode="routed", ip=("172.31.100.2", 30), desc="EXTRANET PARTNER-BANK (static)")
    DEVICES["HQ-EDGE2"].port("Ethernet1/31", mode="routed", ip=("172.31.101.2", 30), desc="THIRD-PARTY VENDOR-A (static)")
