"""Six branches: one Cisco ISR router (two providers) and three switches each; the first switch is the LAN gateway, the other two are L2 access switches.
JKT, SBY and YOG cascade them (SW1 - SW2 - SW3); MKS, MED and BAL are a star (SW1 has two downlinks, to SW2 and to SW3)."""
from __future__ import annotations
from core import dev, connect, endpoint, mac, DEVICES, ipaddress
from plan_hq import PROVIDERS, PROV_NET

# n, code, city, switch vendor, providers (primary, secondary)
BRANCHES = [
    (1, "JKT", "Jakarta", "ios", ("TELKOM", "LINTASARTA")),
    (2, "SBY", "Surabaya", "aoscx", ("TELKOM", "ICON+")),
    (3, "YOG", "Yogyakarta", "vrp", ("LINTASARTA", "TRIGATRA")),
    (4, "MKS", "Makasar", "vrp", ("ICON+", "TRIGATRA")),
    (5, "MED", "Medan", "aoscx", ("TELKOM", "TRIGATRA")),
    (6, "BAL", "Balikpapan", "ios", ("LINTASARTA", "ICON+")),
]
# /30 slot inside the provider block, per branch (PE = slot+1, CE = slot+2); the head quarter owns slot 0
SLOT = {("TELKOM", "JKT"): 4, ("TELKOM", "SBY"): 8, ("TELKOM", "MED"): 12, ("LINTASARTA", "JKT"): 4, ("LINTASARTA", "YOG"): 8, ("LINTASARTA", "BAL"): 12,
        ("ICON+", "SBY"): 4, ("ICON+", "MKS"): 8, ("ICON+", "BAL"): 12, ("TRIGATRA", "YOG"): 4, ("TRIGATRA", "MKS"): 8, ("TRIGATRA", "MED"): 12}
STAR = {"MKS", "MED", "BAL"}      # branches where SW1 has two downlink switches (the others cascade SW1 - SW2 - SW3)
MODEL = {"ios": "C9200L-24P-4G", "aoscx": "6200F 24G 4SFP+", "vrp": "S5735-S24T4X"}
PORTS = {  # endpoints (PC, PC, phone, AP), uplink A (toward the next switch down the chain), uplink B (toward the gateway), routed port to the router, uplink C (SW1 only, a star: toward SW3)
    "ios": (["GigabitEthernet1/0/%d" % i for i in (1, 2, 3, 4)], "GigabitEthernet1/1/1", "GigabitEthernet1/1/2", "GigabitEthernet1/1/3", "GigabitEthernet1/1/4"),
    "aoscx": (["1/1/%d" % i for i in (1, 2, 3, 4)], "1/1/26", "1/1/27", "1/1/25", "1/1/28"),
    "vrp": (["GigabitEthernet0/0/%d" % i for i in (1, 2, 3, 4)], "XGigabitEthernet0/0/1", "XGigabitEthernet0/0/2", "GigabitEthernet0/0/24", "XGigabitEthernet0/0/3"),
}
VLANS = {10: "USERS", 20: "WIFI", 30: "VOICE", 99: "MGMT"}
TRUNK_VLANS = "10,20,30,99"
DNS = "10.10.101.11"
TFTP = "10.10.102.30"


def provider_of(code):
    return next(p for _n, c, _c, _v, p in BRANCHES if c == code)


def svi_if(vendor, vid):
    return {"ios": f"Vlan{vid}", "aoscx": f"Vlan{vid}", "vrp": f"Vlanif{vid}"}[vendor]


def build():
    for n, code, city, vendor, provs in BRANCHES:
        m = 100 + n
        sw_os = vendor
        rtr = dev(f"{code}-RTR1", "iosrtr", "ISR4331/K9", f"FDO24{n}0R0A1", f"10.{m}.255.1", code, "router", chassis=0x0a1b00000100 + n * 0x10)
        sws = []
        for k in (1, 2, 3):
            ip = f"10.{m}.99.{1 if k == 1 else 10 + k}"
            serial = {"ios": f"FCW24{n}{k}L00{k}", "aoscx": f"SG24{n}{k}0AB{k}", "vrp": f"2102353{n}{k}0K{k:04d}"}[vendor]
            sw = dev(f"{code}-SW{k}", sw_os, MODEL[vendor], serial, ip, code, "gateway" if k == 1 else "access", chassis=0x0a1b00000100 + n * 0x10 + k)
            sw.vlans = dict(VLANS)
            sws.append(sw)
        eps, A, B, R, C = PORTS[vendor]
        star = code in STAR
        # ---- cascade: SW1.A <-> SW2.B, SW2.A <-> SW3.B; star: SW1.A <-> SW2.B, SW1.C <-> SW3.B
        trunk = dict(mode="trunk", vlans=TRUNK_VLANS, native=99)
        connect(sws[0].host, A, sws[1].host, B, **trunk)
        if star:
            connect(sws[0].host, C, sws[2].host, B, **trunk)
        else:
            connect(sws[1].host, A, sws[2].host, B, **trunk)
        # ---- SW1 routed port to the router (/26)
        connect(rtr.host, "GigabitEthernet0/0/2", sws[0].host, R)
        rtr.port("GigabitEthernet0/0/2", ip=(f"10.{m}.0.1", 26), ospf_area=0, desc=f"to {sws[0].host} {R} (LAN gateway, OSPF)")
        sws[0].port(R, mode="routed", ip=(f"10.{m}.0.2", 26), ospf_area=0, desc=f"to {rtr.host} Gi0/0/2 (OSPF)")
        # ---- providers
        nb, bgpn = [], []
        for j, pv in enumerate(provs):
            slot = SLOT[(pv, code)]
            net_ = PROV_NET[pv]
            rtr.port(f"GigabitEthernet0/0/{j}", ip=(f"{net_}.{slot + 2}", 30), desc=f"MPLS {pv} (BGP AS {PROVIDERS[pv]})")
            nb.append((f"{net_}.{slot + 1}", PROVIDERS[pv], f"MPLS {pv} PE"))
        rtr.lo[0] = (f"10.{m}.255.1", 32)
        rtr.bgp = {"asn": 65100 + n, "rid": f"10.{m}.255.1", "neighbors": nb, "networks": [(f"10.{m}.0.0", 16)], "af_lines": []}
        rtr.ospf = {"rid": f"10.{m}.255.1", "lines": ["default-information originate", "passive-interface GigabitEthernet0/0/0", "passive-interface GigabitEthernet0/0/1"]}
        rtr.extra["static"] = [f"10.{m}.0.0 255.255.0.0 Null0"]
        # ---- gateway SVIs, DHCP, OSPF
        gw = sws[0]
        names = {10: "USERS wired", 20: "WIFI users", 30: "VOICE phones", 99: "MGMT"}
        for vid in (10, 20, 30, 99):
            gw.svi[vid] = {"ip": (f"10.{m}.{vid}.1", 24), "desc": names[vid], "ospf_area": 0, "dhcp": vid != 99}
        for vid, nm in ((10, "USERS"), (20, "WIFI"), (30, "VOICE")):
            gw.extra.setdefault("dhcp", []).append({"name": f"{code}-{nm}", "gw": f"10.{m}.{vid}.1", "prefix": 24, "net": f"10.{m}.{vid}.0", "excl": f"10.{m}.{vid}.99",
                                                    "start": f"10.{m}.{vid}.100", "end": f"10.{m}.{vid}.199", "dns": DNS, "tftp": TFTP if vid == 30 else ""})
        if vendor == "ios":
            gw.ospf = {"rid": f"10.{m}.255.11", "lines": ["passive-interface default", f"no passive-interface {R}"]}
            gw.extra["static"] = []
        elif vendor == "aoscx":
            gw.ospf = {"rid": f"10.{m}.255.11", "lines": []}
            gw.extra["static"] = []
        else:
            gw.ospf = {"rid": f"10.{m}.255.11", "lines": [f"silent-interface Vlanif{v}" for v in (10, 20, 30, 99)],
                       "networks": [(f"10.{m}.{v}.0", 24) for v in (10, 20, 30, 99)] + [(f"10.{m}.0.0", 26)]}
            gw.extra["static"] = []
        # ---- L2 access switches: management SVI and default route to the gateway
        for sw in sws[1:]:
            sw.svi[99] = {"ip": (sw.mgmt, 24), "desc": "MGMT"}
            sw.extra["static"] = [{"ios": f"0.0.0.0 0.0.0.0 10.{m}.99.1", "aoscx": f"0.0.0.0/0 10.{m}.99.1", "vrp": f"0.0.0.0 0.0.0.0 10.{m}.99.1"}[vendor]]
        # ---- endpoints: 2 PCs, 1 IP phone, 1 access point per switch
        base = n * 0x1000
        pc_i, ph_i, ap_i, wf_i = 0, 0, 0, 0
        for k, sw in enumerate(sws, 1):
            pcp1, pcp2, php, app = eps
            for pport in (pcp1, pcp2):
                pc_i += 1
                sw.port(pport, mode="access", access=10, desc=f"{code}-PC{pc_i}")
                endpoint(sw, pport, "pc", f"{code}-PC{pc_i}", 10, mac(base + 0x100 + pc_i, "02c0"), f"10.{m}.10.{100 + pc_i}")
            ph_i += 1
            if vendor == "aoscx":            # AOS-CX: the phone's voice VLAN is tagged on a trunk whose native VLAN carries the PC behind it
                sw.port(php, mode="trunk", vlans="10,30", native=10, desc=f"{code}-PHONE{ph_i}")
            else:
                sw.port(php, mode="access", access=10, voice=30, desc=f"{code}-PHONE{ph_i}")
            endpoint(sw, php, "phone", f"{code}-PHONE{ph_i}", 30, mac(base + 0x200 + ph_i, "02e1"), f"10.{m}.30.{100 + ph_i}")
            ap_i += 1
            sw.port(app, mode="trunk", vlans="20,99", native=99, desc=f"{code}-AP{ap_i}")
            wifi = []
            for _ in range(2):
                wf_i += 1
                wifi.append((20, mac(base + 0x300 + wf_i, "02f1"), f"10.{m}.20.{100 + wf_i}"))
            endpoint(sw, app, "ap", f"{code}-AP{ap_i}", 99, mac(base + 0x400 + ap_i, "02a9"), f"10.{m}.99.{20 + ap_i}", wifi_clients=wifi)
        # ---- MAC tables: what each switch learns across the cascade
        mac_of = lambda sw: [(e["vlan"], e["mac"]) for e in sw.attached] + [(v, mm) for e in sw.attached for v, mm, _i in e["wifi"]]
        s1, s2, s3 = sws
        for v, mm in mac_of(s2):
            s1.macs.append((v, mm, A))
        for v, mm in mac_of(s3):
            s1.macs.append((v, mm, C if star else A))
        if not star:
            for v, mm in mac_of(s3):
                s2.macs.append((v, mm, A))
        for v, mm in mac_of(s1):
            s2.macs.append((v, mm, B))
            s3.macs.append((v, mm, B))
        for v, mm in mac_of(s2):
            s3.macs.append((v, mm, B))
        for vid in (10, 20, 30, 99):
            s2.macs.append((vid, s1.chassis, B))
            s3.macs.append((vid, s1.chassis, B))
        # ---- ARP of the gateway and of the router
        gwif = lambda vid: svi_if(vendor, vid)
        for sw in sws:
            for e in sw.attached:
                s1.arp.append((e["ip"], e["mac"], gwif(e["vlan"])))
                for v, mm, ip in e["wifi"]:
                    s1.arp.append((ip, mm, gwif(v)))
        for sw in (s2, s3):
            s1.arp.append((sw.mgmt, sw.chassis, gwif(99)))
        s1.arp.append((f"10.{m}.0.1", rtr.chassis, R))
        rtr.arp.append((f"10.{m}.0.2", s1.chassis, "GigabitEthernet0/0/2"))
    return DEVICES
