"""Fills routing tables, OSPF and BGP neighbor tables with what the designed protocols would converge to (OSPF area 0 everywhere, eBGP to the providers)."""
from __future__ import annotations
from core import DEVICES, LINKS, abbr
from plan_hq import PROV_NET, PROVIDERS
from plan_branch import BRANCHES, SLOT, PORTS, svi_if

BR_NETS = {code: f"10.{100 + n}.0.0/16" for n, code, *_ in BRANCHES}
HQ_LAN = ["10.10.110.0/24", "10.10.199.0/24"]
HQ_DC = ["10.10.101.0/24", "10.10.102.0/24", "10.10.103.0/24"]


def R(d, proto, prefix, nh, intf="", metric=0, type=""):
    d.routes.append({"proto": proto, "prefix": prefix, "nh": nh, "intf": intf, "metric": metric, "type": type})


def N(d, rid, addr, intf):
    d.ospf_nbr.append((rid, addr, intf))


def compute():
    D = DEVICES
    rid = {"HQ-CORE1": "10.10.255.1", "HQ-CORE2": "10.10.255.2", "HQ-EDGE1": "10.10.255.3", "HQ-EDGE2": "10.10.255.4", "HQ-WANR1": "10.10.255.5", "HQ-WANR2": "10.10.255.6",
           "HQ-FGLAN1": "10.10.255.11", "HQ-PADC1": "10.10.255.21", "HQ-FGWAN1": "10.10.255.31"}
    for h in ("HQ-CORE1", "HQ-CORE2", "HQ-EDGE1", "HQ-EDGE2"):
        D[h].ospf = {"rid": rid[h], "lines": ["passive-interface default"] if False else []}
        D[h].lo[0] = (rid[h], 32)
    # ---------------------------------------------------------------- HQ OSPF neighbors
    c1, c2, e1, e2 = (D[h] for h in ("HQ-CORE1", "HQ-CORE2", "HQ-EDGE1", "HQ-EDGE2"))
    N(c1, rid["HQ-EDGE1"], "10.10.240.2", "Eth1/49"); N(c1, rid["HQ-EDGE2"], "10.10.240.6", "Eth1/50")
    N(c2, rid["HQ-EDGE1"], "10.10.240.10", "Eth1/49"); N(c2, rid["HQ-EDGE2"], "10.10.240.14", "Eth1/50")
    N(e1, rid["HQ-CORE1"], "10.10.240.1", "Eth1/49"); N(e1, rid["HQ-CORE2"], "10.10.240.9", "Eth1/50")
    N(e2, rid["HQ-CORE1"], "10.10.240.5", "Eth1/49"); N(e2, rid["HQ-CORE2"], "10.10.240.13", "Eth1/50")
    N(c1, rid["HQ-CORE2"], "10.10.251.3", "Vlan901"); N(c1, rid["HQ-CORE2"], "10.10.252.3", "Vlan902")
    N(c2, rid["HQ-CORE1"], "10.10.251.2", "Vlan901"); N(c2, rid["HQ-CORE1"], "10.10.252.2", "Vlan902")
    for c, other in ((c1, "10.10.251.%d"), (c2, "10.10.251.%d")):
        N(c, rid["HQ-FGLAN1"], "10.10.251.1", "Vlan901")
    for c in (c1, c2):
        N(c, rid["HQ-PADC1"], "10.10.252.1", "Vlan902")
    N(e1, rid["HQ-EDGE2"], "10.10.253.3", "Vlan911"); N(e2, rid["HQ-EDGE1"], "10.10.253.2", "Vlan911")
    for e in (e1, e2):
        N(e, rid["HQ-FGWAN1"], "10.10.253.1", "Vlan911")
    N(e1, rid["HQ-WANR1"], "10.10.241.2", "Eth1/21"); N(e1, rid["HQ-WANR2"], "10.10.241.10", "Eth1/22")
    N(e2, rid["HQ-WANR1"], "10.10.241.6", "Eth1/21"); N(e2, rid["HQ-WANR2"], "10.10.241.14", "Eth1/22")
    fl = D["HQ-FGLAN1"]
    N(fl, rid["HQ-CORE1"], "10.10.251.2", "agg-core.901"); N(fl, rid["HQ-CORE2"], "10.10.251.3", "agg-core.901")
    fw = D["HQ-FGWAN1"]
    N(fw, rid["HQ-EDGE1"], "10.10.253.2", "agg-edge.911"); N(fw, rid["HQ-EDGE2"], "10.10.253.3", "agg-edge.911")
    w1, w2 = D["HQ-WANR1"], D["HQ-WANR2"]
    N(w1, rid["HQ-EDGE1"], "10.10.241.1", "Gi0/0/0"); N(w1, rid["HQ-EDGE2"], "10.10.241.5", "Gi0/0/1")
    N(w2, rid["HQ-EDGE1"], "10.10.241.9", "Gi0/0/0"); N(w2, rid["HQ-EDGE2"], "10.10.241.13", "Gi0/0/1")
    # ---------------------------------------------------------------- HQ routes
    def core_routes(c, edge_hops):
        for p in HQ_LAN:
            R(c, "ospf", p, "10.10.251.1", "Vlan901", 20, "intra")
        for p in HQ_DC:
            R(c, "ospf", p, "10.10.252.1", "Vlan902", 20, "intra")
        for p in ["0.0.0.0/0"] + list(BR_NETS.values()):
            for nh, intf in edge_hops:
                R(c, "ospf", p, nh, intf, 1 if p == "0.0.0.0/0" else 100, "E2")
    core_routes(c1, [("10.10.240.2", "Eth1/49"), ("10.10.240.6", "Eth1/50")])
    core_routes(c2, [("10.10.240.10", "Eth1/49"), ("10.10.240.14", "Eth1/50")])

    def edge_routes(e, cores, wans, fgw):
        for p in HQ_LAN + HQ_DC + ["10.10.251.0/29", "10.10.252.0/29"]:
            for nh, intf in cores:
                R(e, "ospf", p, nh, intf, 20 if "/24" in p else 10, "intra")
        R(e, "ospf", "0.0.0.0/0", fgw, "Vlan911", 1, "E2")
        for p in BR_NETS.values():
            for nh, intf in wans:
                R(e, "ospf", p, nh, intf, 100, "E2")
    edge_routes(e1, [("10.10.240.1", "Eth1/49"), ("10.10.240.9", "Eth1/50")], [("10.10.241.2", "Eth1/21"), ("10.10.241.10", "Eth1/22")], "10.10.253.1")
    edge_routes(e2, [("10.10.240.5", "Eth1/49"), ("10.10.240.13", "Eth1/50")], [("10.10.241.6", "Eth1/21"), ("10.10.241.14", "Eth1/22")], "10.10.253.1")
    for p in HQ_LAN + ["10.10.251.0/29", "10.10.252.0/29"] + HQ_DC:
        for nh in ("10.10.251.2", "10.10.251.3"):
            R(fl, "ospf", p, nh, "agg-core.901", 20, "") if p not in ("10.10.251.0/29",) else None
    for p in ["0.0.0.0/0"] + list(BR_NETS.values()):
        for nh in ("10.10.251.2", "10.10.251.3"):
            R(fl, "ospf", p, nh, "agg-core.901", 1 if p == "0.0.0.0/0" else 100, "E2")
    # FortiGate WAN: BGP default from the two internet providers, internal prefixes from the edge
    R(fw, "bgp", "0.0.0.0/0", "198.18.1.1", "wan1", 0); R(fw, "bgp", "0.0.0.0/0", "198.18.2.1", "wan2", 0)
    for p in HQ_LAN + HQ_DC + list(BR_NETS.values()):
        for nh in ("10.10.253.2", "10.10.253.3"):
            R(fw, "ospf", p, nh, "agg-edge.911", 20 if "/24" in p else 100, "" if "/24" in p else "E2")
    fw.bgp_nbr = [{"ip": "198.18.1.1", "asn": 64701, "name": "INET TELKOM", "pfx": 1}, {"ip": "198.18.2.1", "asn": 64703, "name": "INET ICON+", "pfx": 1}]
    # WAN routers: BGP from the MPLS providers, OSPF from the edge pair
    for w, provs, hops in ((w1, ("TELKOM", "LINTASARTA"), [("10.10.241.1", "Gi0/0/0"), ("10.10.241.5", "Gi0/0/1")]),
                           (w2, ("ICON+", "TRIGATRA"), [("10.10.241.9", "Gi0/0/0"), ("10.10.241.13", "Gi0/0/1")])):
        for p in HQ_LAN + HQ_DC + ["10.10.253.0/29"]:
            for nh, intf in hops:
                R(w, "ospf", p, nh, intf, 20, "")
        for nh, intf in hops:
            R(w, "ospf", "0.0.0.0/0", nh, intf, 1, "E2")
        count = {}
        for j, pv in enumerate(provs):
            pe = f"{PROV_NET[pv]}.1"
            n = 0
            for _n, code, _c, _v, bp in BRANCHES:
                if pv in bp:
                    R(w, "bgp", BR_NETS[code], pe, f"Gi0/0/{2 + j}", 0); n += 1
            w.bgp_nbr.append({"ip": pe, "asn": PROVIDERS[pv], "name": f"MPLS {pv} PE", "pfx": n})
        # (the router also redistributes BGP into OSPF -- see its 'redistribute' line)
    # ---------------------------------------------------------------- HQ access switches
    for h in ("HQ-ACC1", "HQ-ACC2", "HQ-DS1", "HQ-DS2"):
        R(D[h], "static", "0.0.0.0/0", "10.10.199.1", "Vlan199", 1)
    # ---------------------------------------------------------------- branches
    for n, code, city, vendor, provs in BRANCHES:
        m = 100 + n
        rtr, s1, s2, s3 = (D[f"{code}-{x}"] for x in ("RTR1", "SW1", "SW2", "SW3"))
        eps, A, B, Rp, _C = PORTS[vendor]
        nb = []
        for j, pv in enumerate(provs):
            pe = f"{PROV_NET[pv]}.{SLOT[(pv, code)] + 1}"
            intf = f"Gi0/0/{j}"
            hq = ["0.0.0.0/0", "10.10.0.0/16", "10.0.0.0/8"]
            others = [BR_NETS[c] for _n, c, _cc, _v, bp in BRANCHES if c != code and pv in bp]
            for p in hq + others:
                R(rtr, "bgp", p, pe, intf, 0)
            rtr.bgp_nbr.append({"ip": pe, "asn": PROVIDERS[pv], "name": f"MPLS {pv} PE", "pfx": len(hq) + len(others)})
        for v in (10, 20, 30, 99):
            R(rtr, "ospf", f"10.{m}.{v}.0/24", f"10.{m}.0.2", "Gi0/0/2", 2, "")
        N(rtr, f"10.{m}.255.11", f"10.{m}.0.2", "Gi0/0/2")
        short = {"ios": abbr(Rp), "aoscx": Rp, "vrp": "GE0/0/24"}[vendor]
        N(s1, f"10.{m}.255.1", f"10.{m}.0.1", short)
        R(s1, "ospf", "0.0.0.0/0", f"10.{m}.0.1", short if vendor != "vrp" else "GigabitEthernet0/0/24", 1, "E2")
        for sw in (s2, s3):
            R(sw, "static", "0.0.0.0/0", f"10.{m}.99.1", svi_if(vendor, 99), 1)
    # HQ WAN routers redistribute BGP into OSPF; the branches' routers learn HQ through the providers
    for w in (w1, w2):
        w.ospf["lines"] = ["redistribute bgp 65010 subnets metric 100 metric-type 2", "default-information originate"] if False else w.ospf["lines"]
    # a few ARP entries of the HQ core for the firewall transit networks
    for c, own in ((c1, 2), (c2, 3)):
        c.arp += [("10.10.251.1", D["HQ-FGLAN1"].chassis, "Vlan901"), ("10.10.252.1", D["HQ-PADC1"].chassis, "Vlan902")]
    for e, own in ((e1, 2), (e2, 3)):
        e.arp += [("10.10.253.1", D["HQ-FGWAN1"].chassis, "Vlan911")]
    # firewalls speak neither CDP nor LLDP: their cabling is written in the port alias / comment as "<peer> - <peer port>"
    for a, pa, b, pb in LINKS:
        for me, mp, other, op in ((a, pa, b, pb), (b, pb, a, pa)):
            d = D[me]
            if d.os == "forti" and mp in d.ifc:
                d.ifc[mp]["desc"] = f"to {other} - {abbr(op)}"
            elif d.os == "pan" and mp in d.ifc:
                d.ifc[mp]["desc"] = f"{other} - {abbr(op)}"
    return D
