"""Generate the captures of the "HQ DC DRC Branches" demo: the head quarter (site HQ-DC), a disaster-recovery copy of it (site DRC) with its own addresses,
a dedicated DCI between the two edge pairs, and the six branches.  The HQ and DRC plans are the HQ plan (plan_hq.py, routing.py) read through a text transform,
so the two sites are built from one design and cannot drift apart."""
import os, re, sys, shutil, types
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core, r_cisco, r_fw, r_other
import plan_hq, plan_branch, routing
from plan_hq import PROV_NET, PROVIDERS
from plan_branch import BRANCHES, SLOT, PORTS, svi_if
from core import connect, DEVICES, LINKS, abbr
from routing import R, N, BR_NETS

HERE = os.path.dirname(os.path.abspath(__file__))
RENDER = {"nxos": r_cisco.render_nxos, "ios": r_cisco.render_ios, "iosrtr": r_cisco.render_ios, "forti": r_fw.render_forti, "pan": r_fw.render_pan, "aoscx": r_other.render_aoscx, "vrp": r_other.render_vrp}

SITES = {
    # prefix of the hostnames, site name, address block (first two octets), BGP AS, provider /30 slot (PE = slot+1, CE = slot+2), internet /29 blocks, extranet blocks, serial/MAC set
    "dc": dict(host="HQ-DC-", site="HQ-DC", a="10.10", asn=65010, pe=1, wan1="198.18.1.", wan2="198.18.2.", ext0="172.31.100.", ext1="172.31.101.", gen=0),
    "drc": dict(host="DRC-", site="DRC", a="10.30", asn=65030, pe=17, wan1="198.18.3.", wan2="198.18.4.", ext0="172.31.110.", ext1="172.31.111.", gen=1),
}


def transform_plan(src: str, s: dict) -> str:
    t = src.replace("HQ-", s["host"]).replace('HQ = "HQ"', f'HQ = "{s["site"]}"').replace("HQ users", f'{s["site"]} users')
    t = t.replace("10.10.", s["a"] + ".")
    t = t.replace("198.18.1.", s["wan1"]).replace("198.18.2.", s["wan2"]).replace("65010", str(s["asn"]))
    t = t.replace("172.31.100.", s["ext0"]).replace("172.31.101.", s["ext1"])
    if s["pe"] != 1:                                               # the customer side of a provider link is the slot + 2, the provider side the slot + 1
        a, b = 'ip=(f"{net_}.2", 30)', 'nb.append((f"{net_}.1", PROVIDERS[pv]'
        assert a in t and b in t
        t = t.replace(a, f'ip=(f"{{net_}}.{s["pe"] + 1}", 30)').replace(b, f'nb.append((f"{{net_}}.{s["pe"]}", PROVIDERS[pv]')
        t = t.replace("198.19.10.0", "198.19.30.0")
    if s["gen"]:                                                   # serial numbers and MAC addresses must differ from the first copy
        for a, b in (("FDO2412", "FDO2413"), ("FXS2412", "FXS2413"), ("FCW2412", "FCW2413"), ("FOC2412", "FOC2413"), ("FG200F5H24", "FG200F5H25"), ("FG6H0F5H24", "FG6H0F5H25"), ("0153510001", "0153510002"),
                     ("0x0a1b0000", "0x0a1b0001"), ('"02c0"', '"02c1"'), ('"0050"', '"0051"'), ('"02d0"', '"02d1"'), ("02d0.", "02d1.")):
            assert a in t, a
            t = t.replace(a, b)
    return t


def load_plan(tag: str):
    s = SITES[tag]
    src = open(os.path.join(HERE, "plan_hq.py"), encoding="utf-8").read()
    mod = types.ModuleType(f"plan_{tag}")
    mod.__dict__["__name__"] = f"plan_{tag}"
    exec(compile(transform_plan(src, s), f"plan_{tag}.py", "exec"), mod.__dict__)
    return mod


def routing_parts():
    lines = open(os.path.join(HERE, "routing.py"), encoding="utf-8").read().splitlines()
    assert lines[20].strip() == "D = DEVICES" and "HQ OSPF neighbors" in lines[26] and "branches" in lines[104] and "# a few ARP entries" in lines[129]
    hq = lines[21:104]                                             # rid ... HQ access switches
    arp = lines[129:134]                                           # the ARP entries of the core and edge
    br = lines[104:126]                                            # the branches
    return hq, arp, br


HQ_SRC, ARP_SRC, BR_SRC = routing_parts()


def site_routes(tag: str, other_net: str | None):
    s = SITES[tag]
    body = "\n".join(HQ_SRC + ARP_SRC)
    t = body.replace("HQ-", s["host"]).replace("10.10.", s["a"] + ".").replace("198.18.1.", s["wan1"]).replace("198.18.2.", s["wan2"]).replace("65010", str(s["asn"]))
    t = t.replace('pe = f"{PROV_NET[pv]}.1"', f'pe = f"{{PROV_NET[pv]}}.{s["pe"]}"')
    if other_net:                                                  # the other site's /16 is learned from every provider the WAN router has
        t = t.replace('            w.bgp_nbr.append({"ip": pe,', f'            R(w, "bgp", "{other_net}", pe, f"Gi0/0/{{2 + j}}", 0); n += 1\n            w.bgp_nbr.append({{"ip": pe,')
    t = t.replace('["0.0.0.0/0"] + list(BR_NETS.values())', '["0.0.0.0/0"] + list(BR_NETS.values())')
    src = "def _site(D, R, N, BR_NETS, BRANCHES, PROV_NET, PROVIDERS, HQ_LAN, HQ_DC):\n" + t.replace("\n    ", "\n    ") + "\n    return dict(c1=c1, c2=c2, e1=e1, e2=e2, fl=fl, fw=fw, w1=w1, w2=w2)\n"
    ns: dict = {}
    exec(compile(src, f"routes_{tag}.py", "exec"), ns)
    lan = [f"{s['a']}.110.0/24", f"{s['a']}.199.0/24"]
    dc = [f"{s['a']}.101.0/24", f"{s['a']}.102.0/24", f"{s['a']}.103.0/24"]
    return ns["_site"](DEVICES, R, N, BR_NETS, BRANCHES, PROV_NET, PROVIDERS, lan, dc), lan, dc


def branches_routes():
    t = "\n".join(BR_SRC)
    old = 'hq = ["0.0.0.0/0", "10.10.0.0/16", "10.0.0.0/8"]'
    assert old in t
    t = t.replace(old, 'hq = ["0.0.0.0/0", "10.10.0.0/16", "10.30.0.0/16", "10.0.0.0/8"]')
    src = "def _br(D, R, N, BR_NETS, BRANCHES, PROV_NET, PROVIDERS, SLOT, PORTS, svi_if, abbr):\n" + t + "\n"
    ns: dict = {}
    exec(compile(src, "routes_branches.py", "exec"), ns)
    ns["_br"](DEVICES, R, N, BR_NETS, BRANCHES, PROV_NET, PROVIDERS, SLOT, PORTS, svi_if, abbr)


DCI = [  # (DC edge, DC port, DRC edge, DRC port, /30 network inside 10.255.0.0/24)
    ("HQ-DC-EDGE1", "Ethernet1/41", "DRC-EDGE1", "Ethernet1/41", 0),
    ("HQ-DC-EDGE2", "Ethernet1/42", "DRC-EDGE2", "Ethernet1/42", 4),
]


def build_dci():
    for a, pa, b, pb, off in DCI:
        connect(a, pa, b, pb, mode="routed", speed="100G", media="QSFP-100G-LR4")
        DEVICES[a].port(pa, ip=(f"10.255.0.{off + 1}", 30), ospf_area="0.0.0.0", desc=f"{b} {abbr(pb)} (DCI, routed /30)")
        DEVICES[b].port(pb, ip=(f"10.255.0.{off + 2}", 30), ospf_area="0.0.0.0", desc=f"{a} {abbr(pa)} (DCI, routed /30)")


def dci_routes(tag, parts, other_lan, other_dc):
    s = SITES[tag]
    a = s["a"]
    other = other_lan + other_dc
    first = tag == "dc"
    e1, e2, c1, c2, fl, fw, w1, w2 = (parts[k] for k in ("e1", "e2", "c1", "c2", "fl", "fw", "w1", "w2"))
    for e, (pa_, pb_, off) in ((e1, (DCI[0][1], DCI[0][3], DCI[0][4])), (e2, (DCI[1][1], DCI[1][3], DCI[1][4]))):
        port = pa_ if first else pb_
        peer_rid = f"{SITES['drc' if first else 'dc']['a']}.255.{3 if e is e1 else 4}"
        peer_ip = f"10.255.0.{off + (2 if first else 1)}"
        N(e, peer_rid, peer_ip, abbr(port))
        for p in other:
            R(e, "ospf", p, peer_ip, abbr(port), 30, "intra")
    for c, hops in ((c1, [(f"{a}.240.2", "Eth1/49"), (f"{a}.240.6", "Eth1/50")]), (c2, [(f"{a}.240.10", "Eth1/49"), (f"{a}.240.14", "Eth1/50")])):
        for p in other:
            for nh, intf in hops:
                R(c, "ospf", p, nh, intf, 40, "intra")
    for p in other:
        for nh in (f"{a}.251.2", f"{a}.251.3"):
            R(fl, "ospf", p, nh, "agg-core.901", 40, "")
        for nh in (f"{a}.253.2", f"{a}.253.3"):
            R(fw, "ospf", p, nh, "agg-edge.911", 40, "")
    for w, hops in ((w1, [(f"{a}.241.1", "Gi0/0/0"), (f"{a}.241.5", "Gi0/0/1")]), (w2, [(f"{a}.241.9", "Gi0/0/0"), (f"{a}.241.13", "Gi0/0/1")])):
        for p in other:
            for nh, intf in hops:
                R(w, "ospf", p, nh, intf, 40, "")


def fix_firewall_descriptions():
    for a, pa, b, pb in LINKS:
        for me, mp, other, op in ((a, pa, b, pb), (b, pb, a, pa)):
            d = DEVICES[me]
            if d.os == "forti" and mp in d.ifc:
                d.ifc[mp]["desc"] = f"to {other} - {abbr(op)}"
            elif d.os == "pan" and mp in d.ifc:
                d.ifc[mp]["desc"] = f"{other} - {abbr(op)}"


def build():
    for tag in ("dc", "drc"):
        load_plan(tag).build()
    plan_branch.build()
    build_dci()
    parts, lan_dc, dc_dc = site_routes("dc", "10.30.0.0/16")
    parts2, lan_drc, dc_drc = site_routes("drc", "10.10.0.0/16")
    dci_routes("dc", parts, lan_drc, dc_drc)
    dci_routes("drc", parts2, lan_dc, dc_dc)
    branches_routes()
    fix_firewall_descriptions()
    return DEVICES


def main(out):
    build()
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)
    for h, d in core.DEVICES.items():
        with open(os.path.join(out, f"{h}.txt"), "w", newline="\n", encoding="utf-8") as fh:
            fh.write(RENDER[d.os](d))
    return list(core.DEVICES)


if __name__ == "__main__":
    names = main(sys.argv[1] if len(sys.argv) > 1 else "out_dcdrc")
    print(len(names), "captures")
