"""Cisco NX-OS and IOS XE (Catalyst switches, ISR / ASR routers) renderers."""
from __future__ import annotations
from core import DEVICES, DOMAIN, abbr, mask, wild, colon, dash

CISCO = ("nxos", "ios", "iosrtr")


def _peer(d, rhost):
    return DEVICES.get(rhost)


def cdp_block(d, local, rhost, rport, native=1):
    r = DEVICES[rhost]
    if r.os == "nxos":
        did = f"{r.host}({r.serial})"
    else:
        did = f"{r.host}.{DOMAIN}"
    platform = r.model if r.os != "ios" or not r.model.startswith("Cisco") else r.model
    caps = {"nxos": "Router Switch IGMP Filtering Supports-STP-Dispute", "ios": "Switch IGMP", "iosrtr": "Router Switch IGMP"}[r.os]
    return (f"-------------------------\nDevice ID:{did}\nEntry address(es): \n  IP address: {r.mgmt}\n"
            f"Platform: cisco {platform},  Capabilities: {caps}\n"
            f"Interface: {local},  Port ID (outgoing port): {rport}\nHoldtime : 150 sec\n\nVersion :\nCisco {'Nexus Operating System' if r.os == 'nxos' else 'IOS XE Software'}\n\n"
            f"advertisement version: 2\nNative VLAN: {native}\nDuplex: full\nMgmt address(es): \n  IPv4 address: {r.mgmt}\n")


def cdp_end(d, ep):
    """CDP block of an access point or an IP phone attached to an IOS switch."""
    if ep["kind"] == "ap":
        plat, caps, extra = "AIR-AP2802I-E-K9", "Trans-Bridge Source-Route-Bridge IGMP", ""
        did, rp = ep["name"], "GigabitEthernet0"
    else:
        plat, caps, extra = "IP Phone 8851", "Host Phone Two-port Mac Relay", ""
        did, rp = "SEP" + ep["mac"].replace(".", "").upper(), "Port 1"
    return (f"-------------------------\nDevice ID:{did}\nEntry address(es): \n  IP address: {ep['ip']}\n"
            f"Platform: cisco {plat},  Capabilities: {caps}\nInterface: {ep['port']},  Port ID (outgoing port): {rp}\nHoldtime : 140 sec\n\n"
            f"Version :\nCisco endpoint\n\nadvertisement version: 2\nNative VLAN: {ep['vlan']}\nDuplex: full\nMgmt address(es): \n  IPv4 address: {ep['ip']}\n")


def lldp_ios(d, rows):
    """IOS XE ``show lldp neighbors detail``; rows: (local, system name, port id, port descr, chassis, caps, mgmt ip, descr)."""
    out = ["------------------------------------------------"]
    for local, name, pid, pdesc, chassis, caps, ip, descr in rows:
        out.append(f"Local Intf: {local}\nChassis id: {chassis}\nPort id: {pid}\nPort Description: {pdesc}\nSystem Name: {name}\n\nSystem Description: \n{descr}\n\n"
                   f"Time remaining: 108 seconds\nSystem Capabilities: {caps}\nEnabled Capabilities: {caps}\nManagement Addresses:\n    IP: {ip}\nAuto Negotiation - supported, enabled\n"
                   "Physical media capabilities:\n    1000baseT(FD)\nMedia Attachment Unit type: 30\nVlan ID: 1\n\n------------------------------------------------")
    out.append(f"\nTotal entries displayed: {len(rows)}")
    return "\n".join(out)


def lldp_nxos(d, rows):
    h = ("Capability codes:\n  (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device\n  (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other\n"
         "Device ID            Local Intf      Hold-time  Capability  Port ID  \n")
    return h + "".join(f"{n:<20} {l:<15} 120        {c:<11} {p}  \n" for l, n, p, c in rows) + f"Total entries displayed: {len(rows)}\n"


def _lldp_rows(d):
    rows = []
    for lport, rhost, rport in d.nbr:
        r = DEVICES[rhost]
        rows.append((lport, r, rport))
    return rows


def _caps(r):
    return {"nxos": "B,R", "ios": "B,R", "iosrtr": "R", "forti": "R", "pan": "R", "aoscx": "B,R", "vrp": "B,R"}.get(r.os, "B")


def show_version(d):
    if d.os == "nxos":
        return (f"{d.host}# show version\nCisco Nexus Operating System (NX-OS) Software\nSoftware\n  BIOS: version 05.47\n  NXOS: version 10.3(5) [Feature Release]\n"
                f"Hardware\n  cisco Nexus9000 {d.model} Chassis\n  Device name: {d.host}\n  bootflash:  115805 MB\nKernel uptime is 112 day(s), 4 hour(s), 31 minute(s), 9 second(s)\n")
    if d.os == "iosrtr":
        return (f"{d.host}#show version\nCisco IOS XE Software, Version 17.09.04a\nCisco IOS Software [Cupertino], {d.model} Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.9.4a\n"
                f"cisco {d.model} (1RU) processor with 1795979K/6147K bytes of memory.\nProcessor board ID {d.serial}\n{d.host} uptime is 16 weeks, 2 days, 4 hours, 12 minutes\n")
    return (f"{d.host}#show version\nCisco IOS XE Software, Version 17.09.04a\nCisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4a\n"
            f"cisco {d.model} (X86) processor with 1392510K/6147K bytes of memory.\nProcessor board ID {d.serial}\n{d.host} uptime is 16 weeks, 2 days, 4 hours, 12 minutes\n")


def show_inventory(d):
    p = "#" if d.os == "nxos" else "#"
    pre = f"{d.host}# " if d.os == "nxos" else f"{d.host}#"
    descr = f"Nexus9000 {d.model} Chassis" if d.os == "nxos" else d.model
    name = "Chassis" if d.os == "nxos" else ("Chassis" if d.os == "iosrtr" else "Switch 1")
    return f'{pre}show inventory\nNAME: "{name}",  DESCR: "{descr}"\nPID: {d.model:<18},  VID: V01 ,  SN: {d.serial}\n'


def _nx_if_block(d, name, p):
    lines = [f"interface {name}"]
    if p.get("desc"):
        lines.append(f"  description {p['desc']}")
    mode = p.get("mode")
    if mode == "trunk":
        lines += ["  switchport", "  switchport mode trunk"]
        if p.get("native"):
            lines.append(f"  switchport trunk native vlan {p['native']}")
        lines.append(f"  switchport trunk allowed vlan {p.get('vlans', '1')}")
    elif mode == "access":
        lines += ["  switchport", f"  switchport access vlan {p.get('access', 1)}", "  spanning-tree port type edge", "  no logical-link"][:3]
    elif mode == "routed":
        lines.append("  no switchport")
    if p.get("po") and not name.startswith("port-channel"):
        lines.append(f"  channel-group {p['po']} mode {p.get('lacp', 'active')}")
    if p.get("vpc"):
        lines.append(f"  vpc {p['vpc']}")
    if p.get("vpc_peer"):
        lines.append("  vpc peer-link")
    if p.get("ip"):
        ip, pl = p["ip"]
        lines.append(f"  ip address {ip}/{pl}")
        if p.get("ospf_area") is not None:
            lines.append(f"  ip ospf network {p.get('ospf_net', 'point-to-point')}")
            lines.append(f"  ip router ospf 1 area {p['ospf_area']}")
            if p.get("passive"):
                lines.append("  ip ospf passive-interface")
    lines.append("  shutdown" if p.get("shut") else "  no shutdown")
    return "\n".join(lines)


def nxos_running(d):
    out = [f"{d.host}# show running-config\n!Command: show running-config\nversion 10.3(5) Bios:version 05.47\nhostname {d.host}\nvdc {d.host} id 1\n"
           "feature ospf\nfeature interface-vlan\nfeature lacp\nfeature vpc\nfeature lldp\nfeature bfd\n" if d.os == "nxos" else ""]
    out = [out[0].replace("feature ospf\n", "feature ospf\n" if d.ospf else "")]
    out.append(f"ntp server 10.10.0.5 use-vrf management\nip domain-name {DOMAIN}\nclock timezone WIB 7 0\n")
    for vid, vname in sorted(d.vlans.items()):
        out.append(f"vlan {vid}\n  name {vname}")
    if d.vpc:
        v = d.vpc
        out.append(f"vpc domain {v['domain']}\n  peer-switch\n  role priority {v['priority']}\n  peer-keepalive destination {v['dst']} source {d.mgmt} vrf management\n  peer-gateway\n  auto-recovery\n"
                   + ("  layer3 peer-router\n" if d.role in ("core", "edge") else ""))
    if d.ospf:
        out.append(f"router ospf 1\n  router-id {d.ospf['rid']}\n  log-adjacency-changes"
                   + "".join(f"\n  {l}" for l in d.ospf.get("lines", [])))
    out.append(f"interface mgmt0\n  vrf member management\n  ip address {d.mgmt}/24")
    for n, (ip, pl) in d.lo.items():
        out.append(f"interface loopback{n}\n  ip address {ip}/{pl}\n  ip router ospf 1 area 0.0.0.0" if d.ospf else f"interface loopback{n}\n  ip address {ip}/{pl}")
    for num, p in d.po.items():
        out.append(_nx_if_block(d, f"port-channel{num}", p))
    for vid, s in d.svi.items():
        ip, pl = s["ip"]
        blk = f"interface Vlan{vid}\n  description {s.get('desc', vname_of(d, vid))}\n  no shutdown\n  ip address {ip}/{pl}"
        if s.get("ospf_area") is not None:
            blk += f"\n  ip ospf network {s.get('ospf_net', 'broadcast')}\n  ip router ospf 1 area {s['ospf_area']}"
        out.append(blk)
    for n, p in d.ifc.items():
        out.append(_nx_if_block(d, n, p))
    return "\n".join(out) + "\n"


def vname_of(d, vid):
    return d.vlans.get(vid, f"VLAN{vid}")


def nx_portchannel(d):
    rows = []
    for num, p in d.po.items():
        members = [n for n, q in d.ifc.items() if q.get("po") == num]
        rows.append(f"{num:<5} Po{num}(SU)    Eth      LACP      " + "    ".join(f"{abbr(m)}(P)" for m in members))
    return (f"{d.host}# show port-channel summary\nFlags:  D - Down        P - Up in port-channel (members)\n        I - Individual  H - Hot-standby (LACP only)\n        s - Suspended   r - Module-removed\n        S - Switched    R - Routed\n        U - Up (port-channel)\n        M - Not in use. Min-links not met\n"
            "--------------------------------------------------------------------------------\nGroup Port-       Type     Protocol  Member Ports\n      Channel\n--------------------------------------------------------------------------------\n" + "\n".join(rows) + "\n")


def nx_vpc(d):
    v = d.vpc
    ids = [(n, p) for n, p in d.po.items() if p.get("vpc")]
    peer = next(n for n, p in d.po.items() if p.get("vpc_peer"))
    vl = ",".join(str(x) for x in sorted(d.vlans)) or "1"
    rows = "".join(f"{p['vpc']:<5} Po{n:<12} up     success     success               {p.get('vlans', vl)}\n" for n, p in ids)
    return (f"{d.host}# show vpc\n\nLegend:\n                (*) - local vPC is down, forwarding via vPC peer-link\n\nvPC domain id                     : {v['domain']}\n"
            f"Peer status                       : peer adjacency formed ok\nvPC keep-alive status             : peer is alive\nConfiguration consistency status  : success\n"
            f"Per-vlan consistency status       : success\nType-2 consistency status         : success\nvPC role                          : {v['role']}\n"
            f"Number of vPCs configured         : {len(ids)}\nPeer Gateway                      : Enabled\nDual-active excluded VLANs        : -\nGraceful Consistency Check        : Enabled\n"
            f"Auto-recovery status              : Enabled, timer is off.(timeout = 240s)\nDelay-restore status              : Timer is off.(timeout = 30s)\n"
            f"Delay-restore SVI status          : Timer is off.(timeout = 10s)\n\nvPC Peer-link status\n---------------------------------------------------------------------\n"
            f"id    Port   Status Active vlans\n--    ----   ------ -------------------------------------------------\n1     Po{peer:<5} up     {vl}\n\nvPC status\n"
            "----------------------------------------------------------------------------\nId    Port          Status Consistency Reason                Active vlans\n--    ------------  ------ ----------- ------                ------------\n" + rows)


def nx_cdp(d):
    blocks = [cdp_block(d, abbr(l) if False else l, r, rp) for l, r, rp in d.nbr if DEVICES[r].os in CISCO]
    return f"{d.host}# show cdp neighbors detail\n" + "".join(blocks)


def nx_lldp(d):
    out = [f"{d.host}# show lldp neighbors detail", "Capability codes:\n  (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device\n  (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other\n"
           "Device ID            Local Intf      Hold-time  Capability  Port ID\n"]
    def entry(local, chassis, pid, pdesc, name, descr, caps, ip):
        return (f"Chassis id: {chassis}\nPort id: {pid}\nLocal Port id: {local}\nPort Description: {pdesc}\nSystem Name: {name}\nSystem Description: {descr}\n"
                f"Time remaining: 112 seconds\nSystem Capabilities: {caps}\nEnabled Capabilities: {caps}\nManagement Address: {ip}\nVlan ID: 1\n")
    for l, r, rp in d.nbr:
        rem = DEVICES[r]
        descr = {"nxos": "Cisco Nexus Operating System (NX-OS) Software 10.3(5)", "forti": f"{rem.model} v7.2.8,build1639,240123 (GA.M)", "pan": f"Palo Alto Networks {rem.model} firewall",
                 "iosrtr": "Cisco IOS XE Software, Version 17.09.04a", "ios": "Cisco IOS XE Software, Version 17.09.04a"}.get(rem.os, rem.model)
        out.append(entry(abbr(l), rem.chassis, rp, d.ifc.get(l, {}).get("desc", ""), r, descr, _caps(rem).replace(",", ", "), rem.mgmt))
    for ep in d.attached:
        if ep["kind"] in ("pc", "server"):
            out.append(entry(abbr(ep["port"]), ep["mac"], ep["mac"], "", ep["name"], "Demo server" if ep["kind"] == "server" else "Demo workstation", "S", ep["ip"]))
    return "\n".join(out) + "\n"


def nx_status(d):
    rows = []
    for n, p in d.ifc.items():
        if not p.get("peer") and p.get("mode") != "access" and not p.get("ip"):
            continue
        up = "connected" if not p.get("shut") else "disabled"
        vl = {"trunk": "trunk", "routed": "routed", "access": str(p.get("access", 1))}.get(p.get("mode"), "1")
        if p.get("po"):
            vl = "trunk"
        rows.append(f"{abbr(n):<13} {p.get('desc', '')[:17]:<18} {up:<9} {vl:<9} full    {p.get('speed', '10G'):<7} {p.get('media', '10Gbase-SR')}")
    return (f"{d.host}# show interface status\n" + "-" * 80 + "\nPort          Name               Status    Vlan      Duplex  Speed   Type\n" + "-" * 80 + "\n" + "\n".join(rows) + "\n")


def nx_mac(d):
    rows = "".join(f"*{v:>5}     {m}   dynamic  0         F      F    {abbr(p)}\n" for v, m, p in d.macs)
    return (f"{d.host}# show mac address-table\nLegend:\n        * - primary entry, G - Gateway MAC, (R) - Routed MAC, O - Overlay MAC\n        age - seconds since last seen,+ - primary entry using vPC Peer-Link\n"
            "   VLAN     MAC Address      Type      age     Secure NTFY Ports\n---------+-----------------+--------+---------+------+----+------------------\n" + rows)


def nx_arp(d):
    rows = "".join(f"{ip:<15} 00:01:10  {m}  {i}\n" for ip, m, i in d.arp)
    return f"{d.host}# show ip arp\nFlags: * - Adjacencies learnt on non-active FHRP router\n\nAddress         Age       MAC Address     Interface       Flags\n{rows}"


def nx_routes(d):
    groups: dict[str, list[dict]] = {}
    for r in d.routes:
        groups.setdefault(r["prefix"], []).append(r)
    out = ['IP Route Table for VRF "default"\n\'*\' denotes best ucast next-hop\n\'**\' denotes best mcast next-hop\n\'[x/y]\' denotes [preference/metric]\n']
    for prefix, rs in groups.items():
        att = ", attached" if rs[0]["proto"] in ("direct", "local") else ""
        out.append(f"{prefix}, ubest/mbest: {len(rs)}/0{att}")
        for r in rs:
            kind = {"ospf": f"ospf-1, {r.get('type', 'intra')}", "direct": "direct", "static": "static", "bgp": f"bgp-65010, {r.get('type', 'external')}"}[r["proto"]]
            pref = {"ospf": 110, "direct": 0, "static": 1, "bgp": 20}[r["proto"]]
            out.append(f"    *via {r['nh']}, {r['intf'] + ', ' if r.get('intf') else ''}[{pref}/{r.get('metric', 0)}], 5d02h, {kind}")
    return f"{d.host}# show ip route\n" + "\n".join(out) + "\n"


def nx_ospf(d):
    rows = "".join(f" {rid:<15} {1:>3} {'FULL/ -' if True else '':<16} 5d02h    {addr:<15} {intf}\n" for rid, addr, intf in d.ospf_nbr)
    return f"{d.host}# show ip ospf neighbors\n OSPF Process ID 1 VRF default\n Total number of neighbors: {len(d.ospf_nbr)}\n Neighbor ID     Pri State            Up Time  Address         Interface\n{rows}"


def nx_ipbrief(d):
    rows = []
    for n, (ip, pl) in d.lo.items():
        rows.append(f"Lo{n:<12} {ip:<15} protocol-up/link-up/admin-up")
    for vid, s in d.svi.items():
        rows.append(f"Vlan{vid:<9} {s['ip'][0]:<15} protocol-up/link-up/admin-up")
    for n, p in d.ifc.items():
        if p.get("ip"):
            rows.append(f"{abbr(n):<13} {p['ip'][0]:<15} protocol-up/link-up/admin-up")
    return f'{d.host}# show ip interface brief\nIP Interface Status for VRF "default"(1)\nInterface            IP Address      Interface Status\n' + "\n".join(rows) + "\n"


def ios_ipbrief(d):
    rows = []
    for n, (ip, pl) in d.lo.items():
        rows.append(f"{'Loopback' + str(n):<26}{ip:<16}YES manual up                    up")
    for vid, s in d.svi.items():
        rows.append(f"{'Vlan' + str(vid):<26}{s['ip'][0]:<16}YES manual up                    up")
    for n, p in d.ifc.items():
        if p.get("ip"):
            rows.append(f"{n:<26}{p['ip'][0]:<16}YES manual up                    up")
    return f"{d.host}#show ip interface brief\nInterface                  IP-Address      OK? Method Status                Protocol\n" + "\n".join(rows) + "\n"


def render_nxos(d):
    parts = [show_version(d), show_inventory(d), nxos_running(d)]
    if d.po:
        parts.append(nx_portchannel(d))
    if d.vpc:
        parts.append(nx_vpc(d))
    parts += [nx_cdp(d), nx_lldp(d), nx_status(d), nx_ipbrief(d)]
    if d.macs:
        parts.append(nx_mac(d))
    if d.arp:
        parts.append(nx_arp(d))
    if d.routes:
        parts.append(nx_routes(d))
    if d.ospf_nbr:
        parts.append(nx_ospf(d))
    return "\n".join(parts) + f"\n{d.host}# \n"


# ------------------------------------------------------------------------------------------------ IOS XE
def _ios_if_block(d, name, p):
    lines = [f"interface {name}"]
    if p.get("desc"):
        lines.append(f" description {p['desc']}")
    mode = p.get("mode")
    if mode == "trunk":
        lines += [" switchport mode trunk"]
        if p.get("native"):
            lines.append(f" switchport trunk native vlan {p['native']}")
        lines.append(f" switchport trunk allowed vlan {p.get('vlans', '1')}")
    elif mode == "access":
        lines += [f" switchport access vlan {p.get('access', 1)}", " switchport mode access"]
        if p.get("voice"):
            lines.append(f" switchport voice vlan {p['voice']}")
        lines += [" spanning-tree portfast"]
    elif mode == "routed" and d.os != "iosrtr":
        lines.append(" no switchport")
    if p.get("po") and not name.startswith("Port-channel"):
        lines.append(f" channel-group {p['po']} mode {p.get('lacp', 'active')}")
    if p.get("ip"):
        ip, pl = p["ip"]
        lines.append(f" ip address {ip} {mask(pl)}")
        if p.get("ospf_area") is not None:
            lines += [" ip ospf network point-to-point", f" ip ospf 1 area {p['ospf_area']}"]
    lines.append(" shutdown" if p.get("shut") else "")
    return "\n".join(l for l in lines if l) + "\n!"


def ios_running(d):
    out = [f"{d.host}#show running-config\nBuilding configuration...\n\nCurrent configuration : 9812 bytes\n!\nversion 17.9\nservice timestamps log datetime msec\n!\nhostname {d.host}\n!\n"
           "no aaa new-model\nip routing\n" if d.os != "iosrtr" or True else ""]
    out.append(f"ip domain name {DOMAIN}\nlldp run\ncdp run\n!")
    for vid, vname in sorted(d.vlans.items()):
        out.append(f"vlan {vid}\n name {vname}\n!")
    for pool in d.extra.get("dhcp", []):
        out.append(f"ip dhcp excluded-address {pool['gw']} {pool['excl']}\nip dhcp pool {pool['name']}\n network {pool['net']} {mask(pool['prefix'])}\n default-router {pool['gw']}\n dns-server {pool['dns']}\n"
                   + (f" option 150 ip {pool['tftp']}\n" if pool.get("tftp") else "") + " lease 0 8\n!")
    for n, (ip, pl) in d.lo.items():
        out.append(f"interface Loopback{n}\n ip address {ip} {mask(pl)}\n" + (" ip ospf 1 area 0\n" if d.ospf else "") + "!")
    for num, p in d.po.items():
        out.append(_ios_if_block(d, f"Port-channel{num}", p))
    for vid, s in d.svi.items():
        ip, pl = s["ip"]
        blk = f"interface Vlan{vid}\n description {s.get('desc', vname_of(d, vid))}\n ip address {ip} {mask(pl)}\n"
        if s.get("ospf_area") is not None:
            blk += f" ip ospf 1 area {s['ospf_area']}\n"
        out.append(blk + "!")
    for n, p in d.ifc.items():
        out.append(_ios_if_block(d, n, p))
    if d.ospf:
        o = d.ospf
        out.append(f"router ospf 1\n router-id {o['rid']}\n log-adjacency-changes\n" + "".join(f" {l}\n" for l in o.get("lines", [])) + "!")
    if d.bgp:
        b = d.bgp
        txt = f"router bgp {b['asn']}\n bgp router-id {b['rid']}\n bgp log-neighbor-changes\n"
        for ip, asn, desc, *_ in b["neighbors"]:
            txt += f" neighbor {ip} remote-as {asn}\n neighbor {ip} description {desc}\n"
        txt += " !\n address-family ipv4\n"
        for n_, pl in b.get("networks", []):
            txt += f"  network {n_} mask {mask(pl)}\n"
        for ip, *_ in b["neighbors"]:
            txt += f"  neighbor {ip} activate\n"
        for line in b.get("af_lines", []):
            txt += f"  {line}\n"
        out.append(txt + " exit-address-family\n!")
    for s in d.extra.get("static", []):
        out.append(f"ip route {s}")
    out.append("line vty 0 15\n transport input ssh\n!\nend")
    return "\n".join(out) + "\n"


def ios_etherchannel(d):
    rows = []
    for num, p in d.po.items():
        members = [n for n, q in d.ifc.items() if q.get("po") == num]
        rows.append(f"{num:<7}Po{num}(SU)         LACP      " + "  ".join(f"{abbr(m)}(P)" for m in members))
    return (f"{d.host}#show etherchannel summary\nFlags:  D - down        P - bundled in port-channel\n        I - stand-alone s - suspended\n        U - in use      N - not in use, no aggregation\n\n"
            f"Number of channel-groups in use: {len(rows)}\nNumber of aggregators:           {len(rows)}\n\nGroup  Port-channel  Protocol    Ports\n------+-------------+-----------+-----------------------------------------------\n" + "\n".join(rows) + "\n")


def ios_cdp(d):
    out = []
    for l, r, rp in d.nbr:
        if DEVICES[r].os in CISCO:
            out.append(cdp_block(d, l, r, rp, native=d.ifc.get(l, {}).get("native", 1)))
    for ep in d.attached:
        if ep["kind"] in ("ap", "phone"):
            out.append(cdp_end(d, ep))
    return f"{d.host}#show cdp neighbors detail\n" + "".join(out)


def ios_lldp(d):
    rows = []
    for l, r, rp in d.nbr:
        rem = DEVICES[r]
        rows.append((abbr(l), r, abbr(rp) if rem.os in CISCO else rp, rp, colon_c(rem.chassis), _caps(rem), rem.mgmt, f"{rem.model} {rem.role}".strip()))
    for ep in d.attached:
        if ep["kind"] in ("ap", "phone"):
            rows.append((abbr(ep["port"]), ep["name"], "Gi0" if ep["kind"] == "ap" else "1", "", ep["mac"], "W" if ep["kind"] == "ap" else "T", ep["ip"],
                         "Cisco access point" if ep["kind"] == "ap" else "Cisco IP Phone 8851"))
        elif ep["kind"] in ("pc", "server"):
            rows.append((abbr(ep["port"]), ep["name"], ep["mac"], "", ep["mac"], "O", ep["ip"], "Demo workstation" if ep["kind"] == "pc" else "Demo server"))
    return f"{d.host}#show lldp neighbors detail\n" + lldp_ios(d, rows)


def colon_c(m):
    return m


def ios_status(d):
    rows = []
    for n, p in d.ifc.items():
        if not p.get("peer") and p.get("mode") != "access":
            continue
        vl = {"trunk": "trunk", "routed": "routed", "access": str(p.get("access", 1))}.get(p.get("mode"), "1")
        spd = p.get("speed", "a-1000")
        rows.append(f"{abbr(n):<9} {p.get('desc', '')[:18]:<18} connected    {vl:<10} a-full  {spd:<6} 10/100/1000BaseTX")
    return f"{d.host}#show interfaces status\n\nPort      Name               Status       Vlan       Duplex  Speed Type\n" + "\n".join(rows) + "\n"


def ios_mac(d):
    rows = "".join(f"{v:>4}    {m}    DYNAMIC     {abbr(p)}\n" for v, m, p in d.macs)
    return f"{d.host}#show mac address-table\n          Mac Address Table\n-------------------------------------------\n\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n{rows}Total Mac Addresses for this criterion: {len(d.macs)}\n"


def ios_arp(d):
    rows = "".join(f"Internet  {ip:<15} {3:>4}   {m}  ARPA   {i}\n" for ip, m, i in d.arp)
    return f"{d.host}#show ip arp\nProtocol  Address          Age (min)  Hardware Addr   Type   Interface\n{rows}"


def ios_routes(d):
    codes = {"ospf": "O", "bgp": "B", "static": "S", "direct": "C"}
    out = [f"{d.host}#show ip route\nCodes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP\n       D - EIGRP, O - OSPF, IA - OSPF inter area, E1/E2 - OSPF external type 1/2\n"]
    dflt = next((r for r in d.routes if r["prefix"] == "0.0.0.0/0"), None)
    out.append(f"Gateway of last resort is {dflt['nh']} to network 0.0.0.0\n" if dflt else "Gateway of last resort is not set\n")
    for r in d.routes:
        c = codes[r["proto"]]
        star = "*" if r["prefix"] == "0.0.0.0/0" else " "
        t = {"E2": "E2", "IA": "IA"}.get(r.get("type", ""), "")
        pref = {"ospf": 110, "bgp": 20, "static": 1}[r["proto"]]
        tail = f", {r['intf']}" if r.get("intf") else ""
        out.append(f"{(c + star + t):<9}{r['prefix']} [{pref}/{r.get('metric', 0)}] via {r['nh']}, 3d04h{tail}")
    return "\n".join(out) + "\n"


def ios_ospf(d):
    rows = "".join(f"{rid:<16}{1:>3}   FULL/{'DR' if i % 2 else 'BDR'}         00:00:33    {addr:<15} {intf}\n" for i, (rid, addr, intf) in enumerate(d.ospf_nbr))
    return f"{d.host}#show ip ospf neighbor\n\nNeighbor ID     Pri   State           Dead Time   Address         Interface\n{rows}"


def ios_bgp(d):
    b = d.bgp
    rows = "".join(f"{n['ip']:<16}4 {n['asn']:>10}    1432    1429       {17:>3}    0    0 3d04h          {n['pfx']:>3}\n" for n in d.bgp_nbr)
    return (f"{d.host}#show ip bgp summary\nBGP router identifier {b['rid']}, local AS number {b['asn']}\nBGP table version is 17, main routing table version 17\n"
            f"{len(d.bgp_nbr)} network entries using {len(d.bgp_nbr) * 248} bytes of memory\n\nNeighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n{rows}")


def render_ios(d):
    parts = [show_version(d), show_inventory(d), ios_running(d), ios_etherchannel(d)]
    parts += [ios_cdp(d), ios_lldp(d), ios_status(d), ios_ipbrief(d)]
    if d.macs:
        parts.append(ios_mac(d))
    if d.arp:
        parts.append(ios_arp(d))
    if d.routes:
        parts.append(ios_routes(d))
    if d.ospf_nbr:
        parts.append(ios_ospf(d))
    if d.bgp_nbr:
        parts.append(ios_bgp(d))
    return "\n".join(parts) + f"\n{d.host}#\n"
