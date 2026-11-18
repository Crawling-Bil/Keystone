"""Aruba AOS-CX and Huawei VRP switch renderers (formats follow real, masked captures of a 6200F and an S5735)."""
from __future__ import annotations
from core import DEVICES, DOMAIN, mask, wild, colon, dash, abbr

SPEED_BY_NAME = lambda n: 10000 if n.startswith(("XGigabit", "10GE")) else 1000


# ------------------------------------------------------------------------------------------------ Aruba AOS-CX
def cx_version(d):
    return (f"{d.host}# show version\n-----------------------------------------------------------------------------\nAOS-CX\n(c) Copyright 2017-2025 Hewlett Packard Enterprise Development LP\n"
            "-----------------------------------------------------------------------------\nVersion      : ML.10.13.1000\nBuild Date   : 2024-09-12 20:56:14 UTC\nBuild ID     : AOS-CX:ML.10.13.1000:35060c169154:202409122045\n"
            "Build SHA    : 35060c1691541672955d13b3006613274c87d269\nHot Patches  :\nActive Image : primary\n\nService OS Version : ML.01.18.0001\nBIOS Version       : ML.01.0002\n")


def cx_system(d):
    return (f"{d.host}# show system\nHostname               : {d.host}\nProduct Name           : JL724B 6200F 24G 4SFP+ Switch\nChassis Serial Nbr     : {d.serial}\n"
            f"Base MAC Address       : {colon(d.chassis)}\nAOS-CX Version         : ML.10.13.1000\nTime Zone              : Asia/Jakarta\n")


def cx_inventory(d):
    return (f"{d.host}# show system inventory\n\nType                 Location        Product          Description                                        Serial           Hardware\n"
            "                                     Number                                                              Number           Version\n"
            "-------------------- --------------- ---------------- -------------------------------------------------- ---------------- -----------\n"
            f"Chassis              1               JL724B           6200F 24G 4SFP+ Switch                             {d.serial:<16} 2\n")


def cx_vlan(d):
    rows = []
    for vid, nm in sorted(d.vlans.items()):
        ports = ",".join(n for n, p in d.ifc.items() if p.get("mode") in ("trunk", "access") and (p.get("access") == vid or vid in _vlist(p.get("vlans", ""), p.get("native"))))
        rows.append(f"{vid:<5} {nm:<33} up      ok                      static      {ports}")
    return (f"{d.host}# show vlan\n\n" + "-" * 114 + "\nVLAN  Name                              Status  Reason                  Type        Interfaces\n" + "-" * 114 + "\n" + "\n".join(rows) + "\n")


def _vlist(spec, native=None):
    out = set()
    for part in str(spec).split(","):
        if "-" in part:
            a, b = part.split("-")
            out |= set(range(int(a), int(b) + 1))
        elif part.strip().isdigit():
            out.add(int(part))
    if native:
        out.add(int(native))
    return out


def cx_interface(d):
    out = [f"{d.host}# show interface"]
    for n, p in d.ifc.items():
        if not p.get("peer") and p.get("mode") != "access":
            continue
        out.append(f"Interface {n} is up\n Admin state is up\n Link state: up for 23 weeks (since Tue Jun 02 08:00:00 WIB 2026)\n Link transitions: 1\n Description: {p.get('desc', '')}\n Persona:\n"
                   f" Hardware: Ethernet, MAC Address: {colon(d.chassis)}\n MTU 1500\n Type 1GbT\n Full-duplex\n qos trust none\n Speed {1000 if not p.get('speed_m') else p['speed_m']} Mb/s\n Auto-negotiation is on\n"
                   " Flow-control: off\n Error-control: off\n MDI mode: MDIX\n"
                   + (f" VLAN Mode: native-untagged\n Native VLAN: {p.get('native', 1)}\n Allowed VLAN List: {p.get('vlans', '1')}\n" if p.get("mode") == "trunk" else
                      (f" VLAN Mode: access\n Access VLAN: {p.get('access', 1)}\n" if p.get("mode") == "access" else ""))
                   + " Rate collection interval: 300 seconds\n")
    return "\n".join(out)


def cx_ipbrief(d):
    rows = []
    for vid, s in d.svi.items():
        rows.append(f"vlan{vid:<12} {s['ip'][0]}/{s['ip'][1]:<12} up/up")
    for n, p in d.ifc.items():
        if p.get("ip"):
            rows.append(f"{n:<16} {p['ip'][0]}/{p['ip'][1]:<12} up/up")
    return f"{d.host}# show ip interface brief\n\nInterface         IP Address             Interface Status\n                                           link/admin\n" + "\n".join(rows) + "\n"


def cx_lldp(d):
    out = [f"{d.host}# show lldp neighbor-info detail\n"]
    total = 0
    def block(port, chassis, pid, pdesc, name, descr, caps, ip):
        return (f"Port                           : {port}\nNeighbor Entries               : 1\nNeighbor Entries Deleted       : 0\nNeighbor Entries Dropped       : 0\nNeighbor Entries Aged-Out      : 0\n"
                f"Neighbor Chassis-Name          : {name}\nNeighbor Chassis-Description   : {descr}\nNeighbor Chassis-ID            : {chassis}\nNeighbor Management-Address    : {ip}\n"
                f"Chassis Capabilities Available : Bridge, Router, WLAN, Telephone\nChassis Capabilities Enabled   : {caps}\nNeighbor Port-ID               : {pid}\nNeighbor Port-Desc             : {pdesc}\n"
                f"Neighbor Port VLAN ID          : 1\nTTL                            : 120\nNeighbor System-Name           : {name}\nNeighbor System-Description    : {descr}\n"
                "-------------------------------------------------------------------------------\n")
    for l, r, rp in d.nbr:
        rem = DEVICES[r]
        total += 1
        out.append(block(l, colon(rem.chassis), abbr(rp) if rem.os in ("nxos", "ios", "iosrtr") else rp, "", r, f"{rem.model}", {"iosrtr": "Router", "ios": "Bridge, Router", "aoscx": "Bridge, Router", "vrp": "Bridge, Router"}.get(rem.os, "Bridge"), rem.mgmt))
    for ep in d.attached:
        if ep["kind"] in ("ap", "phone"):
            total += 1
            out.append(block(ep["port"], colon(ep["mac"]), "1" if ep["kind"] == "phone" else "Gi0", "", ep["name"], "Cisco endpoint", "WLAN" if ep["kind"] == "ap" else "Telephone", ep["ip"]))
    return out[0] + f"LLDP Neighbor Information\n=========================\n\nTotal Neighbor Entries          : {total}\n\n" + "".join(out[1:])


def cx_mac(d):
    rows = "".join(f"{colon(m):<20} {v:<8} dynamic                   {p}\n" for v, m, p in d.macs)
    return (f"{d.host}# show mac-address-table\nMAC age-time            : 300 seconds\nNumber of MAC addresses : {len(d.macs)}\n\nMAC Address          VLAN     Type                      Port\n"
            + "-" * 62 + "\n" + rows)


def cx_arp(d):
    rows = "".join(f"{ip:<16} {colon(m):<18} vlan{i.replace('Vlan', ''):<8} {'-':<52} reachable\n" for ip, m, i in d.arp)
    return f"{d.host}# show arp\n\nIPv4 Address     MAC                Port         Physical Port                                      State\n" + "-" * 109 + f"\n{rows}\nTotal Number Of ARP Entries Listed: {len(d.arp)}.\n" + "-" * 109 + "\n"


def cx_routes(d):
    rows = []
    for r in d.routes:
        code = {"ospf": "O", "static": "S", "bgp": "B"}[r["proto"]]
        t = "/E2" if r.get("type") == "E2" else ""
        rows.append(f"{r['prefix']:<19} {r['nh']:<40} {r.get('intf', ''):<13} {'-':<17} {code + t:<9} [{110 if r['proto'] == 'ospf' else 1}/{r.get('metric', 0)}]   01d:02h:15m")
    for vid, s in d.svi.items():
        ip, pl = s["ip"]
        rows.append(f"{_netaddr(ip, pl):<19} {'-':<40} vlan{vid:<9} {'-':<17} {'C':<9} [0/0]        -")
    return (f"{d.host}# show ip route\n\nDisplaying ipv4 routes selected for forwarding\n\nOrigin Codes: C - connected, S - static, L - local\n              R - RIP, B - BGP, O - OSPF, D - DHCP\n"
            "Type Codes:   E - External BGP, I - Internal BGP, V - VPN, EV - EVPN\n              IA - OSPF internal area, E1 - OSPF external type 1\n              E2 - OSPF external type 2\n\nVRF: default\n\n"
            "Prefix              Nexthop                                  Interface     VRF(egress)       Origin/   Distance/    Age\n                                                                                             Type      Metric\n"
            + "-" * 104 + "\n" + "\n".join(rows) + f"\n\nTotal Route Count : {len(rows)}\n")


def _netaddr(ip, pl):
    import ipaddress
    return str(ipaddress.ip_interface(f"{ip}/{pl}").network)


def cx_ospf(d):
    rows = "".join(f"{rid:<16} {'n/a':<9} {'FULL':<17} {addr:<17} {intf}\n" for rid, addr, intf in d.ospf_nbr)
    return (f"{d.host}# show ip ospf neighbors\n\nVRF : default                                Process : 1\n" + "=" * 58 + f"\n\nTotal Number of Neighbors : {len(d.ospf_nbr)}\n\n"
            "Neighbor ID      Priority  State             Nbr Address       Interface\n" + "-" * 74 + "\n" + rows)


def cx_running(d):
    out = [f"{d.host}# show running-config\n!Version AOS-CX ML.10.13.1000\nhostname {d.host}\nuser admin group administrator\n"
           f"ntp server 10.10.0.5\nntp enable\nclock timezone asia/jakarta\nssh server vrf default\n"]
    out.append("vlan 1")
    for vid, nm in sorted(d.vlans.items()):
        out.append(f"vlan {vid}\n    name {nm}")
    out.append("spanning-tree\nspanning-tree mode rpvst")
    for n, p in d.ifc.items():
        blk = [f"interface {n}", "    no shutdown"]
        if p.get("desc"):
            blk.append(f"    description {p['desc']}")
        if p.get("ip"):
            blk += [f"    ip address {p['ip'][0]}/{p['ip'][1]}"]
            if p.get("ospf_area") is not None:
                blk += ["    ip ospf 1 area 0.0.0.0", "    ip ospf network point-to-point", "    no ip ospf passive"]
        elif p.get("mode") == "trunk":
            blk += ["    no routing", f"    vlan trunk native {p.get('native', 1)}", f"    vlan trunk allowed {p.get('vlans', '1')}"]
        elif p.get("mode") == "access":
            blk += ["    no routing", f"    vlan access {p.get('access', 1)}", "    spanning-tree port-type admin-edge"]
        out.append("\n".join(blk))
    for vid, s in d.svi.items():
        blk = f"interface vlan {vid}\n    description {s.get('desc', d.vlans.get(vid, ''))}\n    ip address {s['ip'][0]}/{s['ip'][1]}"
        if s.get("ospf_area") is not None:
            blk += "\n    ip ospf 1 area 0.0.0.0"
        out.append(blk)
    for pool in d.extra.get("dhcp", []):
        pass
    if d.extra.get("dhcp"):
        txt = "dhcp-server vrf default"
        for pool in d.extra["dhcp"]:
            txt += (f"\n    pool {pool['name']}\n        range {pool['start']} end {pool['end']} prefix-len {pool['prefix']}\n        default-router {pool['gw']}\n        dns-server {pool['dns']}\n        lease 00:08\n"
                    + (f"        option 150 ip {pool['tftp']}\n" if pool.get("tftp") else ""))
        out.append(txt + "    enable")
    if d.ospf:
        o = d.ospf
        out.append(f"router ospf 1\n    router-id {o['rid']}\n    passive-interface default\n    area 0.0.0.0")
    for dst in d.extra.get("static", []):
        out.append(f"ip route {dst}")
    out.append("https-server vrf default")
    return "\n".join(out) + "\n"


def render_aoscx(d):
    parts = [cx_version(d), cx_system(d), cx_inventory(d), cx_running(d), cx_vlan(d), cx_interface(d), cx_ipbrief(d), f"{d.host}# show lacp aggregates\n", cx_lldp(d)]
    if d.macs:
        parts.append(cx_mac(d))
    if d.arp:
        parts.append(cx_arp(d))
    if d.routes:
        parts.append(cx_routes(d))
    if d.ospf_nbr:
        parts.append(cx_ospf(d))
    return "\n".join(parts) + f"\n{d.host}# \n"


# ------------------------------------------------------------------------------------------------ Huawei VRP
def vrp_version(d):
    return (f"<{d.host}>display version\nHuawei Versatile Routing Platform Software\nVRP (R) software, Version 5.170 ({d.model} V200R022C00SPC500)\nCopyright (C) 2000-2023 HUAWEI TECH CO., LTD\n"
            f"HUAWEI {d.model} Routing Switch uptime is 120 days, 5 hours, 42 minutes\n\n<{d.host}>display esn\nESN of master board: {d.serial}\n\n"
            f"<{d.host}>display device\n{d.model}'s Device status:\nSlot Sub  Type                   Online    Power    Register     Status   Role\n"
            "-------------------------------------------------------------------------------\n" f"0    -    {d.model:<22} Present   PowerOn  Registered   Normal   Master\n")


def vrp_ipbrief(d):
    rows = []
    for vid, s in d.svi.items():
        rows.append(f"{'Vlanif' + str(vid):<30}{s['ip'][0] + '/' + str(s['ip'][1]):<20}up        up")
    for n, p in d.ifc.items():
        if p.get("ip"):
            rows.append(f"{n:<30}{p['ip'][0] + '/' + str(p['ip'][1]):<20}up        up")
    return (f"<{d.host}>display ip interface brief\n*down: administratively down\n^down: standby\n(l): loopback\n(s): spoofing\n(d): Dampening Suppressed\n"
            f"Interface                         IP Address/Mask      Physical   Protocol\n" + "\n".join(rows) + "\n")


def vrp_lldp(d):
    brief = ["Local Interface         Exptime(s) Neighbor Interface      Neighbor Device"]
    detail = []
    rows = []
    for l, r, rp in d.nbr:
        rem = DEVICES[r]
        caps = {"iosrtr": "router", "forti": "router", "pan": "router"}.get(rem.os, "bridge router")
        rows.append((l, rem.chassis, abbr(rp) if rem.os in ("nxos", "ios", "iosrtr") else rp, "", r, f"{rem.model}", rem.mgmt, caps))
    for ep in d.attached:
        if ep["kind"] in ("ap", "phone"):
            rows.append((ep["port"], ep["mac"], "Gi0" if ep["kind"] == "ap" else "1", "", ep["name"], "Cisco endpoint", ep["ip"], "wlan-access-point" if ep["kind"] == "ap" else "telephone"))
    for l, chassis, pid, pdesc, name, descr, ip, caps in rows:
        brief.append(f"{l:<23} 105        {pid:<22} {name}")
        detail.append(f"{l} has 1 neighbor(s):\n\nNeighbor index                     :1\nChassis type                       :MAC Address\nChassis ID                         :{dash(chassis)}\n"
                      f"Port ID subtype                    :Interface Name\nPort ID                            :{pid}\nPort description                   :{pdesc}\nSystem name                        :{name}\n"
                      f"System description                 :{descr}\nSystem capabilities supported      :{caps}\nSystem capabilities enabled        :{caps}\nManagement address type            :ipv4\nManagement address value           :{ip}\nPort VLAN ID(PVID)                 :1\n")
    return (f"<{d.host}>display lldp neighbor brief\n" + "\n".join(brief) + "\n\n" + f"<{d.host}>display lldp neighbor\n" + "\n".join(detail))


def vrp_mac(d):
    rows = "".join(f"{dash(m)} {v}/-/-         {p:<19} dynamic             {600 + i}\n" for i, (v, m, p) in enumerate(d.macs))
    return (f"<{d.host}>display mac-address\nFlags: * - Backup\n       # - forwarding logical interface, operations cannot be performed based\n           on the interface.\nBD   : bridge-domain   Age : dynamic MAC learned time in seconds\n"
            + "-" * 79 + "\nMAC Address    VLAN/VSI/BD   Learned-From        Type                Age\n" + "-" * 79 + "\n" + rows + "-" * 79 + f"\nTotal items displayed = {len(d.macs)}\n")


def vrp_arp(d):
    rows = "".join(f"{ip:<15} {dash(m):<14} {9:>4}   D/{i.replace('Vlanif', ''):<12} {i}\n" for ip, m, i in d.arp)
    return (f"<{d.host}>display arp\nARP Entry Types: D - Dynamic, S - Static, I - Interface\nEXP: Expire-time\n\nIP ADDRESS      MAC ADDRESS    EXP(M) TYPE/VLAN       INTERFACE        VPN-INSTANCE\n"
            + "-" * 88 + f"\n{rows}" + "-" * 88 + f"\nTotal:{len(d.arp)}       Dynamic:{len(d.arp)}       Static:0    Interface:0\n")


def vrp_routes(d):
    rows = []
    for r in d.routes:
        proto = {"ospf": "O_ASE" if r.get("type") == "E2" else "OSPF", "static": "Static", "bgp": "BGP"}[r["proto"]]
        pre = {"ospf": 150 if r.get("type") == "E2" else 10, "static": 60, "bgp": 255}[r["proto"]]
        rows.append(f"{r['prefix']:>21}   {proto:<7} {pre:<4} {r.get('metric', 1):<11} D   {r['nh']:<15} {r['intf']}")
    return (f"<{d.host}>display ip routing-table\nRoute Flags: R - relay, D - download to fib\n" + "-" * 78 + f"\nRouting Tables: Public\n         Destinations : {len(rows)}       Routes : {len(rows)}\n\n"
            "Destination/Mask    Proto   Pre  Cost        Flags NextHop         Interface\n\n" + "\n".join(rows) + "\n")


def vrp_ospf(d):
    rows = "".join(f" 0.0.0.0          {intf:<32} {rid:<16} Full\n" for rid, addr, intf in d.ospf_nbr)
    return (f"<{d.host}>display ospf peer brief\n\n\t OSPF Process 1 with Router ID {d.ospf['rid']}\n\t\t  Peer Statistic Information\n " + "-" * 76 + "\n Area Id          Interface                        Neighbor id      State    \n" + rows + " " + "-" * 76 + "\n")


def vrp_config(d):
    out = [f"<{d.host}>display current-configuration\n#\nsysname {d.host}\n#\nvlan batch " + " ".join(str(v) for v in sorted(d.vlans)) + "\n#\ndhcp enable\n#"]
    for vid, nm in sorted(d.vlans.items()):
        out.append(f"vlan {vid}\n name {nm}\n#")
    for pool in d.extra.get("dhcp", []):
        out.append(f"ip pool {pool['name']}\n gateway-list {pool['gw']}\n network {pool['net']} mask {mask(pool['prefix'])}\n excluded-ip-address {pool['net'].rsplit('.', 1)[0]}.2 {pool['net'].rsplit('.', 1)[0]}.99\n lease day 0 hour 8 minute 0\n dns-list {pool['dns']}\n"
                   + (f" option 150 ip-address {pool['tftp']}\n" if pool.get("tftp") else "") + "#")
    for vid, s in d.svi.items():
        ip, pl = s["ip"]
        out.append(f"interface Vlanif{vid}\n description {s.get('desc', d.vlans.get(vid, ''))}\n ip address {ip} {mask(pl)}\n" + (" dhcp select global\n" if s.get("dhcp") else "") + "#")
    for n, p in d.ifc.items():
        blk = [f"interface {n}"]
        if p.get("desc"):
            blk.append(f" description {p['desc']}")
        if p.get("ip"):
            blk += [" undo portswitch", f" ip address {p['ip'][0]} {mask(p['ip'][1])}"]
            if p.get("ospf_area") is not None:
                blk.append(" ospf network-type p2p")
        elif p.get("mode") == "trunk":
            blk += [" port link-type trunk", f" port trunk pvid vlan {p.get('native', 1)}", f" port trunk allow-pass vlan {p.get('vlans', '1').replace(',', ' ').replace('-', ' to ')}"]
        elif p.get("mode") == "access":
            blk += [" port link-type access", f" port default vlan {p.get('access', 1)}", " stp edged-port enable"]
            if p.get("voice"):
                blk.append(f" voice-vlan {p['voice']} enable")
        out.append("\n".join(blk) + "\n#")
    if d.ospf:
        o = d.ospf
        out.append(f"ospf 1 router-id {o['rid']}\n " + "\n ".join(o.get("lines", [])) + "\n area 0.0.0.0\n" + "".join(f"  network {n_} {wild(pl)}\n" for n_, pl in o.get("networks", [])) + "#")
    for dst in d.extra.get("static", []):
        out.append(f"ip route-static {dst}")
    out.append("return")
    return "\n".join(out) + "\n"


def render_vrp(d):
    parts = [vrp_version(d), vrp_config(d), f"<{d.host}>display eth-trunk\n", vrp_lldp(d), vrp_ipbrief(d)]
    if d.macs:
        parts.append(vrp_mac(d))
    if d.arp:
        parts.append(vrp_arp(d))
    if d.routes:
        parts.append(vrp_routes(d))
    if d.ospf_nbr:
        parts.append(vrp_ospf(d))
    return "\n".join(parts) + f"\n<{d.host}>\n"
