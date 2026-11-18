"""FortiGate (FortiOS CLI) and Palo Alto (PAN-OS set commands) renderers."""
from __future__ import annotations
from core import DEVICES, DOMAIN, mask, wild


# ------------------------------------------------------------------------------------------------ FortiGate
def forti_status(d):
    e = d.extra
    return (f"{d.host} # get system status\nVersion: {d.model} v7.2.8,build1639,240123 (GA.M)\nSerial-Number: {d.serial}\nBIOS version: 04000029\nOperation Mode: NAT\n"
            f"Current virtual domain: root\nMax number of virtual domains: 10\nVirtual domains status: 1 in NAT mode, 0 in TP mode\nVirtual domain configuration: disable\n"
            f"Current HA mode: a-p, {e['ha_role']}\nCluster uptime: 112 days, 3 hours, 10 minutes, 44 seconds\nHostname: {d.host}\nSystem time: Sat Nov  1 09:12:41 2026\n")


def forti_ha_status(d):
    e = d.extra
    peer = DEVICES[e["ha_peer"]]
    return (f"{d.host} # get system ha status\nHA Health Status: OK\nModel: {d.model}\nMode: HA A-P\nGroup Name: {e['ha_group']}\nGroup ID: {e['ha_id']}\nDebug: 0\nCluster Uptime: 112 days 3:10:44\n"
            f"Cluster state change time: 2026-07-12 11:01:30\nPrimary selected using:\n    <2026/07/12 11:01:30> {e['ha_primary_serial']} is selected as the primary because it has the largest value of override priority.\n"
            f"ses_pickup: disable\nload_balance: disable\nschedule: none\nMaster: {e['ha_primary']:<18} {e['ha_primary_serial']}  0\nSlave : {e['ha_secondary']:<18} {e['ha_secondary_serial']}  1\n"
            f"number of vcluster: 1\nvcluster 1: work 169.254.0.1\nMaster:0 {e['ha_primary_serial']}\nSlave :1 {e['ha_secondary_serial']}\n")


def _forti_iface(d, name, p):
    t = p.get("type", "physical")
    out = [f'    edit "{name}"', '        set vdom "root"']
    if p.get("ip"):
        ip, pl = p["ip"]
        out.append(f"        set ip {ip} {mask(pl)}")
        out.append(f"        set allowaccess {p.get('allow', 'ping')}")
    if t == "aggregate":
        out += ["        set type aggregate", "        set member " + " ".join(f'"{m}"' for m in p["members"]), "        set lacp-mode active", "        set lacp-speed fast"]
    elif t == "redundant":
        out += ["        set type redundant", "        set member " + " ".join(f'"{m}"' for m in p["members"])]
    elif t == "vlan":
        out += [f'        set interface "{p["parent"]}"', f"        set vlanid {p['vlanid']}"]
    elif t == "loopback":
        out.append("        set type loopback")
    else:
        out.append("        set type physical")
    if p.get("desc"):
        out.append(f'        set alias "{p["desc"]}"')
    if p.get("role"):
        out.append(f"        set role {p['role']}")
    out.append("    next")
    return "\n".join(out)


def forti_config(d):
    e = d.extra
    out = [f'{d.host} # show full-configuration\n#config-version={d.model}-7.2.8-FW-build1639-240123:opmode=0:vdom=0:user=admin\nconfig system global\n    set admintimeout 10\n    set hostname "{d.host}"\n    set timezone "Asia/Jakarta"\n    set strong-crypto enable\nend',
           "config system interface"]
    for n, p in d.ifc.items():
        out.append(_forti_iface(d, n, p))
    out.append("end")
    out.append(f'config system ha\n    set group-id {e["ha_id"]}\n    set group-name "{e["ha_group"]}"\n    set mode a-p\n    set hbdev "{e["hbdev"]}" 50\n    set session-pickup enable\n    set override enable\n    set priority {e["ha_prio"]}\nend')
    for pool in e.get("dhcp", []):
        out.append(f'config system dhcp server\n    edit {pool["id"]}\n        set dns-service default\n        set default-gateway {pool["gw"]}\n        set netmask {mask(pool["prefix"])}\n        set interface "{pool["iface"]}"\n        config ip-range\n            edit 1\n                set start-ip {pool["start"]}\n                set end-ip {pool["end"]}\n            next\n        end\n        set lease-time 28800\n    next\nend')
    if d.ospf:
        o = d.ospf
        txt = f"config router ospf\n    set router-id {o['rid']}\n"
        for line in o.get("fgt_lines", []):
            txt += f"    {line}\n"
        txt += "    config area\n        edit 0.0.0.0\n        next\n    end\n    config ospf-interface\n"
        for i, (name, ifn, nt) in enumerate(o["ifaces"], 1):
            txt += f'        edit "{name}"\n            set interface "{ifn}"\n            set network-type {nt}\n        next\n'
        txt += "    end\n    config network\n"
        for i, (n_, pl) in enumerate(o["networks"], 1):
            txt += f"        edit {i}\n            set prefix {n_} {mask(pl)}\n        next\n"
        txt += "    end\n    config redistribute \"connected\"\n        set status enable\n    end\nend"
        out.append(txt)
    if d.bgp:
        b = d.bgp
        txt = f"config router bgp\n    set as {b['asn']}\n    set router-id {b['rid']}\n    config neighbor\n"
        for ip, asn, desc, *_ in b["neighbors"]:
            txt += f'        edit "{ip}"\n            set remote-as {asn}\n            set description "{desc}"\n            set soft-reconfiguration enable\n        next\n'
        txt += "    end\n    config network\n"
        for i, (n_, pl) in enumerate(b.get("networks", []), 1):
            txt += f"        edit {i}\n            set prefix {n_} {mask(pl)}\n        next\n"
        txt += "    end\nend"
        out.append(txt)
    if e.get("static"):
        txt = "config router static\n"
        for i, (dst, gw, dev) in enumerate(e["static"], 1):
            txt += f"    edit {i}\n" + (f"        set dst {dst}\n" if dst else "") + f"        set gateway {gw}\n        set device \"{dev}\"\n    next\n"
        out.append(txt + "end")
    return "\n".join(out)


def forti_routes(d):
    out = [f"{d.host} # get router info routing-table all\nCodes: K - kernel, C - connected, S - static, R - RIP, B - BGP\n       O - OSPF, IA - OSPF inter area\n       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2\n       E1 - OSPF external type 1, E2 - OSPF external type 2\n       i - IS-IS, L1 - IS-IS level-1, L2 - IS-IS level-2, ia - IS-IS inter area\n       * - candidate default\n"]
    dflt = next((r for r in d.routes if r["prefix"] == "0.0.0.0/0"), None)
    out.append(f"Routing table for VRF=0")
    codes = {"ospf": "O", "bgp": "B", "static": "S"}
    for r in d.routes:
        c = codes[r["proto"]]
        star = "*" if r["prefix"] == "0.0.0.0/0" else " "
        t = r.get("type", "")
        pref = {"ospf": 110, "bgp": 20, "static": 10}[r["proto"]]
        out.append(f"{(c + star + t):<8}{r['prefix']} [{pref}/{r.get('metric', 0)}] via {r['nh']}, {r['intf']}, 3d04h")
    for n, p in d.ifc.items():
        if p.get("ip"):
            ip, pl = p["ip"]
            out.append(f"C       {ip.rsplit('.', 1)[0]}.0/{pl} is directly connected, {n}" if pl < 31 else f"C       {ip}/{pl} is directly connected, {n}")
    return "\n".join(out) + "\n"


def forti_ospf(d):
    rows = "".join(f"{rid:<15} {1:>3}   {'Full/DR' if i % 2 else 'Full/Backup'}     00:00:35    {addr:<15} {intf}\n" for i, (rid, addr, intf) in enumerate(d.ospf_nbr))
    return f"{d.host} # get router info ospf neighbor\n\nOSPF process 0:\nNeighbor ID     Pri   State           Dead Time   Address         Interface\n{rows}"


def forti_bgp(d):
    b = d.bgp
    rows = "".join(f"{n['ip']:<15} 4 {n['asn']:>10} 1432 1429 {9:>6} 0 0 3d04h {n['pfx']:>10}\n" for n in d.bgp_nbr)
    return (f"{d.host} # get router info bgp summary\nVRF 0 BGP router identifier {b['rid']}, local AS number {b['asn']}\nBGP table version is 9\n1 BGP AS-PATH entries\n0 BGP community entries\n\n"
            f"Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n{rows}\nTotal number of neighbors {len(d.bgp_nbr)}\n")


def render_forti(d):
    parts = [forti_status(d), forti_ha_status(d), forti_config(d)]
    if d.routes:
        parts.append(forti_routes(d))
    if d.ospf_nbr:
        parts.append(forti_ospf(d))
    if d.bgp_nbr:
        parts.append(forti_bgp(d))
    return "\n".join(parts) + f"\n{d.host} # \n"


# ------------------------------------------------------------------------------------------------ PAN-OS (set commands)
def render_pan(d):
    e = d.extra
    L = [f"set deviceconfig system hostname {d.host}", f"set deviceconfig system ip-address {d.mgmt}", "set deviceconfig system netmask 255.255.255.0", f"set deviceconfig system default-gateway {e['mgmt_gw']}",
         f"set deviceconfig system dns-setting servers primary 10.10.0.5", f"set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.10.0.5",
         "set deviceconfig system timezone Asia/Jakarta", f"set deviceconfig system domain {DOMAIN}"]
    L += [f"set deviceconfig high-availability enabled yes", f"set deviceconfig high-availability group group-id {e['ha_id']}", f"set deviceconfig high-availability group peer-ip {e['ha_peer_ip']}",
          "set deviceconfig high-availability group mode active-passive", f"set deviceconfig high-availability group election-option device-priority {e['ha_prio']}",
          "set deviceconfig high-availability group election-option preemptive yes", "set deviceconfig high-availability interface ha1 port ha1-a", f"set deviceconfig high-availability interface ha1 ip-address {e['ha_own_ip']}",
          "set deviceconfig high-availability interface ha1 netmask 255.255.255.252", "set deviceconfig high-availability interface ha2 port ha2-a"]
    members = {}
    for n, p in d.ifc.items():
        if p.get("type") == "member":
            L.append(f"set network interface ethernet {n} aggregate-group {p['group']}")
            if p.get("desc"):
                L.append(f'set network interface ethernet {n} comment "{p["desc"]}"')
            members.setdefault(p["group"], []).append(n)
    for n, p in d.ifc.items():
        if p.get("type") == "ae":
            L.append(f"set network interface aggregate-ethernet {n} layer3 lacp enable yes")
            L.append(f"set network interface aggregate-ethernet {n} layer3 lacp mode active")
            L.append(f"set network interface aggregate-ethernet {n} layer3 interface-management-profile MGMT-PING")
            if p.get("desc"):
                L.append(f'set network interface aggregate-ethernet {n} comment "{p["desc"]}"')
        elif p.get("type") == "unit":
            base = p["parent"]
            L.append(f"set network interface aggregate-ethernet {base} layer3 units {n} tag {p['vlanid']}")
            L.append(f"set network interface aggregate-ethernet {base} layer3 units {n} ip {p['ip'][0]}/{p['ip'][1]}")
            L.append(f"set network interface aggregate-ethernet {base} layer3 units {n} interface-management-profile MGMT-PING")
            if p.get("desc"):
                L.append(f'set network interface aggregate-ethernet {base} layer3 units {n} comment "{p["desc"]}"')
        elif p.get("type") == "eth3":
            L.append(f"set network interface ethernet {n} layer3 ip {p['ip'][0]}/{p['ip'][1]}")
            if p.get("desc"):
                L.append(f'set network interface ethernet {n} comment "{p["desc"]}"')
    L.append("set network profiles interface-management-profile MGMT-PING ping yes")
    units = [n for n, p in d.ifc.items() if p.get("type") in ("unit", "eth3")]
    L.append(f"set network virtual-router default interface [ {' '.join(units)} ]")
    for zone, names in e["zones"].items():
        L.append(f"set zone {zone} network layer3 [ {' '.join(names)} ]")
    o = d.ospf
    L.append(f"set network virtual-router default protocol ospf router-id {o['rid']}")
    L.append("set network virtual-router default protocol ospf enable yes")
    for ifn, metric, kind in o["ifaces"]:
        L.append(f"set network virtual-router default protocol ospf area 0.0.0.0 interface {ifn} enable yes")
        L.append(f"set network virtual-router default protocol ospf area 0.0.0.0 interface {ifn} metric {metric}")
        if kind == "passive":
            L.append(f"set network virtual-router default protocol ospf area 0.0.0.0 interface {ifn} passive yes")
        else:
            L.append(f"set network virtual-router default protocol ospf area 0.0.0.0 interface {ifn} link-type {kind}")
    for pol in e.get("rules", []):
        L.append(pol)
    return "\n".join(L) + "\n"
