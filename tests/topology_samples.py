"""Synthetic device captures for the Topology Builder tests.

Every name, address and serial number here is invented. The layout of each command output follows what NX-OS and
IOS XE print, written by hand; no customer capture is copied. Documentation values: RFC 5737 / 1918 style addresses.
"""

from __future__ import annotations


def _cdp_entry(name: str, ip: str, platform: str, local: str, remote: str, caps: str = "Switch IGMP") -> str:
    return (
        "----------------------------------------\n"
        f"Device ID:{name}\n\nInterface address(es): 1\n    IPv4 Address: {ip}\n"
        f"Platform: cisco {platform}, Capabilities: {caps}\n"
        f"Interface: {local}, Port ID (outgoing port): {remote}\nHoldtime: 150 sec\n\n"
        "Version:\nCisco test image\n\nAdvertisement Version: 2\n\nNative VLAN: 10\nDuplex: full\n"
        f"Mgmt address(es):\n    IPv4 Address: {ip}\n"
    )


def nxos_capture(host: str, serial: str, mgmt_ip: str, cdp: list[tuple], lldp: list[tuple] | None = None,
                 port_channels: list[tuple] | None = None, vpc: tuple | None = None, model: str = "N9K-C93180YC-FX3",
                 config_extra: str = "", extra: str = "") -> str:
    """cdp rows: (device id, ip, platform, local port, remote port). lldp rows: (device id, local, remote).
    port_channels: (number, [member ports]). vpc: (domain, role, peer-link Po number, keepalive destination IP)."""
    out = [f"{host}# show version\nCisco Nexus Operating System (NX-OS) Software\n  NXOS: version 10.3(5)\n"
           f"  cisco Nexus9000 {model} Chassis\n  Device name: {host}\n"]
    out.append(f'{host}# show inventory\nNAME: "Chassis",  DESCR: "Nexus9000 {model} Chassis"\n'
               f"PID: {model}    ,  VID: V01 ,  SN: {serial}\n")
    out.append(f"{host}# show running-config\ninterface mgmt0\n  vrf member management\n  ip address {mgmt_ip}/24\n{config_extra}")
    if port_channels:
        rows = "".join(f"{n}   Po{n}(SU)   Eth      LACP      " + "    ".join(f"{m}(P)" for m in members) + "\n" for n, members in port_channels)
        out.append(f"{host}# show port-channel summary\nFlags:  D - Down        P - Up in port-channel (members)\n"
                   "--------------------------------------------------------------------------------\n"
                   "Group Port-       Type     Protocol  Member Ports\n      Channel\n"
                   "--------------------------------------------------------------------------------\n" + rows)
    if vpc:
        domain, role, peer_po, keepalive = vpc
        out.append(f"{host}# show vpc\n\nLegend:\n                (*) - local vPC is down, forwarding via vPC peer-link\n\n"
                   f"vPC domain id                     : {domain} \nPeer status                       : peer adjacency formed ok      \n"
                   "vPC keep-alive status             : peer is alive                 \nConfiguration consistency status  : success \n"
                   f"vPC role                          : {role}\nNumber of vPCs configured         : 1   \n\n"
                   f"vPC Peer-link status\n---------------------------------------------------------------------\n"
                   f"id    Port   Status Active vlans\n--    ----   ------ -------------------------------------------------\n"
                   f"1     Po{peer_po}   up     1,10\n\n"
                   "vPC status\n----------------------------------------------------------------------------\n"
                   "Id    Port          Status Consistency Reason                Active vlans\n"
                   "--    ------------  ------ ----------- ------                ------------\n"
                   "101   Po101         up     success     success               1,10\n")
    out.append(f"{host}# show cdp neighbors detail\n\n" + "".join(_cdp_entry(*row) for row in cdp))
    if lldp:
        out.append(f"{host}# show lldp neighbors\n\nCapability codes:\n  (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device\n"
                   "  (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other\n"
                   "Device ID            Local Intf      Hold-time  Capability  Port ID  \n"
                   + "".join(f"{d:<20} {l:<15} 120        BR          {r}  \n" for d, l, r in lldp)
                   + f"Total entries displayed: {len(lldp)}\n")
    return "\n".join(out) + (f"\n{extra}" if extra else "") + f"\n{host}# \n"


def iosxe_capture(host: str, serial: str, mgmt_ip: str, cdp: list[tuple], port_channels: list[tuple] | None = None,
                  model: str = "C9300L-48P-4X", config_extra: str = "", extra: str = "") -> str:
    """port_channels: (number, [member ports as 'Gi1/0/23'])."""
    out = [f"{host}#show version\nCisco IOS XE Software, Version 17.12.5\nCisco IOS Software [Dublin], Catalyst L3 Switch Software\n"
           f"cisco {model} (X86) processor\nProcessor board ID {serial}\n{host} uptime is 12 weeks\n"]
    out.append(f'{host}#show inventory\nNAME: "Switch 1", DESCR: "{model}"\nPID: {model}   , VID: V01  , SN: {serial}\n')
    out.append(f"{host}#show running-config\nhostname {host}\n!\ninterface Vlan1\n description Management\n ip address {mgmt_ip} 255.255.255.0\n!\n{config_extra}end\n")
    if port_channels:
        rows = "".join(f"{n}      Po{n}(SU)         LACP        " + "  ".join(f"{m}(P)" for m in members) + "\n" for n, members in port_channels)
        out.append(f"{host}#show etherchannel summary\nFlags:  D - down        P - bundled in port-channel\n"
                   "Group  Port-channel  Protocol    Ports\n------+-------------+-----------+-----------------------------------------------\n" + rows)
    out.append(f"{host}#show cdp neighbors detail\n-------------------------\n" + "".join(_cdp_entry(*row) for row in cdp))
    return "\n".join(out) + (f"\n{extra}" if extra else "") + f"\n{host}#\n"


def nxos_mac_table(host: str, rows: list[tuple[str, str, str]]) -> str:
    """rows: (vlan, mac, port)."""
    return (f"{host}# show mac address-table\nLegend:\n        * - primary entry, G - Gateway MAC, (R) - Routed MAC, O - Overlay MAC\n"
            "   VLAN     MAC Address      Type      age     Secure NTFY Ports\n"
            "---------+-----------------+--------+---------+------+----+------------------\n"
            + "".join(f"*{vlan:>5}     {mac}   dynamic  0         F      F    {port}\n" for vlan, mac, port in rows))


def nxos_arp(host: str, rows: list[tuple[str, str, str]]) -> str:
    """rows: (ip, mac, interface)."""
    return (f"{host}# show ip arp\nFlags: * - Adjacencies learnt on non-active FHRP router\n\nAddress         Age       MAC Address     Interface       Flags\n"
            + "".join(f"{ip:<15} 00:01:10  {mac}  {iface}\n" for ip, mac, iface in rows))


def lab_dc() -> dict[str, str]:
    """Two vPC aggregation switches, one IOS XE access switch dual-homed to both, plus one uncaptured firewall."""
    agg1 = nxos_capture(
        "LAB-AGG1", "FDO00000001", "10.99.0.11",
        cdp=[("LAB-ACC1.lab.example(FOC00000001)", "10.99.0.21", "C9300L-48P-4X", "Ethernet1/1", "GigabitEthernet1/0/23"),
             ("LAB-AGG2.lab.example(FDO00000002)", "10.99.0.12", "N9K-C93180YC-FX3", "Ethernet1/47", "Ethernet1/47"),
             ("LAB-AGG2.lab.example(FDO00000002)", "10.99.0.12", "N9K-C93180YC-FX3", "Ethernet1/48", "Ethernet1/48")],
        lldp=[("LAB-FW1", "Eth1/40", "port5")],
        port_channels=[(101, ["Eth1/1"]), (240, ["Eth1/47", "Eth1/48"])],
        vpc=("240", "primary", "240", "10.99.0.12"))
    agg2 = nxos_capture(
        "LAB-AGG2", "FDO00000002", "10.99.0.12",
        cdp=[("LAB-ACC1.lab.example(FOC00000001)", "10.99.0.21", "C9300L-48P-4X", "Ethernet1/1", "GigabitEthernet1/0/24"),
             ("LAB-AGG1.lab.example(FDO00000001)", "10.99.0.11", "N9K-C93180YC-FX3", "Ethernet1/47", "Ethernet1/47"),
             ("LAB-AGG1.lab.example(FDO00000001)", "10.99.0.11", "N9K-C93180YC-FX3", "Ethernet1/48", "Ethernet1/48")],
        port_channels=[(101, ["Eth1/1"]), (240, ["Eth1/47", "Eth1/48"])],
        vpc=("240", "secondary", "240", "10.99.0.11"))
    acc1 = iosxe_capture(
        "LAB-ACC1", "FOC00000001", "10.99.0.21",
        cdp=[("LAB-AGG1.lab.example(FDO00000001)", "10.99.0.11", "N9K-C93180YC-FX3", "GigabitEthernet1/0/23", "Ethernet1/1"),
             ("LAB-AGG2.lab.example(FDO00000002)", "10.99.0.12", "N9K-C93180YC-FX3", "GigabitEthernet1/0/24", "Ethernet1/1")],
        port_channels=[(40, ["Gi1/0/23", "Gi1/0/24"])])
    return {"LAB-AGG1.txt": agg1, "LAB-AGG2.txt": agg2, "LAB-ACC1.txt": acc1}
