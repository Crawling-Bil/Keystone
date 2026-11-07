# Topology demo: head quarter and six branches

The demo set **Head quarter and 6 branches** (`features/topology/demo/multisite`, 44 captures) is an invented company, built to show the Topology Builder on a realistic multi-site, multi-vendor network. Every name, address, MAC address and serial number is made up; there are no passwords, SNMP communities or keys in the files. Load it with the demo button of the Topology Builder (the page chooses *Automatic* grouping: an Overview plus one page per site) and press **Build topology**. The button also fills *Keep my layout* with `layout.drawio` (shipped beside the captures), so the head quarter page is drawn tier by tier: WAN routers and WAN firewalls on top, the edge pair, the core pair, the LAN zone (FortiGate pair, access switches, PCs) on the left, the data-center zone (Palo Alto pair, server-farm and TOR pairs, servers) on the right, every vPC / HA pair side by side. The Overview shows the head quarter above the six branches. Without the layout (clear the field) the builder arranges the page by itself, which is correct but busier for a network of this shape.

How the files were made: they are written by a generator that holds the design below once (devices, cables, VLANs, addresses, routing) and prints each device in the format a real capture has: NX-OS and IOS XE `show` output, FortiOS `get` and `show full-configuration`, PAN-OS `set` commands, AOS-CX `show` output and VRP `display` output. The builder reads them with the normal parsers; nothing in the app is special-cased for the demo.

## Reading order for a demonstration

1. **L3 over L2** (default view), page *Overview*: HQ and the six branches, the four provider clouds shared by the sites, one bundled line per site pair.
2. Page *HQ*: the LAN zone, the data-center zone, core, edge, WAN firewalls and WAN routers, with the vPC pairs.
3. Page *JKT* (Cisco) next to *SBY* (Aruba) and *YOG* (Huawei): the same branch design on three vendors.
4. **L3 route view** and the *L3 routes* tab: OSPF inside, BGP to the providers, the next hop of every route.
5. **vPC view**: four vPC domains.
6. Findings: only three kinds remain on purpose, none to fix (TOPO-008 firewalls have no neighbor table, TOPO-027 the Palo Alto HA links are inferred, TOPO-043 the Palo Alto pair shares its gateway addresses).

## Head quarter (hostnames HQ-xxx)

| Zone | Devices | Design |
|---|---|---|
| LAN | HQ-PC1..4, HQ-ACC1/2 (Catalyst C9300-48P, L2), HQ-DS1/2 (Catalyst C9500-24Y4C distribution pair, L2), HQ-FGLAN1/2 (FortiGate-200F HA pair) | The access and distribution switches are L2 only: each access switch has one 10G uplink to DS1 and one to DS2, the two distribution switches are joined by a two-cable LACP `Po1`, and each FortiGate has a `redundant` interface `lan-sw` (port3 to DS1, port4 to DS2) carrying VLAN 110 (users, 10.10.110.0/24, DHCP .100-.199 on the FortiGate) and VLAN 199 (LAN management, 10.10.199.0/24). The FortiGate is the LAN gateway (L3) and runs OSPF toward the core. |
| Data center | HQ-SRV1..4, HQ-TOR1/2 (Nexus 93180YC-FX3, vPC domain 40), HQ-SF1/2 (server-farm Nexus, vPC domain 30), HQ-PADC1/2 (PA-5220 HA pair) | Servers sit on the TOR pair (VLAN 101 web, 102 app, 103 db). TOR and server farm are joined by a double-sided vPC (Po141). The Palo Alto pair is the gateway of the three server VLANs (10.10.101-103.0/24, gateway .1 on `ae1.101`-`ae1.103`) and is cabled to both server-farm switches (`ae1`, 40G). |
| Core | HQ-CORE1/2 (vPC domain 10) | L3, OSPF area 0. Joined to the FortiGate LAN pair by VLAN 901 (10.10.251.0/29) and to the Palo Alto pair by VLAN 902 (10.10.252.0/29), each on a vPC port-channel (Po111-Po114). Four routed /30 links to the edge in 10.10.240.0/24. |
| Edge | HQ-EDGE1/2 (vPC domain 20) | L3, OSPF area 0. The bridge between the core and everything outside: the WAN firewalls (VLAN 911, 10.10.253.0/29), the two WAN routers (routed /30 links in 10.10.241.0/24) and two uncaptured third-party ports (Eth1/31: extranet partner 172.31.100.0/30, vendor link 172.31.101.0/30, static routes). |
| WAN | HQ-FGWAN1/2 (FortiGate-600F HA pair), HQ-WANR1/2 (ASR1001-X) | The WAN firewalls speak OSPF to the edge (inside) and eBGP to the internet providers (outside, Telkom on wan1 198.18.1.0/29 and ICON+ on wan2 198.18.2.0/29) and originate the default route into OSPF. WANR1 has the MPLS providers Telkom and Lintasarta, WANR2 ICON+ and Trigatra; all four sessions are eBGP. |

Loopbacks and router IDs are in 10.10.255.0/24 (CORE1 .1, CORE2 .2, EDGE1 .3, EDGE2 .4, WANR1 .5, WANR2 .6, FGLAN .11/.12, PADC .21/.22, FGWAN .31/.32). Management addresses are 10.10.0.x/24 (switches .11-.24, Palo Alto .31/.32, FortiGate .41-.44, routers .51/.52) and 10.10.199.11/12 for the access switches.

## Branches (one router and three switches each)

All six branches use the same design; the switch vendor changes. `n` is the branch number 1-6 and the branch owns **10.(100+n).0.0/16**.

| n | Branch | Router (Cisco ISR4331) | Switches | Providers | BGP AS |
|---|---|---|---|---|---|
| 1 | Jakarta JKT | JKT-RTR1 | JKT-SW1..3 Cisco C9200L-24P-4G | Telkom, Lintasarta | 65101 |
| 2 | Surabaya SBY | SBY-RTR1 | SBY-SW1..3 Aruba 6200F (AOS-CX) | Telkom, ICON+ | 65102 |
| 3 | Yogyakarta YOG | YOG-RTR1 | YOG-SW1..3 Huawei S5735-S24T4X | Lintasarta, Trigatra | 65103 |
| 4 | Makasar MKS | MKS-RTR1 | MKS-SW1..3 Huawei S5735-S24T4X | ICON+, Trigatra | 65104 |
| 5 | Medan MED | MED-RTR1 | MED-SW1..3 Aruba 6200F (AOS-CX) | Telkom, Trigatra | 65105 |
| 6 | Balikpapan BAL | BAL-RTR1 | BAL-SW1..3 Cisco C9200L-24P-4G | Lintasarta, ICON+ | 65106 |

Inside a branch (example JKT, n = 1, so 10.101.x.x):

| Item | Value |
|---|---|
| Router to switch | routed `/26`: 10.101.0.0/26, router .1 (Gi0/0/2), SW1 .2 |
| LAN gateway | SW1 (L3 switch), `/24` per VLAN: VLAN 10 users 10.101.10.0/24, VLAN 20 Wi-Fi 10.101.20.0/24, VLAN 30 voice 10.101.30.0/24, VLAN 99 management 10.101.99.0/24 (gateway .1 on each) |
| DHCP | SW1 serves wired users, Wi-Fi users and phones: pools .100-.199 in VLAN 10, 20 and 30 (voice pool carries option 150 to the call manager 10.10.102.30); DNS 10.10.101.11 |
| Switch cabling | **Chain** (JKT, SBY, YOG): SW1 - SW2 - SW3. **Star** (MKS, MED, BAL): SW1 has two downlinks, SW2 and SW3, one cable each. SW2 and SW3 are L2 access switches in both, management addresses 10.10x.99.12 and .13 with a default route to .1 |
| Per switch | 2 PCs (VLAN 10), 1 IP phone (data VLAN 10, voice VLAN 30), 1 access point (management VLAN 99 untagged, Wi-Fi VLAN 20 tagged, two Wi-Fi clients each) |
| Router loopback | 10.101.255.1/32 (router ID and management address) |

Ports of the switch cabling (one cable per line):

| Vendor | End points (PC, PC, phone, AP) | SW1 downlink to SW2 | Downlink on the lower switch (SW2, and SW3 in the chain: its uplink port) | SW1 link to the router | SW1 second downlink to SW3 (star only) |
|---|---|---|---|---|---|
| Cisco C9200L (JKT, BAL) | Gi1/0/1-4 | Gi1/1/1 | Gi1/1/2 | Gi1/1/3 | Gi1/1/4 |
| Aruba 6200F (SBY, MED) | 1/1/1-4 | 1/1/26 | 1/1/27 | 1/1/25 | 1/1/28 |
| Huawei S5735 (YOG, MKS) | GE0/0/1-4 | XGE0/0/1 | XGE0/0/2 | GE0/0/24 | XGE0/0/3 |

In a chain, SW2 uses its first uplink port toward SW3 as well (SW2 Gi1/1/1 to SW3 Gi1/1/2 on Cisco).

The star pages are the check for the placement engine: the hub is found as the core from the shape of the cabling (a plain `SW` in a name states no tier), it is drawn over its two downlinks, and each of the two switches stands over its own end points, with no line crossing (see *A star of switches is drawn as a tree* in the changelog).

Provider links are /30s in documentation ranges: Telkom 198.51.100.0/24, Lintasarta 203.0.113.0/24, ICON+ 192.0.2.0/24, Trigatra 198.18.0.0/24. The provider side of each link is `.slot+1`, the customer side `.slot+2`; HQ uses slot 0, and the branches slots 4, 8 and 12 of the provider they have (Telkom: JKT 4, SBY 8, MED 12; Lintasarta: JKT 4, YOG 8, BAL 12; ICON+: SBY 4, MKS 8, BAL 12; Trigatra: YOG 4, MKS 8, MED 12). Provider AS numbers are 64701 (Telkom), 64702 (Lintasarta), 64703 (ICON+) and 64704 (Trigatra); HQ is AS 65010. All AS numbers are private numbers (RFC 6996).

## Routing and advertisement

- **OSPF area 0 inside the head quarter**: core, edge, both firewall pairs and both WAN routers. Only the active unit of a firewall HA pair forms the adjacency. The server VLANs are passive interfaces on the Palo Alto gateways.
- **eBGP at the WAN routers**: each WAN router and each branch router peers with its provider edge. The provider network is an MPLS VPN, so every site reaches the head quarter and the branches that share a provider.
- **Advertised by HQ**: 10.10.0.0/16 and the aggregate 10.0.0.0/8 (so two branches with no common provider reach each other through the head quarter) and the default route (internet breakout is at the HQ WAN firewalls). The WAN routers redistribute BGP into OSPF so the data center and the LAN know every branch.
- **Advertised by each branch**: its own 10.(100+n).0.0/16 summary (a Null0 static route anchors it).
- **Inside a branch**: router and SW1 run OSPF area 0; the router originates the default route to SW1 (`default-information originate`); SW2 and SW3 use a static default to SW1.
- **Learned by a branch router over BGP**: the default route, 10.10.0.0/16, 10.0.0.0/8 and the /16 of every branch that shares a provider with it.

## What each vendor capture contains

| Vendor | Commands in the file |
|---|---|
| Cisco NX-OS | show version, inventory, running-config, port-channel summary, vpc, cdp / lldp neighbors detail, interface status, mac address-table, ip arp, ip route, ip ospf neighbors, ip interface brief |
| Cisco IOS XE | the same family for Catalyst switches and ISR / ASR routers, plus `show ip bgp summary` on the routers |
| FortiGate | get system status, get system ha status, show full-configuration, get router info routing-table all / ospf neighbor / bgp summary; cables written as `to HOST - port` in the port alias |
| Palo Alto | `set` commands: management, HA, aggregate-ethernet with sub-units, zones, virtual router, OSPF; cables written as `HOST - port` in the interface comment |
| Aruba AOS-CX | show version, system, running-config, vlan, interface, ip interface brief, lldp neighbor-info detail, mac-address-table, arp, ip route, ip ospf neighbors |
| Huawei VRP | display version, current-configuration, lldp neighbor (brief and detail), ip interface brief, mac-address, arp, ip routing-table, ospf peer brief |

## Documentation used

- RFC 1918, private IPv4 addresses: https://datatracker.ietf.org/doc/html/rfc1918
- RFC 5737, IPv4 documentation address blocks: https://datatracker.ietf.org/doc/html/rfc5737
- RFC 6996, private AS numbers: https://datatracker.ietf.org/doc/html/rfc6996
- RFC 2328, OSPF version 2: https://datatracker.ietf.org/doc/html/rfc2328 ; RFC 4271, BGP-4: https://datatracker.ietf.org/doc/html/rfc4271
- Cisco Nexus 9000 vPC best practices: https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html
- Cisco Nexus 9000 NX-OS 10.3 OSPFv2: https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/unicast-routing-configuration/cisco-nexus-9000-series-nx-os-unicast-routing-configuration-guide-release-103x/m_configuring_ospfv2.html
- Cisco IOS XE 17 Configuring a basic BGP network: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/configuration/xe-17/irg-xe-17-book/configuring-a-basic-bgp-network.html
- Cisco IOS XE 17 DHCP server: https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-addressing/b-ip-addressing/m_config-dhcp-server-xe.html
- Cisco Campus high-availability design: https://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Campus/HA_campus_DG/hacampusdg.html
- FortiGate 7.4 HA active-passive cluster setup: https://docs.fortinet.com/document/fortigate/7.4.2/administration-guide/900885 ; FortiGate 7.2 OSPF: https://docs.fortinet.com/document/fortigate/7.2.2/administration-guide/561713/ospf
- Palo Alto PAN-OS 11.1 HA links: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/high-availability/ha-concepts/ha-links-and-backup-links ; Configure OSPF: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/ospf/configure-ospf
- Aruba AOS-CX 10.15 passive OSPF interfaces: https://arubanetworking.hpe.com/techdocs/AOS-CX/10.15/HTML/ip_route_6300-6400-8100-83xx-9300-10000/Content/Chp_OSPFv2/cnf-pas-osp-int.htm ; AOS-CX VSX guide: https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/vsx.pdf
- Huawei CloudEngine S3700/S5700/S6700 configuration guide (the Huawei site refuses automated access, link taken from its listing): https://support.huawei.com/enterprise/en/doc/EDOC1100333463
