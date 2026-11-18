# Topology demo: HQ DC DRC Branches

The demo set **HQ DC DRC Branches** (`features/topology/demo/dcdrc`, 64 captures) extends the company of [HQ DC Branches](topology-demo-multisite.md) with a **disaster recovery site**: the head quarter, which is also the main data center (site **HQ-DC**), a complete copy of it (site **DRC**) and the same six branches. In the Overview the HQ-DC box is on the left and the DRC box on the right. Every name, address, MAC address and serial number is made up (documentation domain `demo.example.test`, private and documentation address ranges); nothing comes from a customer.

## Why the site is called HQ-DC

The head quarter LAN users reach the data center directly through the core, so the LAN zone and the data-center zone are one site and one box. The hostnames spell it `HQ-DC-CORE1`, `HQ-DC-SF1`, `HQ-DC-ACC1` and so on. The automatic grouping takes the first hostname word (`HQ`) and then names the site after the zone word the devices all spell (`sites.qualify`, zone words `DC`, `DR`, `DRC`): when every captured device of a site reads `HQ-DC-...`, the site is **HQ-DC**. A site whose devices differ in that word, or spell a role (`HQ-CORE1`) or a counter (`HQ-SW1`), keeps the short name, so the first demo still shows the site `HQ`. The rule reads the names in the captures only; it is not a list of sites.

## How the files were made

The 40 data-center captures come from **one design**: the DRC site is the HQ-DC design read through a text transform (hostname prefix, address block, BGP AS, provider link slot, internet and extranet blocks, serial numbers and MAC addresses), so the two sites cannot drift apart. Each file is written in the format of a real capture (NX-OS and IOS XE `show` output, FortiOS `get` and `show full-configuration`, PAN-OS `set` commands, AOS-CX and VRP `show` / `display` output). The generator is a development tool and is not part of the repository.

## Reading order for a demonstration

1. **L3 over L2** (default view), page *Overview*: the HQ-DC box on the left, the DRC box on the right, the four MPLS provider clouds below them, the six branches under the clouds. The two edge pairs are joined by two dedicated lines, the DCI.
2. Page *HQ-DC* and page *DRC*: the same drawing tier by tier (WAN routers and WAN firewalls on top, then edge, core, the LAN zone on the left of the core and the data-center zone on the right, access and TOR switches, end points). The edge pair of the other site is drawn beside the near one as a stub, so the DCI is visible on both pages.
3. **L3 route view** and the *L3 routes* tab: OSPF area 0 across the DCI, eBGP from both WAN routers to the providers, the next hop of every route, the other site's /16 learned over BGP.
4. **vPC view**: eight vPC pairs (four per data-center site).
5. Findings: the same three kinds as the first demo, none to fix (TOPO-008 firewalls have no neighbor table, TOPO-027 the Palo Alto HA links are inferred, TOPO-043 the Palo Alto pair shares its gateway addresses).

## What changes between HQ-DC and DRC

| Item | HQ-DC | DRC |
|---|---|---|
| Hostnames | `HQ-DC-xxx` (20 devices) | `DRC-xxx` (the same 20 names without the `HQ-DC-`) |
| Address block | 10.10.0.0/16 (management 10.10.0.x, loopbacks 10.10.255.x, server VLANs 10.10.101-103.0/24) | 10.30.0.0/16, the same layout (the second octet pair is the only change) |
| BGP AS | 65010 | 65030 (both private, RFC 6996) |
| Provider links | /30 slot 0: provider side `.1`, customer side `.2` (Telkom 198.51.100.0/24, Lintasarta 203.0.113.0/24) | slot 16: provider side `.17`, customer side `.18` in the same provider ranges |
| Internet breakout (WAN firewalls) | Telkom 198.18.1.0/29, ICON+ 198.18.2.0/29 | 198.18.3.0/29 and 198.18.4.0/29 |
| Extranet ports on the edge (Eth1/31 and Eth1/32, uncaptured third party) | 172.31.100.0/30 and 172.31.101.0/30 | 172.31.110.0/30 and 172.31.111.0/30 |
| Serial numbers, MAC addresses | first set | second set, so no two devices share one |

Everything else is identical on purpose: the vPC domains (core 10, edge 20, server farm 30, TOR 40), the VLAN numbers, the HA pairs, the port numbers and the cabling. A reviewer can read the HQ-DC page and know the DRC page.

## The links between the two sites

| Link | Design |
|---|---|
| **Dedicated DCI** | Two routed /30 links between the edge pairs, one per edge switch: HQ-DC-EDGE1 Eth1/41 to DRC-EDGE1 Eth1/41 (10.255.0.0/30, HQ-DC `.1`, DRC `.2`) and HQ-DC-EDGE2 Eth1/42 to DRC-EDGE2 Eth1/42 (10.255.0.4/30, `.5` and `.6`). 10.255.0.0/24 is the only block the two sites share. Both ends are `no switchport` routed ports, OSPF point-to-point, **area 0**, so the two data centers are one OSPF domain and an edge switch that loses its DCI reaches the other site through its vPC peer. |
| **MPLS** | Both sites have a WAN router pair on the same four providers: WANR1 peers with Telkom (AS 64701) and Lintasarta (AS 64702), WANR2 with ICON+ (AS 64703) and Trigatra (AS 64704); each site uses its own /30 slot on every provider (see the table above). The WAN firewalls of each site reach the internet over Telkom and ICON+. Each WAN router learns the other site's /16 over BGP, so the route exists even if the DCI is cut. |

Routing in short:

- **OSPF area 0 inside each site** (core, edge, both firewall pairs, both WAN routers) and across the DCI. Only the active unit of a firewall HA pair forms the adjacency.
- **Advertised to the providers by each site**: its own /16 (10.10.0.0/16 and 10.30.0.0/16), the aggregate 10.0.0.0/8 and the default route. Each site originates the default route towards its own core from its WAN firewalls (internet breakout).
- **Branches** learn the default route, both data-center /16 blocks, the 10.0.0.0/8 aggregate and the /16 of every branch that shares a provider with them. Their own design is described in [HQ DC Branches](topology-demo-multisite.md).

## Engine rules this set exercises (they apply to every topology)

The ready-made `layout.drawio` is not needed to get the left / right order: without it the engine gives the same arrangement, because of three general rules (details in `docs/modules/topology.md`). **Peer sites**: two to four sites with about the same number of captured network devices stand side by side on the Overview, the main one on the left and a site whose name says recovery (`DR`, `DRC`) last; the smaller sites go in rows under them and the provider clouds in the strip between. **Peer ghosts**: on a site page, the edge pair of the other site, cabled to the local edge pair over the DCI, stands in the same row. **Zones under one first word**: devices named `HQ-DC-...` and `HQ-DR-...` become the sites `HQ-DC` and `HQ-DR`. The layout file only adds the hand-drawn tiers (LAN zone left of the core, data-center zone right).

## Checks the test suite makes on the set

`tests/test_topology_demo.py` (64 captures, 90 L3 links all working, the two DCI links found with their OSPF evidence, both sites on the same four provider clouds, only invented values), `tests/test_topology_demo_dcdrc_layout.py` (the HQ-DC box left of the DRC box in the Overview, the two site pages drawn the same, every device kept in its place), `tests/test_topology_site_qualifier.py` (the site naming and zone split rules), `tests/test_topology_peer_sites.py` (peer sites and peer ghosts) and `tests/test_topology_layoutscore.py` (crossings and lines through icons stay within budget).

## How the set is made

The 64 captures and the hand-placed pages of `layout.drawio` (HQ-DC and DRC) are generated by `tools/demo_generator/` (`gen_dcdrc.py`, `layout_dcdrc.py`; the README there has the commands); `tests/test_topology_demo_generator.py` regenerates them and compares byte for byte. The set also shows the **Sites · L3 over L2** page (the DCI, the provider clouds and the branch routers on 24 icons) and, with no finding, the DR checks TOPO-047 to 051: the two sites are built from one plan, so they match.

## Documentation used

- RFC 1918, private IPv4 addresses: https://datatracker.ietf.org/doc/html/rfc1918
- RFC 5737, IPv4 documentation address blocks: https://datatracker.ietf.org/doc/html/rfc5737
- RFC 6996, private AS numbers: https://datatracker.ietf.org/doc/html/rfc6996
- RFC 2328, OSPF version 2: https://datatracker.ietf.org/doc/html/rfc2328 ; RFC 4271, BGP-4: https://datatracker.ietf.org/doc/html/rfc4271
- Cisco Data Center Interconnect Design and Deployment Guide, System Release 2.0 (LAN extension, redundant devices and links at every layer, dual-homed sites): https://www3-realm.cisco.com/en/US/docs/solutions/Enterprise/Data_Center/DCI/DCI2_External.pdf
- Cisco Nexus 9000 vPC best practices: https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html
- Cisco Nexus 9000 NX-OS 9.x Unicast Routing Configuration Guide, Configuring OSPFv2: https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/9-x/unicast/configuration/guide/l3_cli_nxos/l3_ospf.html
- Cisco IOS IP Routing: BGP Command Reference (the neighbor, network and address-family commands the IOS captures use): https://www3-realm.cisco.com/en/US/docs/ios-xml/ios/iproute_bgp/command/bgp-m1.html
- FortiGate 7.4 HA active-passive cluster setup: https://docs.fortinet.com/document/fortigate/7.4.2/administration-guide/900885 ; FortiGate 7.2 OSPF: https://docs.fortinet.com/document/fortigate/7.2.6/administration-guide/358640
- Palo Alto PAN-OS 11.1 HA links: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/high-availability/ha-concepts/ha-links-and-backup-links ; Configure OSPF: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/ospf/configure-ospf
