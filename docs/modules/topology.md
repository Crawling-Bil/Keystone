# Topology Builder

Draws the network from the neighbor tables already inside your device captures and exports a draw.io file.
Page: `/topology` (Analyze group). Design, algorithms and roadmap: `docs/modules/topology-design.md`.

## What to upload

Captures (`.txt`, `.log`, `.cfg`) or one or more `.zip` archives of them, up to 100 devices. A file may hold several devices' sessions one after another (a prompt such as `SW1#` or `<SW1>` followed by commands); it is split per device. ZIP member names are reduced to the file name, hidden and non-text members are ignored. Each capture should contain:

| Purpose | Cisco IOS XE / NX-OS | Huawei VRP |
|---|---|---|
| Links | `show cdp neighbors detail`, `show lldp neighbors detail` | `display lldp neighbor brief` |
| Port-channels | `show etherchannel summary` / `show port-channel summary` | `display eth-trunk` |
| vPC pairs | `show vpc` | - |
| Model, serial, stack | `show inventory`, `show version` | `display version`, `display device` |
| Management IP | running configuration or `show ip interface brief` | `display current-configuration` |

The collect lists in `static/collect-scripts/` already contain most of these commands.

## How the diagram is built

1. **Identity.** A neighbor is matched to a captured device by serial number, then management/interface IP, then short hostname (domain and `(SERIAL)` suffix removed). Two captures with the same hostname but different serials are kept apart (TOPO-003).
2. **Links.** Port names are normalised (`TenGigabitEthernet1/1/1` = `Te1/1/1`, LLDP capability codes in front of a port id are dropped). Each device's "on my port X I see device Y port Z" rows are paired. Both ends agree: *confirmed*. Only one end reports it: *single-sided* (peer not captured, or CDP/LLDP off). The peer's own table says the port faces another device: *conflict*.
3. **Bundles and vPC.** Links whose ports belong to the same port-channel become one line labelled with the Po name, member count and protocol. A vPC peer-link (from `show vpc`) is blue. A port-channel whose members reach two different switches is marked multi-chassis and carries the vPC id.
4. **Roles and tiers.** Hostname words (AGG, TOR, FW, RT, AP ...), then model, then graph shape. Rows from the top: edge routers and firewalls, core, aggregation, access, endpoints.
5. **Hosts (option).** MAC addresses from `show mac address-table` / `display mac-address` on edge ports (not port-channels or ports that face another network device), joined with the ARP table for the IP, become hosts. Virtual and multicast MACs (HSRP/VRRP, 01:00:5e...) are dropped. Up to three hosts on a port are drawn one by one, more become one "N hosts" node. They are always in `hosts.csv`; they are drawn only when "Draw hosts" is on.
6. **Routed links (option).** Two captured devices with addresses in the same /30 or /31 (same VRF) get a dashed blue line with the subnet. When a CDP/LLDP link already joins them on that interface the subnet is added to that link instead of drawing a second one. A device whose peer is not captured is still joined when another device's neighbor table advertises the peer address. Management and loopback interfaces are ignored.
7. **Endpoints.** Three or more access points, phones or hosts hanging off one switch become one node ("14 access points"); every port is still listed in `links.csv`.

8. **vPC view.** Each vPC pair (both switches captured, same row) gets a dashed frame titled `vPC domain N`. A bundle that reaches both switches of a pair, or leaves both, becomes one thick line labelled `vPC <id> · <members>x<speed>` with the Po names at the ends, so 62 cables between four pairs read as a handful of lines. The peer-link stays inside the frame. Device positions are those of the physical page, so a hand-tuned layout carries over. A pair whose two switches sit on different rows, or with another device dragged between them, keeps its physical lines. The diagram file holds the physical page and the vPC page (option), and the preview has a Physical / vPC toggle. Concept: https://www.cisco.com/c/it_it/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html
9. **Speed.** Per port, the rating of the transceiver (`show interface transceiver`: `10Gbase-SR`, `SFP-H25GB-SR`, `QSFP-40G-SR-BD`, `1000base-T`) wins; otherwise the interface name says it (`Gi` 1 G, `Te` 10 G, `Twe` 25 G, `Fo` 40 G, `Hu` 100 G, Huawei `XGE`/`GE`); `Eth1/1` on NX-OS without transceiver data stays unknown. It is a rating, not the negotiated rate. Bundle labels read `4x10G LACP`; mixed members read `2x10G+2x1G`. "Style lines by rated speed" colours and thickens the lines by the fastest member (1G light blue, 10G blue, 25G purple, 40G green, 100G orange; dashed = not confirmed from both ends).
10. **Management links.** A link on a `mgmt` port is kind `mgmt`. By default it is left out of the picture (and out of the row layout) and stays in `links.csv`; untick the option to draw it thin and dotted.
11. **Devices behind devices.** A MAC learned on a port that faces a device nobody captured (a UCS fabric interconnect, a hypervisor uplink, a switch not yet collected) belongs to that device. These MACs are listed in `hosts.csv` with `behind`, summarised per port in `behind.csv` (MAC count, MACs with an IP, VMware and Hyper-V by MAC prefix, VLAN ranges), drawn nowhere and never counted by TOPO-007. VMware (`00:50:56`, `00:0C:29`, `00:1C:14`, `00:05:69`) and Hyper-V (`00:15:5D`) are hints only: an administrator can give a virtual machine any MAC. Prefix source: https://macaddress.io/faq/how-to-recognise-a-vmwares-virtual-machine-by-its-mac-address

## Adding to a previous run

`topology.json` holds the tables and a compact `state` block with every captured device (neighbors, bundles, vPC, speeds, MAC and ARP tables). Upload it under "Add to a previous run" next to new captures: the saved devices are kept, a new capture replaces the saved device with the same serial number or hostname, and the whole estate is rebuilt (links between old and new devices are confirmed). With no new captures it rebuilds the previous run with other options. Devices from the saved state are marked `previous run` in `devices.csv` and TOPO-022 lists them, because two captures taken on different days can disagree. The file is read as JSON only, size-limited, with types checked field by field; nothing in it is executed.

## Documentation pack

`keystone-topology-pack.zip` holds `topology-report.html`, one SVG per diagram page, `topology.drawio`, `topology.xlsx`, every CSV and `topology.json`. The report has no scripts and no external files: diagrams (both views), findings, device inventory, bundles and vPC, hosts behind uncaptured devices, one page per captured device (facts and ports) and the method and limits. Open it in a browser and print it to PDF (landscape A4, each device starts a new page). Everything that came from a capture is HTML-escaped.

## Reading the result

| Look | Meaning |
|---|---|
| Black line | Both ends report the link |
| Orange dashed | One end reports it |
| Red dashed | The two ends disagree |
| Blue thick | vPC peer-link |
| Grey box | Seen in a neighbor table, not captured |

Lines are routed around devices that sit in their path, parallel lines between the same two devices are spread apart, and devices inside each row are placed left to right in natural name order (A-Z first, then 0-9; `JKT-A2` before `JKT-A10`), so the sequence on the page is the sequence a reader expects. What hangs off one device (switches, access points, phones, PCs, collapsed nodes) stays together right under that device, and a device that only uplinks (a router or firewall) sits over what it serves, so the APs of switch A are never mixed with those of switch B and routers A, B, C stay side by side over their core. Lines may cross more than with an order chosen to minimise crossings; draw.io lets you move a device when that matters.

Downloads: `keystone-topology-pack.zip`, `topology-report.html`, `topology.drawio` (open in diagrams.net; Edit Data on any device or line shows serial, model, source file, link list, speed, vPC id and state), `topology.xlsx` (Summary, Devices, Links, Bundles, Hosts, Behind devices, Findings; cell text is never stored as a formula), `links.csv`, `devices.csv`, `hosts.csv`, `behind.csv`, `bundles.csv`, `findings.csv`, `topology.json`.

**Keep my layout.** Move devices in draw.io, save, and upload that `.drawio` as "Previous diagram" on the next run. Devices are matched by the `node_key` stored in the file, kept where you put them, and new devices are placed in free space. Only uncompressed draw.io files are read (File > Properties > Compressed off; the files Keystone writes are uncompressed); a DOCTYPE or external entity in the file is refused.

## Findings

| ID | Severity | Meaning |
|---|---|---|
| TOPO-001 | info | Link reported by one end although the peer was captured |
| TOPO-002 | medium | Port mismatch between the two ends |
| TOPO-003 | medium / low | Same hostname twice (medium) or the same device uploaded twice (low) |
| TOPO-004 | info | Network devices advertised by neighbors but not captured: the list to collect next |
| TOPO-008 | low | Capture with no CDP or LLDP data |
| TOPO-009 | info | Inter-switch link in spanning-tree blocking state |
| TOPO-010 | medium / low | Bundle on one end only (medium), or parallel links that are not bundled (low) |
| TOPO-011 | low | CDP and LLDP name different neighbors on the same port (usually a stale CDP entry) |
| TOPO-007 | info | Many MAC addresses behind a port with no network neighbor (unmanaged switch, hypervisor, access point) |
| TOPO-012 | low | Two devices use different masks inside the same /30 or /31 |
| TOPO-013 | info | Captures without `show cdp/lldp neighbors detail`: names the devices to re-collect |
| TOPO-014 | info | A MAC learned on edge ports of two switches (moved host, or a link that lacks CDP/LLDP); not raised for the same MAC behind a vPC port-channel of both peers |
| TOPO-015 | low | Port-channel member with no CDP/LLDP neighbor while its siblings have one |
| TOPO-016 | medium | Port-channel member not bundled (`D` down, `s` suspended, `I` individual, `H` hot-standby ...) while the bundle is otherwise in use. Flags: https://www.cisco.com/c/en/us/support/docs/lan-switching/link-aggregation-control-protocol-lacp-8023ad/221051-troubleshoot-link-aggregation-control-pr.html |
| TOPO-017 | low / medium | Rated speed differs across a link (low) or inside a bundle (medium) |
| TOPO-018 | medium | Native VLAN differs between the two ends of a trunk (own tables, or own table versus the CDP/LLDP advertisement). Discussion: https://community.cisco.com/t5/switching/cdp-4-native-vlan-mismatch-native-vlan-mismatch-discovered-on/m-p/3324797 |
| TOPO-019 | medium | A captured vPC switch reports peer, keep-alive, consistency, peer-link or a vPC member that is not healthy (only from a capture that contains `show vpc`) |
| TOPO-020 | low | vPC peer-link with one member. Cisco community knowledge base recommends at least two 10G links on separate line cards: https://community.cisco.com/t5/networking-knowledge-base/nexus-vpc-recommendations/ta-p/3130797 |
| TOPO-021 | info | vPC switch whose peer was not captured |
| TOPO-022 | info | Devices carried over from a previous run |
| TOPO-023 | info | Port-channel with every member down (unused bundle) |
| TOPO-024 | low / medium | Capture without a configuration command; medium when the first commands scrolled out of the terminal buffer (the capture starts mid-session). Raise the scrollback or log the session to a file and collect again |
| TOPO-025 | low | A link end runs below the rating of its port or transceiver (a 10G port at 1G). Negotiation and speed settings: https://www.cisco.com/c/en/us/support/docs/lan-switching/ethernet/10561-3.html |
| TOPO-026 | medium | The two ends of a link run different duplex (one end hard-coded, the other auto-negotiating). Same document as TOPO-025 |

## Version 0.4: negotiated speed, wireless clients, Aruba CX

- **Speed source.** `show interface status` (Cisco, `a-` prefix = auto-negotiated) and AOS-CX `show interface` give the speed and duplex a port runs at; `links.csv` now has `speed_a/b` (running, else rated), `rated_a/b`, `duplex_a/b` and `port_state_a/b`. Bundle labels use running speeds. Only up ports carry a running speed.
- **Wireless clients.** MACs learned on a port that faces an access point (CDP capability `Trans-Bridge`, LLDP `W`, name or model rules) are counted as wireless clients of that access point: no TOPO-007 / TOPO-014 for them, `device.wireless_clients` in `topology.json`, and the Behind devices table lists the access point with role `ap`.
- **CDP capabilities.** `Capabilities:` of `show cdp neighbors detail` feeds the role classifier (a 3945 reporting `Router Source-Route-Bridge Switch` is a router, an AP reporting `Trans-Bridge` an access point).
- **CDP / LLDP on the same port.** When one neighbor is reported by both protocols under two names (Meraki and Cisco access points report a MAC in CDP and a name in LLDP), the two rows are merged instead of drawing two devices.
- **Aruba AOS-CX.** `show system` supplies model, serial, base MAC and AOS-CX version (own MAC is excluded from the host list); STP rows with role `Disabled` are no longer read as blocking (TOPO-009 false positive); `show interface` supplies speed, duplex, description and bundle. TOPO-013 does not ask Aruba/Huawei captures for `show cdp neighbors`.
- **TOPO-010** is not raised when the end without a bundle did not capture `show lacp` / port-channel summary: the bundle may exist there.
- **Preview.** Zoom (+ / - / fit), Ctrl+wheel, drag to move and "Open in new tab" for large diagrams.

## Version 0.5: logical IP view, inferred neighbors, endpoint options, label placement

- **Logical IP view** ("Diagram file contains" > "Logical IP view only"). Two devices that own addresses in the same subnet are joined by one green line labelled with the interface and address at each end (`Gi0/0/3 172.21.124.1/29` - `vlan153 172.21.124.2/29`). A subnet shared by more than two devices (an SVI VLAN, a LAN) is one yellow oval that every member connects to, labelled with the VLAN, VRF and description. Two devices that share more than three subnets (an aggregation pair with 30 SVIs) are drawn as one line "N shared subnets"; the tables list every address. Loopbacks, /32 addresses, `mgmt0`/OOB, `vmanage` and shut-down interfaces are not links. A subnet is matched by network address only, because VRF names are local to a device. A device nobody captured (an access point, a provider router) joins when an ARP table gave its address and the address falls inside a captured interface's subnet. Under the picture, every device with two or more interface addresses gets a table: interface, description, address/prefix, VRF, state (secondary addresses included). Use it to follow the route of a packet: device, interface, next subnet, next device. The page also exists in the SVG preview, the HTML report and the draw.io file (tables are HTML-table text cells you can edit). /31 point-to-point links are read as two-member subnets (RFC 3021: https://www.rfc-editor.org/rfc/rfc3021).
- **Neighbors without CDP/LLDP** (TOPO-027, low). **Order of trust: CDP/LLDP, then ARP, then MAC address, then port description.** A port that has a CDP/LLDP line is never touched. On any other physical port the first source that names a device wins: (1) ARP: an address on the port that belongs to a known device; (2) MAC address: every MAC learned on the port (at most 8) belongs to one device, found by its chassis MAC or through someone's ARP table; a port that also carries hosts says nothing; (3) the interface description. When the lower sources agree with the chosen one they are added to the evidence (`ARP+DESC`); when they name another device the finding says so (TOPO-028). Only when no known device is found does a lone ARP peer on a routed port, or a description that looks like a device name, create a new grey box. In detail, a routed physical port with no CDP/LLDP line gets a teal dashed line when (a) its interface description names a device and port (`WANR2 G0/1/2`, `to JAS-1-LT-1A`; the name is matched to a captured device first, by full name then by distinctive fragment, otherwise a new grey box is drawn) and/or (b) the ARP table on that port holds exactly one peer whose address belongs to a captured device or sits on a /29-/31 link (ARP maps IPv4 address to MAC address: https://www.rfc-editor.org/rfc/rfc826). ARP tables of every VRF (`show ip arp`, `show ip arp vrf <name>`) are read. Providers named in a description (LINTASARTA, TELKOM, ISP, MPLS, INTERNET...) become cloud boxes. Descriptions that name servers, PCs, printers, cameras, ATMs, phones or other endpoints never create a device; a pair already joined by a CDP/LLDP line is skipped. The evidence (`ARP`, `DESC`) is in the line's tooltip, `links.csv` and the finding. This is evidence, not proof: a stale ARP entry or a wrong description can mislead, so the line is dashed teal and the finding says what to verify. Switch off with "Infer neighbors from ARP and port descriptions".
- **TOPO-028 (low): description names another device.** A port whose CDP/LLDP neighbor (or inferred neighbor) is not the device its description names, for example `Gi2/0/45` described as `AP-6` but facing `AP-7`, or a description that still names the old switch after a move. The line follows the device data; fix the description or the cabling.
- **Topology name and creation time.** The optional box "Topology name" prefixes every download (`Panin-DC-topology.drawio`, `Panin-DC-links.csv`, `Panin-DC-keystone-topology-pack.zip`); letters, digits, `.`, `_`, `-` are kept, spaces become `-`, 60 characters at most; empty keeps the current names. The name is also the title of the HTML report and of every draw.io page, and every draw.io page shows `Topology Created at Date YYYY:MM:DD - Time HH:MM:SS` (local time of the Keystone computer) under it, above the devices.
- **Roles from CDP capabilities.** `Router Switch` is a layer-3 switch, `Router Source-Route-Bridge` a router, `Trans-Bridge` / `WLAN` an access point. AOS-CX LLDP descriptions such as `HPE ANW JL724B ML.10.16.1020` are split into model `JL724B`, version `ML.10.16.1020`, vendor Aruba, and Aruba/HPE `JL` models are switches. Previously an Aruba CX switch seen only by its neighbor was drawn as a router. F5 BIG-IP, NetScaler, `LB/SLB/GSLB/LTM/GTM/ADC` names get the load-balancer role and icon.
- **Exclude IP phones and PCs.** Leaves phones, hosts and servers out of the pictures (and the boxes that stand for several of them) so only routers, firewalls, load balancers, switches and access points remain; tables and CSV still list them. **Collapse phones and hosts** now folds only phones and hosts; **Collapse access points** is a separate option, so each access point can be drawn with its own hostname, model and IP address in a detailed diagram.
- **Grouping by the first one, two or three hostname words** (`JKT`, `JKT-A02`, `JKT-GD1-LT1`). On the overview page each group is a black frame. The group with the most lines to other groups sits in the middle cell of a square grid, the groups linked to it most are next to it, the rest further out, "Other devices" last; cells are as wide as the widest frame of the column, so frames never overlap. Inside a group, the device with the most connections of a row is moved to the middle of that row when that adds no line crossing.
- **Option defaults and the form.** On: exclude IP phones/PCs/servers, collapse phones and hosts (hidden while exclude is on), show port names, infer neighbors, add routed /30 and /31 links, leave management links out. Collapse access points is on too (clear it to draw each access point on its own). Off: draw end hosts (hidden while exclude is on). The form lists the topology name first, then the options, then the device captures; the diagram settings and the earlier-work files are in the right column.
- **`run-settings.txt`.** Every run writes the options it was built with (each option on/off with its label, grouping, file contents, line style, whether a previous run or layout was used), the topology name, the creation time and the tool version. It is in the pack, a separate download, `topology.json` (key `build`) and the HTML report (section Build options). Attach it to a question or a bug report instead of describing the page.
- **Line style** defaults to rated speed (1G, 10G, 25G, 40G, 100G).
- **Spacing and label placement.** The horizontal step grows with the longest label, rows get more room when many lines leave a device, and long endpoint rows wrap into staggered sub-rows. Each port, bundle and subnet label tries several distances and offsets along its own line and takes the first position that is free of icons, hostname text and other labels; the SVG preview and the draw.io file use the same positions. Port lists longer than 30 characters are shown as `N ports` (full list in the tooltip, tables and draw.io data). Labels have a white outline so they stay readable over lines.
- **AOS-CX.** `interface vlan 130` (with a space) is a routed interface in the Switch Analyzer, so its address reaches the IP view.

## Limits of version 0.5

- The IP view shows what the captures say: static or DHCP addresses on interfaces, ARP entries and descriptions. It does not read routing tables, so it shows which devices share a subnet, not which route a packet takes. HSRP/VRRP virtual addresses are listed in the tables when the interface carries them as secondary addresses; they are not drawn as members.
- A very large VLAN (more than 24 SVI members) is drawn with the first 24 members; the tables list all of them.
- Inferred neighbors need ARP, a MAC table or descriptions to be in the capture (`show ip arp`, `show ip arp vrf <name>`, `show mac address-table`, `show running-config`); a router captured without them stays without neighbors. MAC evidence only works for devices whose chassis MAC is reported or whose address appears in an ARP table of a captured device.

## Limits of version 0.4

- The vPC view needs both switches of a pair in the capture set; a pair with one switch missing is drawn as a normal switch and TOPO-021 names it. MLAG pairs of other vendors are framed only when the capture tells the builder about the pair (today: Cisco vPC).
- Rated speeds come from the transceiver or the port name (transceiver data is required for NX-OS `Ethernet` ports); running speeds only from `show interface status` / AOS-CX `show interface` and only for ports that are up.
- The saved state grows with the MAC and ARP tables (about 0.5 MB for six Nexus switches); files above 120 MB are refused.
- PDF is produced by printing the HTML report in the browser; Keystone itself does not render PDF.

- LLDP identity (chassis ID, management address, system serial) is read for Cisco IOS XE and NX-OS, Huawei VRP and ArubaOS-Switch detail output. Other vendors keep neighbor name and ports, so identity falls back to hostname.
- Hosts and routed links depend on the MAC, ARP and interface-address commands being in the capture; the Devices table shows which captures have CDP, LLDP and a MAC table.
- Routed links in the physical view are inferred only from /30 and /31 networks; larger shared subnets (SVI/VLAN segments) are drawn in the logical IP view.
- No live CDP crawl; Keystone reads captures only.
- The preview is a simplified drawing; the `.drawio` file is the deliverable. In very dense tiers a few lines can still cross, which draw.io lets you re-route by hand.

## References

- draw.io file format and style keys: https://www.drawio.com/doc/faq/drawio-style-reference
- Cisco CDP commands: https://www3-realm.cisco.com/en/US/docs/ios-xml/ios/cdp/command/cdp-cr-a1.html
- Cisco LLDP-MED: https://www3-realm.cisco.com/en/US/docs/ios/cether/configuration/guide/ce_lldp-med.html
- IEEE 802.1AB (LLDP): https://1.ieee802.org/maintenance/p802-1ab-2016-revision-station-and-media-access-control-connectivity-discovery/
- Nexus 9000 vPC: https://www.cisco.com/c/it_it/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html
