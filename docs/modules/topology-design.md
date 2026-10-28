# Topology Builder: design plan

Status: draft for review (2026-10-20). Nothing in this document is implemented yet.
Scope: a new Keystone module that reads the device captures an engineer already collects (CDP and LLDP neighbors, MAC and ARP tables, port-channel, vPC and STP state) and builds a network topology as a draw.io (`.drawio`) file, plus a link table and findings.

## 1. Why, and the one decision that matters

Drawing a topology from captures is repetitive, rule-based work. Done by hand or through a chat assistant it costs the same effort and tokens every time. Done by code it costs nothing per run and gives the same answer for the same input.

Decision: build it as a **module inside Keystone** (`features/topology/`), not a separate app. Reasons:

- The expensive part already exists. Keystone parses CDP, LLDP, ARP, MAC, port-channel, vPC/M-LAG, STP and stack data for Cisco IOS and IOS XE, NX-OS, Huawei VRP and Aruba, one device at a time (section 3).
- The upload page, collect lists, redaction, Excel export, tests and local-only security model are reusable as they are.
- At run time it is deterministic Python: no network call, no token cost. Claude is needed only to write it and to fix a parser when a new platform prints something unexpected.

## 2. Goals and non-goals

Goals

| ID | Goal |
| --- | --- |
| G1 | From N captures, produce one topology: devices, links with both port names, port-channels, vPC/M-LAG/stack groups. |
| G2 | Write it as an editable `.drawio` file that opens in draw.io (diagrams.net) with a sensible layout, a legend and per-device data. |
| G3 | Say how sure each link is (confirmed by both ends, reported by one end, inferred) and why. Never draw a guess as a fact. |
| G4 | Place end hosts from MAC and ARP tables on the access port where they really attach, collapsed when there are many. |
| G5 | Show the layer 3 view: gateways, subnets, routed links, FHRP and routing neighbors. |
| G6 | Report what is missing or wrong: single-sided links, port mismatches, native VLAN or duplex mismatch, neighbors not captured, devices with no neighbor data. |
| G7 | Re-run on a newer capture without losing manual layout work, and show what changed. |

Non-goals (for now)

- Live discovery by SNMP or SSH crawling. A read-only crawler is an optional last phase (section 15) and is a different risk class.
- A full IPAM or CMDB. The output is a diagram and tables, not a database of record.
- Wireless client topology, SD-WAN overlay drawing, and firewall rule maps. Router and firewall devices appear as nodes; their internals stay in their own analyzers.
- Pixel-perfect auto layout for networks above a few hundred nodes on one page. Large networks are split into pages (section 8.5).

## 3. What Keystone already provides, and what is missing

| Need | Already in the repo | Gap |
| --- | --- | --- |
| Split a terminal log into commands, strip prompts, tolerate abbreviations | `analyzer_core/capture.py`, `switch_analyzer/command_names.py` | none |
| Vendor and device identity | `switch_analyzer/fingerprint.py`, `analyzer_core/vendor_hint.py`, `analyze()` returns `hostname`, `vendor`, `serials`, `inventory` | the chassis base MAC is not parsed anywhere today; where it comes from differs per platform and must be read from real captures (section 17) |
| CDP neighbors (brief and detail) | `runtime_parser._parse_cdp_detail` returns `neighbor_id, local_interface, remote_interface, platform, management_address, capabilities, software, native_vlan, duplex, holdtime` | none for switches; the router analyzer (`runtime_health.parse_cdp_detail`) uses different key names |
| LLDP neighbors | Cisco, Huawei, ArubaOS-Switch and AOS-CX detail parsers exist | Cisco, Huawei and ArubaOS-Switch rows keep `neighbor_id`, `local_interface`, `remote_interface`, `platform` only. **Chassis ID, port ID subtype, port description, management address and capabilities are dropped**, and those are what make matching reliable. AOS-CX (`aoscx.parse_lldp`) already keeps `chassis_id`, `management_address`, `port_description`, `ttl`, `capabilities`, `port_vlan` |
| ARP and MAC tables | `live_state.parse_arp`, `parse_mac_table` (IOS, NX-OS, Aruba, Huawei layouts; `is_system_mac`) | none; tables are per device |
| Port-channels, vPC/M-LAG, stack, STP | `port_channels`, `vpc_mlag`, `inventory.stack`, `spanning_tree` in the `analyze()` result | none |
| Router interfaces, ARP, OSPF and BGP neighbors | `router_analyzer` (`runtime.py`, `runtime_routing.py`, `ospf.py`) | none |
| Collect lists | `static/collect-scripts/` already runs CDP/LLDP detail, MAC, ARP, EtherChannel / port-channel, vPC, STP root on Catalyst, Nexus and routers | `show interfaces trunk`, `show interfaces status` where absent; see 4.2 |
| Excel export, compare, findings schema | `analyzer_core/export.py`, `compare.py`, `findings.py`, `result.py` | a `graph` view for the result schema |
| Secret redaction | `analyzer_core/redaction.py` (credentials only) | **anonymization of hostnames and IPs does not exist**; see section 14 |
| Multi-file upload | `analyzer_core/blueprint.py` (limit `MAX_FILES = 16`) | a ZIP or folder upload with a higher limit |
| Graph, layout, draw.io writer | none | the module itself |

## 4. Inputs

### 4.1 What the user provides

- One capture per device (the terminal log saved after pasting the collect list), several files at once or one ZIP. A file may hold more than one device (a jump-host session); the module splits by the dominant prompt host and warns when it cannot.
- Optional: a small mapping text for sites (`hostname-pattern = site name`) and for role overrides (`SW-CORE-01 = core`).
- Optional: the previous run's `.layout.json` (section 8.6).

### 4.2 Capture checklist per platform

Checked against the collect lists in `static/collect-scripts/` on 2026-10-20. "Not in list" means the current list does not run it; the module still works without it but loses that layer (section 7). All commands are read-only.

| Purpose | Catalyst (IOS XE) | IOS XE router | Nexus (NX-OS) | Huawei S/L/E and H | Aruba AOS-CX | ArubaOS-Switch |
| --- | --- | --- | --- | --- | --- | --- |
| Identity | `show version` | `show version` | `show version`, `show module` | `display version` | `show version`, `show module` | `show version` |
| CDP detail | `show cdp neighbors detail` | `show cdp neighbors detail` | `show cdp neighbors detail` | n/a | n/a | `show cdp neighbors` (brief only) |
| LLDP detail | `show lldp neighbors detail` | **not in list** | `show lldp neighbors detail` | `display lldp neighbor` | `show lldp neighbor-info detail` | `show lldp info remote-device detail` |
| Bundles | `show etherchannel summary` | `show etherchannel summary` | `show port-channel summary` | `display eth-trunk` | `show lacp interface`, `show lacp aggregate` | not in list |
| vPC / M-LAG / VSX / stack | `show switch` (stack) | n/a | `show vpc`, `show vpc brief` | `display stack` (S/L/E); `display m-lag ...` (H series) | `show vsx status`, `show vsx brief` | n/a |
| MAC table | `show mac address-table` | n/a | `show mac address-table` | `display mac-address` | `show mac-address-table` | `show mac-address` |
| ARP | `show ip arp` | `show ip arp` | `show ip arp` | `display arp` | `show arp` | `show arp` |
| Port state and speed | `show interface status` | **not in list** | `show interface status` | `display interface brief` | `show interface brief` | not in list |
| Trunks | `show interface trunk` | **not in list** | `show interface trunk` | `display port vlan` | `show interface trunk` | not in list |
| STP | `show spanning-tree root` | n/a | `show spanning-tree root` | `display stp brief` | `show spanning-tree` | in list |
| L3 interfaces | `show ip interface brief` | `show ip interface brief` | `show ip interface brief` | `display ip interface brief` | `show ip interface brief` | not in list |
| FHRP | `show standby brief`, `show vrrp brief` | `show standby brief`, `show vrrp brief` | `show hsrp brief`, `show hsrp all` | `display vrrp` | **not in list** | n/a |
| OSPF neighbors | `show ip ospf neighbor` | `show ip ospf neighbor` | in list | `display ospf peer` | `show ip ospf neighbors` | n/a |
| BGP neighbors | not in list | `show ip bgp summary` | in list | not in list | not in list | n/a |

The first diagram needs only CDP/LLDP detail (plus MAC and ARP for hosts). Bundles, groups, port state, trunks and L3 add the later layers. The Huawei and Aruba rows will be read against real captures before phase 1; the list entries come from lists that earlier sessions already checked against real captures.

## 5. Architecture

```
captures (txt / zip)
   |
   v
ingest.py      split files into DeviceCapture (one per device), detect vendor
   |
   v
extract.py     per device: call the existing parsers -> DeviceFacts
   |           (neighbors, interfaces, port-channels, vPC/M-LAG, stack, STP, MAC, ARP, L3, serial, base MAC)
   v
names.py       canonical interface names (Gi1/0/1 = GigabitEthernet1/0/1; Huawei GE1/0/1, Eth-Trunk1, XGE, 25GE ...)
identity.py    DeviceIndex: every name, IP, MAC and serial that identifies a device
   |
   v
links.py       neighbor rows -> half-edges -> pair them -> Link(confirmed | single-sided | conflict)
bundles.py     group member links into logical links; group vPC / M-LAG / VSX / stack into domains
endpoints.py   MAC + ARP -> hosts on edge ports; collapse; infer unmanaged devices
l3.py          SVI / routed interface -> subnets; gateway and FHRP; point-to-point subnet matching
roles.py       tier (core / distribution / access / edge / WAN / firewall / wireless) with explainable score
   |
   v
Graph (JSON, deterministic ids)  ---> findings.py (TOPO-xxx)
   |
   +--> layout.py   tiers, ordering, containers, optional .layout.json reuse
   +--> drawio.py   .drawio XML (pages, nodes, edges, legend)
   +--> svg.py      the on-screen preview (same coordinates)
   +--> exporters   CSV link table, Excel workbook, graph JSON
```

Package layout:

```
features/topology/
  __init__.py  routes.py  service.py
  ingest.py  extract.py  names.py  identity.py
  links.py  bundles.py  endpoints.py  l3.py  roles.py
  layout.py  drawio.py  svg.py  findings.py  anonymize.py
  exporters/  (csv, xlsx, json)
templates/topology.html
static/js/topology.js
tests/test_topology_*.py
tests/fixtures/topology/<lab-name>/*.txt      (synthetic only)
docs/modules/topology.md                     (this plan, kept current)
```

First version of `extract.py` calls `switch_analyzer.service.analyze()` and `router_analyzer` for each capture and reads the fields in section 3. That is slower than calling the low-level parsers directly, but it is already tested on every platform. Optimize only if a 200-device run is too slow.

## 6. Data model

Ids are deterministic (a short hash of device key, port or pair) so two runs on the same input give the same ids.

```
Device     id, hostname, domain-stripped name, vendor, os_family, model, serial(s), base_mac,
           mgmt_ips[], all_ips[], role, tier, site, group_id, captured (true) | stub (false),
           stack_members, source_file, facts_coverage{cdp, lldp, mac, arp, stp, lacp, l3}
Port       device_id, name (as printed), canonical name, kind (physical | bundle | svi | mgmt),
           speed, duplex, state, mode (access | trunk | routed), vlan / allowed vlans, native vlan,
           bundle_id, description, stp_state
HalfEdge   from device + port, protocol (CDP | LLDP), remote name, remote port (+ subtype), remote chassis id,
           remote mgmt ip, platform, capabilities, native vlan, duplex
Link       id, a_device, a_port, b_device, b_port, protocols[], state, evidence,
           confidence (confirmed | single-sided | inferred-l3 | conflict), bundle_id, notes[]
Bundle     id, name per side (Po1 / Eth-Trunk1), protocol (LACP | static), members[], speed sum, kind (access | peer-link | stack)
Group      id, kind (vpc | mlag | vsx | stack | vss | fex), member devices, peer-link, keepalive
Endpoint   mac, ips[], vlan, device_id, port, count of hosts behind port, kind (host | unmanaged-switch | ap | phone | unknown)
Subnet     cidr, vlan, gateways[] (device + interface + FHRP vip + state), members[]
Finding    id (TOPO-nnn), severity, title, detail, refs[] (device ids, link ids)
```

## 7. Algorithms

### 7.1 Interface name canonicalization (`names.py`)

One function per vendor family maps every spelling to one key: `Gi1/0/1`, `Gig1/0/1`, `GigabitEthernet1/0/1` and Huawei `GE1/0/1` are the same port class; `Eth1/1` and `Ethernet1/1` on NX-OS; `Po1`, `Port-channel1`, `Eth-Trunk1`; Aruba plain numbers (`25`, `1/1/25`). The existing `service._canonical_interface_key` is the starting point. Keep the printed name for display and the canonical key for matching. An LLDP port ID that is a MAC address (port ID subtype 3 in IEEE 802.1AB) or a bare number (the ArubaOS-Switch 2540 neighbor in the existing fixtures advertises port `25`) is resolved against the peer's port table.

### 7.2 Identity resolution (`identity.py`)

For every captured device build the set of names that identify it: hostname with and without domain, all interface IPs, base MAC and interface MACs, serial numbers. A neighbor is matched to a device by the first rule that hits, and the rule is recorded as the evidence:

| Order | Evidence | Confidence |
| --- | --- | --- |
| 1 | Neighbor chassis ID equals a known device MAC | high |
| 2 | Neighbor management address equals a known device IP | high |
| 3 | Neighbor system name or CDP device ID equals a known hostname (case-insensitive, domain stripped, `hostname(SERIAL)` form handled, truncated prefix accepted only when unique) | medium |
| 4 | Serial number in the CDP device ID equals a known serial | high |
| none | the neighbor becomes a **stub** device (not captured) with the data it advertised | n/a |

Two captured devices claiming the same hostname are reported (TOPO-003), not merged.

### 7.3 Half-edges to links (`links.py`)

1. Each neighbor row becomes a half-edge from the capturing device.
2. Two half-edges describe the same link when they point at each other (A.port to B.port and B.port to A.port) after canonicalization. CDP and LLDP rows for the same port pair merge into one link carrying both protocols.
3. A pair becomes **confirmed**. A half-edge with no partner becomes **single-sided**: the peer is not captured, does not run the protocol, or advertised a different port. If the peer is captured and has a row for that local port pointing elsewhere, the pair is a **conflict** (stale entry, miscabling, or a port-ID mismatch) and both rows are shown.
4. Parallel links between the same two devices stay separate until section 7.4 groups them.

### 7.4 Bundles and groups (`bundles.py`)

- Links whose local ports are members of the same port-channel (EtherChannel, Eth-Trunk, LAG) on one side are folded into one logical link labelled `Po1 (2x10G, LACP)`. The member list stays in the link's data. If only one side has bundle data the label says so; if the two sides disagree on the member count it is a finding (TOPO-010).
- Without any bundle data, parallel links between the same pair are still drawn as one thick line labelled `2 links`, marked as unverified.
- vPC (NX-OS), M-LAG (Huawei), VSX (Aruba), VSS and stacks become a **group**: the member devices sit inside one container, the peer-link and keepalive are drawn differently from normal links, and downstream bundles that terminate on both members are drawn to the container, not to one member.
- FEX and virtual chassis members are folded into the parent device when the capture says so.

### 7.5 End hosts (`endpoints.py`)

MAC tables are noisy: every switch on the path learns the same MAC. The **edge-port rule**:

1. Drop system and CPU entries (`is_system_mac`), the device's own MACs, and entries on ports that are an inter-switch link or a bundle member of one.
2. For each remaining MAC, the attachment point is the device where the MAC sits on a port with no switch neighbor. When two devices qualify (for example an unmanaged switch in between that neither sees), report the ambiguity instead of choosing.
3. Join ARP (MAC to IP) from the routers and SVIs that hold it. A host with no ARP entry is shown by MAC.
4. Collapse by port: 1 to 3 hosts are drawn; more than a threshold (default 8) become one `N hosts (VLAN x, y)` node; a port with many MACs and no CDP/LLDP neighbor is labelled **probable unmanaged switch or hypervisor** (TOPO-007).
5. Neighbors that advertise a phone or access point capability become typed nodes (icon only), not generic hosts.
6. Entries come from snapshots; the page states the capture time and that aged-out hosts are missing.

An OUI vendor lookup would improve labels, but needs the IEEE registry shipped offline. Treat it as optional and decide separately (licensing, size).

### 7.6 Layer 3 view (`l3.py`)

- Every SVI or routed interface with an IP gives a subnet. A subnet node connects to the devices that have an address in it. The gateway is the FHRP virtual IP if present, with the active and standby member from `show standby`, `show vrrp` or `display vrrp` when captured.
- Two captured devices with addresses in the same /30 or /31 produce an **inferred L3 link** (medium confidence), because point-to-point links often run without CDP or LLDP. Mask mismatches on such a pair are a finding.
- OSPF and BGP neighbors from routers and L3 switches are drawn as dotted adjacency lines on the L3 page, labelled with protocol and state.
- VRFs: one subnet node per VRF and CIDR; the VRF name is shown.

### 7.7 Roles and tiers (`roles.py`)

Each device gets a numeric score from explainable inputs, and the page shows why:

| Signal | Pushes toward |
| --- | --- |
| Routing protocols running, many SVIs, FHRP active, STP root for many VLANs | core / distribution |
| Many downlinks to switches, few uplinks | distribution |
| Many access ports with hosts, uplinks only | access |
| Platform family (Nexus 9K or 7K, Catalyst 9500 vs 9200 or 2960) | core vs access |
| Router platform, WAN-facing IPs or BGP | edge / WAN |
| Firewall, load balancer or controller platform | their own tiers |
| Hostname regex (default `core|dist|agg|acc|edge|fw|rtr|wlc` and a user list) | any |
| User override file | any (always wins) |

### 7.8 Layout (`layout.py`)

Layered drawing, written in Python without new dependencies:

1. Tiers from roles, top to bottom: WAN / edge, firewalls, core, distribution, access, endpoints.
2. Order nodes inside a tier with a few barycenter sweeps to reduce crossings; vPC / M-LAG / stack groups stay adjacent in one container.
3. Coordinates on a 10-unit grid; node width from label length; fixed tier gap.
4. Stub devices and endpoint blocks go under their parent.
5. Pages: one **Overview** page (sites and inter-site links), one **L2** page per site, one **L3** page per site or per VRF. Site assignment: user mapping, else hostname prefix before the first delimiter, else connected components. A single page is used when the network has at most 60 nodes.
6. If a `.layout.json` from an earlier run is supplied, nodes with a known id keep their stored coordinates and only new nodes are placed.

## 8. draw.io output

### 8.1 File structure (confirmed from the draw.io documentation)

A `.drawio` file is XML: `mxfile` containing one `diagram` per page; each has an `mxGraphModel` whose `root` holds the cells. Cell `id="0"` is the root and `id="1"` is the default layer (`parent="0"`); all other cells use `parent="1"` or a container id. A cell is either a vertex (`vertex="1"`) or an edge (`edge="1"`). An edge names existing vertex ids in `source` and `target` and has `<mxGeometry relative="1">`. Files are written uncompressed. Groups are `swimlane` containers. Cisco stencils are referenced as `shape=mxgraph.cisco.*` or `mxgraph.cisco19.*`. Source: draw.io style reference (section 17).

### 8.2 Nodes

- One vertex per device: rounded rectangle, fill by vendor family, a second label line with model and management IP, and a role badge. Stubs use a dashed outline and a lighter fill.
- Per-device facts (hostname, vendor, model, serial, version, mgmt IP, source file, confidence) are stored as custom properties on the cell so Edit Data in draw.io shows them.
- Optional icon style: a mapping dictionary from role to Cisco stencil name. Until the exact names are checked in a real draw.io (section 8.7), the default is the plain labelled rectangle, so a wrong stencil name can never break a file.
- Groups (vPC, M-LAG, VSX, stack, site) are containers; their members are children.

### 8.3 Edges

- One edge per link or bundle, orthogonal routing, labelled at both ends with the local port names and in the middle with the bundle and speed (`Po1 · 2x10G`).
- Style carries meaning: solid = confirmed by both ends; dashed = single-sided or inferred; red = conflict or down; thick = bundle or 10G and above; dotted = L3 adjacency; a distinct style for vPC peer-link, keepalive and stack links.
- Edge ids derive from the two device ports, so a re-run updates the same edge.

### 8.4 Legend and metadata

Every page carries a legend (line styles, colors, role badges), the capture time range, the Keystone version and the number of captured devices, stubs and links. This matters when a diagram is attached to a handover document.

### 8.5 Size

A page is kept to about 60 to 100 nodes. Larger networks produce an Overview page with site boxes and one detail page per site, linked by the same hostnames in labels.

### 8.6 Re-runs and diff

- The generator also writes `<name>.layout.json` (node id to x, y). Feeding it back preserves the arrangement the engineer fixed by hand.
- A second capture set can be compared with the first: added and removed devices, links that appeared or vanished, bundles whose members changed. The result reuses `analyzer_core/compare.py`.

### 8.7 Verified and still to verify

| Item | Status |
| --- | --- |
| `mxfile` / `diagram` / `mxGraphModel` / `root`, cells 0 and 1, vertex and edge, source and target, relative geometry, uncompressed XML, swimlane containers, `mxgraph.cisco.*` and `mxgraph.cisco19.*` shape prefixes | confirmed in the draw.io style reference |
| Exact stencil names for L2 switch, L3 switch, router, firewall, wireless controller, access point | prototype check: place each in draw.io, read the name in Edit Style, store it in the icon table |
| Port labels at the two ends of an edge as child label cells with relative positions | prototype check in draw.io desktop and in the web app |
| Custom properties on a cell (an `object` wrapper) showing under Edit Data | prototype check |
| Rendering of the generated file in the current draw.io desktop release | manual check on every phase; optionally an automated PNG export in CI |

## 9. Other outputs

- On-screen preview: an SVG built from the same coordinates (pan, zoom, click a node or a link for its facts). It works without draw.io.
- `links.csv`: device A, port A, device B, port B, protocols, bundle, speed, confidence, evidence.
- Excel workbook through `analyzer_core/export.py`: Devices, Links, Bundles and groups, Endpoints, Subnets, Findings, Coverage.
- `graph.json`: the full model, for diffing and for other tools.

## 10. Findings

| ID | Severity | Condition |
| --- | --- | --- |
| TOPO-001 | info | Link reported by one end only (peer not captured or not running CDP/LLDP) |
| TOPO-002 | medium | Port mismatch: A says it sees B on port X, B's own table says that port faces another device |
| TOPO-003 | medium | Two captures claim the same hostname |
| TOPO-004 | info | Neighbor advertised but not captured (stub): list of captures to collect next |
| TOPO-005 | medium | Native VLAN mismatch across a link (CDP native VLAN versus the local trunk) |
| TOPO-006 | medium | Duplex mismatch across a link (CDP duplex versus local interface) |
| TOPO-007 | info | Many MACs behind a port with no neighbor: probable unmanaged switch or hypervisor |
| TOPO-008 | low | Captured device with no CDP and no LLDP data |
| TOPO-009 | info | Inter-switch link in STP blocking or discarding state |
| TOPO-010 | medium | Bundle mismatch: one side bundled and the other not, or different member counts |
| TOPO-011 | low | CDP and LLDP disagree for the same port |
| TOPO-012 | low | Two devices share a point-to-point subnet with different masks |

Severity wording follows the existing analyzers. Each finding records its evidence (the capture line it came from) so an engineer can check it.

## 11. User interface and registration

- Tool entry in `core/modules.py`: key `topology`, name "Topology Builder", group `analyze`, risk `offline`, href `/topology`, keywords `diagram, drawio, cdp, lldp, map`. `tests/test_module_registry.py` pins the registry.
- Page `/topology`: drop zone for many files or a ZIP, options (include endpoints, host collapse threshold, site mapping, role overrides, previous `.layout.json`), then Run.
- Result: summary cards (devices, links confirmed, single-sided, conflicts, stubs, hosts), tabs **Map**, **Devices**, **Links**, **Endpoints**, **L3**, **Findings**, **Coverage** (which command was missing in which capture and what that costs), and a **Download .drawio** button.
- The multi-file route is a small custom blueprint; it reuses `decode_bytes`, the upload limits style and the result validator, not the single-file `create_analyzer_blueprint`.
- Docs: README tool table row, PANDUAN section, `docs/modules/topology.md`.

## 12. Changes needed in existing code

| File | Change | Risk |
| --- | --- | --- |
| `switch_analyzer/runtime_parser.py` (Cisco LLDP detail) | Keep `chassis_id`, `port_id_subtype`, `port_description`, `management_address`, `capabilities`, `system_description` in the row. Absent keys stay absent, as was done for CDP detail | low; existing tests pin the current keys |
| `switch_analyzer/runtime_parser.py` (Huawei LLDP detail) | Same fields (the block already prints Chassis ID, Port ID, Port description, System name, serial, model) | low |
| `switch_analyzer/runtime_parser.py` (ArubaOS-Switch LLDP detail) | Same fields. It already skips the duplicate `local` chassis-type block; keep that rule | low |
| `switch_analyzer/aoscx.py` (`parse_lldp`) | none; it already returns the full set. Aruba neighbors advertise bare port numbers, so port-ID resolution (7.1) must handle them | none |
| Router CDP parsers (`router_analyzer/runtime_health.py`) | none; `topology/extract.py` adapts the key names into the shared half-edge shape | none |
| `switch_analyzer/service.py` result | Add the chassis base MAC to `inventory` or `serials` where the capture prints it (source per platform to be confirmed on real captures) | low |
| `static/collect-scripts/*` | Router IOS XE list: add `show lldp neighbors detail`, `show interface status`, `show interface trunk` where the platform supports them. AOS-CX list: add a FHRP command. Bump each list's version header | none |
| `analyzer_core/blueprint.py` | none; a separate multi-file blueprint is added | none |

## 13. Test and validation strategy

- **Synthetic lab fixtures** in `tests/fixtures/topology/<lab>/`: for example a Nexus vPC pair, two Catalyst access switches (one a stack), one IOS XE router with an SVI gateway and a /30 to a second router, one unmanaged switch with five hosts, one AP and one phone. Hostnames and addresses are invented (documentation ranges). Real customer captures stay outside the repo, as before; the existing `tests/fixtures/real_captures/mask_capture.py` is the starting point for masking a real capture into a synthetic one.
- **Unit tests** per module: name canonicalization table, identity ladder (each rung alone and in conflict), half-edge pairing (confirmed, single-sided, conflict), bundle folding, edge-port rule on a three-switch chain, subnet inference, role scoring.
- **Golden graph**: the lab's `graph.json` is stored and compared as data; a change in the algorithm shows up as a diff.
- **draw.io file checks** (automated): well-formed XML, cells 0 and 1 present, ids unique, every edge's `source` and `target` exist, every vertex has geometry, no overlapping node boxes, legend present.
- **Manual check per phase**: open the generated file in draw.io desktop and read it as an engineer would; record the result in the phase notes.
- **Totals check**: for each captured device, the number of neighbors in the output equals the neighbor count the device printed (`Total cdp entries displayed`, LLDP `Total entries`), so a lost line cannot hide.
- The suite stays offline and fast; `pytest` as today.

## 14. Security and privacy

- Everything runs locally; no capture leaves the machine. The existing request guard (`core/local_guard.py`) applies to the new routes automatically.
- A `.drawio` file lists hostnames, models, addresses and cabling. Treat it as sensitive as the captures. The page says so next to the download button.
- **Anonymized export** (delivered in 1.6, `anonymize.py`): consistent pseudonyms for hostnames, domain and VRF words, port descriptions, IPs (prefix-preserving), MACs (vendor prefix kept) and serials, keeping the structure, so a diagram or a bug report can be shared. `analyzer_core/redaction.py` only hides credentials, so this is separate code. The twin is rebuilt from the pseudonymized device state, a scan of the finished files reports any original that is left, and the key `anonymization-map.csv` is written apart from the shareable pack. It does not hide the shape of the network; see "Version 1.6" in `topology.md` for the limits.
- Uploaded files go to the existing `uploads/` and are swept by the existing 30-day cleanup.

## 15. Phases

| Phase | Scope | Acceptance |
| --- | --- | --- |
| **0: spike** (small) | Cisco IOS XE and NX-OS, CDP and LLDP only, canonicalization, identity ladder, links, one L2 page, `.drawio` writer with plain labelled boxes, SVG preview, `links.csv` | On the lab fixture every link appears once with both port names; totals check passes; the file opens in draw.io desktop; the Cisco LLDP parser fields are added |
| **1: coverage** (medium) | Huawei and Aruba neighbors, bundles, vPC / M-LAG / VSX / stack groups, roles and tiers, findings TOPO-001 to 011, Excel export, Coverage tab, collect-list additions, ZIP upload, module registration, docs | Bundled uplinks draw as one labelled link; vPC pair drawn as one container; findings carry evidence; registry test and README updated |
| **2: hosts** (medium) | MAC and ARP, edge-port rule, collapse, unmanaged inference, AP and phone typing | A 3-switch chain places each host once; ambiguity reported, not guessed |
| **3: L3 and scale** (medium) | Subnets, gateways, FHRP, inferred point-to-point links, OSPF and BGP adjacency lines, site pages, `.layout.json` reuse, diff between runs, anonymized export, stencil icons after the prototype check | The L3 page matches `show ip interface brief`; re-run keeps hand-placed nodes; diff lists real changes only |
| **4: live crawl (optional, separate decision)** | Read-only crawler through Lifecycle Manager's SSH layer: seed device, follow CDP/LLDP, run the capture list, feed phases 0 to 3 | Only if requested; needs its own risk review (credentials, rate limits, scope guard) |

Phases 0 and 1 are the minimum useful product. Each phase ends with a delivered, tested slice and a project note.

## 16. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Names disagree across sources (CDP truncation, domain suffix, `hostname(SERIAL)` on Nexus, LLDP with no system name) | Identity ladder prefers chassis ID, management IP and serial over names; every match records its evidence |
| LLDP port ID is not a name (MAC, ifIndex, bare number such as Aruba `25`) | Resolve against the peer's port and MAC tables; otherwise keep the raw value and mark the link medium |
| Partial captures (a command missing or aliased) | `command_names.py` expands abbreviations; Coverage tab lists what is missing per device and what it limits |
| MAC and ARP are snapshots | Edge-port rule, aging note on the page, hosts never drawn as permanent |
| Unreadable diagrams on big networks | Pages per site, host collapse, tiers, role overrides, layout reuse |
| draw.io differences between versions | Plain, documented XML only; shapes beyond the confirmed set go through the prototype check |
| Parser drift on new software versions | Fixtures per platform; a new output shape is a parser fix plus a fixture, not a redesign |
| Sensitive data in diagrams | Local only, warning on download, anonymized export |
| Scope creep into IPAM and live monitoring | Non-goals above; phase 4 is a separate decision |

## 17. References

Confirmed by opening the pages on 2026-10-20:

- draw.io style reference for generated files (file structure, edges, Cisco stencil prefixes): https://www.drawio.com/doc/faq/drawio-style-reference
- Cisco IOS Cisco Discovery Protocol command reference (`show cdp neighbors`, `detail`): https://www3-realm.cisco.com/en/US/docs/ios-xml/ios/cdp/command/cdp-cr-a1.html
- Cisco LLDP and LLDP-MED configuration (LLDP enable, TLV control, `show lldp neighbors`): https://www3-realm.cisco.com/en/US/docs/ios/cether/configuration/guide/ce_lldp-med.html
- Cisco Nexus 9000 NX-API CLI reference, CDP commands (`show cdp neighbors ... detail`): https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/cdp-commands
- IEEE 802.1AB (LLDP) maintenance page: https://1.ieee802.org/maintenance/p802-1ab-2016-revision-station-and-media-access-control-connectivity-discovery/
- RFC 2922, Physical Topology MIB (the SNMP model of the same data, relevant to phase 4): https://www.rfc-editor.org/rfc/rfc2922
- Cisco TAC note 218333, Understand and Configure Nexus 9000 vPC with best practices (peer-link, peer-keepalive, primary and secondary roles; opened 2026-10-20, the page opened is the Italian-language copy): https://www.cisco.com/c/it_it/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html

Not yet confirmed, to be read from real device output before implementation: where each platform prints the chassis base MAC, the Huawei LLDP detail layout for stacks and M-LAG pairs beyond the S5755 sample already seen, the ArubaOS-Switch neighbor layouts other than the 2540 sample, and the exact CDP device-ID format on the Nexus models in the customer's network.

## 18. Decisions needed from the owner

| # | Question | Default if not decided |
| --- | --- | --- |
| 1 | First vendors in phase 0 | IOS XE Catalyst, NX-OS, IOS XE router (the samples you are about to provide) |
| 2 | Sites: how are they named? | Hostname prefix plus an optional mapping text |
| 3 | Draw hosts on the overview page? | Off on Overview, on in site pages, collapsed above 8 per port |
| 4 | Icons | Plain labelled boxes first, Cisco stencils after the prototype check |
| 5 | Keep manual layout between runs? | Yes, through `.layout.json` |
| 6 | Output language and naming of the tool | English, "Topology Builder" |
| 7 | Live crawl (phase 4) | Not in scope until asked |

## 19. What to provide for phase 0

- Sanitized captures from a small, real slice: at least two directly connected devices that were both captured, one Nexus vPC pair, one Catalyst access switch or stack, one router, with the commands in section 4.2 (the existing collect lists already run most of them).
- At least one port-channel, one link whose far end is not captured, one access port with several MACs, and one routed link between two captured devices.
- Optional: one draw.io diagram whose look you like, so the style (colors, line weights, labels) can be matched.
- Keep real captures outside the repository, as before (the `sample ...` folders next to the project). The synthetic fixtures are written from them by hand.
