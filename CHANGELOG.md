# Changelog

Newest first. Module versions are listed in `core/modules.py`.

## Unreleased

### LLD Index: Document Generator index from the inventory, configs and project goals

- Index workbook gets a "Project" sheet (Project Name, Customer, Project Code, Company, Prepared by) that the Document Generator imports into its project record for the master template placeholders; new "Prepared by" field.
- Replacement project: the firewall Existing Device List is filled from Existing devices (Status "Replaced by <new device>" or "Removed"); Scope of Work installs New devices only and adds dismantling; Project Description names the devices removed; Implementation Step gets a Dismantle row.
- Sidebar scrolls when the menu is taller than the screen (Document > LLD Index was out of reach on a laptop).
- Replacement project option: inventory Status column (New / Existing / Keep) and a Before and an After rack table per rack. Existing devices only appear in the Before rack; the BoQ counts New devices only.
- Rack layout tables: device cells light blue, U columns light grey, text centred (Document Generator reads `fills` and `aligns`).
- New module **LLD Index** (`/lld-index`, new sidebar group "Document"). It builds the "LLD Content Index" workbook the Document Generator imports: chapters per technology, expanded per site, per device and per model, tables filled from the inventory and from the configs, narrative written from the project goals.
- Inputs: project form (customer, project, code, goals, scope, out of scope, related documents), technologies (switch, wireless, firewall, router, load balancer), device inventory (Site, Hostname, Model, Role, Mgmt IP, SN, Config; CSV/XLSX import, template download, paste from Excel) and optional config files or a ZIP.
- Templates are JSON files in `features/lld_index/templates/` (common, switch, wireless, firewall, router, loadbalancer), editable without code. Switch, wireless and firewall follow the TAM Switch Replacement, TAM Wireless Network Improvement and Peremajaan Perangkat Firewall Palo Alto LLDs; router and load balancer are drafts until a sample exists.
- Tables come from the existing analyzers through small adapters (`datasets.py`): VLAN, interfaces and configuration blocks for switches; zones, ports, routes, objects, policies, NAT, IKE/IPsec, DHCP and more for Palo Alto and FortiGate; interfaces, VRF, static and BGP for routers; virtual servers, pools, members, monitors and profiles for F5; SSID, AP group and AP list for wireless. Model specifications come from the hardware catalog.
- Output follows the Document Generator importer exactly (checked against `lld_generator_v1.0.5/backend/importer.py`): Index header, `H#` levels, one sheet per table with at least one row (empty tables carry `TBD`), unique sheet names of at most 31 characters. Yellow Index rows still need manual content (images, TBD).
- More than one block per heading: a template node can carry `blocks` (paragraph + table + image under one heading), written as continuation rows with an empty Judul Heading. The model heading in Device Overview now has the description paragraph ("S5755-H24T4Y2CZ (...). 2 units will be used as Core Switch at HO and BR.") and the spec table, as in the existing LLDs. Needs the Document Generator multi-block importer; an older importer keeps the first block only.
- Rack layout: new inventory columns Rack, Rack Size (24/27/32/36/42/45/47/48U, blank = 42), U and U Height (blank = 1). Each rack becomes a table under Rack Layout per site (`U | rack (size) | U`, top unit first, multi-U devices as one merged cell), in the format of the Switch Replacement LLD without the power and cable columns. Overlaps and devices that do not fit are noted and left out; a site with no rack positions keeps an image slot. The page draws every rack before download.
- Docs: `docs/modules/lld-index.md`. Tests: `tests/test_lld_index.py` (20).

### Convert Firewall: guided conversion, PAN-OS reference checks, IKE/IPsec syntax fix

Guided conversion (MikroTik RouterOS to Palo Alto)
- New "Guided Conversion (step by step)" button on Convert Firewall. Ten steps in dependency order: Target, Interfaces, Zones, Routing, Objects, NAT, Security policy, VPN, Services, Review & export. Each step is checked when you press "Validate & continue"; the next step opens only when the step has no errors and its warnings are acknowledged. Download is refused until every step passes.
- Interfaces step: source port, detected role (INET from DHCP client, masquerade egress, default-route next hop or public address; LAN from DHCP server, bridge membership or private address), addresses and a target-port dropdown built from the target model. Swapping LAN and INET is two dropdown changes; zones, NAT egress, MSS, virtual router and IKE local interface follow. Source-side checks: an in-use port with no target (MAP-UNMAPPED), two sources on one port (MAP-DUP), a port the model lacks (MAP-PORT-MISSING), and a renumber list for the cutover (MAP-RENUMBER).
- Zones step: one zone per interface. A bridge member port is layer2 and takes its bridge's zone, so a renamed bridge zone also reaches rules written on a member port. A rule on a RouterOS interface list uses the zones of the list's members (`from [ A B ]` when they were split).
- VPN step: local interface per IKE gateway, zone and tunnel.N per tunnel.
- `converter_engine/wizard/pan_validator.py` reads the generated set commands back and reports what does not resolve or would not commit: undefined interfaces, zones, address objects, services, IKE/IPsec profiles and gateways; an interface in two zones; layer2/layer3 zone mismatch; overlapping subnets; ports beyond the target model; invalid names; NAT with several destination zones or `!` negation; IKE gateway without local interface; non-PAN-OS algorithm keywords; plus warnings (weak crypto, placeholder PSK, unreachable next hop, ECMP, shadowed and any-any rules, NAT egress without address). It cannot replace `validate full` on a firewall, and the export header says so.
- Sessions live under `uploads/configuration/wizard/<token>` and are removed after a day. API: `POST /configuration/api/wizard/start`, `POST /configuration/api/wizard/<token>/validate`, `GET /configuration/api/wizard/<token>/download`.

VLANs, bridges and disabled ports (Interfaces step)
- Every port, VLAN and bridge shows Enabled or Disabled from the source. A disabled physical port is written with `link-state down` and reviewed.
- New "VLAN and bridge interfaces" table. A VLAN on a bridge is either "vlan.N + tagged L2" (default) or an L3 sub-interface on a chosen port (router-on-a-stick); a VLAN on a port is an L3 sub-interface whose parent follows the port mapping. Tag and vlan.N unit are editable, and the resulting PAN-OS name is shown. A one-port bridge can be routed on its port instead of vlan.N.
- Checks: tag outside 1-4094 (MAP-VLAN-TAG), sub-interface without a mapped parent (MAP-VLAN-PARENT), two VLAN interfaces on one unit (MAP-VLAN-UNIT), two VLANs on one port.tag (MAP-VLAN-DUP), routed bridge with more than one port (MAP-BRIDGE-ROUTED); the validator adds IF-MODE for a port written as both layer2 and layer3 and checks that a sub-interface and its parent are the same layer.
- An interface named or commented WAN/ISP/INET/internet/uplink is detected as INET.
- An enabled port with nothing on it (no address, not in a bridge, no rule, NAT, DHCP or VLAN uses it) starts unmapped. "Not mapped (skip)" now really skips the port: the translator writes nothing for it (it used to auto-guess ethernet1/N and add an empty layer3 interface, a zone and a virtual-router entry) and leaves one review note. Unmapping a port that is in use is still an error.

Fixes from a debugging pass on the guided conversion
- Export could differ from the page: after an edit that was not re-checked, the stepper still opened Review as "Passed" and Download exported the last checked state. Leaving a step with unchecked edits now checks them first, and the download carries the revision of the state the page last saw checked (`?rev=`); the server refuses any other revision.
- A port in a slot the model does not have (`ethernet2/1` on a PA-505) passed. Wizard (MAP-PORT-MISSING) and validator (IF-PORT-MISSING) now check slot 1 and the port number.
- Two tunnels could be given the same tunnel.N and both bound to it without an error; a non-numeric unit silently became 1. New MAP-TUNNEL-UNIT / MAP-TUNNEL-DUP in the VPN step and VPN-TUN-DUP in the validator; an invalid unit writes no tunnel interface.
- Marking the WAN as an SD-WAN link lost the IKE gateway's local interface: the owner of the local address is now also looked up in the SD-WAN lines.
- The VPN step's local-interface list held physical ports only, so a WAN on a sub-interface (`ethernet1/1.100`), vlan.N or SD-WAN could not be picked and the error could not be fixed from the page. It now lists every layer3 interface in the output.
- A session that started more than a day ago was deleted by the next start even while in use. Every check now refreshes the session's age.

Translator fixes (all conversions, not only the wizard)
- A VLAN on a bridge was built as vlan.N with the bare bridge ports as members, while the same ports already belonged to the bridge's untagged VLAN object; PAN-OS refuses one interface in two VLAN objects. It now uses a tagged layer2 sub-interface (`ethernet1/2.20 tag 20`) on each bridge port.
- Synthetic vlan.N numbers for untagged bridges restart at 900 per conversion, so converting the same file twice gives the same output.
- IKE and IPsec now use the PAN-OS CLI paths, which follow the configuration XML: `network ike crypto-profiles ike-crypto-profiles`, `network ike crypto-profiles ipsec-crypto-profiles`, `network ike gateway`, and `auto-key proxy-id` under the tunnel. The old `network ike-gateway`, `network ike-crypto-profile`, `network ipsec-crypto-profile` and `proxy-id` without `auto-key` are rejected by PAN-OS.
- Encryption names are PAN-OS keywords (`aes-256` becomes `aes-256-cbc`); lifetimes use the largest exact unit (`lifetime days 1` instead of `lifetime-seconds 86400`, which is above the 65535 limit); `protocol version` is written; `peer-address ip` drops `/32`; `passive-mode` sits under `protocol-common`.
- An IKE gateway is bound to the interface that owns the RouterOS `local-address` (`local-address interface ethernet1/N` plus `local-address ip`), or to the interface picked in the VPN step. When neither exists it is REVIEW-flagged instead of writing a bare `local-address ip` PAN-OS refuses.
- A tunnel with a zone also gets `set network interface tunnel units tunnel.N` before it is referenced.
- A NAT rule whose RouterOS match used `!address` no longer writes the `!` into the PAN-OS address field (refused at commit even on a disabled rule); the rule stays disabled and reviewed.
- The PAN-OS set parser (Firewall Analyzer) reads both the new and the old IKE syntax, bracketed algorithm lists, `lifetime <unit> N`, gateway version/local-address/passive-mode, and `network interface tunnel units`.

Tests: tests/test_firewall_wizard.py (18 tests: IKE paths, gateway binding and swap, NAT negation, parser round trip, validator references and commit blockers, roles, swap consistency, gating, API refusal and export). test_routeros_real_world and test_paloalto_firewall_parser updated for the new syntax.

### Topology Builder 0.5: logical IP view, neighbors from ARP and descriptions, endpoint options, label placement

- New view "Logical IP view only" (`features/topology/iplogical.py`): devices that share a subnet are joined by a line labelled with interface and address at each end; shared VLAN subnets are yellow ovals; pairs that share many subnets are one "N shared subnets" line; every device with two or more interface addresses gets a table (interface, description, address, VRF, state) under the diagram, in the SVG, the HTML report and as HTML-table cells in draw.io. Loopbacks, /32, management and shut-down interfaces are not links.
- Routers and firewalls without CDP/LLDP get neighbors from ARP (`show ip arp`, per VRF) and interface descriptions (`WANR2 G0/1/2`) (`features/topology/inferred.py`, TOPO-027). Evidence is shown in the line, `links.csv` and the finding; endpoint descriptions (SVR, SRV, PC, printer, camera, ATM, phone...) never create a device. Option "Infer neighbors from ARP and port descriptions" (on). Reference: RFC 826 https://www.rfc-editor.org/rfc/rfc826
- Roles: CDP capability words decide router / layer-3 switch / access point; AOS-CX LLDP descriptions (`HPE ANW JL724B ML.10.16.1020`) give model and version; Aruba/HPE `JL` models are switches (an Aruba seen only by its neighbor was drawn as a router); load balancers (F5 BIG-IP, NetScaler, LB/SLB/GSLB names) get their own role and the draw.io `load_balancer` icon.
- Options: "Exclude IP phones and PCs" (only network devices remain), "Collapse phones and hosts" (no longer folds access points), separate "Collapse access points" (off = each access point with hostname, model and IP), line style defaults to rated speed, "What to upload" box spacing.
- Spacing: adaptive horizontal and vertical gaps, wrapped endpoint rows, label placement that avoids icons, hostnames and other labels (`features/topology/labelplace.py`), `N ports` instead of long port lists, SVG viewBox follows lines that leave the page.
- Grouping by the first three hostname words (`JKT-GD1-LT1`); the group with the most links to other groups is drawn in the middle with the others around it (square grid, no overlap); the busiest device of a row is centred; group frames are black in draw.io and the preview.
- Devices of one level are placed left to right in natural name order (A-Z, then 0-9, `JKT-A2` before `JKT-A10`) instead of by crossing reduction; the form lists topology name, options, then device captures (left) and diagram settings, earlier work, buttons (right).
- Tree-aware placement: everything that hangs off one device (switch, access point, IP phone, PC, collapsed node) stays together right under it, in name order, so the three APs of switch A never mix with the two of switch B; a device that only uplinks (router, firewall) sits over what it serves, several side by side; a device with several uplinks keeps its natural place and is centred between them. Long rows are dealt over staggered lines in order, and children are placed as near below their parent as the icon spacing allows.
- New defaults and a redesigned option form: exclude end points on, collapse phones and hosts (hidden while exclude is on), collapse access points on, options in cards with styled check boxes and file pickers. Every run writes `run-settings.txt` (also `build` in topology.json and a section of the report).
- Created-at line in draw.io is `Topology Created at Date YYYY:MM:DD - Time HH:MM:SS`.
- Optional "Topology name" box: every download is prefixed with it (`Panin-DC-links.csv`), it titles the HTML report and each draw.io page, which also shows `Topology Created at YYYY:MM:DD HH:MM:SS` under the name. Empty keeps the current file names.
- Neighbor inference follows an order of trust: CDP/LLDP, then ARP, then MAC address, then port description (new MAC rule: every MAC learned on the port belongs to one device). New TOPO-028: a port description that names another device than the one the port faces. The option "Infer neighbors where CDP/LLDP is silent" is now on the page (the engine had it, the form did not send it).
- Switch Analyzer: AOS-CX `interface vlan 130` (with a space) is parsed as a routed interface; `show ip arp vrf <name>`, `show arp vrf <name>`, NX-OS `show ip arp vrf all` and Huawei `display arp vpn-instance <name>` are read into a new `arp_vrf_table` (each row tagged with its VRF; the plain `arp_table` is unchanged) and the Topology Builder uses it. Before, only one ARP block per capture was read.
- Fix: with grouping off, excluded endpoints were still placed on the overview page.
- `tests/test_topology_v05.py` (synthetic only).

### Topology Builder 0.4 and Aruba CX parsing: fewer false findings, running speeds, wireless clients, AOS-CX ACLs

- Switch Analyzer: `show interface status` speed and duplex (Cisco `a-` auto prefix, NX-OS rows that are not column-aligned) and AOS-CX `show interface` speed/duplex reach the interface table; `show system` supplies model, serial, base MAC and version for AOS-CX captures that lost their top; CDP `Capabilities:` is parsed (`features/switch_analyzer/runtime_parser.py`, `live_state.py`, `service.py`).
- Converter: new `parsers/switch/aruba_acl.py` flattens AOS-CX ACLs and `object-group ip address` groups (cartesian expansion, `count` dropped, `log` kept) so a Huawei target gets real rules instead of one `REVIEW-ACL` line per entry; the Huawei translator summarises `log` reviews per ACL. A session capture with no running-config says that the top may have scrolled away. Documentation: https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/PDF/acls_6200.pdf
- Topology: links.csv gains rated / running speed, duplex and port state; bundle capacity uses running speeds; TOPO-017 compares ratings; new TOPO-024 (capture cut at the top), TOPO-025 (running below rating), TOPO-026 (duplex mismatch); TOPO-016 says how many members are bundled; TOPO-009 no longer fires on AOS-CX `Disabled` ports; CDP and LLDP rows for the same neighbor are merged; wireless clients behind access points are counted, not reported as many-MACs / MAC-twice; TOPO-010 is not raised when the other end did not capture bundle data; TOPO-013 no longer asks Aruba / Huawei for CDP; `bundles.csv` shows `-` instead of `'-`.
- Preview: zoom, Ctrl+wheel, drag to move, open in new tab.
- `tests/test_aruba_parsing_and_topology_checks.py` (synthetic only). Real captures stay local.

### Topology Builder 0.3: vPC view, link speeds, documentation pack, run merge, devices behind devices

- vPC view (`features/topology/logical.py`): a dashed frame per vPC pair and one `vPC <id> · 8x10G` line per bundle that spans the pair; peer-link, host and routed links stay. Same device positions as the physical page. The diagram file holds both pages ("Diagram file contains": both / physical / vPC), the preview has a Physical / vPC toggle.
- Link speed: rated speed per port from the transceiver (`show interface transceiver`) or the interface name; bundle labels `4x10G LACP`; option "Style lines by rated speed" (`features/topology/styles.py`). Ratings, not negotiated rates.
- Management (`mgmt0`) links are left out of the picture and the row layout by default (still in `links.csv`).
- Documentation pack: `keystone-topology-pack.zip` with `topology-report.html` (self-contained, print to PDF, one page per device), one SVG per page, draw.io, Excel, CSV and JSON. New downloads `behind.csv` and `bundles.csv`; Excel gets Bundles and Behind devices sheets (`features/topology/report.py`).
- Add to a previous run: `topology.json` carries a `state` block; upload it with new captures (or alone) to merge by serial or hostname (`features/topology/state.py`). Carried devices are marked in `devices.csv`; the file is parsed as JSON with typed fields and size limits.
- Devices behind devices: MACs learned on a port facing an uncaptured device are summarised per port (MAC count, with IP, VMware / Hyper-V by MAC prefix as a hint, VLANs).
- New findings TOPO-015 to TOPO-023: bundle member without neighbor, member not bundled (LACP flags), speed mismatch, native VLAN mismatch, unhealthy vPC (from `show vpc`), single-member peer-link, vPC peer not captured, devices carried from a previous run, unused port-channel. References in `docs/modules/topology.md`.
- Fix: a switch with an explicit TOR name was promoted to aggregation by vPC degree; an uncaptured stub hanging off two access switches is drawn on its own half row.
- `tests/test_topology_pack.py`: 61 synthetic-capture tests (speeds, vPC view, drawio views, state merge, report escaping, pack, routes). Real captures are used for local checks only and are not stored.

### Topology Builder 0.1: network diagram from CDP/LLDP in device captures

- New tool under Analyze: `/topology`. Upload one capture per device (Cisco IOS XE, NX-OS, Huawei VRP and the other vendors the Switch Analyzer reads); it draws the network and exports `topology.drawio`, `links.csv`, `devices.csv`, `findings.csv` and `topology.json`, with an inline SVG preview.
- The two ends of a link are matched by serial number, management IP and hostname (domain and `(SERIAL)` suffix removed), and by canonical port name (`TenGigabitEthernet1/1/1` = `Te1/1/1`, `BR Ethernet1/49` = `Eth1/49`). A link is confirmed (both ends agree), single-sided (the peer was not captured), or a conflict (the peer's table says the port faces another device). Devices that only appear in a neighbor table are drawn as grey boxes so the diagram is complete before every device is captured.
- Port-channels fold into one line (`Po40`, member count, protocol); vPC peer-links are detected from `show vpc` and drawn in blue; a port-channel whose members reach two different switches is marked multi-chassis with its vPC id. Access points, phones and hosts that hang off one switch are collapsed into one node (every port stays in `links.csv`).
- Role and tier come from the hostname words (AGG, TOR, FW, RT, AP, ...), then the model, then the graph shape, and drive a layered layout: edge and firewall on top, core, aggregation, access, endpoints below. Grouping by hostname prefix draws a box per site plus one page per site.
- The `.drawio` file uses the icon (`mxgraph.cisco19.rect` with `prIcon`), the three-line label (hostname in red, model in blue, management IP in bold), 9 pt port labels with white background and the black 2 pt lines of the reference diagrams. Every device and line is an `object` that carries its data (serial, model, source file, link list, state) in Edit Data.
- Findings: TOPO-001 one-sided link although the peer was captured, TOPO-002 port mismatch, TOPO-003 same hostname or duplicate upload, TOPO-004 neighbors not captured yet, TOPO-008 capture without neighbor data, TOPO-009 spanning-tree blocking on a link, TOPO-010 bundle mismatch or unbundled parallel links, TOPO-011 CDP and LLDP disagree.
- Second pass: ZIP upload and files holding several devices; LLDP chassis ID, management address and system serial for Cisco IOS XE/NX-OS, Huawei and ArubaOS-Switch (identity now also by chassis MAC); hosts from MAC and ARP tables (edge ports only, option "Draw hosts", `hosts.csv`); routed /30 and /31 links (option, dashed blue, annotates an existing CDP link instead of duplicating it); "Previous diagram" keeps your moved devices between runs; lines routed around devices with parallel lines spread and crossing reduction; `topology.xlsx` export; findings TOPO-007, 012, 013, 014.
- `features/switch_analyzer/runtime_parser.py`: LLDP detail rows now also carry `chassis_id`, `management_address`, `capabilities`, `port_description` and `serial` when the device prints them; rows without them keep the old shape.
- Fix: building failed with "The request failed" when the first row of the devices table was a device seen only by neighbors (its row had fewer columns than the captured ones, so `devices.csv` raised ValueError and the server answered with an HTML 500). Every table row now has the same columns, CSV/Excel/page tables use the union of columns, the server returns a readable JSON error for any failure, and the page tells apart "no answer", "HTTP error" and "result could not be shown". Checked in Chromium against a running Waitress server with 1, 6, 11 and 44 real captures.
- Fix: CDP port ids that contain a space (`Port 1` on IP phones, `GigabitEthernet 0/0` on a WAAS appliance) were cut at the first space (`Port`, `Gi`) by `parse_neighbors`; the whole port id is kept now.
- Fixes from a 6-Nexus vPC run: a neighbor that advertises the system name `null` (or `N/A`, `-`) is named by its chassis MAC and treated as a host instead of a device called `NULL`; UCS Fabric Interconnects get their own role `fabric` (they were counted as servers); MAC addresses learned on a port toward an uncaptured device (a fabric interconnect, a switch not yet collected) are listed in `hosts.csv` with `behind` = that device, are not drawn as edge hosts and no longer raise TOPO-007; the same MAC on both vPC peers is no longer reported by TOPO-014 and TOPO-014 lists each MAC once; the software version is read from the `show version` text when the analyzer missed it (NX-OS, IOS XE, IOS); an advertised platform such as `FortiGate-1800F v7.2.9` is split into model and version and the vendor is named when the model prefix is unambiguous (Cisco, Fortinet, Palo Alto, F5, Aruba).
- Tests use synthetic captures only (`tests/topology_samples.py`, invented names and addresses); tests in `tests/test_topology.py` and `tests/test_topology_more.py`. Design and roadmap: `docs/modules/topology-design.md`.

### Easy start for new users: no login, self-installing start scripts, new README and PANDUAN

No login
- The shared-password login is gone. A fresh download opens straight to the dashboard: no password in the terminal, no `data/.auth_password`, no lockout. `core/auth.py` and `templates/login.html` are deleted; `/login` and `/logout` no longer exist. `NES_AUTH_PASSWORD` and `NES_DISABLE_AUTH` are ignored (an old `data/.auth_password` file does nothing and can be deleted).
- New `core/local_guard.py` replaces it with what a login-free localhost tool still needs. It answers only to this computer's names (`localhost`, `127.0.0.1`, `[::1]`; more via `NES_ALLOWED_HOSTS`), which stops DNS rebinding, and it refuses POST, PUT, PATCH and DELETE that another website started (`Sec-Fetch-Site` other than same-origin/none, or an `Origin` that is not the page's own host), which stops cross-site request forgery against routes that take device addresses and SSH credentials. curl, scripts and the test client send neither header and are not affected. `NES_ALLOW_REMOTE=1` turns the Host check off and keeps the cross-site check.
- `run.py`: the outdated "no authentication" comment is now true again and the messages are plain language. Starting Keystone while it already runs reopens the browser instead of failing; a port held by another program says how to pick another one (`NES_PORT`); a non-numeric `NES_PORT` is explained.
- `verify_install.py` no longer logs in; it checks that a foreign Host header is refused.

Start scripts
- `start_windows.bat` and `start_mac_linux.sh` install Keystone on the first start (a missing `.venv` runs the setup), so one double-click or one command is enough.
- `setup_windows.bat` looks for Python 3.13, 3.12, 3.11, then any 3.11 or newer (`py` launcher, then `python`), and says where to download it when none is found. Both setup scripts fall back to `requirements.txt` when the pinned `requirements-lock.txt` does not install, and print what to try when setup fails (proxy, antivirus, `python3-venv` on Debian or Ubuntu). The macOS/Linux scripts are started with `bash ...` so a ZIP download without the executable bit works. `stop_*` honour `NES_PORT` and say "Keystone", not "NES".
- New `.gitattributes`: `*.sh` is stored and checked out with LF, `*.bat` and `*.vbs` with CRLF (a shell script with CRLF fails on macOS and Linux with `env: 'bash\r': No such file or directory`).

Documentation
- README.md and docs/PANDUAN.md: three-step Quick start at the top, what to expect on the first start, a Start and stop table, how to update, Windows SmartScreen and antivirus notes, a longer Troubleshooting table, and a short "Is it safe without a login?" explanation. docs/PRD.md: security rule and architecture diagram updated.

Tests: tests/test_no_login.py (23 tests: pages open without login, no `/login`, guard allows/refuses by Host and Origin, `run.py` bind rules and port handling). The three test files that set `NES_DISABLE_AUTH` no longer do.

### Convert Switch: target-fit check, pre-flight tab, vPC to VSX, derived M-LAG priority, post-conversion checks

Target fit
- `hardware/interface_map.py` `target_fit()`: counts the ports the source really uses by role and speed class and compares them with the chosen target. Verdict `fits`, `partial`, `does-not-fit` or `unknown` (no model chosen); `alternatives` lists catalog models of the same vendor on which no used port would be missing. Shown as a banner in the Interface map tab.
- Catalog: Huawei S6730-H48Y6C-V2 (48x 25GE SFP28 + 6x 100GE QSFP28, e.huawei.com S6730-H-V2 25G page), the like-for-like target of a Nexus N9K-C93180YC. The S6730-H28Y4C is not added: its port layout is only documented for V200R020C00. Ports are written `25GE1/0/n` / `100GE1/0/n`, not `GE1/0/n`.

Pre-flight
- New Pre-flight tab (`preflight.py`): converted lines, REVIEW lines split into "needs a decision" and "not converted", counts by REVIEW code, structural checks, target fit, and one readiness line (ready / decisions needed / target does not fit).
- New `postcheck.py` runs on the converted text of Huawei, AOS-CX and Cisco targets: CHK-ACL-DUPLICATE (a rule repeated after object-group expansion; AGG1 had 12 repeats in one ACL), CHK-ACL-PERMIT-ALL (rules below an unconditional permit can never match), CHK-ACL-NO-DENY, CHK-LAG-EMPTY (an Eth-Trunk / lag / Port-channel with no member).

vPC and HSRP
- Aruba: a `vpc domain` becomes a `vsx` block (`inter-switch-link lag N` from the `vpc peer-link` port-channel, `role primary|secondary`, `keepalive peer ... source ... [vrf]`, `linkup-delay-timer` from `delay restore`); a vPC member port-channel is `interface lag N multi-chassis`. Before, the whole vPC domain was dropped. `system-mac`, `peer-switch` and other domain commands stay REVIEW-VSX-*.
- The NX-OS `management` VRF is the AOS-CX built-in `mgmt` VRF (`vrf attach`, `ip route ... vrf`, `vsx keepalive`); `vrf context management` is no longer an unsupported command.
- vPC `role priority` is parsed (`SwitchConfig.vpc_role_priority`). NX-OS elects the LOWER value as primary, Huawei M-LAG the HIGHER DFS-group priority as master, so only the direction is derived: primary becomes `priority 150`, secondary `priority 100` (the VRP default); no role keeps the marked placeholder. Same direction gives `role primary` / `role secondary` on VSX (`translators/switch/vpc_common.py`).
- Aruba HSRP to VRRP: the REVIEW line carries the source hello/hold timers and the preempt setting.

Not done, on purpose
- AOS-CX VRRP timer and preempt commands, and the `virtual-address` keyword the existing VRRP output uses, could not be checked against an HPE document in this pass (HPE pages refused the fetch); they stay REVIEW.
- Huawei ACL `log` keyword is still unconfirmed (REVIEW-ACL-LOG).
- `show ip interface` in the captures is only a `?` help session; `show ip interface brief` was already read.

Tests: `tests/test_target_fit.py`, `tests/test_preflight.py`; VSX / mgmt VRF / M-LAG priority cases in `tests/test_convert_nxos_acl.py` (fixture extended with a peer-link, role priority, delay restore and HSRP timers).

### Convert Switch and Switch Analyzer: Nexus 9000 (NX-OS) source, six DRC captures

Read the six DRC captures (two N9K-C93180YC-FX3 vPC aggregation switches, four N9K-C93108TC-FX top-of-rack switches, NX-OS 10.4(5) and 10.5(4)) and converted each to Huawei and Aruba.

Convert Switch
- NX-OS ACLs were silently emptied (`acl name X advanced` with no rules; 1,500 REVIEW lines on Aruba). `parsers/switch/nxos_acl.py` reads sequence numbers, CIDR, `remark`, service names and `object-group ip address|port` (`addrgroup` / `portgroup`, expanded and capped at 512 rules per entry). AGG1: about 2,900 real rules on Huawei and on Aruba, two review items left (both damaged capture lines).
- Huawei ACL rules: source ports, `neq`/`gt`/`lt`/`range`, service names as port numbers; `log` keeps the rule and adds REVIEW-ACL-LOG; a `remark` is a comment, not a review item.
- Aruba ACLs are translated for every source (IOS and NX-OS): `access-list ip NAME`, numbered `permit|deny` entries with `A.B.C.D/len` prefixes, `eq|gt|lt|range`, `established`, `log`, remarks as `seq comment` (AOS-CX 10.13 ACLs guide). `neq` and non-contiguous wildcard masks stay REVIEW-ACL.
- NX-OS `username ... password 5 <hash>  role <role>`: the role is no longer glued to the hash. network-admin is Huawei level 3, network-operator level 1, any other role level 0 with REVIEW-USER-ROLE. `passphrase lifetime 99999` (factory default) is dropped.
- Bug: a route written under `vrf context management` was converted as a global route. `StaticRoute.vrf` now carries it: `ip route-static vpn-instance NAME`, AOS-CX `ip route ... vrf NAME`, IOS `ip route vrf NAME`.
- `vlan 1-15,18-19,...` creates every VLAN of the list (VLANs without a name have no block of their own); VLAN 1 is not created.
- AOS-CX: a trunk without an allowed list becomes `vlan trunk allowed all`.
- A port the catalog cannot place on the chosen target keeps its source name and the catalog's reason (for example 25G SFP28 ports on a GE-copper model), instead of a guessed `GE1/0/n` with an unrelated review note.
- Review noise removed: `!Command:` banner, `vdc`, `limit-resource`, `version`, `feature interface-vlan|lacp|vpc|hsrp` (and `feature netflow` on Huawei), bare `switchport`, `hsrp version 2`.
- Catalog: N9K-C93180YC-EX, -FX and -FX3 (48x 1/10/25G SFP28 + 6x 40/100G QSFP28).

Switch Analyzer
- New `nxos_state.py`: show feature, module, boot, system reset-reason, cores, processes log, interface switchport, interface counters errors (the three NX-OS tables merged per port), interface transceiver details (DOM), port-channel database, vpc orphan-ports, spanning-tree root, vrf, vrf interface, logging server and ip route summary, each with a table and findings (SW-NX-* codes) and a link to the Cisco document.
- Paste-ahead captures: the look-ahead for a type-ahead echo is 400 commands instead of 60; with 60 the DRC captures lost `show version`, the platform and filed the running-config under the wrong command.
- Coverage: a `?` help session or a command glued to other text is "ignored", not "answered".
- SW-NX-CAP-001: ACL lines of the running-config with a typed-ahead command or a corrupted address inside.

Tests: `tests/test_convert_nxos_acl.py`, `tests/test_switch_nxos_state.py`, fixture `tests/fixtures/switch/nxos_acl_synthetic.txt`; the catalog tests list the three new models.

### Convert Switch and Switch Analyzer: Catalyst 3650 stacks to S5755-H24T4Y2CZ stacks (Depo Makassar, Manado, Pekanbaru, Semarang)

Read the backup, draft and staging captures of the four Depo sites: four Catalyst 3650 stacks (two members each) replaced by four S5755-H24T4Y2CZ two-member ring stacks (V600R025C00, Master priority 200, Standby 100). The captures are customer data and stay outside the repository; the tests use the synthetic fixture `cisco_3650_stack_netflow_synthetic.txt`.

Convert Switch
- Catalog: the S5755-H24T4Y2CZ stack ports are `25GE<m>/0/3` and `25GE<m>/0/4` at 10G (`Stack-Port<m>/1` and `<m>/2`), each with `device transceiver 10GBASE-COPPER`; `stack_transceiver` and `stack_shares_bank` are new model fields. The `display stack port auto-cable-info` candidates (25GE m/0/1-2, 100GE m/0/1) are not used because the deployed stacks bind 25GE m/0/3-4.
- A source stack is detected from the highest member number in the interface names and from `switch N provision`; the stack ports of every member are reserved (no data configuration, REVIEW-STACK-PORT) and the uplink module ports `Gi<m>/1/3-4` that land on them stay empty.
- The stack template follows V600R025C00: `interface stack-port <m>/1` + `port member-group interface 25GE <m>/0/3` (the older `port interface X enable` is not in this release); no dual-active detection exists on the deployed stacks, so the header explains relay (cores) and direct (small access stacks).
- A 25GE bank that holds the 10G stack links is not set to `port mode GE`; the converter writes a commented `port mode 10GE-GE` plus one REVIEW-PORT-MODE-BANK per bank (documented, not yet run on a real stack).
- Flexible NetFlow exporters are parsed and written as `netstream export ip host <ip> <port> dscp 0` and `netstream export ip source <SVI address>`; interfaces get `netstream inbound ip` / `outbound ip`. Only for the S5755 / S6730 / S6750 / S5732-H / S6780 families: for the S5735 a REVIEW-NETSTREAM explains why nothing is written. When the exporter source SVI does not exist in the file the management SVI is used and the line says so. Aging timers are not carried over.
- The management SVI named by `tacacs` / `tftp` / `flow` / `ssh` source-interface replaces `Vlanif-mgmt` in the NTP lines, and `logging source-interface` does the same for `info-center loghost source`; a source that has no addressed SVI in the file is skipped.
- `clock timezone <name> <h> [<m>]` becomes `clock timezone <name> add|minus hh:mm:ss`.

Switch Analyzer
- SW-NSF-001: `netstream export ip source` is not an address of the switch (three of the four real stacks exported from the Pekanbaru address). SW-NSF-002: `netstream timeout ip active` below 60 s (the real stacks use 1). SW-SRC-001: `ntp server source-interface` or `info-center loghost source` names a Vlanif without an address.

Tests: `tests/test_convert_s5755_stack_depo.py`, `tests/test_convert_port_mapping_tam.py` (stack template syntax).

### Convert Switch and Switch Analyzer: two standalone Catalyst 2960 merged into one Huawei stack (Lexus)

Read the Lexus captures (backup, draft, fix, staging, "migration before" and the two "migration after" captures of the stack that replaced LXS-SWAC-ISP01 and ISP02, plus the OT and CODI switches). The captures are customer data and stay outside the repository; the tests use synthetic fixtures.

Convert Switch
- New "Stack member" and "Units in the stack" fields on the Convert Switch page (API fields `stack_member`, `stack_members`). A file converted as unit N of a stack gets `GE<N>/0/<n>` / `10GE<N>/0/<n>` names, a REVIEW-STACK-MEMBER header with the template B stack commands of the project for that member (priority 200 for member 1, 100 for the others, as in the real stack), and keeps the stack-link ports free: on the S5735-S24T4XE-V2 `GE<m>/0/21` and `GE<m>/0/22` are written as an empty block with REVIEW-STACK-PORT (a real `display stack configuration` binds them to Stack-Port<m>/1 and <m>/2; `10GE<m>/0/5-6` are the alternative media). Other models claim nothing until a capture shows their stack ports.
- Interfaces whose description names a sibling switch of the same site and role (`LXS-SWAC-02-C2960`), and the Port-channel to it, carry REVIEW-STACK-LINK: the link between the old switches becomes a stack cable.
- Catalog: WS-C2960-24TC-L (Cisco 2960 LAN Base data sheet, Table 8) and WS-C2960+24TC-L (2960-Plus data sheet, Table 14): 24 FastEthernet ports and 2 uplinks GigabitEthernet0/1-2. Without them the Gi0/1 and Gi0/2 uplinks (the firewall links) were read as access ports 1 and 2 and merged into Fa0/1 and Fa0/2, so their configuration was lost. The same fault is closed for any unknown FastEthernet model: the faster range of two fixed-port keywords is the uplink pair, and `Gi1/1` style names are module ports.
- A model named only on a `Platform:` line (the CDP neighbour table) is no longer taken for the source switch: a 3750 capture was read as the 2960-X next to it.
- Line blocks: an indented line such as `privilege level 15` no longer ends `line con 0`, so `login authentication CONSOLE` becomes `authentication-mode aaa` instead of a passthrough comment; the privilege is explained in a review line.
- A self-signed certificate chain (about 25 hex lines) is one passthrough line.
- PVST and Rapid-PVST review lines now say that Huawei VBST (`stp mode vbst`) interworks with Cisco PVST (Huawei Interoperation and Replacement Guide, EDOC1000114005) instead of "no Huawei equivalent, consider MSTP".

Switch Analyzer
- A capture without `display dual-active` is no longer reported as "no dual-active detection" (SW-STK-003); only a real `Dual-active detect mode: --` is.
- SW-STK-005 reads the records of `display stack troubleshooting history` (the device wraps them at 80 columns, even inside a word) and says how many are stack-port-down, member-port-down, one-link-left or alarm-threshold events and the time span.
- New SW-STK-007: an Eth-Trunk of a stack whose member ports are all on one stack member.

Tests: `tests/test_convert_port_mapping_tam.py`, `tests/test_switch_huawei_live.py`, `tests/test_hardware_catalog.py`; fixtures `cisco_2960_24tc_synthetic.txt`, `cisco_2960plus_24tc_synthetic.txt`, `cisco_fe_gi_unknown_model_synthetic.txt`, `huawei_stack_history_synthetic.txt`.

### Switch Analyzer and Convert Switch: confirmed against real Huawei and Cisco TAM captures

Read the TAM switch captures (Huawei S5735-S-V2 / S5755-H CLI output, Cisco 2960, 2960-X, 3560-X, 3650 and Aruba 2540 "before" files with their Huawei "after" configurations). The captures themselves are customer data and are not in the repository; the tests use synthetic fixtures that copy only the shape of the output.

Switch Analyzer (Huawei live state)
- New readers for `display stack`, `display stack topology`, `display stack configuration`, `display dual-active` (older software calls it `display mad`), `display stack troubleshooting history`, `display vlan summary`, `display arp statistics`, `display license` and `display stp region-configuration`; the Health tab has a "Stack and device state" card (members, roles, MAC, priority, ring or chain, stack ports).
- New findings: SW-STK-001 (no standby member), SW-STK-002 (chain or single stack link), SW-STK-003 (dual-active detection not configured), SW-STK-004 (dual-active status), SW-STK-005 (stack troubleshooting records), SW-STK-006 (recorded stack port link-down), SW-ARP-001 (incomplete ARP entries), SW-CAP-101 (VLAN list shorter than the VLAN count). Documentation link: Huawei Virtualization guide, stack support (EDOC1100458710).
- Coverage: twelve new capture checks. A command that ran and printed nothing (`display eth-trunk` with no Eth-Trunk) is reported as "ran, empty", not as a missing capture. `display stack peers` is rejected by the device and is not requested.

Convert Switch
- Hardware catalog: Cisco Catalyst 2960-48TC-L, 2960X-24TS-L, 3560-X (standalone, network module), 3650-24TS and Aruba Switch 2540 (the port counts follow the data sheets named in each entry; stack limits are stated only where the sheet states them).
- Port mapping: the target model is taken from the migration inventory when the file names one; two source ports can no longer land on the same Huawei port (the converter used to emit duplicate `interface` blocks); a generic uplink naming is used when the target has no module table; 100 Mb copper to a gigabit port needs no review.
- Optics: a 1G optic in a 10GE SFP+ cage gets `device transceiver 1000BASE-X`, and in a 25GE SFP28 cage also `port mode GE` (it converts the four-port bank).
- `undo poe enable` is written for copper PoE access ports only; a multi-speed Cisco cage that appears under two keywords (Gi1/1 and Te1/1) is one stanza.
- Management port: a source VRF bound to the management interface becomes `ip binding vpn-instance management` on `MEth0/0/0`, the instance VRP creates itself; any other VRF binding keeps its name with a REVIEW line that the instance must be created.
- Tests: `tests/test_switch_huawei_live.py`, `tests/test_convert_port_mapping_tam.py` (new), `tests/test_switch_coverage.py`, `tests/test_hardware_catalog.py`; five synthetic fixtures under `tests/fixtures/switch/`.

### Convert Switch: Aruba port access, catalog tree, Huawei VTY/console; Switch Analyzer: Huawei security baseline

Convert Switch
- Aruba CX target: Cisco 802.1X / MAB is now generated as AOS-CX port access instead of a review block, using the syntax of the AOS-CX 10.11 Security Guide (6200, 6300, 6400): global `aaa authentication port-access dot1x authenticator enable` and `mac-auth` / `enable`; per port `auth-precedence`, `auth-mode multi-domain|device-mode` or `client-limit`, `critical-role CRITICAL-VLAN<n>` (with a `port-access role` that holds `vlan access <n>`), and the `dot1x authenticator` and `mac-auth` contexts with `eapol-timeout`, `reauth`, `reauth-period`, `enable`. `authentication order mab dot1x` is honoured (`auth-precedence mac-auth dot1x`). What has no AOS-CX equivalent in the guide (`event server alive`, open authentication, violation, `mab eap`) is listed once per port group, and the RADIUS server-group binding is given as an instruction. Table in `nac.py`.
- Aruba CX management port: `interface mgmt` with `ip static <ip>/<prefix>` (no `routing`, no `vrf attach`); JL724B gets a management port and the VSF limit of 8 members from the VSF Guide for 6200/6300 (the old "limit not stated" note is gone). `no poe-enable` is no longer written under VLAN, LAG, loopback and mgmt interfaces.
- Catalog page: the model list is a collapsible tree, vendor > product line with its OS (Catalyst IOS-XE, Nexus NX-OS, CX AOS-CX, CloudEngine VRP) > series > model, with Expand all / Collapse all; the router page keeps its model picker, which now opens the branch of the chosen model.
- Huawei target: Cisco `access-class <acl> in|out` on a VTY line becomes `acl <acl> inbound|outbound` (Command Reference V600R025C00: `acl { acl4name | acl4num } { inbound | outbound }`); `line con 0` becomes `user-interface con 0` with `authentication-mode aaa` and `idle-timeout`. Both were review lines or dropped before.

Firewall Analyzer
- The MikroTik "Not interpreted" table shows the configuration line only; it used to carry the converter's PAN-OS migration note ("Palo Alto firewalls are not WiFi access points ...").

Switch Analyzer
- Huawei security baseline from Huawei's "Baseline Check Items for Security Configuration of Campus Switches" (V600R025C00, Mandatory and Optional workbooks): new findings SW-VTY-001 to 004, SW-CON-001, SW-SSH-002/003, SW-TEL-002, SW-FTP-002, SW-HTTP-002, SW-MGT-001, SW-SNMP-005/006, SW-NTP-003 and SW-AAA-101 to 106, each naming the baseline item. `display current-configuration` omits default values, so defaults are judged by an explicit `undo` / `disable` line and missing commands by their absence. Telnet and FTP over IPv6 are recognised like the IPv4 services.

Tests and docs
- `tests/test_convert_nac_and_session.py` (AOS-CX port access), `tests/test_hardware_catalog.py` (catalog tree, JL724B mgmt port and VSF limit), `tests/test_switch_huawei_baseline.py` (new, synthetic fixture `tests/fixtures/switch/huawei_s5735_baseline_synthetic.txt`), `tests/test_firewall_analyzer.py`. `docs/modules/configuration-studio.md` has the AOS-CX mapping, the baseline checks and the step-by-step "adding a model".

### Convert Switch: Huawei device catalog

- The six Huawei CloudEngine targets are now proper entries of the Switch hardware catalog (S5735-L8T4X-QA-V2, S5735-S24T4XE-V2, S5735-S24P4XE-V2, S5735-S48T4XE-V2, S5755-H24T4Y2CZ, S5755-H48UM4Y2CZ) with port groups, speeds, PoE, stack limit (9 where the data sheet states it) and a link to the Huawei product/data-sheet page. The catalog page lists them; the Target Model dropdown and the Interface map read the same data, replacing the hard-coded list and the label-parsing rule.
- The S5755-H48UM4Y2CZ is a Multi-GE switch (48 copper ports, 100M to 10G, PoE++): its access ports are `MultiGE<m>/0/<n>` and a converted config now uses those names instead of `GE`. Its uplinks are 4x 25GE SFP28 and 2x 100GE QSFP28 (the old label said "48x GE + 4x 25GE").
- A Huawei configuration can be the source of the Interface map (`GE`, `MultiGE`, `10GE`, `25GE`, `40GE`, `100GE`, `MEth`, and the older `GigabitEthernet0/0/n` / `XGigabitEthernet0/0/n` spellings), detected from the model name in `display version` or the inventory text.
- Cisco 1G access ports landing on a Multi-GE port are `ok` (no speed-class warning).
- Tests: `tests/test_hardware_catalog.py` (Huawei port counts, names, dropdown, detection, Huawei source, Multi-GE conversion).

### Switch Analyzer and Convert Switch: lessons from the OJK and Panin captures

Learned from the 24 OJK access/distribution switches and the 22 Panin switch, router and SD-WAN backups (three collection rounds).

Switch Analyzer
- Abbreviated commands are spelled out before any parser runs (`features/switch_analyzer/command_names.py`): `show cdp neig detail`, `sh inven`, `show inter transceiver` and the rest of the keyword tree the analyzer uses. Only a unique prefix is expanded and an unknown word is never touched. All CDP detail data had been lost on all 24 OJK captures because of one abbreviation.
- CDP detail now carries the neighbour's management IP, software version, native VLAN, duplex, capabilities and hold time (Neighbours tab: Management IP, Software, Native VLAN).
- New Redundancy (SSO) tables and findings SW-RED-001 to 007 from `show redundancy states`, `show redundancy` and `show redundancy history` (a stack of two or more members without a standby is high).
- New time-synchronisation tables and findings SW-NTP-001 to 006 from `show ntp status` / `associations` (IOS XE), `show ntp status` / `associations` (AOS-CX), `show ntp peer-status` (NX-OS) and `display ntp status` / `sessions` (Huawei V600R025C00, layout taken from the official command reference): unsynchronised clock (high), no usable server, a single usable server, servers that never answer, large offset, NTP disabled.
- New `show spanning-tree inconsistentports` reader and finding SW-STP-102 (a port blocked by root guard, loop guard or a type mismatch).
- A blank model on an SD-WAN edge is filled from `show sdwan system status`; a transceiver table that stopped half-way says why ("incomplete capture").
- The Router Analyzer refuses an Aruba AOS-CX configuration and points to the Switch Analyzer (it used to report it as a "Cisco router"). `vendor_hint.identify` knows AOS-CX.

Convert Switch
- A whole terminal session is reduced to its `show running-config` block before detection and parsing (`converter_engine/session_capture.py`): login banner, `show version`, `show clock` and typed-ahead commands no longer become thousands of review lines. The Panin v2/v3 captures dropped from about 7,000 junk review markers to the few hundred real ones; a Catalyst session that was detected as Aruba (because the jump host was an Aruba switch) is now a Cisco file. The chassis and module PIDs of `show inventory` still feed the hardware catalog. A capture with several `show` outputs and no configuration is refused with an instruction. The page shows "N lines (show running-config cut from a M-line session)".
- 802.1X / MAB (Cisco `authentication ...`, `mab`, `dot1x ...`) becomes Huawei NAC (`converter_engine/nac.py`): one authentication profile per distinct port setting, with dot1x-access-profile, mac-access-profile, `authentication dot1x-mac-bypass`, host mode (`multi-domain` is `single-voice-with-data`), re-authentication, server-down/up actions and `dot1x timer tx-period`. Every command was checked against the V600R025C00 NAC Configuration Guide and Command Reference; what has no documented equivalent is listed once per profile. Cisco to Cisco keeps the lines as they are. Aruba CX targets get one grouped review block per port set (about 1,300 review lines became about 280 on an access switch) because no AOS-CX port-access reference was provided.
- TACACS+ servers become primary, secondary, third and fourth (all were written as primary, so the last one overwrote the others); `ip dhcp excluded-address` becomes `excluded-ip-address`; `no snmp trap link-status` becomes `undo enable snmp trap updown`; Cisco `channel-protocol lacp` is absorbed (Eth-Trunk LACP mode already says it); AOS-CX `snmp-server system-location` / `system-contact` become `snmp-agent sys-info`.
- Aruba CX target: the DHCP pool translation read fields the model does not have and crashed on any pool (3 of 24 OJK files); Cisco `logging buffered` / `source-interface` / `synchronous` were passed through as AOS-CX commands and are now review lines; source comments are no longer review markers; access and trunk ports get the `no routing` that AOS-CX requires before `vlan access`, and an AOS-CX source `no routing` is understood instead of reported.
- Hardware catalog: C9300L-48P-4X, C9300L-48T-4X and C9500-48Y4C.
- Tests: `tests/test_switch_command_names.py`, `tests/test_switch_redundancy.py`, `tests/test_switch_ntp.py`, `tests/test_convert_nac_and_session.py`, `tests/test_analyzer_gaps_ojk_panin.py`; synthetic fixture `tests/fixtures/switch/c9300l_nac_session_synthetic.txt`.

### Convert Switch and Convert Router: hardware catalog and interface map

- New hardware catalog (`converter_engine/hardware/`) built from the two sample folders: Catalyst C9300X-24Y, C9300X-48TX, C9300-48P, C9300-48T, C9200L-24P-4X, C9200L-48P-4X, Nexus N9K-C93108TC-EX/-FX/-FX3, Aruba CX 6200F JL724B, and the routers C8200-1N-4T, C8200L-1N-4T, C8300-1N1S-6T, ISR4431, ISR4331, ASR1002-X, CISCO3825. Each model lists its port groups, uplink modules, stack limit (only when the data sheet states one) and a link to the Cisco or HPE data sheet. Both pages show the catalog.
- Interface map tab on every switch conversion: each port of the detected source model (including unused ports and every stack/VSF member) with the port it becomes on the target, a status (mapped, review, no equivalent, not a port) and the reason. Ports are matched by role, speed class and position, not by digits: `Te1/1/3` is the third port of the uplink module, so it becomes `10GE1/0/3` on a Huawei S5735 with four 10GE ports and is flagged as having no equivalent at `Te1/1/8`.
- Target Model now lists Cisco Catalyst models (the uplink module is part of the choice, for example `C9300-48P + C9300-NM-8X`) and the Aruba CX 6200F, next to the Huawei list. Nexus is source and reference only, because the Cisco translator does not write NX-OS.
- Translators: the Huawei translator numbers uplink-module ports from the map instead of passing them through with a generic warning; the Cisco and Aruba translators now rename physical ports when the source model is known (an Aruba `1/1/25` becomes `TenGigabitEthernet1/1/1` on a Catalyst with an 8x10G module). With an unknown source model the old rules apply unchanged. A port the target does not have is written into the converted config as a review line.
- Convert Router (still not available for conversion): the Router Model dropdown lists the seven routers, and a reference panel shows onboard ports and each expansion slot's naming pattern (NIM, SPA, HWIC), with the module and ports seen in the samples.
- Tests: `tests/test_hardware_catalog.py` with synthetic fixtures under `tests/fixtures/switch/`.

### Firewall Analyzer: more from a PAN-OS CLI capture, and wrong-page hints on every analyzer

- Uploading a Palo Alto capture (`show system info` + `show config running`) to the Load Balancer Analyzer used to end at "No F5 BIG-IP configuration was recognised". The Load Balancer, Router and Firewall analyzers now share `analyzer_core/vendor_hint.py` and add one sentence that names what the file is, with model and software version when the file says so, and the page to open: "This file looks like a Palo Alto PAN-OS firewall (PA-520, PAN-OS 12.1.4-h6) - open the Firewall Analyzer instead." It also recognises FortiGate, MikroTik, F5, Cisco and Huawei text.
- IPsec tunnels: the `disabled` flag was never read from the PAN-OS XML, so a disabled tunnel showed "Disabled: No" and weak crypto on it was rated high. The flag is read now; weak crypto on a disabled tunnel is low and the title says "(tunnel is disabled)".
- DHCP servers were never read from PAN-OS XML (the tab was always empty). The table now lists interface, pool, gateway, DNS, mask, lease and reservation count.
- New tabs and findings read from the same XML (secrets are never read): IKE gateways (version, peer, local interface, authentication type, NAT-T, DPD, tunnels using it), VPN crypto profiles (every proposal, in use or not), IPsec tunnel settings, QoS profiles and bindings, monitor profiles, administrator password policy, content-update schedule, botnet report settings, custom URL categories, log forwarding profiles, device settings. The syslog profile under `shared/log-settings/syslog` is read as well.
- New findings: PAN-VPN-001 to 007 (weak proposals hidden behind a strong first one, unused weak profiles, IKEv1 aggressive mode with a PSK, no DPD, IKEv1, anti-replay off, disabled tunnels), PAN-PWD-001 to 003 (policy off, length under 12, no character-class minimums), PAN-UPD-002 (download-only schedules). Each links to the PAN-OS documentation.
- Tests: `tests/test_panos_network_extras.py` with the synthetic fixture `tests/fixtures/firewall/panos_cli_network_synthetic.txt` (fake hash and keys; the tests prove none reaches the result).

### Convert pages: one layout for all five

- Convert Switch and Convert Firewall: the settings card is now four groups (Source, Platforms, Actions, Batch) with one spacing rule, 22 px between groups and 12 px between controls. Before, each control carried its own margin, so Target Model and Standard Config Profile sat flush under the field above, and the Firewall-only "Preview Interface Mapping" button was squeezed in.
- Result column: the same 16 px between every block, padding on the mapping panels (Interface & Zone Mapping, IPsec, SD-WAN, Panorama), aligned checkboxes, full-width text inputs, a centred empty state, and readable headers on the source and converted code panels (they were dark on dark in the light theme).
- Convert Wireless, Router and Load Balancer: the same settings card, every control disabled and a "Not available yet" badge, plus a status panel (what you can do now with an Open-analyzer button, best source file, what is needed before a converter can be built, how one is added). The page cannot submit and does not load the converter script. On a phone the status panel comes first.
- Registering a parser and translator for a domain switches its page from the disabled card to the working form with no template change.
- Tests: `tests/test_convert_pages.py`.

### Load Balancer Analyzer: Visualization tab (F5 Network Map)

- New tab "Visualization" (right after Overview): a clickable tree, virtual server > pool > pool members, with the health monitors of each pool under a Health monitors toggle. Each object carries a BIG-IP status indicator: available (green circle), offline (red diamond), unavailable (yellow triangle), unknown (blue square, no monitor), disabled (black circle), forced down (black diamond), parent disabled (gray). Same icon meaning as the Network Map in the BIG-IP GUI ([Network Map](https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/big-ip-local-traffic-management-basics-14-0-0/01.html), [LTM object status indicators](https://techdocs.f5.com/en-us/bigip-14-1-0/big-ip-tmos-routing-administration-14-1-0/dynamic-routing/about-route-health-injection/about-route-advertisement-of-virtual-addresses/ltm-object-status-indicators.html)).
- Filters by status and by object type, search by name, address or port, Expand all / Collapse all, keyboard navigation (arrows, Home, End, Enter), a summary by type and status with clickable counts, a detail panel (reason, source, path, properties, link to the table that lists the object) and a legend with the documentation links.
- Honest about its source: a configuration-only capture shows "configured" (enabled and monitored), "unknown" (no monitor), "disabled" and "forced down" (`state user-down`); a member is only ever green when `show ltm ...` output says so. Pools used by several virtual servers appear under each of them; pools nobody uses are grouped separately; pools reached only by an iRule or LTM policy are attached to that virtual server.
- New live parsers: `show ltm pool members` (availability, state, reason, monitor status per member) and `show ltm node`. The collect script for BIG-IP now also runs `tmsh show ltm node`. Two new tables under Live state: Pool members (live) and Nodes (live). The parsers follow the documented layout and have not been run on a real device yet; a pool's own reason no longer picks up its first member's text.
- Shared result schema: new section kind `map` (`map_section`, `map_as_table`, validation of ids, parents and declared statuses). Excel export writes a map as a sheet with a Path column; compare flattens maps, so a member that changed state between two captures is reported.
- Router Analyzer, Interfaces table: filter buttons by State (up/up, up/down, down/down, admin down).

### Load Balancer Analyzer: `show running-config` captures

- `show running-config` prints objects in /Common without the `/Common/` prefix (`ltm pool POOL-A`), while `tmsh list` and bigip.conf print `/Common/POOL-A`. Definitions are now qualified to `/Common/` at parse time, so virtual servers resolve their pools, profiles and monitors. Before, such a capture gave an empty tree and a false "unresolved reference" finding per virtual server.
- `security bot-defense profile / asm-profile`, `security dos profile` and `security protocol-inspection profile` objects count as known profiles (no false LB-REF-001); `websecurity` is a built-in profile.
- LB-VS-001 no longer flags a DNS listener virtual server (dns or udp_gtm_dns profile): it answers from the GTM engine and needs no pool.
- LB-OBJ-004 no longer lists the profiles every unit ships (`georedundancy`, `do-not-remove-without-replacement`) as unused.
- Tests: `tests/test_lb_running_config.py` with the synthetic fixture `bigip_running_config_bare_synthetic.txt`.

### Load Balancer Analyzer: BIG-IP DNS (GTM) and collect lists

- Visualization is now the first tab after Overview (Overview, Visualization, Virtual servers, Pools & nodes, ...). The detail panel no longer prints a stray "null" line.
- Visualization, BIG-IP DNS: wide IP > GTM pool > pool member (server : virtual server) with the same status icons as the LTM tree. Configuration-only captures show configured / unknown / disabled / parent disabled (a disabled server or data center); live `show gtm` output turns them green, red, yellow or black. A pool shared by wide IPs appears under each; GTM pools no wide IP uses are grouped. A DNS-profile virtual server that has no pool is described as a DNS listener instead of "cannot tell". A pool whose enabled members are all offline now says so.
- New live parsers for `show gtm wideip / pool / server / datacenter / iquery / listener` (`parse_gtm`: availability, state, reason, request and load-balancing counters, pool and member nesting). New tables on the DNS (GTM) tab: Wide IPs, GTM pools, GTM pool members, GTM servers, Data centers, iQuery connections and GTM listeners (live). Not yet validated on a DNS device; the layout follows the documented command set.
- New findings from live state: LB-GTM-020 iQuery peer not connected (high), LB-GTM-021 enabled wide IP offline or unavailable, LB-GTM-022 enabled GTM server offline. A configuration file that holds only `gtm` objects (for example `bigip_gtm.conf`) is now recognised. A DNS-only unit is no longer reported as missing its LTM objects, and the DNS (GTM) tab follows Pools & nodes.
- Collect list for F5 LTM rewritten into sections (platform and health, configuration, HA, live LTM state, network) with the extra commands `show sys provision / software status / failover / ha-status / mcp-state / cpu / memory`, `show cm device / device-group / traffic-group`, `show ltm virtual-address`, `show net interface / trunk`, `list ltm virtual-address all-properties` and `list ltm profile server-ssl all-properties`. New collect list "F5 DNS" (`collect-lb-f5-dns.txt`) for BIG-IP DNS: the `show gtm` commands above, GTM global settings, DNS profiles, DNS Express zones, name servers, resolvers and DNSSEC keys (public data only), performance counters. Both lists tell the engineer to mask secrets and exclude TSIG keys. The commands the parsers do not read yet are collected for the next iteration and are labelled that way in the command table.

### Analyzer tables

- Filter buttons by value: Hardening checklist result (pass / fail / n/a) in the Firewall Analyzer (FortiGate) and the Load Balancer Analyzer; virtual server status; pool member state; node state (enabled / disabled / forced down); configuration inventory handling (analysed / counted only / listed on the Security tab). Status filters use the same colours as the pills in the table.
- More filter buttons, from the same rule (a state, status, result or action column with a few values): FortiGate policies (action, status), static and policy routes, local-in, SD-WAN members and rules, interfaces; Palo Alto and MikroTik rules (action) and interfaces (disabled); live BGP and IPsec tunnels; FortiSwitch ports, trunks, STP ports and events; PAN-OS live interfaces, processes, licences, jobs and ARP; F5 service map, virtual addresses, devices, GTM, live virtuals and pools, virtual server protection; Router Analyzer hardening, BGP/OSPF/IKE/SD-WAN neighbors and sessions, ACL and route-map actions, object references, FHRP, environment and platform state. A filter is hidden when the column has fewer than two or more than twelve values.
- The word "analyzed" is now spelled the American way everywhere (coverage status, inventory handling, messages), matching "Analyzer".
- Load Balancer Analyzer, Change history: the "Configuration saves" table has a second time column, Saved (WIB, UTC+7), next to Saved (UTC).

### Parsers and analyzers (branch fix-parser, lessons from six real backups)

- Terminal logs are replayed, not regex-stripped: new `analyzer_core/terminal.py` models carriage return, backspace, erase-in-line and the `less` status line, so PuTTY logs with repainted prompts and hard-wrapped tables read correctly. Used by the PAN-OS operational parser and the new runtime analyzer.
- Firewall Analyzer, MikroTik RouterOS 6 and 7: new `routeros.py` (addressing, firewall filter/NAT/mangle, address lists, bridges and VLANs, queues and bandwidth limiters, PPP, routing, services, users, SNMP, scripts) with findings FW-ROS-*. Secrets are never copied into results or `modeled_lines`.
- Firewall Analyzer, PAN-OS runtime-only logs (`show system info`, `show interface all`, `show routing route`, licences, content, HA, disk, jobs, no configuration): new `panos_capture.py` with findings PAN-RTC-001..024 (expired Threat Prevention licence, content age, PAN-OS and hardware end of life, disk, swap, memory, process state, HA, unused interfaces, single default route). Detected automatically.
- Firewall Analyzer, new platform FortiSwitch (SSH from a FortiGate, `diagnose switch ...`, `diagnose debug report`, `show`): MCLAG split-brain and ICL checks, LACP, STP, switch-controller log grouping, hardware and security checks (FSW-*). Detected before FortiGate because FortiSwitchOS speaks FortiOS syntax.
- Firewall Analyzer, FortiGate: proxy policies, web filter URL lists, external threat feeds, DNS server/zones, virtual-wire pairs, virtual and physical switches and protocol-option profiles are listed; new findings FGT-PXY-001..005, FGT-URL-001, FGT-EXT-001, FGT-DNS-001, FGT-VWP-001.
- Convert, MikroTik to Palo Alto: RouterOS 6 `.rsc` exports parse through the same hook-based parser as RouterOS 7; the PAN-OS translator emits PAN-OS DH group names.
- Convert, Palo Alto source: a `show config running` curly-brace capture and a runtime-only capture are both accepted. A capture that holds a configuration is converted as a configuration even when it also contains `show system info`.
- Behaviour change: the IKE crypto profile DH group is now parsed to the PAN-OS name (`group2`), not the raw RouterOS value; `test_paloalto_firewall_parser` was updated to match.

### Convert

- Convert is split into five pages, one per device type, like Analyze: Wireless, Switch, Router, Firewall, Load Balancer (`/convert/<page>`). `/configuration/` redirects to Switch.
- The page decides the device type. Auto Detect only picks the vendor within that domain, and a file that clearly belongs to another domain (for example a router backup on the Switch page) is refused with a pointer to the right page instead of going through the wrong parser.
- Wireless, Router and Load Balancer have no converter yet. Their pages say so, list what is needed, and link to the matching analyzer; the dashboard tags them "Not available yet".
- New `converter_engine/domains.py` holds the domain registry and `classify()`, which corrects known detector false positives (routers read as Cisco FTD or switch, PAN-OS CLI capture read as an Aruba switch).
- Interface/zone mapping, IPsec, SD-WAN and Panorama panels appear only on the Firewall page; standard config profiles only on the Switch page.
- Conversion activity is logged as `Convert · <page>`.
- Architecture notes and the "add a converter" steps are in `docs/modules/configuration-studio.md`.

## 1.11.0 (2026-10-15)

### Suite

- Dashboard groups tools by work (Analyze, Convert, Operate) and tags each with its risk class: Offline, Read-only, or Writes to devices.
- Sidebar navigation follows the same groups and marks the tools that change live devices.
- One module registry (`core/modules.py`) now drives the dashboard, sidebar, quick guide, and `/api/health`. `/api/health` also reports ZTP, Config Push, Config Backup, and Live Logs.
- Dashboard search also matches vendor names and tasks; empty groups hide while filtering.
- Router Analyzer collect script for IOS-XE now includes `show logging count`, which the analyzer already reads.
- FortiGate hardened test fixture uses deep inspection on its outbound policy, matching the SSL inspection rule (FGT-UTM-001).
- Removed leftover files: a stray test text file, two firewall compatibility stubs under `switch_analyzer`, and the empty `lifecycle_manager/core/ztp` package.
- Documentation split: README covers install and use, `CHANGELOG.md` holds release notes, `docs/` holds the PRD, module notes, and design references.

### Wireless Analyzer 1.11.0

- AP Model & Software Summary in Overview, grouped by device type and runtime version.
- Dedicated VAP Profiles tab keeps the existing WLAN/SSID catalog intact while exposing one row per Huawei VAP.
- Each VAP row resolves SSID/profile, base and effective service VLAN, security, authentication, traffic, forwarding, AP Group/site, AP count, radio, WLAN ID, usage scope, and full profile commands.
- VAP usage is classified as Site-specific, Shared across sites, or Unassigned, so site-level service delivery is visible at a glance.
- Huawei profile parsing is indentation-aware, so nested `wlan` siblings can't contaminate each other's configuration.
- The Wireless Analysis workbook includes a dedicated `VAP Profiles` worksheet.
- Consistency indicators for consistent, mixed, partial, and unavailable version data.
- Click-through filtering from a model/version group to the detailed AP Inventory.
- `AP Device Summary` worksheet added to the Wireless Analysis Excel export.
- Config Delta workspace inside Wireless Analyzer for directional Source-to-Target comparison.
- Config Delta covers every configuration section, not only predefined wireless profiles.
- Known Huawei/Cisco objects use structured parsing. ACLs, traffic policies, services, routing, management, and previously unknown sections fall back to a safe generic parser.
- ACL objects and individual rules are compared directionally: Missing on Target, Value Mismatch, and Target-only detail.
- Generated Delta includes safe Source-only commands in dependency order. Credentials, controller-specific settings, and destructive actions stay in Manual Review.
- Dependency-aware MAC Authentication tab follows Huawei AAA/RADIUS, access profiles, authentication policy, WLAN bindings, and AP group delivery.
- Huawei nested `aaa` and `wlan` objects are compared independently, with their CLI hierarchy and radio-level indentation preserved.
- Local AAA users and credential-bearing commands are masked, excluded from generated commands, and kept in manual review.
- Excel comparison export includes dedicated MAC Authentication detail and dependency-stage worksheets.
- Config Delta recognizes Huawei STA and WIDS whitelist profiles as independent nested `wlan` objects.
- Source-only `sta-mac` entries are generated inside the correct whitelist profile. Target-only entries stay report-only.
- VAP `sta-access-mode whitelist` bindings resolve to their STA whitelist dependency in the MAC Authentication view.
- Huawei PSK `pass-phrase` values are masked and excluded even when the command omits the `cipher` keyword.
- Same-vendor comparison for Huawei-to-Huawei and Cisco 9800-to-Cisco 9800 backups.
- Structured difference states: Identical, Missing on Target, Value Mismatch, and Extra on Target.
- Target-only objects are report-only and never generate an automatic removal command.
- Sensitive values and device-specific settings are masked, excluded from generated commands, and flagged for manual review.
- Downloadable implementation candidate, rollback candidate, and multi-sheet Excel comparison report.
- AP Role Diff workspace for paired TTC/HO Huawei WLC operational inventories.
- Matches AP identities by MAC, then serial number, then AP name. AP ID differences are ignored.
- Classifies Active TTC, Active HO, Dual Active, No Active, and backup-peer-not-ready states.
- Optional Expected Allocation CSV/XLSX detects APs active on the wrong controller.
- Compares group, IP, model, software version, MAC, serial, and AP name between peers.
- Recognizes Huawei `Group name` as an AP Group field in AP Info CSV/XLSX exports.
- AP Groups tab summarizes AP count, active controller, healthy pairs, role issues, group mismatch, and missing peer coverage per group.
- Group drill-down filters the AP list by Mapping Group and mapping status.
- Explicit mapping states distinguish Matched, Group Mismatch, Peer Group Missing, and Unassigned APs.
- Exports a twelve-sheet AP Role Diff Excel workbook, including Group Summary, AP by Group, and Group Mismatch.
- Plain-language AP Status Guide explains Normal, Standby, Idle, and Fault for non-specialist users.
- TTC/HO role-pair examples explain healthy active/standby combinations and critical anomalies.
- Status explanations are available in the UI, accessible badge descriptions, and Excel export.
- Vendor-specific AP Master Inventory templates for Cisco Catalyst 9800 and Huawei WLC, with optional AP count and automatic naming by site, floor/area, and prefix.
- CSV/XLSX AP master validation checks mandatory identity columns, duplicate AP name/serial/MAC, invalid MAC format, and non-standard deployment status.
- Compares the master inventory against actual APs from the WLC analysis (match priority: MAC, serial number, AP name, then AP ID) and reports Validated, Mismatch, Matched - Status Review, or Missing from WLC per planned AP, plus any unexpected AP found on the WLC but not in the master.
- As-built Excel export includes the validation summary and an Unexpected AP worksheet.
