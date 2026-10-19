# Convert (Configuration Studio)

Convert has five pages, one per kind of device, the same five as Analyze:

| Page | URL | Converter today |
| --- | --- | --- |
| Wireless | `/convert/wireless` | none yet |
| Switch | `/convert/switch` | Cisco / Aruba / Huawei switches (Huawei VRP target, standard config profiles), hardware catalog and Interface map |
| Router | `/convert/router` | none yet (router hardware catalog and interface-name reference only) |
| Firewall | `/convert/firewall` | MikroTik RouterOS 6/7 to Palo Alto (interface/zone mapping, IPsec, SD-WAN, Panorama) |
| Load Balancer | `/convert/load-balancer` | none yet |

`/convert/` and `/configuration/` redirect to the Switch page. The JSON API stays under `/configuration/api/*`; the page sends a `domain` field with every request.

## The rules

1. **The page is the device type.** Auto Detect only chooses the vendor, and only among vendors that have a parser in that domain.
2. **A clearly different file is refused.** If a router backup is uploaded on the Switch page, the engine says it looks like a router and points to the right place instead of running the wrong parser. Only high-confidence classifications block; anything unclear is passed to the parser as before.
3. **No converter, no form.** A domain with no parser/translator registered shows what it cannot do yet, what it needs, and a link to the matching analyzer. The API answers 400 for it. It never pretends to convert.
4. **The user is in charge.** Choosing a vendor explicitly skips the mismatch guard.

## Where things live

| File | Role |
| --- | --- |
| `features/configuration_studio/converter_engine/domains.py` | Domain registry (`DOMAINS`) and `classify()`: decides which domain a file belongs to, with evidence. |
| `features/configuration_studio/converter_engine/detector.py` | Vendor/device scoring used inside a domain. Unchanged scoring; `classify()` corrects its known false positives (routers as "Cisco FTD" or switch, PAN-OS CLI as Aruba switch). |
| `features/configuration_studio/converter_engine/engine.py` | Parser and translator registries keyed by `(domain, vendor)`. |
| `features/configuration_studio/service.py` | `convert_file`, `preview_mapping`, `supported_platforms(domain)`, `domain_overview()`, `ensure_domain_available()`. |
| `features/configuration_studio/routes.py` | Pages blueprint (`/convert/<slug>`) and the API blueprint (`/configuration/api/*`). |
| `features/configuration_studio/converter_engine/hardware/` | Hardware catalog (`switches.py`, `routers.py`, `models.py`), lookups (`catalog.py`) and the interface-map engine (`interface_map.py`). See the next section. |
| `features/configuration_studio/converter_engine/session_capture.py` | Cuts the `show running-config` block out of a terminal session before detection and parsing. |
| `features/configuration_studio/converter_engine/nac.py` | 802.1X / MAB settings per port and the Huawei NAC and AOS-CX port-access mappings. |
| `core/modules.py` | One Convert tool per domain (`convert_<domain>`). `status="planned"` marks pages without a converter. |
| `tests/test_convert_domains.py` | Guard rails: registry vs. module registry, classification fixtures, mismatch guard, page and API behaviour. |

## Hardware catalog and interface map

`hardware/` answers "which physical ports does this box have and what does the CLI call each one". Every model carries port groups (CLI keyword, naming template, range, speed class, medium, PoE), compatible uplink modules, a stack limit when the data sheet states one, and a link to the vendor data sheet.

- **Source model** is read from the config text (`PID:`, `Model Number`, `cisco <model> (...) processor`, the Aruba `; JL724B ... Configuration Editor` banner). Lines that state the chassis outright outweigh a neighbour table that merely mentions another model. The uplink module is read from `PID: C9300-NM-...`; when the capture has no inventory the model's default module is assumed and the map says so.
- **Target model** comes from the Target Model dropdown, and every list is built from the catalog: Huawei CloudEngine (six models, below), Cisco IOS-XE Catalyst (the uplink module is part of the choice, `C9300-48P+C9300-NM-8X`) and Aruba CX 6200F. Nexus is source/reference only because the Cisco translator does not emit NX-OS.
- **Mapping** is by role (access, uplink, management), speed class and position, never by the digits alone: `Te1/1/3` is the third port of the uplink module. A port on a faster class is `review`, copper landing on an SFP cage is `review` with the transceiver note, and a port the target does not have is `missing` and is written into the converted config as a review line. Multi-speed stanzas of a module slot that are not physical ports are reported as `stanza`.
- The map is stored on the config (`metadata["interface_map"]`, `metadata["port_map"]`) before translation. The Huawei translator reads it for uplink-module ports, the Cisco and Aruba translators for every port of a known source model. Without a known source model nothing changes: the old name-based rules apply.
- The Switch page shows the map in an Interface map tab of every result; the Switch and Router pages show the catalog as a collapsible tree: vendor, then product line with its OS (Cisco: Catalyst IOS-XE, Nexus NX-OS; Aruba: CX AOS-CX; Huawei: CloudEngine VRP), then series, then model. `catalog_tree()` in `hardware/catalog.py` builds it from the same models; `split_platform()` derives line and series from the model's `platform` text. The router catalog lists onboard ports and every expansion slot's naming pattern; router conversion itself is still not available.

Huawei models (vendor `Huawei`, OS `VRP`, source and target): S5735-L8T4X-QA-V2, S5735-S24T4XE-V2, S5735-S24P4XE-V2, S5735-S48T4XE-V2, S5755-H24T4Y2CZ and S5755-H48UM4Y2CZ. Port names follow the project's drafted devices: `GE<m>/0/<n>`, `10GE`, `25GE`, `100GE` (and `40GE` for a QSFP28 cage run at 40G), `MEth0/0/0`; the Multi-GE ports of the UM model are `MultiGE<m>/0/<n>` (an access port converted to that model is written under that name, interface type confirmed in the V600R025C00 command reference). When a Huawei configuration is the source, the older spellings `GigabitEthernet0/0/n` and `XGigabitEthernet0/0/n` are recognised as well. Stack limit 9 comes from the S5735-S-V2 and S5755-H data sheets; the S5735-L-Q-V2 brochure supports iStack without a member limit, so none is enforced. The two 10G[STACK] cages of the S5735-S models are described in the model notes but not mapped, because the sources do not state their interface numbers; split 40G/100G ports are not modelled. The management port `MEth0/0/0` is the project's convention (V600R025C00 stack guide) and is not visible on the front-panel pictures.

Aruba CX 6200F (JL724B): VSF takes up to 8 members, fixed-port SKUs of the 6200 family can be mixed (AOS-CX Virtual Switching Framework Guide for 6200, 6300 Switch Series, edition 3, April 2023). The out-of-band management port is `interface mgmt` and is configured with `ip static <ip>/<prefix>` (AOS-CX Fundamentals Guide, "Management interface"); it has no `routing` and no `vrf attach`. The Fundamentals guide names the port for the 6200 series, not for the JL724B in particular.

Adding a model, step by step:

1. Add a `HardwareModel` to `hardware/switches.py` (or `routers.py`): `key` (the PID as printed in the inventory), `vendor`, `platform` written as `<product line> <series>` (the tree splits on the first space: `Catalyst 9300`, `CloudEngine S5735-S-V2`, `CX 6200F`), `os_name`, `label`, `summary`, `groups` (one `PortGroup` per run of identical ports: role, CLI keyword, template with `{m}` member and `{n}` port, first/last, speed class, medium, PoE, `aliases` for older spellings) and `detect` strings (what the model prints in `show version` / the inventory).
2. State `max_members` only when the data sheet or guide says so, and name the document in `notes`; leave `None` otherwise. Put what the sources do not confirm into `notes`, not into a port group.
3. Give `doc_title` and a `doc_url` that opens. `target_ok=True` makes it a Target Model choice; the translator for that vendor must be able to write its port names.
4. Nothing else registers the model in the tree: product line and series come from `platform`, and a new product line appears as its own branch.
5. Test it in `tests/test_hardware_catalog.py`: port counts, one converted name per role, the detection string, and (the tree test already checks) that the model is in exactly one leaf.

## Session captures

Engineers save the whole terminal session, not only the configuration. `converter_engine/session_capture.py` finds the output of `show running-config` (also `display current-configuration`, `show running-config all`, the IOS abbreviations) in a switch file and gives the parser only that block; the result carries `capture` (`command`, `total_lines`, `config_lines`) and the page shows it next to the line count. A typed-ahead command printed between the echo and the output is skipped. A file that is not a session, or whose block is under 15 lines, is passed on unchanged. A session with several `show` outputs and no configuration is refused with the command to collect. The whole capture stays available for the hardware catalog (`identity_text`), because the chassis and uplink-module PIDs are in `show inventory`, not in the configuration.

## Port authentication (802.1X / MAB)

`converter_engine/nac.py` reads the `authentication ...`, `mab` and `dot1x ...` lines of each Cisco interface into one settings object; ports with identical settings share one Huawei authentication profile (`authentication-profile`, `dot1x-access-profile`, `mac-access-profile`, an access domain bound to the RADIUS scheme). The mapping table is in the module docstring; every command is documented in the Huawei CloudEngine S3700/S5700/S6700 V600R025C00 Configuration Guide - User Access and Authentication ("NAC Configuration", https://support.huawei.com/enterprise/en/doc/EDOC1100333463) and its Command Reference. What has no documented equivalent (`timer reauthenticate server`, `server dead action authorize voice`, MAB-first order, violation, open authentication) is listed once per profile as a review item. Cisco to Cisco keeps the lines unchanged. Aruba CX targets get AOS-CX port access, checked against the AOS-CX 10.11 Security Guide for the 6200, 6300 and 6400 series (chapter "Port access"): global `aaa authentication port-access dot1x authenticator enable` and `mac-auth` / `enable`, then per interface `auth-precedence`, `auth-mode` (`multi-domain`, `device-mode`) or `client-limit`, `critical-role` (the role `CRITICAL-VLAN<n>` holds `vlan access <n>`), and the `dot1x authenticator` / `mac-auth` contexts with `eapol-timeout`, `reauth`, `reauth-period` and `enable`. The table is in the `nac.py` docstring. Not generated, and listed once per port group: `event server alive`, `timer reauthenticate server`, open authentication, violation, `mab eap`, and the RADIUS server group binding (RADIUS servers are a review item in the AOS-CX translator, so the binding command is given as an instruction). Documentation: https://arubanetworking.hpe.com/techdocs/AOS-CX/

Related Huawei mappings checked in the same documents: TACACS+ servers become primary, secondary, third and fourth in order; `ip dhcp excluded-address` becomes `excluded-ip-address` in the pool's global view; `no snmp trap link-status` becomes `undo enable snmp trap updown`.

## Huawei baseline and VTY/console lines

Cisco `line vty` / `line con` blocks become `user-interface vty|con`: `login local` is `authentication-mode aaa`, `transport input ssh` is `protocol inbound ssh`, `exec-timeout` is `idle-timeout`, and `access-class <acl> in|out` is `acl <acl> inbound|outbound` (a numbered Cisco ACL carries the name `ACL-<n>`). The ACL syntax is from the V600R025C00 Command Reference, "acl (VTY-type user interface view)": `acl { acl4name | acl4num } { inbound | outbound }`. Transport and access-class on a console line are review lines.

The Switch Analyzer checks a Huawei `display current-configuration` against Huawei's Baseline Check Items for Security Configuration of Campus Switches (V600R025C00, Mandatory and Optional workbooks in `Official Reference Huawei`): VTY protocol, idle timeout, authentication mode and ACL (SW-VTY-001 to 004), console authentication (SW-CON-001), SSHv1, IP-block and all-interface listening (SW-SSH-002/003, SW-TEL-002, SW-FTP-002, SW-HTTP-002, SW-MGT-001), SNMP ACL and blacklists (SW-SNMP-005/006), NTP listening on all interfaces (SW-NTP-003), and account locking, password complexity and the initial-password prompt, plus local users that may use Telnet or FTP (SW-AAA-101 to 106). `display current-configuration` leaves out default values, so a setting whose default is already the recommended one is only reported when an explicit `undo` or `disable` line is present, and one that needs a command (`protocol inbound ssh`, an SNMP ACL) is reported when it is absent. Secrets are never printed. Each finding names the baseline item and links the Huawei configuration guide: https://support.huawei.com/enterprise/en/doc/EDOC1100333463

## Lessons from real Huawei and Cisco captures

Real output was compared with the converter and the analyzer (customer files stay outside the repository; fixtures are synthetic).

- Two source ports must never land on one target port. The port map is built from the target model named by the migration inventory, a source model that is not in the catalog falls back to a generic uplink naming, and `_collapse_same_port_stanzas` merges the personality stanzas of a multi-speed Cisco cage (Gi1/1 and Te1/1 are one physical port).
- Optic lines follow the cage, not the source: `device transceiver 1000BASE-X` for a 1G optic in a 10GE cage, plus `port mode GE` in a 25GE cage (the whole four-port bank changes). The pattern is taken from the real after-migration configurations; no Huawei document page was fetch-verified for it, so the 25GE case carries a REVIEW line about the whole bank.
- `undo poe enable` belongs to copper PoE access ports; it is not written on SFP cages, VLAN, Eth-Trunk or loopback interfaces.
- The management Ethernet port is in the built-in VPN instance `management`. The converter writes `ip binding vpn-instance management` on `MEth0/0/0`; the source VRF name (for example `Mgmt-vrf`) does not exist on the Huawei switch.
- Still unconfirmed and therefore not modelled: stack ports of the other Huawei models (the S5735-S24T4XE-V2 is confirmed, below), `MEth0/0/0` per model, the S5735-L stack limit, the Aruba 2540 stacking limit.

## Two switches into one stack

Lexus replaced two standalone Catalyst 2960 (24TC-L and 2960+ 24TC-L) with one stack of two S5735-S24T4XE-V2. Convert each old switch as its own file with **Stack member** 1 and 2 and **Units in the stack** 2: ports become `GE1/0/n` and `GE2/0/n`, the stack-link ports `GE<m>/0/21-22` stay free (REVIEW-STACK-PORT), and the header carries the stack commands (template B, regular UTP cable) for that member. The global settings (VLANs, AAA, SNMP, NTP, management IP) are taken once, from member 1; from member 2's file take the interface blocks. The link between the two old switches (Port-channel and the trunk ports) carries REVIEW-STACK-LINK and is dropped by the engineer: the stack cables replace it. What the converter cannot decide stays a review: the real stack moved the LACP uplink to the core onto GE1/0/4 and GE2/0/4 (an Eth-Trunk across both members), which is a design change, not a conversion. The analyzer then checks the result: `display stack`, `stack topology`, `dual-active`, the troubleshooting history and SW-STK-007 (an Eth-Trunk inside one member).

Evidence: `display stack configuration` of the real stack binds `GE1/0/21` and `GE1/0/22` to Stack-Port1/1 and 1/2 and `GE2/0/21` and `GE2/0/22` to Stack-Port2/1 and 2/2, with `10GE<m>/0/5` and `10GE<m>/0/6` as the alternative media (marked `#` when no optic is present); `display dual-active` lists those ports as not configurable. Huawei Virtualization Configuration Guide (stack support): https://support.huawei.cn/enterprise/en/doc/EDOC1100458710/ca59e588/s5735i-s-v2-stack-support . Cisco 2960 LAN Base data sheet: https://www.cisco.com/c/dam/en_us/solutions/small-business/products/routers-switches/catalyst-2960-series-switches/C78-481303-01_2960-LAN_DS_v1a.pdf . Cisco 2960-Plus data sheet: https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-2960-plus-series-switches/data_sheet_c78-728003.html . Huawei VBST with Cisco PVST: https://support.huawei.com/enterprise/en/doc/EDOC1000114005 (found by search; Huawei blocks fetching it).

Switch Analyzer reads the Huawei stack and device state (`features/switch_analyzer/huawei_live.py`): `display stack`, `stack topology`, `stack configuration`, `dual-active` / `mad`, `stack troubleshooting history`, `vlan summary`, `arp statistics`, `license`, `stp region-configuration`. Findings SW-STK-001 to 006, SW-ARP-001 and SW-CAP-101. A stack should have dual-active detection configured (Huawei Virtualization guide, stack support: https://support.huawei.cn/enterprise/en/doc/EDOC1100458710/ca59e588/s5735i-s-v2-stack-support).

## Catalyst 3650 stack to S5755-H24T4Y2CZ stack

The four Depo sites (Makassar, Manado, Pekanbaru, Semarang) replaced two-member Catalyst 3650 stacks with two-member S5755-H24T4Y2CZ ring stacks. Convert the stack source once with target model S5755-H24T4Y2CZ: the converter sees the second member in the interface names, maps `Gi<m>/0/n` to `GE<m>/0/n` and the uplink module `Gi<m>/1/n` to `25GE<m>/0/n`, and keeps `25GE<m>/0/3-4` free for the stack. The header holds the member commands (`stack member 1 renumber <m>`, `priority`, `interface stack-port <m>/1` and `/2` with `port member-group interface 25GE <m>/0/3` and `/4`); the stack configuration lives in device memory, so the deployed `current-configuration` shows `stack` and the `Stack-Port` blocks empty and the converter writes the commands as comments.

Things the converter leaves to the engineer: dual-active detection (none of the four deployed stacks has it; Virtualization guide, relay mode on Eth-Trunk for a core), `port mode 10GE-GE` on the 25GE bank when an uplink must run 1G next to the 10G stack links (documented, not yet seen on a real device), the NetStream aging timers (`netstream timeout ip active|inactive <seconds>`, defaults 1800 and 15) and the zone name of `clock timezone` (the real drafts use WIB).

Documentation: the V600R025C00 Stack Configuration guide (2.6.11 S5755-H stack support, 2.8.2 configuring a stack by manually binding member ports) and command reference (`port member-group interface`, `port mode`, `netstream export ip host`, `netstream export ip source`, `netstream timeout ip`, `clock timezone`) from Huawei Support, product CloudEngine S300, S500, S2700, S5700 and S6700 V600R025C00: https://support.huawei.com/enterprise/en/doc/EDOC1100333463 (the configuration guide; Huawei Support asks for an account for some documents, so the command-reference page is cited by name). S5755-H data sheet: https://e.huawei.com/en/products/switches/campus-switches/s5755-h-gigabit . Stack support (older release, same feature): https://support.huawei.cn/enterprise/en/doc/EDOC1100458710/ca59e588/s5735i-s-v2-stack-support . Cisco Catalyst 3650 Flexible NetFlow (IOS XE 16.3, flow exporter / monitor, found by search): https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3650/software/release/16-3/configuration_guide/b_163_consolidated_3650_cg/b_163_consolidated_3650_cg_chapter_01001010.html .

## Cisco Nexus 9000 (NX-OS) source

Real NX-OS 10.4(5) / 10.5(4) captures (two N9K-C93180YC-FX3 vPC aggregation switches and four N9K-C93108TC-FX top-of-rack switches) showed what the Catalyst-shaped parser had to learn:

- **ACLs.** Every entry carries a sequence number, prefixes are CIDR, and `addrgroup` / `portgroup` point at `object-group ip address|port` blocks. `parsers/switch/nxos_acl.py` flattens each entry to the IOS dialect (object-groups expanded as source x source-port x destination x destination-port, capped at 512 rules per entry; an unknown group or an over-size entry stays verbatim for review). The Huawei translator writes real `rule` lines (service names as port numbers, source ports, `gt`/`lt`/`range`; `log` keeps the rule and adds REVIEW-ACL-LOG); the Aruba translator writes `access-list ip` entries (`seq permit|deny proto SRC [port] DST [port] [established] [log]`, remarks as `seq comment`; `neq` and non-contiguous wildcards stay REVIEW-ACL).
- **Users.** `username X password 5 <hash>  role network-admin` keeps the role out of the hash. Huawei levels: network-admin 3 (Management), network-operator 1 (Monitor); any other role becomes level 0 with REVIEW-USER-ROLE. The factory aging line (`passphrase lifetime 99999`) is dropped.
- **VRF routes.** `ip route` indented under `vrf context NAME` belongs to that VRF: `ip route-static vpn-instance NAME ...` on Huawei, `ip route ... vrf NAME` on AOS-CX, `ip route vrf NAME ...` on Cisco. Before, a management-VRF default route was written into the global table.
- **VLAN lists.** `vlan 1-15,18-19,...` creates every VLAN in the list (VLANs without a name have no block of their own).
- **Trunks.** A trunk without an allowed list is `vlan trunk allowed all` on AOS-CX.
- **Noise.** The `!Command:` banner, `vdc`, `limit-resource`, `version` and the enablers `feature interface-vlan|lacp|vpc|hsrp` are not review items (`translators/switch/nxos_noise.py`); a bare `switchport` and `hsrp version 2` are no-ops.
- **Ports.** A port the catalog cannot place on the chosen target (25G SFP28 access ports on a GE-copper model) keeps its source name and the catalog's own reason instead of a guessed `GE1/0/n`. Catalog: N9K-C93180YC-EX / FX / FX3 (48x 1/10/25G SFP28 + 6x 40/100G QSFP28).

The Switch Analyzer reads the NX-OS state commands the collect script asks for (`nxos_state.py`): features, modules, boot variables, reset reasons, cores, process logs, switchport, error counters (three tables merged per port), transceiver DOM, port-channel database, vPC orphan ports, STP roots, VRFs, syslog servers and the route summary. A capture whose ACL lines have a typed-ahead command glued into them is reported as SW-NX-CAP-001.

Documentation: Cisco Nexus 9000 NX-OS Security Configuration Guide 10.3(x), "Configure IP ACLs"; HPE Aruba AOS-CX 10.13 ACLs and Classifier Policies Guide (`access-list ip`, `apply access-list ip`), 10.14 Layer-2 Bridging Guide (`vlan trunk native`, `vlan trunk allowed all`), 10.15 IP Routing Guide (`ip route ... vrf <VRF-NAME>`); the links are under References.

### vPC, VSX and the pre-flight tab

- **Target fit.** `target_fit()` compares the ports the source uses with the chosen target and reports `fits` / `partial` / `does-not-fit` / `unknown`, with catalog models on which every used port would exist. The Interface map tab shows it as a banner. Example: the Nexus 93180YC aggregation pair (48x 25G + 6x 100G) does not fit a 24-port S5755 and fits the S6730-H48Y6C-V2.
- **vPC to VSX (AOS-CX).** `vsx` with `inter-switch-link lag`, `role`, `keepalive peer ... source ...`, `linkup-delay-timer`; member port-channels are `interface lag N multi-chassis`. `system-mac` and `peer-switch` stay REVIEW. NX-OS `management` is the built-in `mgmt` VRF.
- **vPC role priority.** NX-OS: lower value = primary. Huawei M-LAG: higher DFS-group priority = master (default 100). Only the direction is carried: primary 150, secondary 100.
- **Pre-flight tab and post-conversion checks.** `preflight.py` summarises the converted text; `postcheck.py` adds duplicate ACL rules, permit-all / no-deny ACLs and empty LAGs. The checks look at the exact bytes that will be pasted.

Documentation: Cisco, "Understand the vPC Election Process" (https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/nx-os-software/212589-understanding-vpc-election-process.html); HPE Aruba Networking VSX examples (https://developer.arubanetworks.com/aoscx/v10.04/docs/architecture-ii-dedicated-data-center-two-tier , https://arubanetworking.hpe.com/techdocs/VSG/docs/050-dc-deploy/esp-dc-deploy-730-central-two-tier-lossless-core/); Huawei CloudEngine S6730-H-V2 25GE product page (https://e.huawei.com/en/products/switches/campus-switches/s6730-h-v2-25g); Huawei M-LAG white paper, DFS group priority (https://actfornet.com/ueditor/php/upload/file/20181230/1546128876958575.pdf, third-party copy of the Huawei document; the V600R025C00 page itself refused the fetch).

## Adding a converter

1. Write the parser under `parsers/<domain>/` and the translator under `translators/<domain>/`.
2. Register both in `engine.py` with the domain key first, for example `("router", "cisco")`. The page switches from "not available" to a working form with no other edit.
3. In `core/modules.py`, remove `status="planned"` from that Convert tool and set its version. `test_static_planned_flag_matches_registered_converters` fails until the two agree.
4. Add the platform's markers to `DeviceDetector` or `classify()` and a masked fixture under `tests/fixtures/` that proves the detection.
5. Add parser tests from a real backup, including the lines the parser cannot translate: they must surface as review markers, never be dropped silently.

## Known limits

- Router classification identifies Cisco IOS/IOS-XE and Huawei routers only when there is strong evidence; thin captures stay "unknown".
- Wireless, Router and Load Balancer have no converter. Each page lists what is needed (a source backup, a mapping decision, and a known-good target for comparison).
- FortiGate and FortiSwitch are analyzed, not converted. Palo Alto is a conversion target only.
- A Palo Alto source file may be XML, `set` commands, or a terminal capture of `show config running` (curly view). A capture with only operational output (no configuration) gives identity and interfaces but no policy; the Firewall Analyzer reads it for health and lifecycle findings.
- Terminal logs (PuTTY, SecureCRT) are replayed through `features/analyzer_core/terminal.py` before parsing, so prompt repaints, pager lines and wrapped rows do not reach the parsers.

## References

- Cisco Catalyst 9300 data sheet: https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html
- Cisco Catalyst 9200 data sheet: https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/nb-06-cat9200-ser-data-sheet-cte-en.html
- Cisco Nexus 93108TC-EX / FX / FX3 data sheets: https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/datasheet-c78-742283.html , https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/datasheet-c78-742284.html , https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/datasheet-c78-744052.html
- Huawei CloudEngine S5735-L-Q-V2, S5735-S-V2 and S5755-H (Gigabit, Multi-GE) product pages with the data sheets: https://e.huawei.com/en/products/switches/campus-switches/s5735-l-q-v2 , https://e.huawei.com/en/products/switches/campus-switches/s5735-s-v2 , https://e.huawei.com/en/products/switches/campus-switches/s5755-h-gigabit , https://e.huawei.com/en/products/switches/campus-switches/s5755-h-multi-ge
- HPE Aruba Networking CX 6200 data sheet: https://www.hpe.com/psnow/doc/a00097415enw
- Cisco Catalyst 8200 / 8300 data sheets: https://www.cisco.com/c/en/us/products/collateral/routers/catalyst-8200-series-edge-platforms/nb-06-cat8200-series-edge-plat-ds-cte-en.html , https://www.cisco.com/c/en/us/products/collateral/routers/catalyst-8300-series-edge-platforms/datasheet-c78-744088.html
- Cisco ISR 4000 and ASR 1000 data sheets: https://www.cisco.com/c/en/us/products/collateral/routers/4000-series-integrated-services-routers-isr/data_sheet-c78-732542.html , https://www.cisco.com/c/en/us/products/collateral/routers/asr-1000-series-aggregation-services-routers/datasheet-c78-731632.html

- Cisco IOS XE configuration guides: https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-17/products-installation-and-configuration-guides-list.html
- Huawei CloudEngine S3700/S5700/S6700 V600R025C00, User Access and Authentication, NAC Configuration: https://support.huawei.com/enterprise/en/doc/EDOC1100333463
- HPE Aruba Networking AOS-CX documentation portal (Security Guide, Port access; Virtual Switching Framework Guide; Fundamentals Guide): https://arubanetworking.hpe.com/techdocs/AOS-CX/
- Huawei VRP command references are published per product on https://support.huawei.com/enterprise/ (needs a Huawei support account for some documents, so no deep link is pinned here).
- MikroTik RouterOS export: https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management
- PAN-OS CLI cheat sheet (operational commands read by the runtime analyzer): https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-cheat-sheet-networking
- PAN-OS CLI and config structure: https://docs.paloaltonetworks.com/pan-os
- Cisco Nexus 9300-FX3 data sheet (N9K-C93180YC-FX3): https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/datasheet-c78-744052.html
- Cisco Nexus 9000 NX-OS Security Configuration Guide 10.3(x), Configure IP ACLs: https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/configuration/security/cisco-nexus-9000-nx-os-security-configuration-guide-103x/m-configuring-ip-acls.pdf
- AOS-CX 10.13 ACLs and Classifier Policies Guide (6300, 6400, 8100, 8360): https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/PDF/acls_6300-6400-8100-8360.pdf
- AOS-CX 10.14 Layer-2 Bridging Guide, vlan trunk native: https://arubanetworking.hpe.com/techdocs/AOS-CX/10.14/HTML/l2_bridging_8400/Content/Chp_vlans/vlan_cmds/vla-tru-nat.htm
- AOS-CX 10.15 IP Routing Guide, ip route (VRF): https://arubanetworking.hpe.com/techdocs/AOS-CX/10.15/HTML/ip_route_8400/Content/Chp_VRF/VRF_cmds/ip-rou-vrf82.htm
