# Changelog

Newest first. Module versions are listed in `core/modules.py`.

## Unreleased

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
