# Changelog

Newest first. Module versions are listed in `core/modules.py`.

## Unreleased

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
