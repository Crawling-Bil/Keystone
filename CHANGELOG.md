# Changelog

Newest first. Module versions are listed in `core/modules.py`.

## Unreleased

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
