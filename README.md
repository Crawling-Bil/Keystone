# Keystone — Network Engineer Suite Web v1.9.2

Local-first web application for network engineering workflows. Keystone runs on `http://127.0.0.1:8002` and includes Configuration Studio, Wireless Analyzer, Switch Analyzer, and Lifecycle Manager in one browser workspace.

## Operations UI design

- FTD-inspired dark-first operations workspace with a cool light theme available.
- Task-first dashboard that helps mixed-seniority teams choose the correct workflow without a separate briefing.
- Self-hosted Archivo and Atkinson Hyperlegible fonts; no font CDN or internet connection required.
- Responsive layouts verified across all routes at 390 and 1440 pixel widths.
- Keyboard-friendly navigation, visible focus states, skip link, and semantic active-page state.
- Searchable tool index (`/` shortcut), plain-language selection guide, and live local-service health check.
- Consistent SVG icon system, 44px minimum controls, reduced-motion support, and accessible status feedback.
- Navy/charcoal surfaces, cyan primary actions, restrained semantic status colors, and consistent FTD-style hierarchy.
- Wireless Analyzer intake reorganized into three explicit steps: required WLC config, recommended AP runtime inventory, then vendor + analysis.
- Equal upload cards on desktop, stacked workflow on mobile, and compact two-column summary metrics on small screens.

## Huawei AC6508 validation preserved

- Tested against a real AC6508 configuration backup and AP Info CSV export.
- Accepts tab-prefixed Huawei CSV headers.
- Imports runtime `Status`, `AP type`, `System version`, IP, group, serial, and MAC fields.
- Enriches AP runtime data before deployment comparison to prevent false model mismatches.
- Validated test result: 49/49 AP matched, with runtime status/model/version/IP populated.

## Wireless Analyzer v1.11.0

- AP Model & Software Summary in Overview, grouped by device type and runtime version.
- Dedicated VAP Profiles tab keeps the existing WLAN/SSID catalog intact while exposing one row per Huawei VAP.
- Each VAP row resolves SSID/profile, base and effective service VLAN, security, authentication, traffic, forwarding, AP Group/site, AP count, radio, WLAN ID, usage scope, and full profile commands.
- VAP usage is classified as Site-specific, Shared across sites, or Unassigned to make site-level service delivery immediately visible.
- Huawei profile parsing is indentation-aware so nested `wlan` siblings cannot contaminate each other's configuration.
- The Wireless Analysis workbook includes a dedicated `VAP Profiles` worksheet.
- Consistency indicators for consistent, mixed, partial, and unavailable version data.
- Click-through filtering from a model/version group to the detailed AP Inventory.
- `AP Device Summary` worksheet added to the Wireless Analysis Excel export.
- Config Delta workspace inside Wireless Analyzer for directional Source-to-Target comparison.
- Comprehensive Config Delta coverage compares every configuration section, not only predefined wireless profiles.
- Known Huawei/Cisco objects use structured parsing; ACLs, traffic policies, services, routing, management, and previously unknown sections are retained by a safe fallback parser.
- ACL objects and individual rules are compared directionally, including Missing on Target, Value Mismatch, and Target-only detail.
- Generated Delta includes safe Source-only commands in dependency order; credentials, controller-specific settings, and destructive actions remain in Manual Review.
- Dependency-aware MAC Authentication tab follows Huawei AAA/RADIUS, access profiles, authentication policy, WLAN bindings, and AP group delivery.
- Huawei nested `aaa` and `wlan` objects are compared independently with their CLI hierarchy and radio-level indentation preserved.
- Local AAA users and credential-bearing commands are masked, excluded from generated commands, and kept in manual review.
- Excel comparison export includes dedicated MAC Authentication detail and dependency-stage worksheets.
- Config Delta recognizes Huawei STA and WIDS whitelist profiles as independent nested `wlan` objects.
- Source-only `sta-mac` entries are generated inside the correct whitelist profile; Target-only entries remain report-only.
- VAP `sta-access-mode whitelist` bindings resolve to their STA whitelist dependency in the MAC Authentication view.
- Huawei PSK `pass-phrase` values are masked and excluded even when the command omits the `cipher` keyword.
- Same-vendor comparison for Huawei-to-Huawei and Cisco 9800-to-Cisco 9800 backups.
- Structured difference states: Identical, Missing on Target, Value Mismatch, and Extra on Target.
- Target-only objects are report-only and never receive automatic removal commands.
- Sensitive values and device-specific settings are masked, excluded from generated commands, and flagged for manual review.
- Downloadable implementation candidate, rollback candidate, and multi-sheet Excel comparison report.
- AP Role Diff workspace for paired TTC/HO Huawei WLC operational inventories.
- Matches AP identities by MAC, then serial number, then AP name; AP ID differences are ignored.
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

See `PRODUCT.md` and `DESIGN.md` for the product and design-system rationale.

## Wireless Center

- New Deployment, Existing Deployment, and Health Assessment modes.
- Vendor-specific AP Master Inventory templates for Cisco Catalyst 9800 and Huawei WLC.
- Optional AP count and automatic naming generation by site, floor/area, and prefix.
- CSV/XLSX AP master validation.
- Checks for mandatory identity columns, duplicate AP name/serial/MAC, invalid MAC format, and non-standard deployment status.
- Planned-versus-actual WLC comparison.
- Match priority: MAC, serial number, AP name, then AP ID.
- Validation states: Validated, Mismatch, Matched - Status Review, and Missing from WLC.
- Unexpected AP detection.
- As-built Excel export with validation summary and unexpected AP worksheet.
- Existing WLC assessment, WLAN/SSID relationship, AP group/profile mapping, and analysis export remain available.

## Start on macOS/Linux

```bash
chmod +x setup_mac_linux.sh start_mac_linux.sh stop_mac_linux.sh verify_install.sh
./setup_mac_linux.sh
./verify_install.sh
./start_mac_linux.sh
```

## Start on Windows

Run `setup_windows.bat` once, then run `start_windows.bat`.

## Local security

The default server binds only to `127.0.0.1`. It is not exposed to other network devices unless the binding is intentionally changed.

## Operations Console v1.0

Keystone v0.6.0 adds a local browser-based SSH console at `http://127.0.0.1:8002/console/`.

Features:
- Interactive SSH shell using Paramiko `invoke_shell`.
- Cisco IOS/IOS-XE, Cisco Catalyst 9800, Huawei VRP, and Huawei WLC quick commands.
- Command history with Up/Down arrows.
- Pagination helpers: Space, q, and Ctrl+C.
- Dangerous-command confirmation.
- Downloadable session transcript.
- Localhost-only application binding by default.

For first real-device testing, confirm IP reachability and SSH credentials first. Generated warnings are guardrails, not a replacement for device authorization and change controls.

## Lifecycle Manager — Discovery, Firmware Upgrade & Jobs

- Subnet SSH discovery (`Start IP`–`End IP` range) logs into every reachable address once, identifies vendor/platform/model/version/serial from read-only inventory commands, and lists only devices that authenticated successfully — failed/unreachable IPs are reported separately rather than filling the device table.
- One TCP+SSH connection per scanned IP (no separate port pre-probe) — two rapid connections from the same source is exactly the pattern that trips Huawei VRP's SSH attack-defense IP blacklist, so discovery deliberately avoids it.
- A single job system (`pending → [prechecking →] ready → running → completed/failed`) is shared across every job type below — Upgrade, Config Push, and Config Backup all read/write the same job store and reuse the same live Execution Log / SSE stream.
- Firmware Upgrade: SFTP/TFTP/FTP firmware transfer, pre/post config backup, install, save, reload, and reconnect-wait, with Pre-Check validating SSH reachability, live device info, and firmware/storage compatibility before a job is allowed to start. Live-tested end-to-end against real Huawei VRP hardware (S5735-class), including parallel upgrade of multiple devices in one job.
- Demo Mode simulates every stage of any job type without touching real hardware, for safe rehearsal; a real (non-demo) run currently supports Huawei VRP end-to-end — other vendors' drivers implement discovery/device-info only.

## Lifecycle Manager — Config Push

- Pushes an operator-prepared draft config to an already-discovered device line-by-line over SSH — no firmware involved, device stays online throughout.
- Fully self-contained page (`/lifecycle/config-push`): select devices, assign a draft config each (pasted, or picked from a saved draft / Configuration Studio's converter output), create the job, then Run Pre-Check and Start Config Push — no detour through any other page required.
- Live per-line push results stream in as they happen; a full before/after config backup is captured automatically around the push for audit.

## Lifecycle Manager — Config Backup

- Captures a fixed, read-only ~40-command snapshot from an already-configured device over SSH: full running-config, hardware/elabel, VLAN/interface/port, LLDP/LACP/eth-trunk, STP, PoE, stack, dual-active, routing, licensing, ACLs, and the MAC address table.
- Read-only end to end, so there is no Pre-Check stage — a job goes straight from creation to Start.
- One command failing (unsupported on a given platform/firmware) never aborts the batch — every command is independent, unlike Config Push's line-by-line push which stops on the first rejection.
- Result is saved as one downloadable, timestamped backup bundle per device; each capture is kept as its own snapshot rather than overwriting the previous one, so a device accumulates a history over time.

## Live Logs & Device Reachability

- Live Logs (`/lifecycle/live-logs`) is a suite-wide, top-level page — merges Lifecycle Manager's Upgrade, Config Push, and Config Backup jobs with ZTP's activity feed into one real-time console, regardless of which module created the job.
- Device Reachability check (topbar action on Config Backup) is a fast, credential-free TCP/SSH-port probe an operator can run on demand against already-discovered devices. Discovery's own "online" status is a snapshot from whenever that IP range was last scanned with no timestamp recorded, so this adds an explicit, timestamped "reachable right now" signal instead.

## Lifecycle Manager — ZTP Provisioning

Lifecycle Manager's "ZTP Provisioning" tab replaces the manual console-and-preconfig step for onboarding a factory-default Huawei VRP switch (CloudEngine S5735/S5755-class, see the vendor's ZTP hardware support table) with DHCP-based Zero Touch Provisioning, following the vendor's "without a controller" flow: DHCP Option 67 points the switch at an SFTP-hosted intermediate file, matched to the device by ESN.

Features:
- Pre-register a device by ESN, hostname, management IP/mask/gateway, MAC, and credentials before it's ever powered on.
- Generates the ZTP intermediate file (`.ini`) and a per-device minimal bootstrap config (identity + SSH reachability only, not full production config) from the pre-registered device list.
- Built-in read-only SFTP server to host the generated files (VRP's ZTP flow requires SFTP; FTP/TFTP are not supported).
- Built-in DHCP server (wraps `dnsmasq`) for staging segments with no existing DHCP service, scoped to one explicitly named interface — it refuses to bind a wildcard/all-interfaces address and requires an explicit "isolated segment" confirmation before starting, to avoid becoming a rogue DHCP server on a shared network.
- A device is marked "provisioned" automatically the next time it's found by a real `/api/discovery` scan (matched by ESN), so completed devices stop reappearing in future deployment-file generation and DHCP reservations; it can also be marked manually from the device table.

**Optional system dependency:** the built-in DHCP server requires `dnsmasq` on the host (`apt install dnsmasq` / `brew install dnsmasq`) — it is not a Python package and is not installed by `setup_mac_linux.sh`/`setup_windows.bat`. It's only needed if you use Keystone's own DHCP server; skip it entirely if your staging segment already has DHCP with an Option 67 reservation pointing at the SFTP server started from this tab.

Not yet validated against real hardware: `rsa local-key-pair create` behavior when applied from a batch-loaded startup-config (rather than typed interactively at a console), and whether the target VRP client reads DHCP Option 67 from the packet's legacy BOOTP `file` field (where every mainstream DHCP server, `dnsmasq` included, places it) versus requiring a separate Option-67 TLV. Test against one spare unit before relying on this for a real rollout, and check the DHCP server's own log if a device gets a lease but never completes ZTP.
