# Sizing Tool

One place to see what runs today before choosing the replacement. The Sizing Tool takes any mix of device captures (Cisco, Huawei, Aruba, Palo Alto, FortiGate, F5), reads each one with the analyzer that already understands it, and rolls the result up for a refresh project: grouped by device type, with every component, the licences, the features in use, today and target figures, and a list of what the captures did not hold.

It extends the "sizing assessment" of the Switch Analyzer to every family: access points, wireless controllers, switches, routers, firewalls and load balancers. Nothing leaves the computer, and credentials, keys and hashes found in a capture are never shown or exported.

## How it reads

| Capture | Reader | Notes |
|---|---|---|
| Cisco Catalyst / Nexus, Huawei VRP, Aruba AOS-CX switch | Switch Analyzer (`switch_analyzer.service.analyze`, `sizing._device_sizing_row`) | Ports by speed, PoE, transceivers, stack members, VLANs, routing, ACLs, DHCP, FHRP. Parts from `show inventory` / `display device`. |
| Cisco IOS / IOS-XE router | Router Analyzer | Interfaces by speed, routes, BGP sessions, VRFs, IPsec, NAT, technology-package licences. |
| FortiGate, Palo Alto | Firewall Analyzer | Interfaces, policies, NAT rules / VIPs, VPN tunnels, zones, routes, HA, profiles. Palo Alto licences from `request license info` (also when the same file holds `show config running`). |
| F5 BIG-IP | Load Balancer Analyzer | Virtual servers, pools, members, nodes, profiles, provisioned modules, HA; licence bundle, add-ons and subscriptions with end dates from `tmsh show sys license` (the registration key is dropped). |
| Cisco C9800, Huawei AC | Wireless Analyzer | One controller record plus one access-point record per AP model, with the quantity. Huawei licences from `display license`. |

Files, ZIP archives, F5 UCS archives and files that hold several devices are split the same way as in the Topology Builder (`topology.ingest.to_captures`). A capture that cannot be read is listed with the reason and never stops the run.

## What the page gives

1. **By device type.** Models, brands, redundancy and tiers; what a replacement must carry (today, target and the largest single device); features in use; licences; what is missing; and the figures to collect before the design is final.
2. **Bill of materials.** Chassis, modules, power supplies, fans, stack cables, optics and access points added up by part number.
3. **Licences.** The licences and entitlements the captures hold, with state and expiry.
4. **Features in use.** How many devices use each feature and how many objects sit behind it (VLANs, BGP peers, policies, virtual servers, WLANs).
5. **Devices.** One row per record. A device can be left out (a duplicate, a lab box), given another type or site, then **Recalculate** (nothing is read again).
6. **Sites.** The site is the leading word(s) of the hostname (`JKT-SW1` is `JKT`).
7. **Gaps and inputs.** Each missing command with the devices it concerns, files that were skipped, a per-type checklist, and vendor documentation.

The **growth margin** (default 25 %) gives *target = today x (1 + growth)*, rounded up, for quantities that add up (ports, interfaces, policies, virtual servers, access points). Counts that do not grow with traffic (VLANs, zones, stack members, vsys) are shown as read. Throughput, concurrent sessions and SSL transactions are not in a configuration: they appear in the checklist, not as invented numbers. End-of-life dates are not stored (they go stale); the vendor pages are linked instead.

The **Excel workbook** (`keystone-<project>.xlsx`) has the sheets Summary, Devices, Sizing by type, Models, Capacity per device, Bill of materials, Licences, Features in use, Features per device, Sites, Gaps in the captures, and Inputs and links. Cells that start with `=`, `+`, `-` or `@` are written as text.

## Demo sets

The five Topology Builder scenarios (data center before and after a change window, firewall and F5 site, head quarter with branches, with and without a disaster recovery site) are reused as they are, so the same files serve both tools. A sixth set, **Campus with wireless and licences** (`features/sizing_tool/demo/campus`), is written for sizing: a Catalyst 9400 core with line cards and power supplies, a stack with PoE, Huawei and Aruba switches, an ISR router, a Palo Alto firewall (configuration, runtime and six licences in one file), a FortiGate pair, an F5 BIG-IP with provisioned modules and subscriptions, a Cisco C9800 with 24 access points in three models, and a Huawei AC with 12 access points. Every capture is invented (`example.test`, documentation address ranges).

## Honest limits

- Huawei licences are read from the documented layout of `display license` and tested on invented text; a real capture with more lines is read for the lines it has and the rest is left out, never guessed.
- Aruba switch licences are not in a switch capture: a note points to Aruba Central / HPE GreenLake.
- FortiGate: `get system status` gives the licence state only; FortiGuard services and their expiry come from FortiCare.
- The model of a PAN-OS capture that has no `show system info` is not known; the record says so.

## Version 1.1: planning, imports and a project you can reopen

**Capture pack.** A short list of read-only commands per platform (Cisco IOS-XE, Nexus, router; Huawei VRP; Aruba CX and AOS-S; Palo Alto; FortiGate; F5; MikroTik), with a reason for each command and the vendor's documentation. It is shown on the page and downloads as one text file. Each command is also in the project's own `static/collect-scripts` list (a test checks it, so the pack cannot drift) or is marked as a documented-only command.

**Peak figures.** A configuration holds no throughput. Peaks come from three places: the F5 `tmsh show sys performance all-stats` output (the maximum column), a CSV from monitoring (unit read from the header: Gbps, Mbps, %, sessions) and values typed in the Peaks tab. A typed value replaces a captured or imported one. Peaks that add up (throughput, sessions) enter the replacement plan.

**Imports** (Imports tab; column order does not matter, each column is found by its name and the answer says which one was used and how many rows matched a device by serial, then by hostname):

| File | Use |
|---|---|
| Site map | hostname or serial to site, building and floor; replaces the site guessed from the hostname |
| Peak figures | one row per device, every numeric column is a peak |
| Licence entitlements | Cisco Smart Account / SNTC, FortiCare, Aruba Central / HPE GreenLake, Palo Alto Customer Support Portal exports; dates become `YYYY-MM-DD`, a numeric `06/12/2026` is read day first and counted as ambiguous in the report |
| Lifecycle table | model, end of sale, end of support, replacement, copied from the vendor's page; the tool keeps no lifecycle dates of its own because they change |

A second file of the same kind replaces the first; **Remove this import** undoes it. A CSV over 5 MB or 50,000 rows is refused (a silent cut would leave devices out). Imported text is escaped on the page and neutralised in the workbook like any capture text.

**Replacement plan.** For each type (switches by tier) the page shows today, target, and a field for the capacity of one unit of the model being considered. *Units = target / (per-unit x (1 - spare %))*; the highest quantity decides; N+1 adds one unit and 2N doubles. The tool keeps no product catalogue: the capacity is typed from the datasheet (links are on the page), so the plan never goes stale. Licence-model notes say how entitlements move per vendor.

**Expiry.** Every licence with an end date: expired, ending within N months (default 12), a 24-month timeline and the full list. Dates from captures and imports are shown in ISO form.

**Data quality.** The same serial in two captures is counted once (the later one is flagged; *Count it anyway* overrides). Two boxes of one vPC / MLAG / VSX / HA design with the same model and names that differ by a trailing number or A / B are one logical unit. Stacks are one record with their members. NX-OS port speeds come from the `show interface status` Type column (QSFP-100G-SR4 is 100G; a 4x10G breakout stays in the explicit "speed not in name" bucket). Logical interfaces (port-channels, loopbacks, tunnels, BDI, AppGigabitEthernet) are not counted as physical ports. A Nexus capture without a port table, a router capture without a routing table, and a missing licence or PoE command each say so in the record's notes. Cisco C9800 power supplies come from `show inventory`.

**Evidence.** Every number lists the command or table it came from and a confidence: high (printed by the device or a configuration count), medium (a moment in time, such as link state), low (the capture lacks the command), entered (typed or imported).

**Project.** *Save project* writes `keystone-<name>.sizing.json` (the devices as read, the imports and the settings); *Open project* restores it with no capture needed. *Add captures* puts more files into the open run (new devices are numbered on and duplicates flagged). *Compare* shows what changed against an earlier run or a saved project (added, removed, changed, quantities that moved). A project file is untrusted input: it is parsed with a size limit, only known fields and types are kept, text is truncated, and it never carries a path. Every table has a filter box and sortable headers.

**Outputs.** The workbook now also has the replacement plan, expiry, peaks, evidence and lifecycle sheets. **Bill of materials (CSV)** has one line per part with quantity today and with growth and an empty column for the replacement part number, ready for a quoting tool.

## Version 1.2: what a real controller capture taught, merged captures, pairs from configuration, the right throughput, licence tiers

Built from a real Huawei AirEngine controller capture (a terminal log in which the whole session was typed three times). What failed was fixed in the shared readers, so the Wireless Analyzer, the Topology Builder, the Converter detector and this tool all benefit; no customer name, address or capture is kept in the repository.

**Controller captures** (`features/wireless_center/huawei_runtime.py`, `readers_extra.huawei_ac_extras`). Every table is read once however many times the session was repeated: access points, AP groups and interfaces are counted once; the radio table (`display radio all`) gives radios, radios on, clients per band, channel utilisation and Wi-Fi standards; `display ap all` gives model, state, uptime and the `P` flag (insufficient PoE, a warning finding); `display ap lldp neighbor brief` gives the switch and port of every access point, so the Topology Builder draws the access points under a captured switch even when that switch's capture does not list them. A truncated neighbour name (`name...`) is replaced by the full name of `display lldp neighbor`. Clients are a moment in time, not a peak, and are marked so.

**Merged captures** (`plan.merge_captures`). Two captures of one device (the same serial, or the same name when one of them prints no serial, as a configuration-only capture does) are no longer "one dropped": the richer one is kept, the missing or larger figures, components, licences and features of the other are added, both files are listed (`merged_from`, in the evidence and in the Excel *Devices* sheet) and the other is left out of the roll-up. Two devices with one name and different serials stay two and are flagged.

**Pairs from configuration** (`pairs.py`). A pair is read from what the two configurations say about each other, not from a hostname: vPC (`vpc domain`, `peer-keepalive`), VSX (`keepalive peer`), M-LAG (`dfs-group`), Huawei HRP and hot standby, PAN-OS HA (`peer-ip`, group id), FortiGate HA (`group-name`, `group-id`), ASA failover (link addresses, one primary and one secondary), BIG-IP device groups, Catalyst 9800 HA SSO. A capture of show commands is paired by domain, model and the neighbour tables. A device that fits more than one other is left for the architect; a pair with one member captured is flagged ("the other half was not captured: two units are needed"). The hostname grouping remains the fallback for captures that name nothing.

**The right throughput** (`fwprofile.py`). A firewall datasheet prints several throughput numbers; the replacement is sized on the level its rules put on the box: firewall, application control, threat prevention, or SSL decryption. The tool counts the rules that carry IPS / antivirus / anti-spyware profiles, match applications or URL categories, or decrypt, takes the highest level in use per group, and the plan says *Size on* that level, names the datasheet column and the peak figure to enter (four new peak figures). An imported column with another spelling is recognised for its level.

**Licence tiers and renewal windows** (`tiers.py`). Each hint names the feature in use, the licence the replacement needs, and a certainty: *stated* (the vendor's page says so; the link is on the row) or *confirm* (gated by platform or release: check it for the chosen model, Cisco Feature Navigator for Catalyst 9000 routing and overlay features). Licences that end within four months of each other form one **renewal window** with the latest date as the co-term date to ask for. Both are in the Licences tab and in two new Excel sheets.

**Smaller items.** Router loopback, tunnel, port-channel and SVI counts from `show ip interface brief` (they showed 0 before). **One-page summary for the customer** (HTML, prints on A4, counts and decisions, no device list). **Candidate library**: the models typed from a datasheet are kept in the browser, exported to `keystone-candidates.json` and imported into another project (no shipped catalogue; every entry is rebuilt from a whitelist). **Compare two candidates** side by side for one group: units, limiting quantity and how full each unit is at the target.

**Not validated, said plainly.** A real Cisco Catalyst 9800 capture was not available: that reader is tested on invented text. Opening the new pages once on your own machine is a check only you can do from your desktop; the tests render them in a headless browser.

Vendor documentation read for these features: Cisco [Catalyst 9000 licences](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst_9000/cat9000-config-available-licenses.html) and [Feature Navigator](https://cfnng.cisco.com/); [Aruba Central licensing](https://arubanetworking.hpe.com/techdocs/central/pdfs/2.5.7/licensing-guide.pdf); Palo Alto [subscriptions](https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/subscriptions/activate-subscription-licenses) and [HA](https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/high-availability/set-up-activepassive-ha/configure-activepassive-ha); Fortinet [security bundles](https://www.fortinet.com/support/support-services/fortiguard-security-subscriptions/fortigate-security-bundles), [FGCP](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/62403/fgcp) and [SSL & SSH inspection](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/929997/ssl-ssh-inspection); F5 [Good / Better / Best](https://www.f5.com/pdf/licensing/good-better-best-licensing-overview.pdf); Huawei [M-LAG DFS group](https://support.huawei.com/enterprise/en/doc/EDOC1100137937/96709576/configuring-a-dfs-group), [hot standby](https://support.huawei.com/enterprise/en/doc/EDOC1100096325/1a753937/vrrp-hsb-configuration) and [HRP](https://support.huawei.com/enterprise/en/doc/EDOC1000179232/2ff1fd4/faq-about-hot-standby-mechanisms); Cisco [ASA failover](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/general/asa-920-general-config/ha-failover.html), [Catalyst 9800 HA SSO](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/220277-configure-high-availability-sso-on-catal.html), [Secure Firewall 3100 datasheet](https://www.cisco.com/c/en/us/products/collateral/security/firewalls/secure-firewall-3100-series-ds.html).

## Routes

`GET /sizing-tool` (page), `GET /api/demo`, `GET /api/links`, `GET /api/capture-packs`, `GET /api/capture-pack.txt`, `GET /api/runs`, `POST /api/analyze` (multipart `files`, form `demo` = comma-separated set ids, `name`, `growth`), `POST /api/add` (multipart `run_id`, `files`, `options`), `POST /api/rollup` (JSON `run_id`, `options`: `growth`, `spare_pct`, `redundancy` none / n+1 / 2n, `ports_basis`, `expiry_months`, `profiles`, `manual_peaks`, `overrides`), `POST /api/import` (multipart `run_id`, `kind` = site_map / peaks / entitlements / lifecycle, `file`), `POST /api/import/clear`, `POST /api/compare` (multipart `run_id` and `other_run_id` or `project`), `POST /api/project/save`, `POST /api/project/open`, `POST /api/export` (xlsx), `POST /api/export-bom` (csv), `POST /api/summary` (one-page HTML), `POST /api/candidates/export`, `POST /api/candidates/import` (multipart `file`), `POST /api/candidates/compare` (JSON `run_id`, `options`, `group`, `candidates` = two); all under `/sizing-tool`. A run is kept in `exports/sizing/<32-hex id>/run.json` (the newest 20 and 30 days); a run id is checked against a 32-hex pattern before any file is opened.

## Vendor documentation

| Brand | Topic | Link |
|---|---|---|
| Cisco | Lifecycle | [Cisco End-of-Sale and End-of-Life Products](https://www.cisco.com/c/en/us/products/eos-eol-listing.html) |
| Cisco | Licensing | [Configuring Licenses on Cisco Catalyst 9000 Series Switches](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst_9000/cat9000-config-available-licenses.html) |
| Cisco | Licensing | [Enterprise Networks Software Subscription Matrix for Switching](https://www.cisco.com/c/m/en_us/products/software/dna-subscription-switching/en-sw-sub-matrix-switching.html) |
| Cisco | Sizing | [Cisco Catalyst 9300 Series Switches Data Sheet](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html) |
| Cisco | Sizing | [Cisco Catalyst 9200 Series Switches Ordering Guide](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/nb-06-cat9200-swit-ser-cte-en.html) |
| Cisco | Lifecycle | [Cisco 1000 Series ISR End-of-Life and End-of-Sale Notices](https://www.cisco.com/c/en/us/products/routers/1000-series-integrated-services-routers-isr/eos-eol-notice-listing.html) |
| Cisco | Sizing | [Cisco Catalyst 9800 Series Wireless Controllers FAQ](https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9800-series-wireless-controllers/nb-06-cat9800-ser-wirel-faq-ctp-en.html) |
| Cisco | Sizing | [Cisco Catalyst 9800-L Wireless Controller Data Sheet](https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9800-series-wireless-controllers/datasheet-c78-742434.html) |
| Cisco | Sizing | [Cisco Catalyst 9800-80 Wireless Controller Data Sheet](https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9800-series-wireless-controllers/nb-06-cat9800-80-wirel-mod-data-sheet-ctp-en.html) |
| Huawei | Lifecycle | [Huawei Product End of Life Policy](https://support.huawei.com/ecolumnsweb/en/warranty-policy) |
| Huawei | Licensing | [Huawei WLAN License Usage Guide: licence control items](https://support.huawei.com/enterprise/en/doc/EDOC1000082825/42125e24/licenses-control-items) |
| Huawei | Sizing | [Huawei AC6508 Access Controller](https://e.huawei.com/en/products/wlan/access-controllers/ac6508) |
| Aruba | Lifecycle | [HPE Aruba Networking Product End of Life notifications](https://networkingsupport.hpe.com/notifications;notificationSortBy=announcementDate;notificationCategory=Product%20End%20of%20Life) |
| Aruba | Lifecycle | [HPE Aruba Networking Product Lifecycle Policy](https://arubanetworking.hpe.com/techdocs/sdwan-PDFs/docs/eula/EC_LifecyclePolicy_latest.pdf) |
| Aruba | Licensing | [Aruba Central Licensing Guide](https://arubanetworking.hpe.com/techdocs/central/pdfs/2.5.7/licensing-guide.pdf) |
| Aruba | Sizing | [HPE Aruba Networking CX 6300 Switch Series QuickSpecs](https://www.hpe.com/us/en/collaterals/collateral.a00073540enw.html) |
| Aruba | Sizing | [HPE Aruba Networking CX 6200 Switch Series QuickSpecs](https://www.hpe.com/us/en/collaterals/collateral.a00059762enw.html) |
| Palo Alto | Lifecycle | [Palo Alto Networks Hardware End-of-Life Dates](https://www.paloaltonetworks.com/services/support/end-of-life-announcements/hardware-end-of-life-dates) |
| Palo Alto | Lifecycle | [Palo Alto Networks End-of-Life Summary](https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary) |
| Palo Alto | Licensing | [Activate Subscription Licenses (PAN-OS)](https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/subscriptions/activate-subscription-licenses) |
| Palo Alto | Licensing | [Licensing, Registration, and Activation](https://docs.paloaltonetworks.com/resources/licensing-registration-activation) |
| Fortinet | Lifecycle | [Product Life Cycle Information on Fortinet products](https://community.fortinet.com/customer-service-42/customer-service-tip-product-life-cycle-information-on-fortinet-products-96482) |
| Fortinet | Sizing | [Fortinet Product Matrix (FortiGate models and throughput)](https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/Fortinet_Product_Matrix.pdf) |
| F5 | Lifecycle | [K11478: End of Life / End of Sale index](https://my.f5.com/manage/s/article/K11478) |
| F5 | Lifecycle | [K5903: BIG-IP software support policy](https://my.f5.com/manage/s/article/K5903) |
| F5 | Lifecycle | [K000133583: End of Sale announcement for BIG-IP iSeries](https://my.f5.com/manage/s/article/K000133583) |
| F5 | Licensing | [K7752: Licensing the BIG-IP system](https://my.f5.com/manage/s/article/K7752) |
| F5 | Licensing | [K12111: Provisioning licensed BIG-IP modules](https://my.f5.com/manage/s/article/K12111) |
