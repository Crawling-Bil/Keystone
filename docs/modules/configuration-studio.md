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
| `features/configuration_studio/converter_engine/nac.py` | 802.1X / MAB settings per port and the Huawei NAC mapping. |
| `core/modules.py` | One Convert tool per domain (`convert_<domain>`). `status="planned"` marks pages without a converter. |
| `tests/test_convert_domains.py` | Guard rails: registry vs. module registry, classification fixtures, mismatch guard, page and API behaviour. |

## Hardware catalog and interface map

`hardware/` answers "which physical ports does this box have and what does the CLI call each one". Every model carries port groups (CLI keyword, naming template, range, speed class, medium, PoE), compatible uplink modules, a stack limit when the data sheet states one, and a link to the vendor data sheet.

- **Source model** is read from the config text (`PID:`, `Model Number`, `cisco <model> (...) processor`, the Aruba `; JL724B ... Configuration Editor` banner). Lines that state the chassis outright outweigh a neighbour table that merely mentions another model. The uplink module is read from `PID: C9300-NM-...`; when the capture has no inventory the model's default module is assumed and the map says so.
- **Target model** comes from the Target Model dropdown, and every list is built from the catalog: Huawei CloudEngine (six models, below), Cisco IOS-XE Catalyst (the uplink module is part of the choice, `C9300-48P+C9300-NM-8X`) and Aruba CX 6200F. Nexus is source/reference only because the Cisco translator does not emit NX-OS.
- **Mapping** is by role (access, uplink, management), speed class and position, never by the digits alone: `Te1/1/3` is the third port of the uplink module. A port on a faster class is `review`, copper landing on an SFP cage is `review` with the transceiver note, and a port the target does not have is `missing` and is written into the converted config as a review line. Multi-speed stanzas of a module slot that are not physical ports are reported as `stanza`.
- The map is stored on the config (`metadata["interface_map"]`, `metadata["port_map"]`) before translation. The Huawei translator reads it for uplink-module ports, the Cisco and Aruba translators for every port of a known source model. Without a known source model nothing changes: the old name-based rules apply.
- The Switch page shows the map in an Interface map tab of every result; the Switch and Router pages show the catalog. The router catalog lists onboard ports and every expansion slot's naming pattern; router conversion itself is still not available.

Huawei models (vendor `Huawei`, OS `VRP`, source and target): S5735-L8T4X-QA-V2, S5735-S24T4XE-V2, S5735-S24P4XE-V2, S5735-S48T4XE-V2, S5755-H24T4Y2CZ and S5755-H48UM4Y2CZ. Port names follow the project's drafted devices: `GE<m>/0/<n>`, `10GE`, `25GE`, `100GE` (and `40GE` for a QSFP28 cage run at 40G), `MEth0/0/0`; the Multi-GE ports of the UM model are `MultiGE<m>/0/<n>` (an access port converted to that model is written under that name, interface type confirmed in the V600R025C00 command reference). When a Huawei configuration is the source, the older spellings `GigabitEthernet0/0/n` and `XGigabitEthernet0/0/n` are recognised as well. Stack limit 9 comes from the S5735-S-V2 and S5755-H data sheets; the S5735-L-Q-V2 brochure supports iStack without a member limit, so none is enforced. The two 10G[STACK] cages of the S5735-S models are described in the model notes but not mapped, because the sources do not state their interface numbers; split 40G/100G ports are not modelled. The management port `MEth0/0/0` is the project's convention (V600R025C00 stack guide) and is not visible on the front-panel pictures.

Adding a model: add a `HardwareModel` to `switches.py` or `routers.py`, a data-sheet link that opens, and a test in `tests/test_hardware_catalog.py`. Leave a limit out (`max_members=None`) when the data sheet does not state it.

## Session captures

Engineers save the whole terminal session, not only the configuration. `converter_engine/session_capture.py` finds the output of `show running-config` (also `display current-configuration`, `show running-config all`, the IOS abbreviations) in a switch file and gives the parser only that block; the result carries `capture` (`command`, `total_lines`, `config_lines`) and the page shows it next to the line count. A typed-ahead command printed between the echo and the output is skipped. A file that is not a session, or whose block is under 15 lines, is passed on unchanged. A session with several `show` outputs and no configuration is refused with the command to collect. The whole capture stays available for the hardware catalog (`identity_text`), because the chassis and uplink-module PIDs are in `show inventory`, not in the configuration.

## Port authentication (802.1X / MAB)

`converter_engine/nac.py` reads the `authentication ...`, `mab` and `dot1x ...` lines of each Cisco interface into one settings object; ports with identical settings share one Huawei authentication profile (`authentication-profile`, `dot1x-access-profile`, `mac-access-profile`, an access domain bound to the RADIUS scheme). The mapping table is in the module docstring; every command is documented in the Huawei CloudEngine S3700/S5700/S6700 V600R025C00 Configuration Guide - User Access and Authentication ("NAC Configuration", https://support.huawei.com/enterprise/en/doc/EDOC1100333463) and its Command Reference. What has no documented equivalent (`timer reauthenticate server`, `server dead action authorize voice`, MAB-first order, violation, open authentication) is listed once per profile as a review item. Cisco to Cisco keeps the lines unchanged. Aruba CX targets receive one grouped review block per port set: AOS-CX port access (`aaa authentication port-access`) is not generated because no AOS-CX reference was available to check the syntax against.

Related Huawei mappings checked in the same documents: TACACS+ servers become primary, secondary, third and fourth in order; `ip dhcp excluded-address` becomes `excluded-ip-address` in the pool's global view; `no snmp trap link-status` becomes `undo enable snmp trap updown`.

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
- HPE Aruba Networking AOS-CX documentation portal: https://arubanetworking.hpe.com/techdocs/AOS-CX/
- Huawei VRP command references are published per product on https://support.huawei.com/enterprise/ (needs a Huawei support account for some documents, so no deep link is pinned here).
- MikroTik RouterOS export: https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management
- PAN-OS CLI cheat sheet (operational commands read by the runtime analyzer): https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-cheat-sheet-networking
- PAN-OS CLI and config structure: https://docs.paloaltonetworks.com/pan-os
