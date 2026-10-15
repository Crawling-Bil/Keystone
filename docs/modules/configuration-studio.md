# Convert (Configuration Studio)

Convert has five pages, one per kind of device, the same five as Analyze:

| Page | URL | Converter today |
| --- | --- | --- |
| Wireless | `/convert/wireless` | none yet |
| Switch | `/convert/switch` | Cisco / Aruba / Huawei switches (Huawei VRP target, standard config profiles) |
| Router | `/convert/router` | none yet |
| Firewall | `/convert/firewall` | MikroTik RouterOS to Palo Alto (interface/zone mapping, IPsec, SD-WAN, Panorama) |
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
| `core/modules.py` | One Convert tool per domain (`convert_<domain>`). `status="planned"` marks pages without a converter. |
| `tests/test_convert_domains.py` | Guard rails: registry vs. module registry, classification fixtures, mismatch guard, page and API behaviour. |

## Adding a converter

1. Write the parser under `parsers/<domain>/` and the translator under `translators/<domain>/`.
2. Register both in `engine.py` with the domain key first, for example `("router", "cisco")`. The page switches from "not available" to a working form with no other edit.
3. In `core/modules.py`, remove `status="planned"` from that Convert tool and set its version. `test_static_planned_flag_matches_registered_converters` fails until the two agree.
4. Add the platform's markers to `DeviceDetector` or `classify()` and a masked fixture under `tests/fixtures/` that proves the detection.
5. Add parser tests from a real backup, including the lines the parser cannot translate: they must surface as review markers, never be dropped silently.

## Known limits

- Router classification identifies Cisco IOS/IOS-XE and Huawei routers only when there is strong evidence; thin captures stay "unknown".
- Wireless, Router and Load Balancer have no converter. Each page lists what is needed (a source backup, a mapping decision, and a known-good target for comparison).
- FortiGate and Palo Alto are analysed, not converted. Palo Alto is a conversion target only.

## References

- Cisco IOS XE configuration guides: https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-17/products-installation-and-configuration-guides-list.html
- Huawei VRP command references are published per product on https://support.huawei.com/enterprise/ (needs a Huawei support account for some documents, so no deep link is pinned here).
- MikroTik RouterOS export: https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management
- PAN-OS CLI and config structure: https://docs.paloaltonetworks.com/pan-os
