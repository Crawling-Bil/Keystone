# Wireless Analyzer

Open the page and pick the controller. The choice is remembered; **Change controller** brings the picker back. `?vendor=Cisco` or `?vendor=Huawei` in the address skips it.

| Controller | Status |
|---|---|
| Huawei WLC (AC6508, AC6805, AirEngine 9700) | Analyze, Config Delta, AP Role Diff |
| Cisco Catalyst 9800 | Analyze, Config Delta, AP Role Diff |
| Cisco AireOS, Aruba Mobility Controller | Planned (shown in the picker) |

Every workspace is locked to the picked controller. A file from the other vendor is refused with a message that names the vendor it looks like.

## Huawei

Unchanged: `display current-configuration`, optionally the AP Info CSV/XLSX, and the VAP, AP group and profile tables.

## Cisco Catalyst 9800

**Input:** `show tech-support wireless` (best: config and runtime in one file). A capture with prompts works too, as long as it holds `show running-config`, `show ap summary`, `show ap tag summary`, `show wireless stats ap join summary`, `show ap config general`, `show wlan summary`, `show redundancy` and `show version`. A bare `show running-config` gives the configuration only; APs then show as Configured.

**Tabs**

| Tab | Content |
|---|---|
| Overview | Controller (model, serials, IOS XE, HA, management), AP state counts, radios up/down per band, licences, AP model and software |
| Findings | Critical, Warning and Info, with the affected APs, WLANs or tags |
| AP Inventory | Name, model, MAC, serial, IP, state, mode, Policy/Site/RF Tag, misconfigured, software, primary/secondary WLC, last disconnect |
| WLANs | ID, profile, SSID, status, security, 802.1X list, MAC filtering, broadcast, radio, PSK, config; plus where each WLAN is broadcast (Policy Tags, Policy Profiles, AP count) |
| Policy Profiles | VLAN, switching, DHCP, auth, AAA override, NAC, accounting, timeouts, ACL |
| Tags | Policy Tag mappings (WLAN to Policy Profile), Site Tags (AP Join + Flex profile, local or FlexConnect), RF Tags, with APs per tag |
| AP Join / Flex / RF | Profile settings and full config |
| AAA & Users | RADIUS/TACACS servers, groups, method lists, local users |
| Deployment Validation | With an AP Master: planned vs actual APs, including Site, Policy and RF Tag |

**Findings checked:** APs not registered, misconfigured tags, APs on the default Policy or Site Tag, Policy Tags pointing to a WLAN or Policy Profile that does not exist, WLANs in no Policy Tag, UP WLANs on a disabled Policy Profile, open WLANs without MAC filtering or web auth, hidden SSIDs, centrally switched Policy Profiles without a VLAN, mixed AP software, APs without a secondary controller when there is no SSO pair, radios down, type 0 local passwords, unused Policy Tags.

**Export:** Excel with one sheet per table.

## Config Delta

Same engine for both vendors, locked to the picked one. For Cisco a `show tech-support wireless` file can be used on either side: only its running-config section is compared.

## AP Role Diff

- Huawei: HSB pairs, Normal on one controller and Standby on the other.
- Cisco 9800: an AP is registered on one controller and absent from the other (N+1 or SSO). Registered on both is Dual Active; on neither is not operational. The Policy Tag stands in for the AP group, and Site and RF Tag differences are listed per AP. Input: `show tech-support wireless` or `show ap summary` (+ `show ap tag summary`) per controller, or CSV.
