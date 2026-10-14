# Router Analyzer fixtures

| file | origin |
|------|--------|
| `synthetic_bad_ios_router.txt` | **Synthetic.** Hand-written classic-IOS running-config with deliberate defects (clear-text/type-7 credentials, telnet on vty, undefined ACL and route-map, RW SNMP community, ...). Used to pin which finding rule fires. Every address is in the RFC 5737 documentation ranges. |
| `asr1002x_iosxe_bgp_masked.txt` | Excerpts (`show ip interface brief`, `show ip bgp neighbors`, `show inventory`) of a real ASR1002-X capture, run through `tests/fixtures/real_captures/mask_capture.py`. |
| `c8200_sdwan_cedge_masked.txt` | Excerpts (`show sdwan system status / control connections / bfd session`, `show ip arp vrf 1`) of a real C8200 SD-WAN cEdge capture, masked. |
| `c3825_ios_gdoi_masked.txt` | Excerpts (`show crypto gdoi`, `show crypto gdoi gm`, `show crypto session detail`, `show inventory`) of a real 3825 capture, masked. |
| `c8200l_iosxe_show_tech_masked.txt` | A C8200L (IOS-XE 17.12) `show tech-support` cut to the sections the Health and NAT tabs read: `show version`, `show process cpu/memory sorted`, `show platform`, `show platform resources`, QFP utilization / drops / exmem (the last two are 4-dash banners nested inside the dump), `show ip nat statistics` with 23 pools and 57,747 translations, `show ip bgp summary`. No running-config, so it also pins the "NAT rules read from the live statistics" view. Healthy router: the only findings are information. |
| `isr4431_iosxe_power_license_masked.txt` | An ISR4431 (IOS-XE 17.3): power supply P1 `fail, badinput` with `V: PEM Out` at 0 mV and CPLD revision 50, a 9,999-byte log buffer without a syslog server, console logging at debugging, an unused 560 MB `.bin` on bootflash, a flapping `track` object. |
| `isr4331_iosxe_ospf_license_masked.txt` | An ISR4331 (IOS-XE 17.3): `router ospf` without any network statement, Smart Licensing under a policy that was never acknowledged (4 `%SMART_LIC-3-COMM_FAILED`), `%BW_LICENSE` max-level events at 100 Mbps, configuration changes by a local user, ESP packets with an unknown SPI from a source that is not a peer. |
| `c8300_iosxe_ospf_log_masked.txt` | A C8300 (IOS-XE 17.12): OSPF enabled by network statements (one of them matches no interface), an adjacency that dropped three times ("Interface down or detached", "Dead timer expired" twice), a log full of successful logins. |
| `c8200l_iosxe_ipsec_nat_masked.txt` | A C8200L (IOS-XE 17.9) running-config excerpt with IPsec and NAT: IKEv1 crypto maps with clear-text pre-shared keys, DH group 2 and 5, 3DES transform sets, PFS group 5, an IKEv2 policy that offers group-2 proposals, one key shared by two peers, three NAT pools (one unused), eleven static NAT entries (four publish FTP / SSH / SQL Server / RDP) and a swapped-digit port forward (5535 to 5355). |
| `cedge_sdwan_overlay_masked.txt` | **Rebuilt from two real cEdge captures (IOS-XE 17.x, controller mode)**: one router's `show sdwan bfd sessions`, `control local-properties`, `omp peers`, `omp tlocs` (three entries), `omp routes` (12 prefixes, 34 paths, five status combinations, four wrapped PATH IDs), `app-route stats` (two tunnels), the VRF 1 head of `show ip route`, and the empty `show etherchannel summary` / `show cdp neighbors`; the pushed policy (`show sdwan policy from-vsmart`, one SLA class, one policy, three sequences, three lists) comes from the second router. Addresses are RFC 5737, list and policy names are `LIST_A` ..., the host name is `EDGE-A`, organisation / DNS name / serial / token lines read `MASKED`, site ids are synthetic. The column layout and vocabulary are the device's own; the numbers were counted from the text and are pinned in `tests/test_router_sdwan_overlay.py`. |

The masked files were produced with `mask_capture.py --extract ... --name <customer words>` and then
hand-normalised in the places where the masker mistakes a hh:mm:ss duration for a MAC/IPv6 address
(uptime and "Last read" columns). Host names, addresses, serial numbers, organisation and site names
are pseudonyms; the column layout and the vocabulary are the real device output.

The five newest files (`c8200l_*`, `isr4431_*`, `isr4331_*`, `c8300_*`) were produced the same way, with these additional rules:

* Addresses are re-mapped per /24: every original /24 keeps its own `10.255.<k>.0/24` and the last octet, so subnet masks, wildcard masks and "is this address inside that network" stay meaningful (the masker alone numbers addresses 10.255.0.1, .2, ... in order of appearance, which makes a /30 and the /29 around it overlap).
* Wildcard masks (`0.0.0.7`) and log clock times (`13:45:07:`) are kept; the masker would take them for an address or a MAC.
* Pre-shared keys are replaced with distinct synthetic tokens (`FIXTURE-PSK-01`, ...). Equal original keys got equal tokens, so the "one key for two peers" finding is still exercised. No original key is present, and `tests/test_router_health_nat_vpn.py` asserts that no token ever reaches the analysis result.
* `description`, `remark` and object-group names that carry customer, partner or site names are dropped; users named in log lines are masked.
* Every file was checked with a second scan against the raw capture (host names, partner names, user names, addresses, serial numbers, secrets) before it was committed.

`mask_capture.py` did not recognise `crypto isakmp key KEY address ...` (the keyword is only "key") nor `pre-shared-key local|remote KEY`; it does now (`tests/test_router_health_nat_vpn.py::test_masker_hides_ipsec_pre_shared_keys`), and `verify()` re-checks keys after masking. Run it, and read the output once, before committing any new IPsec fixture.

Full captures never go into the repository. `tests/test_router_analyzer.py` also runs against the full
captures when the environment variable `KEYSTONE_ROUTER_CAPTURES` points at a folder that holds them.
