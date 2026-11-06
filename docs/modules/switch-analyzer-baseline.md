# Switch Analyzer: baseline compliance

Choose a **Baseline** next to the Vendor box on the Switch Analyzer page (for example *TAM Standard*) and analyze a capture. The deviations from that standard appear in the Findings tab under the category *Baseline compliance*. With *None* selected nothing changes.

## Where the standard comes from

The standard is not typed in a second time. It is read from the converter profile of the same name (`features/configuration_studio/converter_engine/profiles/`): the NTP servers, the syslog host, the "local users only" AAA decision, the removal of DNS, the spanning-tree mode and the SNMP version that Configuration Studio writes into every converted switch. A switch that is already in service has to match the same facts. When a profile is added to `PROFILE_REGISTRY` it shows up in the Baseline list without further code, and a setting the profile leaves empty is not checked.

## What is checked

| Rule | Check | Severity |
|---|---|---|
| SW-BASE-001 | The NTP servers equal the standard's servers (missing and extra servers are named) | medium |
| SW-BASE-002 | Every standard syslog host is configured | medium (missing), low (extra host) |
| SW-BASE-003 | No TACACS+ or RADIUS when the standard is local users only | medium |
| SW-BASE-004 | No name server or domain lines when the standard removes DNS (`no ip domain lookup` is fine) | low |
| SW-BASE-005 | Huawei only: `stp mode` equals the standard's mode, spanning tree enabled | medium |
| SW-BASE-006 | Huawei only: `snmp-agent sys-info version` equals the standard; v1 or `all` is medium | low / medium |
| SW-BASE-099 | The capture holds no running configuration, so nothing was compared (info) | info |
| SW-BASE-100 | Every applicable check passed (info); it also names the checks that were not compared on this vendor | info |

Rules that the capture cannot answer are listed as not applicable, never as a pass. Passwords, TACACS+/RADIUS keys and SNMP community strings are never read into a finding.

## Reading the result

`result["baseline"]` holds `name`, `checks` (id, check, status `pass` / `fail` / `n/a`, expected, found), `passed`, `failed` and the findings. The API accepts the same choice as the form field `baseline` of `POST /switch-analyzer/api/analyze`; an unknown value is refused with HTTP 400.

## References

- Huawei CloudEngine S3700, S5700 and S6700 Configuration Guide (campus switch security baseline, NTP, info-center, AAA, STP, SNMP): <https://support.huawei.com/enterprise/en/doc/EDOC1100333463>
- Cisco IOS XE 17, Setting time and calendar services (NTP): <https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/m_bsm-time-calendar-set.html>
- Cisco, System Message Logging (`logging host`): <https://www.cisco.com/en/US/docs/routers/access/wireless/software/guide/SysMsgLogging.html>
- Cisco IOS Release 15SY, Configuring DNS (`ip name-server`, `ip domain lookup`): <https://www3-realm.cisco.com/en/US/docs/ios-xml/ios/ipaddr_dns/configuration/15-sy/dns-config-dns.html>
- Cisco Catalyst 9300 Layer 2 guide, Configuring Spanning Tree Protocol: <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/lyr2/b_1712_lyr2_9300_cg/configuring_spanning_tree_protocol.html>
