"""Cisco documentation links cited by the Router Analyzer findings.

The IOS-XE 16 configuration guides are used because their command syntax is shared
by IOS-XE 3.x/16.x/17.x and, for the features cited here, by IOS 12.4/15.x as well;
a finding never depends on a release-specific behaviour without saying so in its text.

The keys under "Device health, licensing, logging" and "NAT / IPsec / OSPF details"
were opened on 2026-10-10 and the page title was checked against the claim the
finding makes (for example the ISR4000 power-supply note really does list the CPLD
thresholds). The keys for hardening, routing and SD-WAN were added earlier.

Two keys are not cisco.com documents and are labelled as such in the finding text:
``crash_reason`` is a Cisco Community knowledge-base article (community.cisco.com)
and ``stig_login`` is the DISA STIG check for Cisco IOS-XE routers (V-215816) as
published by stigviewer.com.
"""

CISCO = "https://www.cisco.com/c/en/us/"
TD = "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/"

REFS = {
    # Hardening / management plane
    "harden_ios": CISCO + "support/docs/ip/access-lists/13608-21.html",
    "password_types": CISCO + "support/docs/security-vpn/remote-authentication-dial-user-service-radius/107614-64.html",
    "passwords_privileges": TD + "sec_usr_cfg/configuration/xe-16-9/sec-usr-cfg-xe-16-9-book/sec-cfg-sec-4cli.html",
    "aaa": TD + "sec_usr_aaa/configuration/xe-16/sec-usr-aaa-xe-16-book.html",
    "ssh": TD + "sec_usr_ssh/configuration/xe-16/sec-usr-ssh-xe-16-book.html",
    "snmp": TD + "snmp/configuration/xe-16/snmp-xe-16-book.html",
    "ntp": "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/m_bsm-time-calendar-set.html",
    "copp": "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/qos/b-quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html",
    "acl": TD + "sec_data_acl/configuration/xe-16/sec-data-acl-xe-16-book.html",
    # Routing
    "bgp": TD + "iproute_bgp/configuration/xe-16/irg-xe-16-book.html",
    "bgp_neighbor_options": "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-routing/b-ip-routing/m_irg-neighbor-0.html",
    "bgp_max_prefix": CISCO + "support/docs/ip/border-gateway-protocol-bgp/25160-bgp-maximum-prefix.html",
    "bgp_rib_failure": CISCO + "support/docs/ip/border-gateway-protocol-bgp/213286-understand-bgp-rib-failure-and-the-bgp-s.html",
    "bgp_protect": "https://sec.cloudapps.cisco.com/security/center/resources/protecting_border_gateway_protocol",
    "ospf": TD + "iproute_ospf/configuration/xe-16/iro-xe-16-book.html",
    "fhrp": TD + "ipapp_fhrp/configuration/xe-16/fhp-xe-16-book.html",
    # VPN / crypto
    "ngc": "https://sec.cloudapps.cisco.com/security/center/resources/next_generation_cryptography",
    "ipsec": TD + "sec_conn_vpnips/configuration/xe-16/sec-sec-for-vpns-w-ipsec-xe-16-book.html",
    "getvpn": TD + "sec_conn_getvpn/configuration/xe-16/sec-get-vpn-xe-16-book.html",
    "zbf": TD + "sec_data_zbf/configuration/xe-16/sec-data-zbf-xe-16-book.html",
    # Services
    "qos": TD + "qos_mqc/configuration/xe-16/qos-mqc-xe-16-book.html",
    "ipsla": TD + "ipsla/configuration/xe-16/sla-xe-16-book.html",
    "nat": TD + "ipaddr_nat/configuration/xe-16/nat-xe-16-book.html",
    "netflow": TD + "fnetflow/configuration/xe-16/fnf-xe-16-book.html",
    "interface_troubleshooting": CISCO + "support/docs/switches/catalyst-6500-series-switches/12027-53.html",
    # Device health, licensing, logging (opened or returned by a cisco.com search on 2026-10-10)
    "tac_high_cpu": CISCO + "support/docs/technical-details/222469-reporting-problems-effectively-to-tac-se.html",
    "asr1000_high_cpu": CISCO + "support/docs/routers/asr-1000-series-aggregation-services-routers/212646-troubleshoot-high-cpu-on-asr1000-series.html",
    "iosxe_memory": CISCO + "support/docs/ios-nx-os-software/ios-xe-17/225227-troubleshoot-memory-issues-in-ios-xe.html",
    "power_supply_voltage": CISCO + "support/docs/ip/syslog/221177-power-supply-voltage-warning.html",
    "isr4000_temperature": CISCO + "support/docs/routers/4000-series-integrated-services-routers/221135-critical-temperature-condition-is-observ.html",
    "install_remove_inactive": CISCO + "td/docs/routers/C8000V/Configuration/c8000v-installation-configuration-guide/m_installing-the-software-using-install-commands.html",
    "crash_reason": "https://community.cisco.com/t5/networking-knowledge-base/router-crashes-cheatsheet/ta-p/3121501",
    "smart_lic_troubleshoot": CISCO + "td/docs/routers/sl_using_policy/b-sl-using-policy/troubleshooting.html",
    "isr4000_license": CISCO + "support/docs/routers/4000-series-integrated-services-routers/217135-performance-license-on-cisco-isr4000.html",
    "cat8000_throughput": CISCO + "td/docs/routers/cloud_edge/configure-licenses-throughput-catalyst-8000-platforms.html",
    "debug_console": CISCO + "support/docs/dial-access/integrated-services-digital-networks-isdn-channel-associated-signaling-cas/10374-debug.html",
    "stig_login": "https://stigviewer.com/stig/cisco_ios_xe_router_ndm/2020-09-23/finding/V-215816",
    # NAT / IPsec / OSPF details
    "nat_cat8000": CISCO + "support/docs/ip/network-address-translation-nat/226027-troubleshoot-nat-on-cat8000-platforms.html",
    "invalid_spi": CISCO + "support/docs/security-vpn/ipsec-negotiation-ike-protocols/115801-technote-iosvpn-00.html",
    "ospf_redistribute": CISCO + "support/docs/ip/open-shortest-path-first-ospf/113339-ospf-connected-net.html",
    "ikev2": "https://www.cisco.com/en/US/docs/ios-xml/ios/sec_conn_ike2vpn/configuration/15-2s/sec-cfg-ikev2-flex.html",
    # SD-WAN
    "sdwan_tunnel": "https://www.cisco.com/c/en/us/td/docs/routers/sdwan/command/iosxe/qualified-cli-command-reference-guide/m-sdwan-tunnel-interface-cmds.html",
    "sdwan_bfd": "https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/routing/ios-xe-17/routing-configuration-guide-17-x/cisco-catalyst-sd-wan-bfd1.html",
    "sdwan_bfd_troubleshoot": "https://www.cisco.com/c/en/us/td/docs/routers/sdwan/26x-later/routing/routing-configuration-guide/bfd/troubleshoot-common-bfd-errors.html",
    "sdwan_design": "https://www.cisco.com/c/en/us/td/docs/solutions/CVD/SDWAN/cisco-sdwan-design-guide.html",
    # SD-WAN control plane, management mode, restart history (opened 2026-10-10)
    "sdwan_control_troubleshoot": CISCO + "support/docs/routers/sd-wan/214509-troubleshoot-control-connections.html",
    "sdwan_vmanaged": "https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/Monitor-And-Maintain/monitor-maintain-book/m-device-and-controllers.html",
    "sdwan_cli_mode": CISCO + "support/docs/routers/sd-wan/224923-convert-vedge-from-vmanage-mode-to-cli.html",
    # SD-WAN overlay: OMP, TLOCs, app-route statistics, centralized policy (opened 2026-10-12; the findings paraphrase what each page says)
    "sdwan_omp_bestpath": CISCO + "support/docs/routers/sd-wan/217479-omp-best-path-selection-peculiarities-an.html",
    "sdwan_bfd_approute": CISCO + "support/docs/routers/sd-wan/221604-understand-bfd-protocol-relationship-wit.html",
    "sdwan_aar_policy": "https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/ios-xe-17/policies-book-xe/application-aware-routing.html",
    "sdwan_aar_deploy": "https://www.cisco.com/c/en/us/td/docs/solutions/CVD/SDWAN/cisco-sdwan-application-aware-routing-deploy-guide.html",
    "sdwan_nat_types": CISCO + "support/docs/routers/sd-wan/214517-vedge-can-t-establish-ipsec-tunnel-if-on.html",
    "sdwan_command_reference": "https://www.cisco.com/c/en/us/td/docs/routers/sdwan/command/sdwan-cr-book/operational-cmd.html",
    "syslog_xe_17_9": TD + "17_xe/syslogs/17-9-x/b-system-message-guide-17-9-x.html",
    "router_crashes_xe": CISCO + "support/docs/routers/asr-1000-series-aggregation-services-routers/109723-asr-crash.html",
}


def ref(key: str) -> str:
    return REFS[key]
