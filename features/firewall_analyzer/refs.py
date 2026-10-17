"""Vendor documentation cited by the Firewall Analyzer findings.

How each link was checked (2026-10-09, completed 2026-10-10):

* ``opened``  - the page was fetched and its title matched what the finding cites.
* ``listed``  - the URL comes from the vendor's own table of contents or search
  result for the same guide, but the page itself could not be opened.  No link is
  in this group any more: the eight FortiOS links that were listed on 2026-10-09
  and the three MikroTik links were all opened on 2026-10-10.

On those eight FortiOS pages the fetch returned the page title and the guide's
table of contents but not the article body, so what was confirmed is that the URL
resolves to the section named in the title (OSPF, Administrator profiles, SD-WAN,
Destination NAT, Policies, Local-in policy, DoS policy, Setting the system time),
not the wording of the article.  Fortinet's pages also name release 8.0.1 as the
canonical version while the URL pins an older one; the older release is kept on
purpose because each link pins the release the finding was written against (6.4 to 7.6).

The MikroTik help site shows a banner that it is frozen and that the current
RouterOS manual is at manual.mikrotik.com; the three pages below still load.

``FORTI_STATUS`` records this per key so nobody mistakes a listed link for a
verified one if one is added later.
"""

from __future__ import annotations

FORTI_DOCS = "https://docs.fortinet.com/document/fortigate/"

FORTI = {
    # Hardening and best practice
    "harden_admin": FORTI_DOCS + "6.4.0/hardening-your-fortigate/582009",              # System administrator best practices
    "harden_overview": FORTI_DOCS + "6.4.0/hardening-your-fortigate/612504",           # Hardening your FortiGate
    "harden_70": FORTI_DOCS + "7.0.0/best-practices/555436",                           # Hardening (encrypted protocols, ciphers, password storage)
    "best_policies": "https://docs2.fortinet.com/document/fortigate/7.4.0/best-practices/862226",   # Policies: DoS, local-in, security and VIP policies
    # Administration guide 7.2.5
    "policy_objects": FORTI_DOCS + "7.2.5/administration-guide/728881/policy-and-objects",
    "vpn": FORTI_DOCS + "7.2.5/administration-guide/729214/vpn",
    "ssl_vpn": FORTI_DOCS + "7.2.5/administration-guide/371626/ssl-vpn",
    "bgp": FORTI_DOCS + "7.2.5/administration-guide/750736/bgp",
    "password_policy": FORTI_DOCS + "7.2.5/administration-guide/313307/setting-the-password-policy",
    "ha": FORTI_DOCS + "7.2.4/administration-guide/62403",                              # FGCP
    "sdwan_health": FORTI_DOCS + "7.0.2/administration-guide/580649",                  # Link health monitor
    "log_settings": FORTI_DOCS + "7.2.1/administration-guide/250999",                  # Log settings and targets
    "snmp": FORTI_DOCS + "7.4.8/administration-guide/325005/basic-configuration",
    # opened 2026-10-10: title and table of contents matched, article body not returned by the fetch
    "ospf": FORTI_DOCS + "7.2.5/administration-guide/561713/ospf",
    "admin_profiles": FORTI_DOCS + "7.2.5/administration-guide/294491/administrator-profiles",
    "sdwan": FORTI_DOCS + "7.2.5/administration-guide/19246/sd-wan",
    "dnat": FORTI_DOCS + "7.2.5/administration-guide/728694/destination-nat",
    "policies": FORTI_DOCS + "7.2.4/administration-guide/118003/policies",
    "local_in": FORTI_DOCS + "7.2.2/administration-guide/363127/local-in-policy",
    "dos_policy": FORTI_DOCS + "7.6.6/administration-guide/771644/dos-policy",
    "system_time": FORTI_DOCS + "7.4.3/administration-guide/512210/setting-the-system-time",
    # opened 2026-10-14, page title matched (profile content rules, forti_profiles.py)
    "ssl_cert": FORTI_DOCS + "7.4.7/administration-guide/505842",                      # Certificate inspection
    "ssl_deep": FORTI_DOCS + "7.4.7/administration-guide/122078",                      # Deep inspection
    "ips": FORTI_DOCS + "7.4.7/administration-guide/583477",                           # Configuring an IPS sensor
    "antivirus": FORTI_DOCS + "7.4.1/administration-guide/922423",                     # Configuring an antivirus profile
    "webfilter": FORTI_DOCS + "7.4.1/administration-guide/675558",                     # FortiGuard filter
}

PALO = {
    "security_rule": "https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/policy/security-policy/create-a-security-policy-rule",
    "app_default": "https://origin-docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/app-id/application-default",
    "zone_protection": "https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/zone-protection-and-dos-protection/zone-defense/zone-protection-profiles",
    "ike_crypto": "https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-web-interface-help/network/network-network-profiles/network-network-profiles-ike-crypto",
    "ipsec_crypto": "https://origin-docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/vpns/set-up-site-to-site-vpn/define-cryptographic-profiles/define-ipsec-crypto-profiles",
    "mgmt_profile": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/configure-interfaces/use-interface-management-profiles-to-restrict-access",
    "logging": "https://docs.paloaltonetworks.com/best-practices/10-2/data-center-best-practices/data-center-best-practice-security-policy/log-and-monitor-data-center-traffic/what-data-center-traffic-to-log-and-monitor",
    # added with panos_xml_extra (all returned by a docs.paloaltonetworks.com search on 2026-10-14)
    "admin_access": "https://docs.paloaltonetworks.com/best-practices/10-1/administrative-access-best-practices/administrative-access-best-practices/deploy-administrative-access-best-practices",
    "ssl_tls_profile": "https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/certificate-management/configure-an-ssltls-service-profile",
    "replace_mgmt_cert": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/certificate-management/replace-the-certificate-for-inbound-management-traffic",
    "ha_config": "https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/high-availability/set-up-activepassive-ha/configure-activepassive-ha",
    "ha_failover": "https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/high-availability/set-up-activepassive-ha/define-ha-failover-conditions",
    "snmp": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/snmp-monitoring-and-traps/snmp-support",
    "tacacs": "https://docs.paloaltonetworks.com/ngfw/administration/authentication/configure-tacacs-authentication",
    "auth_profile": "https://docs.paloaltonetworks.com/ngfw/administration/authentication/configure-an-authentication-profile-and-sequence",
    "admin_accounts": "https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/manage-firewall-administrators",
    "path_monitor": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/static-routes/configure-path-monitoring-for-a-static-route",
    "advanced_routing": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/advanced-routing/logical-router-overview",
    "content_updates": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-upgrade/software-and-content-updates/install-content-and-software-updates",
    "device_cert": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/certificate-management/obtain-certificates/device-certificate.html",
    "profile_group": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-profiles/create-a-security-profile-group",
    "best_practice_profiles": "https://docs.paloaltonetworks.com/best-practices/internet-gateway-best-practices/best-practice-internet-gateway-security-policy/create-best-practice-security-profiles.html",
    "rule_usage": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/view-policy-rule-usage",          # returned by a docs.paloaltonetworks.com search on 2026-10-14
    "virtual_systems": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/virtual-systems/configure-virtual-systems",
    # added with panos_capture (runtime-only captures); every URL below was fetched on 2026-10-17 and its content matched
    "license_expiry": "https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/subscriptions/what-happens-when-licenses-expire",
    "activate_licenses": "https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-admin/subscriptions/activate-subscription-licenses.html",
    "eol_software": "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary",
    "eol_hardware": "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/hardware-end-of-life-dates",
    "service_routes": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/service-routes/configure-service-routes",
    "root_disk": "https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClaJCAS",
    "cli_device_mgmt": "https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-cheat-sheet-device-management",
    "cli_networking": "https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-cheat-sheet-networking",
}

# FortiSwitchOS (used by forti_switch.py).  "fetched" = the page was opened on 2026-10-17 and the content matched what the finding
# cites; "listed" = returned by a docs.fortinet.com / community.fortinet.com search for that topic with a matching title.
FORTISWITCH = {
    "mclag": "https://docs.fortinet.com/document/fortiswitch/7.2.10/administration-guide/860027/mclag",                                       # fetched: ICL trunk, split-brain detection (off by default), peer timeout 30-600 s
    "mclag_design": "https://community.fortinet.com/fortiswitch-36/technical-tip-designing-implementing-and-troubleshooting-mclag-on-fortiswitches-managed-by-fortigate-221419",   # fetched: two ICL links, STP on ICL, diagnose commands
    "log_reference": "https://docs.fortinet.com/document/fortiswitch/7.6.0/fortiswitchos-log-reference/265059/switch-controller-log-messages",  # fetched: 9006 / 9008 / 9015
    "capwap_restart": "https://community.fortinet.com/fortiswitch-36/troubleshooting-tip-how-to-restart-capwap-switch-controller-daemon-on-fortigate-and-fortiswitch-212798",   # listed
    "offline": "https://community.fortinet.com/fortigate-3/troubleshooting-tip-fix-fortiswitch-showing-with-the-offline-status-98876",       # listed
    "stp": "https://docs.fortinet.com/document/fortiswitch/7.0.8/devices-managed-by-fortios/173292/configuring-stp-settings",               # listed
    "logging": "https://docs.fortinet.com/document/fortiswitch/7.0.2/devices-managed-by-fortios/173269/fortiswitch-log-settings",          # listed
    "admin": "https://docs.fortinet.com/document/fortiswitch/7.6.4/fortiswitchos-administration-guide/288914/administrators",              # listed
    "upgrade": "https://docs.fortinet.com/document/fortiswitch/7.4.3/fortiswitchos-release-notes/311791/upgrade-information",              # listed
}

MIKROTIK = {
    "filter": "https://help.mikrotik.com/docs/spaces/ROS/pages/48660574/Filter",
    "firewall": "https://help.mikrotik.com/docs/spaces/ROS/pages/250708066/Firewall",
    "securing": "https://help.mikrotik.com/docs/spaces/ROS/pages/328353/Securing+your+router",       # opened 2026-10-10, title matched (site frozen, see module note)
    "nat": "https://help.mikrotik.com/docs/spaces/ROS/pages/3211299/NAT",                                  # opened 2026-10-10, title matched (site frozen, see module note)
    "ipsec": "https://help.mikrotik.com/docs/spaces/ROS/pages/11993097/IPsec",                              # opened 2026-10-10, title matched (site frozen, see module note)
    # returned by a help.mikrotik.com search on 2026-10-17 (titles matched; "sensitive" and "services" pages were also fetched)
    "sensitive": "https://help.mikrotik.com/docs/spaces/ROS/pages/380076066/List+of+menus+with+sensitive+parameters",
    "services": "https://help.mikrotik.com/docs/spaces/ROS/pages/103841820/Services",
    "snmp": "https://help.mikrotik.com/docs/spaces/ROS/pages/8978519/SNMP",
    "ppp_aaa": "https://help.mikrotik.com/docs/spaces/ROS/pages/132350049/PPP+AAA",
    "l2tp": "https://help.mikrotik.com/docs/spaces/ROS/pages/2031631/L2TP",
    "queues": "https://help.mikrotik.com/docs/spaces/ROS/pages/328088/Queues",
    "queue_types": "https://help.mikrotik.com/docs/spaces/ROS/pages/196345871/Queue+types",
    "policy_routing": "https://help.mikrotik.com/docs/spaces/ROS/pages/59965508/Policy+Routing",
    "mangle": "https://help.mikrotik.com/docs/spaces/ROS/pages/48660587/Mangle",
    "upgrading": "https://help.mikrotik.com/docs/spaces/ROS/pages/328142/Upgrading+and+installation",
    "log": "https://help.mikrotik.com/docs/pages/viewpage.action?pageId=171147267",
}

FORTI_STATUS = {key: "opened" for key in FORTI}


def forti(key: str) -> str:
    return FORTI[key]
