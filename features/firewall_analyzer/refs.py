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
}

PALO = {
    "security_rule": "https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/policy/security-policy/create-a-security-policy-rule",
    "app_default": "https://origin-docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/app-id/application-default",
    "zone_protection": "https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/zone-protection-and-dos-protection/zone-defense/zone-protection-profiles",
    "ike_crypto": "https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-web-interface-help/network/network-network-profiles/network-network-profiles-ike-crypto",
    "ipsec_crypto": "https://origin-docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/vpns/set-up-site-to-site-vpn/define-cryptographic-profiles/define-ipsec-crypto-profiles",
    "mgmt_profile": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/configure-interfaces/use-interface-management-profiles-to-restrict-access",
    "logging": "https://docs.paloaltonetworks.com/best-practices/10-2/data-center-best-practices/data-center-best-practice-security-policy/log-and-monitor-data-center-traffic/what-data-center-traffic-to-log-and-monitor",
}

MIKROTIK = {
    "filter": "https://help.mikrotik.com/docs/spaces/ROS/pages/48660574/Filter",
    "firewall": "https://help.mikrotik.com/docs/spaces/ROS/pages/250708066/Firewall",
    "securing": "https://help.mikrotik.com/docs/spaces/ROS/pages/328353/Securing+your+router",       # opened 2026-10-10, title matched (site frozen, see module note)
    "nat": "https://help.mikrotik.com/docs/spaces/ROS/pages/3211299/NAT",                                  # opened 2026-10-10, title matched (site frozen, see module note)
    "ipsec": "https://help.mikrotik.com/docs/spaces/ROS/pages/11993097/IPsec",                              # opened 2026-10-10, title matched (site frozen, see module note)
}

FORTI_STATUS = {key: "opened" for key in FORTI}


def forti(key: str) -> str:
    return FORTI[key]
