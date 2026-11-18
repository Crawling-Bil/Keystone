"""Vendor documentation to open while sizing a replacement, and the figures a capture cannot hold.

Every link below was taken from the vendor's own site (search results of cisco.com, huawei.com, arubanetworking.hpe.com, paloaltonetworks.com,
fortinet.com and my.f5.com).  Nothing here is a lifecycle *date*: end-of-sale and end-of-support dates change, so the tool points at the vendor's
page for the exact model instead of keeping a table that goes stale.
"""

from __future__ import annotations

from typing import Any

# (vendor, device types the link applies to, topic, title, url); "" in the types means every type of that vendor
LINKS: tuple[tuple[str, tuple[str, ...], str, str, str], ...] = (
    ("Cisco", (), "Lifecycle", "Cisco End-of-Sale and End-of-Life Products", "https://www.cisco.com/c/en/us/products/eos-eol-listing.html"),
    ("Cisco", ("switch",), "Licensing", "Configuring Licenses on Cisco Catalyst 9000 Series Switches", "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst_9000/cat9000-config-available-licenses.html"),
    ("Cisco", ("switch",), "Licensing", "Enterprise Networks Software Subscription Matrix for Switching", "https://www.cisco.com/c/m/en_us/products/software/dna-subscription-switching/en-sw-sub-matrix-switching.html"),
    ("Cisco", ("switch",), "Sizing", "Cisco Catalyst 9300 Series Switches Data Sheet", "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html"),
    ("Cisco", ("switch",), "Sizing", "Cisco Catalyst 9200 Series Switches Ordering Guide", "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/nb-06-cat9200-swit-ser-cte-en.html"),
    ("Cisco", ("router",), "Lifecycle", "Cisco 1000 Series ISR End-of-Life and End-of-Sale Notices", "https://www.cisco.com/c/en/us/products/routers/1000-series-integrated-services-routers-isr/eos-eol-notice-listing.html"),
    ("Cisco", ("wlc", "access_point"), "Sizing", "Cisco Catalyst 9800 Series Wireless Controllers FAQ", "https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9800-series-wireless-controllers/nb-06-cat9800-ser-wirel-faq-ctp-en.html"),
    ("Cisco", ("wlc", "access_point"), "Sizing", "Cisco Catalyst 9800-L Wireless Controller Data Sheet", "https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9800-series-wireless-controllers/datasheet-c78-742434.html"),
    ("Cisco", ("wlc", "access_point"), "Sizing", "Cisco Catalyst 9800-80 Wireless Controller Data Sheet", "https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9800-series-wireless-controllers/nb-06-cat9800-80-wirel-mod-data-sheet-ctp-en.html"),
    ("Huawei", (), "Lifecycle", "Huawei Product End of Life Policy", "https://support.huawei.com/ecolumnsweb/en/warranty-policy"),
    ("Huawei", ("wlc", "access_point"), "Licensing", "Huawei WLAN License Usage Guide: licence control items", "https://support.huawei.com/enterprise/en/doc/EDOC1000082825/42125e24/licenses-control-items"),
    ("Huawei", ("wlc", "access_point"), "Sizing", "Huawei AC6508 Access Controller", "https://e.huawei.com/en/products/wlan/access-controllers/ac6508"),
    ("Aruba", (), "Lifecycle", "HPE Aruba Networking Product End of Life notifications", "https://networkingsupport.hpe.com/notifications;notificationSortBy=announcementDate;notificationCategory=Product%20End%20of%20Life"),
    ("Aruba", (), "Lifecycle", "HPE Aruba Networking Product Lifecycle Policy", "https://arubanetworking.hpe.com/techdocs/sdwan-PDFs/docs/eula/EC_LifecyclePolicy_latest.pdf"),
    ("Aruba", ("switch", "wlc", "access_point"), "Licensing", "Aruba Central Licensing Guide", "https://arubanetworking.hpe.com/techdocs/central/pdfs/2.5.7/licensing-guide.pdf"),
    ("Aruba", ("switch",), "Sizing", "HPE Aruba Networking CX 6300 Switch Series QuickSpecs", "https://www.hpe.com/us/en/collaterals/collateral.a00073540enw.html"),
    ("Aruba", ("switch",), "Sizing", "HPE Aruba Networking CX 6200 Switch Series QuickSpecs", "https://www.hpe.com/us/en/collaterals/collateral.a00059762enw.html"),
    ("Palo Alto", (), "Lifecycle", "Palo Alto Networks Hardware End-of-Life Dates", "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/hardware-end-of-life-dates"),
    ("Palo Alto", (), "Lifecycle", "Palo Alto Networks End-of-Life Summary", "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary"),
    ("Palo Alto", (), "Licensing", "Activate Subscription Licenses (PAN-OS)", "https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/subscriptions/activate-subscription-licenses"),
    ("Palo Alto", (), "Licensing", "Licensing, Registration, and Activation", "https://docs.paloaltonetworks.com/resources/licensing-registration-activation"),
    ("Fortinet", (), "Lifecycle", "Product Life Cycle Information on Fortinet products", "https://community.fortinet.com/customer-service-42/customer-service-tip-product-life-cycle-information-on-fortinet-products-96482"),
    ("Fortinet", ("firewall",), "Sizing", "Fortinet Product Matrix (FortiGate models and throughput)", "https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/Fortinet_Product_Matrix.pdf"),
    ("F5", (), "Lifecycle", "K11478: End of Life / End of Sale index", "https://my.f5.com/manage/s/article/K11478"),
    ("F5", (), "Lifecycle", "K5903: BIG-IP software support policy", "https://my.f5.com/manage/s/article/K5903"),
    ("F5", (), "Lifecycle", "K000133583: End of Sale announcement for BIG-IP iSeries", "https://my.f5.com/manage/s/article/K000133583"),
    ("F5", (), "Licensing", "K7752: Licensing the BIG-IP system", "https://my.f5.com/manage/s/article/K7752"),
    ("F5", (), "Licensing", "K12111: Provisioning licensed BIG-IP modules", "https://my.f5.com/manage/s/article/K12111"),
)

# figures a configuration or a command capture does not carry, but a sizing decision needs
INPUTS: dict[str, tuple[str, ...]] = {
    "switch": (
        "Ports in use per speed and per closet, from monitoring over a full business cycle (the capture shows only the moment it was taken).",
        "PoE budget actually drawn (show power inline) against the budget of each switch; plan the new PoE class (802.3af / at / bt) for access points and cameras.",
        "Uplink bandwidth and oversubscription ratio per layer (access to distribution to core); optics type and fibre distance for every uplink.",
        "Stack / vPC / VSX design wanted after the refresh, and whether the licence model changes (perpetual to subscription).",
    ),
    "router": (
        "WAN circuit speeds and the provider handoff (Ethernet, MPLS, internet) for every router; encrypted throughput needed over the tunnels.",
        "Peak routed throughput and packets per second, from interface counters over time, not from the configuration.",
        "Feature licences the new platform must carry (SD-WAN, security, throughput tier) and the routing scale: routes, BGP peers, VRFs.",
    ),
    "firewall": (
        "Peak throughput with the security profiles switched on (firewall, IPS, application control, SSL inspection), from the vendor's datasheet columns, not the headline number.",
        "Concurrent sessions and new sessions per second at peak; VPN peers and SSL-VPN / GlobalProtect users at peak.",
        "Subscriptions in use (threat, URL / web filter, sandbox, SD-WAN, support level) and their end dates, from the vendor portal.",
        "HA design wanted after the refresh (active-passive or active-active) and the number of virtual systems / VDOMs.",
    ),
    "load_balancer": (
        "Peak throughput, concurrent connections, new connections per second and SSL transactions per second (separately for RSA and ECDSA keys), from the unit's own performance statistics.",
        "Licensed modules and their provision level (LTM, GTM / DNS, ASM / Advanced WAF, APM) and the add-on licences (throughput, compression, SSL).",
        "Virtualisation wanted after the refresh (vCMP, VE, rSeries / VELOS tenants) and the TMOS version the applications' iRules are written for.",
    ),
    "wlc": (
        "Licensed AP count and client count against the joined APs today; controller redundancy design (N+1, SSO pair) wanted after the refresh.",
        "Wi-Fi standard and radio design of the new access points; site survey or predictive design per floor.",
        "Management model after the refresh (on-premises controller, cloud-managed, embedded in the switch).",
    ),
    "access_point": (
        "Wi-Fi 6 / 6E / 7 target, radios and spatial streams, indoor or outdoor, antenna type and mounting.",
        "PoE class available at the access switch port (a Wi-Fi 6E or 7 access point often needs 802.3bt or a power injector).",
        "Client density per area and applications on the air (voice, video, location) to confirm the AP count with a survey.",
    ),
}


def links_for(device_type: str, vendors: list[str]) -> list[dict[str, str]]:
    out = []
    for vendor, types, topic, title, url in LINKS:
        if vendor not in vendors:
            continue
        if device_type and types and device_type not in types:
            continue
        out.append({"vendor": vendor, "topic": topic, "title": title, "url": url})
    return out


def sizing_inputs(device_type: str) -> list[str]:
    return list(INPUTS.get(device_type, ()))


def all_links() -> list[dict[str, Any]]:
    return [{"vendor": v, "types": list(t), "topic": topic, "title": title, "url": url} for v, t, topic, title, url in LINKS]


# the peak figures an architect can type per device (the label carries the unit; the same labels are the ones read from a capture or a CSV, so they line up)
PEAK_FIELDS: dict[str, list[str]] = {
    "firewall": ["Peak throughput (Mbit/s)", "Peak application-control throughput (Mbit/s)", "Peak threat-prevention throughput (Mbit/s)", "Peak SSL-inspected throughput (Mbit/s)",
                 "Peak IPsec VPN throughput (Mbit/s)", "Peak concurrent sessions", "Peak new sessions/s", "Peak VPN tunnels", "Peak CPU (%)"],
    "load_balancer": ["Peak throughput (Mbit/s)", "Peak concurrent connections", "Peak new client connections/s", "Peak SSL transactions/s", "Peak CPU (%)"],
    "router": ["Peak throughput (Mbit/s)", "Peak packets/s (pps)", "Peak CPU (%)"],
}
