"""Convert domains: what Keystone can convert, per kind of device.

Why this exists
---------------
Configuration Studio used to be one page with one pool of vendors. A router
backup, a firewall export and a switch config all went through the same
auto-detect, and the detector picks the highest keyword score even when that
score is tiny: an IOS-XE router with ACLs was reported as "Cisco FTD" because
the ASA branch counts the generic words ``access-list `` and ``access-group ``,
and a router with no Layer-2 lines was reported as a "Cisco Switch" with
confidence 2.

A *domain* is the kind of device a conversion is about. There are five, the
same five as the Analyze menu:

    wireless, switch, router, firewall, load_balancer

Each Convert page is bound to exactly one domain. Three rules follow:

* The domain is the device type. Auto Detect only chooses the *vendor*, and
  only among vendors that have a parser in that domain.
* A file that clearly belongs to another domain is refused, with the page to
  open instead, rather than being pushed through the wrong parser.
* A domain with no registered parser/translator says so, and says what is
  needed to add one. It never pretends to convert.

Adding a converter
------------------
1. Write the parser under ``parsers/<domain>/`` and the translator under
   ``translators/<domain>/``.
2. Register them in ``engine.parser_registry`` / ``engine.translator_registry``
   with the domain key as the first element of the key, for example
   ``("router", "cisco")``. This module reads those registries, so the page
   switches from "not available" to a working form without further edits.
3. Add the platform's markers to ``DeviceDetector`` or ``classify`` below and
   a fixture under ``tests/fixtures/`` that proves the detection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .detector import DeviceDetector

_FLAGS = re.M | re.I


@dataclass(frozen=True)
class DomainSpec:
    key: str
    label: str
    icon: str
    analyzer_name: str
    analyzer_href: str
    summary: str
    capture: str          # what a good source file looks like
    needs: tuple[str, ...]  # what is needed before a converter can exist


DOMAINS: dict[str, DomainSpec] = {
    "wireless": DomainSpec(
        "wireless", "Wireless", "wireless", "Wireless Analyzer", "/wireless",
        "Wireless controller configuration (Cisco 9800 / AireOS, Huawei AC, Aruba).",
        "Full running configuration of the controller.",
        ("A source controller backup and the target controller type",
         "A mapping rule for WLAN/SSID, security, AP group and RF profiles",
         "A target configuration that is known to be correct, for comparison"),
    ),
    "switch": DomainSpec(
        "switch", "Switch", "switch", "Switch Analyzer", "/switch-analyzer",
        "Layer-2 and Layer-3 switch configuration: VLANs, trunks, port-channels, SVIs, routing, ACLs.",
        "show running-config (Cisco / Aruba) or display current-configuration (Huawei).",
        (),
    ),
    "router": DomainSpec(
        "router", "Router", "router", "Router Analyzer", "/router-analyzer",
        "Router configuration: WAN interfaces, routing protocols, NAT, IPsec/GRE, SD-WAN.",
        "show running-config of the router (IOS / IOS-XE), or the SD-WAN device template.",
        ("A source router backup and the target platform",
         "A decision on how routing, NAT, IPsec and ACL sections map to the target",
         "A target configuration that is known to be correct, for comparison"),
    ),
    "firewall": DomainSpec(
        "firewall", "Firewall", "firewall", "Firewall Analyzer", "/firewall-analyzer",
        "Firewall policy, NAT, address objects, VPN and routing moved between vendors.",
        "RouterOS /export (MikroTik). FortiGate and Palo Alto files are analysed, not converted.",
        ("A source export for each additional vendor (FortiGate, Palo Alto, Cisco ASA/FTD)",
         "The zone and interface mapping to the target firewall",
         "A target configuration that is known to be correct, for comparison"),
    ),
    "load_balancer": DomainSpec(
        "load_balancer", "Load Balancer", "balancer", "Load Balancer Analyzer", "/load-balancer-analyzer",
        "Load balancer virtual servers, pools, monitors, persistence and SSL profiles.",
        "F5 bigip.conf or a UCS archive.",
        ("A source F5 configuration and the target load balancer",
         "A mapping rule for virtual servers, pools, monitors, profiles and iRules",
         "A target configuration that is known to be correct, for comparison"),
    ),
}

# DeviceDetector.device_type (lower case) -> domain key
_DETECTOR_DOMAIN = {"switch": "switch", "firewall": "firewall", "wlc": "wireless"}


def domain_keys() -> tuple[str, ...]:
    return tuple(DOMAINS)


def get_domain(key: str) -> DomainSpec:
    try:
        return DOMAINS[str(key or "").strip().lower()]
    except KeyError:
        raise ValueError(f"Unknown convert domain: {key!r}") from None


@dataclass(frozen=True)
class DomainGuess:
    domain: str          # a DOMAINS key, or "unknown"
    vendor: str
    confidence: str      # "high" | "none"
    evidence: tuple[str, ...] = ()


def _hits(patterns: tuple[tuple[str, str], ...], text: str) -> list[str]:
    return [name for name, pattern in patterns if re.search(pattern, text, _FLAGS)]


_F5 = (
    ("ltm object", r"^ltm (virtual|pool|node|monitor|profile|rule|policy|persistence|virtual-address) "),
    ("gtm object", r"^gtm (wideip|pool|server|datacenter|listener) "),
    ("net object", r"^net (vlan|self|route|trunk|route-domain) "),
    ("sys object", r"^sys (global-settings|ntp|dns|httpd|sshd|software|provision|folder) "),
    ("tmsh command", r"^(tmsh )?(list|show) (ltm|gtm|net|sys) "),
)

_CISCO_ROUTER = (
    ("routing process", r"^router (bgp|eigrp|rip|isis|ospfv3)\b"),
    ("crypto", r"^crypto (isakmp|ikev2|ipsec|map|pki)\b"),
    ("nat pool", r"^ip nat (inside|outside|pool)\b"),
    ("nat on interface", r"^\s+ip nat (inside|outside)\b"),
    ("tunnel interface", r"^interface tunnel\d"),
    ("tunnel settings", r"^\s+tunnel (source|destination|mode)\b"),
    ("ip sla", r"^ip sla( monitor)? \d"),
    ("vrf", r"^(vrf definition|ip vrf)\b"),
    ("sd-wan", r"^(sdwan|system\s*\n\s+system-ip)\b"),
    ("license level", r"^license boot level"),
    ("wan interface", r"^interface (serial|cellular|multilink|dialer)\S*"),
    ("router show command",
     r"^(?:\S+[#>])?\s*show (ip bgp|bgp|ip ospf|ip eigrp|crypto (isakmp|ikev2|ipsec|gdoi|session)|ip nat|sdwan|ip sla|ip cef)\b"),
    ("router platform",
     r"\b(ISR\d{4}\w*|ASR\d{4}\w*|C8[0-9]{3}\w*|CSR1000V|C(?:3825|3845|2951|2911|1941|2921|3945))\b"),
)

_LAYER2 = (
    ("switchport", r"^\s*switchport\b"),
    ("spanning-tree", r"^spanning-tree\b"),
    ("vlan", r"^vlan \d"),
    ("vtp", r"^vtp\b"),
    ("poe", r"^\s*power inline"),
    ("errdisable", r"^errdisable\b"),
    ("layer-2 show command",
     r"^(?:\S+[#>])?\s*show (vlan|spanning-tree|mac address-table|interfaces? status|etherchannel|power inline|vtp)\b"),
    ("switch platform",
     r"\b(WS-C\d+\w*|C9[2-5]00\w*|N[3579]K-\w+|Nexus ?\d+|C(?:2960|3560|3650|3850)\w*)\b"),
)

_HUAWEI_ROUTER = (
    ("ike", r"^ike (peer|proposal)\b"),
    ("ipsec", r"^ipsec (policy|proposal)\b"),
    ("nat", r"^\s*nat (outbound|server)\b"),
    ("tunnel interface", r"^interface tunnel\S*"),
    ("wan interface", r"^interface (cellular|dialer)\S*"),
)
_HUAWEI_LAYER2 = (
    ("vlan batch", r"^vlan batch\b"),
    ("port link-type", r"^\s*port link-type\b"),
    ("stp", r"^stp \S+"),
    ("port-group", r"^port-group\b"),
)

_ASA_SPECIFIC = re.compile(
    r"^\s*(nameif|security-level)\b|^object (network|service) |^object-group (network|service) |asa version",
    _FLAGS,
)


def classify(text: str) -> DomainGuess:
    """Say which domain a file belongs to, only when the evidence is clear.

    ``confidence`` is ``"high"`` or ``"none"``. ``"none"`` means "no strong
    evidence either way": callers must then fall back to the page's own
    domain instead of treating the file as foreign.
    """
    # PAN-OS "show config running" (curly-brace view) has none of the markers
    # DeviceDetector knows; it was being read as an Aruba switch.
    from .parsers.firewall.paloalto_curly import looks_like_curly

    if looks_like_curly(text):
        return DomainGuess("firewall", "Palo Alto", "high", ("PAN-OS CLI configuration",))

    base = DeviceDetector().detect_text(text)
    base_domain = _DETECTOR_DOMAIN.get(base.device_type.lower(), "unknown")

    f5 = _hits(_F5, text)
    if len(f5) >= 2 or (len(f5) == 1 and len(re.findall(_F5[0][1], text, _FLAGS)) >= 3):
        return DomainGuess("load_balancer", "F5", "high", tuple(f5))

    # The ASA/FTD branch of the detector counts generic words ("access-list ",
    # "access-group ") that every IOS device has, so without ASA-only lines
    # that result is not evidence of a firewall.
    ftd_without_asa = base.vendor == "Cisco FTD" and not _ASA_SPECIFIC.search(text)

    if base_domain in ("switch", "unknown") or ftd_without_asa:
        router = _hits(_CISCO_ROUTER, text)
        layer2 = _hits(_LAYER2, text)
        if (len(router) >= 2 and not layer2) or (len(router) >= 4 and len(router) > 2 * len(layer2)):
            return DomainGuess("router", "Cisco", "high", tuple(router))
        huawei = _hits(_HUAWEI_ROUTER, text)
        if len(huawei) >= 2 and not _hits(_HUAWEI_LAYER2, text):
            return DomainGuess("router", "Huawei", "high", tuple(huawei))
        if ftd_without_asa:
            return DomainGuess("unknown", "Cisco", "none")

    if base_domain == "unknown" or base.confidence <= 0:
        return DomainGuess("unknown", base.vendor, "none")
    return DomainGuess(base_domain, base.vendor, "high")
