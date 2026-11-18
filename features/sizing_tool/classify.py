"""Which analyzer reads a capture, and what kind of device it is.

The vendor and the analyzer family come from ``analyzer_core.vendor_hint.identify`` (the same call every analyzer uses to point at the right page).
The finer calls (a wireless controller is not a router, a Catalyst 8300 is not a switch) use the role rules of the Topology Builder, so the
two tools name a device the same way: the model first, then the words of the hostname.
"""

from __future__ import annotations

import re

from features.analyzer_core.capture import F5_PROMPT
from features.analyzer_core.vendor_hint import identify
from features.topology import roles

DEVICE_TYPES = ("switch", "router", "firewall", "load_balancer", "wlc", "access_point")
TYPE_LABELS = {
    "switch": "Switch", "router": "Router", "firewall": "Firewall",
    "load_balancer": "Load balancer", "wlc": "Wireless controller", "access_point": "Access point",
}
ANALYZER_OF = {
    "switch": "Switch Analyzer", "router": "Router Analyzer", "firewall": "Firewall Analyzer",
    "load_balancer": "Load Balancer Analyzer", "wlc": "Wireless Analyzer", "access_point": "Wireless Analyzer",
}
ROLE_TYPE = {
    "firewall": "firewall", "loadbalancer": "load_balancer", "router": "router", "cloud": "router",
    "wlc": "wlc", "ap": "access_point",
    "core": "switch", "aggregation": "switch", "access": "switch", "switch": "switch", "fabric": "switch",
}
# the tier a switch plays, in the words an architect uses
TIER_LABEL = {"core": "Core", "aggregation": "Distribution", "access": "Access", "switch": "Switch", "fabric": "Fabric"}

# a Cisco IOS / IOS-XE router: the Router Analyzer reads it (BGP, OSPF, IPsec, NAT, SD-WAN); every other switch or router goes through the Switch Analyzer
_CISCO_ROUTER_MODEL = re.compile(r"(?im)\b(?:ISR\s?\d{3,4}|ASR\s?\d{3,4}|C8[0-9]{3}[A-Z]?(?:-[A-Z0-9]+)*|CSR\s?1000V|C11[0-9]{2}|NCS\s?\d{3,4}|cEdge)\b")
_CISCO_ROUTER_BOARD = re.compile(r"(?im)^cisco\s+(?:ISR|ASR|C8[0-9]{3}|CSR|C11[0-9]{2})\S*")
# Cisco C9800 controller (IOS-XE) and Huawei AC (VRP)
_WLC_CISCO = re.compile(r"(?im)^(?:wireless (?:management interface|tag policy|profile policy|profile policy|aaa|country)\b|wireless\s+(?:management|tag|profile|rf-profile)\b|ap profile\s+\S+|ap tag\s+\S+|show wireless\b|show ap summary\b)|\bC9800\b|Catalyst 9800|wireless management interface")
_WLC_HUAWEI = re.compile(r"(?im)^(?:capwap source\b|ap-group name\b|regulatory-domain-profile name\b|vap-profile name\b|ssid-profile name\b|ap-id \d+|ap-mac\s)|\bdisplay ap (?:all|config-info)\b|\bAC6[0-9]{3}\b|\bAC66[0-9]{2}\b")
_AP_ONLY = re.compile(r"(?im)^(?:ap name\s|AP Name\s+AP Model|show ap summary)|\bCisco AP Software\b|\bC91[0-9]{2}AX[A-Z]*-[A-Z0-9]+\b")


# ArubaOS-Switch (AOS-S, ProVision): "show tech" / "show system" output or a config whose first line names the product number
_AOS_S = re.compile(r"(?im)^;\s*J[LK]?\d{3,4}[A-Z]?\s+Configuration Editor|^\s*Status and Counters - General System Information|^\s*module\s+\d+\s+type\s+j[lk]?\d{3,4}[a-z]?\b|^\s*Software revision\s*:\s*[A-Z]{1,2}\.\d{2}\.\d{2}")
# a Cisco IOS / IOS-XE box captured with show commands only (show version, show inventory): identify() needs a configuration to recognise it
_IOS_SHOW = re.compile(r"(?im)^Cisco IOS (?:XE )?Software\b|^cisco\s+\S+\s+\(.*?\)\s+processor\b|^System image file is\s+\"?(?:flash|bootflash|usbflash)|^PID:\s*[A-Z0-9][\w./-]+\s*,\s*VID:")
_NXOS = re.compile(r"(?im)^\s*(?:Cisco Nexus Operating System \(NX-OS\) Software|NXOS:\s*version\s+\d)")


class Classified(dict):
    """``{"analyzer": "switch"|"router"|"firewall"|"lb"|"wireless", "brand": str, "label": str}`` plus nothing else; a dict so it travels as JSON."""


def _f5(text: str) -> bool:
    return any(F5_PROMPT.match(line) for line in text[:300_000].splitlines()[:600])


def classify(text: str) -> dict[str, str]:
    """The analyzer that should read ``text``.  ``analyzer`` is "" when nothing recognised it."""
    sample = text[:3_000_000]
    if _AOS_S.search(sample) and not _f5(sample):
        return {"analyzer": "aos_s", "brand": "Aruba", "label": "Aruba AOS-S switch (ArubaOS-Switch)"}
    found = identify(sample)
    kind, label = found.get("kind", ""), found.get("label", "")
    if kind == "firewall":
        brand = "Palo Alto" if label.startswith("Palo Alto") else "Fortinet" if label.startswith("Fortinet") else "MikroTik"
        return {"analyzer": "firewall", "brand": brand, "label": label}
    if kind == "lb" or _f5(sample):
        return {"analyzer": "lb", "brand": "F5", "label": label or "F5 BIG-IP"}
    if _WLC_HUAWEI.search(sample) and re.search(r"(?im)^(?:sysname |#\s*$|<[^>\s]+>)", sample):
        return {"analyzer": "wireless", "brand": "Huawei", "label": "Huawei wireless controller"}
    if _WLC_CISCO.search(sample) and re.search(r"(?im)\bcisco\b|IOS XE|IOS-XE", sample):
        return {"analyzer": "wireless", "brand": "Cisco", "label": "Cisco Catalyst 9800 controller"}
    brand = {"Aruba AOS-CX switch": "Aruba", "Huawei switch or router configuration": "Huawei", "Cisco switch or router configuration": "Cisco"}.get(label, "")
    if not brand and _NXOS.search(sample):
        # a Nexus capture made of show commands (version, inventory, port-channel, vpc) has no configuration for identify() to recognise; the Switch Analyzer reads it
        return {"analyzer": "switch", "brand": "Cisco", "label": "Cisco Nexus switch (show commands)"}
    if not brand and _IOS_SHOW.search(sample):
        brand, label = "Cisco", label or "Cisco IOS / IOS-XE (show commands)"
    if not brand:
        return {"analyzer": "", "brand": "", "label": label}
    if brand == "Cisco" and (_CISCO_ROUTER_BOARD.search(sample) or _router_by_model(sample)):
        return {"analyzer": "router", "brand": brand, "label": label}
    return {"analyzer": "switch", "brand": brand, "label": label}


_ROUTER_FAMILY = r"(?:ISR|ASR|C8[0-9]{3}|CSR|C11[0-9]{2}|NCS)"
_ROUTER_BY_MODEL = re.compile(r"(?im)^(?:NAME:.*DESCR:\s*\"?(?:Cisco\s+)?" + _ROUTER_FAMILY + r"|PID:\s*" + _ROUTER_FAMILY + r"|cisco\s+" + _ROUTER_FAMILY + r"|license udi pid\s+" + _ROUTER_FAMILY
                              + r"|Model name:\s*" + _ROUTER_FAMILY + r"|Model Number\s*:\s*" + _ROUTER_FAMILY + r")")


def _router_by_model(text: str) -> bool:
    """A Cisco router by the model its own ``show version`` / ``show inventory`` names.  The whole capture is searched: on a long
    configuration the inventory sits far below the first lines (an ASR 1002-X names itself at line 1480)."""
    return bool(_ROUTER_BY_MODEL.search(text))


def role_of(hostname: str, model: str, fallback: str = "") -> str:
    """The Topology Builder's role word for a device: the model rules decide first for a controller, a firewall, a router, then the hostname words."""
    name = (hostname or "").upper()
    mod = (model or "").upper()
    by_model = roles._by_rules(roles._MODEL_RULES, mod)
    if by_model in ("firewall", "loadbalancer", "router", "wlc", "ap"):
        return by_model
    by_name = roles._by_rules(roles._WORD_RULES, name) or roles._by_rules(roles._EMBEDDED_RULES, name)
    return by_name or by_model or fallback or ""


def device_type_of(role: str, analyzer: str) -> str:
    if analyzer == "firewall":
        return "firewall"
    if analyzer == "lb":
        return "load_balancer"
    if analyzer == "router":
        return "router"
    if analyzer == "wireless":
        return "wlc"
    return ROLE_TYPE.get(role, "switch")


def tier_of(role: str, device_type: str) -> str:
    """Core / Distribution / Access for a switch; the type's own word for the others."""
    if device_type == "switch":
        return TIER_LABEL.get(role, "Switch")
    return TYPE_LABELS.get(device_type, device_type)


_SITE_WORDS = {"CORE", "EDGE", "SW", "RTR", "FW", "LB", "WLC", "AP", "ACC", "DS", "TOR", "SF", "WANR", "FGLAN", "FGWAN", "PADC", "CSW", "AGG", "DIST", "SPINE", "LEAF", "BL", "FI"}


def site_of(hostname: str) -> str:
    """The site a hostname names by its first word (JKT-SW1 -> JKT, HQ-DC-CORE1 -> HQ-DC); one word names no site.  The user can regroup in the page."""
    parts = [p for p in re.split(r"[-_.]", (hostname or "").upper()) if p]
    if len(parts) < 2:
        return ""
    keep: list[str] = []
    for part in parts[:-1]:
        stem = re.sub(r"\d+$", "", part)
        if stem in _SITE_WORDS and keep:
            break
        if stem in _SITE_WORDS and not keep:
            return ""
        keep.append(part)
        if len(keep) == 2:
            break
    return "-".join(keep)
