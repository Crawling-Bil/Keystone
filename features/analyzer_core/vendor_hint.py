"""Recognise which analyzer a capture belongs to, so a wrong-page upload gets a pointer instead of a dead end.

Every analyzer calls :func:`wrong_page_hint` when it cannot read a file.  The answer names what the file looks like (and, when the
file says so, the model and software version) and the page to open.  The patterns are deliberately cheap and conservative: a hint
that is wrong is worse than no hint.
"""

from __future__ import annotations

import re

PAGES = {
    "firewall": ("Firewall Analyzer", "/firewall-analyzer/"),
    "router": ("Router Analyzer", "/router-analyzer/"),
    "switch": ("Switch Analyzer", "/switch-analyzer/"),
    "lb": ("Load Balancer Analyzer", "/load-balancer-analyzer/"),
}

_PAN_PROMPT = re.compile(r"(?m)^\S+@\S+>\s*(?:show|set cli|request|configure|debug)\b")
_PAN_MODEL = re.compile(r"(?m)^model:\s*(PA-\S+|VM-\S+)")
_PAN_VERSION = re.compile(r"(?m)^sw-version:\s*(\S+)")
_PAN_CURLY = re.compile(r"(?m)^\s*(?:config\s*\{|deviceconfig\s*\{|devices\s*\{|rulebase\s*\{)")
_PAN_SET = re.compile(r"(?m)^set (?:deviceconfig|rulebase|network|zone|shared|vsys)\b|<config\b[^>]*version=")
_FORTI = re.compile(r"(?m)^(?:#config-version=FG|config (?:system global|firewall policy|system interface|vpn ipsec phase1-interface)\b)")
_MIKROTIK = re.compile(r"(?m)^(?:/(?:ip|interface|system|routing|queue)\s|# .*by RouterOS)")
_F5 = re.compile(r"(?m)^(?:#TMSH-VERSION:|ltm (?:virtual|pool|node|monitor|profile)\b|net (?:self|vlan)\b|sys global-settings\b|cm device-group\b)")
_CISCO = re.compile(r"(?m)^(?:interface (?:GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet|Vlan|Loopback|Port-channel)\S*|router (?:bgp|ospf|eigrp)\b|ip route \d|spanning-tree mode|switchport mode)")
_HUAWEI = re.compile(r"(?m)^(?:sysname |interface (?:XGigabitEthernet|Eth-Trunk|Vlanif)|vlan batch)")
# AOS-CX prints its release on the first lines of ``show running-config`` and numbers ports member/slot/port (``interface 1/1/1``).
_AOSCX = re.compile(r"(?m)^(?:!Version AOS-CX\b|interface \d+/\d+/\d+\s*$)")
_ARUBA = re.compile(r"(?m)^(?:hostname \"|;\s*\S+ Configuration Editor|vlan \d+\s*$|ArubaOS-CX|aruba-central)")


def identify(text: str) -> dict[str, str]:
    """``{"kind": "firewall"|"router"|"switch"|"lb"|"", "label": "...", "detail": "..."}`` for the first family that matches."""
    sample = text[:3_000_000]
    if _PAN_SET.search(sample) or (_PAN_CURLY.search(sample) and re.search(r"(?m)^\s*(?:deviceconfig|network|zone|rulebase)\s*\{", sample)):
        return {"kind": "firewall", "label": "Palo Alto PAN-OS firewall", "detail": _pan_detail(sample)}
    model = _PAN_MODEL.search(sample)
    if _PAN_PROMPT.search(sample) and (model or re.search(r"(?m)^sw-version:", sample)):
        return {"kind": "firewall", "label": "Palo Alto PAN-OS firewall", "detail": _pan_detail(sample)}
    if _PAN_PROMPT.search(sample) and re.search(r"(?m)^\S+@\S+>\s*(?:set cli (?:pager|scripting-mode)\b|show (?:system|config running)\b)", sample):
        return {"kind": "firewall", "label": "Palo Alto PAN-OS firewall", "detail": _pan_detail(sample)}
    if _FORTI.search(sample):
        return {"kind": "firewall", "label": "Fortinet FortiGate firewall", "detail": ""}
    if _MIKROTIK.search(sample):
        return {"kind": "firewall", "label": "MikroTik RouterOS export", "detail": ""}
    if _F5.search(sample):
        return {"kind": "lb", "label": "F5 BIG-IP configuration", "detail": ""}
    if _AOSCX.search(sample):
        return {"kind": "switch", "label": "Aruba AOS-CX switch", "detail": ""}
    if _HUAWEI.search(sample):
        return {"kind": "router", "label": "Huawei switch or router configuration", "detail": ""}
    if _CISCO.search(sample):
        return {"kind": "router", "label": "Cisco switch or router configuration", "detail": ""}
    return {"kind": "", "label": "", "detail": ""}


def _pan_detail(sample: str) -> str:
    model, version = _PAN_MODEL.search(sample), _PAN_VERSION.search(sample)
    return ", ".join(x for x in (model.group(1) if model else "", f"PAN-OS {version.group(1)}" if version else "") if x)


def wrong_page_hint(text: str, current: str) -> str:
    """A sentence to append to a "not recognised" error; ``current`` is the page that is reading the file (``firewall``, ``lb``...)."""
    found = identify(text)
    kind = found["kind"]
    if not kind or kind == current or (kind == "router" and current == "switch"):
        return ""
    if kind == "router":
        target = "the Router Analyzer (routers) or the Switch Analyzer (switches)"
    else:
        target = f"the {PAGES[kind][0]}"
    detail = f" ({found['detail']})" if found["detail"] else ""
    article = "an" if found["label"][:1] in "AEIOU" or found["label"].startswith("F5") else "a"
    return f" This file looks like {article} {found['label']}{detail} - open {target} instead."
