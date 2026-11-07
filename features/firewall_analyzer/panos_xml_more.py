"""PAN-OS objects that have no table of their own, shown generically so that nothing in an export is silently dropped.

Each entry of the listed object types becomes one row: type, scope (shared, a vsys or the device), name and a one-line summary of its settings.  The summary
is built from the entry's own elements.  Anything whose name looks like a secret (``key``, ``password``, ``phash``, ``secret``, ``community``, ``token``,
``pre-shared`` ...) is skipped by name, never by value, so no secret can reach the result whatever its content.

Reference (object types and where they sit in the configuration): https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin
"""

from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree as ET

from ..analyzer_core.result import table_section

SECRET_TAG = re.compile(r"(?i)(pass|secret|key|phash|community|token|pwd|psk|pre-shared|credential)")
MAX_ITEMS = 16
MAX_VALUE = 60

# collapsed element path (entry names removed) -> friendly type.  A path matches when it ends with the key.
TYPES: dict[str, str] = {
    "/network/tunnel/ipsec/auto-key/proxy-id": "IPsec tunnel proxy ID",
    "/global-protect-portal/client-config/configs/gp-app-config/config": "GlobalProtect agent setting",
    "/global-protect-portal/client-config/configs/gateways/external/list": "GlobalProtect external gateway",
    "/global-protect-portal/client-config/configs/gateways/external/list/priority-rule": "GlobalProtect gateway priority rule",
    "/profiles/virus/decoder": "Antivirus profile decoder",
    "/profiles/virus/mlav-engine-filebased-enabled": "Antivirus ML engine",
    "/profiles/vulnerability/rules": "Vulnerability profile rule",
    "/profiles/spyware/rules": "Anti-spyware profile rule",
    "/profiles/spyware/mica-engine-spyware-enabled": "Anti-spyware ML engine",
    "/profiles/spyware/botnet-domains/dns-security-categories": "Anti-spyware DNS security category",
    "/profiles/file-blocking/rules": "File blocking profile rule",
    "/profiles/url-filtering/mlav-engine-urlbased-enabled": "URL filtering ML engine",
    "/profiles/decryption": "Decryption profile",
    "/profiles/zone-protection-profile/scan": "Zone protection scan setting",
    "/rulebase/qos/rules": "QoS rule",
    "/rulebase/default-security-rules/rules": "Default security rule (intrazone / interzone)",
    "/network/qos/interface/regular-traffic/groups": "QoS group (regular traffic)",
    "/network/qos/interface/tunnel-traffic/groups": "QoS group (tunnel traffic)",
    "/protocol/ospf/area/range": "OSPF area range",
    "/protocol/ospf/export-rules": "OSPF export rule",
    "/protocol/redist-profile": "Redistribution profile",
    "/protocol/bgp/dampening-profile": "BGP dampening profile",
    "/path-monitor/monitor-destinations": "Static route path-monitor destination",
    "/log-settings/snmptrap/version/v3/server": "SNMPv3 trap server",
    "/log-settings/snmptrap": "SNMP trap profile",
    "/log-settings/syslog/server": "Log settings syslog server",
    "/tag": "Tag",
    "/certificate-profile": "Certificate profile",
    "/external-list": "External dynamic list",
    "/application": "Custom application",
    "/alg-override/application": "ALG override",
    "/system/ssh/profiles/mgmt-profiles/server-profiles": "Management SSH server profile",
    "/system/snmp-setting/access-setting/version/v3/views/view": "SNMPv3 view",
    "/setting/wildfire/file-size-limit": "WildFire file size limit",
    "/ike/crypto-profiles/global-protect-app-crypto-profiles": "GlobalProtect app crypto profile",
}


def _leaves(node: ET.Element, prefix: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for child in node:
        if SECRET_TAG.search(child.tag):
            continue
        path = f"{prefix}/{child.tag}" if prefix else child.tag
        if child.tag == "entry":
            name = child.get("name", "")
            if name and not SECRET_TAG.search(name):
                out.append((prefix or "entry", name))
            out += _leaves(child, prefix)
        elif child.tag == "member":
            continue
        elif len(child) == 0:
            text = (child.text or "").strip()
            out.append((path, text or "yes"))                       # an empty element is a flag
        else:
            members = [(m.text or "").strip() for m in child.findall("member") if (m.text or "").strip()]
            if members:
                out.append((path, ", ".join(members)))
            out += _leaves(child, path)
    return out


def _summary(entry: ET.Element) -> str:
    merged: dict[str, list[str]] = {}
    for key, value in _leaves(entry):
        merged.setdefault(key, []).append(value[:MAX_VALUE])
    pieces = [f"{k.split('/')[-1] if k.count('/') < 2 else k}={'; '.join(v[:4])}{'…' if len(v) > 4 else ''}" for k, v in merged.items()]
    text = "  ·  ".join(pieces[:MAX_ITEMS])
    return text + ("  ·  …" if len(pieces) > MAX_ITEMS else "")


def extract(root: ET.Element) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ordered = sorted(TYPES, key=len, reverse=True)

    def walk(node: ET.Element, path: str, scope: str) -> None:
        for child in node:
            if child.tag == "entry":
                name = child.get("name", "")
                kind = next((TYPES[k] for k in ordered if path.endswith(k)), "")
                if kind and not SECRET_TAG.search(name):
                    rows.append({"type": kind, "scope": scope, "name": name, "settings": _summary(child)})
                inner_scope = name if path.endswith("/vsys") else scope
                walk(child, path, inner_scope)
            else:
                walk(child, path + "/" + child.tag, "shared" if (path == "" and child.tag == "shared") else scope)

    walk(root, "", "device")
    seen = set()
    unique = []
    for r in rows:
        key = (r["type"], r["scope"], r["name"], r["settings"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def sections(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return []
    return [table_section("pan_more_objects", "Other configuration objects", [("type", "Type"), ("scope", "Scope"), ("name", "Name", "mono"), ("settings", "Settings", "wrap")], rows, group="Objects",
                          hint="Object types that have no table of their own, listed so nothing in the export is hidden. Names that look like keys, passwords or community strings are never read; only the element names are skipped, not their content.")]
