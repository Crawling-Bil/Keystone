"""FortiGate objects that have no table of their own, shown generically so that nothing in a configuration is silently dropped.

One row per entry (or one row for a block that only has settings): type, VDOM, name and a one-line summary of the settings.  Secrets never get here: ``forti_tree``
keeps every password, key, PSK and token in ``FNode.secrets`` and only harmless settings in ``FNode.settings``.  The one object whose entry name is itself an
identifier (a FortiToken serial number) is masked to its last four characters.

Factory tables that hold thousands of built-in rows and carry no decision (internet-service names, GUI dashboard widgets, replacement messages, NPU queues,
WAN-optimisation CDN rules, SSL VPN host-check software and the like) are left out on purpose.

Reference: FortiOS Administration Guide and CLI Reference, https://docs.fortinet.com/product/fortigate/7.2
"""

from __future__ import annotations

import re
from typing import Any

from ..analyzer_core.result import table_section
from .forti_tree import FNode, FortiTree

PATHS: dict[str, str] = {
    "dlp sensor": "DLP sensor", "dlp filepattern": "DLP file pattern", "dlp dictionary": "DLP dictionary", "dlp sensitivity": "DLP sensitivity label", 
    "dlp data-type": "DLP data type", "dlp fp-doc-source": "DLP fingerprint source",
    "webfilter ftgd-local-cat": "Web filter local category", "webfilter ftgd-local-rating": "Web filter local rating",
    "user fortitoken": "FortiToken", "user peer": "Peer user", "user peergrp": "Peer group", "user pop3": "POP3 server", "user nac-policy": "NAC policy",
    "switch-controller lldp-profile": "FortiSwitch LLDP profile", "switch-controller qos qos-policy": "FortiSwitch QoS policy", "switch-controller qos queue-policy": "FortiSwitch queue policy",
    "switch-controller qos dot1p-map": "FortiSwitch 802.1p map", "switch-controller qos ip-dscp-map": "FortiSwitch DSCP map", "switch-controller storm-control-policy": "FortiSwitch storm control",
    "switch-controller security-policy 802-1X": "FortiSwitch 802.1X policy", "switch-controller security-policy local-access": "FortiSwitch local-access policy",
    "switch-controller remote-log": "FortiSwitch remote log", "switch-controller auto-config policy": "FortiSwitch auto-config policy", "switch-controller initial-config template": "FortiSwitch initial config template",
    "switch-controller traffic-policy": "FortiSwitch traffic policy", "switch-controller ptp policy": "FortiSwitch PTP policy", "switch-controller switch-profile": "FortiSwitch switch profile",
    "wireless-controller wids-profile": "Wireless IDS profile", "wireless-controller ble-profile": "BLE profile", "wireless-controller arrp-profile": "ARRP profile",
    "system storage": "Local storage", "system ha ha-mgmt-interfaces": "HA management interface", "system session-ttl": "Session TTL", "system resource-limits": "Resource limits",
    "system central-management": "Central management", "system cluster-sync": "Cluster sync", "system standalone-cluster": "Standalone cluster", "system email-server": "Email server",
    "system federated-upgrade": "Federated upgrade", "system sso-admin": "SSO administrator", "system console": "Console", "system object-tagging": "Object tagging",
    "log tap-device": "Log tap device", "log threat-weight": "Log threat weight",
    "firewall ssh local-ca": "SSH proxy local CA", "firewall ssh local-key": "SSH proxy local key", "firewall multicast-policy": "Multicast policy", 
    "icap profile": "ICAP profile", "vpn ocvpn": "Overlay controller VPN", "firewall internet-service-definition": "Internet service definition",
    "firewall internet-service-custom": "Custom internet service", "firewall internet-service-group": "Internet service group", "firewall shaping-profile": "Shaping profile",
    "web-proxy global": "Web proxy global", "web-proxy explicit": "Explicit web proxy", "ztna web-proxy": "ZTNA web proxy", "ztna traffic-forward-proxy": "ZTNA traffic forward proxy",
    "endpoint-control profile": "Endpoint control profile", "extension-controller extender": "FortiExtender",
    "system lldp network-policy": "LLDP network policy",
    "system geoip-override": "GeoIP override", "system ips-urlfilter-dns": "IPS URL filter DNS", "system vdom-dns": "VDOM DNS", "system vdom-netflow": "VDOM NetFlow", "system vdom-sflow": "VDOM sFlow",
    "system netflow": "NetFlow", "system sflow": "sFlow", "system tos-based-priority": "ToS-based priority", "system proxy-arp": "Proxy ARP", "system wccp": "WCCP", "system gre-tunnel": "GRE tunnel",
    "system ipip-tunnel": "IPIP tunnel", "system sit-tunnel": "SIT tunnel", "system vxlan": "VXLAN", "system switch-interface": "Switch interface", "system pppoe-interface": "PPPoE interface",
    "system mobile-tunnel": "Mobile tunnel", "system nat64": "NAT64", "system nat64-policy": "NAT64 policy", "system ipv6-neighbor-cache": "IPv6 neighbour cache", "system ipv6-tunnel": "IPv6 tunnel",
    "system fortiguard": "FortiGuard", "system fortisandbox": "FortiSandbox", "system fm": "FortiManager", "system csf": "Security Fabric", 
    "system probe-response": "Probe response", "system replacemsg-group": "Replacement message group",
}
SECRET_KEY = re.compile(r"(?i)(pass|secret|key|seed|psk|token|community|credential|auth-|priv-)")           # names only; a second line of defence behind FNode.secrets
TOKEN_TYPES = {"user fortitoken"}
MAX_ITEMS = 18
MAX_VALUE = 70
MAX_BLOB = 100


def _mask(name: str) -> str:
    return ("*" * max(len(name) - 4, 0)) + name[-4:]


def _summary(node: FNode) -> str:
    parts: list[str] = []
    for key, values in node.settings.items():
        joined = " ".join(values)
        if values and (values[0] == "ENC" or (SECRET_KEY.search(key) and not key.endswith(("-name", "-type")) and len(joined) > 20 and not key.startswith("public"))):
            parts.append(f"{key}=<hidden>")
            continue
        shown = f"<{len(joined)} characters not shown>" if len(joined) > MAX_BLOB or "-----BEGIN" in joined else joined[:MAX_VALUE]       # certificates and public keys are long blobs, not settings
        parts.append(f"{key}={shown}")
    for child in node.children:
        if child.kind == "config":
            count = len(child.entries())
            parts.append(f"{child.name}: {count} entr{'y' if count == 1 else 'ies'}" if count else f"{child.name}: settings")
    for hidden in node.secrets:
        if not any(part.startswith(hidden + "=") for part in parts):
            parts.append(f"{hidden}=<hidden>")
    text = "  ·  ".join(parts[:MAX_ITEMS])
    return text + ("  ·  …" if len(parts) > MAX_ITEMS else "")


def extract(tree: FortiTree, already: set[str] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path, label in PATHS.items():
        for scope, block in tree.find(path):
            entries = block.entries()
            if entries:
                for entry in entries:
                    name = _mask(entry.name) if path in TOKEN_TYPES else entry.name
                    rows.append({"vdom": scope, "type": label, "name": name, "settings": _summary(entry)})
            elif block.settings or block.children:
                rows.append({"vdom": scope, "type": label, "name": "(settings)", "settings": _summary(block)})
    seen: set[tuple[str, str, str, str]] = set()
    out = []
    for row in rows:
        key = (row["vdom"], row["type"], row["name"], row["settings"])
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out


def sections(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return []
    return [table_section("more_objects", "Other configuration objects", [("vdom", "VDOM"), ("type", "Type"), ("name", "Name", "mono"), ("settings", "Settings", "wrap")], rows, group="Objects",
                          hint="Object types that have no table of their own, listed so nothing in the configuration is hidden. Passwords, keys, PSKs and tokens are never shown; FortiToken serial numbers are masked.")]
