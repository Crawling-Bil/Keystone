"""Nodes for the things nobody captured: provider networks (MPLS, Internet, Metro-E, mobile) and gateways.

The provider edge router and the modem are not captured, so the picture needs a cloud and the reader needs to know why it is there.
A cloud is drawn when one of these signals says what an access link connects to, strongest first:

1. a rule typed in the "Provider hints" box (``parse_hints``): ``HQWANR1 Gi0/0/1 = mpls Telkom``, ``203.0.113.0/30 = internet Biznet``, ``METRO-JKT = metro Moratel``;
2. words in the interface description, the VRF name or the name of the neighbor seen on that port (CDP / LLDP): ``MPLS``, ``INET``, ``Metro-E``, ``LTE`` and
   provider names;
3. the SD-WAN colour of the tunnel interface that uses the port: ``mpls`` is MPLS, ``metro-ethernet`` Metro-E, ``biz-internet`` and
   ``public-internet`` Internet, ``lte`` and ``3g`` mobile.  Colour names: Cisco Catalyst SD-WAN colour list
   (https://netascode.cisco.com/docs/data_models/sdwan/policy_objects/color_list/); ``mpls``, ``metro-ethernet`` and ``private1..6`` are the private colours;
4. nothing but a gateway address (a static or default route, an uncaptured routing neighbor): a plain gateway node.

One cloud is shared by every site that uses the same transport and provider; each link keeps the gateway address it reaches the cloud through.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from .extract import Device
from .graph import Graph
from .names import canon_port

TYPE_LABEL = {"mpls": "MPLS", "internet": "Internet", "metro": "Metro-E", "mobile": "Mobile (LTE / 3G)", "private": "Private WAN", "other": "WAN"}
COLOUR_TYPE = {"mpls": "mpls", "metro-ethernet": "metro", "biz-internet": "internet", "public-internet": "internet", "lte": "mobile", "3g": "mobile",
               "private1": "private", "private2": "private", "private3": "private", "private4": "private", "private5": "private", "private6": "private"}
WORD_TYPE = (("mpls", "mpls"), ("vpls", "metro"), ("metro-e", "metro"), ("metroe", "metro"), ("metro", "metro"), ("internet", "internet"), ("inet", "internet"),
             ("broadband", "internet"), ("ftth", "internet"), ("dia", "internet"), ("isp", "internet"), ("lte", "mobile"), ("4g", "mobile"), ("5g", "mobile"), ("gsm", "mobile"))
PROVIDERS = ("telkomsel", "telkom", "indihome", "indosat", "biznet", "lintasarta", "moratel", "iforte", "firstmedia", "cbn", "xl", "smartfren", "linknet", "mncplay",
             "icon+", "oxygen", "verizon", "comcast", "lumen", "level3", "orange", "vodafone", "ntt", "singtel", "pccw", "telstra", "tata", "airtel", "equinix", "att")
_TYPE_WORDS = {"mpls": "mpls", "internet": "internet", "inet": "internet", "metro": "metro", "metro-e": "metro", "metroe": "metro", "lte": "mobile", "mobile": "mobile", "private": "private"}


@dataclass
class Rule:
    type: str
    provider: str = ""
    device: str = ""
    interface: str = ""
    network: Any = None
    keyword: str = ""
    source: str = ""


@dataclass
class Classification:
    kind: str
    provider: str = ""
    reasons: list[str] = field(default_factory=list)
    typed: bool = False


def parse_hints(text: str) -> list[Rule]:
    """One rule per line, ``<match> = <type> [provider]``; ``#`` starts a comment.  match: ``DEVICE INTERFACE``, an address or subnet, or a word that
    appears in a description, a VRF name or a neighbor name.  type: mpls, internet, metro, lte (mobile) or private."""
    rules: list[Rule] = []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if "=" not in line:
            continue
        match, _, tail = line.partition("=")
        words = tail.split()
        if not words or not match.strip():
            continue
        kind = _TYPE_WORDS.get(words[0].lower().strip(",;"))
        if kind is None:
            continue
        provider = " ".join(words[1:])[:40]
        match = match.strip()
        rule = Rule(kind, provider, source=line)
        try:
            rule.network = ipaddress.ip_network(match, strict=False)
        except ValueError:
            parts = match.split()
            if len(parts) == 2 and re.search(r"\d", parts[1]):
                rule.device, rule.interface = parts[0].lower(), canon_port(parts[1])
            else:
                rule.keyword = match.lower()
        rules.append(rule)
    return rules


def _row(node: Device, interface: str) -> dict[str, Any]:
    return next((r for r in node.l3 if r["name"] == interface), {})


def _words(text: str, source: str, kinds: dict[str, str]) -> tuple[str, str, str] | None:
    """(type, provider, reason) from the first transport word in ``text``, provider words found next to it."""
    low = text.lower()
    found = ""
    for word, kind in WORD_TYPE:
        if re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", low):
            found = kind
            break
    provider = next((p for p in PROVIDERS if re.search(rf"(?<![a-z0-9]){re.escape(p)}(?![a-z0-9])", low)), "")
    if not found and not provider:
        return None
    return found or "other", provider.title() if provider else "", f"{source} '{text.strip()[:60]}'"


def classify(graph: Graph, key: str, interface: str, ip: str, hints: dict[str, Any] | None = None) -> Classification | None:
    node = graph.nodes.get(key)
    if node is None:
        return None
    row = _row(node, interface)
    rules: list[Rule] = (hints or {}).get("rules", [])
    description = str(row.get("description", "")) or node.descriptions.get(interface, "")
    vrf = str(row.get("vrf", ""))
    neighbors = [h.remote_name for h in node.halves if h.local_port == interface and h.remote_name]
    texts = [(description, "port description"), (vrf, "VRF name")] + [(n, "neighbor name") for n in neighbors]
    network = None
    try:
        network = ipaddress.ip_interface(f"{row['ip']}/{int(row['prefix_len'])}").network if row else None
        address = ipaddress.ip_address(ip) if ip else None
    except (KeyError, ValueError, TypeError):
        address = None
    found: Classification | None = None
    for rule in rules:                                                  # 1. typed by the user
        hit = ((rule.device and rule.interface and rule.device in (node.hostname.lower(), key.lower()) and rule.interface == canon_port(interface))
               or (rule.network is not None and ((address is not None and address in rule.network) or (network is not None and network.overlaps(rule.network))))
               or (rule.keyword and any(rule.keyword in t.lower() for t, _ in texts if t)))
        if hit:
            if found is None:
                found = Classification(rule.type, rule.provider, [f"hint typed by you: {rule.source}"], True)
            elif rule.type == found.kind:
                found.provider = found.provider or rule.provider
    if found:
        return found
    for text, source in texts:                                          # 2. words in the capture
        hit = _words(text, source, {}) if text else None
        if hit:
            found = Classification(hit[0], hit[1], [hit[2]])
            break
    colour = str((node.l3facts.get("wan_colour") or {}).get(interface, ""))
    if colour:                                                          # 3. SD-WAN colour of the tunnel interface on this port
        kind = COLOUR_TYPE.get(colour, "other")
        reason = f"SD-WAN colour {colour} on {interface}"
        if found is None:
            found = Classification(kind, "", [reason])
        elif found.kind == kind or found.kind == "other":
            found.kind = kind if found.kind == "other" else found.kind
            found.reasons.append(reason)
        else:
            found.reasons.append(f"{reason} (disagrees with the description: {TYPE_LABEL[found.kind]} vs {TYPE_LABEL[kind]})")
    return found


def cloud_node(graph: Graph, node: str, interface: str, ip: str, hints: dict[str, Any] | None = None, peer: bool = False) -> tuple[Device, list[str]]:
    """The node an uncaptured next hop or provider is drawn as, and the sentences that say why it is that."""
    found = classify(graph, node, interface, ip, hints)
    if found is None:
        label = f"Tunnel peer {ip}" if peer else f"Gateway {ip}"
        return Device(key=f"GW:{ip}", hostname=label, captured=False, role_hint="cloud", model="not captured", mgmt_ip=ip), []
    name = TYPE_LABEL.get(found.kind, "WAN")
    title = f"{name} · {found.provider}" if found.provider else name
    return Device(key=f"CLOUD:{found.kind}:{found.provider.lower()}", hostname=title, captured=False, role_hint="cloud",
                  model="", mgmt_ip=""), [f"{node} {interface} faces {title}: " + "; ".join(found.reasons)]
