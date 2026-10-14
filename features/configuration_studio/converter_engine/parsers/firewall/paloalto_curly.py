"""PAN-OS CLI capture -> the XML tree that ``PaloAltoXmlConfigParser`` already reads.

``show config running`` in the PAN-OS CLI prints the configuration in the curly-brace view::

    config {
      devices { localhost.localdomain { vsys { vsys1 { rulebase { security { rules {
        Allow-DNS { from trust; to untrust; source [ A B ]; action allow; } } } } } } } }
    }

Most admins capture exactly this (PuTTY/SecureCRT log) together with ``show system info``.  The view carries the same
information as the XML export but drops the two things that make XML self-describing: ``<entry name="x">`` becomes a bare
block ``x { }``, and a one-member ``<member>`` list is printed as a plain ``key value;``.  This module rebuilds both:

* **list vs value** - ``key [ a b ];`` becomes ``<key><member>a</member>...``; a single value stays ``<key>v</key>`` and the XML
  parser's ``_members`` accepts a plain value as a one-member list.
* **entry vs container** - decided by the parent element: children of a *collection* tag (``rules``, ``address``, ``zone``,
  ``ethernet``, ``users``, ``static-route``...) are entries; a few tags are used both ways (``ip``, ``vlan``, ``profiles``,
  ``interface``) and are resolved by the child's name.  The tables below were derived from real exports and checked by
  converting a capture of a firewall and comparing the tree with that firewall's own XML export.  A block under a collection
  tag that is not listed is treated as a container, so an unknown collection is simply not read (never mis-read).

``show system info`` (model, serial, software version, advanced-routing flag...) is returned separately because no
configuration format carries it.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from features.configuration_studio.converter_engine.parsers.firewall.paloalto_operational import (
    PaloAltoOperationalCaptureParser,
    _clean_putty_capture,
    _parse_kv_section,
)

# Tags whose child blocks are <entry name="..."> (PAN-OS schema; first block derived from real exports).
ENTRY_PARENTS = frozenset("""
CA address address-group application application-filter application-group application-status area authentication-profile
authentication-sequence certificate certificate-profile class custom-url-category decoder device-group devices
dynamic-user-group edl email external-list file-size-limit gateway global-protect-app-crypto-profiles ike-crypto-profiles
ike-gateway interface-management-profile ipsec ipsec-crypto-profiles kerberos ldap link-group logical-router match-list
monitor-destinations monitor-profile netflow peer peer-group permitted-ip profile profile-group proxy-id radius region
redistribution-profile redist-profile reserved rules saml-idp scan schedule server-profiles service service-group shared-gateway snmp-trap ssl-tls-service-profile
static-route static-route-v6 syslog tacplus tag template template-stack units url-filtering users view views virtual-router
virtual-wire vrf vsys vulnerability virus spyware zone zone-protection-profile aggregate-ethernet ethernet
""".split())

# Tags used both for entries and for fixed sub-sections: name -> child names that are sub-sections (the rest are entries).
MIXED = {
    "ip": {"static-route", "static-route-v6", "bgp", "ospf", "rip"},
    "vlan": {"units"},
    "interface": {"ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan", "ha", "tap", "decrypt-mirror", "sdwan", "virtual-wire"},
    "profiles": {"virus", "spyware", "vulnerability", "url-filtering", "file-blocking", "wildfire-analysis", "data-filtering", "custom-url-category",
                 "decryption", "custom-spyware-signature", "custom-vulnerability-signature", "dos-protection", "interface-management-profile",
                 "zone-protection-profile", "monitor-profile", "bfd", "qos-profile", "lldp-profile", "sdwan-interface-profile", "sdwan-path-quality",
                 "sdwan-saas-quality", "sdwan-error-correction", "sdwan-traffic-distribution", "hip-objects", "gtp", "sctp", "mobile-network-profile"},
    "server": {"option", "lease", "inheritance", "reserved"},     # dhcp server: fixed sub-sections; syslog/ldap servers: entries
}
# A bare "name;" under these tags is an empty entry; under any other tag it is a flag.
EMPTY_ENTRY_PARENTS = ENTRY_PARENTS - {"profile"}


# ----------------------------------------------------------------------------- scanner / tree
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_TOKEN = re.compile(r'\s*(?:(?P<q>"(?:[^"\\]|\\.)*")|(?P<p>[{};\[\]])|(?P<w>[^\s{};\[\]"]+))')


@dataclass
class _Node:
    name: str
    block: bool = False
    value: str = ""
    items: list[str] | None = None
    children: list["_Node"] = field(default_factory=list)
    uuid: str = ""


def _unquote(text: str) -> str:
    return text[1:-1].replace('\\"', '"').replace("\\\\", "\\") if len(text) >= 2 and text[0] == '"' and text[-1] == '"' else text


def _tokens(text: str):
    pos = 0
    while True:
        match = _TOKEN.match(text, pos)
        if not match:
            return
        pos = match.end()
        if match.group("q") is not None:
            yield "w", _unquote(match.group("q"))
        elif match.group("p") is not None:
            yield "p", match.group("p")
        else:
            yield "w", match.group("w")


def _parse(it, depth: int = 0) -> list[_Node]:
    if depth > 60:
        raise ValueError("PAN-OS configuration is nested too deeply")
    nodes: list[_Node] = []
    words: list[str] = []
    items: list[str] | None = None

    def flush() -> None:
        nonlocal words, items
        if words:
            nodes.append(_Node(name=words[0], value=" ".join(words[1:]), items=items))
        words, items = [], None

    for kind, value in it:
        if kind == "w":
            words.append(value)
        elif value == "{":
            node = _Node(name=" ".join(words), block=True)
            if len(words) > 1 and _UUID.fullmatch(words[-1]):          # rules print as "name uuid { ... }"
                node.name, node.uuid = " ".join(words[:-1]), words[-1]
            words, items = [], None
            node.children = _parse(it, depth + 1)
            nodes.append(node)
        elif value == "}":
            flush()
            return nodes
        elif value == ";":
            flush()
        elif value == "[":
            items = []
            for kind2, value2 in it:
                if kind2 == "p" and value2 == "]":
                    break
                items.append(value2)
    flush()
    return nodes


def _is_entry(parent_tag: str, name: str, block: bool) -> bool:
    if parent_tag in MIXED:
        return name not in MIXED[parent_tag]
    return parent_tag in (ENTRY_PARENTS if block else EMPTY_ENTRY_PARENTS)


def _safe_tag(name: str) -> str:
    """A name that is not a valid XML tag (it is an unlisted collection's entry, e.g. ``10.1.1.0/24``) is kept readable and valid."""
    if re.match(r"^[A-Za-z_][A-Za-z0-9_.-]*$", name):
        return name
    return "x_" + re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def _build(nodes: list[_Node], parent: ET.Element, parent_tag: str) -> None:
    for node in nodes:
        if _is_entry(parent_tag, node.name, node.block) and node.items is None and not node.value:
            element = ET.SubElement(parent, "entry", {"name": node.name, **({"uuid": node.uuid} if node.uuid else {})})
            _build(node.children, element, "entry")
            continue
        element = ET.SubElement(parent, _safe_tag(node.name))
        if node.block:
            _build(node.children, element, node.name)
        elif node.items is not None:
            for item in node.items:
                ET.SubElement(element, "member").text = item
        elif node.value:
            element.text = node.value


# ----------------------------------------------------------------------------- capture handling
_CONFIG_START = re.compile(r"(?m)^[ \t]*config[ \t]*\{[ \t]*$")
_TOP_LEVEL = re.compile(r"\s*(?:version\b|mgt-config\b|shared\b|devices\b|deviceconfig\b|network\b|vsys\b|panorama\b)")


@dataclass
class CurlyCapture:
    xml: str
    system_info: dict[str, str]
    prompt_host: str
    lines: int


def _config_block(cleaned: str) -> str | None:
    for start in _CONFIG_START.finditer(cleaned):
        tail = cleaned[start.end():start.end() + 400]
        if _TOP_LEVEL.match(tail):
            begin = start.end()
            depth, in_quote, i = 1, False, begin
            while i < len(cleaned) and depth:
                ch = cleaned[i]
                if in_quote:
                    if ch == "\\":
                        i += 1
                    elif ch == '"':
                        in_quote = False
                elif ch == '"':
                    in_quote = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                i += 1
            return cleaned[begin:i - 1] if depth == 0 else cleaned[begin:]
    return None


def looks_like_curly(raw_text: str) -> bool:
    stripped = raw_text.lstrip("﻿ \t\r\n")
    if stripped.startswith(("<?xml", "<config", "set ")):
        return False
    return _config_block(_clean_putty_capture(raw_text[:6_000_000])) is not None


def convert(raw_text: str) -> CurlyCapture:
    """Cleaned capture -> ``CurlyCapture``.  Raises ``ValueError`` when no ``config { ... }`` block is present."""
    cleaned = _clean_putty_capture(raw_text.lstrip("﻿"))
    body = _config_block(cleaned)
    if body is None:
        raise ValueError("No 'config { ... }' block found - capture the output of 'show config running'.")
    root = ET.Element("config")
    _build(_parse(_tokens(body)), root, "config")
    info = _parse_kv_section(PaloAltoOperationalCaptureParser._split_into_sections(cleaned).get("system info", []))
    if info.get("sw-version"):
        root.set("version", ".".join(re.match(r"(\d+)\.(\d+)", info["sw-version"]).groups() + ("0",)) if re.match(r"(\d+)\.(\d+)", info["sw-version"]) else "")
    host = re.search(r"(?m)^\S+@(\S+?)[>#]", cleaned)
    return CurlyCapture(xml=ET.tostring(root, encoding="unicode"), system_info=info, prompt_host=host.group(1) if host else "", lines=cleaned.count("\n") + 1)
