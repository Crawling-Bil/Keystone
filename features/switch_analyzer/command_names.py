"""Expand abbreviated Cisco-style ``show`` commands to their full spelling.

IOS, IOS-XE and NX-OS accept any unique prefix of a keyword, so engineers (and collection scripts) type ``show inven``, ``sh ver``,
``show cdp neig detail`` or ``show inter transceiver``.  The parsers look a command up by its full name; keeping a list of every
abbreviation in every parser does not scale (``show cdp neig detail`` was in none of them, so all CDP detail data was lost on 24
of 24 OJK captures).  This module rewrites the *command echo line* of a capture once, before any parser runs:

    JKT-A02-LAN-SW-1#show cdp neig detail   ->   JKT-A02-LAN-SW-1#show cdp neighbors detail

Rules, chosen so a wrong rewrite is impossible rather than unlikely:

* Only a keyword that is a unique prefix of exactly one keyword known at that level is expanded.  An exact keyword always wins.
* Expansion stops at the first word that is not a known keyword (an interface name, a VLAN id, ``| include``); the rest is kept verbatim.
* ``sh`` becomes ``show``.  ``display`` (Huawei) and every line that is not a command echo are left alone.
* The keyword tree is a list of commands the analyzer (or a collect list) uses; a keyword it does not know is never touched.

Reference: Cisco IOS XE command-line interface help and abbreviation behaviour,
https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/configuration/xe-16/fundamentals-xe-16-book/cf-cli-basics.html
"""
from __future__ import annotations

import re

from . import capture_text

_TREE_SPEC: dict[str, object] = {
    "version": {}, "inventory": {"raw": {}}, "running-config": {"all": {}, "interface": {}}, "startup-config": {},
    "clock": {}, "users": {}, "history": {}, "whoami": {}, "tech-support": {},
    "interfaces": {"status": {}, "description": {}, "trunk": {}, "transceiver": {"detail": {}}, "counters": {"errors": {}}, "switchport": {},
                   "summary": {}, "capabilities": {}},
    "ip": {"arp": {"summary": {}}, "route": {"summary": {}, "connected": {}, "static": {}, "ospf": {}, "bgp": {}, "eigrp": {}},
           "interface": {"brief": {}}, "ospf": {"neighbor": {"detail": {}}, "interface": {"brief": {}}, "database": {}, "border-routers": {}},
           "bgp": {"summary": {}, "neighbors": {}}, "eigrp": {"neighbors": {}, "interfaces": {}}, "dhcp": {"snooping": {}, "binding": {}, "pool": {}},
           "cef": {}, "vrf": {"brief": {}}, "protocols": {}, "sla": {"configuration": {}, "statistics": {}, "summary": {}},
           "igmp": {"snooping": {}, "groups": {}}, "pim": {"neighbor": {}}, "mroute": {}, "access-lists": {}, "nat": {"translations": {}, "statistics": {}},
           "ssh": {}, "verify": {}, "traffic": {}, "route-map": {}, "prefix-list": {}, "source": {}, "helper-address": {}, "default-gateway": {}},
    "cdp": {"neighbors": {"detail": {}}, "interface": {}, "traffic": {}, "entry": {}},
    "lldp": {"neighbors": {"detail": {}}, "interface": {}, "traffic": {}, "entry": {}},
    "etherchannel": {"summary": {}, "detail": {}, "port-channel": {}, "load-balance": {}},
    "port-channel": {"summary": {}},
    "vlan": {"brief": {}, "summary": {}, "id": {}, "name": {}},
    "spanning-tree": {"summary": {}, "detail": {}, "vlan": {}, "root": {}, "blockedports": {}, "inconsistentports": {}, "interface": {}, "mst": {}, "bridge": {}},
    "mac": {"address-table": {"count": {}, "dynamic": {}, "static": {}, "aging-time": {}, "vlan": {}, "interface": {}}},
    "mac-address-table": {"count": {}, "dynamic": {}, "static": {}, "aging-time": {}},
    "license": {"summary": {}, "usage": {}, "all": {}, "status": {}, "udi": {}, "feature": {}, "brief": {}},
    "redundancy": {"states": {}, "history": {}, "switchover": {"history": {}}, "inter-device": {}, "config-sync": {}, "clients": {}, "counters": {}},
    "logging": {"onboard": {}, "history": {}, "summary": {}},
    "environment": {"all": {}, "power": {}, "temperature": {}, "fan": {}, "led": {}},
    "power": {"inline": {"detail": {}}, "redundancy": {}},
    "switch": {"detail": {}, "stack-ports": {"summary": {}}, "stack-mode": {}},
    "module": {}, "platform": {"software": {}, "hardware": {}, "resources": {}}, "stack-power": {"detail": {}, "summary": {}},
    "processes": {"cpu": {"sorted": {}, "history": {}}, "memory": {}}, "memory": {"statistics": {}, "summary": {}},
    "vtp": {"status": {}, "counters": {}, "password": {}}, "lacp": {"neighbor": {}, "counters": {}, "internal": {}, "sys-id": {}},
    "vpc": {"brief": {}, "consistency-parameters": {}, "peer-keepalive": {}, "role": {}},
    "standby": {"brief": {}}, "vrrp": {"brief": {}}, "hsrp": {"brief": {}}, "glbp": {"brief": {}},
    "access-lists": {}, "snmp": {"user": {}, "community": {}, "group": {}}, "ntp": {"status": {}, "associations": {}}, "aaa": {"servers": {}, "sessions": {}},
    "boot": {}, "flash": {}, "file": {"systems": {}}, "track": {}, "monitor": {"session": {}}, "errdisable": {"recovery": {}, "detect": {}}, "diagnostic": {"result": {}}, "mls": {"qos": {}}, "ipv6": {"interface": {}, "route": {}, "neighbors": {}}, "sdm": {"prefer": {}}, "udld": {}, "storm-control": {}, "authentication": {"sessions": {}}, "dot1x": {"all": {}}, "vrf": {}, "feature": {}, "system": {"resources": {}, "uptime": {}}, "cores": {}, "install": {"summary": {}, "active": {}, "inactive": {}, "committed": {}}, "romvar": {}, "terminal": {}, "privilege": {}, "line": {}, "controllers": {}, "wireless": {}, "ap": {}, "event": {"manager": {}},
}

_TREE_SPEC["interface"] = _TREE_SPEC["interfaces"]   # AOS-CX and NX-OS spell it in the singular; both are real
_BARE_SHOW = re.compile(r"^(sh(?:ow)?)(\s+)(.*)$", re.IGNORECASE)


def _resolve(token: str, children: dict[str, object]) -> str | None:
    """The keyword ``token`` stands for at this level: itself when exact, the only keyword it is a prefix of, else None."""
    low = token.lower()
    if low in children:
        return low
    hits = [word for word in children if word.startswith(low)]
    if len(hits) == 2 and sorted(hits, key=len)[1] == sorted(hits, key=len)[0] + "s":   # interface / interfaces: the shorter, both are accepted
        return min(hits, key=len)
    return hits[0] if len(hits) == 1 else None


def expand(command: str) -> str:
    """``command`` (``show ...`` without prompt) with every abbreviated keyword spelled out; unknown parts are kept as typed."""
    match = _BARE_SHOW.match(command.strip())
    if not match:
        return command
    words = match.group(3).split()
    out = ["show"]
    level: dict[str, object] | None = _TREE_SPEC
    for position, token in enumerate(words):
        word = _resolve(token, level) if level and not token.startswith(("|", "<", "?")) else None
        if word is None:
            out.extend(words[position:])
            break
        out.append(word)
        level = level[word]   # type: ignore[assignment]
    return " ".join(out)


def _expand_echo(line: str) -> str:
    """Rewrite one command echo line (``HOST#sh inven``, ``HOST# show ver  <glued output>``); any other line is returned unchanged."""
    if not line or len(line) > 200:
        return line
    stripped = line.strip()
    parsed = capture_text.split_prompt(stripped)
    prompt, rest = (parsed if parsed else ("", stripped))
    if not rest or not _BARE_SHOW.match(rest):
        return line
    glued = re.match(r"^(.*?\S)(\s{2,}\S.*)$", rest)
    head, tail = (glued.group(1), glued.group(2)) if glued else (rest, "")
    expanded = expand(head)
    if expanded == re.sub(r"\s+", " ", head.strip()):
        return line
    gap = stripped[len(prompt):len(stripped) - len(stripped[len(prompt):].lstrip())]
    return f"{prompt}{gap}{expanded}{tail}"


def expand_lines(lines: list[str]) -> list[str]:
    """``lines`` with every abbreviated ``show`` command echo spelled out (content lines are never touched)."""
    return [_expand_echo(line) for line in lines]
