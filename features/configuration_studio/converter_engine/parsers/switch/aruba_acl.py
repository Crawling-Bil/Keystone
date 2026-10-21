"""AOS-CX ``access-list ip`` blocks and ``object-group ip address`` groups -> the IOS-style entries the translators read.

A running-config of an Aruba CX switch writes an ACL like this::

    object-group ip address BR_ATM
        10 172.18.18.224/255.255.255.240
    access-list ip 130_STUN_SENAYAN_IN
        10 permit any BR_STUN_SENAYAN ALL_DC_DRC log count
        20 permit any 172.17.254.144 any

The Huawei and Aruba translators speak the IOS dialect (``ip access-list extended NAME`` / ``permit ip A B``), so this module
flattens each entry, expanding object-groups as a cartesian product exactly like the NX-OS path in ``nxos_acl.py`` (same limit,
same note for an over-large expansion, which is kept verbatim so the translator flags it).

What is read: ``any`` or a protocol word / number, a source and a destination that are ``any``, ``A.B.C.D``, ``A.B.C.D/len``,
``A.B.C.D/mask`` or an object-group name (bare, or after ``group``), optional ``eq|neq|gt|lt|range`` ports for tcp/udp, and the
trailing words ``log`` (kept) and ``count`` (dropped: a hit counter has no VRP rule keyword). Anything else is left untouched.
"""
from __future__ import annotations

import ipaddress
import re

from . import nxos_acl

_HEADER = re.compile(r"^access-list\s+ip\s+(\S+)\s*$", re.I)
_GROUP = re.compile(r"^object-group\s+ip\s+(address|port)\s+(\S+)\s*$", re.I)
_PORT_OPS = ("eq", "neq", "gt", "lt", "range")
_DROP_TAIL = {"count"}
_PROTOCOLS = {"any": "ip", "ip": "ip", "tcp": "tcp", "udp": "udp", "icmp": "icmp", "igmp": "igmp", "gre": "gre", "esp": "esp", "ahp": "ahp", "ospf": "ospf", "pim": "pim", "sctp": "sctp", "vrrp": "vrrp"}


def group_header(line: str):
    found = _GROUP.match(line.strip())
    return (found.group(1).lower(), found.group(2)) if found else None


def _cidr(token: str):
    """``A.B.C.D`` -> ``host A.B.C.D``; ``A.B.C.D/len`` or ``A.B.C.D/mask`` -> ``A.B.C.D/len``; ``None`` when it is neither."""
    if "/" not in token:
        try:
            ipaddress.IPv4Address(token)
        except ValueError:
            return None
        return f"host {token}"
    base, _, tail = token.partition("/")
    try:
        ipaddress.IPv4Address(base)
        if "." in tail:
            length = ipaddress.IPv4Network(f"0.0.0.0/{tail}").prefixlen
        else:
            length = int(tail)
            if not 0 <= length <= 32:
                return None
    except ValueError:
        return None
    return f"{base}/{length}"


def collect_groups(blocks: dict) -> dict:
    """``{("address", NAME): [members]}`` in the NX-OS member notation, from ``{("address", NAME): ["10 10.1.1.1", ...]}``."""
    groups: dict = {}
    for key, rows in blocks.items():
        members = []
        for row in rows:
            tokens = row.split()
            if tokens and tokens[0].isdigit():
                tokens = tokens[1:]
            if not tokens:
                continue
            if key[0] == "address":
                value = _cidr(tokens[0])
                if value:
                    members.append(value)
            else:
                members.append(" ".join(tokens))
        groups[key] = members
    return groups


def _endpoint(tokens: list, names: set):
    """Consume one address spec; returns ``(nxos_text, rest)`` or ``(None, tokens)``."""
    if not tokens:
        return None, tokens
    head = tokens[0]
    if head.lower() == "any":
        return "any", tokens[1:]
    if head.lower() == "group" and len(tokens) >= 2:
        return f"addrgroup {tokens[1]}", tokens[2:]
    if head in names:
        return f"addrgroup {head}", tokens[1:]
    value = _cidr(head)
    return (value, tokens[1:]) if value else (None, tokens)


def _port(tokens: list):
    if tokens and tokens[0] in _PORT_OPS:
        need = 3 if tokens[0] == "range" else 2
        if len(tokens) >= need:
            return " ".join(tokens[:need]), tokens[need:]
    return "", tokens


def convert_entry(line: str, groups: dict):
    """One AOS-CX ACL entry -> ``(ios_lines, notes)``; an unreadable entry comes back unchanged."""
    tokens = nxos_acl.strip_sequence(line).split()
    if not tokens:
        return [], []
    if tokens[0].lower() == "remark" or tokens[0].lower() not in ("permit", "deny"):
        return [" ".join(tokens)], []
    action, rest = tokens[0].lower(), tokens[1:]
    if not rest:
        return [" ".join(tokens)], []
    protocol = _PROTOCOLS.get(rest[0].lower())
    if protocol is None:
        if rest[0].isdigit():
            protocol = rest[0]
        else:
            return [" ".join(tokens)], [f"unknown protocol in '{' '.join(tokens)}'"]
    rest = rest[1:]
    names = {name for (kind, name) in groups if kind == "address"}
    src, rest = _endpoint(rest, names)
    if src is None:
        return [" ".join(tokens)], [f"unparsed source in '{' '.join(tokens)}'"]
    sport, rest = _port(rest) if protocol in ("tcp", "udp") else ("", rest)
    dst, rest = _endpoint(rest, names)
    if dst is None:
        return [" ".join(tokens)], [f"unparsed destination in '{' '.join(tokens)}'"]
    dport, rest = _port(rest) if protocol in ("tcp", "udp") else ("", rest)
    tail = [word for word in rest if word.lower() not in _DROP_TAIL]
    nxos = " ".join(part for part in (action, protocol, src, sport, dst, dport, " ".join(tail)) if part)
    return nxos_acl.expand_entry(nxos, groups)


def convert(commands: list, group_blocks: dict) -> tuple[list, list]:
    """The ``acl_commands`` of an AOS-CX file in IOS dialect.  Lines that are already IOS-style (ArubaOS-Switch) pass through."""
    groups = collect_groups(group_blocks)
    out: list = []
    notes: list = []
    inside = False
    for command in commands:
        header = _HEADER.match(command.strip())
        if header:
            out.append(f"ip access-list extended {header.group(1)}")
            inside = True
            continue
        if command.startswith(("ip access-list ", "ipv6 access-list ")):
            inside = False
            out.append(command)
            continue
        if inside:
            lines, found = convert_entry(command, groups)
            out.extend(lines)
            notes.extend(found)
            continue
        out.append(command)
    return out, notes
