"""NX-OS access-list grammar -> IOS-style entries the translators already understand.

NX-OS differs from IOS in four ways that matter to a converter:

* every entry carries a sequence number (``10 permit ip any any``);
* prefixes are written in CIDR (``10.16.4.248/29``) instead of ``net wildcard``;
* ``addrgroup NAME`` / ``portgroup NAME`` refer to ``object-group ip address|port`` blocks;
* service names (``eq domain``, ``eq ntp``) are used in place of port numbers.

The converter's Huawei/Aruba translators speak the IOS dialect (``permit tcp host A 10.0.0.0 0.0.0.255 eq 443``),
so this module flattens an NX-OS entry into one or more IOS lines.  Object-groups are expanded as a cartesian product
(source x source-port x destination x destination-port), which is exactly what the switch ASIC does with them.

Cisco reference: *Cisco Nexus 9000 Series NX-OS Security Configuration Guide, Release 10.3(x)* - "Configure IP ACLs"
(https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/configuration/security/cisco-nexus-9000-nx-os-security-configuration-guide-103x/m-configuring-ip-acls.pdf).
"""
from __future__ import annotations

import ipaddress
import re
from itertools import product

# Upper bound for one NX-OS entry after object-group expansion.  Huawei CloudEngine S-series ACL capacity is a
# platform resource, so a runaway cross product is cut and flagged instead of silently emitted.
MAX_EXPANSION = 512

_SEQ = re.compile(r"^\d+\s+")
_GROUP_HEADER = re.compile(r"^object-group\s+ip\s+(address|port)\s+(\S+)\s*$", re.I)
_PORT_OPS = ("eq", "neq", "gt", "lt", "range")
_ACTIONS = ("permit", "deny")


def strip_sequence(line: str) -> str:
    return _SEQ.sub("", line.strip(), count=1)


def is_entry(line: str) -> bool:
    """True for an NX-OS ACL entry: optional sequence number, then permit/deny/remark."""
    body = strip_sequence(line)
    return body.startswith(("permit ", "deny ", "remark ", "evaluate ", "dynamic "))


def is_sequenced(line: str) -> bool:
    return bool(_SEQ.match(line.strip()))


def group_header(line: str):
    """``(kind, name)`` for an ``object-group ip address|port NAME`` line, otherwise ``None``."""
    m = _GROUP_HEADER.match(line.strip())
    return (m.group(1).lower(), m.group(2)) if m else None


def collect_groups(lines) -> dict:
    """Pre-pass over the raw configuration: ``{("address"|"port", NAME): [member, ...]}``.

    Members are kept as the text after the sequence number: ``host 10.1.1.1``, ``10.16.0.0/24``, ``eq 53``, ``range 1 9``.
    """
    groups: dict = {}
    current = None
    for raw in lines:
        text = raw.rstrip("\r\n")
        header = group_header(text)
        if header and not text[:1].isspace():
            current = header
            groups.setdefault(current, [])
            continue
        if current is None:
            continue
        if text[:1].isspace() and text.strip():
            body = strip_sequence(text)
            if body and not body.startswith(("!", "#")):
                groups[current].append(body)
            continue
        if text.strip():          # a new top-level command closes the group
            current = None
    return groups


def _cidr_to_ios(token: str):
    """``10.16.4.248/29`` -> ``10.16.4.248 0.0.0.7``; ``/32`` -> ``host``; ``/0`` -> ``any``; otherwise ``None``."""
    if "/" not in token:
        return None
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    if net.prefixlen == 0:
        return "any"
    return f"{net.network_address} {net.hostmask}"


def _endpoint(tokens: list, groups: dict):
    """Consume one address specification.  Returns ``(alternatives, rest)``; ``alternatives`` are IOS address strings."""
    if not tokens:
        return None, tokens
    head = tokens[0]
    if head == "any":
        return ["any"], tokens[1:]
    if head == "host" and len(tokens) >= 2:
        return [f"host {tokens[1]}"], tokens[2:]
    if head == "addrgroup" and len(tokens) >= 2:
        return _group_members(("address", tokens[1]), groups), tokens[2:]
    cidr = _cidr_to_ios(head)
    if cidr:
        return [cidr], tokens[1:]
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", head) and len(tokens) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[1]):
        return [f"{head} {tokens[1]}"], tokens[2:]
    return None, tokens


def _group_members(key, groups: dict):
    out = []
    for member in groups.get(key, []):
        parts = member.split()
        if not parts:
            continue
        if key[0] == "address":
            alt, rest = _endpoint(parts, groups)
            if alt and not rest:
                out.extend(alt)
        else:
            out.append(" ".join(parts))
    return out or None


def _port(tokens: list, groups: dict):
    """Consume an optional port match.  Returns ``(alternatives, rest)``; ``[""]`` means 'no port match'."""
    if tokens and tokens[0] == "portgroup" and len(tokens) >= 2:
        members = _group_members(("port", tokens[1]), groups)
        return (members if members else None), tokens[2:]
    if tokens and tokens[0] in _PORT_OPS:
        need = 3 if tokens[0] == "range" else 2
        if len(tokens) >= need:
            return [" ".join(tokens[:need])], tokens[need:]
    return [""], tokens


def expand_entry(line: str, groups: dict):
    """Flatten one NX-OS ACL entry.

    Returns ``(ios_lines, notes)``.  ``ios_lines`` is empty only for a blank entry; an entry the grammar above cannot
    read (or one that references an undefined or empty object-group) is returned unchanged, without its sequence number, so
    the translator reports it as a review item instead of losing it.  ``notes`` carries human-readable warnings.
    """
    body = strip_sequence(line)
    if not body:
        return [], []
    tokens = body.split()
    if tokens[0] not in _ACTIONS:
        return [body], []                       # remark / evaluate / dynamic pass through
    if len(tokens) < 3:
        return [body], []
    action, protocol, rest = tokens[0], tokens[1], tokens[2:]

    src, rest = _endpoint(rest, groups)
    if src is None:
        return [body], [f"unparsed source in '{body}'"]
    sport, rest = _port(rest, groups) if protocol in ("tcp", "udp") else ([""], rest)
    if sport is None:
        return [body], [f"undefined or empty port-group in '{body}'"]
    dst, rest = _endpoint(rest, groups)
    if dst is None:
        return [body], [f"unparsed destination in '{body}'"]
    dport, rest = _port(rest, groups) if protocol in ("tcp", "udp") else ([""], rest)
    if dport is None:
        return [body], [f"undefined or empty port-group in '{body}'"]

    size = len(src) * len(sport) * len(dst) * len(dport)
    notes = []
    if size > MAX_EXPANSION:
        notes.append(f"'{body}' expands to {size} rules (> {MAX_EXPANSION}); keep it as an object-group / address-set on the target")
        return [body], notes
    tail = " ".join(rest)
    out = []
    for s, sp, d, dp in product(src, sport, dst, dport):
        pieces = [action, protocol, s, sp, d, dp, tail]
        out.append(" ".join(p for p in pieces if p))
    if size > 1 and ("addrgroup" in body or "portgroup" in body):
        notes.append(f"'{body}' expanded to {size} rules from object-groups")
    return out, notes
