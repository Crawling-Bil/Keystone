"""ACL helpers shared by the switch translators (IOS-dialect entries in, vendor syntax out)."""
from __future__ import annotations

import ipaddress
import re

# IANA service names accepted after eq/gt/lt/range by Cisco IOS / NX-OS, written as numbers so no translator depends on a
# target-vendor keyword table.
PORT_NAMES = {
    "ftp-data": "20", "ftp": "21", "ssh": "22", "telnet": "23", "smtp": "25", "tacacs": "49", "domain": "53",
    "bootps": "67", "bootpc": "68", "tftp": "69", "www": "80", "http": "80", "pop3": "110", "sunrpc": "111",
    "nntp": "119", "ntp": "123", "netbios-ns": "137", "netbios-dgm": "138", "netbios-ssn": "139", "imap": "143",
    "snmp": "161", "snmptrap": "162", "bgp": "179", "ldap": "389", "https": "443", "smtps": "465", "syslog": "514",
    "ldaps": "636", "imaps": "993", "pop3s": "995",
}

_IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def wildcard_to_prefix(wildcard: str):
    """``0.0.0.255`` -> ``24``.  ``None`` when the wildcard is not a contiguous host-bit run (not expressible as a prefix)."""
    try:
        value = int(ipaddress.IPv4Address(wildcard))
    except ValueError:
        return None
    inverted = value ^ 0xFFFFFFFF
    bits = f"{inverted:032b}"          # the netmask; a valid one is a run of ones followed by zeros
    if "01" in bits:
        return None
    return bits.count("1")


def parse_endpoint(tokens: list):
    """Consume one IOS-dialect address spec.  Returns ``(kind, value, rest)`` with kind ``any|prefix`` or ``(None, None, tokens)``.

    ``value`` is ``"A.B.C.D/len"`` for a prefix.
    """
    if not tokens:
        return None, None, tokens
    head = tokens[0]
    if head == "any":
        return "any", "any", tokens[1:]
    if head == "host" and len(tokens) >= 2 and _IPV4.match(tokens[1]):
        return "prefix", f"{tokens[1]}/32", tokens[2:]
    if _IPV4.match(head) and len(tokens) >= 2 and _IPV4.match(tokens[1]):
        length = wildcard_to_prefix(tokens[1])
        if length is None:
            return None, None, tokens
        net = ipaddress.ip_network(f"{head}/{length}", strict=False)
        return "prefix", f"{net.network_address}/{length}", tokens[2:]
    return None, None, tokens


def parse_port(tokens: list):
    """Consume an optional ``eq|neq|gt|lt|range`` match.  Returns ``((op, values) or None, rest)``."""
    if tokens and tokens[0] in ("eq", "neq", "gt", "lt", "range"):
        need = 3 if tokens[0] == "range" else 2
        if len(tokens) >= need:
            return (tokens[0], [PORT_NAMES.get(t, t) for t in tokens[1:need]]), tokens[need:]
    return None, tokens
