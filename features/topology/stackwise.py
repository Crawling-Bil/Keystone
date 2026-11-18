"""Cisco StackWise Virtual (SVL): two Catalyst 9000 chassis that run as one switch, read from the configuration.

An SVL is one node in the picture (one hostname, one control plane), so there is nothing to frame; what the engineer needs to see is that the node *is* an SVL and whether the
pair is protected against a split.  Three lines of the running configuration say it::

    stackwise-virtual
     domain 1                                   <- the SVL domain (both chassis must agree)
    interface HundredGigE1/0/51
     stackwise-virtual link 1                    <- a StackWise Virtual Link (SVL): the cable between the two chassis
    interface TwentyFiveGigE1/0/48
     stackwise-virtual dual-active-detection     <- a dual-active-detection (DAD) link: a second path that tells each chassis the other one is alive

If every SVL goes down and nothing else tells the standby chassis that the active one lives, both become active with the same addresses (dual-active, split brain).  DAD is the
protection; Cisco recommends a DAD link in addition to the SVLs.  ``read`` returns the facts, ``findings.py`` turns missing protection into TOPO-057.

Cisco, Troubleshoot SVL on Catalyst 9000 Switch: https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9500-series-switches/216537-troubleshoot-svl-on-catalyst-9000-switch.html
"""

from __future__ import annotations

import re

from .names import canon_port

_DOMAIN = re.compile(r"^stackwise-virtual\s*$\n(?:[ \t]+.*\n)*?[ \t]+domain\s+(\d+)\s*$", re.I | re.M)
_INTERFACE = re.compile(r"^interface\s+(\S+)\s*$", re.I)
_SVL = re.compile(r"^\s+stackwise-virtual\s+link\s+(\d+)\s*$", re.I)
_DAD = re.compile(r"^\s+stackwise-virtual\s+dual-active-detection\s*$", re.I)


def read(text: str) -> dict:
    """``{"domain": "1", "links": {port: link number}, "dad": [ports]}``; empty strings and containers when the configuration has no StackWise Virtual."""
    found = {"domain": "", "links": {}, "dad": []}
    if not isinstance(text, str) or "stackwise-virtual" not in text.lower():
        return found
    domain = _DOMAIN.search(text.replace("\r\n", "\n"))
    if domain:
        found["domain"] = domain.group(1)
    port = ""
    for line in text.splitlines():
        head = _INTERFACE.match(line.strip("\r")) if not line[:1].isspace() else None
        if head:
            port = canon_port(head.group(1))
            continue
        if line and not line[:1].isspace() and not line.startswith("!"):
            port = ""
            continue
        if port and _SVL.match(line):
            found["links"][port] = _SVL.match(line).group(1)
        elif port and _DAD.match(line) and port not in found["dad"]:         # a capture can hold the configuration twice (running-config and a tech-support part)
            found["dad"].append(port)
    return found
