"""Aruba AOS-CX Virtual Switching Extension (VSX): two switches that run as one for the cables below them, read from the configuration and from ``show vsx status``.

VSX is the Aruba CX counterpart of Cisco vPC and Huawei M-LAG: each switch keeps its own control plane, the two are joined by an *inter-switch link* (ISL, a LAG), a separate
*keepalive* path tells each one that the other is alive, and a LAG that is multi-chassis (``interface lag 10 multi-chassis``) can have members on both switches.  The running configuration says
it in five lines::

    vsx
        system-mac 02:00:00:00:10:01             <- the same on both members: the identity of the pair (the "domain")
        inter-switch-link lag 256                  <- the ISL: the peer-link of the pair
        role primary                               <- primary on one member, secondary on the other
        keepalive peer 172.16.104.25 source 172.16.104.24 vrf mgmt
    interface lag 255 multi-chassis                <- a multi-chassis LAG (the "vPC number" is the LAG number)

``show vsx status`` adds the state: ``ISL channel`` and ``Config Sync Status`` (both ``In-Sync`` when healthy) and, in ``show vsx status keepalive``, ``Keepalive State``.  Keystone fills the
same fields as for vPC and M-LAG (``vpc_domain``, ``vpc_peer_link``, ``vpc_keepalive`` ...) so that the pair is drawn as one frame, the peer-link is confirmed or inferred, and the
vPC findings apply to it.

HPE Aruba Networking, VSX in the AOS-CX validated solution guide: https://arubanetworking.hpe.com/techdocs/VSG/docs/050-dc-deploy/esp-dc-deploy-540-central-two-tier-access/
"""

from __future__ import annotations

import re


_BLOCK = re.compile(r"^vsx[ \t]*$\n((?:[ \t]+.*\n?)*)", re.I | re.M)
_MAC = re.compile(r"^\s*system-mac\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*$", re.I)
_ISL = re.compile(r"^\s*inter-switch-link\s+lag\s+(\d+)\s*$", re.I)
_ROLE = re.compile(r"^\s*role\s+(primary|secondary)\s*$", re.I)
_KEEPALIVE = re.compile(r"^\s*keepalive\s+peer\s+(\S+)(?:\s+source\s+(\S+))?(?:\s+vrf\s+(\S+))?", re.I)
_MULTI = re.compile(r"^interface\s+lag\s+(\d+)\s+multi-chassis\s*$", re.I | re.M)
_STATE = re.compile(r"^\s*(ISL channel|ISL mgmt channel|Config Sync Status|Keepalive State)\s*:\s*(\S.*?)\s*$", re.I | re.M)
_ROLE_ROW = re.compile(r"^\s*Device Role\s+(primary|secondary)\s+(primary|secondary)?", re.I | re.M)


def read(text: str) -> dict:
    """``{"system_mac", "isl", "role", "peer", "source", "vrf", "multi_chassis": [lag numbers], "state": {...}}``; empty values when the capture has no VSX."""
    found: dict = {"system_mac": "", "isl": "", "role": "", "peer": "", "source": "", "vrf": "", "multi_chassis": [], "state": {}}
    if not isinstance(text, str) or "vsx" not in text.lower():
        return found
    flat = text.replace("\r\n", "\n")
    block = _BLOCK.search(flat)
    if block:
        for line in block.group(1).splitlines():
            for pattern, names in ((_MAC, ("system_mac",)), (_ISL, ("isl",)), (_ROLE, ("role",)), (_KEEPALIVE, ("peer", "source", "vrf"))):
                match = pattern.match(line)
                if match:
                    for name, value in zip(names, match.groups()):
                        found[name] = (value or "").lower() if name in ("system_mac", "role") else (value or "")
    if found["system_mac"] or found["isl"]:
        found["multi_chassis"] = sorted({int(n) for n in _MULTI.findall(flat)})
        found["state"] = {key.lower(): value for key, value in _STATE.findall(flat)}
        row = _ROLE_ROW.search(flat)
        if row and not found["role"]:
            found["role"] = row.group(1).lower()
    return found


def _bundle_name(device, number: int | str) -> str:
    """The name the device's bundle table uses for ``lag <number>`` (the analyzer calls an AOS-CX LAG ``Po256``); ``Po<number>`` when the capture lists no members."""
    for name in getattr(device, "bundles", {}) or {}:
        if re.fullmatch(rf"(?i)(?:po|lag|port-channel)\s*0*{int(number)}", name):
            return name
    return f"Po{int(number)}"


def apply(device, text: str) -> bool:
    """Fill the pair fields of ``device`` (shared with vPC / M-LAG) from a VSX configuration.  Does nothing when the device already carries a vPC or M-LAG domain, or the capture has no VSX."""
    if getattr(device, "vpc_domain", ""):
        return False
    found = read(text)
    if not (found["system_mac"] and found["isl"]):
        return False
    device.vpc_domain = found["system_mac"]
    device.pair_kind = "VSX"
    device.vpc_role = found["role"]
    device.vpc_peer_link = _bundle_name(device, found["isl"])
    device.vpc_keepalive = found["peer"]
    for number in found["multi_chassis"]:
        device.vpc_ids[_bundle_name(device, number)] = str(number)
    if found["source"]:
        device.ips.add(found["source"])                      # the address the other member's keepalive points at (``pairs.config_pairs``)
    state = found["state"]
    if state:
        device.vpc_health = {"peer_status": "ok" if state.get("isl channel", "").lower() == "in-sync" else f"ISL channel {state.get('isl channel', '?')}",
                             "keepalive_status": ("alive" if "established" in state["keepalive state"].lower() else f"not alive ({state['keepalive state']})") if state.get("keepalive state") else "",
                             "consistency_status": "success" if state.get("config sync status", "").lower() == "in-sync" else (f"Config sync {state['config sync status']}" if state.get("config sync status") else ""),
                             "peer_link_status": ""}
    return True
