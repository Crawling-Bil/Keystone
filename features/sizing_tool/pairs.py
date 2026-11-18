"""Which two captured devices are one redundant pair, read from what their configurations say about each other (never from the hostname).

A hostname that ends in 1 / 2 or A / B is a convention, not evidence: two unrelated sites share it, and a pair is often named by two different people.  What a
configuration holds is a **peer address** (the keep-alive or heartbeat destination) and the device's **own addresses**.  Two captures are the two members of one pair when each
names an address of the other, and they agree on what the vendor needs identical on both members (the domain or group number).  Where a technology does not print a peer
address (FortiGate, F5, Cisco ASA) the group name / device list / failover link addresses play that part.  A capture of show commands only (no ``vpc domain`` line) is paired by
the domain number, the model and the CDP / LLDP tables: each lists the other.

Documentation (the pages that describe the commands read here):

* vPC, NX-OS: https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.pdf  (``vpc domain N``, ``peer-keepalive destination P source S``)
* VSX, Aruba AOS-CX: https://arubanetworking.hpe.com/techdocs/new-central/content/get-started/cx-alias-vsx-cfg.htm  (``vsx`` ... ``keepalive peer P source S``)
* M-LAG, Huawei CloudEngine: https://support.huawei.com/enterprise/en/doc/EDOC1100137937/96709576/configuring-a-dfs-group  (``dfs-group N``, ``source ip S [peer P]``)
* HRP, Huawei USG: https://support.huawei.com/enterprise/en/doc/EDOC1000179232/2ff1fd4/faq-about-hot-standby-mechanisms  (``hrp interface <port> remote P``)
* HA, PAN-OS: https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/high-availability/set-up-activepassive-ha/configure-activepassive-ha  (group ID, HA1 ``peer-ip``)
* HA, FortiGate (FGCP): https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/62403/fgcp  (``config system ha``: ``group-name``, ``group-id``, ``mode``)
* Failover, Cisco ASA: https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/general/asa-920-general-config/ha-failover.html  (``failover lan unit``, ``failover interface ip ... standby``)
* Device service clustering, F5 BIG-IP: https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/big-ip-device-service-clustering-administration-14-1-0/01.html  (sync-failover device group and its devices)
* HA SSO, Cisco Catalyst 9800: https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/220277-configure-high-availability-sso-on-catal.html  (``chassis redundancy ha-interface ... local-ip A remote-ip B``)
* Hot standby (HSB), Huawei AC: https://support.huawei.com/enterprise/en/doc/EDOC1100096325/1a753937/vrrp-hsb-configuration  (``hsb-service``, ``local-ip A peer-ip B``)
"""

from __future__ import annotations

import re
from typing import Any

_IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
_OWN = re.compile(r"(?:ip address|ip-address|ipv4 address|set ip|<ip-address>|<ip>|\bip)\s+" + _IPV4 + r"(?!\d)", re.I)
_SKIP_SELF = {"0.0.0.0", "255.255.255.255"}
KIND_DEVICE_TYPES = ("switch", "router", "firewall", "load_balancer", "wlc")


def _first(pattern: str, text: str, flags: int = re.I | re.M) -> re.Match[str] | None:
    return re.search(pattern, text, flags)


def _own_addresses(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for match in _OWN.finditer(text):
        ip = match.group(1)
        if ip not in _SKIP_SELF and not ip.startswith("255.") and all(int(p) < 256 for p in ip.split(".")):
            seen[ip] = None
        if len(seen) >= 60:
            break
    return list(seen)


def _neighbours(text: str) -> list[str]:
    """Short names of what the capture's CDP / LLDP tables list: a pair shows its partner on the peer-link, whatever the hostnames look like."""
    names = re.findall(r"^\s*Device ID\s*:\s*([A-Za-z0-9_.\-]+)", text, re.I | re.M) + re.findall(r"^\s*System Name\s*:\s*([A-Za-z0-9_.\-]+)", text, re.I | re.M)
    return list(dict.fromkeys(_short(n) for n in names))[:300]


def read_facts(text: str) -> dict[str, Any] | None:
    """The pairing facts of one capture: ``{"kind", "id", "peer": [addresses], "self": [addresses], "members": [names], "unit": ""}``, or None when the capture holds none.
    Only the kinds above are read; a stack, a VSS / StackWise Virtual pair and a controller-managed AP are one asset already and need no pairing."""
    facts: dict[str, Any] | None = None
    peers: list[str] = []
    members: list[str] = []
    ident, unit = "", ""
    if _first(r"^\s*vpc domain\s+(\d+)", text) or _first(r"^\s*vPC domain id\s*:\s*(\d+)", text):
        ident = (_first(r"^\s*vpc domain\s+(\d+)", text) or _first(r"^\s*vPC domain id\s*:\s*(\d+)", text)).group(1)
        ka = _first(r"peer-keepalive\s+destination\s+" + _IPV4 + r"(?:\s+source\s+" + _IPV4 + r")?", text)
        peers = [ka.group(1)] if ka else []
        extra = [ka.group(2)] if ka and ka.group(2) else []
        facts = {"kind": "vPC", "id": ident, "peer": peers, "self": extra, "members": [], "unit": ""}
    elif _first(r"^\s*vsx\s*$", text) and _first(r"keepalive\s+peer\s+" + _IPV4, text):
        ka = _first(r"keepalive\s+peer\s+" + _IPV4 + r"(?:\s+source\s+" + _IPV4 + r")?", text)
        role = _first(r"^\s*role\s+(primary|secondary)", text)
        facts = {"kind": "VSX", "id": "", "peer": [ka.group(1)], "self": [ka.group(2)] if ka.group(2) else [], "members": [], "unit": role.group(1).lower() if role else ""}
    elif _first(r"^\s*dfs-group\s+(\d+)", text):
        ident = _first(r"^\s*dfs-group\s+(\d+)", text).group(1)
        src = _first(r"^\s*dfs-group\s+\d+\s*\n(?:.*\n){0,6}?\s*source ip\s+" + _IPV4 + r"(?:\s+vpn-instance\s+\S+)?(?:\s+peer\s+" + _IPV4 + r")?", text)
        facts = {"kind": "M-LAG", "id": ident, "peer": [src.group(2)] if src and src.group(2) else [], "self": [src.group(1)] if src else [], "members": [], "unit": ""}
    elif _first(r"^\s*hrp\s+interface\s+\S+\s+remote\s+" + _IPV4, text):
        peer = _first(r"^\s*hrp\s+interface\s+\S+\s+remote\s+" + _IPV4, text).group(1)
        facts = {"kind": "HRP", "id": "", "peer": [peer], "self": [], "members": [], "unit": ""}
    elif _first(r"(?:set\s+deviceconfig\s+high-availability|<high-availability>|^\s*high-availability\s*\{)", text) and _first(r"peer-ip", text):
        peer = _first(r"peer-ip\s*[>\s]\s*" + _IPV4, text) or _first(r"<peer-ip>\s*" + _IPV4, text)
        own = _first(r"(?:ha1\s+ip-address|<ha1>.*?<ip-address>)\s*" + _IPV4, text, re.I | re.S)
        group = _first(r"(?:group\s+group-id|<group-id>|\bgroup-id)\s*[>\s]\s*(\d+)", text)
        facts = {"kind": "PAN-OS HA", "id": group.group(1) if group else "", "peer": [peer.group(1)] if peer else [], "self": [own.group(1)] if own else [], "members": [], "unit": ""}
    elif _first(r"^\s*config system ha\b", text):
        block = text[_first(r"^\s*config system ha\b", text).end():][:3000]
        name = re.search(r"set group-name\s+\"?([^\"\n]+?)\"?\s*$", block, re.I | re.M)
        gid = re.search(r"set group-id\s+(\d+)", block, re.I)
        mode = re.search(r"set mode\s+(\S+)", block, re.I)
        if mode and mode.group(1).lower() != "standalone":
            facts = {"kind": "FortiGate HA", "id": f"{name.group(1) if name else ''}/{gid.group(1) if gid else '0'}", "peer": [], "self": [], "members": [], "unit": ""}
    elif _first(r"^\s*failover\s+lan\s+unit\s+(primary|secondary)", text) and _first(r"^\s*failover\s+interface\s+ip\s+\S+\s+" + _IPV4 + r"\s+\S+\s+standby\s+" + _IPV4, text):
        unit = _first(r"^\s*failover\s+lan\s+unit\s+(primary|secondary)", text).group(1).lower()
        link = _first(r"^\s*failover\s+interface\s+ip\s+\S+\s+" + _IPV4 + r"\s+\S+\s+standby\s+" + _IPV4, text)
        facts = {"kind": "ASA failover", "id": f"{link.group(1)}|{link.group(2)}", "peer": [], "self": [], "members": [], "unit": unit}
    elif _first(r"^\s*ha-interface\b.*local-ip\s+" + _IPV4 + r".*remote-ip\s+" + _IPV4, text) or _first(r"chassis\s+\d+\s+ha-interface\s+local-ip\s+" + _IPV4 + r".*?remote-ip\s+" + _IPV4, text):
        link = _first(r"local-ip\s+" + _IPV4 + r"(?:\s*/\d+)?\s+remote-ip\s+" + _IPV4, text)
        if link:
            facts = {"kind": "C9800 HA SSO", "id": "", "peer": [link.group(2)], "self": [link.group(1)], "members": [], "unit": ""}
    elif _first(r"^\s*hsb-service\b", text) and _first(r"local-ip\s+" + _IPV4 + r"\s+peer-ip\s+" + _IPV4, text):
        link = _first(r"local-ip\s+" + _IPV4 + r"\s+peer-ip\s+" + _IPV4, text)
        facts = {"kind": "HSB", "id": "", "peer": [link.group(2)], "self": [link.group(1)], "members": [], "unit": ""}
    elif _first(r"cm device-group\s+\S+\s*\{[^}]*type sync-failover", text, re.I | re.S) or _first(r"ltm\s+device-group.*sync-failover", text):
        names = re.findall(r"^\s*(?:cm\s+)?device\s+(?:/Common/)?([A-Za-z0-9_.\-]+)\s*\{", text, re.M)
        names += re.findall(r"^\s*cm device (?:/Common/)?([A-Za-z0-9_.\-]+)\s*\{", text, re.M)
        group = _first(r"cm device-group\s+(?:/Common/)?(\S+)\s*\{", text)
        members = list(dict.fromkeys(n.lower().split(".")[0] for n in names if n.lower() not in ("name",)))
        facts = {"kind": "F5 device group", "id": group.group(1) if group else "", "peer": [], "self": [], "members": members, "unit": ""}
    if facts is None:
        return None
    facts["self"] = list(dict.fromkeys(facts["self"] + _own_addresses(text)))[:60]
    facts["neighbours"] = _neighbours(text)
    facts["peer"] = [p for p in facts["peer"] if p]
    return facts


def attach(assets: list[dict[str, Any]], text: str) -> None:
    """Put the facts of one capture on the assets it produced (not on an access point record: its controller carries the pair)."""
    facts = read_facts(text)
    if not facts:
        return
    for asset in assets:
        if asset.get("device_type") in KIND_DEVICE_TYPES:
            asset["ha_facts"] = dict(facts)


def _short(name: str) -> str:
    return (name or "").lower().split(".")[0].split(" ")[0]


def _is_pair(a: dict[str, Any], b: dict[str, Any]) -> bool:
    fa, fb = a.get("ha_facts"), b.get("ha_facts")
    if not fa or not fb or fa["kind"] != fb["kind"] or a["device_type"] != b["device_type"] or a is b:
        return False
    if fa.get("id") and fb.get("id") and fa["id"] != fb["id"] and fa["kind"] != "F5 device group":
        return False
    if fa["kind"] == "F5 device group":
        return _short(b["hostname"]) in fa["members"] and _short(a["hostname"]) in fb["members"] and _short(a["hostname"]) != _short(b["hostname"])
    if fa["kind"] in ("ASA failover", "FortiGate HA"):
        return bool(fa["id"]) and fa["id"] == fb["id"] and a.get("model") == b.get("model") and (fa["kind"] != "ASA failover" or fa["unit"] != fb["unit"])
    mine, theirs = set(fa["self"]), set(fb["self"])
    if set(fa["peer"]) & theirs or set(fb["peer"]) & mine:
        return True
    # no address to compare (a capture of show commands): the same domain or group and model, and each lists the other on its neighbour tables
    return (bool(fa.get("id")) and fa["id"] == fb.get("id") and a.get("model") == b.get("model")
            and _short(b["hostname"]) in fa.get("neighbours", []) and _short(a["hostname"]) in fb.get("neighbours", []))


def pair_by_config(assets: list[dict[str, Any]]) -> dict[str, str]:
    """``{asset id: partner id}`` for the captured devices whose configurations name each other.  A device that more than one other could be paired with is left alone (two
    sites that reuse domain 1 and the same addresses are ambiguous; the architect decides), and a device whose capture holds pair facts but has no partner is flagged."""
    live = [a for a in assets if not a.get("duplicate_of") and a.get("ha_facts")]
    candidates: dict[str, list[str]] = {a["id"]: [b["id"] for b in live if _is_pair(a, b)] for a in live}
    out: dict[str, str] = {}
    for key, found in candidates.items():
        if len(found) == 1 and candidates.get(found[0]) == [key]:
            out[key] = found[0]
    for asset in live:
        if asset["id"] in out:
            continue
        found = candidates.get(asset["id"], [])
        note_start = "Redundant pair:"
        asset["notes"] = [n for n in asset["notes"] if not n.startswith(note_start)]
        facts = asset["ha_facts"]
        if len(found) > 1:
            asset["notes"].append(f"{note_start} the configuration fits more than one other capture ({facts['kind']}); not paired automatically. Group them in the Devices tab.")
        else:
            asset["pair_missing"] = facts["kind"]
            asset["notes"].append(f"{note_start} this {facts['kind']} member has a partner that was not captured; the replacement needs two devices. Send the second capture so the pair is sized from both.")
    for asset in live:
        if asset["id"] in out:
            asset["pair_missing"] = ""
            asset["notes"] = [n for n in asset["notes"] if not n.startswith("Redundant pair:")]
    return out
