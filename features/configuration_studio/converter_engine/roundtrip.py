"""Round-trip check of one switch conversion.

The translators work one source command at a time, so a command that is not understood, or a value that is lost on the way,
leaves no trace in the output.  This module reads the converted text back with the parser of the TARGET vendor and compares what
it finds with what the parser of the SOURCE vendor found in the original, in vendor-neutral terms:

* VLANs (ids and names), SVIs (address, relay, gateway protocol, ACL), loopbacks and the management port;
* every port the source really uses, through the interface map: description, shutdown, access / trunk mode, VLANs, native VLAN,
  speed, duplex, edge-port and guard features, voice VLAN, PoE, port security, DHCP snooping trust, ACL binding;
* link aggregation: which ports are members of which bundle and whether the bundle is LACP or static;
* static routes and the default gateway, DHCP pools, ACL names and rule counts;
* services that decide whether the switch can be managed after the cut-over: NTP, syslog, SNMP, TACACS+/RADIUS servers,
  local users, name servers and the banner.

Every difference is listed with the source and the target value.  A difference on a port or a section where the translator already
wrote a ``REVIEW`` line is marked ``flagged`` (the engineer was told); an unflagged difference is a SILENT one, the kind that
causes an outage after the cut-over, and decides the verdict.

The comparison is deliberately one-directional: it asks "did what the source configured reach the target?".  Extra lines on the
target (a defaults the vendor prints, a management ACL the profile adds) are counted as ``added`` and never reported as a fault.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

from .postcheck import _acl_blocks

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LOGICAL = (
    ("svi", re.compile(r"^(?:vlan|vlanif|vlan-interface)\s*(\d+)$", re.I)),
    ("lag", re.compile(r"^(?:port-channel|eth-trunk|lag|po|bridge-aggregation)\s*(\d+)$", re.I)),
    ("loopback", re.compile(r"^(?:loopback|lo|loop)\s*(\d+)$", re.I)),
)
_MGMT = re.compile(r"^(?:mgmt|meth|oobm|management)", re.I)
_MGMT_VRF = {"mgmt-vrf", "management", "mgmt", "mgmt_vrf"}
_REVIEW = re.compile(r"REVIEW", re.I)

# A REVIEW line is tied to a section of the comparison by the words in its CODE (``REVIEW-SNMP-COMMUNITY``, ``REVIEW-HSRP->VRRP``).  The
# codes of the "not converted" family quote the source command instead of naming the topic, so for those the words are looked for in the
# quoted text as well.
_TOPIC_WORDS = {
    "vlan": ("VLAN",),
    "route": ("ROUTE", "ROUTING", "MGMT-VRF", "DEFAULT-GATEWAY"),
    "dhcp": ("DHCP",),
    "acl": ("ACL", "ACCESS-GROUP", "TRAFFIC", "OBJECT-GROUP"),
    "ntp": ("NTP", "CLOCK"),
    "syslog": ("SYSLOG", "LOGGING", "LOGHOST", "INFO-CENTER"),
    "snmp": ("SNMP",),
    "aaa": ("AAA", "TACACS", "RADIUS", "PASSWORD", "USER", "LOGIN"),
    "dns": ("DNS", "NAME-SERVER"),
    "banner": ("BANNER", "MOTD"),
    "lag": ("LACP", "LAG", "PORT-CHANNEL", "ETH-TRUNK", "CHANNEL", "BUNDLE", "MLAG", "M-LAG", "VPC", "PEER-LINK"),
    "fhrp": ("HSRP", "VRRP", "FHRP", "GLBP"),
}
_UNSUPPORTED_FAMILY = ("UNSUPPORTED", "NO-EQUIVALENT", "UNMAPPED", "DROPPED", "NOT-CONVERTED", "CISCO", "ARUBA", "HUAWEI", "MANUAL")
_REVIEW_CODE = re.compile(r"REVIEW-[A-Z0-9][A-Z0-9>\-]*")


def review_index(text: str) -> list[tuple[str, str]]:
    """``[(code, quoted text), ...]`` for every REVIEW line of the converted text.  The comment lines that follow a bare
    ``REVIEW-UNSUPPORTED...`` heading belong to it (the converter lists the commands it left out there)."""
    entries: list[tuple[str, str]] = []
    lines = text.splitlines()
    for position, line in enumerate(lines):
        match = _REVIEW_CODE.search(line)
        if not match:
            continue
        quoted = line
        if any(word in match.group(0) for word in _UNSUPPORTED_FAMILY) and line.strip().lstrip("#! ").strip() == match.group(0):
            for follow in lines[position + 1:position + 400]:
                if follow.strip().startswith(("#", "!")) and "REVIEW" not in follow:
                    quoted += "\n" + follow
                else:
                    break
        entries.append((match.group(0), quoted))
    return entries


_SERVICE_PATTERNS: dict[str, dict[str, re.Pattern[str]]] = {
    "ntp": {
        "cisco": re.compile(r"^\s*ntp\s+(?:server|peer)\b", re.I),
        "aruba": re.compile(r"^\s*ntp\s+server\b", re.I),
        "huawei": re.compile(r"^\s*ntp-service\s+(?:unicast-server|unicast-peer|server)\b", re.I),
    },
    "syslog": {
        "cisco": re.compile(r"^\s*logging\s+(?:host\s+|server\s+|\d)", re.I),
        "aruba": re.compile(r"^\s*logging\s+(?:\d|server\s|host\s)", re.I),
        "huawei": re.compile(r"^\s*info-center\s+loghost\s+(?!source)", re.I),
    },
    "snmp-trap": {
        "cisco": re.compile(r"^\s*snmp-server\s+host\b", re.I),
        "aruba": re.compile(r"^\s*snmp-server\s+host\b", re.I),
        "huawei": re.compile(r"^\s*snmp-agent\s+target-host\b", re.I),
    },
    "tacacs": {
        "cisco": re.compile(r"^\s*(?:tacacs-server\s+host|tacacs\s+server|address\s+ipv4)\b", re.I),
        "aruba": re.compile(r"^\s*tacacs-server\s+host\b", re.I),
        "huawei": re.compile(r"^\s*hwtacacs-server\s+(?:authentication|authorization|accounting)\b", re.I),
    },
    "radius": {
        "cisco": re.compile(r"^\s*radius-server\s+host\b", re.I),
        "aruba": re.compile(r"^\s*radius-server\s+host\b", re.I),
        "huawei": re.compile(r"^\s*radius-server\s+(?:authentication|accounting)\b", re.I),
    },
    "dns": {
        "cisco": re.compile(r"^\s*ip\s+name-server\b", re.I),
        "aruba": re.compile(r"^\s*(?:ip\s+dns\s+server-address|dns\s+server)\b", re.I),
        "huawei": re.compile(r"^\s*dns\s+server\b", re.I),
    },
}
_SERVICE_LABEL = {
    "ntp": "NTP server", "syslog": "Syslog host", "snmp-trap": "SNMP trap host", "tacacs": "TACACS+ server", "radius": "RADIUS server",
    "dns": "DNS server",
}
_SERVICE_TOPIC = {"ntp": "ntp", "syslog": "syslog", "snmp-trap": "snmp", "tacacs": "aaa", "radius": "aaa", "dns": "dns"}

_USER_PATTERNS = {
    "cisco": re.compile(r"^\s*username\s+(\S+)", re.I),
    "aruba": re.compile(r"^\s*(?:username|user)\s+(\S+)", re.I),
    "huawei": re.compile(r"^\s*local-user\s+(\S+)\s+(?:password|privilege|service-type)", re.I),
}
_COMMUNITY_PATTERNS = {
    "cisco": re.compile(r"^\s*snmp-server\s+community\s+(\S+)", re.I),
    "aruba": re.compile(r"^\s*snmp-server\s+community\s+(\S+)", re.I),
    "huawei": re.compile(r"^\s*snmp-agent\s+community\s+(?:read|write)\s+(?:cipher\s+|simple\s+)?(\S+)", re.I),
}


# --------------------------------------------------------------------------------------------------------------------------
# Neutral facts
# --------------------------------------------------------------------------------------------------------------------------


def _vendor_key(vendor: str) -> str:
    value = str(vendor or "").lower()
    for key in ("cisco", "aruba", "huawei"):
        if key in value:
            return key
    return value


def _canon(name: str) -> str:
    text = re.sub(r"\s+", "", str(name or "")).lower()
    text = re.sub(r"^tengigabitethernet", "te", text)
    text = re.sub(r"^(\d+)gigabitethernet", r"\1ge", text)
    text = re.sub(r"^gigabitethernet", "ge", text)
    text = re.sub(r"^fastethernet", "fa", text)
    return text


def classify(interface) -> tuple[str, str]:
    """``(kind, key)``: svi / lag / loopback / mgmt keyed by number, a physical port keyed by its canonical name."""
    name = str(getattr(interface, "name", "") or "").strip()
    for kind, pattern in _LOGICAL:
        match = pattern.match(name)
        if match:
            return kind, str(int(match.group(1)))
    vrf = str(getattr(interface, "vrf_forwarding", "") or "").lower()
    if _MGMT.match(name) or vrf in _MGMT_VRF:
        return "mgmt", "0"
    return "port", _canon(name)


def expand_vlans(tokens: Iterable[Any]) -> frozenset[int] | str:
    """A VLAN list as a set of ids, or ``"all"`` when the list is empty or says all."""
    found: set[int] = set()
    seen_any = False
    for token in tokens or []:
        text = str(token).strip().lower()
        if not text:
            continue
        seen_any = True
        if text in ("all", "1-4094", "1 to 4094"):
            return "all"
        for part in re.split(r"[,\s]+", text.replace(" to ", "-")):
            if not part:
                continue
            if re.fullmatch(r"\d+", part):
                found.add(int(part))
            else:
                span = re.fullmatch(r"(\d+)-(\d+)", part)
                if span:
                    low, high = int(span.group(1)), int(span.group(2))
                    if high - low > 4094:
                        return "all"
                    found.update(range(low, high + 1))
    if not seen_any:
        return "all"
    if len(found) >= 4094:
        return "all"
    return frozenset(found)


def _speed(value: str) -> str:
    text = str(value or "").strip().lower()
    if text in ("", "auto"):
        return ""
    match = re.fullmatch(r"(\d+)\s*(g|m)?(?:bps|b)?(?:-?(?:full|half))?", text)
    if not match:
        return text
    number = int(match.group(1))
    if match.group(2) == "g":
        number *= 1000
    return str(number)


def _network(destination: str, mask: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{destination}/{mask}", strict=False))
    except ValueError:
        return f"{destination}/{mask}"


def _subnet(address: str, mask: str) -> str:
    try:
        return str(ipaddress.ip_interface(f"{address}/{mask}"))
    except ValueError:
        return f"{address}/{mask}"


def port_facts(interface) -> dict[str, Any]:
    """The attributes of one port that carry meaning on any vendor; empty / default values are left out."""
    facts: dict[str, Any] = {}
    description = str(getattr(interface, "description", "") or "").strip()
    if description:
        facts["description"] = description
    if getattr(interface, "shutdown", False):
        facts["shutdown"] = True
    mode = str(getattr(interface, "mode", "") or "").lower()
    if mode == "trunk":
        facts["mode"] = mode                                # "access" is the default on every vendor and is not printed; the VLAN below is
    if mode == "access" or (getattr(interface, "access_vlan", None) and mode != "trunk"):
        vlan = getattr(interface, "access_vlan", None)
        if vlan and int(vlan) != 1:
            facts["access_vlan"] = int(vlan)
    if mode == "trunk":
        native = getattr(interface, "native_vlan", None)
        if native and int(native) != 1:
            facts["native_vlan"] = int(native)
        allowed = expand_vlans(getattr(interface, "allowed_vlans", None) or [])
        if allowed != "all":
            facts["allowed_vlans"] = allowed
    speed = _speed(getattr(interface, "speed", ""))
    if speed:
        facts["speed"] = speed
    duplex = str(getattr(interface, "duplex", "") or "").lower()
    if duplex in ("full", "half"):
        facts["duplex"] = duplex
    for label, attribute in (
        ("edge port (portfast)", "spanning_tree_portfast"), ("BPDU guard", "bpduguard"), ("root guard", "spanning_tree_root_guard"),
        ("loop guard", "spanning_tree_loop_guard"), ("port security", "port_security_enabled"), ("DHCP snooping trust", "dhcp_snooping_trusted"),
        ("LLDP transmit off", "lldp_transmit_disabled"), ("LLDP receive off", "lldp_receive_disabled"),
    ):
        if getattr(interface, attribute, False):
            facts[label] = True
    voice = getattr(interface, "voice_vlan_id", None)
    if voice:
        facts["voice VLAN"] = int(voice)
    if getattr(interface, "poe_enabled", None) is not None:
        facts["PoE"] = bool(interface.poe_enabled)
    _acl_bindings(interface, facts)
    storm = [getattr(interface, f"storm_control_{kind}_level", None) for kind in ("broadcast", "multicast", "unicast")]
    if any(storm):
        facts["storm control"] = True
    return facts


def _acl_bindings(interface, facts: dict[str, Any]) -> None:
    """ACL in / out of a port or SVI.  Huawei binds an ACL through ``traffic-policy`` / ``traffic-filter``, which the parser keeps apart."""
    for label, attribute, alternative in (("ACL in", "access_group_in", "traffic_policy_inbound"), ("ACL out", "access_group_out", "traffic_policy_outbound")):
        value = str(getattr(interface, attribute, "") or getattr(interface, alternative, "") or "").strip()
        if value:
            facts[label] = value


def routed_facts(interface) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    description = str(getattr(interface, "description", "") or "").strip()
    if description:
        facts["description"] = description
    if getattr(interface, "shutdown", False):
        facts["shutdown"] = True
    if getattr(interface, "ip_address", "") and getattr(interface, "subnet_mask", ""):
        facts["address"] = _subnet(interface.ip_address, interface.subnet_mask)
    elif getattr(interface, "ip_dhcp", False):
        facts["address"] = "dhcp"
    relays = sorted(set(getattr(interface, "helper_addresses", None) or []))
    if relays:
        facts["DHCP relay"] = tuple(relays)
    vip = getattr(interface, "hsrp_virtual_ip", "") or getattr(interface, "vrrp_virtual_ip", "")
    group = getattr(interface, "hsrp_group", None) or getattr(interface, "vrrp_vrid", None)
    if vip:
        facts["gateway protocol address"] = vip
        if group is not None:
            facts["gateway protocol group"] = int(group)
    _acl_bindings(interface, facts)
    vrf = str(getattr(interface, "vrf_forwarding", "") or "").strip()
    if vrf and vrf.lower() not in _MGMT_VRF:
        facts["VRF"] = vrf.lower()
    return facts


def _strip_comment_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip() and not line.strip().startswith(("#", "!", "//"))]


def stanzas(text: str) -> dict[str, list[str]]:
    """``interface`` blocks of a configuration, keyed by canonical interface name; comments are kept (REVIEW markers live there)."""
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for raw in text.splitlines():
        match = re.match(r"^interface\s+(.+?)\s*$", raw, re.I)
        if match:
            current = _canon(match.group(1))
            blocks.setdefault(current, [])
            continue
        if current is None:
            continue
        if raw and not raw[0].isspace():                   # anything that starts in column 1 ends the block, a comment included
            current = None
            continue
        blocks[current].append(raw)
    return blocks


def lag_modes(text: str, vendor: str) -> dict[str, str]:
    """``{lag id: "lacp" | "static"}`` as the configuration text says it (a parser does not expose it on every vendor)."""
    vendor = _vendor_key(vendor)
    modes: dict[str, str] = {}
    blocks = stanzas(text)
    if vendor == "huawei":
        for name, body in blocks.items():
            match = re.fullmatch(r"eth-trunk(\d+)", name)
            if match:
                joined = "\n".join(body).lower()
                modes[match.group(1)] = "lacp" if "mode lacp" in joined else "static"
    elif vendor == "aruba":
        for name, body in blocks.items():
            match = re.fullmatch(r"lag(\d+)", name)
            if match:
                modes[match.group(1)] = "lacp" if re.search(r"lacp\s+mode\s+(?:active|passive)", "\n".join(body).lower()) else "static"
        for line in text.splitlines():                         # ArubaOS-Switch: "trunk 1-2 trk1 lacp"
            match = re.match(r"^\s*trunk\s+\S+\s+trk(\d+)\s+(lacp|trunk)\b", line, re.I)
            if match:
                modes[match.group(1)] = "lacp" if match.group(2).lower() == "lacp" else "static"
    elif vendor == "cisco":
        for line in text.splitlines():
            match = re.match(r"^\s*channel-group\s+(\d+)\s+mode\s+(\S+)", line, re.I)
            if match:
                modes.setdefault(match.group(1), "lacp" if match.group(2).lower() in ("active", "passive") else "static")
    return modes


def service_values(text: str, vendor: str) -> dict[str, Any]:
    """Addresses and names of the services, read from the configuration text (comments are skipped)."""
    vendor = _vendor_key(vendor)
    lines = _strip_comment_lines(text)
    values: dict[str, Any] = {}
    for key, patterns in _SERVICE_PATTERNS.items():
        pattern = patterns.get(vendor)
        found: set[str] = set()
        if pattern is not None:
            for line in lines:
                if pattern.match(line):
                    found.update(address for address in IPV4.findall(line) if _valid_host(address))
        values[key] = found
    user_pattern = _USER_PATTERNS.get(vendor)
    values["users"] = {m.group(1).lower() for line in lines if user_pattern and (m := user_pattern.match(line))}
    community_pattern = _COMMUNITY_PATTERNS.get(vendor)
    values["communities"] = {m.group(1).strip('"').lower() for line in lines if community_pattern and (m := community_pattern.match(line))}
    return values


def _valid_host(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (ip.is_unspecified or str(ip).startswith("255."))


def acl_rules(text: str, vendor: str) -> dict[str, int]:
    return {name.lower(): len(rules) for name, rules in _acl_blocks(text.splitlines(), vendor)}


# --------------------------------------------------------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------------------------------------------------------


class _Rows:
    def __init__(self, review_text: str) -> None:
        self.rows: list[dict[str, Any]] = []
        self.reviews = review_index(review_text)
        self.added = 0

    def mentions(self, name: str) -> bool:
        """A REVIEW line names this source interface (the translator explained what it did with it)."""
        needle = name.lower()
        return bool(needle) and any(needle in quoted.lower() for _code, quoted in self.reviews)

    def topic_flagged(self, topic: str) -> bool:
        words = _TOPIC_WORDS.get(topic, (topic.upper(),))
        for code, quoted in self.reviews:
            if any(word in code for word in words):
                return True
            if any(marker in code for marker in _UNSUPPORTED_FAMILY) and any(word.lower() in quoted.lower() for word in words):
                return True
        return False

    def add(self, area: str, item: str, status: str, source: Any = "", target: Any = "", note: str = "", flagged: bool = False) -> None:
        self.rows.append({
            "area": area, "item": item, "status": status, "source": _show(source), "target": _show(target), "note": note, "flagged": bool(flagged),
        })


def _show(value: Any) -> str:
    if isinstance(value, (set, frozenset)):
        if all(isinstance(v, int) for v in value):
            return _ranges(sorted(value))
        return ", ".join(sorted(str(v) for v in value))
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "" if value is None else str(value)


def _ranges(numbers: list[int]) -> str:
    out, start, last = [], None, None
    for number in numbers:
        if start is None:
            start = last = number
        elif number == last + 1:
            last = number
        else:
            out.append(f"{start}" if start == last else f"{start}-{last}")
            start = last = number
    if start is not None:
        out.append(f"{start}" if start == last else f"{start}-{last}")
    return ",".join(out)


def _compare_facts(rows: _Rows, area: str, item: str, source: dict[str, Any], target: dict[str, Any], flagged: bool, skip: Iterable[str] = ()) -> None:
    skipped = set(skip)
    for key, value in source.items():
        if key in skipped:
            continue
        if key not in target:
            rows.add(area, item, "missing", f"{key}: {_show(value)}", "(absent)", f"{key} is configured on the source and not on the target", flagged)
        elif target[key] != value:
            rows.add(area, item, "changed", f"{key}: {_show(value)}", f"{key}: {_show(target[key])}", "", flagged)
    for key in target:
        if key not in source and key not in skipped:
            rows.added += 1


def _by_position(ports: dict[str, Any], wanted: str, taken: set[str]):
    """The one not yet matched target port whose position numbers (``1/1/1``) equal those of ``wanted``."""
    match = re.search(r"(\d+(?:/\d+)+)$", wanted)
    if not match:
        return None
    candidates = [(key, port) for key, port in ports.items() if key not in taken and key.endswith(match.group(1)) and re.search(r"(?:^|\D)" + re.escape(match.group(1)) + "$", key)]
    return candidates[0] if len(candidates) == 1 else None


def compare(source_config, target_config, *, source_text: str, target_text: str, source_vendor: str, target_vendor: str,
            port_map: dict[str, dict] | None = None, include_same: bool = False) -> dict[str, Any]:
    """Compare the parsed source with the parsed converted text; returns the rows and the summary."""
    sv, tv = _vendor_key(source_vendor), _vendor_key(target_vendor)
    port_map = port_map or {}
    rows = _Rows(target_text)
    all_stanzas = stanzas(target_text)
    review_by_port = {name: any(_REVIEW.search(line) for line in body) for name, body in all_stanzas.items()}

    # ---- interfaces split by kind
    def by_kind(config) -> dict[str, dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {"port": {}, "svi": {}, "lag": {}, "loopback": {}, "mgmt": {}}
        for interface in getattr(config, "interfaces", []) or []:
            kind, key = classify(interface)
            grouped[kind].setdefault(key, interface)
        return grouped

    source_if, target_if = by_kind(source_config), by_kind(target_config)
    source_members: dict[str, list[str]] = {}              # lag id -> target port names of the members
    source_lacp: dict[str, str] = {}
    target_members: dict[str, list[str]] = {}

    # ---- VLANs
    source_vlans = {int(v.vlan_id): (v.name or "") for v in getattr(source_config, "vlans", []) or [] if int(v.vlan_id) != 1}
    target_vlans = {int(v.vlan_id): (v.name or "") for v in getattr(target_config, "vlans", []) or []}
    vlan_flag = rows.topic_flagged("vlan")
    for vid, name in sorted(source_vlans.items()):
        if vid not in target_vlans:
            rows.add("VLAN", f"VLAN {vid}", "missing", name or "(no name)", "(absent)", "VLAN is defined on the source and not on the target", vlan_flag)
        else:
            rows.add("VLAN", f"VLAN {vid}", "same")
            if name and target_vlans[vid] != name:
                limit = "" if len(target_vlans[vid]) >= len(name) else "the target name is shorter, check the name length limit of the vendor"
                rows.add("VLAN", f"VLAN {vid} name", "changed", name, target_vlans[vid] or "(none)", limit, vlan_flag)
    rows.added += len([v for v in target_vlans if v not in source_vlans and v != 1])

    # ---- physical ports
    taken: set[str] = set()
    for key, interface in source_if["port"].items():
        mapped_name = (port_map.get(interface.name) or {}).get("target") or interface.name
        if _canon(mapped_name) in target_if["port"]:
            taken.add(_canon(mapped_name))
    for key, interface in source_if["port"].items():
        facts = port_facts(interface)
        member_of = getattr(interface, "channel_group", None)
        mapped = (port_map.get(interface.name) or {}).get("target") or interface.name
        target_key = _canon(mapped)
        if member_of is not None:
            source_members.setdefault(str(int(member_of)), []).append(target_key)
            source_lacp.setdefault(str(int(member_of)), "lacp" if str(getattr(interface, "lacp_mode", "")).lower() in ("active", "passive") else "static")
        if not facts and member_of is None:
            continue                                         # a port the source never touched
        counterpart = target_if["port"].get(target_key)
        if counterpart is None:
            # The interface map has no name for a port the target model lacks and the translator still wrote one (25GE1/1/1 for a
            # TwentyFiveGigE1/1/1 on a model without 25G ports); the position numbers are the same.
            found = _by_position(target_if["port"], target_key, taken)
            if found is not None:
                target_key, counterpart = found
                mapped = counterpart.name
        taken.add(target_key)
        flagged = review_by_port.get(target_key, False)
        item = f"{interface.name} -> {mapped}"
        if counterpart is None:
            status_note = (port_map.get(interface.name) or {}).get("note") or "no counterpart on the target model"
            rows.add("Port", item, "missing", ", ".join(f"{k}: {_show(v)}" for k, v in facts.items()) or "configured", "(absent)", status_note,
                     flagged or rows.mentions(interface.name) or (port_map.get(interface.name) or {}).get("status") in ("review", "missing"))
            continue
        target_facts = port_facts(counterpart)
        skip = set()
        if member_of is not None or getattr(counterpart, "channel_group", None) is not None:
            skip = {"mode", "access_vlan", "native_vlan", "allowed_vlans"}      # these live on the bundle
        before = len(rows.rows)
        _compare_facts(rows, "Port", item, facts, target_facts, flagged, skip)
        if len(rows.rows) == before:
            rows.add("Port", item, "same")
        if getattr(counterpart, "channel_group", None) is not None:
            target_members.setdefault(str(int(counterpart.channel_group)), []).append(target_key)
    for key, interface in target_if["port"].items():
        if getattr(interface, "channel_group", None) is not None:
            target_members.setdefault(str(int(interface.channel_group)), [])
            if key not in target_members[str(int(interface.channel_group))]:
                target_members[str(int(interface.channel_group))].append(key)

    # ---- bundles
    source_modes, target_modes = source_lacp, lag_modes(target_text, tv)
    lag_flag = rows.topic_flagged("lag")
    for lag_id, members in sorted(source_members.items(), key=lambda item: int(item[0])):
        found = target_members.get(lag_id)
        lag_item = f"Bundle {lag_id}"
        if found is None:
            mapped_elsewhere = [k for k, ports in target_members.items() if set(ports) == set(members)]
            if mapped_elsewhere:
                rows.add("Bundle", lag_item, "same", note=f"renumbered to bundle {mapped_elsewhere[0]}")
                found = target_members[mapped_elsewhere[0]]
                lag_id_target = mapped_elsewhere[0]
            else:
                rows.add("Bundle", lag_item, "missing", f"members {', '.join(sorted(members))}", "(absent)", "the ports are not in a bundle on the target", lag_flag)
                continue
        else:
            lag_id_target = lag_id
            if set(found) == set(members):
                rows.add("Bundle", lag_item, "same")
            else:
                rows.add("Bundle", lag_item, "changed", ", ".join(sorted(members)), ", ".join(sorted(found)), "bundle members differ", lag_flag)
        want, have = source_modes.get(lag_id), target_modes.get(lag_id_target)
        if want and have and want != have:
            rows.add("Bundle", f"{lag_item} mode", "changed", want, have,
                     "a static bundle against an LACP neighbour (or the reverse) does not come up; check the other end", lag_flag)
    # bundle interfaces themselves (description, trunk VLANs)
    for key, interface in source_if["lag"].items():
        counterpart = target_if["lag"].get(key)
        facts = port_facts(interface)
        facts.pop("speed", None)
        if counterpart is None:
            if facts:
                rows.add("Bundle", f"Bundle {key} interface", "missing", ", ".join(f"{k}: {_show(v)}" for k, v in facts.items()), "(absent)", "", lag_flag)
            continue
        before = len(rows.rows)
        _compare_facts(rows, "Bundle", f"Bundle {key} interface", facts, port_facts(counterpart), lag_flag)
        if facts and len(rows.rows) == before:
            rows.add("Bundle", f"Bundle {key} interface", "same")

    # ---- SVIs, loopbacks, management
    fhrp_flag = rows.topic_flagged("fhrp")
    for kind, label in (("svi", "SVI"), ("loopback", "Loopback"), ("mgmt", "Management port")):
        for key, interface in source_if[kind].items():
            facts = routed_facts(interface)
            if kind == "svi" and key == "1" and not facts:
                continue
            counterpart = target_if[kind].get(key)
            item = f"{label} {key}" if kind != "mgmt" else label
            if counterpart is None:
                if facts:
                    rows.add(label, item, "missing", ", ".join(f"{k}: {_show(v)}" for k, v in facts.items()), "(absent)",
                             "the interface is not on the target", rows.topic_flagged("vlan") or fhrp_flag)
                continue
            before = len(rows.rows)
            flag = fhrp_flag or rows.topic_flagged("acl") or rows.topic_flagged("dhcp")
            target_facts = routed_facts(counterpart)
            if kind == "svi" and "gateway protocol address" in facts and "gateway protocol address" not in target_facts:
                # Not every parser reads the VRRP / active-gateway block; look for the virtual address in the written text.
                body = "\n".join(line for name, lines in all_stanzas.items() if re.fullmatch(rf"(?:vlan|vlanif|vlan-interface)0*{key}", name) for line in lines)
                if facts["gateway protocol address"] in body:
                    target_facts["gateway protocol address"] = facts["gateway protocol address"]
                    if "gateway protocol group" in facts and re.search(rf"\b{facts['gateway protocol group']}\b", body):
                        target_facts["gateway protocol group"] = facts["gateway protocol group"]
            _compare_facts(rows, label, item, facts, target_facts, flag)
            if len(rows.rows) == before:
                rows.add(label, item, "same")

    # ---- static routes
    def route_set(config) -> dict[tuple[str, str, str], Any]:
        out = {}
        for route in getattr(config, "routes", []) or []:
            if not re.match(r"^\d", str(route.destination)):
                continue
            out[(str(route.vrf or "").lower() if str(route.vrf or "").lower() not in _MGMT_VRF else "mgmt", _network(route.destination, route.mask), str(route.next_hop))] = route
        return out

    source_routes, target_routes = route_set(source_config), route_set(target_config)
    route_flag = rows.topic_flagged("route")
    for key, route in sorted(source_routes.items()):
        label = f"{key[1]} via {key[2]}" + (f" (VRF {key[0]})" if key[0] else "")
        if key in target_routes:
            rows.add("Route", label, "same")
        else:
            rows.add("Route", label, "missing", label, "(absent)", "static route is not on the target", route_flag)
    gateway = str(getattr(source_config, "default_gateway", "") or "").strip()
    if gateway:
        has_default = any(k[1] == "0.0.0.0/0" and k[2] == gateway for k in target_routes) or str(getattr(target_config, "default_gateway", "") or "") == gateway
        if has_default:
            rows.add("Route", f"default gateway {gateway}", "same")
        else:
            rows.add("Route", f"default gateway {gateway}", "missing", gateway, "(absent)", "a Layer 2 switch loses its management path without it", route_flag)

    # ---- DHCP pools
    source_pools = {(_network(p.network, p.mask) if p.network and p.mask else p.name): p for p in getattr(source_config, "dhcp_pools", []) or []}
    target_pools = {(_network(p.network, p.mask) if p.network and p.mask else p.name): p for p in getattr(target_config, "dhcp_pools", []) or []}
    dhcp_flag = rows.topic_flagged("dhcp")
    for key, pool in sorted(source_pools.items()):
        if key in target_pools:
            rows.add("DHCP", f"pool {pool.name or key}", "same")
        else:
            rows.add("DHCP", f"pool {pool.name or key}", "missing", key, "(absent)", "DHCP server pool is not on the target", dhcp_flag)

    # ---- ACLs
    source_acls, target_acls = acl_rules(source_text, sv), acl_rules(target_text, tv)
    acl_flag = rows.topic_flagged("acl")
    for name, count in sorted(source_acls.items()):
        if name not in target_acls:
            rows.add("ACL", f"ACL {name}", "missing", f"{count} rule(s)", "(absent)", "", acl_flag)
        elif target_acls[name] < count:
            rows.add("ACL", f"ACL {name}", "changed", f"{count} rule(s)", f"{target_acls[name]} rule(s)", "fewer rules on the target", acl_flag)
        else:
            rows.add("ACL", f"ACL {name}", "same")

    # ---- services
    source_services, target_services = service_values(source_text, sv), service_values(target_text, tv)
    for key, label in _SERVICE_LABEL.items():
        flag = rows.topic_flagged(_SERVICE_TOPIC[key])
        for address in sorted(source_services[key]):
            if address in target_services[key]:
                rows.add("Service", f"{label} {address}", "same")
            else:
                rows.add("Service", f"{label} {address}", "missing", address, "(absent)", "the target will not use this server", flag)
    flag = rows.topic_flagged("aaa")
    for user in sorted(source_services["users"]):
        if user in target_services["users"]:
            rows.add("Service", f"Local user {user}", "same")
        else:
            rows.add("Service", f"Local user {user}", "missing", user, "(absent)", "no local account of this name on the target; confirm there is another way in", flag)
    if source_services["communities"]:
        flag = rows.topic_flagged("snmp")
        wanted, found = len(source_services["communities"]), len(target_services["communities"])
        if found >= wanted:
            rows.add("Service", "SNMP communities", "same")
        else:
            rows.add("Service", "SNMP communities", "changed", f"{wanted} community(ies)", f"{found}",
                     "a poller that uses a community loses access after the cut-over", flag)
    if getattr(source_config, "banner_commands", None):
        flag = rows.topic_flagged("banner")
        if getattr(target_config, "banner_commands", None):
            rows.add("Service", "Banner", "same")
        else:
            rows.add("Service", "Banner", "missing", "present", "(absent)", "", flag)

    return _summary(rows, include_same)


def _summary(rows: _Rows, include_same: bool = False) -> dict[str, Any]:
    differences = [row for row in rows.rows if row["status"] in ("missing", "changed")]
    silent = [row for row in differences if not row["flagged"]]
    areas: dict[str, dict[str, int]] = {}
    for row in rows.rows:
        slot = areas.setdefault(row["area"], {"same": 0, "changed": 0, "missing": 0, "silent": 0})
        slot[row["status"]] += 1
        if row["status"] in ("missing", "changed") and not row["flagged"]:
            slot["silent"] += 1
    if not rows.rows:
        verdict = "empty"
    elif silent:
        verdict = "differences"
    elif differences:
        verdict = "flagged"
    else:
        verdict = "equivalent"
    return {
        "verdict": verdict,
        "checked": len(rows.rows),
        "same": len([r for r in rows.rows if r["status"] == "same"]),
        "different": len(differences),
        "silent": len(silent),
        "flagged": len(differences) - len(silent),
        "added": rows.added,
        "areas": [{"area": area, **counts} for area, counts in areas.items()],
        # the rows that agree are only counted: a 48-port switch would send hundreds of "same" lines nobody reads
        "rows": rows.rows if include_same else differences,
    }


def unreadable(reason: str) -> dict[str, Any]:
    """The result when the converted text could not be read back at all."""
    return {"verdict": "unreadable", "checked": 0, "same": 0, "different": 0, "silent": 0, "flagged": 0, "added": 0, "areas": [], "rows": [],
            "reason": reason}


def reading_copy(text: str) -> str:
    """The converted text with every top-level REVIEW comment reduced to its bare marker.

    A REVIEW line quotes source lines (``! REVIEW-UNSUPPORTED: SW1# show running-config``); the Cisco parser looks for that command to find the
    configuration inside a session capture and would cut the configuration at such a quote.  Indented comments (the REVIEW lines inside a port)
    stay as they are: the parsers already skip them.
    """
    out = []
    for line in text.splitlines():
        if line and line[0] in "#!" and "REVIEW" in line:
            out.append(line[0])
        else:
            out.append(line)
    return "\n".join(out) + "\n"


def check_conversion(engine, source_path, *, source_vendor: str, target_vendor: str, output_text: str, port_map: dict[str, dict] | None,
                     include_same: bool = False) -> dict[str, Any]:
    """Parse the source again and the converted text, then compare.  Never raises: a failure is reported as ``unreadable`` / ``None``."""
    import os
    import tempfile
    from pathlib import Path

    if _vendor_key(target_vendor) not in ("cisco", "aruba", "huawei"):
        return {}
    try:
        source_config = engine.parse(filename=source_path, source_vendor=source_vendor, source_device_type="switch")
        source_text = Path(source_path).read_text(encoding="utf-8", errors="ignore")
    except Exception as error:                              # noqa: BLE001 - a check must not stop a conversion
        return unreadable(f"the source could not be read again: {error}")
    handle, name = tempfile.mkstemp(suffix=".cfg")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(reading_copy(output_text))
        parser = engine.get_parser(target_vendor, "switch")
        target_config = parser.parse_file(name)
    except Exception as error:                              # noqa: BLE001
        return unreadable(f"the converted text could not be read back: {error}")
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass
    if getattr(source_config, "interfaces", None) and not getattr(target_config, "interfaces", None):
        return unreadable("the target parser found no interface in the converted text")
    try:
        return compare(source_config, target_config, source_text=source_text, target_text=output_text, source_vendor=source_vendor,
                       target_vendor=target_vendor, port_map=port_map, include_same=include_same)
    except Exception as error:                              # noqa: BLE001
        return unreadable(f"the comparison failed: {error}")
